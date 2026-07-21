import os, queue, threading, time, uuid, shutil
from pathlib import Path
from app.config import UPLOAD_DIR, RESULT_DIR, REPORT_DIR, EXPORT_DIR, WORKERS, CHECKPOINT_EVERY, SAMPLE_EVENTS, MAX_FINDINGS, VALIDATE_RULES_DURING_ANALYSIS
from app.utils import capture_sha256, write_json, read_json, validate_capture, gzip_capture_file, load_storage_settings, load_app_settings, remove_capture_file, register_capture_file, capture_inventory_aliases
from app.parsers.reader import stream_events
from app.analysis.aggregator import AnalysisContext
from app.rules.engine import load_rules, match_event, aggregate_findings, build_validation_results
from app.plugins.loader import load_plugins, run_plugins
from app.attack.versioned import add_technique, finalize_techniques
from app.coverage_cache import ensure_coverage_cache
from app.reports.generator import generate_reports

JOB_DB = RESULT_DIR / 'jobs.json'
CHECKPOINT_DB = RESULT_DIR / 'checkpoints.json'
Q = queue.Queue()
STARTED = False
LOCK = threading.Lock()

def _jobs(): return read_json(JOB_DB, {})
def _save_jobs(j): write_json(JOB_DB, j)
def _checkpoints(): return read_json(CHECKPOINT_DB, {})
def _save_checkpoints(c): write_json(CHECKPOINT_DB, c)

PIPELINE_STAGES = [
    ('uploading', 'Upload'),
    ('decompressing', 'Decompress / Expand'),
    ('packet_parse', 'Packet Parse'),
    ('storage', 'Storage Policy'),
    ('flow_reconstruction', 'Flow Reconstruction'),
    ('normalization', 'Event Normalization'),
    ('asset_discovery', 'Asset Discovery'),
    ('log_source_detection', 'Log Source Detection'),
    ('rule_validation', 'Rule Evaluation'),
    ('attack_mapping', 'ATT&CK Mapping'),
    ('coverage_model', 'Coverage Model'),
    ('reports', 'Reports'),
]

def _default_stage_progress():
    return {key: 0 for key, _label in PIPELINE_STAGES}

def _pipeline_progress(**kw):
    data = _default_stage_progress()
    # Backward-compatible aliases used by older templates/jobs.
    aliases = {'parsing': 'packet_parse', 'compression': 'storage'}
    for k, v in (kw or {}).items():
        key = aliases.get(k, k)
        if key in data:
            try:
                data[key] = max(0, min(100, int(v)))
            except Exception:
                data[key] = 0
    return data


class JobStopped(Exception):
    pass


def _control_state(jid):
    return (_jobs().get(jid) or {})


def _control_checkpoint(jid, message='Paused'):
    """Cooperative pause/stop hook used while parsing large captures."""
    while True:
        job = _control_state(jid)
        if not job:
            raise JobStopped('Job removed')
        if job.get('stop_requested') or job.get('state') == 'stopped':
            raise JobStopped('Job stopped by user')
        if job.get('pause_requested') or job.get('state') == 'paused':
            _update(jid, state='paused', message=message or 'Paused')
            time.sleep(0.5)
            continue
        return


def pause_job(jid):
    jobs = _jobs(); job = jobs.get(jid)
    if not job:
        return False, 'Job not found'
    if job.get('state') in ('complete', 'failed', 'stopped'):
        return False, 'Job is not running or queued'
    job['pause_previous_state'] = job.get('state')
    job['pause_requested'] = True
    job['state'] = 'paused'
    job['message'] = 'Paused by user'
    job['updated'] = time.time()
    _save_jobs(jobs)
    return True, 'Paused'


def resume_job(jid):
    jobs = _jobs(); job = jobs.get(jid)
    if not job:
        return False, 'Job not found'
    if job.get('state') not in ('paused', 'queued', 'uploading', 'decompressing') and not job.get('pause_requested'):
        return False, 'Job is not paused'
    previous_state = job.get('pause_previous_state') or 'running'
    job['pause_requested'] = False
    job['stop_requested'] = False
    job['state'] = 'queued' if previous_state in ('queued', 'uploading', 'decompressing', 'new') else 'running'
    job['message'] = 'Resumed'
    job['updated'] = time.time()
    _save_jobs(jobs)
    if previous_state in ('queued', 'uploading', 'decompressing', 'new'):
        Q.put(jid)
    return True, 'Resumed'


def stop_job(jid):
    jobs = _jobs(); job = jobs.get(jid)
    if not job:
        return False, 'Job not found'
    if job.get('state') in ('complete', 'failed', 'stopped'):
        return False, 'Job is already finished'
    job['stop_requested'] = True
    job['pause_requested'] = False
    job['state'] = 'stopped'
    job['message'] = 'Stopped by user'
    job['updated'] = time.time()
    _save_jobs(jobs)
    return True, 'Stopped'

def rename_job(jid, name):
    jobs = _jobs()
    job = jobs.get(jid)
    if not job:
        return False
    clean = str(name or '').strip()[:120]
    job['name'] = clean or f'Job {jid[:8]}'
    job['updated'] = time.time()
    _save_jobs(jobs)
    return True

def create_job(files, append_to=None, validate_during_analysis=None, run_reports_during_analysis=None):
    jid = append_to or str(uuid.uuid4())
    jobs = _jobs()
    if jid not in jobs:
        jobs[jid] = {'id': jid, 'name': f'Job {jid[:8]}', 'state': 'queued', 'files': [], 'uploaded_files': [], 'upload_table': [], 'created': time.time(), 'progress': 0, 'message': 'Queued', 'stage_progress': _default_stage_progress()}
    else:
        # Backward compatibility: imported jobs and jobs created by older builds
        # may not have upload-specific fields. Initialize them before appending
        # new captures so uploads to existing jobs never fail with KeyError.
        jobs[jid].setdefault('id', jid)
        jobs[jid].setdefault('created', time.time())
        jobs[jid].setdefault('progress', 0)
        jobs[jid].setdefault('message', 'Queued')
    existing_files = jobs[jid].setdefault('files', [])
    if not isinstance(existing_files, list):
        existing_files = [existing_files] if existing_files else []
        jobs[jid]['files'] = existing_files
    jobs[jid]['files'].extend([str(f) for f in files])
    try:
        existing_uploads = jobs[jid].setdefault('uploaded_files', [])
        if not isinstance(existing_uploads, list):
            existing_uploads = []
            jobs[jid]['uploaded_files'] = existing_uploads
        upload_table = jobs[jid].setdefault('upload_table', [])
        if not isinstance(upload_table, list):
            upload_table = []
            jobs[jid]['upload_table'] = upload_table
        known_names = set(existing_uploads)
        known_keys = {x.get('key') for x in upload_table if isinstance(x, dict)}
        for f in files:
            name = Path(str(f)).name
            aliases = sorted(capture_inventory_aliases(name))
            if name and name not in known_names:
                existing_uploads.append(name)
                known_names.add(name)
            key = aliases[0] if aliases else name.lower()
            if key and key not in known_keys:
                upload_table.append({'filename': name, 'key': key, 'aliases': aliases, 'stored_file': str(f), 'status': 'queued', 'updated_at': time.time()})
                known_keys.add(key)
    except Exception:
        pass
    jobs[jid]['state'] = 'queued'
    jobs[jid].setdefault('name', f'Job {jid[:8]}')
    jobs[jid].setdefault('stage_progress', _default_stage_progress())
    jobs[jid].setdefault('uploaded_files', [])
    jobs[jid]['stage_progress'].setdefault('storage', 0)
    jobs[jid]['stage_progress']['uploading'] = 100
    jobs[jid]['stage_progress']['decompressing'] = 100
    jobs[jid]['message'] = 'Queued for parsing'
    if validate_during_analysis is not None:
        jobs[jid]['validate_during_analysis'] = bool(validate_during_analysis)
    if run_reports_during_analysis is not None:
        jobs[jid]['run_reports_during_analysis'] = bool(run_reports_during_analysis)
    jobs[jid]['updated'] = time.time()
    _save_jobs(jobs)
    Q.put(jid)
    return jid


def create_empty_job():
    """Create a new empty current job without deleting previous results."""
    jid = str(uuid.uuid4())
    jobs = _jobs()
    outdir = RESULT_DIR / jid
    outdir.mkdir(parents=True, exist_ok=True)
    write_json(outdir / 'result.json', {
        'summary': {},
        'hosts': [],
        'flows': [],
        'protocols': {},
        'iocs': {'ips': [], 'domains': [], 'urls': []},
        'findings': [],
        'log_sources': [],
        'techniques': [],
        'data_source_coverage': [],
        'enterprise_coverage': {},
        'rule_validations': {'summary': {}, 'matches': [], 'validated_techniques': []},
        'validated_techniques': [],
        'processed_files': [],
        'skipped_files': [],
    })
    now = time.time()
    jobs[jid] = {
        'id': jid,
        'state': 'new',
        'name': f'Job {jid[:8]}',
        'files': [],
        'uploaded_files': [],
        'upload_table': [],
        'created': now,
        'updated': now,
        'progress': 0,
        'stage_progress': _default_stage_progress(),
        'message': 'New empty job ready for PCAP upload',
        'result_path': str(outdir / 'result.json'),
        'internal_data_ready': True,
        'reports_generated': False,
    }
    _save_jobs(jobs)
    return jid


def delete_job(jid):
    """Delete a stored job and its generated artifacts.

    Running jobs are not deleted to avoid removing files while a worker is using
    them. Previous completed/failed/new jobs can be deleted from the UI.
    """
    jobs = _jobs()
    job = jobs.get(jid)
    if not job:
        return False, 'Job not found'
    if job.get('state') == 'running':
        return False, 'Cannot delete a running job'
    jobs.pop(jid, None)
    _save_jobs(jobs)
    for base in (RESULT_DIR, REPORT_DIR, EXPORT_DIR):
        path = base / jid
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)
    return True, 'Deleted'

def list_jobs(): return _jobs()
def get_job(jid): return _jobs().get(jid)

def _update(jid, **kw):
    with LOCK:
        jobs=_jobs(); jobs.setdefault(jid, {'id':jid}); jobs[jid].update(kw); jobs[jid]['updated']=time.time(); _save_jobs(jobs)

def worker_loop(num):
    while True:
        jid = Q.get()
        try: analyze_job(jid)
        except JobStopped as e: _update(jid, state='stopped', message=str(e), stop_requested=True)
        except Exception as e: _update(jid, state='failed', message=str(e))
        finally: Q.task_done()

def start_workers():
    global STARTED
    if STARTED: return
    STARTED=True
    try:
        configured_workers = int(load_app_settings().get('worker_count') or WORKERS)
    except Exception:
        configured_workers = WORKERS
    for i in range(max(1, configured_workers)):
        t=threading.Thread(target=worker_loop, args=(i,), daemon=True); t.start()

def analyze_job(jid):
    jobs=_jobs(); job=jobs.get(jid)
    if not job: return
    if job.get('stop_requested') or job.get('state') == 'stopped':
        _update(jid, state='stopped', message='Stopped before analysis started')
        return
    _control_checkpoint(jid, 'Paused before analysis started')
    _update(jid, state='running', progress=0, message='Validating files', packets=0, bytes_read=0, total_bytes=0, stage_progress=_pipeline_progress(uploading=100, decompressing=100))
    ctx=AnalysisContext(); rules=load_rules(); plugins=load_plugins(); cps=_checkpoints(); processed=[]; skipped=[]
    storage_settings = load_storage_settings(); storage_policy = storage_settings.get('archive_policy', 'delete_after_analysis')
    lightweight_rules = [r for r in rules if r.get('run_during_analysis') or r.get('lightweight')]
    validate_during_analysis = bool(job.get('validate_during_analysis', VALIDATE_RULES_DURING_ANALYSIS))
    run_reports_during_analysis = bool(job.get('run_reports_during_analysis', False))
    full_validation_deferred = not validate_during_analysis
    files=[Path(f) for f in job.get('files',[])]
    file_count = max(1, len(files))
    for fi,path in enumerate(files):
        _control_checkpoint(jid, 'Paused before next capture')
        ok,msg=validate_capture(path)
        if not ok:
            skipped.append({'file':str(path),'reason':msg}); continue
        digest=capture_sha256(path)
        cp=cps.get(digest, {})
        if cp.get('complete') and cp.get('result_path') and Path(cp['result_path']).exists():
            # Incremental skip: merge previous partial result.
            old=read_json(Path(cp['result_path']), {})
            for ev in old.get('events_sample',[]): ctx.add_event(ev)
            skipped.append({'file':str(path),'reason':'already analyzed by sha256 checkpoint'})
            continue
        work_dir = RESULT_DIR / jid / digest[:12]; work_dir.mkdir(parents=True, exist_ok=True)
        sample=[]
        file_size = path.stat().st_size if path.exists() else 0
        base_progress = int((fi / file_count) * 90) + 5
        _update(jid, state='running', message=f'Parsing {path.name}', current_stage='parsing', current_file=path.name, current_file_index=fi+1, total_files=len(files), current_file_progress=0, current_file_bytes_read=0, current_file_bytes_total=file_size, progress=base_progress, stage_progress=_pipeline_progress(uploading=100, decompressing=100, packet_parse=int((fi/file_count)*100)))
        packet_count=0
        def prog(n, bytes_read=None, bytes_total=None):
            bytes_total = int(bytes_total or file_size or 0)
            bytes_read = int(bytes_read or 0)
            if bytes_total > 0:
                file_fraction = max(0.0, min(1.0, bytes_read / bytes_total))
            else:
                file_fraction = 0.0
            overall = int(5 + (((fi + file_fraction) / file_count) * 90))
            current_pct = int(file_fraction * 100)
            if n and n % CHECKPOINT_EVERY == 0:
                cps[digest]={'file':str(path),'sha256':digest,'packets':n,'bytes_read':bytes_read,'bytes_total':bytes_total,'complete':False,'updated':time.time()}
                _save_checkpoints(cps)
            if bytes_total > 0 or (n and n % 10000 == 0):
                _update(jid, packets=n, bytes_read=bytes_read, total_bytes=bytes_total, current_file_progress=current_pct, current_file_bytes_read=bytes_read, current_file_bytes_total=bytes_total, progress=overall, current_stage='parsing', stage_progress=_pipeline_progress(uploading=100, decompressing=100, packet_parse=int(((fi + file_fraction)/file_count)*100)), message=f'Parsing {path.name}: {current_pct}% read, {n} packets')
        for idx, ev in stream_events(path, work_dir, cp, prog):
            if idx % 250 == 0:
                _control_checkpoint(jid, f'Paused while parsing {path.name}')
            packet_count=idx+1
            ctx.add_event(ev)
            if len(sample) < SAMPLE_EVENTS:
                sample.append(ev)
            # Performance: do not run the full rule library while Scapy is
            # streaming packets.  Only explicit lightweight parser-time rules
            # and plugins run here.  Full Detection/Network Rule validation is
            # executed later on demand from the UI, or automatically only when
            # VALIDATE_RULES_DURING_ANALYSIS=1 or the dashboard checkbox is selected.
            findings = match_event(ev, lightweight_rules) if lightweight_rules else []
            findings += run_plugins(ev, ctx, plugins)
            for f in findings:
                if len(ctx.findings) < MAX_FINDINGS:
                    ctx.findings.append(f)
                for tid in f.get('attack',[]): add_technique(ctx, tid, f)
            if packet_count and packet_count % CHECKPOINT_EVERY == 0:
                cps[digest]={'file':str(path),'sha256':digest,'packets':packet_count,'complete':False,'updated':time.time()}; _save_checkpoints(cps)
        partial=work_dir/'partial_result.json'
        write_json(partial, {'events_sample': sample, 'packet_count': packet_count})
        cps[digest]={'file':str(path),'sha256':digest,'packets':packet_count,'bytes_read':file_size,'bytes_total':file_size,'complete':True,'result_path':str(partial),'updated':time.time()}; _save_checkpoints(cps)
        compression_pct = int(((fi + 0.5) / file_count) * 100)
        _update(jid, state='running', current_stage='compression', message=f'Applying storage policy to parsed capture {path.name}', stage_progress=_pipeline_progress(uploading=100, decompressing=100, packet_parse=int(((fi + 1) / file_count) * 100), flow_reconstruction=100, normalization=100, asset_discovery=100, log_source_detection=100, storage=compression_pct))
        storage_action = {'policy': storage_policy, 'compressed': False, 'deleted': False, 'retained_raw': False}
        stored_file = str(path)
        if storage_policy == 'keep_raw':
            storage_action.update({'retained_raw': True, 'original_file': str(path), 'compressed': False, 'message': 'Raw capture retained by storage policy'})
        elif storage_policy == 'delete_after_analysis':
            storage_action.update(remove_capture_file(path))
            stored_file = storage_action.get('deleted_marker') or ''
        else:
            storage_action.update(gzip_capture_file(path))
            stored_file = storage_action.get('compressed_file') or str(path)
        processed.append({'file':stored_file,'original_file':str(path),'sha256':digest,'packets':packet_count,'storage_compression':storage_action})
        try:
            register_capture_file(Path(path).name, job_id=jid, sha256=digest, stored_file=stored_file, status='processed')
        except Exception:
            pass
        try:
            jobs_now = _jobs(); job_now = jobs_now.get(jid) or {}
            table = job_now.setdefault('upload_table', [])
            aliases = capture_inventory_aliases(Path(path).name)
            updated = False
            for row in table:
                if not isinstance(row, dict):
                    continue
                row_aliases = set(row.get('aliases') or []) | capture_inventory_aliases(row.get('filename') or '') | capture_inventory_aliases(row.get('stored_file') or '')
                if aliases & row_aliases:
                    row.update({'stored_file': stored_file, 'sha256': digest, 'status': 'processed', 'storage_policy': storage_policy, 'updated_at': time.time()})
                    updated = True
            if not updated:
                table.append({'filename': Path(path).name, 'key': sorted(aliases)[0] if aliases else Path(path).name.lower(), 'aliases': sorted(aliases), 'stored_file': stored_file, 'sha256': digest, 'status': 'processed', 'storage_policy': storage_policy, 'updated_at': time.time()})
            jobs_now[jid] = job_now; _save_jobs(jobs_now)
        except Exception:
            pass
        files[fi] = Path(stored_file) if stored_file else Path(str(path) + '.deleted')
        status_name = Path(stored_file).name if stored_file else path.name
        _update(jid, current_stage='compression', message=f'Storage policy complete for {status_name}', storage_archive_policy=storage_policy, stage_progress=_pipeline_progress(uploading=100, decompressing=100, packet_parse=int(((fi + 1) / file_count) * 100), flow_reconstruction=100, normalization=100, asset_discovery=100, log_source_detection=100, storage=int(((fi + 1) / file_count) * 100)))
    # Persist compressed capture paths so future duplicate checks compare against the .gz files.
    jobs = _jobs()
    if jid in jobs:
        jobs[jid]['files'] = [str(f) for f in files]
        jobs[jid]['storage_archive_policy'] = storage_policy
        jobs[jid]['storage_compression_complete'] = storage_policy == 'compress_after_analysis'
        jobs[jid]['storage_capture_deleted'] = storage_policy == 'delete_after_analysis'
        jobs[jid]['storage_compression_message'] = {'compress_after_analysis':'Parsed captures compressed with gzip', 'keep_raw':'Raw captures retained', 'delete_after_analysis':'Original captures deleted after analysis'}.get(storage_policy, 'Storage policy applied')
        _save_jobs(jobs)
    # Aggregate rules can be expensive across large flow sets.  Keep them out
    # of the parse-completion path unless full validation during analysis is
    # explicitly enabled.
    if validate_during_analysis:
        for f in aggregate_findings(ctx, rules):
            if len(ctx.findings) < MAX_FINDINGS:
                ctx.findings.append(f)
            for tid in f.get('attack',[]): add_technique(ctx, tid, f)
    _update(jid, current_stage='log_source_detection', message='Finalizing detected telemetry and log-source mapping', stage_progress=_pipeline_progress(uploading=100, decompressing=100, packet_parse=100, storage=100, flow_reconstruction=100, normalization=100, asset_discovery=100, log_source_detection=90, rule_validation=100 if validate_during_analysis else 0))
    finalize_techniques(ctx)
    result=ctx.to_dict(); result['processed_files']=processed; result['skipped_files']=skipped
    if validate_during_analysis:
        validations = build_validation_results(result, rules)
        result['rule_validations'] = validations
        result['validated_techniques'] = validations.get('validated_techniques', [])
        result['rule_validation_status'] = 'complete'
        result['rule_validation_message'] = 'Validated automatically during analysis'
        _update(jid, stage_progress=_pipeline_progress(uploading=100, decompressing=100, packet_parse=100, flow_reconstruction=100, normalization=100, asset_discovery=100, log_source_detection=100, attack_mapping=100, rule_validation=100, coverage_model=100, storage=100), current_stage='rule_validation')
    else:
        result['rule_validations'] = {'summary': {}, 'matches': [], 'validated_techniques': []}
        result['validated_techniques'] = []
        result['rule_validation_status'] = 'not_run'
        result['rule_validation_message'] = 'Rule validation deferred; click Validate Rules to run the full rule engine.'
    _update(jid, current_stage='attack_mapping', message='Building ATT&CK mapping and coverage model', stage_progress=_pipeline_progress(uploading=100, decompressing=100, packet_parse=100, flow_reconstruction=100, normalization=100, asset_discovery=100, log_source_detection=100, attack_mapping=50, rule_validation=100 if validate_during_analysis else 0, storage=100))
    # Build and cache ATT&CK coverage once when analysis completes.  UI pages
    # should load this cached model instead of recomputing STIX expansion on
    # every request.
    result, _coverage_rebuilt = ensure_coverage_cache(result, rules, force=True)
    _update(jid, current_stage='coverage_model', message='Coverage model complete', stage_progress=_pipeline_progress(uploading=100, decompressing=100, packet_parse=100, flow_reconstruction=100, normalization=100, asset_discovery=100, log_source_detection=100, attack_mapping=100, rule_validation=100 if validate_during_analysis else 0, coverage_model=100, storage=100))
    outdir=RESULT_DIR/jid; outdir.mkdir(exist_ok=True)
    write_json(outdir/'result.json', result)
    reports_generated = False
    if run_reports_during_analysis:
        _control_checkpoint(jid, 'Paused before report generation')
        _update(jid, current_stage='reports', message='Generating reports after analysis', stage_progress=_pipeline_progress(uploading=100, decompressing=100, packet_parse=100, flow_reconstruction=100, normalization=100, asset_discovery=100, log_source_detection=100, attack_mapping=100, rule_validation=100 if validate_during_analysis else 0, coverage_model=100, storage=100, reports=25))
        generate_reports(jid, result, None)
        _update(jid, current_stage='reports', message='Reports generated after analysis', stage_progress=_pipeline_progress(uploading=100, decompressing=100, packet_parse=100, flow_reconstruction=100, normalization=100, asset_discovery=100, log_source_detection=100, attack_mapping=100, rule_validation=100 if validate_during_analysis else 0, coverage_model=100, storage=100, reports=100))
        reports_generated = True
    # Downloadable reports are optional. If the dashboard checkbox is enabled,
    # they are generated as the final pipeline stage; otherwise they remain
    # available on demand from the Reports page.
    _update(
        jid,
        state='complete',
        progress=100,
        current_stage='complete',
        stage_progress=_pipeline_progress(uploading=100, decompressing=100, packet_parse=100, flow_reconstruction=100, normalization=100, asset_discovery=100, log_source_detection=100, attack_mapping=100, rule_validation=100 if validate_during_analysis else 0, coverage_model=100, storage=100, reports=100 if reports_generated else 0),
        message={'compress_after_analysis':'Analysis complete; PCAP storage compressed with gzip','keep_raw':'Analysis complete; raw PCAP storage retained by policy','delete_after_analysis':'Analysis complete; original PCAP storage deleted after parsing'}.get(storage_policy, 'Analysis complete') + ('; reports generated' if reports_generated else '; reports are available on demand'),
        result_path=str(outdir/'result.json'),
        internal_data_ready=True,
        reports_generated=reports_generated,
    )
