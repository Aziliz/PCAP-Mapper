import os, uuid, csv, json, threading, time, zipfile, shutil, tempfile, traceback
from io import StringIO, BytesIO
from pathlib import Path
from flask import Flask, request, redirect, url_for, render_template, jsonify, send_file, abort, Response
from app.config import UPLOAD_DIR, RESULT_DIR, REPORT_DIR, EXPORT_DIR, MAX_UPLOAD_GB
from app.jobs.manager import start_workers, create_job, create_empty_job, delete_job, rename_job, list_jobs, get_job, _update, pause_job, resume_job, stop_job
from app.rules.engine import load_rules, add_rule, validate_rule, build_validation_results, delete_rule, set_rule_enabled, preview_rule, load_rule_history, export_rules, import_rules_from_file, rule_conflicts, templates as rule_templates, attack_pipeline_diagnostics
from app.utils import read_json, validate_capture, write_json, sha256_file, capture_sha256, expand_supported_upload, is_supported_capture_upload, safe_relative_path, load_storage_settings, save_storage_settings, load_app_settings, save_app_settings, capture_name_exists, register_capture_file, load_capture_inventory, capture_names_for_job, capture_inventory_aliases
from app.attack.versioned import (
    build_data_source_coverage,
    enterprise_coverage_assessment,
    detected_data_sources,
    SOURCE_CATEGORY,
    SOURCE_COMPONENTS,
    RECOMMENDATION_LIBRARY,
    VALID_TECHNIQUES,
    LEGACY_TECHNIQUES,
    TACTIC_DISPLAY_ORDER,
    build_enterprise_attack_coverage_model,
    _detected_coverage_scope,
    _technique_in_detected_scope,
    _is_external_visibility_tactic,
    _external_visibility_reason,
    coverage_engine_from_result,
    attack_version_from_result,
    supported_attack_versions,
    set_attack_version,
    environment_scoped_recommendations,
    _detected_environment_categories,
)
from app.reports.generator import generate_reports
from app.coverage_cache import ensure_coverage_cache, coverage_cache_current

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD_GB * 1024 * 1024 * 1024


def _sorted_jobs_for_nav():
    jobs = list_jobs() or {}
    return sorted(jobs.values(), key=lambda x: x.get('updated', x.get('created', 0)), reverse=True)

def _active_job_id_from_request():
    jid = request.args.get('job') or request.form.get('job')
    if jid and (get_job(jid) or (RESULT_DIR / jid / 'result.json').exists()):
        return jid
    return latest_job_id()

@app.context_processor
def inject_active_job_context():
    jobs = _sorted_jobs_for_nav()
    active_job_id = request.args.get('job') or request.form.get('job') or latest_job_id()
    active_job = get_job(active_job_id) if active_job_id else None
    return {'nav_jobs': jobs, 'nav_active_job_id': active_job_id, 'nav_active_job': active_job}

@app.route('/select-job', methods=['POST'])
def select_active_job():
    jid = request.form.get('job') or ''
    next_url = request.form.get('next') or request.referrer or url_for('dashboard')
    from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
    try:
        parts = urlparse(next_url)
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        if jid:
            query['job'] = jid
        else:
            query.pop('job', None)
        next_url = urlunparse((parts.scheme, parts.netloc, parts.path, parts.params, urlencode(query), parts.fragment))
    except Exception:
        next_url = url_for('dashboard', job=jid) if jid else url_for('dashboard')
    return redirect(next_url)



def is_capture_upload(filename):
    return is_supported_capture_upload(filename)


def safe_relative_upload_path(filename):
    return safe_relative_path(filename)



def existing_capture_hashes(job_id=None):
    """Legacy compatibility shim.

    Duplicate upload prevention now uses the capture inventory table populated
    with uploaded filenames, so the app no longer scans or hashes stored raw/.gz
    captures on each upload.  The function remains for older callers.
    """
    return set()


def existing_capture_names(job_id=None):
    """Return duplicate keys for the selected job from both persisted sources.

    The authoritative fast path is results/capture_inventory.json, but older or
    partially migrated installs may only have the per-job upload_table in
    jobs.json.  Combining both prevents re-upload after captures were compressed
    or deleted.
    """
    jid = job_id or ''
    names = set(capture_names_for_job(jid))
    try:
        job = get_job(jid) or {}
        for row in job.get('upload_table') or []:
            if not isinstance(row, dict):
                continue
            names.update(row.get('aliases') or [])
            names.update(capture_inventory_aliases(row.get('filename') or ''))
            names.update(capture_inventory_aliases(row.get('stored_file') or ''))
            if row.get('key'):
                names.add(row.get('key'))
        for name in job.get('uploaded_files') or []:
            names.update(capture_inventory_aliases(name))
        for name in job.get('files') or []:
            names.update(capture_inventory_aliases(name))
    except Exception:
        pass
    return {x for x in names if x}


def save_unique_capture_uploads(files, append_to=None, progress_cb=None):
    """Save capture uploads, expanding compressed/archive inputs and skipping duplicate filenames.

    Duplicate prevention uses results/capture_inventory.json instead of scanning
    stored raw or .gz captures.  This keeps upload checks fast even when old
    captures have been compressed or deleted by storage policy.
    """
    saved = []
    skipped_duplicates = []
    skipped_invalid = []
    try:
        seen_names = existing_capture_names(append_to or '')
    except Exception as exc:
        seen_names = set()
        skipped_invalid.append({'file': '(capture inventory)', 'reason': f'could not load duplicate filename inventory: {exc}'})
    upload_root = UPLOAD_DIR / f"directory_upload_{uuid.uuid4().hex}"
    staging_root = upload_root / '_archives'
    extracted_root = upload_root / 'captures'
    upload_root.mkdir(parents=True, exist_ok=True)
    file_list = list(files or [])
    total_upload_items = max(1, len(file_list))
    for upload_index, f in enumerate(file_list):
        staging_path = None
        filename = getattr(f, 'filename', '') or ''
        try:
            if not filename:
                continue
            if not is_supported_capture_upload(filename):
                skipped_invalid.append({'file': filename, 'reason': 'unsupported file type'})
                continue
            rel = safe_relative_upload_path(filename)
            staging_path = staging_root / rel
            staging_path.parent.mkdir(parents=True, exist_ok=True)
            if progress_cb:
                progress_cb('uploading', int((upload_index / total_upload_items) * 100), f'Receiving {filename}')
            f.save(staging_path)
            if progress_cb:
                progress_cb('uploading', int(((upload_index + 1) / total_upload_items) * 100), f'Uploaded {filename}')
                progress_cb('decompressing', int((upload_index / total_upload_items) * 100), f'Expanding {filename}')
            expanded_paths, expanded_skipped = expand_supported_upload(staging_path, extracted_root / rel.parent)
            if progress_cb:
                progress_cb('decompressing', int(((upload_index + 1) / total_upload_items) * 100), f'Expanded {filename}')
            skipped_invalid.extend(expanded_skipped or [])
            if not expanded_paths:
                skipped_invalid.append({'file': filename, 'reason': 'no valid PCAP/PCAPNG files found'})
            for path in expanded_paths or []:
                path = Path(path)
                aliases = capture_inventory_aliases(path.name)
                if (aliases & seen_names) or capture_name_exists(path.name, append_to or ''):
                    skipped_duplicates.append({'file': path.name, 'reason': 'filename already exists in capture inventory'})
                    try: path.unlink()
                    except Exception: pass
                    continue
                try:
                    digest = capture_sha256(path)
                except Exception as exc:
                    skipped_invalid.append({'file': path.name, 'reason': f'could not hash capture metadata: {exc}'})
                    digest = ''
                seen_names.update(aliases)
                register_capture_file(path.name, job_id=append_to or '', sha256=digest, stored_file=str(path), status='uploaded')
                saved.append(path)
            if staging_path and staging_path.exists() and staging_path not in saved:
                try:
                    staging_path.unlink()
                except Exception:
                    pass
        except Exception as exc:
            skipped_invalid.append({'file': filename or '(unknown upload)', 'reason': f'upload processing failed: {exc}'})
            try:
                if staging_path and staging_path.exists() and staging_path not in saved:
                    staging_path.unlink()
            except Exception:
                pass
            continue
    if progress_cb:
        progress_cb('uploading', 100, 'Upload complete')
        progress_cb('decompressing', 100, 'Decompression/archive expansion complete')
    return saved, skipped_duplicates, skipped_invalid


DEFAULT_RESULT = {
    'summary': {},
    'hosts': [],
    'flows': [],
    'protocols': {},
    'iocs': {'ips': [], 'domains': [], 'urls': []},
    'findings': [],
    'log_sources': [],
    'techniques': [],
    'normalized_events': [],
    'normalized_event_summary': {},
    'data_source_coverage': [],
    'enterprise_coverage': {},
    'rule_validations': {'summary': {}, 'matches': [], 'validated_techniques': []},
    'validated_techniques': [],
    'rule_validation_status': 'not_run',
    'rule_validation_message': 'Rule validation has not been run yet.',
}



def normalize_result(result):
    """Cheap result normalizer used by all page routes.

    Do not build ATT&CK coverage here.  load_result() is called by most pages,
    so any heavy STIX/rule expansion in this function makes the whole UI feel
    slow.  Coverage is built once at analysis/validation/report time by
    ensure_coverage_cache().
    """
    merged = {**DEFAULT_RESULT, **(result or {})}
    iocs = merged.get('iocs') or {}
    merged['iocs'] = {
        'ips': iocs.get('ips') or [],
        'domains': iocs.get('domains') or [],
        'urls': iocs.get('urls') or [],
    }
    for key in ['hosts', 'flows', 'findings', 'log_sources', 'techniques', 'normalized_events', 'data_source_coverage', 'validated_techniques']:
        merged[key] = merged.get(key) or []
    merged['summary'] = merged.get('summary') or {}
    merged['protocols'] = merged.get('protocols') or {}
    merged['normalized_event_summary'] = merged.get('normalized_event_summary') or {}
    merged['enterprise_coverage'] = merged.get('enterprise_coverage') or {}
    merged['enterprise_attack_coverage_model'] = merged.get('enterprise_attack_coverage_model') or {}
    if not merged.get('rule_validations'):
        merged['rule_validations'] = {'summary': {}, 'matches': [], 'validated_techniques': []}
    if not merged.get('rule_validation_status'):
        merged['rule_validation_status'] = 'not_run'
    if not merged.get('rule_validation_message'):
        merged['rule_validation_message'] = 'Rule validation has not been run yet.'
    return merged



def _attack_registry_for_mode(attack_mode):
    return LEGACY_TECHNIQUES if attack_mode == 'legacy' else VALID_TECHNIQUES


def build_tactic_rollups(result, rules=None, attack_mode='stix'):
    """Build tactic rollups from the canonical Enterprise ATT&CK coverage model.

    Observed and Theoretical no longer use separate data paths.  Theoretical is
    telemetry-supported coverage UNION observed techniques, so anything observed
    is also represented in the theoretical rollup.  Validated remains dependent
    on successful rule validation.
    """
    result = normalize_result(result)
    if attack_mode == 'legacy':
        rules = rules or load_rules()
        registry = LEGACY_TECHNIQUES
        def empty_counts():
            return {t: {'tactic': t, 'name': t.replace('-', ' ').title(), 'covered': 0, 'total': 0, 'score': 0} for t in TACTIC_DISPLAY_ORDER}
        totals = {t: 0 for t in TACTIC_DISPLAY_ORDER}
        for tid, meta in registry.items():
            tactic = meta.get('tactic')
            if tactic in totals:
                totals[tactic] += 1
        observed_ids = {x.get('techniqueID') or x.get('technique_id') for x in result.get('techniques', []) or []}
        theoretical_ids = ({x.get('techniqueID') for x in (result.get('data_source_coverage') or build_data_source_coverage(result)) if x.get('techniqueID')} | observed_ids)
        validated_items = result.get('validated_techniques') or (result.get('rule_validations') or {}).get('validated_techniques') or []
        validated_ids = {x.get('techniqueID') for x in validated_items if x.get('techniqueID')}
        rollups = {'observed': empty_counts(), 'theoretical': empty_counts(), 'validated': empty_counts()}
        for key in rollups:
            for tactic, total in totals.items():
                rollups[key][tactic]['total'] = total
        for dataset, ids in [('observed', observed_ids), ('theoretical', theoretical_ids), ('validated', validated_ids)]:
            for tid in ids:
                meta = registry.get(tid)
                if not meta: continue
                tactic = meta.get('tactic')
                if tactic in rollups[dataset]: rollups[dataset][tactic]['covered'] += 1
            for tactic, row in rollups[dataset].items():
                row['score'] = round((row['covered'] / row['total']) * 100, 1) if row['total'] else 0
        return {key: [rows[t] for t in TACTIC_DISPLAY_ORDER if t in rows] for key, rows in rollups.items()}
    model = result.get('enterprise_attack_coverage_model') or {}
    if not model:
        result, _rebuilt = ensure_coverage_cache(result, rules)
        model = result.get('enterprise_attack_coverage_model') or {}
    return model.get('rollups', {'observed': [], 'theoretical': [], 'validated': []})



def _compact_log_enterprise(enterprise):
    enterprise = enterprise or {}
    keys = [
        'maturity','overall_score','observed_score','theoretical_score','validated_score',
        'observed_count','theoretical_count','validated_count','detectable_count',
        'scoped_technique_total','not_applicable_count','external_visibility_count',
        'coverage_engine','coverage_scope','rule_coverage','readiness','recommendations','gaps'
    ]
    return {k: enterprise.get(k) for k in keys if k in enterprise}


def _compact_log_diagnostics(diag):
    diag = diag or {}
    compact = {
        'coverage_engine': diag.get('coverage_engine'),
        'detected_operating_systems': diag.get('detected_operating_systems', []),
        'detected_os_scope': diag.get('detected_os_scope', []),
        'detected_log_sources': diag.get('detected_log_sources', []),
        'supported_technique_count': diag.get('supported_technique_count', 0),
        'theoretical_technique_count': diag.get('theoretical_technique_count', 0),
        'applicable_technique_count': diag.get('applicable_technique_count', 0),
        'coverage_ratio': diag.get('coverage_ratio', ''),
        'product_inferred_capability_count': diag.get('product_inferred_capability_count', 0),
        'os_inferred_capability_count': diag.get('os_inferred_capability_count', 0),
        'pipeline': diag.get('pipeline', []),
    }
    compact['components'] = (diag.get('components') or [])[:80]
    compact['attack_data_sources'] = (diag.get('attack_data_sources') or [])[:80]
    rows = []
    for row in (diag.get('source_rows') or [])[:160]:
        rows.append({
            'source': row.get('source'), 'category': row.get('category'),
            'components': (row.get('components') or [])[:20],
            'attack_data_sources': (row.get('attack_data_sources') or [])[:12],
            'technique_count': row.get('technique_count', 0),
            'confidence': row.get('confidence'), 'basis': row.get('basis'),
            'inferred': row.get('inferred'), 'reason': row.get('reason'),
        })
    compact['source_rows'] = rows
    compact['unmapped_details'] = (diag.get('unmapped_details') or [])[:80]
    compact['unmapped_sources'] = (diag.get('unmapped_sources') or [])[:80]
    return compact

def build_log_source_view(result):
    """Build page-only telemetry context for the Log Sources view.

    This keeps the underlying analysis data unchanged and only enriches it for
    display/export on /log-sources.
    """
    result = normalize_result(result)
    cache = result.get('log_source_view_cache') or {}
    cov_meta = result.get('coverage_cache') or {}
    if cache.get('coverage_cache_version') == cov_meta.get('version') and cache.get('coverage_engine') == result.get('coverage_engine'):
        return cache.get('view') or {}
    rows = []
    raw = result.get('log_sources', []) or []
    coverage = result.get('data_source_coverage') or []
    coverage_by_source = {}
    for item in coverage:
        for src in item.get('data_sources', []) or []:
            coverage_by_source.setdefault(src, set()).add(item.get('techniqueID'))

    detected = set(detected_data_sources(result))
    # Preserve row-level observations, then add source-level context.
    for idx, lsrc in enumerate(raw):
        evidence_text = ' '.join(str(lsrc.get(k, '')) for k in ['collector', 'protocol', 'port', 'confidence', 'evidence', 'technology', 'log_source', 'source_type'])
        matched = [s for s in detected if s.lower() in evidence_text.lower()]
        if not matched:
            matched = [lsrc.get('technology') or lsrc.get('log_source') or lsrc.get('source_type') or lsrc.get('protocol') or 'Unknown']
        for source in matched[:3]:
            rows.append({
                'id': f'ls-{idx}-{len(rows)}',
                'source': source,
                'category': SOURCE_CATEGORY.get(source, 'Other'),
                'host': lsrc.get('host', ''),
                'collector': lsrc.get('collector', ''),
                'protocol': lsrc.get('protocol', ''),
                'port': lsrc.get('port', ''),
                'confidence': lsrc.get('confidence', 'Observed'),
                'status': lsrc.get('status') or lsrc.get('confidence') or 'Observed',
                'evidence': lsrc.get('evidence', ''),
                'components': SOURCE_COMPONENTS.get(source, []),
                'technique_count': len(coverage_by_source.get(source, set())),
                'first_seen': lsrc.get('first_seen') or lsrc.get('ts') or '',
                'last_seen': lsrc.get('last_seen') or lsrc.get('ts') or '',
            })

    # If no row was directly captured but enterprise telemetry sources were
    # inferred, display source-level entries so the page is still useful.
    existing = {r['source'] for r in rows}
    for source in sorted(detected - existing):
        rows.append({
            'id': f'inferred-{source.lower().replace(" ", "-")}',
            'source': source,
            'category': SOURCE_CATEGORY.get(source, 'Other'),
            'host': '', 'collector': '', 'protocol': '', 'port': '',
            'confidence': 'Inferred', 'status': 'Inferred',
            'evidence': 'Inferred from enterprise telemetry/log-source indicators in the current analysis.',
            'components': SOURCE_COMPONENTS.get(source, []),
            'technique_count': len(coverage_by_source.get(source, set())),
            'first_seen': '', 'last_seen': '',
        })

    overview = {}
    for row in rows:
        overview[row['source']] = overview.get(row['source'], 0) + 1
    categories = {}
    for row in rows:
        categories[row['category']] = categories.get(row['category'], 0) + 1

    enterprise = result.get('enterprise_coverage') or {}
    detected_sources = set(detected)
    expected_by_category = {
        'Windows': ['Windows Security', 'Windows System', 'Windows Application', 'Sysmon', 'PowerShell Operational', 'Defender', 'Defender for Endpoint', 'WinRM', 'WMI', 'SMB', 'Windows DNS', 'Windows DHCP', 'IIS', 'Task Scheduler', 'Windows Firewall', 'AppLocker', 'Windows Event Forwarding', 'RDP', 'Active Directory', 'Certificate Services', 'Winlogbeat'],
        'Linux': ['auditd', 'auth.log', 'secure', 'sudo', 'sshd', 'cron', 'journald', 'systemd', 'kernel', 'rsyslog', 'syslog-ng', 'Apache', 'Nginx', 'Docker', 'containerd', 'Podman', 'Kubernetes Audit', 'SELinux', 'AppArmor', 'osquery', 'Falco'],
        'macOS': ['Apple Unified Logging', 'OpenBSM', 'launchd', 'launchctl', 'Gatekeeper', 'TCC', 'XProtect', 'Jamf', 'Santa', 'osquery', 'Endpoint Security', 'FileVault'],
        'Network': ['Zeek', 'Suricata', 'Packetbeat', 'NetFlow', 'IPFIX', 'Cisco ASA', 'Cisco IOS', 'Cisco NX-OS', 'Cisco Firepower', 'Palo Alto', 'Fortinet', 'Check Point', 'SonicWall', 'pfSense', 'OPNsense', 'Squid', 'HAProxy', 'F5', 'DNS', 'DHCP', 'VPN', 'Wireless Controller', 'Syslog', 'Syslog TLS'],
        'SIEM / Forwarding': ['Elastic Agent', 'Filebeat', 'Auditbeat', 'Fluent Bit', 'Fluentd', 'Vector', 'OpenTelemetry Collector'],
    }
    allowed_missing_categories = _detected_environment_categories(result, detected_sources)
    if not allowed_missing_categories:
        allowed_missing_categories = {'Network', 'SIEM / Forwarding'}
    missing = []
    for cat, names in expected_by_category.items():
        if cat not in allowed_missing_categories:
            continue
        for name in names:
            if name not in detected_sources:
                missing.append({'category': cat, 'source': name, 'reason': 'Not detected in this capture or current telemetry inventory.'})

    rule_list = load_rules()
    dependencies = {}
    for rule in rule_list:
        reqs = rule.get('required_telemetry') or rule.get('dependencies') or []
        if isinstance(reqs, str):
            reqs = [reqs]
        blob = ' '.join(str(x) for x in reqs + [rule.get('description',''), rule.get('name','')])
        for source in detected_sources:
            if source.lower() in blob.lower():
                dependencies.setdefault(source, []).append(rule.get('name', 'Unnamed rule'))

    recommendations = environment_scoped_recommendations(result, detected_sources, 8)

    timeline = []
    for row in rows:
        ts = row.get('first_seen') or row.get('last_seen')
        if ts:
            timeline.append({'time': ts, 'source': row['source'], 'host': row.get('host',''), 'evidence': row.get('evidence','')})
    timeline = sorted(timeline, key=lambda x: str(x.get('time','')))[:100]

    view = {
        'rows': rows,
        'overview': dict(sorted(overview.items(), key=lambda x: (-x[1], x[0]))),
        'categories': dict(sorted(categories.items())),
        'enterprise': _compact_log_enterprise(enterprise),
        'missing': missing[:30],
        'recommendations': recommendations,
        'dependencies': dependencies,
        'timeline': timeline,
        'diagnostics': _compact_log_diagnostics(enterprise.get('theoretical_diagnostics', {})),
    }
    result['log_source_view_cache'] = {
        'coverage_cache_version': (result.get('coverage_cache') or {}).get('version'),
        'coverage_engine': result.get('coverage_engine'),
        'view': view,
    }
    return view


def save_result_for_job(jid, result):
    if not jid:
        return
    out = RESULT_DIR / jid / 'result.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    write_json(out, result)


def mark_validation_stale(reason='Rules changed; validation should be re-run.'):
    jobs = list_jobs()
    for jid, job in jobs.items():
        p = RESULT_DIR / jid / 'result.json'
        if not p.exists():
            continue
        result = read_json(p, {})
        if not result:
            continue
        result['rule_validation_status'] = 'stale'
        result['rule_validation_message'] = reason
        # Preserve prior validation evidence for review, but invalidate cached
        # detectable/validated coverage because enabled rules changed.
        meta = result.get('coverage_cache') or {}
        meta['stale'] = True
        meta['stale_reason'] = reason
        result['coverage_cache'] = meta
        write_json(p, result)


VALIDATION_LOCK = threading.Lock()
VALIDATION_THREADS = set()


def update_rule_validation_progress(jid, status, progress, message):
    """Persist rule-validation progress for the current job."""
    if not jid:
        return
    result, _ = load_result(jid)
    result['rule_validation_status'] = status
    result['rule_validation_progress'] = int(progress)
    result['rule_validation_message'] = message
    save_result_for_job(jid, result)
    _update(jid, rule_validation_status=status, rule_validation_progress=int(progress), rule_validation_message=message, current_stage='rule_validation', stage_progress={'uploading':100,'decompressing':100,'packet_parse':100,'rule_validation':int(progress)})


def run_rule_validation_for_job(jid):
    result, jid = load_result(jid)
    if not jid:
        return result, None
    update_rule_validation_progress(jid, 'running', 5, 'Rule validation started.')
    rules = load_rules()
    update_rule_validation_progress(jid, 'running', 15, f'Loaded {len(rules)} rules; evaluating current analysis.')
    validations = build_validation_results(result, rules)
    update_rule_validation_progress(jid, 'running', 85, 'Rule matches complete; rebuilding ATT&CK coverage.')
    result, _ = load_result(jid)
    result['rule_validations'] = validations
    result['validated_techniques'] = validations.get('validated_techniques', [])
    result['attack_pipeline_diagnostics'] = validations.get('attack_pipeline_diagnostics') or attack_pipeline_diagnostics(result, validations, rules)
    result['rule_validation_status'] = 'complete'
    result['rule_validation_progress'] = 100
    result['rule_validation_message'] = 'Rule validation completed on demand.'
    result, _rebuilt = ensure_coverage_cache(result, rules, force=True)
    save_result_for_job(jid, result)
    _update(jid, rule_validation_status='complete', rule_validation_progress=100, rule_validation_message='Rule validation completed on demand.')
    return result, jid


def start_rule_validation_for_job(jid):
    """Start validation in the background so the page can show progress."""
    if not jid:
        return None
    with VALIDATION_LOCK:
        if jid in VALIDATION_THREADS:
            return jid
        result, _ = load_result(jid)
        if result.get('rule_validation_status') == 'running':
            return jid
        update_rule_validation_progress(jid, 'running', 0, 'Queued rule validation.')
        VALIDATION_THREADS.add(jid)

    def _runner():
        try:
            run_rule_validation_for_job(jid)
        except Exception as exc:
            result, _ = load_result(jid)
            result['rule_validation_status'] = 'failed'
            result['rule_validation_progress'] = result.get('rule_validation_progress', 0)
            result['rule_validation_message'] = f'Rule validation failed: {exc}'
            save_result_for_job(jid, result)
            _update(jid, rule_validation_status='failed', rule_validation_progress=result.get('rule_validation_progress', 0), rule_validation_message=result['rule_validation_message'])
        finally:
            with VALIDATION_LOCK:
                VALIDATION_THREADS.discard(jid)

    threading.Thread(target=_runner, daemon=True).start()
    return jid

def start_services():
    start_workers()


def latest_job_id():
    jobs=list_jobs()
    if not jobs: return None
    return sorted(jobs.values(), key=lambda x:x.get('updated',x.get('created',0)), reverse=True)[0]['id']




def rule_from_form(form, network=False):
    rule={
        'name': form.get('name','Custom Rule'),
        'description': form.get('description',''),
        'event_type': form.get('event_type') or 'flow',
        'protocol': form.get('protocol') or None,
        'port': int(form.get('port') or 0) or None,
        'severity': form.get('severity','medium'),
        'severity_override': form.get('severity_override') or '',
        'confidence': form.get('confidence') or 'medium',
        'version': form.get('version') or '1.0',
        'attack': [x.strip() for x in form.get('attack','').split(',') if x.strip()],
        'requires': [x.strip() for x in form.get('requires','').split(',') if x.strip()],
        'exclude_src_ips': [x.strip() for x in form.get('exclude_src_ips','').split(',') if x.strip()],
        'exclude_dst_ips': [x.strip() for x in form.get('exclude_dst_ips','').split(',') if x.strip()],
        'exclude_protocols': [x.strip() for x in form.get('exclude_protocols','').split(',') if x.strip()],
    }
    if network:
        rule['rule_type']='network'
    return {k:v for k,v in rule.items() if v not in [None,'',[]]}

def load_result(jid=None):
    jid = jid or latest_job_id()
    if not jid:
        return normalize_result({}), None
    p = RESULT_DIR / jid / 'result.json'
    return normalize_result(read_json(p, {})), jid

@app.route('/', methods=['GET','POST'])
def dashboard():
    duplicate_message = ''
    invalid_upload_message = ''
    if request.method == 'POST':
        try:
            if request.form.get('action') == 'new_job':
                jid = create_empty_job()
                return redirect(url_for('dashboard', job=jid))
            files = request.files.getlist('pcaps')
            append_to = request.form.get('append_to') or None
            # Duplicate-upload tracking is per job. If this form starts a new
            # analysis, create the job before saving files so the upload table
            # is attached to that specific job instead of a global bucket.
            jid_for_upload = append_to or create_empty_job()
            saved, duplicate_uploads, invalid_uploads = save_unique_capture_uploads(files, append_to=jid_for_upload)
            if saved:
                jid = create_job(saved, append_to=jid_for_upload, validate_during_analysis=(request.form.get('validate_during_analysis') == '1'), run_reports_during_analysis=(request.form.get('run_reports_during_analysis') == '1'))
                return redirect(url_for('job_status', job_id=jid))
            if duplicate_uploads:
                duplicate_message = f"Skipped {len(duplicate_uploads)} duplicate file(s); no new PCAPs were added."
            if invalid_uploads:
                invalid_upload_message = f"Ignored {len(invalid_uploads)} unsupported or invalid file(s): " + '; '.join((x.get('file','?') + ' - ' + x.get('reason','')) for x in invalid_uploads[:5])
        except Exception as exc:
            invalid_upload_message = f"Upload failed before analysis could start: {exc}"
    result,jid=load_result(request.args.get('job'))
    jobs=list_jobs()
    return render_template('dashboard.html', result=result, job_id=jid, jobs=jobs, duplicate_message=duplicate_message, invalid_upload_message=invalid_upload_message)


@app.route('/api/upload-job', methods=['POST'])
def api_upload_job():
    """XHR upload endpoint used by the dashboard to show upload progress.

    Browser-side progress covers bytes sent to Flask. Server-side stage fields
    then cover decompression/archive expansion and parsing via the job API.
    The endpoint returns JSON for recoverable upload failures instead of an
    HTML 500 page so the UI can show the skipped-file reason.
    """
    jid = None
    try:
        append_to = request.form.get('append_to') or None
        jid = append_to or create_empty_job()
        _update(jid, state='uploading', progress=0, current_stage='uploading', message='Uploading captures', stage_progress={'uploading':0,'decompressing':0,'packet_parse':0,'storage':0,'rule_validation':0})
        files = request.files.getlist('pcaps')
        def cb(stage, pct, message):
            job = get_job(jid) or {}
            sp = job.get('stage_progress') or {'uploading':0,'decompressing':0,'packet_parse':0,'storage':0,'rule_validation':0}
            sp[stage] = max(0, min(100, int(pct)))
            overall = int((sp.get('uploading',0)*0.25) + (sp.get('decompressing',0)*0.25))
            _update(jid, state='uploading' if stage != 'decompressing' else 'decompressing', current_stage=stage, progress=overall, stage_progress=sp, message=message)
        saved, duplicate_uploads, invalid_uploads = save_unique_capture_uploads(files, append_to=jid, progress_cb=cb)
        if saved:
            jid = create_job(saved, append_to=jid, validate_during_analysis=(request.form.get('validate_during_analysis') == '1'), run_reports_during_analysis=(request.form.get('run_reports_during_analysis') == '1'))
            return jsonify({'ok': True, 'job_id': jid, 'job_url': url_for('job_status', job_id=jid), 'duplicates': duplicate_uploads, 'invalid': invalid_uploads})
        msg = 'No new captures were added'
        if invalid_uploads:
            msg += ': ' + '; '.join((x.get('file','?') + ' - ' + x.get('reason','')) for x in invalid_uploads[:5])
        _update(jid, state='new', progress=0, current_stage='uploading', message=msg, stage_progress={'uploading':100,'decompressing':100,'packet_parse':0,'storage':0,'rule_validation':0})
        return jsonify({'ok': False, 'job_id': jid, 'job_url': url_for('dashboard', job=jid), 'duplicates': duplicate_uploads, 'invalid': invalid_uploads, 'message': msg})
    except Exception as exc:
        if jid:
            try:
                _update(jid, state='failed', progress=0, current_stage='uploading', message=f'Upload failed: {exc}', upload_traceback=traceback.format_exc())
            except Exception:
                pass
        return jsonify({'ok': False, 'job_id': jid, 'job_url': url_for('dashboard', job=jid) if jid else url_for('dashboard'), 'message': f'Upload failed: {exc}', 'error': str(exc)}), 200

@app.route('/jobs/<job_id>')
def job_status(job_id):
    return render_template('job.html', job=get_job(job_id), job_id=job_id)

@app.route('/api/jobs/<job_id>')
def api_job(job_id):
    return jsonify(get_job(job_id) or {})


@app.route('/jobs/<job_id>/pause', methods=['POST'])
def pause_job_route(job_id):
    ok, msg = pause_job(job_id)
    next_url = request.form.get('next') or request.referrer or url_for('job_status', job_id=job_id)
    if request.headers.get('Accept','').startswith('application/json'):
        return jsonify({'ok': ok, 'message': msg, 'job': get_job(job_id) or {}})
    return redirect(next_url)


@app.route('/jobs/<job_id>/resume', methods=['POST'])
def resume_job_route(job_id):
    ok, msg = resume_job(job_id)
    next_url = request.form.get('next') or request.referrer or url_for('job_status', job_id=job_id)
    if request.headers.get('Accept','').startswith('application/json'):
        return jsonify({'ok': ok, 'message': msg, 'job': get_job(job_id) or {}})
    return redirect(next_url)


@app.route('/jobs/<job_id>/stop', methods=['POST'])
def stop_job_route(job_id):
    ok, msg = stop_job(job_id)
    next_url = request.form.get('next') or request.referrer or url_for('job_status', job_id=job_id)
    if request.headers.get('Accept','').startswith('application/json'):
        return jsonify({'ok': ok, 'message': msg, 'job': get_job(job_id) or {}})
    return redirect(next_url)

@app.route('/api/chunk/init', methods=['POST'])
def chunk_init():
    data=request.json or {}
    upload_id=uuid.uuid4().hex
    d=UPLOAD_DIR/'chunks'/upload_id; d.mkdir(parents=True, exist_ok=True)
    write_json(d/'meta.json', {'filename': Path(data.get('filename','upload.pcap')).name, 'size': data.get('size'), 'sha256': data.get('sha256')})
    return jsonify({'upload_id': upload_id})

@app.route('/api/chunk/<upload_id>/<int:index>', methods=['PUT'])
def chunk_put(upload_id,index):
    d=UPLOAD_DIR/'chunks'/upload_id; d.mkdir(parents=True, exist_ok=True)
    (d/f'{index:08d}.part').write_bytes(request.get_data())
    return jsonify({'ok': True, 'index': index})

@app.route('/api/chunk/<upload_id>/complete', methods=['POST'])
def chunk_complete(upload_id):
    d=UPLOAD_DIR/'chunks'/upload_id
    meta=read_json(d/'meta.json', {})
    out=UPLOAD_DIR/f"{uuid.uuid4().hex}_{meta.get('filename','upload.pcap')}"
    with open(out,'wb') as dst:
        for part in sorted(d.glob('*.part')):
            dst.write(part.read_bytes())
    payload = request.json or {}
    expand_root = UPLOAD_DIR / f"chunk_upload_{uuid.uuid4().hex}"
    expanded_paths, expanded_skipped = expand_supported_upload(out, expand_root)
    if not expanded_paths:
        try:
            out.unlink()
        except Exception:
            pass
        return jsonify({'ok': False, 'error': 'No valid PCAP/PCAPNG files found', 'skipped': expanded_skipped}), 400
    jid_for_upload = payload.get('append_to') or create_empty_job()
    seen_names = existing_capture_names(jid_for_upload)
    saved = []
    duplicates = []
    hashes = []
    for path in expanded_paths:
        digest = capture_sha256(path)
        aliases = capture_inventory_aliases(path.name)
        if (aliases & seen_names) or capture_name_exists(path.name, jid_for_upload):
            duplicates.append({'file': path.name, 'reason': 'filename already exists in capture inventory'})
            try: path.unlink()
            except Exception: pass
            continue
        seen_names.update(aliases)
        register_capture_file(path.name, job_id=jid_for_upload, sha256=digest, stored_file=str(path), status='uploaded')
        hashes.append(digest)
        saved.append(path)
    try:
        if out.exists() and out not in saved:
            out.unlink()
    except Exception:
        pass
    if not saved:
        return jsonify({'ok': False, 'duplicate': True, 'error': 'Duplicate PCAP skipped; this file is already attached to the selected job.', 'duplicates': duplicates}), 409
    jid=create_job(saved, append_to=jid_for_upload, validate_during_analysis=bool(payload.get('validate_during_analysis')))
    return jsonify({'ok': True, 'job_id': jid, 'files': [str(p) for p in saved], 'sha256': hashes, 'duplicates': duplicates, 'skipped': expanded_skipped})

@app.route('/assets')
def assets():
    result,jid=load_result(request.args.get('job'))
    return render_template('assets.html', result=result, job_id=jid)

@app.route('/communications')
def communications():
    result,jid=load_result(request.args.get('job'))
    return render_template('communications.html', result=result, job_id=jid)




def filter_normalized_events(events, args):
    def contains(value, needle):
        return not needle or needle.lower() in str(value or '').lower()
    q=(args.get('q') or '').strip()
    platform=(args.get('platform') or '').strip()
    log_source=(args.get('log_source') or '').strip()
    event_type=(args.get('event_type') or '').strip()
    host=(args.get('host') or '').strip()
    attack=(args.get('attack') or '').strip()
    out=[]
    for e in events or []:
        raw_blob=' '.join(str(e.get(k,'')) for k in ['raw','event_type','log_source','host','user','process','command_line'])
        if q and q.lower() not in raw_blob.lower(): continue
        if not contains(e.get('platform'), platform): continue
        if not contains(e.get('log_source'), log_source): continue
        if not contains(e.get('event_type'), event_type): continue
        if not contains(e.get('host'), host): continue
        if attack and attack.lower() not in ' '.join(e.get('attack_candidates') or []).lower(): continue
        out.append(e)
    return out


def related_flows_for_event(event, flows, limit=20):
    if not event:
        return []
    ips={event.get('src_ip'), event.get('dst_ip'), event.get('host')}
    ips={x for x in ips if x and str(x).count('.')==3}
    matches=[]
    for f in flows or []:
        if f.get('src_ip') in ips or f.get('dst_ip') in ips:
            matches.append(f)
            if len(matches) >= limit: break
    return matches


def build_combined_timeline(result, limit=500):
    items=[]
    for ev in result.get('normalized_events', []) or []:
        items.append({'time': ev.get('timestamp') or '', 'kind': 'event', 'src': ev.get('src_ip') or ev.get('host') or '', 'dst': ev.get('dst_ip') or '', 'context': f"{ev.get('log_source','')} / {ev.get('event_type','')}", 'attack': ', '.join(ev.get('attack_candidates') or [])})
    for f in result.get('flows', []) or []:
        items.append({'time': f.get('first_seen') or '', 'kind': 'flow', 'src': f.get('src_ip') or '', 'dst': f.get('dst_ip') or '', 'context': f"{f.get('protocol','')}:{f.get('dport','')} packets={f.get('packets',0)} bytes={f.get('bytes',0)}", 'attack': ''})
    for m in (result.get('rule_validations') or {}).get('matches', []) or []:
        items.append({'time': m.get('timestamp') or '', 'kind': 'rule_match', 'src': m.get('src_ip') or '', 'dst': m.get('dst_ip') or '', 'context': m.get('rule') or '', 'attack': ', '.join(m.get('attack') or [])})
    return sorted(items, key=lambda x: str(x.get('time','')))[:limit]

@app.route('/events')
def events_page():
    result, jid = load_result(request.args.get('job'))
    events = filter_normalized_events(result.get('normalized_events', []), request.args)
    selected = None
    event_id = request.args.get('event_id')
    if event_id:
        selected = next((e for e in result.get('normalized_events', []) if e.get('event_id') == event_id), None)
    filters = {k: request.args.get(k, '') for k in ['q','platform','log_source','event_type','host','attack']}
    unmapped = [e for e in events if not e.get('attack_candidates')]
    return render_template('events.html', events=events, summary=result.get('normalized_event_summary', {}), job_id=jid, filters=filters, selected_event=selected, related_flows=related_flows_for_event(selected, result.get('flows', [])), unmapped=unmapped)

@app.route('/events/export/<fmt>')
def export_events(fmt):
    result, jid = load_result(request.args.get('job'))
    events = filter_normalized_events(result.get('normalized_events', []), request.args)
    if fmt == 'json':
        return send_file(BytesIO(json.dumps({'job_id': jid, 'events': events}, indent=2, default=str).encode()), as_attachment=True, download_name='normalized_events.json', mimetype='application/json')
    if fmt == 'csv':
        out = StringIO(); fields=['timestamp','platform','log_source','event_type','host','user','process','src_ip','dst_ip','attack_candidates','confidence','raw']
        w=csv.DictWriter(out, fieldnames=fields); w.writeheader()
        for e in events:
            row=dict(e); row['attack_candidates']=', '.join(e.get('attack_candidates') or []); w.writerow({k: row.get(k,'') for k in fields})
        return Response(out.getvalue(), mimetype='text/csv', headers={'Content-Disposition':'attachment; filename=normalized_events.csv'})
    if fmt == 'md':
        lines=['# Normalized Events','',f'Job: {jid or ""}','']
        for e in events[:2000]:
            lines.append(f"- **{e.get('event_type','')}** `{e.get('log_source','')}` host={e.get('host','')} ATT&CK={', '.join(e.get('attack_candidates') or [])}")
        return send_file(BytesIO('\n'.join(lines).encode()), as_attachment=True, download_name='normalized_events.md', mimetype='text/markdown')
    if fmt == 'ndjson':
        buf=[]
        for e in events:
            buf.append(json.dumps({'index': {'_index': 'pcap-normalized-events'}})); buf.append(json.dumps(e, default=str))
        return send_file(BytesIO(('\n'.join(buf)+'\n').encode()), as_attachment=True, download_name='normalized_events.ndjson', mimetype='application/x-ndjson')
    abort(404)

@app.route('/timeline')
def timeline_page():
    result, jid = load_result(request.args.get('job'))
    return render_template('timeline.html', timeline=build_combined_timeline(result), job_id=jid)

@app.route('/events/rule-from-event', methods=['POST'])
def rule_from_event():
    result, jid = load_result(request.form.get('job'))
    event_id = request.form.get('event_id')
    ev = next((e for e in result.get('normalized_events', []) if e.get('event_id') == event_id), None)
    if not ev:
        return redirect(url_for('events_page', job=jid))
    attacks = ev.get('attack_candidates') or []
    if not attacks:
        return redirect(url_for('events_page', job=jid, event_id=event_id))
    rule = {
        'name': 'Event: ' + (ev.get('event_type') or ev.get('log_source') or 'Normalized Event'),
        'description': 'Generated from normalized event evidence.',
        'event_type': ev.get('event_type') or 'event',
        'severity': 'medium',
        'confidence': ev.get('confidence') or 'medium',
        'version': '1.0',
        'attack': attacks[:5],
        'requires': [ev.get('log_source')] if ev.get('log_source') else [],
    }
    add_rule(rule)
    mark_validation_stale('Rules changed; validation should be re-run.')
    return redirect(url_for('rules', job=jid))

@app.route('/log-sources')
def log_sources():
    result,jid=load_result(request.args.get('job'))
    result, rebuilt = ensure_coverage_cache(result)
    if rebuilt and jid:
        save_result_for_job(jid, result)
    telemetry = build_log_source_view(result)
    if jid and result.get('log_source_view_cache'):
        save_result_for_job(jid, result)
    return render_template('log_sources.html', result=result, job_id=jid, telemetry=telemetry)

@app.route('/log-sources/export/<fmt>')
def export_log_sources(fmt):
    result,jid=load_result(request.args.get('job'))
    result, rebuilt = ensure_coverage_cache(result)
    if rebuilt and jid:
        save_result_for_job(jid, result)
    telemetry = build_log_source_view(result)
    rows = telemetry.get('rows', [])
    if fmt == 'json':
        payload = json.dumps({'job_id': jid, 'telemetry': telemetry}, indent=2, default=str).encode('utf-8')
        return send_file(BytesIO(payload), as_attachment=True, download_name='telemetry_inventory.json', mimetype='application/json')
    if fmt == 'csv':
        out = StringIO()
        writer = csv.DictWriter(out, fieldnames=['source','category','host','collector','protocol','port','confidence','status','technique_count','components','evidence','first_seen','last_seen'])
        writer.writeheader()
        for row in rows:
            r = dict(row)
            r['components'] = '; '.join(row.get('components', []))
            writer.writerow({k: r.get(k, '') for k in writer.fieldnames})
        return Response(out.getvalue(), mimetype='text/csv', headers={'Content-Disposition':'attachment; filename=telemetry_inventory.csv'})
    abort(404)



def build_legacy_heatmap_display(result, rules):
    """Return a display-only result copy that uses the older bundled ATT&CK registry.

    This does not alter the saved analysis. It only lets the MITRE Heat Map page
    render the pre-STIX/legacy technique universe for users who want to compare
    the old heat-map behavior with the official STIX-based behavior.
    """
    legacy = LEGACY_TECHNIQUES
    out = dict(result or {})
    out['techniques'] = [t for t in (out.get('techniques') or []) if (t.get('techniqueID') or t.get('technique_id')) in legacy]
    ds = out.get('data_source_coverage') or build_data_source_coverage(out)
    out['data_source_coverage'] = [t for t in ds if t.get('techniqueID') in legacy]
    validated_items = out.get('validated_techniques') or (out.get('rule_validations') or {}).get('validated_techniques') or []
    out['validated_techniques'] = [t for t in validated_items if t.get('techniqueID') in legacy]

    observed = {t.get('techniqueID') or t.get('technique_id') for t in out.get('techniques', []) if (t.get('techniqueID') or t.get('technique_id')) in legacy}
    covered = {t.get('techniqueID'): t for t in out.get('data_source_coverage', []) if t.get('techniqueID') in legacy}
    validated = {t.get('techniqueID') for t in out.get('validated_techniques', []) if t.get('techniqueID') in legacy}
    rule_techs = set()
    for r in rules or []:
        for tid in r.get('attack', []) or r.get('techniques', []) or []:
            if tid in legacy:
                rule_techs.add(tid)

    # Apply the same detected OS/log-source scope to legacy display mode so
    # legacy heat maps do not mark out-of-scope techniques as uncovered.
    try:
        coverage_scope = _detected_coverage_scope(out, detected_data_sources(out))
        applicable_ids = {tid for tid, meta in legacy.items() if (not _is_external_visibility_tactic(meta.get('tactic',''))) and (_technique_in_detected_scope(tid, meta, coverage_scope) or tid in observed or tid in covered or tid in validated)}
    except Exception:
        coverage_scope = []
        applicable_ids = set()

    totals = {t: 0 for t in TACTIC_DISPLAY_ORDER}
    counts = {t: 0 for t in TACTIC_DISPLAY_ORDER}
    sums = {t: 0 for t in TACTIC_DISPLAY_ORDER}
    for tid, meta in legacy.items():
        if tid not in applicable_ids:
            continue
        tac = meta.get('tactic')
        if tac in totals:
            totals[tac] += 1
            if tid in covered:
                counts[tac] += 1
                sums[tac] += float(covered[tid].get('score', 0))

    tactic_coverage = []
    for tac in TACTIC_DISPLAY_ORDER:
        total = totals.get(tac, 0)
        cnt = counts.get(tac, 0)
        avg_strength = (sums.get(tac, 0) / cnt) if cnt else 0
        coverage_pct = round((cnt / total) * 100, 1) if total else 0
        effective_score = round((coverage_pct * 0.65) + (avg_strength * 0.35), 1) if total else 0
        tactic_coverage.append({'tactic': tac, 'name': tac.replace('-', ' ').title(), 'covered': cnt, 'total': total, 'coverage_pct': coverage_pct, 'avg_strength': round(avg_strength, 1), 'score': effective_score})

    coverage_states = []
    for tid, meta in legacy.items():
        external_visibility = _is_external_visibility_tactic(meta.get('tactic', ''))
        applicable = (tid in applicable_ids) and not external_visibility
        is_obs = tid in observed
        is_cov = tid in covered
        score = covered[tid].get('score', 0) if is_cov else 0
        if external_visibility:
            state = 'Out of Enterprise Visibility'
            score = 0
        elif not applicable:
            state = 'Not Applicable'
            score = 0
        elif is_obs and is_cov and tid in validated:
            state = 'Validated'
        elif is_obs and is_cov:
            state = 'Observed + Covered'
        elif is_obs:
            state = 'Observed Only'
        elif is_cov and score >= 70:
            state = 'Covered'
        elif is_cov:
            state = 'Partially Covered'
        elif tid in rule_techs:
            state = 'Detectable'
        else:
            state = 'Not Covered'
        coverage_states.append({'techniqueID': tid, 'name': meta.get('name', tid), 'tactic': meta.get('tactic', ''), 'state': state, 'score': score, 'rule': tid in rule_techs, 'validated': tid in validated, 'applicable': applicable, 'external_visibility': external_visibility, 'external_visibility_reason': _external_visibility_reason(meta.get('tactic', ''))})

    known_total = len(applicable_ids)
    covered_total = len([tid for tid in covered if tid in applicable_ids])
    avg_strength = sum(float(covered[tid].get('score', 0)) for tid in covered if tid in applicable_ids) / covered_total if covered_total else 0
    breadth = (covered_total / known_total) * 100 if known_total else 0
    overall = round((breadth * 0.65) + (avg_strength * 0.35), 1) if known_total else 0
    ec = dict(out.get('enterprise_coverage') or {})
    ec.update({
        'basis': 'legacy heat-map processing',
        'attack_version': 'legacy bundled registry',
        'overall_score': overall,
        'maturity': 'High' if overall >= 75 else 'Moderate' if overall >= 55 else 'Basic' if overall >= 30 else 'Limited',
        'coverage_scope': coverage_scope,
        'scoped_technique_total': known_total,
        'not_applicable_count': len(legacy) - known_total - len([1 for _tid, _meta in legacy.items() if _is_external_visibility_tactic(_meta.get('tactic',''))]),
        'external_visibility_count': len([1 for _tid, _meta in legacy.items() if _is_external_visibility_tactic(_meta.get('tactic',''))]),
        'tactic_coverage': tactic_coverage,
        'coverage_states': coverage_states,
        'rule_coverage': {'techniques_with_rules': len(rule_techs), 'covered_with_rules': len([tid for tid in covered if tid in rule_techs]), 'detectable_without_rules': max(0, covered_total - len([tid for tid in covered if tid in rule_techs])), 'validated_techniques': len(validated)},
        'executive_summary': 'Legacy heat-map processing is selected. This view uses the older bundled ATT&CK registry and legacy rollup behavior for comparison with the official STIX-based mode.',
    })
    out['enterprise_coverage'] = ec
    return out




def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _attack_ids_from_obj(obj):
    ids = []
    if not isinstance(obj, dict):
        return ids
    for key in ('techniqueID','technique_id','attack_id','attackId','id'):
        v = obj.get(key)
        if isinstance(v, str) and v.upper().startswith('T'):
            ids.append(v)
    for key in ('attack','attacks','attack_ids','attack_candidates','techniques','mitre','validated_techniques'):
        for item in _as_list(obj.get(key)):
            if isinstance(item, str) and item.upper().startswith('T'):
                ids.append(item)
            elif isinstance(item, dict):
                ids.extend(_attack_ids_from_obj(item))
    return sorted({x for x in ids if x})


def _first_ip_from_obj(obj, prefer_source=True):
    if not isinstance(obj, dict):
        return ''
    source_keys = ('src_ip','source_ip','source','src','client_ip','remote_ip','host_ip','ip')
    other_keys = ('dst_ip','destination_ip','destination','dst','server_ip','peer_ip')
    keys = source_keys + other_keys if prefer_source else other_keys + source_keys
    for key in keys:
        v = obj.get(key)
        if isinstance(v, str) and v and any(ch.isdigit() for ch in v):
            return v
    return ''


def _short_text(value, limit=220):
    if value is None:
        return ''
    if not isinstance(value, str):
        try:
            value = json.dumps(value, default=str)
        except Exception:
            value = str(value)
    value = ' '.join(value.split())
    return value[:limit] + ('...' if len(value) > limit else '')


def _observed_drilldown_index(result):
    """Build technique -> source IP/details for observed MITRE overlay cards.

    This is intentionally tolerant because result structures vary between parser
    generations, imported jobs, and legacy/STIX coverage modes.
    """
    idx = {}
    def add(tid, source, obj):
        if not tid:
            return
        row = idx.setdefault(tid, {
            'source_ip': '', 'dst_ip': '', 'host': '', 'sources': set(),
            'events': 0, 'flows': 0, 'evidence': [], 'event_ids': [], 'flow_ids': [], 'full_event': ''
        })
        row['sources'].add(source)
        if source == 'event': row['events'] += 1
        if source == 'flow': row['flows'] += 1
        if not row['source_ip']:
            row['source_ip'] = _first_ip_from_obj(obj, True)
        if not row['dst_ip']:
            for k in ('dst_ip','destination_ip','destination','dst','server_ip'):
                if isinstance(obj, dict) and obj.get(k): row['dst_ip'] = str(obj.get(k)); break
        if not row['host']:
            for k in ('host','hostname','asset','computer','computer_name'):
                if isinstance(obj, dict) and obj.get(k): row['host'] = str(obj.get(k)); break
        if isinstance(obj, dict):
            if not row.get('full_event') and source == 'event':
                try:
                    row['full_event'] = json.dumps(obj, indent=2, sort_keys=True, default=str)
                except Exception:
                    row['full_event'] = str(obj)
            eid = obj.get('event_id') or obj.get('id')
            fid = obj.get('flow_id') or obj.get('uid')
            if eid and len(row['event_ids']) < 5: row['event_ids'].append(str(eid))
            if fid and len(row['flow_ids']) < 5: row['flow_ids'].append(str(fid))
            ev = obj.get('evidence') or obj.get('reason') or obj.get('rationale') or obj.get('raw') or obj.get('summary') or obj.get('event_type') or obj.get('protocol')
            ev = _short_text(ev)
            if ev and ev not in row['evidence'] and len(row['evidence']) < 5:
                row['evidence'].append(ev)
    for e in result.get('normalized_events', []) or []:
        for tid in _attack_ids_from_obj(e):
            add(tid, 'event', e)
    for f in result.get('flows', []) or []:
        for tid in _attack_ids_from_obj(f):
            add(tid, 'flow', f)
    for t in result.get('techniques', []) or []:
        for tid in _attack_ids_from_obj(t):
            add(tid, 'technique', t)
    for row in idx.values():
        row['sources'] = ', '.join(sorted(row['sources']))
        row['evidence_text'] = ' | '.join(row['evidence'])
        row['full_event_text'] = row.get('full_event', '')
    return idx


def annotate_observed_drilldowns(result):
    ec = result.get('enterprise_coverage') or {}
    states = ec.get('coverage_states') or []
    if not states:
        return result
    idx = _observed_drilldown_index(result)
    for st in states:
        tid = st.get('techniqueID') or st.get('technique_id')
        if not tid or not st.get('observed'):
            continue
        d = idx.get(tid, {})
        st['observed_source_ip'] = d.get('source_ip', '')
        st['observed_dst_ip'] = d.get('dst_ip', '')
        st['observed_host'] = d.get('host', '')
        st['observed_sources'] = d.get('sources', '')
        st['observed_event_count'] = d.get('events', 0)
        st['observed_flow_count'] = d.get('flows', 0)
        st['observed_evidence'] = d.get('evidence_text', '')
        st['observed_full_event'] = d.get('full_event_text', '')
        st['observed_event_ids'] = d.get('event_ids', [])
        st['observed_flow_ids'] = d.get('flow_ids', [])
    result['enterprise_coverage'] = ec
    return result


def build_mitre_page_context(job_arg=None, attack_mode_arg=None, coverage_engine_arg=None, attack_version_arg=None):
    """Shared MITRE page context for Coverage, Data Sources, and Normalized Events pages."""
    result, jid = load_result(job_arg)
    attack_mode = (attack_mode_arg or 'stix').lower()
    if attack_mode not in ('stix', 'legacy'):
        attack_mode = 'stix'
    coverage_engine = coverage_engine_from_result(result, coverage_engine_arg)
    attack_version = attack_version_from_result(result, attack_version_arg)
    set_attack_version(attack_version)
    result['coverage_engine'] = coverage_engine
    result['attack_version_selected'] = attack_version
    rules = None
    if attack_mode == 'legacy':
        # Legacy mode is explicitly comparative and may need its older transform.
        rules = load_rules()
        result['data_source_coverage'] = result.get('data_source_coverage') or build_data_source_coverage(result, coverage_engine)
        result = build_legacy_heatmap_display(result, rules)
    else:
        result, rebuilt = ensure_coverage_cache(result)
        if rebuilt and jid:
            save_result_for_job(jid, result)
    result = annotate_observed_drilldowns(result)
    tactic_rollups = build_tactic_rollups(result, rules, attack_mode=attack_mode)
    return result, jid, attack_mode, tactic_rollups, coverage_engine, attack_version

@app.route('/mitre')
def mitre():
    result, jid, attack_mode, tactic_rollups, coverage_engine, attack_version = build_mitre_page_context(request.args.get('job'), request.args.get('attack_mode'), request.args.get('coverage_engine'), request.args.get('attack_version'))
    return render_template('mitre.html', result=result, job_id=jid, tactic_rollups=tactic_rollups, attack_mode=attack_mode, coverage_engine=coverage_engine, attack_version=attack_version, supported_attack_versions=supported_attack_versions())

@app.route('/mitre/coverage')
def mitre_coverage():
    result, jid, attack_mode, tactic_rollups, coverage_engine, attack_version = build_mitre_page_context(request.args.get('job'), request.args.get('attack_mode'), request.args.get('coverage_engine'), request.args.get('attack_version'))
    return render_template('mitre.html', result=result, job_id=jid, tactic_rollups=tactic_rollups, attack_mode=attack_mode, coverage_engine=coverage_engine, attack_version=attack_version, supported_attack_versions=supported_attack_versions())

@app.route('/mitre/data-sources')
def mitre_data_sources():
    result, jid, attack_mode, tactic_rollups, coverage_engine, attack_version = build_mitre_page_context(request.args.get('job'), request.args.get('attack_mode'), request.args.get('coverage_engine'), request.args.get('attack_version'))
    return render_template('mitre_data_sources.html', result=result, job_id=jid, tactic_rollups=tactic_rollups, attack_mode=attack_mode, coverage_engine=coverage_engine, attack_version=attack_version, supported_attack_versions=supported_attack_versions())

@app.route('/mitre/normalized-events')
def mitre_normalized_events():
    result, jid, attack_mode, tactic_rollups, coverage_engine, attack_version = build_mitre_page_context(request.args.get('job'), request.args.get('attack_mode'), request.args.get('coverage_engine'), request.args.get('attack_version'))
    return render_template('mitre_normalized_events.html', result=result, job_id=jid, tactic_rollups=tactic_rollups, attack_mode=attack_mode, coverage_engine=coverage_engine, attack_version=attack_version, supported_attack_versions=supported_attack_versions())

@app.route('/rules', methods=['GET','POST'])
def rules():
    result,jid=load_result(request.args.get('job'))
    preview=None; errors=None
    if request.method == 'POST':
        rule=rule_from_form(request.form)
        action=request.form.get('action','add')
        if action == 'preview':
            preview = preview_rule(rule, result)
        else:
            ok, errors = add_rule(rule)
            if ok:
                mark_validation_stale('Rules changed; validation should be re-run.')
                return redirect(url_for('rules'))
    return render_template('rules.html', rules=load_rules(), result=result, job_id=jid, validation=result.get('rule_validations'), errors=errors, preview=preview, conflicts=rule_conflicts(load_rules()), history=load_rule_history(), templates=rule_templates())


@app.route('/network-rules', methods=['GET','POST'])
def network_rules():
    result,jid=load_result(request.args.get('job'))
    preview=None; errors=None
    if request.method == 'POST':
        rule=rule_from_form(request.form, network=True)
        action=request.form.get('action','add')
        if action == 'preview':
            preview = preview_rule(rule, result)
        else:
            ok, errors = add_rule(rule)
            if ok:
                mark_validation_stale('Rules changed; validation should be re-run.')
                return redirect(url_for('network_rules'))
    rules=[r for r in load_rules() if r.get('rule_type') == 'network' or r.get('event_type') in ['flow','dns','icmp','http','tls','network']]
    return render_template('network_rules.html', rules=rules, result=result, job_id=jid, validation=result.get('rule_validations'), errors=errors, preview=preview, conflicts=rule_conflicts(rules), history=load_rule_history(), templates=rule_templates())





@app.route('/rules/<rule_id>/delete', methods=['POST'])
def delete_detection_rule(rule_id):
    delete_rule(rule_id)
    mark_validation_stale('Rules changed; validation should be re-run.')
    return redirect(url_for('rules'))

@app.route('/rules/<rule_id>/toggle', methods=['POST'])
def toggle_detection_rule(rule_id):
    enabled = request.form.get('enabled') == '1'
    set_rule_enabled(rule_id, enabled)
    mark_validation_stale('Rules changed; validation should be re-run.')
    return redirect(url_for('rules'))

@app.route('/network-rules/<rule_id>/delete', methods=['POST'])
def delete_network_rule(rule_id):
    delete_rule(rule_id)
    mark_validation_stale('Rules changed; validation should be re-run.')
    return redirect(url_for('network_rules'))

@app.route('/network-rules/<rule_id>/toggle', methods=['POST'])
def toggle_network_rule(rule_id):
    enabled = request.form.get('enabled') == '1'
    set_rule_enabled(rule_id, enabled)
    mark_validation_stale('Rules changed; validation should be re-run.')
    return redirect(url_for('network_rules'))

@app.route('/api/rule-validation/<job_id>')
def api_rule_validation_status(job_id):
    result, jid = load_result(job_id)
    summary = (result.get('rule_validations') or {}).get('summary', {})
    return jsonify({
        'job_id': jid,
        'status': result.get('rule_validation_status', 'not_run'),
        'progress': int(result.get('rule_validation_progress', 0) or 0),
        'message': result.get('rule_validation_message', 'Rule validation has not been run yet.'),
        'summary': summary,
    })

@app.route('/rules/validate', methods=['POST'])
def validate_rules_now():
    jid = start_rule_validation_for_job(request.form.get('job') or None)
    return redirect(url_for('rules', job=jid) if jid else url_for('rules'))

@app.route('/network-rules/validate', methods=['POST'])
def validate_network_rules_now():
    jid = start_rule_validation_for_job(request.form.get('job') or None)
    return redirect(url_for('network_rules', job=jid) if jid else url_for('network_rules'))

@app.route('/mitre/validate', methods=['POST'])
def validate_rules_from_mitre():
    attack_mode = (request.form.get('attack_mode') or request.args.get('attack_mode') or 'stix').lower()
    if attack_mode not in ('stix', 'legacy'):
        attack_mode = 'stix'
    coverage_engine = coverage_engine_from_result(None, request.form.get('coverage_engine') or request.args.get('coverage_engine'))
    jid = start_rule_validation_for_job(request.form.get('job') or None)
    return redirect(url_for('mitre', job=jid, attack_mode=attack_mode, coverage_engine=coverage_engine) if jid else url_for('mitre', attack_mode=attack_mode, coverage_engine=coverage_engine))


@app.route('/rules/template/<int:index>', methods=['POST'])
def add_rule_template(index):
    items = rule_templates()
    if index < 0 or index >= len(items): abort(404)
    add_rule(items[index])
    mark_validation_stale('Rules changed; validation should be re-run.')
    return redirect(url_for('rules'))

@app.route('/network-rules/template/<int:index>', methods=['POST'])
def add_network_rule_template(index):
    items = rule_templates()
    if index < 0 or index >= len(items): abort(404)
    rule = dict(items[index]); rule['rule_type']='network'
    add_rule(rule)
    mark_validation_stale('Rules changed; validation should be re-run.')
    return redirect(url_for('network_rules'))

@app.route('/rules/export')
def export_rule_pack():
    path = export_rules()
    return send_file(path, as_attachment=True, download_name='pcap_mapper_rule_pack.json')

@app.route('/rules/import', methods=['POST'])
def import_rule_pack():
    f=request.files.get('rule_pack')
    if not f or not f.filename:
        return redirect(url_for('rules'))
    path=UPLOAD_DIR / f'rule_import_{uuid.uuid4().hex}.json'
    f.save(path)
    import_rules_from_file(path)
    mark_validation_stale('Rules changed; validation should be re-run.')
    return redirect(url_for('rules'))

@app.route('/network-rules/import', methods=['POST'])
def import_network_rule_pack():
    f=request.files.get('rule_pack')
    if not f or not f.filename:
        return redirect(url_for('network_rules'))
    path=UPLOAD_DIR / f'rule_import_{uuid.uuid4().hex}.json'
    f.save(path)
    import_rules_from_file(path)
    mark_validation_stale('Rules changed; validation should be re-run.')
    return redirect(url_for('network_rules'))

@app.route('/rules/guide')
def rule_guide():
    return render_template('rule_guide.html')

@app.route('/reports/guide')
def reports_guide():
    return render_template('report_guide.html')


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    message = request.args.get('message') or ''
    if request.method == 'POST':
        profile = request.form.get('performance_profile') or 'balanced'
        policy = request.form.get('archive_policy') or 'delete_after_analysis'
        include_default = request.form.get('include_captures_in_exports_default') in ('1','true','yes','on')
        reports_background = request.form.get('reports_background') in ('1','true','yes','on')
        backup_type = request.form.get('default_backup_type') or 'job'
        if backup_type not in ('job', 'configuration', 'workspace'):
            backup_type = 'job'
        save_app_settings({'performance_profile': profile, 'include_captures_in_exports_default': include_default, 'default_backup_type': backup_type, 'reports_background': reports_background})
        save_storage_settings({'archive_policy': policy, 'include_captures_in_exports_default': include_default})
        return redirect(url_for('settings', message='Settings saved. Performance profile changes apply to newly started worker threads after restart.'))
    
    telemetry_registry = {'plugin_count': 0, 'categories': {}}
    try:
        from app.telemetry.registry import plugin_summary
        telemetry_registry = plugin_summary()
    except Exception:
        pass
    return render_template('settings.html', app_settings=load_app_settings(), storage_settings=load_storage_settings(), storage_stats=_storage_stats(), message=message, telemetry_registry=telemetry_registry)



@app.route('/reports')
def reports():
    jobs=list_jobs()
    return render_template('reports.html', jobs=jobs)


def _merge_stage_progress(job_id, **updates):
    job = get_job(job_id) or {}
    sp = dict(job.get('stage_progress') or {})
    for key, value in updates.items():
        try:
            sp[key] = max(0, min(100, int(value)))
        except Exception:
            sp[key] = 0
    return sp

@app.route('/reports/<job_id>/generate', methods=['POST'])
def generate_job_reports(job_id):
    _update(job_id, current_stage='reports', message='Generating reports', stage_progress=_merge_stage_progress(job_id, reports=15))
    result, _ = load_result(job_id)
    _update(job_id, current_stage='reports', message='Writing report and export files', stage_progress=_merge_stage_progress(job_id, reports=55))
    generate_reports(job_id, result, None)
    save_result_for_job(job_id, result)
    _update(job_id, reports_generated=True, reports_generated_at=__import__('time').time(), current_stage='reports', stage_progress=_merge_stage_progress(job_id, reports=100), message='Reports generated on demand')
    return redirect(url_for('reports'))


@app.route('/jobs/<job_id>/rename', methods=['POST'])
def rename_job_route(job_id):
    name = request.form.get('name') or request.form.get('job_name') or ''
    rename_job(job_id, name)
    next_url = request.form.get('next') or request.referrer or url_for('job_status', job_id=job_id)
    return redirect(next_url)



def _safe_copy_tree_into_zip(zf, base_dir, arc_prefix):
    base_dir = Path(base_dir)
    if not base_dir.exists():
        return
    for path in base_dir.rglob('*'):
        if path.is_file():
            zf.write(path, str(Path(arc_prefix) / path.relative_to(base_dir)))



def _backup_config_payload():
    """Return user-created/custom configuration only; never bundled built-ins."""
    payload = {
        'app_settings': load_app_settings(),
        'storage_settings': load_storage_settings(),
        'rules': {
            'custom_rules': read_json(RESULT_DIR / 'custom_rules.json', []),
            'rule_state': read_json(RESULT_DIR / 'rule_state.json', {}),
            'rule_history': read_json(RESULT_DIR / 'rule_validation_history.json', []),
        },
        'telemetry': {'version': 2, 'export_scope': 'custom_only', 'custom_plugins': [], 'disabled_plugins': []},
        'environment_profiles': {'custom_profiles': [], 'modified_profiles': [], 'manual_overrides': read_json(RESULT_DIR / 'environment_profile_overrides.json', {})},
    }
    try:
        from app.telemetry import registry as tr
        payload['telemetry'] = tr.export_plugins_json()
    except Exception:
        pass
    # Remove derived/runtime-only settings from persisted backup payload.
    payload['app_settings'].pop('performance_profiles', None)
    payload['app_settings'].pop('logical_cores', None)
    payload['app_settings'].pop('worker_count', None)
    return payload


def _write_config_payload(zf, payload):
    zf.writestr('config/app_settings.json', json.dumps(payload.get('app_settings', {}), indent=2, default=str))
    zf.writestr('config/storage_settings.json', json.dumps(payload.get('storage_settings', {}), indent=2, default=str))
    zf.writestr('rules/custom_rules.json', json.dumps(payload.get('rules', {}).get('custom_rules', []), indent=2, default=str))
    zf.writestr('rules/rule_state.json', json.dumps(payload.get('rules', {}).get('rule_state', {}), indent=2, default=str))
    zf.writestr('rules/rule_history.json', json.dumps(payload.get('rules', {}).get('rule_history', []), indent=2, default=str))
    zf.writestr('telemetry/custom_plugins.json', json.dumps(payload.get('telemetry', {}), indent=2, default=str))
    zf.writestr('environment/custom_profiles.json', json.dumps(payload.get('environment_profiles', {}), indent=2, default=str))


def _export_previous_results_archive(job_ids=None, include_captures=False, backup_type=None):
    """Create a portable backup ZIP.

    Backup types:
      - job: selected/all job data plus generated reports/exports and custom configuration.
      - configuration: custom settings/rules/telemetry only, no jobs.
      - workspace: all jobs plus custom configuration.

    Built-in telemetry plugins, bundled ATT&CK datasets, built-in reports, and other
    application-shipped resources are intentionally excluded.
    """
    backup_type = backup_type or load_app_settings().get('default_backup_type', 'job') or 'job'
    if backup_type not in ('job', 'configuration', 'workspace'):
        backup_type = 'job'
    jobs = list_jobs() or {}
    if backup_type == 'configuration':
        selected = {}
    elif backup_type == 'workspace':
        selected = jobs
    elif job_ids:
        selected = {jid: jobs[jid] for jid in job_ids if jid in jobs}
    else:
        selected = jobs

    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    out = EXPORT_DIR / f"pcap_mapper_{backup_type}_backup_{uuid.uuid4().hex}.zip"
    config_payload = _backup_config_payload()
    includes = []
    if selected:
        includes.extend(['jobs', 'results', 'reports', 'exports'])
    if include_captures and selected:
        includes.append('captures')
    includes.extend(['settings', 'custom_rules', 'custom_telemetry_plugins', 'custom_environment_profiles'])
    manifest = {
        'format': 'pcap_mapper_backup',
        'version': 2,
        'backup_type': backup_type,
        'exported_at': time.time(),
        'include_captures': bool(include_captures and selected),
        'jobs': selected,
        'includes': includes,
        'excludes': ['built_in_telemetry_plugins', 'built_in_attack_bundles', 'built_in_reports', 'application_code'],
        'app_version': 'v2',
        'attack_version': config_payload.get('app_settings', {}).get('attack_version') or config_payload.get('app_settings', {}).get('mitre_attack_version'),
        'coverage_engine': config_payload.get('app_settings', {}).get('coverage_engine'),
    }
    with zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('manifest.json', json.dumps(manifest, indent=2, default=str))
        _write_config_payload(zf, config_payload)
        capture_manifest = {}
        for jid in selected:
            _safe_copy_tree_into_zip(zf, RESULT_DIR / jid, Path('jobs') / jid / 'results')
            _safe_copy_tree_into_zip(zf, REPORT_DIR / jid, Path('jobs') / jid / 'reports')
            _safe_copy_tree_into_zip(zf, EXPORT_DIR / jid, Path('jobs') / jid / 'exports')
            # Legacy-compatible paths for older imports.
            _safe_copy_tree_into_zip(zf, RESULT_DIR / jid, Path('results') / jid)
            _safe_copy_tree_into_zip(zf, REPORT_DIR / jid, Path('reports') / jid)
            _safe_copy_tree_into_zip(zf, EXPORT_DIR / jid, Path('exports') / jid)
            if include_captures:
                capture_manifest[jid] = []
                meta = selected.get(jid) or {}
                for file_path in meta.get('files', []) or []:
                    try:
                        src = Path(file_path)
                        if not src.exists() or not src.is_file():
                            continue
                        arc = Path('captures') / jid / src.name
                        zf.write(src, str(arc))
                        capture_manifest[jid].append({'original_path': str(src), 'archive_path': str(arc), 'filename': src.name})
                    except Exception:
                        continue
        if include_captures and selected:
            zf.writestr('capture_manifest.json', json.dumps(capture_manifest, indent=2, default=str))
    return out


def _merge_imported_configuration(td):
    """Merge custom backup configuration without overwriting built-ins."""
    # Settings are merged shallowly so local defaults survive when absent.
    app_payload = read_json(td / 'config' / 'app_settings.json', {})
    if isinstance(app_payload, dict) and app_payload:
        save_app_settings(app_payload)
    storage_payload = read_json(td / 'config' / 'storage_settings.json', {})
    if isinstance(storage_payload, dict) and storage_payload:
        save_storage_settings(storage_payload)

    # Rules: merge custom rules by id/name, then merge state/history.
    imported_rules = read_json(td / 'rules' / 'custom_rules.json', [])
    if isinstance(imported_rules, list) and imported_rules:
        existing = read_json(RESULT_DIR / 'custom_rules.json', [])
        by_key = {}
        for rule in existing if isinstance(existing, list) else []:
            if isinstance(rule, dict):
                key = str(rule.get('id') or rule.get('name') or uuid.uuid4()).casefold()
                by_key[key] = rule
        for rule in imported_rules:
            if isinstance(rule, dict):
                key = str(rule.get('id') or rule.get('name') or uuid.uuid4()).casefold()
                by_key[key] = rule
        write_json(RESULT_DIR / 'custom_rules.json', list(by_key.values()))
    imported_state = read_json(td / 'rules' / 'rule_state.json', {})
    if isinstance(imported_state, dict) and imported_state:
        current_state = read_json(RESULT_DIR / 'rule_state.json', {})
        current_state.update(imported_state)
        write_json(RESULT_DIR / 'rule_state.json', current_state)
    imported_history = read_json(td / 'rules' / 'rule_history.json', [])
    if isinstance(imported_history, list) and imported_history:
        current_history = read_json(RESULT_DIR / 'rule_validation_history.json', [])
        write_json(RESULT_DIR / 'rule_validation_history.json', (current_history if isinstance(current_history, list) else []) + imported_history)

    telemetry_payload = read_json(td / 'telemetry' / 'custom_plugins.json', {})
    if telemetry_payload:
        try:
            from app.telemetry import registry as tr
            tr.import_plugins_json(telemetry_payload)
        except Exception:
            pass
    env_payload = read_json(td / 'environment' / 'custom_profiles.json', {})
    if isinstance(env_payload, dict) and env_payload:
        # No built-in profile data is overwritten; keep user overrides separately.
        current = read_json(RESULT_DIR / 'environment_profile_overrides.json', {})
        if not isinstance(current, dict):
            current = {}
        current.update(env_payload.get('manual_overrides') or {})
        if env_payload.get('custom_profiles'):
            current.setdefault('custom_profiles', [])
            current['custom_profiles'].extend(env_payload.get('custom_profiles') or [])
        write_json(RESULT_DIR / 'environment_profile_overrides.json', current)

def _safe_extract_backup(zf, dest):
    dest = Path(dest).resolve()
    for member in zf.infolist():
        target = (dest / member.filename).resolve()
        if not str(target).startswith(str(dest)):
            raise ValueError('backup contains unsafe paths')
    zf.extractall(dest)


def _import_previous_results_archive(path):
    """Import a previous-results ZIP. Existing job IDs are preserved unless they collide."""
    imported = []
    with tempfile.TemporaryDirectory(prefix='pcap_mapper_import_') as td:
        td = Path(td)
        with zipfile.ZipFile(path) as zf:
            _safe_extract_backup(zf, td)
        manifest = read_json(td / 'manifest.json', {})
        if manifest.get('format') not in ('pcap_mapper_previous_results', 'pcap_mapper_backup'):
            raise ValueError('not a PCAP Mapper backup')
        if manifest.get('format') == 'pcap_mapper_backup':
            _merge_imported_configuration(td)
        incoming_jobs = manifest.get('jobs') or {}
        capture_manifest = read_json(td / 'capture_manifest.json', {})
        jobs = list_jobs() or {}
        for old_jid, meta in incoming_jobs.items():
            new_jid = old_jid if old_jid not in jobs else str(uuid.uuid4())
            imported.append(new_jid)
            for src_root, dst_root in ((td/'results'/old_jid, RESULT_DIR/new_jid), (td/'reports'/old_jid, REPORT_DIR/new_jid), (td/'exports'/old_jid, EXPORT_DIR/new_jid)):
                if src_root.exists():
                    if dst_root.exists():
                        shutil.rmtree(dst_root, ignore_errors=True)
                    dst_root.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copytree(src_root, dst_root)
            restored_files = []
            for item in (capture_manifest.get(old_jid) or []):
                src = td / item.get('archive_path', '')
                if src.exists() and src.is_file():
                    dst_dir = UPLOAD_DIR / 'imported_results' / new_jid
                    dst_dir.mkdir(parents=True, exist_ok=True)
                    dst = dst_dir / Path(item.get('filename') or src.name).name
                    if dst.exists():
                        dst = dst_dir / f"{uuid.uuid4().hex}_{dst.name}"
                    shutil.copy2(src, dst)
                    restored_files.append(str(dst))
            new_meta = dict(meta or {})
            if restored_files:
                new_meta['files'] = restored_files
                new_meta['restored_captures'] = True
            new_meta['id'] = new_jid
            new_meta['imported_at'] = time.time()
            new_meta['updated'] = time.time()
            new_meta['result_path'] = str(RESULT_DIR / new_jid / 'result.json')
            new_meta.setdefault('state', 'complete')
            if new_jid != old_jid:
                new_meta['name'] = 'Imported ' + str(new_meta.get('name') or f'Job {old_jid[:8]}')
                new_meta['source_job_id'] = old_jid
            new_meta['message'] = 'Imported previous result backup'
            jobs[new_jid] = new_meta
        write_json(RESULT_DIR / 'jobs.json', jobs)
    return imported


def _storage_stats():
    jobs = list_jobs() or {}
    raw = compressed = missing = captures = 0
    for meta in jobs.values():
        for file_path in meta.get('files', []) or []:
            try:
                p = Path(file_path)
                if not p.exists() or not p.is_file():
                    missing += 1
                    continue
                captures += 1
                size = p.stat().st_size
                if p.name.lower().endswith('.gz'):
                    compressed += size
                else:
                    raw += size
            except Exception:
                missing += 1
    total = raw + compressed
    savings = None
    # Prefer actual per-file compression telemetry when available.
    original_total = compressed_total = 0
    for jid in jobs:
        result = read_json(RESULT_DIR / jid / 'result.json', {})
        for item in result.get('processed_files', []) or []:
            sc = item.get('storage_compression') or {}
            if sc.get('original_size') and sc.get('compressed_size'):
                original_total += int(sc.get('original_size') or 0)
                compressed_total += int(sc.get('compressed_size') or 0)
    if original_total and compressed_total:
        savings = round((1 - (compressed_total / original_total)) * 100, 1)
    inv = load_capture_inventory()
    inventory_count = len(inv.get('files') or [])
    job_inventory_count = len(inv.get('jobs') or {})
    return {'raw_bytes': raw, 'compressed_bytes': compressed, 'total_bytes': total, 'capture_count': captures, 'missing_count': missing, 'compression_savings_percent': savings, 'inventory_count': inventory_count, 'job_inventory_count': job_inventory_count}

@app.route('/storage/settings', methods=['POST'])
def storage_settings_route():
    policy = request.form.get('archive_policy') or 'delete_after_analysis'
    include_default = request.form.get('include_captures_in_exports_default') in ('1','true','yes','on')
    save_storage_settings({'archive_policy': policy, 'include_captures_in_exports_default': include_default})
    save_app_settings({'include_captures_in_exports_default': include_default})
    return redirect(url_for('settings', message='Storage settings updated.'))

@app.route('/previous')
def previous():
    return render_template('previous.html', jobs=list_jobs(), import_message=request.args.get('import_message'), storage_settings=load_storage_settings(), storage_stats=_storage_stats())

@app.route('/previous/export')
def export_previous_all():
    include_arg = request.args.get('include_captures')
    include_captures = (include_arg in ('1','true','yes','on')) if include_arg is not None else bool(load_storage_settings().get('include_captures_in_exports_default'))
    backup_type = request.args.get('type') or load_app_settings().get('default_backup_type', 'job')
    path = _export_previous_results_archive(include_captures=include_captures, backup_type=backup_type)
    return send_file(path, as_attachment=True, download_name=f'pcap_mapper_{backup_type}_backup.zip')

@app.route('/previous/<job_id>/export')
def export_previous_job(job_id):
    include_arg = request.args.get('include_captures')
    include_captures = (include_arg in ('1','true','yes','on')) if include_arg is not None else bool(load_storage_settings().get('include_captures_in_exports_default'))
    backup_type = request.args.get('type') or 'job'
    if backup_type not in ('job', 'configuration', 'workspace'):
        backup_type = 'job'
    path = _export_previous_results_archive([job_id], include_captures=include_captures, backup_type=backup_type)
    return send_file(path, as_attachment=True, download_name=f'pcap_mapper_{backup_type}_{job_id}.zip')

@app.route('/previous/import', methods=['POST'])
def import_previous_results():
    f = request.files.get('previous_results')
    if not f or not f.filename:
        return redirect(url_for('previous', import_message='No backup ZIP selected.'))
    path = UPLOAD_DIR / f'previous_results_import_{uuid.uuid4().hex}.zip'
    f.save(path)
    try:
        imported = _import_previous_results_archive(path)
        msg = f'Imported {len(imported)} previous result(s).'
    except Exception as exc:
        msg = f'Import failed: {exc}'
    finally:
        try: path.unlink()
        except Exception: pass
    return redirect(url_for('previous', import_message=msg))

@app.route('/previous/<job_id>/delete', methods=['POST'])
def delete_previous_result(job_id):
    delete_job(job_id)
    return redirect(url_for('previous'))

@app.route('/download/<job_id>/<kind>/<path:name>')
def download(job_id, kind, name):
    base = {'report': REPORT_DIR/job_id, 'export': EXPORT_DIR/job_id, 'result': RESULT_DIR/job_id}.get(kind)
    if not base: abort(404)
    path=(base/name).resolve()
    if not str(path).startswith(str(base.resolve())) or not path.exists(): abort(404)
    return send_file(path, as_attachment=True)

# Telemetry plugin registry UI
def _has_active_dataset(result, jid):
    if not jid or not isinstance(result, dict):
        return False
    for key in ('normalized_events', 'events', 'flows', 'assets', 'communications', 'log_sources', 'detected_log_sources', 'processed_files'):
        value = result.get(key)
        if isinstance(value, (list, tuple, dict)) and len(value) > 0:
            return True
    return False


def _telemetry_runtime(plugin_matches, has_dataset):
    if not has_dataset:
        return {}
    runtime = {}
    for p in plugin_matches or []:
        runtime[p.get('name')] = {
            'observed_count': len(p.get('observed_components') or []),
            'potential_count': len(p.get('potential_components') or []),
            'matched_aliases': p.get('matched_aliases') or [],
            'observed_components': p.get('observed_components') or [],
            'potential_components': p.get('potential_components') or [],
        }
    return runtime


@app.route('/telemetry')
def telemetry_home():
    return redirect(url_for('telemetry_plugins_page', **request.args))


@app.route('/telemetry/plugins', methods=['GET', 'POST'])
def telemetry_plugins_page():
    from app.telemetry import registry as tr
    message = request.args.get('message') or ''
    category = request.args.get('category') or 'All categories'
    search = (request.args.get('search') or '').strip()
    test_results = []
    sample = ''
    if request.method == 'POST':
        sample = request.form.get('sample_log') or ''
        test_results = tr.test_sample(sample)
    plugins = tr.get_plugins(include_disabled=True)
    if category and category != 'All categories':
        plugins = [p for p in plugins if p.get('category') == category]
    if search:
        q = search.lower()
        plugins = [p for p in plugins if q in str(p.get('name','')).lower() or q in str(p.get('description','')).lower() or any(q in str(a).lower() for a in (p.get('aliases') or []))]
    validation = tr.validate_plugins()
    active_result, active_jid = load_result(request.args.get('job'))
    has_dataset = _has_active_dataset(active_result, active_jid)
    observed_matches = tr.observed_plugin_matches(active_result) if has_dataset else []
    runtime_by_plugin = _telemetry_runtime(observed_matches, has_dataset)
    library_summary = tr.plugin_summary()
    library_summary['observed_component_definitions'] = sum(len(p.get('observed_components') or []) for p in tr.get_plugins(include_disabled=True))
    library_summary['potential_component_definitions'] = sum(len(p.get('potential_components') or []) for p in tr.get_plugins(include_disabled=True))
    return render_template(
        'telemetry.html',
        plugins=plugins,
        categories=tr.categories(include_all=True),
        selected_category=category,
        search=search,
        validation=validation,
        test_results=test_results,
        sample=sample,
        message=message,
        has_active_dataset=has_dataset,
        active_dataset_job_id=active_jid,
        runtime_by_plugin=runtime_by_plugin,
        observed_matches=observed_matches,
        library_summary=library_summary,
    )


@app.route('/telemetry/profile')
def telemetry_environment_profile_page():
    from app.telemetry import registry as tr
    active_result, active_jid = load_result(request.args.get('job'))
    has_dataset = _has_active_dataset(active_result, active_jid)
    profile_assessment = tr.auto_select_environment_profile(active_result) if has_dataset else {
        'selected': 'No active dataset',
        'ranked': [],
        'observed_plugins': [],
        'observed_categories': [],
    }
    return render_template(
        'environment_profile.html',
        profiles=tr.environment_profiles(),
        profile_assessment=profile_assessment,
        active_profile_job_id=active_jid,
        has_active_dataset=has_dataset,
    )


def _telemetry_redirect(message):
    args = {'message': message}
    category = request.form.get('return_category') or request.args.get('category')
    search = request.form.get('return_search') or request.args.get('search')
    if category:
        args['category'] = category
    if search:
        args['search'] = search
    return redirect(url_for('telemetry_plugins_page', **args))

@app.route('/telemetry/new', methods=['POST'])
def telemetry_new_plugin():
    from app.telemetry import registry as tr
    tr.upsert_custom_plugin({
        'name': request.form.get('name'),
        'category': request.form.get('category'),
        'aliases': request.form.get('aliases'),
        'observed_components': request.form.get('observed_components'),
        'potential_components': request.form.get('potential_components'),
        'description': request.form.get('description'),
        'confidence': request.form.get('confidence') or 'high',
        'enabled': request.form.get('enabled') in ('1','true','yes','on'),
    })
    return _telemetry_redirect('Telemetry plugin saved.')

@app.route('/telemetry/<path:name>/update', methods=['POST'])
def telemetry_update_plugin(name):
    from app.telemetry import registry as tr
    tr.upsert_custom_plugin({
        'name': request.form.get('name') or name,
        'category': request.form.get('category'),
        'aliases': request.form.get('aliases'),
        'observed_components': request.form.get('observed_components'),
        'potential_components': request.form.get('potential_components'),
        'description': request.form.get('description'),
        'confidence': request.form.get('confidence') or 'high',
        'enabled': request.form.get('enabled') in ('1','true','yes','on'),
    })
    return _telemetry_redirect('Telemetry plugin updated.')

@app.route('/telemetry/<path:name>/delete', methods=['POST'])
def telemetry_delete_plugin(name):
    from app.telemetry import registry as tr
    tr.delete_plugin(name)
    return _telemetry_redirect('Telemetry plugin removed or disabled.')

@app.route('/telemetry/<path:name>/toggle', methods=['POST'])
def telemetry_toggle_plugin(name):
    from app.telemetry import registry as tr
    tr.set_plugin_enabled(name, request.form.get('enabled') in ('1','true','yes','on'))
    return _telemetry_redirect('Telemetry plugin status updated.')

@app.route('/telemetry/export')
def telemetry_export_plugins():
    from app.telemetry import registry as tr
    payload = json.dumps(tr.export_plugins_json(), indent=2, sort_keys=True).encode('utf-8')
    return send_file(BytesIO(payload), as_attachment=True, download_name='pcap_mapper_telemetry_plugins.json', mimetype='application/json')

@app.route('/telemetry/import', methods=['POST'])
def telemetry_import_plugins():
    from app.telemetry import registry as tr
    f = request.files.get('plugin_file')
    if not f or not f.filename:
        return redirect(url_for('telemetry_plugins_page', message='No plugin file selected.'))
    data = json.loads(f.read().decode('utf-8'))
    count = tr.import_plugins_json(data)
    return redirect(url_for('telemetry_plugins_page', message=f'Imported {count} telemetry plugin(s).'))
