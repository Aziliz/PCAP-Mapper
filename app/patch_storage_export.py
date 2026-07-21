from pathlib import Path
p=Path('/mnt/data/pcap23/app/config.py')
s=p.read_text()
add="""

# Capture archival policy. Runtime UI settings are stored in results/storage_settings.json;
# this environment value is used as the default for new installs.
# Supported: compress_after_analysis, keep_raw, delete_after_analysis
STORAGE_ARCHIVE_POLICY = os.getenv('STORAGE_ARCHIVE_POLICY', 'compress_after_analysis')
"""
if 'STORAGE_ARCHIVE_POLICY' not in s:
    p.write_text(s+add)

p=Path('/mnt/data/pcap23/app/utils.py')
s=p.read_text()
if 'STORAGE_SETTINGS_FILE' not in s:
    insert="""

STORAGE_SETTINGS_FILE = Path(os.getenv('STORAGE_SETTINGS_FILE', Path(__file__).resolve().parents[1] / 'results' / 'storage_settings.json'))
SUPPORTED_STORAGE_POLICIES = {'compress_after_analysis', 'keep_raw', 'delete_after_analysis'}


def load_storage_settings() -> dict:
    default_policy = os.getenv('STORAGE_ARCHIVE_POLICY', 'compress_after_analysis')
    if default_policy not in SUPPORTED_STORAGE_POLICIES:
        default_policy = 'compress_after_analysis'
    data = read_json(STORAGE_SETTINGS_FILE, {}) if STORAGE_SETTINGS_FILE.exists() else {}
    policy = data.get('archive_policy') or default_policy
    if policy not in SUPPORTED_STORAGE_POLICIES:
        policy = default_policy
    return {
        'archive_policy': policy,
        'include_captures_in_exports_default': bool(data.get('include_captures_in_exports_default', False)),
    }


def save_storage_settings(settings: dict) -> dict:
    current = load_storage_settings()
    current.update(settings or {})
    if current.get('archive_policy') not in SUPPORTED_STORAGE_POLICIES:
        current['archive_policy'] = 'compress_after_analysis'
    STORAGE_SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    write_json(STORAGE_SETTINGS_FILE, current)
    return current


def remove_capture_file(path: Path) -> dict:
    path = Path(path)
    info = {'original_file': str(path), 'deleted': False}
    if path.exists() and path.is_file():
        info['original_size'] = path.stat().st_size
        try:
            path.unlink()
            info['deleted'] = True
        except Exception as exc:
            info['reason'] = str(exc)
    else:
        info['reason'] = 'missing file'
    return info
"""
    s=s.replace('\ndef gzip_capture_file(path: Path) -> dict:', insert+'\n\ndef gzip_capture_file(path: Path) -> dict:')
    p.write_text(s)

# Patch manager imports and compression policy
p=Path('/mnt/data/pcap23/app/jobs/manager.py')
s=p.read_text()
s=s.replace('from app.utils import capture_sha256, write_json, read_json, validate_capture, gzip_capture_file', 'from app.utils import capture_sha256, write_json, read_json, validate_capture, gzip_capture_file, load_storage_settings, remove_capture_file')
s=s.replace("    ctx=AnalysisContext(); rules=load_rules(); plugins=load_plugins(); cps=_checkpoints(); processed=[]; skipped=[]", "    ctx=AnalysisContext(); rules=load_rules(); plugins=load_plugins(); cps=_checkpoints(); processed=[]; skipped=[]\n    storage_settings = load_storage_settings(); storage_policy = storage_settings.get('archive_policy', 'compress_after_analysis')")
old="""        compression_pct = int(((fi + 0.5) / file_count) * 100)
        _update(jid, state='running', current_stage='compression', message=f'Compressing parsed capture {path.name}', stage_progress={'uploading':100,'decompressing':100,'parsing':int(((fi + 1) / file_count) * 100),'compression':compression_pct,'rule_validation':0})
        compression = gzip_capture_file(path)
        stored_file = compression.get('compressed_file') or str(path)
        processed.append({'file':stored_file,'original_file':str(path),'sha256':digest,'packets':packet_count,'storage_compression':compression})
        files[fi] = Path(stored_file)
        _update(jid, current_stage='compression', message=f'Storage compression complete for {Path(stored_file).name}', stage_progress={'uploading':100,'decompressing':100,'parsing':int(((fi + 1) / file_count) * 100),'compression':int(((fi + 1) / file_count) * 100),'rule_validation':0})
"""
new="""        compression_pct = int(((fi + 0.5) / file_count) * 100)
        _update(jid, state='running', current_stage='compression', message=f'Applying storage policy to parsed capture {path.name}', stage_progress={'uploading':100,'decompressing':100,'parsing':int(((fi + 1) / file_count) * 100),'compression':compression_pct,'rule_validation':0})
        storage_action = {'policy': storage_policy, 'compressed': False, 'deleted': False, 'retained_raw': False}
        stored_file = str(path)
        if storage_policy == 'keep_raw':
            storage_action.update({'retained_raw': True, 'original_file': str(path), 'compressed': False, 'message': 'Raw capture retained by storage policy'})
        elif storage_policy == 'delete_after_analysis':
            storage_action.update(remove_capture_file(path))
            stored_file = ''
        else:
            storage_action.update(gzip_capture_file(path))
            stored_file = storage_action.get('compressed_file') or str(path)
        processed.append({'file':stored_file,'original_file':str(path),'sha256':digest,'packets':packet_count,'storage_compression':storage_action})
        files[fi] = Path(stored_file) if stored_file else Path(str(path) + '.deleted')
        status_name = Path(stored_file).name if stored_file else path.name
        _update(jid, current_stage='compression', message=f'Storage policy complete for {status_name}', storage_archive_policy=storage_policy, stage_progress={'uploading':100,'decompressing':100,'parsing':int(((fi + 1) / file_count) * 100),'compression':int(((fi + 1) / file_count) * 100),'rule_validation':0})
"""
if old in s:
    s=s.replace(old,new)
s=s.replace("jobs[jid]['storage_compression_complete'] = True\n        jobs[jid]['storage_compression_message'] = 'Parsed captures compressed with gzip'", "jobs[jid]['storage_archive_policy'] = storage_policy\n        jobs[jid]['storage_compression_complete'] = storage_policy == 'compress_after_analysis'\n        jobs[jid]['storage_capture_deleted'] = storage_policy == 'delete_after_analysis'\n        jobs[jid]['storage_compression_message'] = {'compress_after_analysis':'Parsed captures compressed with gzip', 'keep_raw':'Raw captures retained', 'delete_after_analysis':'Original captures deleted after analysis'}.get(storage_policy, 'Storage policy applied')")
s=s.replace("message='Analysis complete; PCAP storage compressed with gzip; rule validation and reports are available on demand',", "message={'compress_after_analysis':'Analysis complete; PCAP storage compressed with gzip; rule validation and reports are available on demand','keep_raw':'Analysis complete; raw PCAP storage retained by policy; rule validation and reports are available on demand','delete_after_analysis':'Analysis complete; original PCAP storage deleted after parsing; rule validation and reports are available on demand'}.get(storage_policy, 'Analysis complete; rule validation and reports are available on demand'),")
p.write_text(s)

# Patch web imports and export funcs/routes
p=Path('/mnt/data/pcap23/app/web.py')
s=p.read_text()
s=s.replace('from app.utils import read_json, validate_capture, write_json, sha256_file, capture_sha256, expand_supported_upload, is_supported_capture_upload, safe_relative_path', 'from app.utils import read_json, validate_capture, write_json, sha256_file, capture_sha256, expand_supported_upload, is_supported_capture_upload, safe_relative_path, load_storage_settings, save_storage_settings')
s=s.replace('def _export_previous_results_archive(job_ids=None):\n    """Create a portable ZIP backup of previous result metadata/artifacts."""', 'def _export_previous_results_archive(job_ids=None, include_captures=False):\n    """Create a portable ZIP backup of previous result metadata/artifacts.\n\n    By default this is parsed analysis data only.  Set include_captures=True\n    to include stored raw/.gz capture archives referenced by the selected jobs.\n    """')
s=s.replace("'includes': ['results', 'reports', 'exports'],", "'includes': ['results', 'reports', 'exports'] + (['captures'] if include_captures else []),\n        'include_captures': bool(include_captures),")
needle="""        for jid in selected:
            _safe_copy_tree_into_zip(zf, RESULT_DIR / jid, Path('results') / jid)
            _safe_copy_tree_into_zip(zf, REPORT_DIR / jid, Path('reports') / jid)
            _safe_copy_tree_into_zip(zf, EXPORT_DIR / jid, Path('exports') / jid)
"""
rep="""        capture_manifest = {}
        for jid in selected:
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
        if include_captures:
            zf.writestr('capture_manifest.json', json.dumps(capture_manifest, indent=2, default=str))
"""
if needle in s:
    s=s.replace(needle, rep)
needle="""        incoming_jobs = manifest.get('jobs') or {}
        jobs = list_jobs() or {}
        for old_jid, meta in incoming_jobs.items():
"""
rep="""        incoming_jobs = manifest.get('jobs') or {}
        capture_manifest = read_json(td / 'capture_manifest.json', {})
        jobs = list_jobs() or {}
        for old_jid, meta in incoming_jobs.items():
"""
s=s.replace(needle, rep)
needle="""            new_meta = dict(meta or {})
            new_meta['id'] = new_jid
"""
rep="""            restored_files = []
            for item in (capture_manifest.get(old_jid) or []):
                src = td / item.get('archive_path', '')
                if src.exists() and src.is_file():
                    dst_dir = UPLOAD_DIR / 'imported_results' / new_jid
                    dst_dir.mkdir(parents=True, exist_ok=True)
                    dst = dst_dir / Path(item.get('filename') or src.name).name
                    if dst.exists():
                        dst = dst_dir / f\"{uuid.uuid4().hex}_{dst.name}\"
                    shutil.copy2(src, dst)
                    restored_files.append(str(dst))
            new_meta = dict(meta or {})
            if restored_files:
                new_meta['files'] = restored_files
                new_meta['restored_captures'] = True
            new_meta['id'] = new_jid
"""
s=s.replace(needle, rep)
s=s.replace("def previous():\n    return render_template('previous.html', jobs=list_jobs(), import_message=request.args.get('import_message'))", "def previous():\n    return render_template('previous.html', jobs=list_jobs(), import_message=request.args.get('import_message'), storage_settings=load_storage_settings(), storage_stats=_storage_stats())")
s=s.replace("def export_previous_all():\n    path = _export_previous_results_archive()", "def export_previous_all():\n    include_captures = request.args.get('include_captures') in ('1','true','yes','on')\n    path = _export_previous_results_archive(include_captures=include_captures)")
s=s.replace("def export_previous_job(job_id):\n    path = _export_previous_results_archive([job_id])", "def export_previous_job(job_id):\n    include_captures = request.args.get('include_captures') in ('1','true','yes','on')\n    path = _export_previous_results_archive([job_id], include_captures=include_captures)")
insert="""

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
    return {'raw_bytes': raw, 'compressed_bytes': compressed, 'total_bytes': total, 'capture_count': captures, 'missing_count': missing, 'compression_savings_percent': savings}

@app.route('/storage/settings', methods=['POST'])
def storage_settings_route():
    policy = request.form.get('archive_policy') or 'compress_after_analysis'
    include_default = request.form.get('include_captures_in_exports_default') in ('1','true','yes','on')
    save_storage_settings({'archive_policy': policy, 'include_captures_in_exports_default': include_default})
    return redirect(url_for('previous', import_message='Storage settings updated.'))
"""
if 'def _storage_stats()' not in s:
    s=s.replace('\n@app.route(\'/previous\')\ndef previous():', insert+'\n@app.route(\'/previous\')\ndef previous():')
p.write_text(s)

# Patch previous template
p=Path('/mnt/data/pcap23/app/templates/previous.html')
s=p.read_text()
new="""{% extends 'base.html' %}
{% block body %}
<section class="card">
  <div class="row-between">
    <h2>Previous Results</h2>
    <div class="button-row">
      <a class="button" href="/previous/export">Export Parsed Results Only</a>
      <a class="button" href="/previous/export?include_captures=1">Export Results + Captures</a>
    </div>
  </div>
  {% if import_message %}<p class="alert">{{ import_message }}</p>{% endif %}
  <form method="post" action="/previous/import" enctype="multipart/form-data" class="inline-form">
    <label>Import previous-results backup <input type="file" name="previous_results" accept=".zip"></label>
    <button type="submit">Import</button>
  </form>
  <p><small>Default exports include parsed result JSON plus generated reports/exports only. Use <b>Export Results + Captures</b> when you also need the stored raw or <code>.gz</code> PCAP archives for long-term evidence retention.</small></p>
</section>

<section class="card">
  <h3>Storage Management</h3>
  <form method="post" action="/storage/settings" class="inline-form">
    <label>Capture archival policy
      <select name="archive_policy">
        <option value="compress_after_analysis" {% if storage_settings.archive_policy == 'compress_after_analysis' %}selected{% endif %}>Compress after successful analysis (default)</option>
        <option value="keep_raw" {% if storage_settings.archive_policy == 'keep_raw' %}selected{% endif %}>Never compress; keep original PCAPs</option>
        <option value="delete_after_analysis" {% if storage_settings.archive_policy == 'delete_after_analysis' %}selected{% endif %}>Delete original after analysis; keep parsed data only</option>
      </select>
    </label>
    <label><input type="checkbox" name="include_captures_in_exports_default" value="1" {% if storage_settings.include_captures_in_exports_default %}checked{% endif %}> Prefer capture-inclusive backups</label>
    <button type="submit">Save Storage Settings</button>
  </form>
  <div class="summary-grid">
    <div><b>Stored captures</b><br>{{ storage_stats.capture_count }}</div>
    <div><b>Raw capture storage</b><br>{{ '%.2f'|format((storage_stats.raw_bytes or 0)/1024/1024) }} MB</div>
    <div><b>Compressed capture storage</b><br>{{ '%.2f'|format((storage_stats.compressed_bytes or 0)/1024/1024) }} MB</div>
    <div><b>Compression savings</b><br>{% if storage_stats.compression_savings_percent is not none %}{{ storage_stats.compression_savings_percent }}%{% else %}n/a{% endif %}</div>
  </div>
</section>

<section class="card">
  <table>
    <tr><th>Name</th><th>Job ID</th><th>State</th><th>Storage</th><th>Created</th><th>Open</th><th>Export</th><th>Rename</th><th>Delete</th></tr>
    {% for id,j in jobs.items() %}
    <tr>
      <td>{{ j.name if j.name else ('Job ' ~ id[:8]) }}</td>
      <td><small>{{id}}</small></td>
      <td>{{j.state}}</td>
      <td>{% if j.storage_capture_deleted %}<span class="badge">parsed only</span>{% elif j.storage_compression_complete %}<span class="badge">.gz compressed</span>{% elif j.storage_archive_policy == 'keep_raw' %}<span class="badge">raw retained</span>{% else %}<small>pending/legacy</small>{% endif %}</td>
      <td>{{j.created}}</td>
      <td><a href="/jobs/{{id}}">status</a> | <a href="/?job={{id}}">dashboard</a></td>
      <td><a href="/previous/{{id}}/export">Parsed</a> | <a href="/previous/{{id}}/export?include_captures=1">With Captures</a></td>
      <td>
        <form method="post" action="/jobs/{{id}}/rename" class="inline-form rename-form">
          <input type="hidden" name="next" value="/previous">
          <input name="name" value="{{ j.name if j.name else '' }}" placeholder="Job name">
          <button type="submit">Rename</button>
        </form>
      </td>
      <td>{% if j.state != 'running' %}<form method="post" action="/previous/{{id}}/delete" onsubmit="return confirm('Delete this previous result?')"><button type="submit">Delete</button></form>{% else %}<small>Running</small>{% endif %}</td>
    </tr>
    {% else %}<tr><td colspan="9">No previous results.</td></tr>{% endfor %}
  </table>
</section>
{% endblock %}
"""
p.write_text(new)

# Patch job template completion indicator
p=Path('/mnt/data/pcap23/app/templates/job.html')
s=p.read_text()
if 'storage-indicator' not in s:
    s=s.replace('<p><b>Current file:</b> <span id="file">{{job.current_file if job else \'\'}}</span></p>', '<p><b>Current file:</b> <span id="file">{{job.current_file if job else \'\'}}</span></p>\n  <p id="storage-indicator"><b>Storage:</b> {% if job.storage_capture_deleted %}Parsed data only; original capture deleted by policy{% elif job.storage_compression_complete %}Archived as .gz{% elif job.storage_archive_policy == \'keep_raw\' %}Raw capture retained{% else %}Pending{% endif %}</p>')
    s=s.replace("document.getElementById('raw').textContent=JSON.stringify(j,null,2);", "const si=document.getElementById('storage-indicator'); if(si){let text='Pending'; if(j.storage_capture_deleted) text='Parsed data only; original capture deleted by policy'; else if(j.storage_compression_complete) text='Archived as .gz'; else if(j.storage_archive_policy==='keep_raw') text='Raw capture retained'; si.innerHTML='<b>Storage:</b> '+text;}document.getElementById('raw').textContent=JSON.stringify(j,null,2);")
p.write_text(s)
