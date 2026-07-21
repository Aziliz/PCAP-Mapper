import bz2, gzip, hashlib, json, lzma, os, shutil, subprocess, tarfile, zipfile
from pathlib import Path

CAPTURE_SUFFIXES = (
    '.pcap', '.pcapng',
    '.pcap.gz', '.pcapng.gz',
    '.pcap.bz2', '.pcapng.bz2',
    '.pcap.xz', '.pcapng.xz',
    '.pcap.zst', '.pcapng.zst', '.pcap.zstd', '.pcapng.zstd',
)
ARCHIVE_SUFFIXES = (
    '.zip', '.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz', '.tbz2', '.tar.xz', '.txz'
)
SUPPORTED_UPLOAD_SUFFIXES = CAPTURE_SUFFIXES + ARCHIVE_SUFFIXES


def is_capture_file(path_or_name) -> bool:
    name = str(path_or_name or '').lower()
    return name.endswith(CAPTURE_SUFFIXES)


def is_archive_file(path_or_name) -> bool:
    name = str(path_or_name or '').lower()
    return name.endswith(ARCHIVE_SUFFIXES)


def is_supported_capture_upload(path_or_name) -> bool:
    name = str(path_or_name or '').lower()
    return name.endswith(SUPPORTED_UPLOAD_SUFFIXES)


def safe_relative_path(filename):
    """Return a safe relative path for directory/archive uploads."""
    parts = []
    for part in Path(filename or '').parts:
        if part in ('', '.', '..'):
            continue
        clean = ''.join(ch for ch in part if ch.isalnum() or ch in (' ', '.', '_', '-')).strip()
        if clean:
            parts.append(clean)
    if not parts:
        parts = ['upload.pcap']
    return Path(*parts)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def capture_sha256(path: Path) -> str:
    """Hash the logical capture contents.

    For compressed single-capture uploads this hashes decompressed bytes, so an
    uploaded sample.pcap and sample.pcap.gz are recognized as duplicates when
    they contain the same capture. Archives are expanded before this function is
    used, so archive container bytes are intentionally not hashed here.
    """
    name = path.name.lower()
    h = hashlib.sha256()
    if name.endswith('.gz') and not name.endswith(('.tar.gz', '.tgz')):
        opener = gzip.open
    elif name.endswith('.bz2') and not name.endswith(('.tar.bz2', '.tbz', '.tbz2')):
        opener = bz2.open
    elif name.endswith('.xz') and not name.endswith(('.tar.xz', '.txz')):
        opener = lzma.open
    else:
        opener = open
    with opener(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def read_json(path: Path, default):
    try:
        if path.exists():
            return json.loads(path.read_text())
    except Exception:
        return default
    return default


def write_json(path: Path, data):
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(json.dumps(data, indent=2, default=str))
    tmp.replace(path)


def _read_capture_magic(path: Path) -> bytes:
    name = path.name.lower()
    if name.endswith('.gz') and not name.endswith(('.tar.gz', '.tgz')):
        with gzip.open(path, 'rb') as f:
            return f.read(8)
    if name.endswith('.bz2') and not name.endswith(('.tar.bz2', '.tbz', '.tbz2')):
        with bz2.open(path, 'rb') as f:
            return f.read(8)
    if name.endswith('.xz') and not name.endswith(('.tar.xz', '.txz')):
        with lzma.open(path, 'rb') as f:
            return f.read(8)
    with open(path, 'rb') as f:
        return f.read(8)


def validate_capture(path: Path) -> tuple[bool, str]:
    name = path.name.lower()
    if name.endswith(('.zst', '.zstd')):
        # Python-only/no external package: accept extension but require external
        # zstd binary if available. This preserves prior behavior without adding
        # dependencies beyond Python/Flask/Scapy.
        if shutil.which('zstd') is None:
            return False, 'zstd compressed files require zstd binary in the container; install it or decompress before upload'
    try:
        raw = _read_capture_magic(path)
    except Exception as e:
        return False, f'compressed capture read failed: {e}'
    if raw.startswith((b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d')):
        return True, 'pcap'
    if raw.startswith(b'\x0a\x0d\x0d\x0a'):
        return True, 'pcapng'
    return False, 'unknown capture format'


def maybe_decompress(path: Path, work_dir: Path) -> Path:
    name = path.name.lower()
    work_dir.mkdir(parents=True, exist_ok=True)
    if name.endswith('.gz') and not name.endswith(('.tar.gz', '.tgz')):
        out = work_dir / path.name[:-3]
        if not out.exists():
            with gzip.open(path, 'rb') as src, open(out, 'wb') as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)
        return out
    if name.endswith('.bz2') and not name.endswith(('.tar.bz2', '.tbz', '.tbz2')):
        out = work_dir / path.name[:-4]
        if not out.exists():
            with bz2.open(path, 'rb') as src, open(out, 'wb') as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)
        return out
    if name.endswith('.xz') and not name.endswith(('.tar.xz', '.txz')):
        out = work_dir / path.name[:-3]
        if not out.exists():
            with lzma.open(path, 'rb') as src, open(out, 'wb') as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)
        return out
    if name.endswith(('.zst', '.zstd')):
        out = work_dir / path.name.rsplit('.', 1)[0]
        if not out.exists():
            if shutil.which('zstd') is None:
                raise RuntimeError('zstd binary not available')
            subprocess.check_call(['zstd', '-d', '-f', '-o', str(out), str(path)])
        return out
    return path


def _unique_destination(root: Path, rel: Path) -> Path:
    candidate = root / rel
    if not candidate.exists():
        return candidate
    stem = candidate.stem
    suffix = ''.join(candidate.suffixes) or candidate.suffix
    parent = candidate.parent
    for i in range(1, 10000):
        nxt = parent / f'{stem}_{i}{suffix}'
        if not nxt.exists():
            return nxt
    raise RuntimeError(f'could not find unique destination for {rel}')


def expand_supported_upload(path: Path, output_root: Path):
    """Expand an uploaded capture/archive into concrete capture files.

    Returns (capture_paths, skipped_items). Archives are extracted safely with
    path traversal protection and only PCAP/PCAPNG files, including stdlib
    compressed variants, are kept. Single captures are returned unchanged.
    """
    output_root.mkdir(parents=True, exist_ok=True)
    captures = []
    skipped = []
    name = path.name.lower()
    if is_capture_file(name):
        ok, msg = validate_capture(path)
        if not ok:
            skipped.append({'file': path.name, 'reason': msg})
            return captures, skipped
        # Decompress single compressed captures during the upload expansion
        # stage so duplicate detection, parsing, and progress reporting all use
        # the same logical PCAP/PCAPNG bytes. Plain captures remain in place.
        if name.endswith(('.gz', '.bz2', '.xz', '.zst', '.zstd')):
            try:
                dest = maybe_decompress(path, output_root)
                captures.append(dest)
            except Exception as exc:
                skipped.append({'file': path.name, 'reason': f'decompression failed: {exc}'})
        else:
            captures.append(path)
        return captures, skipped

    if name.endswith('.zip'):
        try:
            with zipfile.ZipFile(path) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    rel = safe_relative_path(info.filename)
                    if not is_capture_file(str(rel)):
                        skipped.append({'file': info.filename, 'reason': 'unsupported file type inside archive'})
                        continue
                    dest = _unique_destination(output_root, rel)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(info, 'r') as src, open(dest, 'wb') as dst:
                        shutil.copyfileobj(src, dst, length=1024 * 1024)
                    ok, msg = validate_capture(dest)
                    if ok:
                        captures.append(dest)
                    else:
                        skipped.append({'file': info.filename, 'reason': msg})
                        try: dest.unlink()
                        except Exception: pass
        except Exception as exc:
            skipped.append({'file': path.name, 'reason': f'zip extraction failed: {exc}'})
        return captures, skipped

    if name.endswith(('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz', '.tbz2', '.tar.xz', '.txz')):
        try:
            with tarfile.open(path, mode='r:*') as tf:
                for member in tf.getmembers():
                    if not member.isfile():
                        continue
                    rel = safe_relative_path(member.name)
                    if not is_capture_file(str(rel)):
                        skipped.append({'file': member.name, 'reason': 'unsupported file type inside archive'})
                        continue
                    src = tf.extractfile(member)
                    if src is None:
                        skipped.append({'file': member.name, 'reason': 'could not read archive member'})
                        continue
                    dest = _unique_destination(output_root, rel)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    with src, open(dest, 'wb') as dst:
                        shutil.copyfileobj(src, dst, length=1024 * 1024)
                    ok, msg = validate_capture(dest)
                    if ok:
                        captures.append(dest)
                    else:
                        skipped.append({'file': member.name, 'reason': msg})
                        try: dest.unlink()
                        except Exception: pass
        except Exception as exc:
            skipped.append({'file': path.name, 'reason': f'tar extraction failed: {exc}'})
        return captures, skipped

    skipped.append({'file': path.name, 'reason': 'unsupported file type'})
    return captures, skipped



STORAGE_SETTINGS_FILE = Path(os.getenv('STORAGE_SETTINGS_FILE', Path(__file__).resolve().parents[1] / 'results' / 'storage_settings.json'))
SUPPORTED_STORAGE_POLICIES = {'compress_after_analysis', 'keep_raw', 'delete_after_analysis'}


def load_storage_settings() -> dict:
    default_policy = os.getenv('STORAGE_ARCHIVE_POLICY', 'delete_after_analysis')
    if default_policy not in SUPPORTED_STORAGE_POLICIES:
        default_policy = 'delete_after_analysis'
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
        current['archive_policy'] = 'delete_after_analysis'
    STORAGE_SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    write_json(STORAGE_SETTINGS_FILE, current)
    return current



# Application settings -----------------------------------------------------
# Storage remains backward compatible with the existing storage_settings.json
# file. Performance/export UI settings live alongside it and are safe to edit
# from the Settings page.
APP_SETTINGS_FILE = Path(os.getenv('APP_SETTINGS_FILE', Path(__file__).resolve().parents[1] / 'results' / 'app_settings.json'))
PERFORMANCE_PROFILES = {
    'maximum_performance': {'label': 'Maximum Performance', 'core_fraction': 1.0, 'reserve_cores': 1, 'description': 'Use all but one logical core.'},
    'balanced': {'label': 'Balanced', 'core_fraction': 0.50, 'reserve_cores': 0, 'description': 'Use about 50% of logical cores.'},
    'low_impact': {'label': 'Low Impact', 'core_fraction': 0.25, 'reserve_cores': 0, 'description': 'Use about 10-25% of logical cores.'},
}

def _profile_worker_count(profile: str) -> int:
    cores = max(1, int(os.cpu_count() or 1))
    profile = profile if profile in PERFORMANCE_PROFILES else 'balanced'
    if profile == 'maximum_performance':
        return max(1, cores - 1)
    if profile == 'balanced':
        return max(1, int(round(cores * 0.50)))
    # Low impact: prefer 25%, but never more than 25% and never below one worker.
    return max(1, int(max(1, round(cores * 0.25))))

def load_app_settings() -> dict:
    data = read_json(APP_SETTINGS_FILE, {}) if APP_SETTINGS_FILE.exists() else {}
    if not isinstance(data, dict):
        data = {}
    profile = data.get('performance_profile') or os.getenv('PERFORMANCE_PROFILE', 'balanced')
    if profile not in PERFORMANCE_PROFILES:
        profile = 'balanced'
    include_default = bool(data.get('include_captures_in_exports_default', load_storage_settings().get('include_captures_in_exports_default', False)))
    backup_type = data.get('default_backup_type') or os.getenv('DEFAULT_BACKUP_TYPE', 'job')
    if backup_type not in {'job', 'configuration', 'workspace'}:
        backup_type = 'job'
    return {
        'performance_profile': profile,
        'performance_profiles': PERFORMANCE_PROFILES,
        'logical_cores': max(1, int(os.cpu_count() or 1)),
        'worker_count': _profile_worker_count(profile),
        'include_captures_in_exports_default': include_default,
        'default_backup_type': backup_type,
        'reports_background': bool(data.get('reports_background', False)),
    }

def save_app_settings(settings: dict) -> dict:
    current = load_app_settings()
    current.update(settings or {})
    if current.get('performance_profile') not in PERFORMANCE_PROFILES:
        current['performance_profile'] = 'balanced'
    current['worker_count'] = _profile_worker_count(current['performance_profile'])
    APP_SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    persist = {k:v for k,v in current.items() if k not in ('performance_profiles', 'logical_cores', 'worker_count')}
    write_json(APP_SETTINGS_FILE, persist)
    return load_app_settings()



CAPTURE_INVENTORY_FILE = Path(os.getenv('CAPTURE_INVENTORY_FILE', Path(__file__).resolve().parents[1] / 'results' / 'capture_inventory.json'))


def _capture_inventory_key(name: str) -> str:
    """Normalize an uploaded capture name for duplicate tracking.

    The inventory is filename-based so duplicate checks do not need to scan,
    decompress, or hash already archived captures on every upload. Common
    compression suffixes are stripped so sample.pcap and sample.pcap.gz resolve
    to the same key. Duplicate scope is per job, not global.
    """
    n = Path(str(name or '')).name.lower().strip()
    # Treat deleted-marker files as the original capture name.  For example,
    # linux.pcap.deleted and linux.pcap.gz.deleted both compare as linux.pcap.
    if n.endswith('.deleted'):
        n = n[:-len('.deleted')]
    for suffix in ('.gz', '.bz2', '.xz'):
        if n.endswith(suffix):
            n = n[:-len(suffix)]
    return n


def capture_inventory_aliases(name: str) -> set:
    """Return normalized duplicate keys for an uploaded/stored capture name.

    This intentionally includes raw, compressed, and deleted-marker variants so
    a job remembers that linux.pcap was uploaded even after storage policy turns
    it into linux.pcap.deleted or linux.pcap.gz.
    """
    raw = Path(str(name or '')).name.lower().strip()
    aliases = set()
    candidates = {raw}
    if raw.endswith('.deleted'):
        candidates.add(raw[:-len('.deleted')])
    for c in list(candidates):
        for suffix in ('.gz', '.bz2', '.xz'):
            if c.endswith(suffix):
                candidates.add(c[:-len(suffix)])
    for c in list(candidates):
        if c:
            aliases.add(_capture_inventory_key(c))
            aliases.add(_capture_inventory_key(c + '.deleted'))
            aliases.add(_capture_inventory_key(c + '.gz'))
            aliases.add(_capture_inventory_key(c + '.gz.deleted'))
    return {a for a in aliases if a}


def _normalize_job_id(job_id: str = '') -> str:
    return str(job_id or '').strip() or '_unassigned'


def load_capture_inventory() -> dict:
    """Load duplicate-upload inventory.

    Current format:
        {"jobs": {"<job_id>": {"files": [...]}}}

    Older builds stored a single global {"files": [...]} list or a raw list.
    Those entries are migrated into the _unassigned bucket so existing installs
    continue to load without breaking, while new duplicate checks are scoped to
    the selected job.
    """
    data = read_json(CAPTURE_INVENTORY_FILE, {}) if CAPTURE_INVENTORY_FILE.exists() else {}
    if isinstance(data, list):
        data = {'files': [{'filename': str(x), 'key': _capture_inventory_key(str(x)), 'job_id': '_unassigned'} for x in data]}
    if not isinstance(data, dict):
        data = {}
    jobs = data.get('jobs')
    if not isinstance(jobs, dict):
        jobs = {}
    legacy_files = data.get('files')
    if isinstance(legacy_files, list) and legacy_files:
        bucket = jobs.setdefault('_unassigned', {'files': []})
        if not isinstance(bucket.get('files'), list):
            bucket['files'] = []
        for item in legacy_files:
            if not isinstance(item, dict):
                item = {'filename': str(item)}
            item.setdefault('job_id', item.get('job_id') or '_unassigned')
            item['key'] = item.get('key') or _capture_inventory_key(item.get('filename') or item.get('stored_file') or '')
            bucket['files'].append(item)
    normalized_jobs = {}
    for jid, bucket in jobs.items():
        jid = _normalize_job_id(jid)
        files = bucket.get('files') if isinstance(bucket, dict) else []
        if not isinstance(files, list):
            files = []
        cleaned = []
        for item in files:
            if not isinstance(item, dict):
                item = {'filename': str(item)}
            key = item.get('key') or _capture_inventory_key(item.get('filename') or item.get('stored_file') or '')
            if not key:
                continue
            item['key'] = key
            item['job_id'] = item.get('job_id') or jid
            cleaned.append(item)
        normalized_jobs[jid] = {'files': cleaned}
    all_files = []
    for bucket in normalized_jobs.values():
        all_files.extend(bucket.get('files') or [])
    return {'jobs': normalized_jobs, 'files': all_files}


def save_capture_inventory(data: dict) -> dict:
    CAPTURE_INVENTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    inv = load_capture_inventory()
    jobs = inv.get('jobs') or {}
    incoming_jobs = (data or {}).get('jobs') if isinstance(data, dict) else None
    if isinstance(incoming_jobs, dict):
        jobs = incoming_jobs
    else:
        # Backward-compatible save of a flat files list.
        files = (data or {}).get('files') if isinstance(data, dict) else []
        if isinstance(files, list):
            jobs = {}
            for item in files:
                if not isinstance(item, dict):
                    item = {'filename': str(item)}
                jid = _normalize_job_id(item.get('job_id'))
                jobs.setdefault(jid, {'files': []})['files'].append(item)
    normalized_jobs = {}
    for jid, bucket in (jobs or {}).items():
        jid = _normalize_job_id(jid)
        files = bucket.get('files') if isinstance(bucket, dict) else []
        by_key = {}
        for item in files or []:
            if not isinstance(item, dict):
                item = {'filename': str(item)}
            key = item.get('key') or _capture_inventory_key(item.get('filename') or item.get('stored_file') or '')
            if not key:
                continue
            item['key'] = key
            item['job_id'] = item.get('job_id') or jid
            by_key[key] = item
        normalized_jobs[jid] = {'files': sorted(by_key.values(), key=lambda x: x.get('filename',''))}
    out = {'jobs': normalized_jobs}
    out['files'] = [item for bucket in normalized_jobs.values() for item in (bucket.get('files') or [])]
    write_json(CAPTURE_INVENTORY_FILE, out)
    return out


def capture_name_exists(filename: str, job_id: str = '') -> bool:
    aliases = capture_inventory_aliases(filename)
    if not aliases:
        return False
    jid = _normalize_job_id(job_id)
    inv = load_capture_inventory()
    bucket = (inv.get('jobs') or {}).get(jid, {})
    known = set()
    for item in bucket.get('files', []) or []:
        known.update(capture_inventory_aliases(item.get('filename') or ''))
        known.update(capture_inventory_aliases(item.get('stored_file') or ''))
        if item.get('key'):
            known.add(item.get('key'))
    return bool(aliases & known)


def capture_names_for_job(job_id: str = '') -> set:
    jid = _normalize_job_id(job_id)
    inv = load_capture_inventory()
    bucket = (inv.get('jobs') or {}).get(jid, {})
    names = set()
    for item in (bucket.get('files') or []):
        names.update(capture_inventory_aliases(item.get('filename') or ''))
        names.update(capture_inventory_aliases(item.get('stored_file') or ''))
        if item.get('key'):
            names.add(item.get('key'))
    return {x for x in names if x}


def register_capture_file(filename: str, job_id: str = '', sha256: str = '', stored_file: str = '', status: str = 'uploaded') -> dict:
    inv = load_capture_inventory()
    jid = _normalize_job_id(job_id)
    key = _capture_inventory_key(filename or stored_file)
    if not key:
        return inv
    item = {
        'filename': Path(str(filename or stored_file)).name,
        'key': key,
        'aliases': sorted(capture_inventory_aliases(filename or stored_file)),
        'job_id': jid,
        'sha256': sha256 or '',
        'stored_file': str(stored_file or ''),
        'status': status,
        'updated_at': __import__('time').time(),
    }
    jobs = inv.get('jobs') or {}
    bucket = jobs.setdefault(jid, {'files': []})
    files = bucket.get('files') if isinstance(bucket, dict) else []
    if not isinstance(files, list):
        files = []
    files = [x for x in files if (x.get('key') or _capture_inventory_key(x.get('filename',''))) != key]
    files.append(item)
    jobs[jid] = {'files': files}
    return save_capture_inventory({'jobs': jobs})


def remove_capture_file(path: Path) -> dict:
    path = Path(path)
    marker = path.with_name(path.name + '.deleted')
    info = {'original_file': str(path), 'deleted': False, 'deleted_marker': str(marker)}
    original_size = None
    if path.exists() and path.is_file():
        original_size = path.stat().st_size
        info['original_size'] = original_size
        try:
            path.unlink()
            info['deleted'] = True
        except Exception as exc:
            info['reason'] = str(exc)
    else:
        info['reason'] = 'missing file'
    try:
        marker.write_text(json.dumps({'original_file': str(path), 'original_size': original_size, 'deleted_at': __import__('time').time()}, indent=2))
    except Exception as exc:
        info['marker_error'] = str(exc)
    return info


def gzip_capture_file(path: Path) -> dict:
    """Compress a parsed capture to .gz and remove the uncompressed copy.

    The returned dictionary is JSON-safe and keeps both original and compressed
    paths so previous-result screens can show that storage compression finished.
    Existing .gz captures are left untouched.
    """
    path = Path(path)
    original = str(path)
    if not path.exists() or not path.is_file():
        return {'original_file': original, 'compressed': False, 'reason': 'missing file'}
    if path.name.lower().endswith('.gz'):
        return {
            'original_file': original,
            'compressed_file': str(path),
            'compressed': True,
            'already_compressed': True,
            'original_size': path.stat().st_size,
            'compressed_size': path.stat().st_size,
        }
    gz_path = path.with_name(path.name + '.gz')
    if gz_path.exists():
        stem = path.name
        for i in range(1, 10000):
            candidate = path.with_name(f'{stem}_{i}.gz')
            if not candidate.exists():
                gz_path = candidate
                break
    original_size = path.stat().st_size
    tmp = gz_path.with_suffix(gz_path.suffix + '.tmp')
    with open(path, 'rb') as src, gzip.open(tmp, 'wb') as dst:
        shutil.copyfileobj(src, dst, length=1024 * 1024)
    tmp.replace(gz_path)
    compressed_size = gz_path.stat().st_size
    try:
        path.unlink()
    except Exception:
        pass
    ratio = None
    if original_size:
        ratio = round((1 - (compressed_size / original_size)) * 100, 2)
    return {
        'original_file': original,
        'compressed_file': str(gz_path),
        'compressed': True,
        'already_compressed': False,
        'original_size': original_size,
        'compressed_size': compressed_size,
        'space_saved_percent': ratio,
    }
