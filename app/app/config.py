import os
from pathlib import Path

BASE = Path('/app') if Path('/app').exists() else Path(__file__).resolve().parents[1]
UPLOAD_DIR = Path(os.getenv('UPLOAD_DIR', BASE / 'uploads'))
RESULT_DIR = Path(os.getenv('RESULT_DIR', BASE / 'results'))
REPORT_DIR = Path(os.getenv('REPORT_DIR', BASE / 'reports'))
EXPORT_DIR = Path(os.getenv('EXPORT_DIR', BASE / 'exports'))
PLUGIN_DIR = Path(os.getenv('PLUGIN_DIR', BASE / 'plugins'))
WATCH_DIR = Path(os.getenv('WATCH_DIR', BASE / 'watch'))
for p in [UPLOAD_DIR, RESULT_DIR, REPORT_DIR, EXPORT_DIR, PLUGIN_DIR, WATCH_DIR]:
    p.mkdir(parents=True, exist_ok=True)

# Performance-oriented defaults.
# Scapy parsing is CPU-heavy and Python threads do not make one large PCAP parse faster.
# Use WORKERS>1 only when processing multiple independent jobs/files on fast storage.
WORKERS = int(os.getenv('WORKERS', '1'))
MAX_UPLOAD_GB = int(os.getenv('MAX_UPLOAD_GB', '500'))
CHECKPOINT_EVERY = int(os.getenv('CHECKPOINT_EVERY', '50000'))
PROGRESS_EVERY = int(os.getenv('PROGRESS_EVERY', '10000'))
SAMPLE_EVENTS = int(os.getenv('SAMPLE_EVENTS', '500'))
MAX_FLOWS = int(os.getenv('MAX_FLOWS', '250000'))
MAX_EVENTS = int(os.getenv('MAX_EVENTS', '500000'))
MAX_FINDINGS = int(os.getenv('MAX_FINDINGS', '50000'))
MAX_LOG_SOURCES = int(os.getenv('MAX_LOG_SOURCES', '50000'))
MAX_NORMALIZED_EVENTS = int(os.getenv('MAX_NORMALIZED_EVENTS', '250000'))
REPORTS_BACKGROUND = os.getenv('REPORTS_BACKGROUND', '0').lower() in ('1', 'true', 'yes', 'on')
ATTACK_VERSION = os.getenv('ATTACK_VERSION', '18')
NAVIGATOR_VERSION = os.getenv('NAVIGATOR_VERSION', '5.2.0')

# Full rule validation is intentionally deferred by default for performance.
# Set to 1 only when you want the expensive Detection/Network Rule pass to run
# automatically after PCAP parsing completes.
VALIDATE_RULES_DURING_ANALYSIS = os.getenv('VALIDATE_RULES_DURING_ANALYSIS', '0').lower() in ('1', 'true', 'yes', 'on')


# Capture archival policy. Runtime UI settings are stored in results/storage_settings.json;
# this environment value is used as the default for new installs.
# Supported: compress_after_analysis, keep_raw, delete_after_analysis
STORAGE_ARCHIVE_POLICY = os.getenv('STORAGE_ARCHIVE_POLICY', 'delete_after_analysis')
