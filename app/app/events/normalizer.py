import re
import time
import hashlib
from collections import Counter, defaultdict

# Keep this module dependency-free.  It intentionally uses simple heuristics and
# regular expressions so the app stays within Python + Flask + Scapy.

WINDOWS_EVENT_MAP = {
    '4624': ('authentication_success', ['T1078']),
    '4625': ('authentication_failure', ['T1110']),
    '4634': ('logoff', []),
    '4648': ('explicit_credentials', ['T1078', 'T1550']),
    '4670': ('permission_change', ['T1222.001']),
    '4672': ('privileged_logon', ['T1548', 'T1078']),
    '4688': ('process_creation', ['T1059']),
    '4697': ('service_creation', ['T1543.003', 'T1569.002']),
    '4698': ('scheduled_task_created', ['T1053.005']),
    '4699': ('scheduled_task_deleted', ['T1070.009']),
    '4702': ('scheduled_task_updated', ['T1053.005']),
    '4719': ('audit_policy_changed', ['T1562.002']),
    '4720': ('account_created', ['T1136']),
    '4722': ('account_enabled', ['T1098']),
    '4724': ('password_reset', ['T1098']),
    '4728': ('group_member_added', ['T1098.007']),
    '4732': ('local_group_member_added', ['T1098.007']),
    '4738': ('account_changed', ['T1098']),
    '4740': ('account_locked', ['T1110']),
    '4756': ('universal_group_member_added', ['T1098.007']),
    '4768': ('kerberos_as_request', ['T1558.004']),
    '4769': ('kerberos_tgs_request', ['T1558.003']),
    '4771': ('kerberos_preauth_failed', ['T1110']),
    '4776': ('ntlm_authentication', ['T1078']),
    '5140': ('network_share_access', ['T1135', 'T1021.002']),
    '5145': ('network_share_file_access', ['T1039', 'T1021.002']),
    '7045': ('service_creation', ['T1543.003', 'T1569.002']),
    '1102': ('windows_event_log_cleared', ['T1070.001']),
}

SYSMON_EVENT_MAP = {
    '1': ('process_creation', ['T1059']),
    '2': ('file_time_changed', ['T1070.006']),
    '3': ('network_connection', ['T1071']),
    '5': ('process_terminated', []),
    '6': ('driver_loaded', ['T1547.006']),
    '7': ('image_loaded', ['T1574']),
    '8': ('remote_thread_created', ['T1055.004']),
    '10': ('process_access', ['T1003.001', 'T1055']),
    '11': ('file_created', ['T1105', 'T1074']),
    '12': ('registry_object_created', ['T1112']),
    '13': ('registry_value_set', ['T1112']),
    '14': ('registry_renamed', ['T1112']),
    '15': ('alternate_data_stream_created', ['T1564.004']),
    '17': ('pipe_created', ['T1559']),
    '18': ('pipe_connected', ['T1559']),
    '22': ('dns_query', ['T1071.004', 'T1568']),
    '23': ('file_deleted', ['T1070.004']),
    '25': ('process_tampering', ['T1055', 'T1562']),
    '26': ('file_delete_detected', ['T1070.004']),
}

SOURCE_KEYWORDS = [
    ('windows security', 'windows', 'Windows Security'), ('security.evtx', 'windows', 'Windows Security'),
    ('microsoft-windows-security-auditing', 'windows', 'Windows Security'),
    ('sysmon event', 'windows', 'Sysmon'), ('microsoft-windows-sysmon', 'windows', 'Sysmon'),
    ('powershell operational', 'windows', 'PowerShell Operational'), ('microsoft-windows-powershell', 'windows', 'PowerShell Operational'),
    ('microsoft-windows-defender', 'windows', 'Defender'), ('defender for endpoint', 'windows', 'Defender for Endpoint'),
    ('microsoft-windows-winrm', 'windows', 'WinRM'), ('microsoft-windows-wmi', 'windows', 'WMI'),
    ('microsoft-windows-task', 'windows', 'Task Scheduler'), ('applocker', 'windows', 'AppLocker'),
    ('windows firewall', 'windows', 'Windows Firewall'), ('active directory', 'windows', 'Active Directory'),
    ('certificate services', 'windows', 'Certificate Services'),
    ('zeek conn', 'network', 'Zeek'), ('zeek dns', 'network', 'Zeek'), ('zeek http', 'network', 'Zeek'), ('zeek ssl', 'network', 'Zeek'),
    ('suricata eve', 'network', 'Suricata'), ('suricata alert', 'network', 'Suricata'),
    ('cisco ios', 'network', 'Cisco IOS'), ('cisco nx-os', 'network', 'Cisco NX-OS'), ('cisco firepower', 'network', 'Cisco Firepower'),
    ('palo alto', 'network', 'Palo Alto'), ('pan-os', 'network', 'Palo Alto'), ('fortinet', 'network', 'Fortinet'),
    ('check point', 'network', 'Check Point'), ('sonicwall', 'network', 'SonicWall'),
    ('sysmon', 'windows', 'Sysmon'), ('winlogbeat', 'windows', 'Winlogbeat'),
    ('windows event', 'windows', 'Windows Event Log'), ('eventid', 'windows', 'Windows Event Log'),
    ('event id', 'windows', 'Windows Event Log'), ('powershell', 'windows', 'PowerShell'),
    ('defender', 'windows', 'Defender'), ('task scheduler', 'windows', 'Task Scheduler'),
    ('terminalservices', 'windows', 'Terminal Services'), ('winrm', 'windows', 'WinRM'),
    ('wmi', 'windows', 'WMI'), ('iis', 'windows', 'IIS'),

    ('auditd', 'linux', 'auditd'), ('type=execve', 'linux', 'auditd'),
    ('journald', 'linux', 'systemd-journald'), ('systemd', 'linux', 'systemd'),
    ('sshd', 'linux', 'sshd'), ('sudo', 'linux', 'sudo'), ('cron', 'linux', 'cron'),
    ('iptables', 'linux', 'iptables'), ('nftables', 'linux', 'nftables'),
    ('apparmor', 'linux', 'AppArmor'), ('selinux', 'linux', 'SELinux'),
    ('falco', 'linux', 'Falco'), ('docker', 'linux', 'Docker'), ('containerd', 'linux', 'containerd'),
    ('kubernetes audit', 'linux', 'Kubernetes Audit'), ('kube-apiserver', 'linux', 'Kubernetes Audit'),
    ('nginx', 'linux', 'Nginx'), ('apache', 'linux', 'Apache'),

    ('apple unified', 'macos', 'Apple Unified Logging'), ('opensbm', 'macos', 'OpenBSM'),
    ('openbsm', 'macos', 'OpenBSM'), ('launchd', 'macos', 'launchd'), ('launchctl', 'macos', 'launchctl'),
    ('jamf', 'macos', 'Jamf'), ('santa', 'macos', 'Santa'), ('gatekeeper', 'macos', 'Gatekeeper'),
    ('xprotect', 'macos', 'XProtect'), ('tcc', 'macos', 'TCC'), ('filevault', 'macos', 'FileVault'),

    ('zeek', 'network', 'Zeek'), ('suricata', 'network', 'Suricata'), ('packetbeat', 'network', 'Packetbeat'),
    ('netflow', 'network', 'NetFlow'), ('ipfix', 'network', 'IPFIX'), ('sflow', 'network', 'sFlow'),
    ('cisco asa', 'network', 'Cisco ASA'), ('pan-os', 'network', 'Palo Alto PAN-OS'),
    ('fortigate', 'network', 'Fortinet FortiGate'), ('checkpoint', 'network', 'Check Point'),
    ('pfsense', 'network', 'pfSense'), ('opnsense', 'network', 'OPNsense'), ('sonicwall', 'network', 'SonicWall'),
    ('squid', 'network', 'Squid Proxy'), ('proxy', 'network', 'Proxy'), ('vpn', 'network', 'VPN'),
    ('wireless controller', 'network', 'Wireless Controller'), ('dns server', 'network', 'DNS Server'),
    ('dhcp', 'network', 'DHCP'),

    ('cloudtrail', 'cloud', 'AWS CloudTrail'), ('guardduty', 'cloud', 'AWS GuardDuty'),
    ('azureactivity', 'cloud', 'Azure Activity'), ('azure ad', 'cloud', 'Azure AD'),
    ('gcp audit', 'cloud', 'GCP Audit Logs'), ('workspace logs', 'cloud', 'Google Workspace'),
]

BEHAVIOR_PATTERNS = [
    (r'powershell|encodedcommand|script block|event\s*id\s*4104', 'script_execution', ['T1059.001']),
    (r'cmd\.exe|command shell', 'command_shell', ['T1059.003']),
    (r'/bin/(ba)?sh|zsh|shell command|execve', 'unix_shell', ['T1059.004']),
    (r'python(\.exe)?|python script', 'python_execution', ['T1059.006']),
    (r'wscript|cscript|vbscript|visual basic', 'visual_basic_execution', ['T1059.005']),
    (r'osascript|applescript', 'applescript_execution', ['T1059.002']),
    (r'mshta|rundll32|regsvr32|msbuild|installutil|msiexec|mavinject|cmstp', 'proxy_execution', ['T1218']),
    (r'winrm|invoke-command|psremoting', 'remote_execution', ['T1021.006', 'T1059.001']),
    (r'wmi|wmic|dcom|rpc', 'wmi_or_rpc', ['T1047', 'T1021.003']),
    (r'scheduled task|task scheduler|event\s*id\s*4698|schtasks|cron|crontab|systemd timer', 'scheduled_task', ['T1053']),
    (r'service created|service installed|event\s*id\s*7045|systemctl enable|launchctl|launch daemon|launchagent', 'service_or_daemon', ['T1543', 'T1569.002']),
    (r'registry run|run key|startup folder|plist|login item|xdg autostart', 'autostart', ['T1547']),
    (r'uac|sudo|setuid|setgid|high integrity|privilege escalation|root', 'privilege_escalation', ['T1548']),
    (r'token impersonation|createprocesswithtoken|sid-history|ppid spoof', 'token_manipulation', ['T1134']),
    (r'lsass|ntds\.dit|sam database|dcsync|kerberoast|as-rep|credential dump', 'credential_access', ['T1003', 'T1558']),
    (r'password spray|brute force|failed logon|event\s*id\s*4625|authentication failure', 'brute_force', ['T1110']),
    (r'clear.*event log|wevtutil\s+cl|journalctl.*vacuum|history cleared|rm /var/log', 'log_clearing', ['T1070']),
    (r'defender disabled|firewall disabled|auditd disabled|logging disabled|cloud logs disabled', 'impair_defenses', ['T1562']),
    (r'timestomp|file time changed', 'timestomp', ['T1070.006']),
    (r'dll sideload|dll search order|dylib|path interception|cor_profiler', 'hijack_execution_flow', ['T1574']),
    (r'process injection|createremotethread|process hollowing|ptrace|proc memory', 'process_injection', ['T1055']),
    (r'ldap query|net user|net group|whoami|ipconfig|ifconfig|netstat|tasklist|ps aux|systeminfo|uname', 'discovery', ['T1087', 'T1082', 'T1016', 'T1057']),
    (r'smb admin\$|c\$|ipc\$|admin share|remote service|rdp|ssh accepted|vnc', 'lateral_movement', ['T1021']),
    (r'clipboard|screen capture|audio capture|video capture|mailbox collection|sharepoint|confluence|git clone|recursive copy', 'collection', ['T1115', 'T1113', 'T1123', 'T1125', 'T1213']),
    (r'beacon|checkin|dns tunneling|domain fronting|proxy relay|non-standard port|mqtt|webhook', 'command_and_control', ['T1071', 'T1090', 'T1571']),
    (r'large upload|exfil|cloud storage upload|git push|smtp attachment|scheduled transfer|webhook', 'exfiltration', ['T1041', 'T1567']),
    (r'ransomware|encrypted extension|shadow copy deleted|service stopped|defacement|ddos|flood|shutdown|reboot|disk wipe', 'impact', ['T1486', 'T1490', 'T1489', 'T1499', 'T1529']),
]

FIELD_PATTERNS = {
    'event_id': [r'(?:event\s*id|eventid|eid)[=:\s]+(\d{1,5})', r'\bEID[=:\s]+(\d{1,5})'],
    'process': [r'(?:image|process|process_name|exe)[=:\s]+"?([^"\s,;]+)', r'\b(Image|Command)\s*:\s*([^,;]+)'],
    'command_line': [r'(?:commandline|cmdline|command_line|cmd)[=:\s]+"?([^"\r\n]+)', r'CommandLine\s*:\s*([^\r\n]+)'],
    'user': [r'(?:user|username|account|subjectuser)[=:\s]+"?([^"\s,;]+)'],
    'host': [r'(?:host|hostname|computer|computername|device)[=:\s]+"?([^"\s,;]+)'],
    'src_ip': [r'(?:src|src_ip|source|source_ip)[=:\s]+(\d+\.\d+\.\d+\.\d+)'],
    'dst_ip': [r'(?:dst|dst_ip|dest|destination|destination_ip)[=:\s]+(\d+\.\d+\.\d+\.\d+)'],
}

RFC3164_RE = re.compile(r'^(?:<\d+>)?([A-Z][a-z]{2}\s+\d{1,2}\s+[\d:]{8})\s+([^\s]+)\s+([^:]+):\s*(.*)$')
RFC5424_RE = re.compile(r'^(?:<\d+>)?\d\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)$')


def _lower(text):
    return (text or '').lower()


def _hash_id(*parts):
    h = hashlib.sha1('|'.join(str(p) for p in parts).encode('utf-8', 'ignore')).hexdigest()
    return h[:16]


def _first_match(patterns, text, group=1):
    for pat in patterns:
        m = re.search(pat, text, re.I)
        if m:
            try:
                if m.lastindex and m.lastindex >= group:
                    return m.group(group).strip(' "')
                return m.group(1).strip(' "')
            except Exception:
                continue
    return ''


def identify_source(text, proto='', dport=0):
    low = _lower(text)
    platform = 'unknown'
    source = ''
    for needle, plat, src in SOURCE_KEYWORDS:
        if needle in low:
            platform, source = plat, src
            break
    if not source:
        if proto in ('Syslog', 'Syslog TLS') or dport in (514, 6514):
            source = 'Syslog'
            platform = 'network'
        elif proto == 'Elastic Beats' or dport == 5044:
            source = 'Elastic Beats'
            platform = 'siem'
        elif proto in ('NetFlow', 'IPFIX', 'sFlow') or dport in (2055, 4739, 6343):
            source = proto or 'Flow Telemetry'
            platform = 'network'
        elif proto in ('SNMP Trap', 'SNMP') or dport in (161, 162):
            source = 'SNMP'
            platform = 'network'
    return platform, source


def parse_syslog_header(text):
    text = text or ''
    m = RFC3164_RE.match(text)
    if m:
        return {'syslog_format': 'RFC3164', 'timestamp_text': m.group(1), 'host': m.group(2), 'program': m.group(3), 'message': m.group(4)}
    m = RFC5424_RE.match(text)
    if m:
        return {'syslog_format': 'RFC5424', 'timestamp_text': m.group(1), 'host': m.group(2), 'program': m.group(3), 'procid': m.group(4), 'msgid': m.group(5), 'message': m.group(7)}
    return {'message': text}


def extract_fields(text):
    fields = {}
    for key, patterns in FIELD_PATTERNS.items():
        val = _first_match(patterns, text)
        if key == 'process' and not val:
            # Pattern with two capture groups can return the label; retry group 2.
            val = _first_match(patterns, text, group=2)
        if val:
            fields[key] = val
    return fields


def event_type_from_ids(event_id, source):
    if not event_id:
        return '', []
    source_low = _lower(source)
    if 'sysmon' in source_low and event_id in SYSMON_EVENT_MAP:
        return SYSMON_EVENT_MAP[event_id]
    if event_id in WINDOWS_EVENT_MAP:
        return WINDOWS_EVENT_MAP[event_id]
    return '', []


def behavior_from_text(text):
    event_types = []
    attack = []
    for pat, etype, tids in BEHAVIOR_PATTERNS:
        if re.search(pat, text, re.I):
            event_types.append(etype)
            attack.extend(tids)
    return event_types, sorted(set(attack))



def attack_ids_from_text(text):
    ids = re.findall(r'T\d{4}(?:\.\d{3})?', text or '', re.I)
    return sorted(set(x.upper() for x in ids))

def normalize_event(ev):
    """Return zero or more normalized events from a packet-derived event.

    The input is the existing flow event dictionary.  The output is deliberately
    stable and generic so future v2 phases can use it without caring whether the
    evidence came from Syslog, Beats, Zeek, Windows, Linux, macOS, cloud, or a
    network appliance log forwarded through the capture.
    """
    evidence = ev.get('evidence') or {}
    text = evidence.get('payload_hint') or evidence.get('query') or ev.get('summary') or ''
    proto = ev.get('protocol') or ''
    dport = int(ev.get('dport') or 0)
    if not text and proto not in ('Syslog', 'Syslog TLS', 'Elastic Beats', 'NetFlow', 'IPFIX', 'sFlow', 'SNMP Trap'):
        return []

    platform, log_source = identify_source(text, proto, dport)
    if not log_source and not text:
        return []

    syslog = parse_syslog_header(text) if proto in ('Syslog', 'Syslog TLS') or dport in (514, 6514) else {'message': text}
    body = syslog.get('message') or text
    fields = extract_fields(body)
    event_id = fields.get('event_id') or _first_match([r'\bEventID[=:\s]*(\d+)', r'\bEventCode[=:\s]*(\d+)'], body)
    etype, event_attack = event_type_from_ids(event_id, log_source)
    behavior_types, behavior_attack = behavior_from_text(body)
    if not etype:
        etype = behavior_types[0] if behavior_types else ('log_event' if log_source else 'network_observation')
    attack_candidates = sorted(set(event_attack + behavior_attack + attack_ids_from_text(body)))

    host = fields.get('host') or syslog.get('host') or ev.get('src_ip') or ''
    src_ip = fields.get('src_ip') or ev.get('src_ip') or ''
    dst_ip = fields.get('dst_ip') or ev.get('dst_ip') or ''

    normalized = {
        'event_id': _hash_id(ev.get('ts'), src_ip, dst_ip, proto, dport, body[:120]),
        'timestamp': ev.get('ts'),
        'platform': platform,
        'log_source': log_source or proto or 'Unknown',
        'event_type': etype,
        'source_event_id': event_id,
        'host': host,
        'user': fields.get('user', ''),
        'process': fields.get('process', ''),
        'command_line': fields.get('command_line', ''),
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'src_port': ev.get('sport') or 0,
        'dst_port': ev.get('dport') or 0,
        'transport_protocol': proto,
        'attack_candidates': attack_candidates,
        'confidence': 'medium' if attack_candidates else 'low',
        'raw': body[:1000],
        'evidence': {
            'packet_summary': ev.get('summary', ''),
            'syslog': syslog,
            'matched_behaviors': behavior_types,
        },
    }

    # Avoid producing generic noise for ordinary flows unless a log source,
    # event ID, or behavior was detected.
    if normalized['log_source'] in ('Unknown', 'TCP', 'UDP') and not attack_candidates and not behavior_types:
        return []
    return [normalized]


def summarize_normalized_events(events):
    by_platform = Counter()
    by_source = Counter()
    by_type = Counter()
    attack = Counter()
    examples = defaultdict(list)
    for ev in events or []:
        by_platform[ev.get('platform') or 'unknown'] += 1
        by_source[ev.get('log_source') or 'Unknown'] += 1
        by_type[ev.get('event_type') or 'unknown'] += 1
        for tid in ev.get('attack_candidates') or []:
            attack[tid] += 1
            if len(examples[tid]) < 3:
                examples[tid].append({'event_type': ev.get('event_type'), 'log_source': ev.get('log_source'), 'host': ev.get('host'), 'evidence': ev.get('raw', '')[:180]})
    return {
        'total_events': len(events or []),
        'by_platform': dict(by_platform.most_common()),
        'by_log_source': dict(by_source.most_common()),
        'by_event_type': dict(by_type.most_common()),
        'attack_candidate_counts': dict(attack.most_common()),
        'attack_candidate_examples': dict(examples),
        'generated_at': time.time(),
    }
