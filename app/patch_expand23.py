from pathlib import Path
p=Path('app/attack/versioned.py')
s=p.read_text()
insert=r'''

# ---------------------------------------------------------------------------
# Expanded telemetry capability inference (steps 2 and 3)
# ---------------------------------------------------------------------------
# These profiles turn detected products and operating systems into telemetry
# capabilities.  They intentionally model what the environment can reasonably
# collect, not only the exact event that appeared in the PCAP.
PRODUCT_TELEMETRY_CAPABILITY_PROFILES = {
    'Sysmon': {
        'confidence': 'high', 'score': 94,
        'implied_sources': ['Sysmon'],
        'components': ['Process Creation','Process Termination','Process Metadata','Command Execution','Network Connection Creation','DNS Query','File Creation','File Modification','File Deletion','File Metadata','Registry Key Creation','Registry Key Modification','Registry Value Modification','Driver Load','Image Load','Named Pipe Creation','WMI Activity','WMI Event Subscription','Process Access','Clipboard Data'],
    },
    'Defender': {
        'confidence': 'high', 'score': 88,
        'implied_sources': ['Defender'],
        'components': ['Malware Detection','Threat Quarantine','Suspicious Script','Exploit Detection','Ransomware Behavior','Tamper Protection','Attack Surface Reduction','Controlled Folder Access','Process Activity','File Activity','Network Activity','Registry Key Modification','Script Execution'],
    },
    'Defender for Endpoint': {
        'confidence': 'high', 'score': 96,
        'implied_sources': ['Defender for Endpoint','Defender'],
        'components': ['Endpoint Detection Alert','Process Creation','Process Metadata','Command Execution','Script Execution','PowerShell Script Block','File Creation','File Modification','File Deletion','File Metadata','Registry Key Modification','Network Connection Creation','DNS Query','Module Load','Driver Load','User Account Authentication','Logon Session','Malware Detection','Suspicious Behavior','Exploit Detection','Credential Theft Detection','Ransomware Behavior','Sensor Health'],
    },
    'Zeek': {
        'confidence': 'high', 'score': 92,
        'implied_sources': ['Zeek'],
        'components': ['Network Traffic Flow','Network Connection Creation','DNS Query','DNS Response','HTTP Requests','HTTP Response','TLS SNI','TLS Certificate','X.509 Certificate','SMB Session','SMB File Access','File Transfer','FTP Activity','SSH Session','RDP Session','Kerberos Authentication','NTLM Authentication','DHCP Lease','Software Identification','User Agent','JA3 Fingerprint'],
    },
    'Suricata': {
        'confidence': 'high', 'score': 90,
        'implied_sources': ['Suricata'],
        'components': ['IDS Alerts','Network Traffic Content','Network Traffic Flow','DNS Query','HTTP Requests','HTTP Response','TLS SNI','TLS Certificate','SMB Session','File Transfer','Exploit Attempt','Malware Callback','C2 Beaconing','Protocol Anomaly','Signature Match'],
    },
    'Cisco ASA': {
        'confidence': 'high', 'score': 84,
        'implied_sources': ['Cisco ASA','VPN'],
        'components': ['Firewall Events','Allowed Connection','Denied Connection','Network Traffic Flow','NAT Translation','VPN Session','VPN Authentication','ACL Decision','Remote Access','Connection Teardown','Threat Alert'],
    },
    'Cisco IOS': {
        'confidence': 'medium', 'score': 78,
        'implied_sources': ['Cisco IOS'],
        'components': ['Network Device Logs','Network Device Authentication','Configuration Change','Interface Status','Routing Event','ACL Decision','SNMP Activity','NetFlow Export','Administrative Login','Command Execution'],
    },
    'Cisco NX-OS': {
        'confidence': 'medium', 'score': 78,
        'implied_sources': ['Cisco NX-OS'],
        'components': ['Network Device Logs','Network Device Authentication','Configuration Change','Interface Status','Routing Event','ACL Decision','SNMP Activity','NetFlow Export','Administrative Login','Command Execution'],
    },
    'Cisco Firepower': {
        'confidence': 'high', 'score': 86,
        'implied_sources': ['Cisco Firepower','Suricata'],
        'components': ['Firewall Events','IDS Alerts','Threat Alert','Allowed Connection','Denied Connection','Network Traffic Flow','DNS Query','HTTP Requests','TLS SNI','SMB Session','File Transfer','Exploit Attempt','Malware Callback'],
    },
    'Palo Alto': {
        'confidence': 'high', 'score': 86,
        'implied_sources': ['Palo Alto','VPN'],
        'components': ['Firewall Events','Allowed Connection','Denied Connection','Threat Alert','URL Filtering','DNS Security Event','VPN Session','VPN Authentication','NAT Translation','Application Identification','TLS Inspection','IPS Alert','Malware Detection','User-ID Mapping'],
    },
    'Fortinet': {
        'confidence': 'high', 'score': 84,
        'implied_sources': ['Fortinet','VPN'],
        'components': ['Firewall Events','Allowed Connection','Denied Connection','Threat Alert','URL Filtering','DNS Security Event','VPN Session','VPN Authentication','NAT Translation','Application Identification','TLS Inspection','IPS Alert','Malware Detection'],
    },
    'Check Point': {'confidence': 'high', 'score': 84, 'implied_sources': ['Check Point','VPN'], 'components': ['Firewall Events','Allowed Connection','Denied Connection','Threat Alert','URL Filtering','VPN Session','VPN Authentication','NAT Translation','Application Identification','TLS Inspection','IPS Alert','Malware Detection']},
    'SonicWall': {'confidence': 'medium', 'score': 80, 'implied_sources': ['SonicWall','VPN'], 'components': ['Firewall Events','Allowed Connection','Denied Connection','Threat Alert','VPN Session','VPN Authentication','NAT Translation','Application Identification','IPS Alert']},
    'pfSense': {'confidence': 'medium', 'score': 76, 'implied_sources': ['pfSense','VPN'], 'components': ['Firewall Events','Allowed Connection','Denied Connection','VPN Session','VPN Authentication','NAT Translation','Network Traffic Flow']},
    'OPNsense': {'confidence': 'medium', 'score': 76, 'implied_sources': ['OPNsense','VPN'], 'components': ['Firewall Events','Allowed Connection','Denied Connection','VPN Session','VPN Authentication','NAT Translation','Network Traffic Flow']},
    'Apache': {'confidence': 'medium', 'score': 78, 'implied_sources': ['Apache'], 'components': ['HTTP Requests','HTTP Response','URL Path','Query String','User Agent','Source IP','Web Authentication','Web Error','File Request','File Upload','Web Shell Indicator','Server-Side Script Execution']},
    'Nginx': {'confidence': 'medium', 'score': 78, 'implied_sources': ['Nginx'], 'components': ['HTTP Requests','HTTP Response','URL Path','Query String','User Agent','Source IP','Web Authentication','Web Error','File Request','File Upload','Web Shell Indicator','Server-Side Script Execution']},
    'IIS': {'confidence': 'medium', 'score': 80, 'implied_sources': ['IIS'], 'components': ['HTTP Requests','HTTP Response','URL Path','Query String','User Agent','Source IP','Web Authentication','Web Error','File Request','File Upload','Web Shell Indicator','Server-Side Script Execution','Application Pool Event']},
    'Kubernetes Audit': {'confidence': 'high', 'score': 90, 'implied_sources': ['Kubernetes Audit'], 'components': ['Kubernetes API Request','Pod Creation','Container Creation','Secret Access','ConfigMap Access','Service Account Use','RBAC Change','Exec Into Container','Image Pull','Deployment Change','Namespace Activity','Admission Controller Event']},
    'Falco': {'confidence': 'high', 'score': 88, 'implied_sources': ['Falco'], 'components': ['Runtime Detection Alert','Process Creation','Command Execution','File Access','Container Escape Attempt','Privilege Escalation','Shell Spawned in Container','Sensitive File Read','Network Connection Creation','Unexpected Binary Execution','Kubernetes API Request']},
    'osquery': {'confidence': 'high', 'score': 86, 'implied_sources': ['osquery'], 'components': ['Process Inventory','Process Creation','Listening Ports','Logged-in Users','File Metadata','File Hash','Package Inventory','Kernel Modules','Startup Items','Crontab Entries','User Account Metadata','Group Metadata','Network Connection Creation','Browser Extensions','Certificates','Mounts']},
    'Packetbeat': {'confidence': 'medium', 'score': 82, 'implied_sources': ['Packetbeat'], 'components': ['Network Traffic Flow','DNS Query','HTTP Requests','TLS SNI','SMB Session','Database Query','Application Protocol Metadata']},
    'NetFlow': {'confidence': 'medium', 'score': 74, 'implied_sources': ['NetFlow'], 'components': ['Network Traffic Flow','Allowed Connection','Connection Metadata','Source IP','Destination IP','Port','Protocol']},
    'IPFIX': {'confidence': 'medium', 'score': 74, 'implied_sources': ['IPFIX'], 'components': ['Network Traffic Flow','Allowed Connection','Connection Metadata','Source IP','Destination IP','Port','Protocol']},
}

OS_TELEMETRY_CAPABILITY_PROFILES = {
    'windows': {
        'name': 'Windows OS Baseline', 'confidence': 'medium', 'score': 72,
        'log_sources': ['Windows Security','Windows System','Windows Application','PowerShell Operational','Defender','Task Scheduler','WinRM','WMI','SMB','Windows DNS','Windows DHCP','Windows Firewall','RDP','Active Directory'],
        'components': ['Windows Event Logs','User Account Authentication','Credential Validation','Kerberos Authentication','NTLM Authentication','Logon Session','Remote Logon','Account Management','Group Membership Change','Privilege Use','Object Access','Policy Change','Process Creation','Service Creation','Service Activity','Driver Load','System Boot','Device Installation','PowerShell Script Block','Script Execution','PowerShell Remoting','Malware Detection','Threat Quarantine','Scheduled Job','Remote Service Session','WMI Activity','WMI Event Subscription','SMB Session','File Share Access','Named Pipe Creation','DNS Query','DHCP Lease','HTTP Requests','Firewall Events','Application Control Decision','Forwarded Event','Directory Service Access','Active Directory Object Modification','Certificate Enrollment'],
    },
    'linux': {
        'name': 'Linux OS Baseline', 'confidence': 'medium', 'score': 70,
        'log_sources': ['auditd','auth.log','secure','sudo','sshd','cron','journald','systemd','kernel','rsyslog','syslog-ng','SELinux','AppArmor'],
        'components': ['Process Creation','Command Execution','Unix Shell','File Access','File Modification','File Deletion','File Metadata','Privilege Escalation','User Account Authentication','SSH Session','Sudo Command','su Command','PAM Event','User Session','Password Change','Scheduled Job','Cron Job','Service Creation','Service Activity','Systemd Service','System Boot','Kernel Events','Kernel Module Load','Network Interface','SELinux AVC','AppArmor Denial','Syslog Message'],
    },
    'macos': {
        'name': 'macOS OS Baseline', 'confidence': 'medium', 'score': 70,
        'log_sources': ['Apple Unified Logging','OpenBSM','launchd','launchctl','Gatekeeper','TCC','XProtect','Endpoint Security','FileVault'],
        'components': ['Process Activity','Process Creation','Command Execution','File Access','File Modification','Authentication Logs','User Account Authentication','Privilege Changes','Network Activity','Application Launch','System Extension Event','Security Policy Event','TCC Decision','Gatekeeper Decision','XProtect Event','Launch Agent Created','Launch Daemon Created','Service Loaded','Downloaded File Assessment','Malware Detection','Privacy Permission Grant','Quarantine Attribute','Disk Encryption Event'],
    },
}

# Expand existing source profiles in-place so both STIX and heuristic engines can
# use the richer product capability model.
for _src, _profile in PRODUCT_TELEMETRY_CAPABILITY_PROFILES.items():
    SOURCE_CATEGORY.setdefault(_src, SOURCE_CATEGORY.get(_src, 'Telemetry Product'))
    _base = list(SOURCE_COMPONENTS.get(_src, []) or [])
    for _comp in _profile.get('components', []) or []:
        if _comp not in _base:
            _base.append(_comp)
    SOURCE_COMPONENTS[_src] = _base
for _os_key, _profile in OS_TELEMETRY_CAPABILITY_PROFILES.items():
    _os_src = _profile['name']
    SOURCE_CATEGORY[_os_src] = 'OS Baseline'
    SOURCE_COMPONENTS[_os_src] = list(dict.fromkeys(_profile.get('components', []) or []))

# Add practical ATT&CK technique backfills for common capability names.  These
# are used when official x_mitre_data_sources are unavailable/incomplete in the
# bundled dataset, and they keep inferred coverage explainable by component.
COMPONENT_TECHNIQUES.update({
    'Process Termination': ['T1489','T1562.001'], 'Process Metadata': ['T1057','T1518','T1518.001'],
    'Script Execution': ['T1059','T1059.001','T1059.003','T1059.004','T1059.006'], 'Module Load': ['T1129','T1055'],
    'File Creation': ['T1105','T1027','T1036','T1074','T1547','T1053'], 'File Modification': ['T1027','T1036','T1070','T1486','T1565'],
    'File Deletion': ['T1070.004','T1485','T1486'], 'File Metadata': ['T1005','T1083','T1039'], 'File Hash': ['T1027','T1036'],
    'File Transfer': ['T1105','T1570','T1041','T1567'], 'File Share Access': ['T1039','T1135','T1021.002','T1570'],
    'Registry Key Creation': ['T1547.001','T1112','T1546'], 'Registry Value Modification': ['T1547.001','T1112','T1562.001'],
    'Driver Load': ['T1068','T1014','T1547.006'], 'Image Load': ['T1574','T1055','T1129'], 'Named Pipe Creation': ['T1021.002','T1559','T1135'],
    'WMI Event Subscription': ['T1546.003','T1047'], 'Process Access': ['T1003.001','T1055','T1555'], 'Clipboard Data': ['T1115'],
    'Malware Detection': ['T1204','T1105','T1027','T1562.001'], 'Threat Quarantine': ['T1562.001','T1070'], 'Suspicious Script': ['T1059','T1027'],
    'Exploit Detection': ['T1190','T1203','T1068'], 'Ransomware Behavior': ['T1486','T1485'], 'Tamper Protection': ['T1562.001'],
    'Attack Surface Reduction': ['T1562.001','T1204','T1059.001'], 'Controlled Folder Access': ['T1486','T1485'],
    'Endpoint Detection Alert': ['T1059','T1105','T1027','T1562.001','T1003'], 'Suspicious Behavior': ['T1059','T1105','T1027','T1071.001'],
    'Credential Theft Detection': ['T1003','T1555','T1110'], 'Sensor Health': ['T1562.001','T1562.006'],
    'DNS Response': ['T1071.004','T1568','T1590.002'], 'TLS SNI': ['T1071.001','T1573','T1567'], 'TLS Certificate': ['T1573','T1588.004','T1553'],
    'X.509 Certificate': ['T1588.004','T1553'], 'SMB File Access': ['T1021.002','T1039','T1570'], 'FTP Activity': ['T1071.002','T1048'],
    'RDP Session': ['T1021.001','T1078','T1110'], 'Kerberos Authentication': ['T1558','T1558.003','T1078'], 'NTLM Authentication': ['T1110','T1550.002','T1078'],
    'DHCP Lease': ['T1016','T1018'], 'Software Identification': ['T1518','T1518.001'], 'User Agent': ['T1071.001','T1189'], 'JA3 Fingerprint': ['T1071.001','T1573'],
    'HTTP Response': ['T1071.001','T1190','T1189','T1567'], 'Exploit Attempt': ['T1190','T1203','T1068'], 'Malware Callback': ['T1071.001','T1071.004','T1105'],
    'C2 Beaconing': ['T1071.001','T1071.004','T1095','T1573'], 'Protocol Anomaly': ['T1571','T1095'], 'Signature Match': ['T1071.001','T1190','T1041'],
    'Allowed Connection': ['T1046','T1049','T1071.001','T1041','T1567'], 'Denied Connection': ['T1046','T1562.004','T1498','T1499'],
    'NAT Translation': ['T1090','T1041','T1567'], 'VPN Session': ['T1133','T1021','T1078'], 'VPN Authentication': ['T1133','T1078','T1110'],
    'ACL Decision': ['T1046','T1562.004','T1498'], 'Remote Access': ['T1133','T1021','T1078'], 'Connection Teardown': ['T1049','T1041'],
    'Threat Alert': ['T1190','T1071.001','T1041','T1567'], 'Network Device Authentication': ['T1078','T1110'], 'Configuration Change': ['T1562.004','T1601'],
    'Interface Status': ['T1016','T1498','T1499'], 'Routing Event': ['T1016','T1090'], 'SNMP Activity': ['T1046','T1016'], 'NetFlow Export': ['T1046','T1049','T1041'],
    'Administrative Login': ['T1078','T1021'], 'URL Filtering': ['T1189','T1071.001','T1567'], 'DNS Security Event': ['T1071.004','T1568'],
    'Application Identification': ['T1071','T1046'], 'TLS Inspection': ['T1071.001','T1573'], 'IPS Alert': ['T1190','T1203','T1046'], 'User-ID Mapping': ['T1078','T1110'],
    'URL Path': ['T1190','T1189','T1071.001'], 'Query String': ['T1190','T1071.001'], 'Source IP': ['T1046','T1018','T1049'],
    'Web Authentication': ['T1078','T1110','T1133'], 'Web Error': ['T1190','T1059'], 'File Request': ['T1005','T1039','T1567'],
    'File Upload': ['T1105','T1190','T1505.003'], 'Web Shell Indicator': ['T1505.003','T1059'], 'Server-Side Script Execution': ['T1059','T1505.003'],
    'Application Pool Event': ['T1505.003','T1543.003'], 'Kubernetes API Request': ['T1613','T1611','T1609','T1610'], 'Pod Creation': ['T1610'],
    'Container Creation': ['T1610'], 'Secret Access': ['T1552','T1555'], 'ConfigMap Access': ['T1613'], 'Service Account Use': ['T1078.004','T1552'],
    'RBAC Change': ['T1098','T1578'], 'Exec Into Container': ['T1609','T1059.012'], 'Image Pull': ['T1612','T1105'], 'Deployment Change': ['T1610','T1578'],
    'Namespace Activity': ['T1613'], 'Admission Controller Event': ['T1611','T1610'], 'Container Escape Attempt': ['T1611'], 'Shell Spawned in Container': ['T1059.012','T1609'],
    'Sensitive File Read': ['T1005','T1552'], 'Unexpected Binary Execution': ['T1204','T1059'], 'Process Inventory': ['T1057'], 'Listening Ports': ['T1049'],
    'Logged-in Users': ['T1033','T1078'], 'Package Inventory': ['T1518','T1518.001'], 'Kernel Modules': ['T1547.006','T1014'], 'Startup Items': ['T1547'],
    'Crontab Entries': ['T1053.003'], 'User Account Metadata': ['T1087'], 'Group Metadata': ['T1069'], 'Browser Extensions': ['T1176'],
    'Certificates': ['T1553','T1588.004'], 'Mounts': ['T1083','T1005'], 'Credential Validation': ['T1078','T1110','T1550'],
    'Remote Logon': ['T1021','T1078'], 'Account Management': ['T1098','T1136'], 'Group Membership Change': ['T1098','T1069'],
    'Privilege Use': ['T1068','T1548'], 'Object Access': ['T1005','T1039'], 'Policy Change': ['T1562.001','T1484'], 'System Boot': ['T1547','T1529'],
    'Device Installation': ['T1547.006'], 'PowerShell Remoting': ['T1021.006','T1059.001'], 'Remote Service Session': ['T1021','T1569'],
    'Directory Service Access': ['T1087.002','T1069.002','T1482'], 'Active Directory Object Modification': ['T1098','T1484.001','T1136'], 'Certificate Enrollment': ['T1553.004','T1649'],
    'Unix Shell': ['T1059.004'], 'Sudo Command': ['T1548.003','T1059.004'], 'su Command': ['T1548','T1078'], 'PAM Event': ['T1078','T1110'],
    'User Session': ['T1033','T1078'], 'Password Change': ['T1098','T1110'], 'Cron Job': ['T1053.003'], 'Systemd Service': ['T1543.002'],
    'Kernel Module Load': ['T1547.006','T1014'], 'SELinux AVC': ['T1562.001'], 'AppArmor Denial': ['T1562.001'], 'Syslog Message': ['T1059','T1078'],
    'Application Launch': ['T1059','T1204'], 'System Extension Event': ['T1547.006'], 'Security Policy Event': ['T1562.001'], 'TCC Decision': ['T1555.001','T1562.001'],
    'Gatekeeper Decision': ['T1553.001','T1204'], 'XProtect Event': ['T1204','T1105'], 'Launch Agent Created': ['T1543.001'], 'Launch Daemon Created': ['T1543.004'],
    'Service Loaded': ['T1543'], 'Downloaded File Assessment': ['T1204','T1189'], 'Privacy Permission Grant': ['T1555.001','T1113'], 'Quarantine Attribute': ['T1553.001'],
    'Disk Encryption Event': ['T1486','T1005'],
})


def _detect_os_capability_tokens(result, detected_sources=None):
    """Return normalized OS tokens that justify baseline telemetry inference."""
    tokens = set()
    scope = _detected_coverage_scope(result or {}, detected_sources or detected_data_sources(result or {}))
    for s in scope:
        ns = _norm_attack_string(s)
        if 'windows' in ns: tokens.add('windows')
        if 'linux' in ns: tokens.add('linux')
        if 'macos' in ns or 'mac os' in ns: tokens.add('macos')
        if 'network' in ns: tokens.add('network')
    for source in detected_sources or []:
        cat = SOURCE_CATEGORY.get(_canon_source_name(source) or source, '')
        if cat == 'Windows': tokens.add('windows')
        elif cat == 'Linux': tokens.add('linux')
        elif cat == 'macOS': tokens.add('macos')
        elif cat == 'Network': tokens.add('network')
    return sorted(tokens)


def _telemetry_capability_records(result):
    """Detected plus inferred telemetry capabilities for theoretical coverage."""
    result = result or {}
    detected = [_canon_source_name(s) or s for s in detected_data_sources(result)]
    records = []
    seen = set()

    def add_record(source, reason, confidence='medium', score=78, components=None, inferred=False, basis='detected log source'):
        source = _canon_source_name(source) or source
        key = (source, reason, inferred)
        if key in seen:
            return
        seen.add(key)
        comps = list(dict.fromkeys(components if components is not None else SOURCE_COMPONENTS.get(source, []) or []))
        records.append({
            'source': source, 'category': SOURCE_CATEGORY.get(source, 'Other'), 'reason': reason,
            'confidence': confidence, 'score': score, 'components': comps,
            'inferred': bool(inferred), 'basis': basis,
        })

    for source in detected:
        prof = PRODUCT_TELEMETRY_CAPABILITY_PROFILES.get(source)
        if prof:
            add_record(source, f'{source} product detected; expanded to standard product telemetry capabilities.', prof.get('confidence','high'), prof.get('score',90), prof.get('components', []), False, 'detected product')
            for implied in prof.get('implied_sources', []) or []:
                if implied != source:
                    add_record(implied, f'{source} implies {implied} telemetry capability.', prof.get('confidence','high'), max(65, int(prof.get('score',90))-4), SOURCE_COMPONENTS.get(implied, []), True, 'product-inferred source')
        else:
            cat = SOURCE_CATEGORY.get(source, 'Other')
            base_score = 82 if cat in {'Windows','Linux','macOS'} else 76 if cat == 'Network' else 68
            add_record(source, f'{source} detected directly in parsed logs/events/traffic.', 'high' if cat != 'Other' else 'medium', base_score, SOURCE_COMPONENTS.get(source, []), False, 'detected log source')

    for os_token in _detect_os_capability_tokens(result, detected):
        prof = OS_TELEMETRY_CAPABILITY_PROFILES.get(os_token)
        if not prof:
            continue
        add_record(prof['name'], f'{os_token.title()} assets detected; inferred baseline OS telemetry capabilities.', prof.get('confidence','medium'), prof.get('score',70), prof.get('components', []), True, 'os-baseline')
        for implied in prof.get('log_sources', []) or []:
            if implied not in detected:
                add_record(implied, f'{prof["name"]} implies standard {implied} telemetry capability.', 'low', max(55, int(prof.get('score',70))-10), SOURCE_COMPONENTS.get(implied, []), True, 'os-inferred source')

    # If any high-fidelity network sensor is present, add generic network
    # visibility so C2/exfil/discovery coverage does not depend on a single log.
    if any((SOURCE_CATEGORY.get(s) == 'Network' or s in PRODUCT_TELEMETRY_CAPABILITY_PROFILES and SOURCE_CATEGORY.get(s) == 'Network') for s in detected):
        add_record('Network Visibility Baseline', 'Network telemetry sensor detected; inferred enterprise network visibility capabilities.', 'medium', 72, ['Network Traffic Flow','Network Traffic Content','DNS Query','HTTP Requests','TLS SNI','SMB Session','SSH Session','VPN Session','Firewall Events'], True, 'network-baseline')
        SOURCE_CATEGORY['Network Visibility Baseline'] = 'Network'
        SOURCE_COMPONENTS['Network Visibility Baseline'] = ['Network Traffic Flow','Network Traffic Content','DNS Query','HTTP Requests','TLS SNI','SMB Session','SSH Session','VPN Session','Firewall Events']
    return records


def _match_capability_record_to_attack(record):
    """Resolve a capability record to components, data sources, and techniques."""
    source = record.get('source')
    components = list(dict.fromkeys(record.get('components') or SOURCE_COMPONENTS.get(source, []) or []))
    # Reuse the STIX matching path by temporarily making sure the source has the
    # expanded components registered.
    if components:
        old = SOURCE_COMPONENTS.get(source)
        SOURCE_COMPONENTS[source] = components
        try:
            match = _source_stix_matches(source)
        finally:
            if old is None:
                SOURCE_COMPONENTS.pop(source, None)
            else:
                SOURCE_COMPONENTS[source] = old
    else:
        match = _source_stix_matches(source)
    techniques = set(match.get('techniques') or [])
    # Always include local component technique backfill.  Official STIX remains
    # preferred, but the bundled dataset and ATT&CK component names are not
    # always perfectly aligned with product vocabulary.
    for comp in components:
        techniques.update(_component_technique_ids(comp))
    for tid in _source_technique_expansion(source):
        techniques.add(tid)
    return {
        'source': source,
        'data_components': sorted(set(match.get('data_components') or []) | set(components)),
        'attack_data_sources': sorted(set(match.get('attack_data_sources') or []) | set(_attck_data_sources_for_source(source))),
        'techniques': {tid for tid in techniques if tid in VALID_TECHNIQUES},
    }
'''
marker='\ndef build_data_source_coverage(result, coverage_engine=None):\n'
idx=s.rfind(marker)
if idx==-1:
    raise SystemExit('final build_data_source_coverage marker not found')
s=s[:idx]+insert+s[idx:]
# Replace final build_data_source_coverage body
start=s.rfind(marker)
end=s.find('\ndef _build_model_with_engine', start)
new_func=r'''
def build_data_source_coverage(result, coverage_engine=None):
    engine = coverage_engine_from_result(result, coverage_engine)
    if engine == COVERAGE_ENGINE_HEURISTIC:
        # The legacy engine now also benefits from expanded SOURCE_COMPONENTS,
        # but keeps its original scoring/mapping behavior.
        return _HEURISTIC_BUILD_DATA_SOURCE_COVERAGE(result)

    coverage = {}
    records = _telemetry_capability_records(result or {})
    for record in records:
        source = record.get('source')
        category = record.get('category') or SOURCE_CATEGORY.get(source, 'Other')
        match = _match_capability_record_to_attack(record)
        components = set(match.get('data_components') or [])
        attack_data_sources = set(match.get('attack_data_sources') or [])
        for tid in match.get('techniques') or []:
            meta = VALID_TECHNIQUES.get(tid)
            if not meta:
                continue
            score = int(record.get('score') or 78)
            if record.get('confidence') == 'high':
                score = max(score, 88)
            elif record.get('confidence') == 'low':
                score = min(score, 68)
            if category == 'Network' and score > 88:
                score = 88
            cur = coverage.setdefault(tid, {
                'techniqueID': tid,
                'name': meta.get('name', tid),
                'tactic': meta.get('tactic', ''),
                'score': 0,
                'coverage': 'Theoretical',
                'data_sources': set(),
                'data_components': set(),
                'attack_data_sources': set(),
                'rationale': [],
                'confidence_labels': set(),
                'capability_basis': set(),
                'coverage_engine': COVERAGE_ENGINE_STIX,
            })
            cur['score'] = max(cur['score'], score)
            cur['data_sources'].add(source)
            cur['data_components'].update(components)
            cur['attack_data_sources'].update(attack_data_sources)
            cur['confidence_labels'].add(record.get('confidence','medium'))
            cur['capability_basis'].add(record.get('basis','telemetry capability'))
            cur['rationale'].append(
                f"{record.get('reason')} -> {len(components)} telemetry/data components -> supports {meta.get('name', tid)} theoretically ({record.get('confidence','medium')} confidence)."
            )
    out = []
    for item in coverage.values():
        for key in ('data_sources', 'data_components', 'attack_data_sources', 'confidence_labels', 'capability_basis'):
            item[key] = sorted(item[key])
        item['rationale'] = item['rationale'][:12]
        out.append(item)
    return sorted(out, key=lambda x: (-x['score'], x['tactic'], x['techniqueID']))

'''
s=s[:start]+new_func+s[end:]
# Patch diagnostics to use capability records instead of direct detected only
old="""    detected_sources = detected_data_sources(result)
    scope = _detected_coverage_scope(result, detected_sources)
    coverage = build_data_source_coverage({**result, 'coverage_engine': engine}, engine)
"""
new="""    detected_sources = detected_data_sources(result)
    capability_records = _telemetry_capability_records(result)
    scope = _detected_coverage_scope(result, detected_sources)
    coverage = build_data_source_coverage({**result, 'coverage_engine': engine}, engine)
"""
s=s.replace(old,new,1)
old_loop="""    for source in detected_sources:
        if engine == COVERAGE_ENGINE_HEURISTIC:
            comps = SOURCE_COMPONENTS.get(source, []) or []
            tids = set(_source_technique_expansion(source)) & applicable_ids
            ds_names = _attck_data_sources_for_source(source)
        else:
            match = _source_stix_matches(source)
            comps = match.get('data_components') or []
            tids = set(match.get('techniques') or []) & applicable_ids
            ds_names = match.get('attack_data_sources') or []
        for comp in comps:
            component_map.setdefault(comp, set()).add(source)
        for ds in ds_names:
            attack_ds.setdefault(ds, set()).add(source)
        source_rows.append({'source': source, 'category': SOURCE_CATEGORY.get(source, 'Other'), 'components': comps, 'attack_data_sources': ds_names, 'technique_count': len(tids), 'sample_techniques': sorted(tids)[:16]})
"""
new_loop="""    diag_records = capability_records if engine != COVERAGE_ENGINE_HEURISTIC else [{'source': s, 'category': SOURCE_CATEGORY.get(s, 'Other'), 'components': SOURCE_COMPONENTS.get(s, []) or [], 'confidence': 'high', 'basis': 'detected log source', 'inferred': False} for s in detected_sources]
    for record in diag_records:
        source = record.get('source')
        if engine == COVERAGE_ENGINE_HEURISTIC:
            comps = SOURCE_COMPONENTS.get(source, []) or []
            tids = set(_source_technique_expansion(source)) & applicable_ids
            ds_names = _attck_data_sources_for_source(source)
        else:
            match = _match_capability_record_to_attack(record)
            comps = match.get('data_components') or []
            tids = set(match.get('techniques') or []) & applicable_ids
            ds_names = match.get('attack_data_sources') or []
        for comp in comps:
            component_map.setdefault(comp, set()).add(source)
        for ds in ds_names:
            attack_ds.setdefault(ds, set()).add(source)
        source_rows.append({'source': source, 'category': record.get('category') or SOURCE_CATEGORY.get(source, 'Other'), 'components': comps, 'attack_data_sources': ds_names, 'technique_count': len(tids), 'sample_techniques': sorted(tids)[:16], 'confidence': record.get('confidence', 'medium'), 'basis': record.get('basis', 'detected log source'), 'inferred': bool(record.get('inferred')), 'reason': record.get('reason', '')})
"""
if old_loop not in s:
    raise SystemExit('diagnostic loop not found')
s=s.replace(old_loop,new_loop,1)
# Add fields to diagnostics return
old_return="""        'detected_log_sources': detected_sources,
        'source_rows': sorted(source_rows, key=lambda r: (r['category'], r['source'])),
"""
new_return="""        'detected_log_sources': detected_sources,
        'telemetry_capabilities': sorted(source_rows, key=lambda r: (r.get('inferred', False), r['category'], r['source'])),
        'product_inferred_capability_count': len([r for r in source_rows if r.get('basis') in ('detected product', 'product-inferred source')]),
        'os_inferred_capability_count': len([r for r in source_rows if r.get('basis') in ('os-baseline', 'os-inferred source')]),
        'source_rows': sorted(source_rows, key=lambda r: (r['category'], r['source'])),
"""
s=s.replace(old_return,new_return,1)
p.write_text(s)
