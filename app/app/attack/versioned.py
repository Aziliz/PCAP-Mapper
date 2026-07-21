import re
from app.config import ATTACK_VERSION, NAVIGATOR_VERSION
from app.attack.stix_dataset import load_official_techniques, tactic_counts, TACTIC_ORDER, SUPPORTED_ATTACK_VERSIONS, DEFAULT_ATTACK_VERSION, normalize_attack_version

VALID_TECHNIQUES = {
 'T1589': {'name':'Gather Victim Identity Information','tactic':'reconnaissance'},
 'T1589.001': {'name':'Gather Victim Identity Information: Credentials','tactic':'reconnaissance'},
 'T1589.002': {'name':'Gather Victim Identity Information: Email Addresses','tactic':'reconnaissance'},
 'T1589.003': {'name':'Gather Victim Identity Information: Employee Names','tactic':'reconnaissance'},
 'T1590': {'name':'Gather Victim Network Information','tactic':'reconnaissance'},
 'T1590.001': {'name':'Gather Victim Network Information: Domain Properties','tactic':'reconnaissance'},
 'T1590.002': {'name':'Gather Victim Network Information: DNS','tactic':'reconnaissance'},
 'T1590.003': {'name':'Gather Victim Network Information: Network Trust Dependencies','tactic':'reconnaissance'},
 'T1590.004': {'name':'Gather Victim Network Information: Network Topology','tactic':'reconnaissance'},
 'T1590.005': {'name':'Gather Victim Network Information: IP Addresses','tactic':'reconnaissance'},
 'T1590.006': {'name':'Gather Victim Network Information: Network Security Appliances','tactic':'reconnaissance'},
 'T1591': {'name':'Gather Victim Org Information','tactic':'reconnaissance'},
 'T1591.001': {'name':'Gather Victim Org Information: Determine Physical Locations','tactic':'reconnaissance'},
 'T1591.002': {'name':'Gather Victim Org Information: Business Relationships','tactic':'reconnaissance'},
 'T1591.003': {'name':'Gather Victim Org Information: Identify Business Tempo','tactic':'reconnaissance'},
 'T1591.004': {'name':'Gather Victim Org Information: Identify Roles','tactic':'reconnaissance'},
 'T1592': {'name':'Gather Victim Host Information','tactic':'reconnaissance'},
 'T1592.001': {'name':'Gather Victim Host Information: Hardware','tactic':'reconnaissance'},
 'T1592.002': {'name':'Gather Victim Host Information: Software','tactic':'reconnaissance'},
 'T1592.003': {'name':'Gather Victim Host Information: Firmware','tactic':'reconnaissance'},
 'T1592.004': {'name':'Gather Victim Host Information: Client Configurations','tactic':'reconnaissance'},
 'T1593': {'name':'Search Open Websites/Domains','tactic':'reconnaissance'},
 'T1593.001': {'name':'Search Open Websites/Domains: Social Media','tactic':'reconnaissance'},
 'T1593.002': {'name':'Search Open Websites/Domains: Search Engines','tactic':'reconnaissance'},
 'T1593.003': {'name':'Search Open Websites/Domains: Code Repositories','tactic':'reconnaissance'},
 'T1594': {'name':'Search Victim-Owned Websites','tactic':'reconnaissance'},
 'T1595': {'name':'Active Scanning','tactic':'reconnaissance'},
 'T1595.001': {'name':'Active Scanning: Scanning IP Blocks','tactic':'reconnaissance'},
 'T1595.002': {'name':'Active Scanning: Vulnerability Scanning','tactic':'reconnaissance'},
 'T1595.003': {'name':'Active Scanning: Wordlist Scanning','tactic':'reconnaissance'},
 'T1596': {'name':'Search Open Technical Databases','tactic':'reconnaissance'},
 'T1596.001': {'name':'Search Open Technical Databases: DNS/Passive DNS','tactic':'reconnaissance'},
 'T1596.002': {'name':'Search Open Technical Databases: WHOIS','tactic':'reconnaissance'},
 'T1596.003': {'name':'Search Open Technical Databases: Digital Certificates','tactic':'reconnaissance'},
 'T1596.004': {'name':'Search Open Technical Databases: CDNs','tactic':'reconnaissance'},
 'T1596.005': {'name':'Search Open Technical Databases: Scan Databases','tactic':'reconnaissance'},
 'T1597': {'name':'Search Closed Sources','tactic':'reconnaissance'},
 'T1597.001': {'name':'Search Closed Sources: Threat Intel Vendors','tactic':'reconnaissance'},
 'T1597.002': {'name':'Search Closed Sources: Purchase Technical Data','tactic':'reconnaissance'},
 'T1598': {'name':'Phishing for Information','tactic':'reconnaissance'},
 'T1598.001': {'name':'Phishing for Information: Spearphishing Service','tactic':'reconnaissance'},
 'T1598.002': {'name':'Phishing for Information: Spearphishing Attachment','tactic':'reconnaissance'},
 'T1598.003': {'name':'Phishing for Information: Spearphishing Link','tactic':'reconnaissance'},

 # Resource Development - ATT&CK v18 TA0042.
 'T1650': {'name':'Acquire Access','tactic':'resource-development'},
 'T1583': {'name':'Acquire Infrastructure','tactic':'resource-development'},
 'T1583.001': {'name':'Acquire Infrastructure: Domains','tactic':'resource-development'},
 'T1583.002': {'name':'Acquire Infrastructure: DNS Server','tactic':'resource-development'},
 'T1583.003': {'name':'Acquire Infrastructure: Virtual Private Server','tactic':'resource-development'},
 'T1583.004': {'name':'Acquire Infrastructure: Server','tactic':'resource-development'},
 'T1583.005': {'name':'Acquire Infrastructure: Botnet','tactic':'resource-development'},
 'T1583.006': {'name':'Acquire Infrastructure: Web Services','tactic':'resource-development'},
 'T1583.007': {'name':'Acquire Infrastructure: Serverless','tactic':'resource-development'},
 'T1583.008': {'name':'Acquire Infrastructure: Malvertising','tactic':'resource-development'},
 'T1586': {'name':'Compromise Accounts','tactic':'resource-development'},
 'T1586.001': {'name':'Compromise Accounts: Social Media Accounts','tactic':'resource-development'},
 'T1586.002': {'name':'Compromise Accounts: Email Accounts','tactic':'resource-development'},
 'T1586.003': {'name':'Compromise Accounts: Cloud Accounts','tactic':'resource-development'},
 'T1584': {'name':'Compromise Infrastructure','tactic':'resource-development'},
 'T1584.001': {'name':'Compromise Infrastructure: Domains','tactic':'resource-development'},
 'T1584.002': {'name':'Compromise Infrastructure: DNS Server','tactic':'resource-development'},
 'T1584.003': {'name':'Compromise Infrastructure: Virtual Private Server','tactic':'resource-development'},
 'T1584.004': {'name':'Compromise Infrastructure: Server','tactic':'resource-development'},
 'T1584.005': {'name':'Compromise Infrastructure: Botnet','tactic':'resource-development'},
 'T1584.006': {'name':'Compromise Infrastructure: Web Services','tactic':'resource-development'},
 'T1584.007': {'name':'Compromise Infrastructure: Serverless','tactic':'resource-development'},
 'T1584.008': {'name':'Compromise Infrastructure: Network Devices','tactic':'resource-development'},
 'T1587': {'name':'Develop Capabilities','tactic':'resource-development'},
 'T1587.001': {'name':'Develop Capabilities: Malware','tactic':'resource-development'},
 'T1587.002': {'name':'Develop Capabilities: Code Signing Certificates','tactic':'resource-development'},
 'T1587.003': {'name':'Develop Capabilities: Digital Certificates','tactic':'resource-development'},
 'T1587.004': {'name':'Develop Capabilities: Exploits','tactic':'resource-development'},
 'T1585': {'name':'Establish Accounts','tactic':'resource-development'},
 'T1585.001': {'name':'Establish Accounts: Social Media Accounts','tactic':'resource-development'},
 'T1585.002': {'name':'Establish Accounts: Email Accounts','tactic':'resource-development'},
 'T1585.003': {'name':'Establish Accounts: Cloud Accounts','tactic':'resource-development'},
 'T1683': {'name':'Generate Content','tactic':'resource-development'},
 'T1683.001': {'name':'Generate Content: Written Content','tactic':'resource-development'},
 'T1683.002': {'name':'Generate Content: Audio-Visual Content','tactic':'resource-development'},
 'T1588': {'name':'Obtain Capabilities','tactic':'resource-development'},
 'T1588.001': {'name':'Obtain Capabilities: Malware','tactic':'resource-development'},
 'T1588.002': {'name':'Obtain Capabilities: Tool','tactic':'resource-development'},
 'T1588.003': {'name':'Obtain Capabilities: Code Signing Certificates','tactic':'resource-development'},
 'T1588.004': {'name':'Obtain Capabilities: Digital Certificates','tactic':'resource-development'},
 'T1588.005': {'name':'Obtain Capabilities: Exploits','tactic':'resource-development'},
 'T1588.006': {'name':'Obtain Capabilities: Vulnerabilities','tactic':'resource-development'},
 'T1588.007': {'name':'Obtain Capabilities: Artificial Intelligence','tactic':'resource-development'},
 'T1608': {'name':'Stage Capabilities','tactic':'resource-development'},
 'T1608.001': {'name':'Stage Capabilities: Upload Malware','tactic':'resource-development'},
 'T1608.002': {'name':'Stage Capabilities: Upload Tool','tactic':'resource-development'},
 'T1608.003': {'name':'Stage Capabilities: Install Digital Certificate','tactic':'resource-development'},
 'T1608.004': {'name':'Stage Capabilities: Drive-by Target','tactic':'resource-development'},
 'T1608.005': {'name':'Stage Capabilities: Link Target','tactic':'resource-development'},
 'T1608.006': {'name':'Stage Capabilities: SEO Poisoning','tactic':'resource-development'},
 # Initial Access - ATT&CK v18 TA0001.
 'T1659': {'name':'Content Injection','tactic':'initial-access'},
 'T1189': {'name':'Drive-by Compromise','tactic':'initial-access'},
 'T1133': {'name':'External Remote Services','tactic':'initial-access'},
 'T1200': {'name':'Hardware Additions','tactic':'initial-access'},
 'T1091': {'name':'Replication Through Removable Media','tactic':'initial-access'},
 'T1195': {'name':'Supply Chain Compromise','tactic':'initial-access'},
 'T1195.001': {'name':'Supply Chain Compromise: Compromise Software Dependencies and Development Tools','tactic':'initial-access'},
 'T1195.002': {'name':'Supply Chain Compromise: Compromise Software Supply Chain','tactic':'initial-access'},
 'T1195.003': {'name':'Supply Chain Compromise: Compromise Hardware Supply Chain','tactic':'initial-access'},
 'T1199': {'name':'Trusted Relationship','tactic':'initial-access'},
 'T1078': {'name':'Valid Accounts','tactic':'initial-access'},
 'T1078.001': {'name':'Valid Accounts: Default Accounts','tactic':'initial-access'},
 'T1078.002': {'name':'Valid Accounts: Domain Accounts','tactic':'initial-access'},
 'T1078.003': {'name':'Valid Accounts: Local Accounts','tactic':'initial-access'},
 'T1078.004': {'name':'Valid Accounts: Cloud Accounts','tactic':'initial-access'},
 'T1669': {'name':'Wi-Fi Networks','tactic':'initial-access'},
 'T1566.002': {'name':'Phishing: Spearphishing Link','tactic':'initial-access'},
 'T1566.003': {'name':'Phishing: Spearphishing via Service','tactic':'initial-access'},
 'T1566.004': {'name':'Phishing: Spearphishing Voice','tactic':'initial-access'},
 'T1003.001': {'name':'OS Credential Dumping: LSASS Memory','tactic':'credential-access'},
 'T1005': {'name':'Data from Local System','tactic':'collection'},
 'T1016': {'name':'System Network Configuration Discovery','tactic':'discovery'},
 'T1018': {'name':'Remote System Discovery','tactic':'discovery'},
 'T1020': {'name':'Automated Exfiltration','tactic':'exfiltration'},
 'T1021.001': {'name':'Remote Services: Remote Desktop Protocol','tactic':'lateral-movement'},
 'T1021.002': {'name':'Remote Services: SMB/Windows Admin Shares','tactic':'lateral-movement'},
 'T1021.003': {'name':'Remote Services: Distributed Component Object Model','tactic':'lateral-movement'},
 'T1021.004': {'name':'Remote Services: SSH','tactic':'lateral-movement'},
 'T1021.005': {'name':'Remote Services: VNC','tactic':'lateral-movement'},
 'T1021.006': {'name':'Remote Services: Windows Remote Management','tactic':'lateral-movement'},
 'T1027': {'name':'Obfuscated Files or Information','tactic':'defense-evasion'},
 'T1030': {'name':'Data Transfer Size Limits','tactic':'exfiltration'},
 'T1033': {'name':'System Owner/User Discovery','tactic':'discovery'},
 'T1036': {'name':'Masquerading','tactic':'defense-evasion'},
 'T1039': {'name':'Data from Network Shared Drive','tactic':'collection'},
 'T1041': {'name':'Exfiltration Over C2 Channel','tactic':'exfiltration'},
 'T1046': {'name':'Network Service Discovery','tactic':'discovery'},
 'T1048': {'name':'Exfiltration Over Alternative Protocol','tactic':'exfiltration'},
 'T1049': {'name':'System Network Connections Discovery','tactic':'discovery'},
 'T1053.003': {'name':'Scheduled Task/Job: Cron','tactic':'persistence'},
 'T1053.005': {'name':'Scheduled Task/Job: Scheduled Task','tactic':'persistence'},
 'T1055': {'name':'Process Injection','tactic':'privilege-escalation'},
 'T1057': {'name':'Process Discovery','tactic':'discovery'},
 'T1059': {'name':'Command and Scripting Interpreter','tactic':'execution'},
 'T1059.001': {'name':'Command and Scripting Interpreter: PowerShell','tactic':'execution'},
 'T1059.004': {'name':'Command and Scripting Interpreter: Unix Shell','tactic':'execution'},
 # Execution - ATT&CK v18 TA0002 additional technique IDs.
 'T1197': {'name':'BITS Jobs','tactic':'execution'},
 'T1651': {'name':'Cloud Administration Command','tactic':'execution'},
 'T1059.002': {'name':'Command and Scripting Interpreter: AppleScript','tactic':'execution'},
 'T1059.003': {'name':'Command and Scripting Interpreter: Windows Command Shell','tactic':'execution'},
 'T1059.005': {'name':'Command and Scripting Interpreter: Visual Basic','tactic':'execution'},
 'T1059.006': {'name':'Command and Scripting Interpreter: Python','tactic':'execution'},
 'T1059.007': {'name':'Command and Scripting Interpreter: JavaScript','tactic':'execution'},
 'T1059.008': {'name':'Command and Scripting Interpreter: Network Device CLI','tactic':'execution'},
 'T1059.009': {'name':'Command and Scripting Interpreter: Cloud API','tactic':'execution'},
 'T1059.010': {'name':'Command and Scripting Interpreter: AutoHotKey & AutoIT','tactic':'execution'},
 'T1059.011': {'name':'Command and Scripting Interpreter: Lua','tactic':'execution'},
 'T1059.012': {'name':'Command and Scripting Interpreter: Hypervisor CLI','tactic':'execution'},
 'T1059.013': {'name':'Command and Scripting Interpreter: Container CLI/API','tactic':'execution'},
 'T1609': {'name':'Container Administration Command','tactic':'execution'},
 'T1610': {'name':'Deploy Container','tactic':'execution'},
 'T1675': {'name':'ESXi Administration Command','tactic':'execution'},
 'T1203': {'name':'Exploitation for Client Execution','tactic':'execution'},
 'T1574': {'name':'Hijack Execution Flow','tactic':'execution'},
 'T1574.001': {'name':'Hijack Execution Flow: DLL','tactic':'execution'},
 'T1574.004': {'name':'Hijack Execution Flow: Dylib Hijacking','tactic':'execution'},
 'T1574.005': {'name':'Hijack Execution Flow: Executable Installer File Permissions Weakness','tactic':'execution'},
 'T1574.006': {'name':'Hijack Execution Flow: Dynamic Linker Hijacking','tactic':'execution'},
 'T1574.007': {'name':'Hijack Execution Flow: Path Interception by PATH Environment Variable','tactic':'execution'},
 'T1574.008': {'name':'Hijack Execution Flow: Path Interception by Search Order Hijacking','tactic':'execution'},
 'T1574.009': {'name':'Hijack Execution Flow: Path Interception by Unquoted Path','tactic':'execution'},
 'T1574.010': {'name':'Hijack Execution Flow: Services File Permissions Weakness','tactic':'execution'},
 'T1574.011': {'name':'Hijack Execution Flow: Services Registry Permissions Weakness','tactic':'execution'},
 'T1574.012': {'name':'Hijack Execution Flow: COR_PROFILER','tactic':'execution'},
 'T1574.013': {'name':'Hijack Execution Flow: KernelCallbackTable','tactic':'execution'},
 'T1574.014': {'name':'Hijack Execution Flow: AppDomainManager','tactic':'execution'},
 'T1674': {'name':'Input Injection','tactic':'execution'},
 'T1559': {'name':'Inter-Process Communication','tactic':'execution'},
 'T1559.001': {'name':'Inter-Process Communication: Component Object Model','tactic':'execution'},
 'T1559.002': {'name':'Inter-Process Communication: Dynamic Data Exchange','tactic':'execution'},
 'T1559.003': {'name':'Inter-Process Communication: XPC Services','tactic':'execution'},
 'T1106': {'name':'Native API','tactic':'execution'},
 'T1677': {'name':'Poisoned Pipeline Execution','tactic':'execution'},
 'T1053': {'name':'Scheduled Task/Job','tactic':'execution'},
 'T1053.002': {'name':'Scheduled Task/Job: At','tactic':'execution'},
 'T1053.006': {'name':'Scheduled Task/Job: Systemd Timers','tactic':'execution'},
 'T1053.007': {'name':'Scheduled Task/Job: Container Orchestration Job','tactic':'execution'},
 'T1648': {'name':'Serverless Execution','tactic':'execution'},
 'T1129': {'name':'Shared Modules','tactic':'execution'},
 'T1072': {'name':'Software Deployment Tools','tactic':'execution'},
 'T1569': {'name':'System Services','tactic':'execution'},
 'T1569.001': {'name':'System Services: Launchctl','tactic':'execution'},
 'T1569.002': {'name':'System Services: Service Execution','tactic':'execution'},
 'T1569.003': {'name':'System Services: Systemctl','tactic':'execution'},
 'T1127': {'name':'Trusted Developer Utilities Proxy Execution','tactic':'execution'},
 'T1127.001': {'name':'Trusted Developer Utilities Proxy Execution: MSBuild','tactic':'execution'},
 'T1127.002': {'name':'Trusted Developer Utilities Proxy Execution: ClickOnce','tactic':'execution'},
 'T1127.003': {'name':'Trusted Developer Utilities Proxy Execution: JamPlus','tactic':'execution'},
 'T1204': {'name':'User Execution','tactic':'execution'},
 'T1204.001': {'name':'User Execution: Malicious Link','tactic':'execution'},
 'T1204.002': {'name':'User Execution: Malicious File','tactic':'execution'},
 'T1204.003': {'name':'User Execution: Malicious Image','tactic':'execution'},
 'T1204.004': {'name':'User Execution: Malicious Copy and Paste','tactic':'execution'},
 'T1204.005': {'name':'User Execution: Malicious Library','tactic':'execution'},
 'T1047': {'name':'Windows Management Instrumentation','tactic':'execution'},
 'T1069': {'name':'Permission Groups Discovery','tactic':'discovery'},
 'T1069.002': {'name':'Permission Groups Discovery: Domain Groups','tactic':'discovery'},
 'T1070.001': {'name':'Indicator Removal: Clear Windows Event Logs','tactic':'defense-evasion'},
 'T1070.002': {'name':'Indicator Removal: Clear Linux or Mac System Logs','tactic':'defense-evasion'},
 'T1071.001': {'name':'Application Layer Protocol: Web Protocols','tactic':'command-and-control'},
 'T1071.004': {'name':'Application Layer Protocol: DNS','tactic':'command-and-control'},
 'T1082': {'name':'System Information Discovery','tactic':'discovery'},
 'T1083': {'name':'File and Directory Discovery','tactic':'discovery'},
 'T1087': {'name':'Account Discovery','tactic':'discovery'},
 'T1087.002': {'name':'Account Discovery: Domain Account','tactic':'discovery'},
 'T1090': {'name':'Proxy','tactic':'command-and-control'},
 'T1095': {'name':'Non-Application Layer Protocol','tactic':'command-and-control'},
 'T1102': {'name':'Web Service','tactic':'command-and-control'},
 'T1105': {'name':'Ingress Tool Transfer','tactic':'command-and-control'},
 'T1110': {'name':'Brute Force','tactic':'credential-access'},
 'T1113': {'name':'Screen Capture','tactic':'collection'},
 'T1135': {'name':'Network Share Discovery','tactic':'discovery'},
 'T1136': {'name':'Create Account','tactic':'persistence'},
 'T1190': {'name':'Exploit Public-Facing Application','tactic':'initial-access'},
 'T1210': {'name':'Exploitation of Remote Services','tactic':'lateral-movement'},
 'T1219': {'name':'Remote Access Software','tactic':'command-and-control'},
 'T1486': {'name':'Data Encrypted for Impact','tactic':'impact'},
 'T1543.001': {'name':'Create or Modify System Process: Launch Agent','tactic':'persistence'},
 'T1543.002': {'name':'Create or Modify System Process: Systemd Service','tactic':'persistence'},
 'T1543.003': {'name':'Create or Modify System Process: Windows Service','tactic':'persistence'},
 'T1547.001': {'name':'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder','tactic':'persistence'},
 'T1552': {'name':'Unsecured Credentials','tactic':'credential-access'},
 'T1555': {'name':'Credentials from Password Stores','tactic':'credential-access'},
 'T1555.001': {'name':'Credentials from Password Stores: Keychain','tactic':'credential-access'},
 'T1557': {'name':'Adversary-in-the-Middle','tactic':'credential-access'},
 'T1558.003': {'name':'Steal or Forge Kerberos Tickets: Kerberoasting','tactic':'credential-access'},
 'T1560': {'name':'Archive Collected Data','tactic':'collection'},
 'T1562.001': {'name':'Impair Defenses: Disable or Modify Tools','tactic':'defense-evasion'},
 'T1562.002': {'name':'Impair Defenses: Disable Windows Event Logging','tactic':'defense-evasion'},
 'T1566': {'name':'Phishing','tactic':'initial-access'},
 'T1566.001': {'name':'Phishing: Spearphishing Attachment','tactic':'initial-access'},
 'T1567': {'name':'Exfiltration Over Web Service','tactic':'exfiltration'},
 'T1571': {'name':'Non-Standard Port','tactic':'command-and-control'},
 'T1572': {'name':'Protocol Tunneling','tactic':'command-and-control'},
}
LEGACY_TECHNIQUES = dict(VALID_TECHNIQUES)

# Prefer the selected MITRE ATT&CK Enterprise STIX dataset as the authoritative
# technique registry. v18 is the default; v13-v19 are selectable. Offline bundles
# are included under app/attack/data and may be replaced with official MITRE
# enterprise-attack.json files for version-exact operation.
_CURRENT_ATTACK_VERSION = DEFAULT_ATTACK_VERSION
_ATTACK_REGISTRY_CACHE = {}
ATTACK_DATASET_METADATA = {'version': f'{DEFAULT_ATTACK_VERSION}.0', 'dataset_label': 'ATT&CK Enterprise STIX'}

def attack_version_from_result(result=None, attack_version=None):
    raw = attack_version
    if raw is None and isinstance(result, dict):
        raw = result.get('attack_version_selected') or result.get('attack_version')
    return normalize_attack_version(raw)

def supported_attack_versions():
    return list(SUPPORTED_ATTACK_VERSIONS)

def _refresh_attack_derived_globals():
    global VALID_TACTICS, ATTACK_TACTIC_COUNTS
    VALID_TACTICS = [t for t in TACTIC_ORDER if t in set(v.get('tactic') for v in VALID_TECHNIQUES.values())] + sorted(set(v.get('tactic') for v in VALID_TECHNIQUES.values()) - set(TACTIC_ORDER))
    ATTACK_TACTIC_COUNTS = tactic_counts(VALID_TECHNIQUES)

def set_attack_version(version=None):
    global _CURRENT_ATTACK_VERSION, VALID_TECHNIQUES, ATTACK_DATASET_METADATA
    version = normalize_attack_version(version)
    if version in _ATTACK_REGISTRY_CACHE:
        techniques, meta = _ATTACK_REGISTRY_CACHE[version]
    else:
        techniques, meta = load_official_techniques(version)
        _ATTACK_REGISTRY_CACHE[version] = (techniques, meta)
    if techniques:
        VALID_TECHNIQUES = dict(techniques)
    ATTACK_DATASET_METADATA = meta
    _CURRENT_ATTACK_VERSION = version
    _refresh_attack_derived_globals()
    return version

set_attack_version(DEFAULT_ATTACK_VERSION)
VALID_PLATFORMS = ['Windows','macOS','Linux','Network','PRE','Containers','Office 365','SaaS','IaaS','Azure AD','Google Workspace']
COLORS = {'critical':'#7f0000','high':'#d73027','medium':'#fc8d59','low':'#fee08b','informational':'#91bfdb'}
PCAP_MAPPER_HEATMAP_COLORS = {'observed':'#ef4444','validated':'#facc15','covered':'#22c55e','partial':'#86efac','detectable':'#fb923c','missing':'#374151','notapp':'#6b7280','external':'#64748b'}
SCORES = {'critical':100,'high':80,'medium':55,'low':30,'informational':10}

def add_technique(ctx, technique_id, finding):
    if technique_id not in VALID_TECHNIQUES:
        return
    meta = VALID_TECHNIQUES[technique_id]
    cur = ctx.techniques.setdefault(technique_id, {'techniqueID': technique_id, 'name': meta['name'], 'tactic': meta['tactic'], 'score': 0, 'severity': 'informational', 'evidence': [], 'hosts': set(), 'confidence': 'Observed'})
    sev = finding.get('severity','informational')
    cur['score'] = max(cur['score'], SCORES.get(sev, 10))
    if SCORES.get(sev,0) >= SCORES.get(cur.get('severity','informational'),0):
        cur['severity'] = sev
    cur['evidence'].append(str(finding.get('evidence',''))[:300])
    for k in ['src_ip','dst_ip']:
        if finding.get(k): cur['hosts'].add(finding[k])

def finalize_techniques(ctx):
    for t in ctx.techniques.values():
        t['hosts'] = sorted(t['hosts']) if isinstance(t['hosts'], set) else t['hosts']
        t['evidence'] = t['evidence'][:10]

def strict_navigator_layer(ctx, name='Observed ATT&CK Layer'):
    finalize_techniques(ctx)
    techniques=[]
    for t in ctx.techniques.values():
        tid=t['techniqueID']
        if tid not in VALID_TECHNIQUES:
            continue
        score=float(max(0,min(100,t.get('score',0))))
        color='#ef4444'  # observed coverage is red in Navigator/heat-map exports
        comments='; '.join(t.get('evidence',[])[:3])[:900]
        techniques.append({'techniqueID':tid,'tactic':VALID_TECHNIQUES[tid]['tactic'],'score':score,'color':color,'comment':comments,'metadata':[{'name':'Severity','value':t.get('severity','informational')},{'name':'Confidence','value':t.get('confidence','Observed')},{'name':'Hosts','value':', '.join(t.get('hosts',[])[:20])}]})
    layer={
      'versions': {'attack': ATTACK_VERSION, 'navigator': NAVIGATOR_VERSION, 'layer':'4.5'},
      'name': name,
      'domain':'enterprise-attack',
      'description':'Observed ATT&CK Navigator v18 layer generated from PCAP-derived events and normalized logs. Red means directly observed evidence.',
      'filters': {'platforms': VALID_PLATFORMS},
      'sorting': 0,
      'layout': {'layout':'side','aggregateFunction':'average','showID':False,'showName':True,'showAggregateScores':False,'countUnscored':False,'expandedSubtechniques':'all'},
      'hideDisabled': False,
      'techniques': techniques,
      'gradient': {'colors':['#374151','#ef4444'],'minValue':0,'maxValue':100},
      'legendItems': [{'label':'Observed','color':'#ef4444'},{'label':'Not covered','color':'#374151'}],
      'metadata': [{'name':'ATT&CK version','value':ATTACK_DATASET_METADATA.get('version', ATTACK_VERSION)},{'name':'Strict validation','value':'true'}],
      'links': [], 'showTacticRowBackground': False, 'tacticRowBackground':'#dddddd', 'selectTechniquesAcrossTactics': True, 'selectSubtechniquesWithParent': False, 'selectVisibleTechniques': False
    }
    validate_layer(layer)
    return layer


# Hypothetical coverage is intentionally separate from observed behavior.  It
# answers: "If these telemetry sources are present, what ATT&CK techniques could
# reasonably be covered by those data sources?"  It does not claim the behavior
# occurred in the PCAP.
DATA_SOURCE_COVERAGE = {
    'Windows Event Log': [
        ('T1110', 'credential-access', 85, 'Windows Security logon events can support brute-force, password spraying, and failed-authentication coverage.'),
        ('T1021.001', 'lateral-movement', 80, 'Windows logon/session events can support Remote Desktop Protocol investigations.'),
        ('T1021.006', 'lateral-movement', 80, 'WinRM and PowerShell remoting events can support Windows Remote Management coverage.'),
        ('T1059.001', 'execution', 75, 'PowerShell event records and command-line auditing can support PowerShell execution coverage.'),
        ('T1053.005', 'persistence', 70, 'Task Scheduler operational/security events can support scheduled task persistence coverage.'),
        ('T1543.003', 'persistence', 70, 'Service Control Manager and system events can support Windows service creation/modification coverage.'),
        ('T1547.001', 'persistence', 65, 'Registry and startup-folder auditing can support Run Key/startup persistence coverage.'),
        ('T1070.001', 'defense-evasion', 85, 'Event ID 1102 and related records can support Clear Windows Event Logs coverage.'),
        ('T1562.002', 'defense-evasion', 75, 'Windows event logging changes can support detection of event logging impairment.'),
        ('T1003.001', 'credential-access', 65, 'Security and process-access telemetry can support LSASS credential-dumping investigations when audit policy is enabled.'),
        ('T1558.003', 'credential-access', 75, 'Kerberos service ticket events can support Kerberoasting coverage.'),
        ('T1087.002', 'discovery', 65, 'Directory and logon events can support domain account discovery investigations.'),
        ('T1069.002', 'discovery', 65, 'Directory/group enumeration events can support domain group discovery investigations.'),
        ('T1046', 'discovery', 55, 'Firewall/security logs may support network service discovery investigation when connection auditing is enabled.'),
    ],
    'Sysmon': [
        ('T1059', 'execution', 90, 'Sysmon process creation events support command and scripting interpreter investigations.'),
        ('T1059.001', 'execution', 90, 'Sysmon process creation and command-line telemetry supports PowerShell coverage.'),
        ('T1046', 'discovery', 90, 'Sysmon network connection events can support network service discovery coverage.'),
        ('T1049', 'discovery', 80, 'Process and network telemetry can support system network connection discovery.'),
        ('T1057', 'discovery', 75, 'Process creation telemetry can support process discovery investigations.'),
        ('T1082', 'discovery', 75, 'Process execution telemetry can support system information discovery investigations.'),
        ('T1083', 'discovery', 70, 'Process/file telemetry can support file and directory discovery investigations.'),
        ('T1021.002', 'lateral-movement', 85, 'Process, named-pipe, and network telemetry can support SMB/Admin Share lateral movement investigation.'),
        ('T1021.006', 'lateral-movement', 80, 'Process and network telemetry can support WinRM/PowerShell remoting investigations.'),
        ('T1021.001', 'lateral-movement', 75, 'Network connection telemetry can support RDP remote-service coverage.'),
        ('T1003.001', 'credential-access', 85, 'Process access telemetry can support LSASS memory access investigations.'),
        ('T1558.003', 'credential-access', 65, 'Process and Kerberos-related telemetry can support Kerberoasting investigations.'),
        ('T1543.003', 'persistence', 80, 'Service creation events can support Windows service persistence coverage.'),
        ('T1547.001', 'persistence', 75, 'Registry modification telemetry can support Run Key/startup persistence coverage.'),
        ('T1036', 'defense-evasion', 65, 'Process and image path telemetry can support masquerading investigations.'),
        ('T1027', 'defense-evasion', 55, 'Command-line and process telemetry can support obfuscation triage.'),
        ('T1071.001', 'command-and-control', 75, 'Network events can help identify web protocol C2 patterns.'),
        ('T1071.004', 'command-and-control', 70, 'DNS/network telemetry can support DNS C2 triage when DNS events are collected.'),
        ('T1105', 'command-and-control', 70, 'Process and network events can support ingress tool transfer investigations.'),
        ('T1567', 'exfiltration', 70, 'Network and file telemetry can support exfiltration-over-web-service investigations.'),
        ('T1041', 'exfiltration', 65, 'Network telemetry can support exfiltration-over-C2 investigations.'),
    ],
    'Windows Event Forwarding': [
        ('T1110', 'credential-access', 80, 'Forwarded Windows Security events can support brute-force coverage.'),
        ('T1021.001', 'lateral-movement', 75, 'Forwarded logon/session events can support RDP investigations.'),
        ('T1021.006', 'lateral-movement', 75, 'Forwarded WinRM and PowerShell events can support WinRM coverage.'),
        ('T1059.001', 'execution', 75, 'Forwarded PowerShell logs can support PowerShell execution coverage.'),
        ('T1070.001', 'defense-evasion', 80, 'Forwarded Security events can preserve evidence of cleared Windows event logs.'),
        ('T1558.003', 'credential-access', 70, 'Forwarded Kerberos service-ticket events can support Kerberoasting coverage.'),
        ('T1053.005', 'persistence', 65, 'Forwarded scheduled task events can support scheduled task persistence coverage.'),
    ],
    'PowerShell Operational Log': [
        ('T1059.001', 'execution', 90, 'PowerShell operational logs can support script block and command execution coverage.'),
        ('T1021.006', 'lateral-movement', 80, 'PowerShell remoting telemetry can support WinRM/remote execution coverage.'),
        ('T1105', 'command-and-control', 70, 'PowerShell download commands can support ingress tool transfer investigations.'),
        ('T1071.001', 'command-and-control', 65, 'PowerShell web requests can support web protocol C2 triage.'),
        ('T1027', 'defense-evasion', 70, 'Encoded or obfuscated PowerShell command telemetry can support obfuscation investigations.'),
    ],
    'Defender': [
        ('T1055', 'privilege-escalation', 70, 'Endpoint protection alerts can support process injection investigation.'),
        ('T1003.001', 'credential-access', 80, 'Defender alerts can support LSASS credential-dumping coverage.'),
        ('T1105', 'command-and-control', 70, 'Defender detections can support ingress tool transfer triage.'),
        ('T1562.001', 'defense-evasion', 80, 'Defender configuration and tamper alerts can support impairment of defenses coverage.'),
        ('T1486', 'impact', 75, 'Defender ransomware detections can support data encryption impact coverage.'),
    ],
    'systemd-journald': [
        ('T1021.004', 'lateral-movement', 80, 'journald commonly records sshd authentication/session activity.'),
        ('T1110', 'credential-access', 75, 'journald/auth logs can support SSH brute-force detection.'),
        ('T1059.004', 'execution', 70, 'Shell execution and service logs can support Unix shell execution investigations.'),
        ('T1053.003', 'persistence', 70, 'Cron service logs can support cron persistence coverage.'),
        ('T1543.002', 'persistence', 75, 'systemd unit lifecycle logs can support systemd service persistence coverage.'),
        ('T1070.002', 'defense-evasion', 70, 'journal rotation/vacuum records may support Linux log-clearing investigations.'),
        ('T1562.001', 'defense-evasion', 65, 'Service stop/disable events can support impairment of defenses investigations.'),
        ('T1046', 'discovery', 55, 'System logs may support limited service discovery investigation.'),
        ('T1082', 'discovery', 55, 'System/service logs can support system information discovery triage.'),
    ],
    'rsyslog': [
        ('T1021.004', 'lateral-movement', 75, 'rsyslog may forward SSH authentication/session events.'),
        ('T1110', 'credential-access', 70, 'rsyslog may forward auth failure events.'),
        ('T1053.003', 'persistence', 60, 'Cron syslog records can support cron persistence coverage.'),
        ('T1543.002', 'persistence', 60, 'System service syslog can support systemd service investigations.'),
        ('T1070.002', 'defense-evasion', 60, 'Syslog gaps or log-management records can support Linux/macOS log-clearing triage.'),
        ('T1046', 'discovery', 55, 'Network device and host syslog can support discovery triage.'),
    ],
    'syslog-ng': [
        ('T1021.004', 'lateral-movement', 75, 'syslog-ng may forward SSH authentication/session events.'),
        ('T1110', 'credential-access', 70, 'syslog-ng may forward auth failure events.'),
        ('T1053.003', 'persistence', 60, 'Cron syslog records can support cron persistence coverage.'),
        ('T1070.002', 'defense-evasion', 60, 'Forwarded system logs can support Linux/macOS log-clearing triage.'),
        ('T1046', 'discovery', 55, 'Forwarded system logs can support discovery triage.'),
    ],
    'auditd': [
        ('T1059.004', 'execution', 85, 'Linux audit records can support Unix shell and command execution coverage.'),
        ('T1021.004', 'lateral-movement', 75, 'Linux audit records can support SSH and remote execution investigation.'),
        ('T1110', 'credential-access', 70, 'audit/auth telemetry can support brute-force investigation.'),
        ('T1053.003', 'persistence', 75, 'Audit records can support cron modification coverage.'),
        ('T1543.002', 'persistence', 80, 'Audit records can support systemd service creation/modification coverage.'),
        ('T1070.002', 'defense-evasion', 80, 'Audit records can support Linux log-clearing and evidence removal investigations.'),
        ('T1562.001', 'defense-evasion', 75, 'Audit records can support security tool/service disablement investigations.'),
        ('T1005', 'collection', 65, 'File access auditing can support data from local system coverage.'),
        ('T1083', 'discovery', 70, 'File and directory access telemetry can support file discovery coverage.'),
        ('T1033', 'discovery', 60, 'User/session audit records can support system owner/user discovery.'),
    ],
    'Apple Unified Log': [
        ('T1021.004', 'lateral-movement', 65, 'macOS unified logging may support SSH/remote administration investigation.'),
        ('T1021.005', 'lateral-movement', 70, 'Screen Sharing and VNC service logs can support remote service coverage.'),
        ('T1543.001', 'persistence', 80, 'LaunchAgent/launchd logs can support macOS Launch Agent persistence coverage.'),
        ('T1555.001', 'credential-access', 75, 'securityd/keychain-related logs can support Keychain credential-access triage.'),
        ('T1113', 'collection', 65, 'Screen sharing and UI-related logs can support screen capture triage when collected.'),
        ('T1070.002', 'defense-evasion', 70, 'Unified log and system log events can support macOS log-clearing investigations.'),
        ('T1059.004', 'execution', 60, 'Shell and script execution records can support Unix shell coverage.'),
        ('T1071.001', 'command-and-control', 60, 'macOS network/process telemetry may support web protocol C2 triage when collected.'),
    ],
    'OpenBSM audit': [
        ('T1021.004', 'lateral-movement', 65, 'OpenBSM audit records may support SSH/session investigation.'),
        ('T1110', 'credential-access', 60, 'Audit records may support authentication failure investigation.'),
        ('T1059.004', 'execution', 70, 'OpenBSM process/exec records can support Unix shell execution coverage.'),
        ('T1555.001', 'credential-access', 60, 'macOS audit records can support Keychain access triage.'),
        ('T1005', 'collection', 60, 'File access auditing can support local data collection investigations.'),
        ('T1070.002', 'defense-evasion', 65, 'Audit records can support macOS log-clearing investigations.'),
    ],
    'osquery': [
        ('T1057', 'discovery', 85, 'osquery process tables can support process discovery coverage.'),
        ('T1082', 'discovery', 85, 'osquery system tables can support system information discovery.'),
        ('T1083', 'discovery', 80, 'osquery file tables can support file and directory discovery.'),
        ('T1033', 'discovery', 75, 'osquery user/session tables can support user discovery.'),
        ('T1543.001', 'persistence', 70, 'osquery launchd tables can support macOS Launch Agent coverage.'),
        ('T1543.002', 'persistence', 70, 'osquery service tables can support systemd service coverage.'),
        ('T1547.001', 'persistence', 70, 'osquery startup item/registry tables can support autostart persistence coverage.'),
        ('T1555.001', 'credential-access', 60, 'osquery/macOS telemetry can support Keychain access triage.'),
    ],
    'Elastic Beats': [
        ('T1046', 'discovery', 80, 'Packetbeat/Filebeat/Winlogbeat telemetry can support discovery coverage.'),
        ('T1071.001', 'command-and-control', 75, 'Elastic network/log telemetry can support web protocol C2 coverage.'),
        ('T1071.004', 'command-and-control', 75, 'Packetbeat/DNS telemetry can support DNS C2 coverage.'),
        ('T1567', 'exfiltration', 70, 'Network and endpoint logs can support exfiltration-over-web-service coverage.'),
        ('T1041', 'exfiltration', 65, 'Network and endpoint telemetry can support exfiltration-over-C2 coverage.'),
        ('T1110', 'credential-access', 70, 'Winlogbeat/auth log forwarding can support brute-force coverage.'),
        ('T1059', 'execution', 65, 'Endpoint log forwarding can support command and scripting interpreter coverage when process logs are collected.'),
        ('T1070.001', 'defense-evasion', 70, 'Winlogbeat can preserve Windows event-log clearing evidence.'),
        ('T1070.002', 'defense-evasion', 65, 'Filebeat/audit logs can support Linux/macOS log-clearing coverage.'),
    ],
    'Filebeat': [
        ('T1110', 'credential-access', 70, 'Forwarded authentication logs can support brute-force coverage.'),
        ('T1021.004', 'lateral-movement', 70, 'Forwarded auth logs can support SSH remote-service coverage.'),
        ('T1053.003', 'persistence', 65, 'Forwarded cron logs can support cron persistence coverage.'),
        ('T1070.002', 'defense-evasion', 65, 'Forwarded system logs can support Linux/macOS log-clearing triage.'),
        ('T1046', 'discovery', 55, 'Application/system logs can support discovery triage.'),
    ],
    'Winlogbeat': [
        ('T1110', 'credential-access', 85, 'Forwarded Windows Security logs can support brute-force coverage.'),
        ('T1021.001', 'lateral-movement', 80, 'Forwarded logon/session events can support RDP coverage.'),
        ('T1021.006', 'lateral-movement', 80, 'Forwarded WinRM/PowerShell events can support WinRM coverage.'),
        ('T1059.001', 'execution', 75, 'Forwarded PowerShell logs can support PowerShell coverage.'),
        ('T1070.001', 'defense-evasion', 85, 'Forwarded Windows Security logs can support event-log clearing coverage.'),
        ('T1558.003', 'credential-access', 75, 'Forwarded Kerberos service-ticket events can support Kerberoasting coverage.'),
    ],
    'Auditbeat': [
        ('T1059', 'execution', 80, 'Auditbeat process telemetry can support command execution coverage.'),
        ('T1059.004', 'execution', 80, 'Auditbeat/auditd telemetry can support Unix shell coverage.'),
        ('T1005', 'collection', 70, 'Auditbeat file integrity and access telemetry can support local data collection coverage.'),
        ('T1083', 'discovery', 75, 'File activity telemetry can support file and directory discovery.'),
        ('T1070.002', 'defense-evasion', 75, 'Auditbeat can support Linux/macOS log-clearing investigations.'),
    ],
    'Packetbeat': [
        ('T1046', 'discovery', 90, 'Packetbeat protocol telemetry can support service discovery coverage.'),
        ('T1071.001', 'command-and-control', 80, 'Packetbeat HTTP/TLS telemetry can support web protocol C2 coverage.'),
        ('T1071.004', 'command-and-control', 80, 'Packetbeat DNS telemetry can support DNS C2 coverage.'),
        ('T1021.002', 'lateral-movement', 70, 'SMB telemetry can support SMB/Admin Share investigation.'),
        ('T1021.004', 'lateral-movement', 70, 'SSH telemetry can support SSH remote-service coverage.'),
        ('T1567', 'exfiltration', 75, 'HTTP/TLS telemetry can support exfiltration-over-web-service coverage.'),
        ('T1041', 'exfiltration', 70, 'Connection timing and volume can support exfiltration-over-C2 coverage.'),
    ],
    'Zeek': [
        ('T1046', 'discovery', 95, 'Zeek connection logs strongly support network service discovery coverage.'),
        ('T1018', 'discovery', 80, 'Zeek connection and DNS logs can support remote system discovery coverage.'),
        ('T1049', 'discovery', 80, 'Zeek connection logs can support system network connection discovery.'),
        ('T1135', 'discovery', 70, 'SMB logs can support network share discovery coverage.'),
        ('T1021.002', 'lateral-movement', 80, 'Zeek SMB logs can support SMB/Admin Share lateral movement investigation.'),
        ('T1021.004', 'lateral-movement', 75, 'Zeek SSH logs can support SSH remote-service coverage.'),
        ('T1021.001', 'lateral-movement', 70, 'Zeek connection logs can support RDP coverage.'),
        ('T1071.001', 'command-and-control', 85, 'Zeek HTTP/SSL logs support web protocol C2 coverage.'),
        ('T1071.004', 'command-and-control', 85, 'Zeek DNS logs support DNS C2 coverage.'),
        ('T1090', 'command-and-control', 65, 'Zeek proxy-like connection telemetry can support proxy triage.'),
        ('T1571', 'command-and-control', 70, 'Zeek service and port metadata can support non-standard port coverage.'),
        ('T1041', 'exfiltration', 80, 'Zeek connection/file logs can support exfiltration-over-C2 investigation.'),
        ('T1567', 'exfiltration', 80, 'Zeek HTTP/TLS logs can support web service exfiltration investigation.'),
    ],
    'Suricata': [
        ('T1046', 'discovery', 85, 'Suricata alerts/flow logs can support discovery coverage.'),
        ('T1071.001', 'command-and-control', 85, 'Suricata protocol detection can support web C2 coverage.'),
        ('T1071.004', 'command-and-control', 80, 'Suricata DNS events can support DNS C2 coverage.'),
        ('T1571', 'command-and-control', 70, 'Protocol/port mismatch alerts can support non-standard port coverage.'),
        ('T1095', 'command-and-control', 65, 'Flow and protocol alerts can support non-application-layer protocol triage.'),
        ('T1041', 'exfiltration', 70, 'Flow and alert data can support exfiltration-over-C2 investigations.'),
        ('T1567', 'exfiltration', 70, 'HTTP/TLS alerts can support web-service exfiltration investigations.'),
    ],
    'NetFlow': [
        ('T1046', 'discovery', 85, 'Flow records can support network scanning/service discovery detection.'),
        ('T1018', 'discovery', 70, 'Flow records can support remote system discovery triage.'),
        ('T1049', 'discovery', 75, 'Flow records can support network connection discovery.'),
        ('T1071.001', 'command-and-control', 65, 'Flow timing and volume can support web C2 triage.'),
        ('T1090', 'command-and-control', 60, 'Flow chains and unusual egress can support proxy triage.'),
        ('T1571', 'command-and-control', 60, 'Flow records can support non-standard port triage.'),
        ('T1041', 'exfiltration', 75, 'Flow volume can support exfiltration-over-C2 investigation.'),
        ('T1567', 'exfiltration', 70, 'Flow records can support web-service exfiltration triage.'),
        ('T1030', 'exfiltration', 65, 'Flow volume patterns can support data transfer size limit investigations.'),
        ('T1020', 'exfiltration', 60, 'Repeated high-volume flows can support automated exfiltration triage.'),
    ],
    'IPFIX': [
        ('T1046', 'discovery', 85, 'IPFIX records can support network scanning/service discovery detection.'),
        ('T1018', 'discovery', 70, 'IPFIX records can support remote system discovery triage.'),
        ('T1049', 'discovery', 75, 'IPFIX records can support network connection discovery.'),
        ('T1071.001', 'command-and-control', 65, 'IPFIX timing and volume can support web C2 triage.'),
        ('T1041', 'exfiltration', 75, 'IPFIX volume records can support exfiltration investigation.'),
        ('T1567', 'exfiltration', 70, 'IPFIX records can support web-service exfiltration triage.'),
        ('T1030', 'exfiltration', 65, 'IPFIX volume patterns can support data transfer size limit investigations.'),
    ],
    'sFlow': [
        ('T1046', 'discovery', 70, 'sFlow samples can support discovery and scanning triage.'),
        ('T1018', 'discovery', 55, 'sFlow samples can support remote system discovery triage.'),
        ('T1041', 'exfiltration', 60, 'sFlow samples can support high-volume exfiltration triage.'),
        ('T1567', 'exfiltration', 55, 'sFlow samples can support web-service exfiltration triage.'),
    ],
    'SNMP Trap': [
        ('T1046', 'discovery', 45, 'SNMP trap telemetry can provide limited network/device context for discovery triage.'),
        ('T1016', 'discovery', 45, 'SNMP telemetry can support network configuration discovery context.'),
        ('T1049', 'discovery', 40, 'SNMP device state can support network connection discovery context.'),
    ],
    'Syslog': [
        ('T1046', 'discovery', 65, 'Network and system syslog can support scanning/discovery triage.'),
        ('T1110', 'credential-access', 65, 'Authentication syslog can support brute-force triage when forwarded.'),
        ('T1021.004', 'lateral-movement', 65, 'SSH syslog can support remote-service investigation.'),
        ('T1053.003', 'persistence', 55, 'Cron/syslog messages can support cron persistence coverage.'),
        ('T1543.002', 'persistence', 55, 'Service syslog messages can support systemd service investigations.'),
        ('T1070.002', 'defense-evasion', 55, 'Syslog can support Linux/macOS log-clearing triage.'),
        ('T1016', 'discovery', 50, 'Network-device syslog can support network configuration discovery context.'),
    ],
    'Syslog TLS': [
        ('T1046', 'discovery', 65, 'TLS-protected syslog can support scanning/discovery triage.'),
        ('T1110', 'credential-access', 65, 'Authentication syslog can support brute-force triage when forwarded.'),
        ('T1021.004', 'lateral-movement', 65, 'SSH syslog can support remote-service investigation.'),
        ('T1053.003', 'persistence', 55, 'Cron/syslog messages can support cron persistence coverage.'),
        ('T1070.002', 'defense-evasion', 55, 'Forwarded syslog can support Linux/macOS log-clearing triage.'),
    ],
    'Fluent Bit': [
        ('T1110', 'credential-access', 60, 'Forwarded authentication logs can support brute-force triage.'),
        ('T1059', 'execution', 55, 'Forwarded application/system logs can support command execution triage.'),
        ('T1070.002', 'defense-evasion', 55, 'Forwarded system logs can support Linux/macOS log-clearing triage.'),
        ('T1046', 'discovery', 50, 'Forwarded logs can support discovery triage.'),
    ],
    'Fluentd': [
        ('T1110', 'credential-access', 60, 'Forwarded authentication logs can support brute-force triage.'),
        ('T1059', 'execution', 55, 'Forwarded application/system logs can support command execution triage.'),
        ('T1070.002', 'defense-evasion', 55, 'Forwarded system logs can support Linux/macOS log-clearing triage.'),
        ('T1046', 'discovery', 50, 'Forwarded logs can support discovery triage.'),
    ],
    'Vector': [
        ('T1110', 'credential-access', 60, 'Forwarded authentication logs can support brute-force triage.'),
        ('T1059', 'execution', 55, 'Forwarded application/system logs can support command execution triage.'),
        ('T1070.002', 'defense-evasion', 55, 'Forwarded system logs can support Linux/macOS log-clearing triage.'),
        ('T1046', 'discovery', 50, 'Forwarded logs can support discovery triage.'),
    ],
    'OpenTelemetry Collector': [
        ('T1046', 'discovery', 55, 'Collected metrics/logs can support discovery triage.'),
        ('T1059', 'execution', 55, 'Application and host telemetry can support execution triage when process logs are collected.'),
        ('T1071.001', 'command-and-control', 55, 'Collected network/application telemetry can support web protocol C2 triage.'),
        ('T1567', 'exfiltration', 50, 'Application and network telemetry can support web-service exfiltration triage.'),
    ],
}


LOG_SOURCE_ALIASES = {
    'microsoft defender for endpoint': 'Defender',
    'defender for endpoint': 'Defender',
    'windows defender': 'Defender',
    'defender': 'Defender',
    'winlogbeat': 'Winlogbeat',
    'windows event log': 'Windows Event Log',
    'windows security': 'Windows Event Log',
    'eventid': 'Windows Event Log',
    'windows event forwarding': 'Windows Event Forwarding',
    'wef': 'Windows Event Forwarding',
    'sysmon': 'Sysmon',
    'powershell operational': 'PowerShell Operational Log',
    'powershell': 'PowerShell Operational Log',
    'systemd-journald': 'systemd-journald',
    'journald': 'systemd-journald',
    'systemd': 'systemd-journald',
    'rsyslog': 'rsyslog',
    'syslog-ng': 'syslog-ng',
    'auditbeat': 'Auditbeat',
    'auditd': 'auditd',
    'apple unified log': 'Apple Unified Log',
    'unified logging': 'Apple Unified Log',
    'oslog': 'Apple Unified Log',
    'macos': 'Apple Unified Log',
    'openbsm': 'OpenBSM audit',
    'osquery': 'osquery',
    'elastic agent': 'Elastic Beats',
    'elastic beats': 'Elastic Beats',
    'filebeat': 'Filebeat',
    'packetbeat': 'Packetbeat',
    'zeek': 'Zeek',
    'suricata': 'Suricata',
    'snort': 'Suricata',
    'netflow': 'NetFlow',
    'ipfix': 'IPFIX',
    'sflow': 'sFlow',
    'snmp trap': 'SNMP Trap',
    'snmp': 'SNMP Trap',
    'opentelemetry': 'OpenTelemetry Collector',
    'otel': 'OpenTelemetry Collector',
    'fluent bit': 'Fluent Bit',
    'fluent-bit': 'Fluent Bit',
    'fluentd': 'Fluentd',
    'vector': 'Vector',
    'syslog tls': 'Syslog TLS',
    '6514': 'Syslog TLS',
    'syslog': 'Syslog',
}


def _canonical_log_source(text):
    t = (text or '').lower()
    for needle, canonical in LOG_SOURCE_ALIASES.items():
        if needle in t:
            return canonical
    return None

def _canonical_log_sources(text):
    t = (text or '').lower()
    hits = set()
    for needle, canonical in LOG_SOURCE_ALIASES.items():
        if needle in t:
            hits.add(canonical)
    return hits

def detected_data_sources(result):
    sources = set()
    for item in result.get('log_sources', []) or []:
        evidence = ' '.join(str(item.get(k,'')) for k in ['protocol','evidence','summary','technology','log_source','source_type'])
        sources.update(_canonical_log_sources(evidence))
    # Add light inference from host protocols when the capture did not expose a
    # richer log source object.  This remains hypothetical coverage only.
    for host in result.get('hosts', []) or []:
        protos = ' '.join(host.get('protocols', []) if isinstance(host.get('protocols'), list) else [str(host.get('protocols',''))])
        sources.update(_canonical_log_sources(protos))
    return sorted(sources)

def build_data_source_coverage(result):
    coverage = {}
    sources = detected_data_sources(result)
    for source in sources:
        for tid, tactic, score, rationale in DATA_SOURCE_COVERAGE.get(source, []):
            if tid not in VALID_TECHNIQUES:
                continue
            cur = coverage.setdefault(tid, {
                'techniqueID': tid,
                'name': VALID_TECHNIQUES[tid]['name'],
                'tactic': tactic,
                'score': 0,
                'coverage': 'Hypothetical',
                'data_sources': set(),
                'rationale': [],
            })
            cur['score'] = max(cur['score'], score)
            cur['data_sources'].add(source)
            cur['rationale'].append(rationale)
    out = []
    for item in coverage.values():
        item['data_sources'] = sorted(item['data_sources'])
        item['rationale'] = item['rationale'][:8]
        out.append(item)
    return sorted(out, key=lambda x: (-x['score'], x['techniqueID']))

def strict_data_source_coverage_layer(result, name='Hypothetical ATT&CK Data Source Coverage'):
    techniques = []
    for t in build_data_source_coverage(result):
        tid = t['techniqueID']
        score = float(max(0, min(100, t.get('score', 0))))
        if score >= 75:
            color = '#2ca25f'
            label = 'Strong hypothetical coverage'
        elif score >= 55:
            color = '#99d8c9'
            label = 'Moderate hypothetical coverage'
        else:
            color = '#e5f5f9'
            label = 'Limited hypothetical coverage'
        techniques.append({
            'techniqueID': tid,
            'tactic': VALID_TECHNIQUES[tid]['tactic'],
            'score': score,
            'color': color,
            'comment': ('Hypothetical coverage based on detected telemetry sources: ' + '; '.join(t.get('rationale', [])[:3]))[:900],
            'metadata': [
                {'name': 'Coverage Type', 'value': 'Hypothetical data-source coverage'},
                {'name': 'Data Sources', 'value': ', '.join(t.get('data_sources', [])[:20])},
                {'name': 'Not Observed Behavior', 'value': 'true'},
            ]
        })
    layer = {
      'versions': {'attack': ATTACK_VERSION, 'navigator': NAVIGATOR_VERSION, 'layer':'4.5'},
      'name': name,
      'domain':'enterprise-attack',
      'description':'Strict ATT&CK Navigator v18 layer showing hypothetical technique coverage based on detected log/data sources. This is telemetry coverage, not observed adversary behavior.',
      'filters': {'platforms': VALID_PLATFORMS},
      'sorting': 0,
      'layout': {'layout':'side','aggregateFunction':'average','showID':False,'showName':True,'showAggregateScores':False,'countUnscored':False,'expandedSubtechniques':'all'},
      'hideDisabled': False,
      'techniques': techniques,
      'gradient': {'colors':['#ffffff','#e5f5f9','#99d8c9','#2ca25f'],'minValue':0,'maxValue':100},
      'legendItems': [{'label':'Limited hypothetical coverage','color':'#e5f5f9'},{'label':'Moderate hypothetical coverage','color':'#99d8c9'},{'label':'Strong hypothetical coverage','color':'#2ca25f'}],
      'metadata': [{'name':'ATT&CK version','value':ATTACK_DATASET_METADATA.get('version', ATTACK_VERSION)},{'name':'Strict validation','value':'true'},{'name':'Coverage basis','value':'detected log/data sources'}],
      'links': [], 'showTacticRowBackground': False, 'tacticRowBackground':'#dddddd', 'selectTechniquesAcrossTactics': True, 'selectSubtechniquesWithParent': False, 'selectVisibleTechniques': False
    }
    validate_layer(layer)
    return layer



# Enterprise-wide theoretical coverage assessment.  This intentionally avoids
# per-host scoring.  It answers: "Given telemetry sources observed or inferred
# across the enterprise represented by this capture, what ATT&CK coverage could
# the SOC reasonably expect?"
TACTIC_DISPLAY_ORDER = [
    'reconnaissance','resource-development','initial-access','execution','persistence',
    'privilege-escalation','defense-evasion','credential-access','discovery',
    'lateral-movement','collection','command-and-control','exfiltration','impact'
]

SOURCE_CATEGORY = {
    'Windows Event Log': 'Windows', 'Windows Event Forwarding': 'Windows', 'Winlogbeat': 'Windows',
    'Sysmon': 'Windows', 'PowerShell Operational Log': 'Windows', 'Defender': 'Windows',
    'systemd-journald': 'Linux', 'auditd': 'Linux', 'rsyslog': 'Linux', 'syslog-ng': 'Linux',
    'Apple Unified Logging': 'macOS', 'OpenBSM': 'macOS', 'osquery': 'macOS',
    'Syslog': 'Network', 'Syslog TLS': 'Network', 'Zeek': 'Network', 'Suricata': 'Network',
    'Packetbeat': 'Network', 'NetFlow': 'Network', 'IPFIX': 'Network', 'sFlow': 'Network', 'SNMP Trap': 'Network',
    'Elastic Agent': 'SIEM / Forwarding', 'Filebeat': 'SIEM / Forwarding', 'Auditbeat': 'SIEM / Forwarding',
    'Fluent Bit': 'SIEM / Forwarding', 'Fluentd': 'SIEM / Forwarding', 'Vector': 'SIEM / Forwarding',
    'OpenTelemetry Collector': 'SIEM / Forwarding',
}

SOURCE_COMPONENTS = {
    'Windows Event Log': ['Windows Event Logs', 'User Account Authentication', 'Logon Session', 'Service Creation', 'Scheduled Job', 'Registry Key Modification'],
    'Windows Event Forwarding': ['Windows Event Logs', 'User Account Authentication', 'PowerShell Logs', 'Service Activity'],
    'Winlogbeat': ['Windows Event Logs', 'Security Events', 'PowerShell Logs', 'Authentication Logs'],
    'Sysmon': ['Process Creation', 'Network Connection Creation', 'File Creation', 'Registry Key Modification', 'WMI Activity', 'Driver Load', 'Image Load'],
    'PowerShell Operational Log': ['PowerShell Script Block', 'Command Execution', 'Process Creation'],
    'Defender': ['Malware Detection', 'File Activity', 'Process Activity', 'Network Activity'],
    'systemd-journald': ['Service Activity', 'User Authentication', 'System Boot', 'Command Execution'],
    'auditd': ['Process Creation', 'Command Execution', 'File Access', 'User Authentication', 'Kernel Events'],
    'rsyslog': ['Authentication Logs', 'Service Logs', 'System Logs'],
    'syslog-ng': ['Authentication Logs', 'Service Logs', 'System Logs'],
    'Apple Unified Logging': ['Process Activity', 'Authentication Logs', 'System Activity', 'Application Activity'],
    'OpenBSM': ['Process Creation', 'File Access', 'User Authentication', 'Privilege Changes'],
    'osquery': ['Process Activity', 'File Activity', 'User Sessions', 'System Information', 'Launchd Items'],
    'Zeek': ['Network Traffic Flow', 'DNS', 'HTTP', 'TLS', 'SMB', 'SSH', 'Files'],
    'Suricata': ['Network Traffic Content', 'IDS Alerts', 'DNS', 'HTTP', 'TLS'],
    'Packetbeat': ['Network Traffic Flow', 'DNS', 'HTTP', 'TLS', 'SMB'],
    'NetFlow': ['Network Traffic Flow'], 'IPFIX': ['Network Traffic Flow'], 'sFlow': ['Network Traffic Flow'],
    'SNMP Trap': ['Network Device Logs', 'Interface Status', 'Device Health'],
    'Syslog': ['Network Device Logs', 'Authentication Logs', 'Service Logs'],
    'Syslog TLS': ['Network Device Logs', 'Authentication Logs', 'Service Logs'],
    'Elastic Agent': ['Endpoint Telemetry', 'Process Activity', 'Network Activity', 'File Activity'],
    'Filebeat': ['Log File Collection', 'Authentication Logs', 'System Logs', 'Application Logs'],
    'Auditbeat': ['Process Activity', 'File Integrity', 'User Sessions', 'Kernel Events'],
    'Fluent Bit': ['Generic Log Collection', 'Application Logs', 'System Logs'],
    'Fluentd': ['Generic Log Collection', 'Application Logs', 'System Logs'],
    'Vector': ['Generic Log Collection', 'Application Logs', 'System Logs'],
    'OpenTelemetry Collector': ['Telemetry Collection', 'Application Logs', 'Metrics', 'Traces'],
}

RECOMMENDATION_LIBRARY = [
    {'source': 'Sysmon', 'category': 'Windows', 'gain': 12, 'reason': 'Adds high-value Windows process, file, registry, network, image-load, and WMI telemetry.'},
    {'source': 'PowerShell Operational Log', 'category': 'Windows', 'gain': 6, 'reason': 'Improves command/script execution coverage and PowerShell tradecraft visibility.'},
    {'source': 'Windows Event Forwarding', 'category': 'Windows', 'gain': 8, 'reason': 'Centralizes Windows Security/System/PowerShell events for enterprise detection.'},
    {'source': 'auditd', 'category': 'Linux', 'gain': 10, 'reason': 'Improves Linux command, process, file, privilege, and kernel-event coverage.'},
    {'source': 'systemd-journald', 'category': 'Linux', 'gain': 5, 'reason': 'Improves Linux service, authentication, and system activity visibility.'},
    {'source': 'Apple Unified Logging', 'category': 'macOS', 'gain': 6, 'reason': 'Improves macOS process, authentication, system, and application visibility.'},
    {'source': 'OpenBSM', 'category': 'macOS', 'gain': 5, 'reason': 'Improves macOS audit visibility for process, file, authentication, and privilege events.'},
    {'source': 'Zeek', 'category': 'Network', 'gain': 10, 'reason': 'Adds rich protocol metadata for DNS, HTTP, TLS, SSH, SMB, files, and connection behavior.'},
    {'source': 'Suricata', 'category': 'Network', 'gain': 8, 'reason': 'Adds IDS alerting and protocol-aware network-content telemetry.'},
    {'source': 'NetFlow', 'category': 'Network', 'gain': 5, 'reason': 'Adds broad enterprise flow visibility for discovery, C2, and exfiltration analytics.'},
]


def _tactic_name(tactic):
    return tactic.replace('-', ' ').title()


# ATT&CK Resource Development represents adversary preparation outside the
# monitored enterprise. Enterprise endpoint/network logs normally cannot make
# these techniques theoretically detectable, so keep them out of the coverage
# denominator and render them as a distinct visibility state instead of plain
# Not Covered.
_EXTERNAL_VISIBILITY_TACTICS = {'resource-development'}

def _is_external_visibility_tactic(tactic):
    return str(tactic or '').lower() in _EXTERNAL_VISIBILITY_TACTICS

def _external_visibility_reason(tactic):
    if _is_external_visibility_tactic(tactic):
        return 'Resource Development is adversary preparation activity that normally occurs outside the monitored enterprise telemetry boundary.'
    return ''



# v2 Phase 3: scope enterprise coverage to the operating systems and log types
# actually observed in the current analysis.  A Linux-only job should not be
# penalized for missing Windows-only or macOS-only telemetry.
def _detected_coverage_scope(result, detected_sources=None):
    detected_sources = detected_sources or detected_data_sources(result)
    scope = set()
    for source in detected_sources:
        cat = SOURCE_CATEGORY.get(source, '')
        if cat == 'Windows': scope.add('windows')
        elif cat == 'Linux': scope.add('linux')
        elif cat == 'macOS': scope.add('macos')
        elif cat == 'Network': scope.add('network')
        elif cat == 'Cloud': scope.add('cloud')
        elif cat == 'SIEM / Forwarding': scope.add('forwarding')
    for ev in result.get('normalized_events', []) or []:
        plat = str(ev.get('platform') or '').lower()
        src = str(ev.get('log_source') or '').lower()
        raw = str(ev.get('raw') or '').lower()
        blob = ' '.join([plat, src, raw])
        if 'windows' in blob or 'sysmon' in blob or 'winlog' in blob or 'eventid' in blob or 'powershell' in blob:
            scope.add('windows')
        if 'linux' in blob or 'auditd' in blob or 'journald' in blob or 'systemd' in blob or 'sshd' in blob or 'sudo' in blob:
            scope.add('linux')
        if 'macos' in blob or 'apple unified' in blob or 'openbsm' in blob or 'jamf' in blob or 'tcc' in blob:
            scope.add('macos')
        if 'zeek' in blob or 'suricata' in blob or 'packetbeat' in blob or 'netflow' in blob or 'syslog' in blob:
            scope.add('network')
        if 'cloud' in blob or 'cloudtrail' in blob or 'azure' in blob or 'gcp' in blob or 'iam' in blob:
            scope.add('cloud')
    # Flow protocols imply network telemetry even when forwarded logs are absent.
    if result.get('flows'):
        scope.add('network')
    # Do not assume a default scope for empty jobs. With no PCAP/log data loaded,
    # every technique should render gray / Not Applicable and should not affect
    # coverage percentages.
    return sorted(scope)

_WINDOWS_TERMS = ('windows','powershell','wmi','winrm','dcom','rdp','smb','ntds','lsass','sam','registry','uac','event log','sysmon','scheduled task','bits','msbuild','mshta','rundll32','regsvr32','mavinject','cmstp','appinit','appcert','winlogon','kerberos','ntlm','domain controller','group policy','dcsync','admin shares')
_LINUX_TERMS = ('linux','unix','bash','shell','sudo','setuid','setgid','auditd','systemd','cron','sshd','pam','iptables','nftables','journal','/etc/passwd','/etc/shadow','ptrace','proc filesystem','udev','xdg')
_MAC_TERMS = ('macos','apple','osascript','applescript','launchd','launchctl','launch agent','launch daemon','plist','keychain','securityd','tcc','gatekeeper','xprotect','openbsm','dylib','santa','jamf')
_CLOUD_TERMS = ('cloud','aws','azure','gcp','saml','oauth','iam','serverless','container','kubernetes','vpc','s3','bucket','snapshot','cloudtrail','metadata api')
_NETWORK_TERMS = ('network','dns','http','https','tls','smtp','ftp','ssh','rdp','smb','ldap','kerberos','proxy','vpn','icmp','netflow','ipfix','sflow','suricata','zeek','packetbeat','c2','beacon','tunnel','exfiltration','scan','web service')

def _technique_in_detected_scope(tid, meta, scope):
    # No detected OS/log-source scope means no techniques are applicable yet.
    # This keeps empty jobs from showing default network coverage and renders the
    # full overlay gray / Not Applicable until data is loaded.
    if not scope:
        return False
    name = (meta.get('name') or tid).lower()
    # Techniques without OS-specific words are enterprise-generic and remain in
    # scope once any relevant environment scope has been observed.
    hits = set()
    if any(t in name for t in _WINDOWS_TERMS): hits.add('windows')
    if any(t in name for t in _LINUX_TERMS): hits.add('linux')
    if any(t in name for t in _MAC_TERMS): hits.add('macos')
    if any(t in name for t in _CLOUD_TERMS): hits.add('cloud')
    if any(t in name for t in _NETWORK_TERMS): hits.add('network')
    if not hits:
        return True
    return bool(hits & set(scope))

def enterprise_coverage_assessment(result, rules=None):
    coverage = build_data_source_coverage(result)
    detected_sources = detected_data_sources(result)
    coverage_scope = _detected_coverage_scope(result, detected_sources)
    scoped_techniques = {tid: meta for tid, meta in VALID_TECHNIQUES.items() if _technique_in_detected_scope(tid, meta, coverage_scope)}
    observed = {t.get('techniqueID') or t.get('technique_id') for t in (result.get('techniques') or []) if (t.get('techniqueID') or t.get('technique_id'))}
    covered = {t['techniqueID']: t for t in coverage}
    rules = rules or []
    rule_techs = set()
    for r in rules:
        for tid in r.get('attack', []) or r.get('techniques', []) or []:
            if tid in VALID_TECHNIQUES:
                rule_techs.add(tid)
    validated_items = result.get('validated_techniques') or (result.get('rule_validations') or {}).get('validated_techniques') or []
    validated_techs = {x.get('techniqueID') for x in validated_items if x.get('techniqueID') in VALID_TECHNIQUES}

    enterprise = {
        'basis': 'enterprise-wide telemetry assessment',
        'attack_version': ATTACK_DATASET_METADATA.get('version', ATTACK_VERSION),
        'navigator_version': NAVIGATOR_VERSION,
        'overall_score': 0,
        'maturity': 'None',
        'detected_sources': detected_sources,
        'coverage_scope': coverage_scope,
        'scoped_technique_total': len(scoped_techniques),
        'telemetry_inventory': {},
        'data_components': [],
        'tactic_coverage': [],
        'coverage_states': [],
        'gaps': [],
        'recommendations': [],
        'rule_coverage': {'techniques_with_rules': len(rule_techs), 'covered_with_rules': 0, 'detectable_without_rules': 0, 'validated_techniques': len(validated_techs)},
        'readiness': [],
        'executive_summary': '',
    }

    # Enterprise telemetry inventory grouped by capability area, not host.
    grouped = {}
    for source in detected_sources:
        grouped.setdefault(SOURCE_CATEGORY.get(source, 'Other'), []).append(source)
    for cat in sorted(set(list(grouped) + ['Windows','Linux','macOS','Network','SIEM / Forwarding'])):
        enterprise['telemetry_inventory'][cat] = sorted(grouped.get(cat, []))

    # Data source/component inventory.
    components = {}
    for source in detected_sources:
        for comp in SOURCE_COMPONENTS.get(source, []):
            components.setdefault(comp, set()).add(source)
    enterprise['data_components'] = [{'component': k, 'sources': sorted(v)} for k, v in sorted(components.items())]

    # Per-tactic enterprise coverage.  Denominator is the technique set known to this app/version.
    totals = {t: 0 for t in TACTIC_DISPLAY_ORDER}
    sums = {t: 0 for t in TACTIC_DISPLAY_ORDER}
    counts = {t: 0 for t in TACTIC_DISPLAY_ORDER}
    for tid, meta in scoped_techniques.items():
        tac = meta['tactic']
        totals[tac] = totals.get(tac, 0) + 1
        if tid in covered:
            counts[tac] = counts.get(tac, 0) + 1
            sums[tac] = sums.get(tac, 0) + float(covered[tid].get('score', 0))
    for tac in TACTIC_DISPLAY_ORDER:
        total = totals.get(tac, 0)
        cnt = counts.get(tac, 0)
        avg_strength = (sums.get(tac, 0) / cnt) if cnt else 0
        coverage_pct = round((cnt / total) * 100, 1) if total else 0
        effective_score = round((coverage_pct * 0.65) + (avg_strength * 0.35), 1) if total else 0
        enterprise['tactic_coverage'].append({'tactic': tac, 'name': _tactic_name(tac), 'covered': cnt, 'total': total, 'coverage_pct': coverage_pct, 'avg_strength': round(avg_strength,1), 'score': effective_score})

    known_total = len(scoped_techniques)
    covered = {tid: val for tid, val in covered.items() if tid in scoped_techniques}
    covered_total = len(covered)
    avg_strength = sum(float(x.get('score', 0)) for x in coverage) / covered_total if covered_total else 0
    breadth = (covered_total / known_total) * 100 if known_total else 0
    overall = round((breadth * 0.65) + (avg_strength * 0.35), 1) if known_total else 0
    enterprise['overall_score'] = overall
    enterprise['maturity'] = 'High' if overall >= 75 else 'Moderate' if overall >= 55 else 'Basic' if overall >= 30 else 'Limited'

    # State overlay: observed behavior vs theoretical coverage capability.
    for tid, meta in scoped_techniques.items():
        is_obs = tid in observed
        is_cov = tid in covered
        score = covered[tid]['score'] if is_cov else 0
        has_rule = tid in rule_techs
        if is_obs and is_cov and tid in validated_techs:
            state = 'Validated'
        elif is_obs and is_cov:
            state = 'Observed + Covered'
        elif is_obs:
            state = 'Observed Only'
        elif is_cov and score >= 70:
            state = 'Covered'
        elif is_cov:
            state = 'Partially Covered'
        else:
            state = 'Not Covered'
        enterprise['coverage_states'].append({'techniqueID': tid, 'name': meta['name'], 'tactic': meta['tactic'], 'state': state, 'score': score, 'rule': has_rule, 'validated': tid in validated_techs})

    # Gaps and detection engineering readiness.
    for tc in enterprise['tactic_coverage']:
        if tc['score'] < 50:
            enterprise['gaps'].append({'tactic': tc['name'], 'coverage': tc['score'], 'gap': 'Low enterprise telemetry coverage for this tactic.'})
        elif tc['score'] < 70:
            enterprise['gaps'].append({'tactic': tc['name'], 'coverage': tc['score'], 'gap': 'Partial telemetry coverage; validate data sources and detection rules.'})
        readiness = 'Excellent' if tc['score'] >= 80 else 'Good' if tc['score'] >= 65 else 'Fair' if tc['score'] >= 45 else 'Poor'
        enterprise['readiness'].append({'tactic': tc['name'], 'readiness': readiness, 'score': tc['score']})

    for rec in RECOMMENDATION_LIBRARY:
        rec_cat = SOURCE_CATEGORY.get(rec.get('source'), '')
        rec_scope = {'Windows':'windows','Linux':'linux','macOS':'macos','Network':'network','Cloud':'cloud'}.get(rec_cat)
        if rec['source'] not in detected_sources and (not rec_scope or rec_scope in coverage_scope or rec_cat == 'SIEM / Forwarding'):
            enterprise['recommendations'].append(rec)
    enterprise['recommendations'] = sorted(enterprise['recommendations'], key=lambda r: -r['gain'])[:8]

    enterprise['rule_coverage']['covered_with_rules'] = len([tid for tid in covered if tid in rule_techs])
    enterprise['rule_coverage']['validated_techniques'] = len(validated_techs)
    enterprise['rule_coverage']['detectable_without_rules'] = max(0, covered_total - enterprise['rule_coverage']['covered_with_rules'])

    strong = [x['name'] for x in enterprise['tactic_coverage'] if x['score'] >= 70]
    weak = [x['name'] for x in enterprise['tactic_coverage'] if x['score'] < 50]
    enterprise['executive_summary'] = (
        f"Enterprise theoretical ATT&CK coverage is {overall}% ({enterprise['maturity']}) for the detected scope: {', '.join(coverage_scope)}. "
        f"Detected telemetry sources include {', '.join(detected_sources) if detected_sources else 'none'}. "
        f"Strongest tactic coverage: {', '.join(strong[:4]) if strong else 'none'}. "
        f"Priority gaps: {', '.join(weak[:4]) if weak else 'no major gaps in the mapped technique set'}. "
        "This assessment describes enterprise detection potential from telemetry sources; it is not evidence that every technique occurred."
    )
    return enterprise

def validate_layer(layer):
    assert layer['domain'] == 'enterprise-attack'
    assert layer['versions']['layer'] == '4.5'
    assert isinstance(layer['techniques'], list)
    for x in layer['techniques']:
        assert x['techniqueID'] in VALID_TECHNIQUES, x['techniqueID']
        assert x['tactic'] in VALID_TACTICS, x['tactic']
        assert isinstance(x['score'], float)
        assert 0 <= x['score'] <= 100
        assert isinstance(x.get('color',''), str) and x['color'].startswith('#') and len(x['color']) == 7
    return True


# v2 baseline: single Enterprise ATT&CK coverage model ----------------------
# UI pages, report generation, and Navigator exports should render from the
# same Observed/Theoretical/Validated model.  Theoretical coverage is defined as
# telemetry-supported techniques UNION observed techniques, so Observed is
# always a subset of Theoretical.  Validated is driven by successful rule
# matches and carries rule/evidence details when available.

def _attack_id_set_from_result(result):
    ids = set()
    for t in result.get('techniques', []) or []:
        tid = t.get('techniqueID') or t.get('technique_id')
        if tid in VALID_TECHNIQUES:
            ids.add(tid)
    for ev in result.get('normalized_events', []) or []:
        for tid in ev.get('attack_candidates', []) or []:
            if tid in VALID_TECHNIQUES:
                ids.add(tid)
    return ids


def _validated_ids_and_details(result):
    details = {}
    items = result.get('validated_techniques') or (result.get('rule_validations') or {}).get('validated_techniques') or []
    for item in items or []:
        tid = item.get('techniqueID') or item.get('technique_id')
        if tid in VALID_TECHNIQUES:
            details[tid] = dict(item)
    return set(details), details


def _rule_technique_ids(rules=None):
    out = set()
    for r in rules or []:
        for tid in r.get('attack', []) or r.get('techniques', []) or []:
            if tid in VALID_TECHNIQUES:
                out.add(tid)
    return out


def build_enterprise_attack_coverage_model(result, rules=None):
    """Return a canonical ATT&CK coverage model for UI and reports.

    Each technique in scope has consistent observed/theoretical/validated flags.
    The denominator is scoped to seen OS/log types to avoid penalizing Linux-only
    or network-only analyses for missing unrelated Windows/macOS/cloud telemetry.
    """
    result = result or {}
    rules = rules or []
    data_source_items = result.get('data_source_coverage') or build_data_source_coverage(result)
    data_source_by_id = {x.get('techniqueID'): x for x in data_source_items if x.get('techniqueID') in VALID_TECHNIQUES}
    observed_ids = _attack_id_set_from_result(result)
    validated_ids, validated_details = _validated_ids_and_details(result)
    detected_sources = detected_data_sources(result)
    coverage_scope = _detected_coverage_scope(result, detected_sources)

    # Anything observed or validated must be in scope, even if its name appears
    # OS-specific and the telemetry scope inference missed that OS/log type.
    scoped_techniques = {
        tid: meta for tid, meta in VALID_TECHNIQUES.items()
        if _technique_in_detected_scope(tid, meta, coverage_scope) or tid in observed_ids or tid in validated_ids
    }
    theoretical_ids = ({tid for tid, item in data_source_by_id.items() if _coverage_item_counts_as_theoretical(item)} | observed_ids) & set(scoped_techniques)
    observed_ids = observed_ids & set(scoped_techniques)
    validated_ids = validated_ids & set(scoped_techniques)
    rule_techs = _rule_technique_ids(rules)

    techniques = []
    tactic_totals = {t: 0 for t in TACTIC_DISPLAY_ORDER}
    tactic_observed = {t: 0 for t in TACTIC_DISPLAY_ORDER}
    tactic_theoretical = {t: 0 for t in TACTIC_DISPLAY_ORDER}
    tactic_validated = {t: 0 for t in TACTIC_DISPLAY_ORDER}
    tactic_strength_sum = {t: 0.0 for t in TACTIC_DISPLAY_ORDER}

    for tid, meta in sorted(scoped_techniques.items()):
        tactic = meta.get('tactic', '')
        if tactic not in tactic_totals:
            tactic_totals[tactic] = 0; tactic_observed[tactic] = 0; tactic_theoretical[tactic] = 0; tactic_validated[tactic] = 0; tactic_strength_sum[tactic] = 0.0
        ds = data_source_by_id.get(tid, {})
        score = float(ds.get('score', 0) or 0)
        obs = tid in observed_ids
        theo = tid in theoretical_ids
        val = tid in validated_ids
        if obs and score < 70:
            # Observed evidence proves at least a minimum theoretical capability
            # for this analysis because some telemetry/evidence source surfaced it.
            score = 70.0
        if val and score < 85:
            score = 85.0
        if val:
            state = 'Validated'
        elif obs and theo:
            state = 'Observed + Covered'
        elif obs:
            state = 'Observed Only'
        elif theo and score >= 70:
            state = 'Covered'
        elif theo:
            state = 'Partially Covered'
        else:
            state = 'Not Covered'
        tactic_totals[tactic] += 1
        if obs: tactic_observed[tactic] += 1
        if theo:
            tactic_theoretical[tactic] += 1
            tactic_strength_sum[tactic] += score
        if val: tactic_validated[tactic] += 1
        techniques.append({
            'techniqueID': tid,
            'name': meta.get('name', tid),
            'tactic': tactic,
            'observed': obs,
            'theoretical': theo,
            'validated': val,
            'state': state,
            'score': round(score, 1),
            'rule': tid in rule_techs,
            'data_sources': sorted(ds.get('data_sources', []) or []),
            'rationale': ds.get('rationale', []) or [],
            'validated_rules': (validated_details.get(tid, {}) or {}).get('rules', []),
            'validated_evidence': (validated_details.get(tid, {}) or {}).get('evidence', []),
            'match_count': (validated_details.get(tid, {}) or {}).get('match_count', 0),
        })

    def rollup(kind):
        out = []
        for tac in TACTIC_DISPLAY_ORDER:
            total = tactic_totals.get(tac, 0)
            if kind == 'observed': covered = tactic_observed.get(tac, 0); strength = 100 if covered else 0
            elif kind == 'validated': covered = tactic_validated.get(tac, 0); strength = 100 if covered else 0
            else:
                covered = tactic_theoretical.get(tac, 0)
                strength = (tactic_strength_sum.get(tac, 0.0) / covered) if covered else 0
            pct = round((covered / total) * 100, 1) if total else 0
            score = pct if kind != 'theoretical' else round((pct * 0.65) + (strength * 0.35), 1) if total else 0
            out.append({'tactic': tac, 'name': _tactic_name(tac), 'covered': covered, 'total': total, 'coverage_pct': pct, 'avg_strength': round(strength, 1), 'score': round(score, 1)})
        return out

    theoretical_count = sum(1 for t in techniques if t['theoretical'])
    scoped_total = len(techniques)
    avg_strength = sum(t['score'] for t in techniques if t['theoretical']) / theoretical_count if theoretical_count else 0
    breadth = (theoretical_count / scoped_total) * 100 if scoped_total else 0
    overall = round((breadth * 0.65) + (avg_strength * 0.35), 1) if scoped_total else 0

    return {
        'basis': 'enterprise-wide unified ATT&CK coverage model',
        'attack_version': ATTACK_DATASET_METADATA.get('version', ATTACK_VERSION),
        'navigator_version': NAVIGATOR_VERSION,
        'dataset_label': ATTACK_DATASET_METADATA.get('dataset_label', 'ATT&CK Enterprise STIX'),
        'dataset_source': ATTACK_DATASET_METADATA.get('source'),
        'coverage_scope': coverage_scope,
        'scoped_technique_total': scoped_total,
        'observed_count': len(observed_ids),
        'theoretical_count': theoretical_count,
        'validated_count': len(validated_ids),
        'overall_score': overall,
        'maturity': 'High' if overall >= 75 else 'Moderate' if overall >= 55 else 'Basic' if overall >= 30 else 'Limited',
        'techniques': techniques,
        'rollups': {'observed': rollup('observed'), 'theoretical': rollup('theoretical'), 'validated': rollup('validated')},
        'observed_ids': sorted(observed_ids),
        'theoretical_ids': sorted(theoretical_ids),
        'validated_ids': sorted(validated_ids),
    }


# Override enterprise_coverage_assessment with the canonical model-backed scorer.
def enterprise_coverage_assessment(result, rules=None):
    result = result or {}
    rules = rules or []
    coverage = result.get('data_source_coverage') or build_data_source_coverage(result)
    detected_sources = detected_data_sources(result)
    model = build_enterprise_attack_coverage_model({**result, 'data_source_coverage': coverage}, rules)
    enterprise = {
        'basis': model['basis'],
        'attack_version': model['attack_version'],
        'navigator_version': model['navigator_version'],
        'dataset_label': model.get('dataset_label'),
        'dataset_source': model.get('dataset_source'),
        'overall_score': model['overall_score'],
        'maturity': model['maturity'],
        'detected_sources': detected_sources,
        'coverage_scope': model['coverage_scope'],
        'scoped_technique_total': model['scoped_technique_total'],
        'observed_count': model['observed_count'],
        'theoretical_count': model['theoretical_count'],
        'validated_count': model['validated_count'],
        'detectable_count': model.get('detectable_count', 0),
        'out_of_scope_validated_count': model.get('out_of_scope_validated_count', 0),
        'out_of_scope_observed_count': model.get('out_of_scope_observed_count', 0),
        'telemetry_inventory': {},
        'data_components': [],
        'tactic_coverage': model['rollups']['theoretical'],
        'tactic_rollups': model['rollups'],
        'coverage_states': model['techniques'],
        'gaps': [],
        'recommendations': [],
        'rule_coverage': {},
        'readiness': [],
        'executive_summary': '',
    }
    grouped = {}
    for source in detected_sources:
        grouped.setdefault(SOURCE_CATEGORY.get(source, 'Other'), []).append(source)
    for cat in sorted(set(list(grouped) + ['Windows','Linux','macOS','Network','SIEM / Forwarding'])):
        enterprise['telemetry_inventory'][cat] = sorted(grouped.get(cat, []))
    components = {}
    for source in detected_sources:
        for comp in SOURCE_COMPONENTS.get(source, []):
            components.setdefault(comp, set()).add(source)
    enterprise['data_components'] = [{'component': k, 'sources': sorted(v)} for k, v in sorted(components.items())]
    for tc in enterprise['tactic_coverage']:
        if tc['total'] and tc['score'] < 50:
            enterprise['gaps'].append({'tactic': tc['name'], 'coverage': tc['score'], 'gap': 'Low scoped telemetry coverage for this tactic.'})
        elif tc['total'] and tc['score'] < 70:
            enterprise['gaps'].append({'tactic': tc['name'], 'coverage': tc['score'], 'gap': 'Partial scoped telemetry coverage; validate data sources and detection rules.'})
        readiness = 'Excellent' if tc['score'] >= 80 else 'Good' if tc['score'] >= 65 else 'Fair' if tc['score'] >= 45 else 'Poor'
        enterprise['readiness'].append({'tactic': tc['name'], 'readiness': readiness, 'score': tc['score']})
    for rec in RECOMMENDATION_LIBRARY:
        rec_cat = SOURCE_CATEGORY.get(rec.get('source'), rec.get('category', ''))
        rec_scope = {'Windows':'windows','Linux':'linux','macOS':'macos','Network':'network','Cloud':'cloud'}.get(rec_cat)
        # Recommendations are strictly OS/log-type scoped. For example, a
        # Linux-only environment only receives Linux recommendations, and a
        # network-only environment only receives network recommendations.
        if rec['source'] not in detected_sources and rec_scope and rec_scope in model['coverage_scope']:
            enterprise['recommendations'].append(rec)
    enterprise['recommendations'] = sorted(enterprise['recommendations'], key=lambda r: -r['gain'])[:8]
    rule_techs = _rule_technique_ids(rules)
    applicable_rule_techs = [t for t in model['techniques'] if t.get('applicable') and t.get('rule')]
    enterprise['rule_coverage'] = {
        'techniques_with_rules': len(rule_techs),
        'applicable_techniques_with_rules': len(applicable_rule_techs),
        'detectable_techniques': model.get('detectable_count', 0),
        'covered_with_rules': len([t for t in applicable_rule_techs if t.get('theoretical')]),
        'applicable_without_rules': len([t for t in model['techniques'] if t.get('applicable') and not t.get('rule')]),
        'validated_techniques': model['validated_count'],
    }
    strong = [x['name'] for x in enterprise['tactic_coverage'] if x['score'] >= 70]
    weak = [x['name'] for x in enterprise['tactic_coverage'] if x['total'] and x['score'] < 50]
    enterprise['executive_summary'] = (
        f"Scoped enterprise ATT&CK coverage is {enterprise['overall_score']}% across {model['scoped_technique_total']} techniques relevant to detected OS/log types. "
        f"Observed: {model['observed_count']}; theoretical: {model['theoretical_count']}; detectable: {model.get('detectable_count', 0)}; validated: {model['validated_count']}. "
        + ("Strongest areas: " + ', '.join(strong[:4]) + '. ' if strong else '')
        + ("Priority gaps: " + ', '.join(weak[:4]) + '.' if weak else 'No major scoped gaps identified.')
    )
    return enterprise


def strict_data_source_coverage_layer(result, name='Unified Enterprise ATT&CK Coverage'):
    model = build_enterprise_attack_coverage_model(result, [])
    techniques = []
    for t in model.get('techniques', []):
        if not t.get('applicable'):
            color = '#9ca3af'; label = 'Not Applicable'
        elif t.get('validated'):
            color = '#7c3aed'; label = 'Validated'
        elif t.get('observed'):
            color = '#60a5fa'; label = 'Observed'
        elif t.get('theoretical') and t.get('rule'):
            color = '#f97316'; label = 'Theoretical + Detectable'
        elif t.get('theoretical') and t.get('score', 0) >= 70:
            color = '#22c55e'; label = 'Theoretical'
        elif t.get('theoretical'):
            color = '#f59e0b'; label = 'Partial Theoretical'
        elif t.get('rule'):
            color = '#fb923c'; label = 'Detectable'
        else:
            color = '#f3f4f6'; label = 'Not Covered'
        techniques.append({
            'techniqueID': t['techniqueID'],
            'tactic': t['tactic'],
            'score': float(max(0, min(100, t.get('score', 0)))),
            'color': color,
            'comment': (f"{label}. Sources: {', '.join(t.get('data_sources', [])[:10])}. Evidence: {'; '.join(t.get('validated_evidence', [])[:3])}")[:900],
            'metadata': [
                {'name': 'Coverage State', 'value': t.get('state', label)},
                {'name': 'Observed', 'value': str(bool(t.get('observed'))).lower()},
                {'name': 'Theoretical', 'value': str(bool(t.get('theoretical'))).lower()},
                {'name': 'Validated', 'value': str(bool(t.get('validated'))).lower()},
                {'name': 'Rule Exists', 'value': str(bool(t.get('rule'))).lower()},
                {'name': 'Applicable', 'value': str(bool(t.get('applicable'))).lower()},
                {'name': 'Data Sources', 'value': ', '.join(t.get('data_sources', [])[:20])},
            ]
        })
    layer = {
      'versions': {'attack': ATTACK_VERSION, 'navigator': NAVIGATOR_VERSION, 'layer':'4.5'},
      'name': name,
      'domain':'enterprise-attack',
      'description':'Environment-scoped ATT&CK Navigator layer from PCAP Mapper. Observed, theoretical, detectable, validated, and not-applicable states share the same OS/log-source scope.',
      'filters': {'platforms': VALID_PLATFORMS},
      'sorting': 0,
      'layout': {'layout':'side','aggregateFunction':'average','showID':False,'showName':True,'showAggregateScores':False,'countUnscored':False,'expandedSubtechniques':'all'},
      'hideDisabled': False,
      'techniques': techniques,
      'gradient': {'colors':['#f3f4f6','#f59e0b','#22c55e','#60a5fa','#7c3aed'],'minValue':0,'maxValue':100},
      'legendItems': [
        {'label':'Not Applicable','color':'#9ca3af'},
        {'label':'Not Covered','color':'#f3f4f6'},
        {'label':'Detectable','color':'#fb923c'},
        {'label':'Partial Theoretical','color':'#f59e0b'},
        {'label':'Theoretical','color':'#22c55e'},
        {'label':'Observed','color':'#60a5fa'},
        {'label':'Validated','color':'#7c3aed'},
      ],
      'metadata': [{'name':'ATT&CK version','value':ATTACK_DATASET_METADATA.get('version', ATTACK_VERSION)},{'name':'Coverage model','value':'environment-scoped observed/theoretical/detectable/validated/not-applicable'},{'name':'Coverage scope','value':', '.join(model.get('coverage_scope', []))}],
      'links': [], 'showTacticRowBackground': False, 'tacticRowBackground':'#dddddd', 'selectTechniquesAcrossTactics': True, 'selectSubtechniquesWithParent': False, 'selectVisibleTechniques': False
    }
    validate_layer(layer)
    return layer


# v2 scoped heat-map baseline override --------------------------------------
# All ATT&CK views now share one applicable-scope model.  Observed,
# theoretical, and validated remain separate questions, but each percentage is
# calculated against the same environment-specific denominator.  Techniques
# outside the detected OS/log-source scope are retained as gray Not Applicable
# entries for UI and Navigator exports and are excluded from coverage math.

def _coverage_state_class(t):
    if t.get('external_visibility'):
        return 'external_visibility'
    if not t.get('applicable'):
        return 'not_applicable'
    # Unified heat-map priority: observed/observable evidence first, then
    # validated rule matches, then theoretical telemetry capability.
    if t.get('observed'):
        return 'observed'
    if t.get('validated'):
        return 'validated'
    if t.get('theoretical') and t.get('rule'):
        return 'theoretical_detectable'
    if t.get('theoretical') and float(t.get('score') or 0) >= 70:
        return 'covered'
    if t.get('theoretical'):
        return 'partial'
    if t.get('rule'):
        return 'detectable'
    return 'not_covered'


def build_enterprise_attack_coverage_model(result, rules=None):
    result = result or {}
    rules = rules or []
    data_source_items = result.get('data_source_coverage') or build_data_source_coverage(result)
    data_source_by_id = {x.get('techniqueID'): x for x in data_source_items if x.get('techniqueID') in VALID_TECHNIQUES}
    observed_ids = _attack_id_set_from_result(result)
    validated_ids, validated_details = _validated_ids_and_details(result)
    detected_sources = detected_data_sources(result)
    coverage_scope = _detected_coverage_scope(result, detected_sources)
    rule_techs = _rule_technique_ids(rules)

    raw_observed_ids = set(observed_ids)
    raw_validated_ids = set(validated_ids)

    # Applicability is based only on the detected OS/log-source environment.
    # Evidence or a rule match must not make an out-of-scope technique appear
    # applicable. For example, a macOS-only technique in a Windows-only capture
    # remains gray / Not Applicable even if a broad rule or legacy mapping
    # produced a match.
    applicable_ids = {
        tid for tid, meta in VALID_TECHNIQUES.items()
        if _technique_in_detected_scope(tid, meta, coverage_scope)
    }

    # Theoretical is telemetry/log-type capability within that scope. Observed
    # and validated are independently scoped to the same environment so every
    # heat map and report uses the same denominator.
    theoretical_ids = {tid for tid, item in data_source_by_id.items() if _coverage_item_counts_as_theoretical(item)} & applicable_ids
    observed_ids = observed_ids & applicable_ids
    validated_ids = validated_ids & applicable_ids

    techniques = []
    tactic_totals = {t: 0 for t in TACTIC_DISPLAY_ORDER}
    tactic_observed = {t: 0 for t in TACTIC_DISPLAY_ORDER}
    tactic_theoretical = {t: 0 for t in TACTIC_DISPLAY_ORDER}
    tactic_validated = {t: 0 for t in TACTIC_DISPLAY_ORDER}
    tactic_strength_sum = {t: 0.0 for t in TACTIC_DISPLAY_ORDER}

    for tid, meta in sorted(VALID_TECHNIQUES.items()):
        tactic = meta.get('tactic', '')
        applicable = tid in applicable_ids
        ds = data_source_by_id.get(tid, {})
        score = float(ds.get('score', 0) or 0)
        obs = tid in observed_ids
        theo = tid in theoretical_ids
        val = tid in validated_ids
        if val and score < 85:
            score = 85.0
        elif obs and score < 60:
            score = 60.0
        if not applicable:
            state = 'Not Applicable'
            score = 0.0
        elif val:
            state = 'Validated'
        elif obs and theo:
            state = 'Observed + Theoretical'
        elif obs:
            state = 'Observed'
        elif theo and (tid in rule_techs):
            state = 'Theoretical + Detectable'
        elif theo and score >= 70:
            state = 'Theoretical'
        elif theo:
            state = 'Partial Theoretical'
        elif tid in rule_techs:
            state = 'Detectable'
        else:
            state = 'Not Covered'

        if applicable:
            if tactic not in tactic_totals:
                tactic_totals[tactic] = 0; tactic_observed[tactic] = 0; tactic_theoretical[tactic] = 0; tactic_validated[tactic] = 0; tactic_strength_sum[tactic] = 0.0
            tactic_totals[tactic] += 1
            if obs: tactic_observed[tactic] += 1
            if theo:
                tactic_theoretical[tactic] += 1
                tactic_strength_sum[tactic] += score
            if val: tactic_validated[tactic] += 1

        techniques.append({
            'techniqueID': tid,
            'name': meta.get('name', tid),
            'tactic': tactic,
            'applicable': applicable,
            'observed': obs,
            'theoretical': theo,
            'validated': val,
            'validated_raw': tid in raw_validated_ids,
            'observed_raw': tid in raw_observed_ids,
            'out_of_scope_validated_match': (tid in raw_validated_ids) and not applicable,
            'not_applicable': not applicable,
            'state': state,
            'state_class': _coverage_state_class({'applicable': applicable, 'observed': obs, 'theoretical': theo, 'validated': val, 'rule': tid in rule_techs, 'score': score}),
            'detectable': applicable and (tid in rule_techs) and not val,
            'score': round(score, 1),
            'rule': tid in rule_techs,
            'data_sources': sorted(ds.get('data_sources', []) or []),
            'rationale': ds.get('rationale', []) or [],
            'validated_rules': (validated_details.get(tid, {}) or {}).get('rules', []),
            'validated_evidence': (validated_details.get(tid, {}) or {}).get('evidence', []),
            'match_count': (validated_details.get(tid, {}) or {}).get('match_count', 0),
        })

    def rollup(kind):
        out = []
        for tac in TACTIC_DISPLAY_ORDER:
            total = tactic_totals.get(tac, 0)
            if kind == 'observed':
                covered = tactic_observed.get(tac, 0); strength = 100 if covered else 0
            elif kind == 'validated':
                covered = tactic_validated.get(tac, 0); strength = 100 if covered else 0
            else:
                covered = tactic_theoretical.get(tac, 0)
                strength = (tactic_strength_sum.get(tac, 0.0) / covered) if covered else 0
            pct = round((covered / total) * 100, 1) if total else 0
            score = pct if kind != 'theoretical' else (round((pct * 0.65) + (strength * 0.35), 1) if total else 0)
            out.append({'tactic': tac, 'name': _tactic_name(tac), 'covered': covered, 'total': total, 'not_applicable': len([x for x in techniques if x.get('tactic') == tac and not x.get('applicable') and not x.get('external_visibility')]), 'external_visibility': len([x for x in techniques if x.get('tactic') == tac and x.get('external_visibility')]), 'coverage_pct': pct, 'avg_strength': round(strength, 1), 'score': round(score, 1)})
        return out

    applicable_total = len(applicable_ids)
    theoretical_count = len(theoretical_ids)
    avg_strength = sum(t['score'] for t in techniques if t['theoretical']) / theoretical_count if theoretical_count else 0
    breadth = (theoretical_count / applicable_total) * 100 if applicable_total else 0
    overall = round((breadth * 0.65) + (avg_strength * 0.35), 1) if applicable_total else 0

    return {
        'basis': 'environment-scoped ATT&CK coverage model',
        'attack_version': ATTACK_DATASET_METADATA.get('version', ATTACK_VERSION),
        'navigator_version': NAVIGATOR_VERSION,
        'dataset_label': ATTACK_DATASET_METADATA.get('dataset_label', 'ATT&CK Enterprise STIX'),
        'dataset_source': ATTACK_DATASET_METADATA.get('source'),
        'coverage_scope': coverage_scope,
        'scoped_technique_total': applicable_total,
        'total_registry_techniques': len(VALID_TECHNIQUES),
        'not_applicable_count': len(VALID_TECHNIQUES) - applicable_total,
        'observed_count': len(observed_ids),
        'theoretical_count': theoretical_count,
        'validated_count': len(validated_ids),
        'detectable_count': len([tid for tid in applicable_ids if tid in rule_techs and tid not in validated_ids]),
        'out_of_scope_validated_count': len([tid for tid in raw_validated_ids if tid not in applicable_ids]),
        'out_of_scope_observed_count': len([tid for tid in raw_observed_ids if tid not in applicable_ids]),
        'observed_score': round((len(observed_ids) / applicable_total) * 100, 1) if applicable_total else 0,
        'theoretical_score': overall,
        'validated_score': round((len(validated_ids) / applicable_total) * 100, 1) if applicable_total else 0,
        'overall_score': overall,
        'maturity': 'High' if overall >= 75 else 'Moderate' if overall >= 55 else 'Basic' if overall >= 30 else 'Limited',
        'techniques': techniques,
        'rollups': {'observed': rollup('observed'), 'theoretical': rollup('theoretical'), 'validated': rollup('validated')},
        'observed_ids': sorted(observed_ids),
        'theoretical_ids': sorted(theoretical_ids),
        'validated_ids': sorted(validated_ids),
        'detectable_ids': sorted([tid for tid in applicable_ids if tid in rule_techs and tid not in validated_ids]),
        'applicable_ids': sorted(applicable_ids),
    }


def enterprise_coverage_assessment(result, rules=None):
    result = result or {}
    rules = rules or []
    coverage = result.get('data_source_coverage') or build_data_source_coverage(result)
    detected_sources = detected_data_sources(result)
    model = build_enterprise_attack_coverage_model({**result, 'data_source_coverage': coverage}, rules)
    enterprise = {
        'basis': model['basis'],
        'attack_version': model['attack_version'],
        'navigator_version': model['navigator_version'],
        'dataset_label': model.get('dataset_label'),
        'dataset_source': model.get('dataset_source'),
        'overall_score': model['overall_score'],
        'observed_score': model['observed_score'],
        'theoretical_score': model['theoretical_score'],
        'validated_score': model['validated_score'],
        'maturity': model['maturity'],
        'detected_sources': detected_sources,
        'coverage_scope': model['coverage_scope'],
        'scoped_technique_total': model['scoped_technique_total'],
        'total_registry_techniques': model['total_registry_techniques'],
        'not_applicable_count': model['not_applicable_count'],
        'observed_count': model['observed_count'],
        'theoretical_count': model['theoretical_count'],
        'validated_count': model['validated_count'],
        'detectable_count': model.get('detectable_count', 0),
        'out_of_scope_validated_count': model.get('out_of_scope_validated_count', 0),
        'out_of_scope_observed_count': model.get('out_of_scope_observed_count', 0),
        'telemetry_inventory': {},
        'data_components': [],
        'tactic_coverage': model['rollups']['theoretical'],
        'tactic_rollups': model['rollups'],
        'coverage_states': model['techniques'],
        'gaps': [],
        'recommendations': [],
        'rule_coverage': {},
        'readiness': [],
        'executive_summary': '',
    }
    grouped = {}
    for source in detected_sources:
        grouped.setdefault(SOURCE_CATEGORY.get(source, 'Other'), []).append(source)
    for cat in sorted(set(list(grouped) + ['Windows','Linux','macOS','Network','SIEM / Forwarding'])):
        enterprise['telemetry_inventory'][cat] = sorted(grouped.get(cat, []))
    components = {}
    for source in detected_sources:
        for comp in SOURCE_COMPONENTS.get(source, []):
            components.setdefault(comp, set()).add(source)
    enterprise['data_components'] = [{'component': k, 'sources': sorted(v)} for k, v in sorted(components.items())]
    for tc in enterprise['tactic_coverage']:
        if not tc['total']:
            continue
        if tc['score'] < 50:
            enterprise['gaps'].append({'tactic': tc['name'], 'coverage': tc['score'], 'gap': 'Low coverage within the detected OS/log-source scope.'})
        elif tc['score'] < 70:
            enterprise['gaps'].append({'tactic': tc['name'], 'coverage': tc['score'], 'gap': 'Partial coverage within the detected OS/log-source scope.'})
        readiness = 'Excellent' if tc['score'] >= 80 else 'Good' if tc['score'] >= 65 else 'Fair' if tc['score'] >= 45 else 'Poor'
        enterprise['readiness'].append({'tactic': tc['name'], 'readiness': readiness, 'score': tc['score']})
    for rec in RECOMMENDATION_LIBRARY:
        rec_cat = SOURCE_CATEGORY.get(rec.get('source'), rec.get('category', ''))
        rec_scope = {'Windows':'windows','Linux':'linux','macOS':'macos','Network':'network','Cloud':'cloud'}.get(rec_cat)
        # Recommendations are strictly OS/log-type scoped. For example, a
        # Linux-only environment only receives Linux recommendations, and a
        # network-only environment only receives network recommendations.
        if rec['source'] not in detected_sources and rec_scope and rec_scope in model['coverage_scope']:
            enterprise['recommendations'].append(rec)
    enterprise['recommendations'] = sorted(enterprise['recommendations'], key=lambda r: -r['gain'])[:8]
    rule_techs = _rule_technique_ids(rules)
    applicable_rule_techs = [t for t in model['techniques'] if t.get('applicable') and t.get('rule')]
    enterprise['rule_coverage'] = {
        'techniques_with_rules': len(rule_techs),
        'applicable_techniques_with_rules': len(applicable_rule_techs),
        'detectable_techniques': model.get('detectable_count', 0),
        'covered_with_rules': len([t for t in applicable_rule_techs if t.get('theoretical')]),
        'applicable_without_rules': len([t for t in model['techniques'] if t.get('applicable') and not t.get('rule')]),
        'validated_techniques': model['validated_count'],
    }
    strong = [x['name'] for x in enterprise['tactic_coverage'] if x['score'] >= 70]
    weak = [x['name'] for x in enterprise['tactic_coverage'] if x['total'] and x['score'] < 50]
    enterprise['executive_summary'] = (
        f"Scoped enterprise ATT&CK theoretical coverage is {enterprise['overall_score']}% across {model['scoped_technique_total']} applicable techniques. "
        f"{model['not_applicable_count']} techniques are gray/not applicable for the detected OS/log-source scope ({', '.join(model['coverage_scope'])}). "
        f"Observed: {model['observed_count']} ({model['observed_score']}%); theoretical: {model['theoretical_count']} ({model['theoretical_score']}%); detectable: {model.get('detectable_count', 0)}; validated: {model['validated_count']} ({model['validated_score']}%). "
        f"Out-of-scope validated matches ignored: {model.get('out_of_scope_validated_count', 0)}. "
        + ("Strongest scoped areas: " + ', '.join(strong[:4]) + '. ' if strong else '')
        + ("Priority scoped gaps: " + ', '.join(weak[:4]) + '.' if weak else 'No major scoped gaps identified.')
    )
    return enterprise



def _navigator_base_layer(name, description, techniques, legend_items, metadata=None, gradient=None):
    layer = {
      'versions': {'attack': ATTACK_VERSION, 'navigator': NAVIGATOR_VERSION, 'layer':'4.5'},
      'name': name,
      'domain':'enterprise-attack',
      'description': description,
      'filters': {'platforms': VALID_PLATFORMS},
      'sorting': 0,
      'layout': {'layout':'side','aggregateFunction':'average','showID':False,'showName':True,'showAggregateScores':False,'countUnscored':False,'expandedSubtechniques':'all'},
      'hideDisabled': False,
      'techniques': techniques,
      'gradient': gradient or {'colors':[PCAP_MAPPER_HEATMAP_COLORS['missing'],PCAP_MAPPER_HEATMAP_COLORS['partial'],PCAP_MAPPER_HEATMAP_COLORS['covered'],PCAP_MAPPER_HEATMAP_COLORS['validated'],PCAP_MAPPER_HEATMAP_COLORS['observed']],'minValue':0,'maxValue':100},
      'legendItems': legend_items,
      'metadata': metadata or [],
      'links': [], 'showTacticRowBackground': False, 'tacticRowBackground':'#dddddd', 'selectTechniquesAcrossTactics': True, 'selectSubtechniquesWithParent': False, 'selectVisibleTechniques': False
    }
    validate_layer(layer)
    return layer


def _coverage_metadata(t, label, model):
    return [
        {'name': 'Coverage State', 'value': t.get('state', label)},
        {'name': 'Navigator Export State', 'value': label},
        {'name': 'Applicable to detected environment', 'value': str(bool(t.get('applicable'))).lower()},
        {'name': 'External visibility boundary', 'value': str(bool(t.get('external_visibility'))).lower()},
        {'name': 'External visibility reason', 'value': t.get('external_visibility_reason', '')},
        {'name': 'Observed', 'value': str(bool(t.get('observed'))).lower()},
        {'name': 'Theoretical', 'value': str(bool(t.get('theoretical'))).lower()},
        {'name': 'Detectable / Rule Exists', 'value': str(bool(t.get('rule'))).lower()},
        {'name': 'Validated / Rule Matched', 'value': str(bool(t.get('validated'))).lower()},
        {'name': 'Data Sources', 'value': ', '.join(t.get('data_sources', [])[:20])},
        {'name': 'Detected Scope', 'value': ', '.join(model.get('coverage_scope', []))},
    ]


def _technique_comment(t, label, model):
    parts = [
        f"{label}.",
        f"Applicable={bool(t.get('applicable'))}.",
        f"Observed={bool(t.get('observed'))}.",
        f"Theoretical={bool(t.get('theoretical'))}.",
        f"Detectable={bool(t.get('rule'))}.",
        f"Validated={bool(t.get('validated'))}.",
        f"Scope={', '.join(model.get('coverage_scope', [])) or 'none'}.",
    ]
    if t.get('validated_rules'):
        parts.append('Rules=' + ', '.join(t.get('validated_rules', [])[:5]) + '.')
    if t.get('validated_evidence'):
        parts.append('Evidence=' + '; '.join(t.get('validated_evidence', [])[:3]) + '.')
    if t.get('data_sources'):
        parts.append('Data sources=' + ', '.join(t.get('data_sources', [])[:10]) + '.')
    return ' '.join(parts)[:900]


def strict_data_source_coverage_layer(result, name='Theoretical ATT&CK Coverage'):
    """Navigator layer for theoretical enterprise detection capability only.

    This intentionally differs from the unified layer. It shows techniques that
    should be detectable from detected OS/log-source/data-source coverage. It
    does not promote observed or validated techniques into the layer color.
    """
    model = build_enterprise_attack_coverage_model(result, [])
    techniques = []
    for t in model.get('techniques', []):
        if t.get('external_visibility'):
            color = '#64748b'; label = 'External Visibility'; score = 0.0
        elif not t.get('applicable'):
            color = '#6b7280'; label = 'Not Applicable'; score = 0.0
        elif t.get('theoretical') and t.get('score', 0) >= 70:
            color = PCAP_MAPPER_HEATMAP_COLORS['covered']; label = 'Theoretical'; score = float(max(70, min(100, t.get('score', 70))))
        elif t.get('theoretical'):
            color = PCAP_MAPPER_HEATMAP_COLORS['partial']; label = 'Partial Theoretical'; score = float(max(30, min(69, t.get('score', 50))))
        else:
            color = '#374151'; label = 'Not Covered'; score = 0.0
        techniques.append({
            'techniqueID': t['techniqueID'],
            'tactic': t['tactic'],
            'score': score,
            'color': color,
            'comment': _technique_comment(t, label, model),
            'metadata': _coverage_metadata(t, label, model)
        })
    return _navigator_base_layer(
        name,
        'Theoretical ATT&CK Navigator layer from PCAP Mapper. Green means the technique should be detectable from the detected OS/log-source/data-source scope. Dark gray means not covered. Gray means not applicable and is excluded from scoped coverage calculations.',
        techniques,
        [
            {'label':'Theoretical','color':PCAP_MAPPER_HEATMAP_COLORS['covered']},
            {'label':'Partial theoretical','color':PCAP_MAPPER_HEATMAP_COLORS['partial']},
            {'label':'External visibility','color':'#64748b'},
            {'label':'Not covered','color':'#374151'},
            {'label':'Not applicable','color':'#6b7280'},
        ],
        [
            {'name':'ATT&CK version','value':ATTACK_DATASET_METADATA.get('version', ATTACK_VERSION)},
            {'name':'Coverage model','value':'theoretical/data-source only'},
            {'name':'Coverage scope','value':', '.join(model.get('coverage_scope', []))},
            {'name':'Applicable technique denominator','value':str(model.get('scoped_technique_total', 0))},
            {'name':'Not applicable techniques','value':str(model.get('not_applicable_count', 0))},
            {'name':'External visibility techniques','value':str(model.get('external_visibility_count', 0))},
        ],
        {'colors':[PCAP_MAPPER_HEATMAP_COLORS['missing'],PCAP_MAPPER_HEATMAP_COLORS['partial'],PCAP_MAPPER_HEATMAP_COLORS['covered']],'minValue':0,'maxValue':100}
    )


def strict_unified_coverage_layer(result, name='Unified ATT&CK Coverage'):
    """Navigator layer for the complete unified coverage state.

    State priority is: observed/observable evidence, validated rule matches,
    theoretical capability, detectable rules, partial theoretical, external
    visibility, not applicable, not covered.
    """
    model = build_enterprise_attack_coverage_model(result, [])
    techniques = []
    for t in model.get('techniques', []):
        if t.get('observed'):
            color = '#ef4444'; label = 'Observed'; score = 100.0
        elif t.get('validated'):
            color = PCAP_MAPPER_HEATMAP_COLORS['validated']; label = 'Validated'; score = 90.0
        elif t.get('theoretical') and t.get('score', 0) >= 70:
            color = PCAP_MAPPER_HEATMAP_COLORS['covered']; label = 'Theoretical'; score = float(max(70, min(90, t.get('score', 70))))
        elif t.get('theoretical'):
            color = PCAP_MAPPER_HEATMAP_COLORS['partial']; label = 'Partial Theoretical'; score = float(max(30, min(69, t.get('score', 50))))
        elif t.get('rule'):
            color = '#fb923c'; label = 'Detectable'; score = 45.0
        elif t.get('external_visibility'):
            color = '#64748b'; label = 'External Visibility'; score = 0.0
        elif not t.get('applicable'):
            color = '#6b7280'; label = 'Not Applicable'; score = 0.0
        else:
            color = '#374151'; label = 'Not Covered'; score = 0.0
        techniques.append({
            'techniqueID': t['techniqueID'],
            'tactic': t['tactic'],
            'score': float(score),
            'color': color,
            'comment': _technique_comment(t, label, model),
            'metadata': _coverage_metadata(t, label, model)
        })
    return _navigator_base_layer(
        name,
        'Unified ATT&CK Navigator layer from PCAP Mapper. Red=observed/observable evidence highest priority, yellow=validated rule match, green=theoretical/covered capability, orange=detectable rule exists, yellow=partial theoretical, slate=external visibility, dark gray=not covered, gray=not applicable.',
        techniques,
        [
            {'label':'Observed','color':'#ef4444'},
            {'label':'Validated','color':PCAP_MAPPER_HEATMAP_COLORS['validated']},
            {'label':'Theoretical','color':PCAP_MAPPER_HEATMAP_COLORS['covered']},
            {'label':'Detectable','color':'#fb923c'},
            {'label':'Partial theoretical','color':PCAP_MAPPER_HEATMAP_COLORS['partial']},
            {'label':'External visibility','color':'#64748b'},
            {'label':'Not covered','color':'#374151'},
            {'label':'Not applicable','color':'#6b7280'},
        ],
        [
            {'name':'ATT&CK version','value':ATTACK_DATASET_METADATA.get('version', ATTACK_VERSION)},
            {'name':'Coverage model','value':'unified observed/theoretical/detectable/validated/not-applicable'},
            {'name':'Coverage scope','value':', '.join(model.get('coverage_scope', []))},
            {'name':'Applicable technique denominator','value':str(model.get('scoped_technique_total', 0))},
            {'name':'Observed techniques','value':str(model.get('observed_count', 0))},
            {'name':'Theoretical techniques','value':str(model.get('theoretical_count', 0))},
            {'name':'Detectable techniques','value':str(model.get('detectable_count', 0))},
            {'name':'Validated techniques','value':str(model.get('validated_count', 0))},
            {'name':'Not applicable techniques','value':str(model.get('not_applicable_count', 0))},
            {'name':'External visibility techniques','value':str(model.get('external_visibility_count', 0))},
            {'name':'Out-of-scope validated matches ignored','value':str(model.get('out_of_scope_validated_count', 0))},
        ],
        {'colors':[PCAP_MAPPER_HEATMAP_COLORS['missing'],PCAP_MAPPER_HEATMAP_COLORS['partial'],PCAP_MAPPER_HEATMAP_COLORS['covered'],PCAP_MAPPER_HEATMAP_COLORS['validated'],PCAP_MAPPER_HEATMAP_COLORS['observed']],'minValue':0,'maxValue':100}
    )

# ---------------------------------------------------------------------------
# v2 theoretical coverage expansion patch
# ---------------------------------------------------------------------------
# The original v2 pipeline detected that syslog/forwarding existed, but the
# theoretical heat map could remain empty because specific forwarded log types
# were not always expanded into ATT&CK data components and supported techniques.
# These overrides keep the public function names stable while making the
# theoretical path: detected OS/logs -> data components -> ATT&CK techniques ->
# unified coverage model.

# Extend source categories for common Windows, Linux, macOS, network, and cloud
# log types that may appear inside UDP/514 syslog, Beats-like payloads, or
# normalized events.
SOURCE_CATEGORY.update({
    # Windows
    'Windows Security': 'Windows', 'Security': 'Windows', 'System': 'Windows', 'Application': 'Windows',
    'Sysmon': 'Windows', 'PowerShell': 'Windows', 'PowerShell Operational Log': 'Windows',
    'Defender': 'Windows', 'Task Scheduler': 'Windows', 'WinRM': 'Windows', 'Terminal Services': 'Windows',
    'RDP / Terminal Services': 'Windows', 'SMB Server': 'Windows', 'DNS Server': 'Windows', 'DHCP Server': 'Windows',
    'IIS': 'Windows', 'WMI': 'Windows', 'WMI Activity': 'Windows', 'Windows Firewall': 'Windows',
    # Linux
    'auth.log': 'Linux', 'secure': 'Linux', 'sshd': 'Linux', 'sudo': 'Linux', 'cron': 'Linux',
    'systemd': 'Linux', 'systemd-journald': 'Linux', 'journald': 'Linux', 'auditd': 'Linux',
    'iptables': 'Linux', 'nftables': 'Linux', 'AppArmor': 'Linux', 'SELinux': 'Linux', 'Falco': 'Linux',
    'Docker': 'Linux', 'containerd': 'Linux', 'Podman': 'Linux', 'Kubernetes Audit': 'Linux',
    'Nginx': 'Linux', 'Apache': 'Linux', 'osquery': 'Linux',
    # macOS
    'Apple Unified Log': 'macOS', 'Apple Unified Logging': 'macOS', 'OpenBSM audit': 'macOS', 'OpenBSM': 'macOS',
    'launchd': 'macOS', 'launchctl': 'macOS', 'TCC': 'macOS', 'Gatekeeper': 'macOS', 'XProtect': 'macOS',
    'Jamf': 'macOS', 'Jamf Protect': 'macOS', 'Santa': 'macOS', 'FileVault': 'macOS',
    # Network
    'Cisco ASA': 'Network', 'Cisco IOS': 'Network', 'Cisco Firepower': 'Network', 'Palo Alto PAN-OS': 'Network',
    'Fortinet FortiGate': 'Network', 'Check Point': 'Network', 'pfSense': 'Network', 'OPNsense': 'Network',
    'SonicWall': 'Network', 'Squid Proxy': 'Network', 'Proxy': 'Network', 'VPN': 'Network',
    'Wireless Controller': 'Network', 'Firewall': 'Network',
    # Cloud
    'AWS CloudTrail': 'Cloud', 'AWS GuardDuty': 'Cloud', 'Azure Activity': 'Cloud', 'Azure AD': 'Cloud',
    'GCP Audit Logs': 'Cloud', 'Google Workspace': 'Cloud',
})

SOURCE_COMPONENTS.update({
    # Windows components
    'Windows Security': ['User Account Authentication', 'Logon Session', 'Account Management', 'Object Access', 'Scheduled Job', 'Windows Event Logs'],
    'Security': ['User Account Authentication', 'Logon Session', 'Windows Event Logs'],
    'System': ['Service Activity', 'Driver Load', 'System Boot', 'Windows Event Logs'],
    'Application': ['Application Logs', 'Process Activity'],
    'PowerShell': ['PowerShell Script Block', 'Command Execution', 'Process Creation'],
    'Task Scheduler': ['Scheduled Job', 'Process Creation'],
    'WinRM': ['Remote Services', 'PowerShell Remoting', 'Logon Session'],
    'Terminal Services': ['Remote Desktop Session', 'Logon Session'],
    'RDP / Terminal Services': ['Remote Desktop Session', 'Logon Session'],
    'SMB Server': ['SMB Session', 'File Share Access', 'Network Share Access'],
    'DNS Server': ['DNS Queries', 'Domain Name Resolution'],
    'DHCP Server': ['DHCP Lease', 'Host Inventory'],
    'IIS': ['Web Server Logs', 'HTTP Requests', 'Application Logs'],
    'WMI': ['WMI Activity', 'Remote Service Activity'],
    'WMI Activity': ['WMI Activity', 'Remote Service Activity'],
    'Windows Firewall': ['Firewall Events', 'Network Connection Creation'],
    # Linux components
    'auth.log': ['Authentication Logs', 'SSH Session', 'Privilege Changes'],
    'secure': ['Authentication Logs', 'SSH Session', 'Privilege Changes'],
    'sshd': ['SSH Session', 'User Authentication', 'Remote Services'],
    'sudo': ['Privilege Changes', 'Command Execution'],
    'cron': ['Scheduled Job', 'Command Execution'],
    'systemd': ['Service Activity', 'Scheduled Job', 'System Boot'],
    'journald': ['Service Activity', 'Authentication Logs', 'Command Execution'],
    'iptables': ['Firewall Events', 'Network Traffic Flow'],
    'nftables': ['Firewall Events', 'Network Traffic Flow'],
    'AppArmor': ['Policy Violation', 'File Access', 'Process Activity'],
    'SELinux': ['Policy Violation', 'File Access', 'Process Activity'],
    'Falco': ['Runtime Alert', 'Process Activity', 'Container Activity'],
    'Docker': ['Container Activity', 'Process Activity'],
    'containerd': ['Container Activity', 'Process Activity'],
    'Podman': ['Container Activity', 'Process Activity'],
    'Kubernetes Audit': ['Kubernetes API', 'Container Activity', 'Cloud API'],
    'Nginx': ['Web Server Logs', 'HTTP Requests'],
    'Apache': ['Web Server Logs', 'HTTP Requests'],
    # macOS components
    'Apple Unified Log': ['Process Activity', 'Authentication Logs', 'TCC Activity', 'Application Activity'],
    'Apple Unified Logging': ['Process Activity', 'Authentication Logs', 'TCC Activity', 'Application Activity'],
    'OpenBSM': ['Process Creation', 'File Access', 'User Authentication', 'Privilege Changes'],
    'OpenBSM audit': ['Process Creation', 'File Access', 'User Authentication', 'Privilege Changes'],
    'launchd': ['Launch Agent', 'Launch Daemon', 'Service Activity'],
    'launchctl': ['Launch Agent', 'Launch Daemon', 'Service Activity'],
    'TCC': ['Privacy Permission Change', 'TCC Activity'],
    'Gatekeeper': ['Trust Decision', 'Application Execution'],
    'XProtect': ['Malware Detection', 'File Activity'],
    'Jamf': ['MDM Inventory', 'Process Activity', 'Policy Execution'],
    'Jamf Protect': ['Endpoint Alert', 'Process Activity', 'File Activity'],
    'Santa': ['Binary Authorization', 'Process Activity'],
    'FileVault': ['Disk Encryption', 'Authentication Logs'],
    # Network components
    'Cisco ASA': ['Firewall Events', 'Network Traffic Flow', 'VPN Session', 'ACL Decision'],
    'Cisco IOS': ['Network Device Logs', 'ACL Decision', 'Interface Status'],
    'Cisco Firepower': ['Firewall Events', 'IDS Alerts', 'Network Traffic Content'],
    'Firewall': ['Firewall Events', 'Network Traffic Flow'],
    'Proxy': ['HTTP Requests', 'Web Proxy Logs', 'TLS SNI'],
    'VPN': ['VPN Session', 'User Authentication', 'Remote Access'],
    'Wireless Controller': ['Wireless Association', 'Authentication Logs'],
    # Cloud components
    'AWS CloudTrail': ['Cloud API', 'IAM Activity', 'Object Storage Activity'],
    'AWS GuardDuty': ['Cloud Detection Alert', 'Network Traffic Flow'],
    'Azure Activity': ['Cloud API', 'IAM Activity', 'Resource Modification'],
    'Azure AD': ['User Account Authentication', 'IAM Activity', 'Conditional Access'],
    'GCP Audit Logs': ['Cloud API', 'IAM Activity', 'Resource Modification'],
    'Google Workspace': ['SaaS Audit Log', 'Email Activity', 'File Access'],
})

# Add aliases for payloads that commonly appear inside syslog body text rather
# than in the outer transport protocol field.
LOG_SOURCE_ALIASES.update({
    # Windows
    'microsoft-windows-security-auditing': 'Windows Security', 'channel=security': 'Windows Security',
    'eventid=4624': 'Windows Security', 'eventid=4625': 'Windows Security', 'eventid=4688': 'Windows Security',
    'microsoft-windows-sysmon': 'Sysmon', 'sysmon': 'Sysmon',
    'microsoft-windows-powershell': 'PowerShell', 'script block': 'PowerShell', 'eventid=4104': 'PowerShell',
    'task scheduler': 'Task Scheduler', 'taskscheduler': 'Task Scheduler', 'eventid=4698': 'Task Scheduler',
    'winrm': 'WinRM', 'wsman': 'WinRM', 'terminalservices': 'Terminal Services', 'remote desktop services': 'Terminal Services',
    'smbserver': 'SMB Server', 'admin$': 'SMB Server', 'eventid=5140': 'SMB Server',
    'dns server': 'DNS Server', 'microsoft-windows-dns-server': 'DNS Server',
    'dhcp server': 'DHCP Server', 'microsoft-windows-dhcp': 'DHCP Server',
    'iis': 'IIS', 'microsoft-iis': 'IIS', 'wmi-activity': 'WMI Activity', 'microsoft-windows-wmi': 'WMI Activity',
    'windows firewall': 'Windows Firewall', 'advanced security/firewall': 'Windows Firewall',
    # Linux
    'auth.log': 'auth.log', 'pam_unix': 'auth.log', 'sshd': 'sshd', 'failed password': 'sshd', 'accepted publickey': 'sshd',
    'sudo:': 'sudo', ' sudo ': 'sudo', 'auditd': 'auditd', 'type=execve': 'auditd', 'type=syscall': 'auditd',
    'journald': 'journald', 'systemd': 'systemd', 'cron': 'cron', 'crontab': 'cron', 'iptables': 'iptables',
    'nftables': 'nftables', 'apparmor': 'AppArmor', 'selinux': 'SELinux', 'falco': 'Falco', 'docker': 'Docker',
    'containerd': 'containerd', 'podman': 'Podman', 'kube-audit': 'Kubernetes Audit', 'kubernetes audit': 'Kubernetes Audit',
    'nginx': 'Nginx', 'apache2': 'Apache', 'httpd': 'Apache',
    # macOS
    'apple unified log': 'Apple Unified Log', 'apple unified logging': 'Apple Unified Logging', 'openbsm': 'OpenBSM',
    'launchd': 'launchd', 'launchctl': 'launchctl', ' tcc ': 'TCC', 'gatekeeper': 'Gatekeeper', 'xprotect': 'XProtect',
    'jamf protect': 'Jamf Protect', 'jamf': 'Jamf', 'santa': 'Santa', 'filevault': 'FileVault',
    # Network appliances / sensors
    'zeek': 'Zeek', 'conn.log': 'Zeek', 'dns.log': 'Zeek', 'suricata': 'Suricata', 'event_type":"alert': 'Suricata',
    'cisco asa': 'Cisco ASA', '%asa-': 'Cisco ASA', 'cisco ios': 'Cisco IOS', '%sec-6-ipaccesslogp': 'Cisco IOS',
    'firepower': 'Cisco Firepower', 'pan-os': 'Palo Alto PAN-OS', 'fortigate': 'Fortinet FortiGate',
    'netflow': 'NetFlow', 'ipfix': 'IPFIX', 'sflow': 'sFlow', 'vpn': 'VPN', 'proxy': 'Proxy',
    # Cloud
    'cloudtrail': 'AWS CloudTrail', 'guardduty': 'AWS GuardDuty', 'azureactivity': 'Azure Activity',
    'azure ad': 'Azure AD', 'gcp audit': 'GCP Audit Logs', 'google workspace': 'Google Workspace',
})

# Source-to-technique expansion. These detected log/source mappings drive theoretical coverage:
# they do not claim the activity occurred; they identify what the detected
# telemetry should be able to support theoretically.
ENHANCED_SOURCE_TECHNIQUES = {
    'Windows Security': ['T1078','T1110','T1021.001','T1021.002','T1021.006','T1053.005','T1543.003','T1547.001','T1136','T1098','T1070.001','T1562.002','T1558.003','T1003.001','T1087.002','T1069.002','T1484.001','T1531'],
    'Windows Event Log': ['T1078','T1110','T1059','T1053.005','T1543.003','T1070.001','T1562.002','T1087.002','T1046'],
    'Winlogbeat': ['T1078','T1110','T1059','T1059.001','T1053.005','T1543.003','T1003.001','T1070.001','T1562.002','T1021.001','T1021.006'],
    'Sysmon': ['T1059','T1059.001','T1059.003','T1047','T1106','T1053.005','T1543.003','T1547.001','T1574','T1055','T1003.001','T1112','T1036','T1027','T1070.004','T1046','T1049','T1057','T1082','T1083','T1021.002','T1021.006','T1071.001','T1071.004','T1105','T1567','T1041','T1486'],
    'PowerShell': ['T1059.001','T1021.006','T1105','T1071.001','T1027','T1053.005','T1562.001'],
    'PowerShell Operational Log': ['T1059.001','T1021.006','T1105','T1071.001','T1027'],
    'Defender': ['T1055','T1003.001','T1105','T1562.001','T1486','T1027','T1070.004'],
    'Task Scheduler': ['T1053.005','T1070.009','T1547','T1059'],
    'WinRM': ['T1021.006','T1059.001','T1047','T1569.002'],
    'Terminal Services': ['T1021.001','T1078','T1110'],
    'RDP / Terminal Services': ['T1021.001','T1078','T1110'],
    'SMB Server': ['T1021.002','T1135','T1039','T1570','T1003.003','T1486','T1070.004'],
    'DNS Server': ['T1071.004','T1568','T1046','T1018','T1590.002','T1596.001'],
    'DHCP Server': ['T1016','T1018','T1046'],
    'IIS': ['T1190','T1505.003','T1059','T1071.001','T1567','T1491'],
    'WMI': ['T1047','T1021.003','T1546.003','T1059'],
    'WMI Activity': ['T1047','T1021.003','T1546.003','T1059'],
    'Windows Firewall': ['T1046','T1049','T1562.004','T1499','T1498'],

    'auth.log': ['T1021.004','T1110','T1078','T1548.003','T1059.004','T1087.001'],
    'secure': ['T1021.004','T1110','T1078','T1548.003','T1059.004','T1087.001'],
    'sshd': ['T1021.004','T1110','T1078','T1570','T1552.004'],
    'sudo': ['T1548.003','T1059.004','T1068'],
    'auditd': ['T1059.004','T1059.006','T1003.007','T1003.008','T1552.001','T1552.003','T1552.004','T1548.001','T1548.003','T1053.003','T1543.002','T1070.002','T1070.003','T1070.004','T1083','T1082','T1057','T1005','T1560.001','T1489'],
    'systemd': ['T1543.002','T1053.006','T1059.004','T1489','T1070.002','T1562.001'],
    'systemd-journald': ['T1543.002','T1053.006','T1059.004','T1489','T1070.002','T1562.001','T1021.004','T1110'],
    'journald': ['T1543.002','T1053.006','T1059.004','T1489','T1070.002','T1562.001','T1021.004','T1110'],
    'cron': ['T1053.003','T1059.004','T1547'],
    'iptables': ['T1046','T1049','T1562.004','T1498','T1499'],
    'nftables': ['T1046','T1049','T1562.004','T1498','T1499'],
    'Falco': ['T1059.004','T1003.008','T1552.001','T1548.003','T1543.002','T1611','T1562.001'],
    'Docker': ['T1610','T1609','T1611','T1613','T1059.013'],
    'containerd': ['T1610','T1609','T1611','T1613','T1059.013'],
    'Kubernetes Audit': ['T1609','T1610','T1613','T1611','T1053.007','T1098.006'],
    'Nginx': ['T1190','T1505.003','T1071.001','T1567','T1491','T1499.003'],
    'Apache': ['T1190','T1505.003','T1071.001','T1567','T1491','T1499.003'],
    'osquery': ['T1059','T1059.004','T1082','T1083','T1057','T1005','T1547','T1543'],

    'Apple Unified Log': ['T1059.002','T1543.001','T1543.004','T1547.011','T1547.015','T1548.006','T1555.001','T1555.002','T1564.009','T1070.002','T1082','T1057'],
    'Apple Unified Logging': ['T1059.002','T1543.001','T1543.004','T1547.011','T1547.015','T1548.006','T1555.001','T1555.002','T1564.009','T1070.002','T1082','T1057'],
    'OpenBSM': ['T1059.004','T1548.003','T1005','T1083','T1057','T1070.002'],
    'OpenBSM audit': ['T1059.004','T1548.003','T1005','T1083','T1057','T1070.002'],
    'launchd': ['T1543.001','T1543.004','T1547.011'],
    'launchctl': ['T1543.001','T1543.004','T1547.011'],
    'TCC': ['T1548.006'],
    'Gatekeeper': ['T1553.001','T1553.005'],
    'XProtect': ['T1105','T1027','T1055'],
    'Jamf': ['T1059','T1082','T1543','T1547'],
    'Jamf Protect': ['T1059','T1082','T1543','T1547','T1003'],
    'Santa': ['T1059','T1218','T1553.002'],

    'Zeek': ['T1595','T1595.001','T1595.002','T1595.003','T1590.002','T1596.001','T1189','T1190','T1133','T1566.002','T1046','T1018','T1049','T1135','T1021.001','T1021.002','T1021.004','T1570','T1071.001','T1071.004','T1568','T1090','T1571','T1572','T1041','T1567','T1030','T1498','T1499'],
    'Suricata': ['T1595','T1595.001','T1595.002','T1190','T1566.002','T1046','T1071.001','T1071.004','T1568','T1571','T1095','T1041','T1567','T1498','T1499'],
    'Packetbeat': ['T1595','T1590.002','T1046','T1018','T1049','T1021.002','T1021.004','T1071.001','T1071.004','T1041','T1567'],
    'Cisco ASA': ['T1595','T1590.005','T1046','T1018','T1049','T1133','T1021.001','T1021.004','T1071.001','T1071.004','T1090','T1571','T1041','T1567','T1498','T1499','T1562.004'],
    'Cisco IOS': ['T1595','T1590.004','T1590.005','T1046','T1016','T1018','T1049','T1071.001','T1090','T1498','T1499'],
    'Cisco Firepower': ['T1595','T1046','T1190','T1071.001','T1071.004','T1041','T1567','T1498','T1499'],
    'NetFlow': ['T1595','T1046','T1018','T1049','T1071.001','T1090','T1571','T1041','T1567','T1030','T1020','T1498'],
    'IPFIX': ['T1595','T1046','T1018','T1049','T1071.001','T1090','T1041','T1567','T1030'],
    'sFlow': ['T1046','T1018','T1049','T1041','T1567','T1498'],
    'Syslog': ['T1046','T1110','T1021.004','T1053.003','T1543.002','T1070.002','T1016'],
    'Syslog TLS': ['T1046','T1110','T1021.004','T1053.003','T1543.002','T1070.002'],
    'Proxy': ['T1189','T1566.002','T1071.001','T1090','T1090.004','T1567','T1041'],
    'VPN': ['T1133','T1021','T1078','T1110','T1550'],

    'AWS CloudTrail': ['T1078.004','T1098.001','T1098.003','T1537','T1567.002','T1578','T1562.008','T1531'],
    'Azure Activity': ['T1078.004','T1098.001','T1098.003','T1537','T1567.002','T1578','T1562.008','T1531'],
    'Azure AD': ['T1078.004','T1098.003','T1110','T1556.006','T1550.001','T1531'],
    'GCP Audit Logs': ['T1078.004','T1098.001','T1098.003','T1537','T1567.002','T1578','T1562.008'],
}

# Data-component-to-technique fallback gives components weight even if a new log
# source is detected before it has a bespoke mapping above.
COMPONENT_TECHNIQUES = {
    'Process Creation': ['T1059','T1059.001','T1059.003','T1059.004','T1059.006','T1106','T1057'],
    'Command Execution': ['T1059','T1059.001','T1059.003','T1059.004','T1059.006'],
    'PowerShell Script Block': ['T1059.001','T1027','T1105'],
    'User Account Authentication': ['T1078','T1110','T1550'],
    'Logon Session': ['T1078','T1021.001','T1021.006'],
    'SSH Session': ['T1021.004','T1078','T1110'],
    'Scheduled Job': ['T1053','T1053.003','T1053.005','T1053.006'],
    'Service Activity': ['T1543','T1543.002','T1543.003','T1489'],
    'Registry Key Modification': ['T1112','T1547.001','T1546'],
    'Network Traffic Flow': ['T1046','T1018','T1049','T1071.001','T1041','T1567','T1498'],
    'Network Traffic Content': ['T1071.001','T1071.004','T1568','T1567','T1041'],
    'DNS': ['T1071.004','T1568','T1590.002','T1596.001'],
    'DNS Queries': ['T1071.004','T1568','T1590.002','T1596.001'],
    'HTTP': ['T1071.001','T1190','T1189','T1567'],
    'HTTP Requests': ['T1071.001','T1190','T1189','T1567'],
    'TLS': ['T1071.001','T1573','T1567'],
    'SMB': ['T1021.002','T1135','T1039','T1570'],
    'SMB Session': ['T1021.002','T1135','T1039','T1570'],
    'IDS Alerts': ['T1046','T1071.001','T1071.004','T1190','T1041'],
    'Firewall Events': ['T1046','T1049','T1562.004','T1498','T1499'],
    'Cloud API': ['T1078.004','T1098.003','T1578','T1562.008'],
    'IAM Activity': ['T1078.004','T1098','T1556','T1531'],
    'Container Activity': ['T1609','T1610','T1611','T1613','T1059.013'],
}


def _enhanced_source_hits_from_result(result):
    """Return canonical log sources detected from transport, payload, and normalized events."""
    sources = set()
    result = result or {}

    def add_from_text(text):
        if text:
            sources.update(_canonical_log_sources(str(text)))

    # Existing log source inventory, including summary/evidence strings.
    for item in result.get('log_sources', []) or []:
        for key in ('protocol','evidence','summary','technology','log_source','source_type','collector','host'):
            add_from_text(item.get(key, ''))
        if str(item.get('protocol','')).lower() == 'syslog':
            sources.add('Syslog')
        if int(item.get('port') or 0) in (514, 6514):
            sources.add('Syslog')

    # Host protocol hints.
    for host in result.get('hosts', []) or []:
        protos = host.get('protocols', [])
        if not isinstance(protos, list):
            protos = [str(protos)]
        add_from_text(' '.join(protos))

    # Normalized event summary and event body. This is the critical path for
    # forwarded Windows/Linux/macOS/network logs encapsulated in syslog/514.
    summary = result.get('normalized_event_summary') or {}
    for src in (summary.get('by_log_source') or {}).keys():
        sources.add(src)
        add_from_text(src)
    for platform in (summary.get('by_platform') or {}).keys():
        add_from_text(platform)
    for ev in result.get('normalized_events', []) or []:
        src = ev.get('log_source')
        if src:
            sources.add(src)
            add_from_text(src)
        plat = (ev.get('platform') or '').lower()
        if plat == 'windows':
            sources.add('Windows Event Log')
        elif plat == 'linux':
            sources.add('Syslog')
        elif plat == 'macos':
            sources.add('Apple Unified Log')
        add_from_text(ev.get('event_type',''))
        add_from_text(ev.get('raw',''))
        add_from_text((ev.get('evidence') or {}).get('packet_summary',''))

    # Stored techniques/evidence may include source names from rule or parser output.
    for tech in result.get('techniques', []) or []:
        add_from_text(tech.get('source',''))
        for e in tech.get('evidence', []) or []:
            add_from_text(e)

    # Normalize equivalent names.
    equivalences = {
        'PowerShell': 'PowerShell Operational Log',
        'Apple Unified Logging': 'Apple Unified Log',
        'OpenBSM audit': 'OpenBSM',
        'journald': 'systemd-journald',
        'systemd': 'systemd-journald',
    }
    for a, b in list(equivalences.items()):
        if a in sources:
            sources.add(b)
    return sorted(s for s in sources if s)


def detected_data_sources(result):
    return _enhanced_source_hits_from_result(result)


def _source_technique_expansion(source):
    out = set()
    for tid in ENHANCED_SOURCE_TECHNIQUES.get(source, []) or []:
        if tid in VALID_TECHNIQUES:
            out.add(tid)
    for comp in SOURCE_COMPONENTS.get(source, []) or []:
        for tid in COMPONENT_TECHNIQUES.get(comp, []) or []:
            if tid in VALID_TECHNIQUES:
                out.add(tid)
    # Preserve original hand-tuned mapping if present.
    for tid, _tactic, _score, _reason in DATA_SOURCE_COVERAGE.get(source, []) or []:
        if tid in VALID_TECHNIQUES:
            out.add(tid)
    return sorted(out)


def build_data_source_coverage(result):
    """Build theoretical technique coverage from detected OS/log types.

    This replaces the old transport-only behavior. A syslog packet containing
    Sysmon, Windows Security, auditd, Apple Unified Log, Zeek, Suricata, or
    Cisco messages now expands into data components and ATT&CK techniques.
    """
    coverage = {}
    sources = detected_data_sources(result)
    for source in sources:
        # Original mapping with its specific scores/rationales.
        for tid, tactic, score, rationale in DATA_SOURCE_COVERAGE.get(source, []) or []:
            if tid not in VALID_TECHNIQUES:
                continue
            cur = coverage.setdefault(tid, {
                'techniqueID': tid,
                'name': VALID_TECHNIQUES[tid]['name'],
                'tactic': VALID_TECHNIQUES[tid]['tactic'],
                'score': 0,
                'coverage': 'Theoretical',
                'data_sources': set(),
                'data_components': set(),
                'rationale': [],
            })
            cur['score'] = max(cur['score'], score)
            cur['data_sources'].add(source)
            cur['rationale'].append(rationale)
            for comp in SOURCE_COMPONENTS.get(source, []) or []:
                cur['data_components'].add(comp)

        # Enhanced source/component expansion.
        for tid in _source_technique_expansion(source):
            meta = VALID_TECHNIQUES[tid]
            cat = SOURCE_CATEGORY.get(source, 'Telemetry')
            # Score by specificity: named source > generic syslog > forwarding.
            base_score = 78
            if source in ('Syslog', 'Syslog TLS', 'Fluent Bit', 'Fluentd', 'Vector', 'OpenTelemetry Collector'):
                base_score = 58
            elif cat in ('Windows', 'Linux', 'macOS'):
                base_score = 76
            elif cat == 'Network':
                base_score = 72
            elif cat == 'Cloud':
                base_score = 74
            cur = coverage.setdefault(tid, {
                'techniqueID': tid,
                'name': meta.get('name', tid),
                'tactic': meta.get('tactic', ''),
                'score': 0,
                'coverage': 'Theoretical',
                'data_sources': set(),
                'data_components': set(),
                'rationale': [],
            })
            cur['score'] = max(cur['score'], base_score)
            cur['data_sources'].add(source)
            for comp in SOURCE_COMPONENTS.get(source, []) or []:
                cur['data_components'].add(comp)
            cur['rationale'].append(f"{source} telemetry was detected and maps to ATT&CK data components supporting {meta.get('name', tid)}.")

    out = []
    for item in coverage.values():
        item['data_sources'] = sorted(item['data_sources'])
        item['data_components'] = sorted(item['data_components'])
        item['rationale'] = item['rationale'][:8]
        out.append(item)
    return sorted(out, key=lambda x: (-x['score'], x['tactic'], x['techniqueID']))


def theoretical_coverage_diagnostics(result):
    result = result or {}
    detected_sources = detected_data_sources(result)
    scope = _detected_coverage_scope(result, detected_sources)
    component_map = {}
    source_rows = []
    for source in detected_sources:
        comps = SOURCE_COMPONENTS.get(source, []) or []
        tids = _source_technique_expansion(source)
        source_rows.append({
            'source': source,
            'category': SOURCE_CATEGORY.get(source, 'Other'),
            'components': comps,
            'technique_count': len(tids),
            'sample_techniques': tids[:12],
        })
        for comp in comps:
            component_map.setdefault(comp, set()).add(source)
    data_coverage = build_data_source_coverage(result)
    applicable_ids = {
        tid for tid, meta in VALID_TECHNIQUES.items()
        if _technique_in_detected_scope(tid, meta, scope)
    }
    theoretical_ids = {x.get('techniqueID') for x in data_coverage if x.get('techniqueID') in applicable_ids}
    unmapped_sources = [r['source'] for r in source_rows if r['technique_count'] == 0]
    return {
        'detected_os_scope': scope,
        'detected_log_sources': detected_sources,
        'telemetry_capabilities': sorted(source_rows, key=lambda r: (r.get('inferred', False), r['category'], r['source'])),
        'product_inferred_capability_count': len([r for r in source_rows if r.get('basis') in ('detected product', 'product-inferred source')]),
        'os_inferred_capability_count': len([r for r in source_rows if r.get('basis') in ('os-baseline', 'os-inferred source')]),
        'calibration_note': 'Theoretical coverage is source-only: directly detected log sources are mapped through the selected ATT&CK STIX bundle. OS baselines and product assumptions do not contribute to theoretical coverage.',
        'source_rows': sorted(source_rows, key=lambda r: (r['category'], r['source'])),
        'components': [{'component': c, 'sources': sorted(s)} for c, s in sorted(component_map.items())],
        'applicable_technique_count': len(applicable_ids),
        'theoretical_technique_count': len(theoretical_ids),
        'unmapped_sources': unmapped_sources,
        'pipeline': [
            'Detected OS/log sources from normalized events, syslog/514 payloads, Beats-like payloads, and log-source inventory.',
            'Expanded sources into ATT&CK data components.',
            'Expanded components and source-specific mappings into ATT&CK techniques.',
            'Wrote theoretical technique IDs into the unified enterprise coverage model.',
        ],
    }


_previous_enterprise_coverage_assessment_for_diag = enterprise_coverage_assessment

def enterprise_coverage_assessment(result, rules=None):
    ent = _previous_enterprise_coverage_assessment_for_diag(result, rules)
    diag = theoretical_coverage_diagnostics(result)
    ent['theoretical_diagnostics'] = diag
    # Keep inventory/components synchronized with the enhanced detector.
    grouped = {}
    for source in diag.get('detected_log_sources', []) or []:
        grouped.setdefault(SOURCE_CATEGORY.get(source, 'Other'), []).append(source)
    for cat in sorted(set(list(grouped) + ['Windows','Linux','macOS','Network','Cloud','SIEM / Forwarding'])):
        ent.setdefault('telemetry_inventory', {})[cat] = sorted(grouped.get(cat, []))
    ent['data_components'] = diag.get('components', [])
    ent['detected_sources'] = diag.get('detected_log_sources', [])
    ent['coverage_scope'] = diag.get('detected_os_scope', ent.get('coverage_scope', []))
    return ent


# ---------------------------------------------------------------------------
# v2 telemetry expansion fix: canonical log source -> data components ->
# ATT&CK data sources -> supported techniques -> unified coverage model.
# This final override is intentionally appended so it supersedes earlier partial
# mappings while preserving every public function name used elsewhere.

# Canonical source names requested for platform-specific telemetry detection.
ENTERPRISE_LOG_SOURCE_CATEGORIES = {
    # Windows
    'Windows Security': 'Windows', 'Windows System': 'Windows', 'Windows Application': 'Windows',
    'Sysmon': 'Windows', 'PowerShell Operational': 'Windows', 'Defender': 'Windows',
    'Defender for Endpoint': 'Windows', 'WinRM': 'Windows', 'WMI': 'Windows', 'SMB': 'Windows',
    'Windows DNS': 'Windows', 'Windows DHCP': 'Windows', 'IIS': 'Windows', 'Task Scheduler': 'Windows',
    'Windows Firewall': 'Windows', 'AppLocker': 'Windows', 'Windows Event Forwarding': 'Windows',
    'RDP': 'Windows', 'Active Directory': 'Windows', 'Certificate Services': 'Windows',
    'Windows Event Log': 'Windows', 'Winlogbeat': 'Windows',
    # Linux
    'auditd': 'Linux', 'auth.log': 'Linux', 'secure': 'Linux', 'sudo': 'Linux', 'sshd': 'Linux',
    'cron': 'Linux', 'journald': 'Linux', 'systemd': 'Linux', 'kernel': 'Linux', 'rsyslog': 'Linux',
    'syslog-ng': 'Linux', 'Apache': 'Linux', 'Nginx': 'Linux', 'Docker': 'Linux', 'containerd': 'Linux',
    'Podman': 'Linux', 'Kubernetes Audit': 'Linux', 'SELinux': 'Linux', 'AppArmor': 'Linux',
    'osquery': 'Linux', 'Falco': 'Linux', 'systemd-journald': 'Linux',
    # macOS
    'Apple Unified Logging': 'macOS', 'Apple Unified Log': 'macOS', 'OpenBSM': 'macOS',
    'launchd': 'macOS', 'launchctl': 'macOS', 'Gatekeeper': 'macOS', 'TCC': 'macOS', 'XProtect': 'macOS',
    'Jamf': 'macOS', 'Santa': 'macOS', 'Endpoint Security': 'macOS', 'FileVault': 'macOS',
    # Network
    'Zeek': 'Network', 'Suricata': 'Network', 'Packetbeat': 'Network', 'NetFlow': 'Network',
    'IPFIX': 'Network', 'Cisco ASA': 'Network', 'Cisco IOS': 'Network', 'Cisco NX-OS': 'Network',
    'Cisco Firepower': 'Network', 'Palo Alto': 'Network', 'Fortinet': 'Network', 'Check Point': 'Network',
    'SonicWall': 'Network', 'pfSense': 'Network', 'OPNsense': 'Network', 'Squid': 'Network',
    'HAProxy': 'Network', 'F5': 'Network', 'DNS': 'Network', 'DHCP': 'Network', 'VPN': 'Network',
    'Wireless Controller': 'Network', 'Syslog': 'Network', 'Syslog TLS': 'Network', 'Proxy': 'Network',
}
SOURCE_CATEGORY.update(ENTERPRISE_LOG_SOURCE_CATEGORIES)

# Normalize older internal names to requested canonical display names.
_CANONICAL_EQUIV = {
    'PowerShell': 'PowerShell Operational',
    'PowerShell Operational Log': 'PowerShell Operational',
    'Windows Event Log': 'Windows Security',
    'SMB Server': 'SMB',
    'DNS Server': 'Windows DNS',
    'DHCP Server': 'Windows DHCP',
    'WMI Activity': 'WMI',
    'Terminal Services': 'RDP',
    'RDP / Terminal Services': 'RDP',
    'OpenBSM audit': 'OpenBSM',
    'Palo Alto PAN-OS': 'Palo Alto',
    'Fortinet FortiGate': 'Fortinet',
}

LOG_SOURCE_ALIASES.update({
    # Windows Security/System/Application/Sysmon/PowerShell/Defender/etc.
    'windows security': 'Windows Security', 'security-auditing': 'Windows Security', 'microsoft-windows-security-auditing': 'Windows Security',
    'event id 4624': 'Windows Security', 'eventid 4624': 'Windows Security', 'eventid=4624': 'Windows Security',
    'event id 4625': 'Windows Security', 'eventid 4625': 'Windows Security', 'eventid=4625': 'Windows Security',
    'event id 4688': 'Windows Security', 'eventid 4688': 'Windows Security', 'eventid=4688': 'Windows Security',
    'windows system': 'Windows System', 'system.evtx': 'Windows System', 'service control manager': 'Windows System',
    'windows application': 'Windows Application', 'application.evtx': 'Windows Application',
    'sysmon': 'Sysmon', 'microsoft-windows-sysmon': 'Sysmon',
    'powershell operational': 'PowerShell Operational', 'microsoft-windows-powershell': 'PowerShell Operational', 'scriptblock': 'PowerShell Operational', 'script block': 'PowerShell Operational', 'eventid=4104': 'PowerShell Operational',
    'defender for endpoint': 'Defender for Endpoint', 'microsoft defender for endpoint': 'Defender for Endpoint', 'mde': 'Defender for Endpoint',
    'windows defender': 'Defender', 'defender': 'Defender',
    'winrm': 'WinRM', 'wsman': 'WinRM', 'wmi-activity': 'WMI', 'microsoft-windows-wmi': 'WMI', ' wmi ': 'WMI',
    'smbserver': 'SMB', 'eventid=5140': 'SMB', 'admin$': 'SMB', 'cifs': 'SMB',
    'microsoft-windows-dns-server': 'Windows DNS', 'windows dns': 'Windows DNS', 'dns server': 'Windows DNS',
    'microsoft-windows-dhcp': 'Windows DHCP', 'windows dhcp': 'Windows DHCP', 'dhcp server': 'Windows DHCP',
    'iis': 'IIS', 'microsoft-iis': 'IIS', 'w3svc': 'IIS',
    'task scheduler': 'Task Scheduler', 'taskscheduler': 'Task Scheduler', 'eventid=4698': 'Task Scheduler',
    'windows firewall': 'Windows Firewall', 'mpssvc': 'Windows Firewall', 'advanced security/firewall': 'Windows Firewall',
    'applocker': 'AppLocker', 'wef': 'Windows Event Forwarding', 'windows event forwarding': 'Windows Event Forwarding',
    'rdp': 'RDP', 'terminalservices': 'RDP', 'remote desktop': 'RDP',
    'active directory': 'Active Directory', 'ntds': 'Active Directory', 'domain controller': 'Active Directory',
    'certificate services': 'Certificate Services', 'certsrv': 'Certificate Services', 'adcs': 'Certificate Services',
    # Linux
    'auditd': 'auditd', 'type=execve': 'auditd', 'type=syscall': 'auditd', 'auth.log': 'auth.log',
    '/var/log/secure': 'secure', ' secure ': 'secure', 'sudo:': 'sudo', ' sudo ': 'sudo',
    'sshd': 'sshd', 'failed password': 'sshd', 'accepted password': 'sshd', 'accepted publickey': 'sshd',
    'cron': 'cron', 'crond': 'cron', 'journald': 'journald', 'journalctl': 'journald',
    'systemd': 'systemd', 'kernel:': 'kernel', 'rsyslog': 'rsyslog', 'syslog-ng': 'syslog-ng',
    'apache': 'Apache', 'apache2': 'Apache', 'httpd': 'Apache', 'nginx': 'Nginx',
    'docker': 'Docker', 'containerd': 'containerd', 'podman': 'Podman', 'kube-audit': 'Kubernetes Audit', 'kubernetes audit': 'Kubernetes Audit',
    'selinux': 'SELinux', 'apparmor': 'AppArmor', 'osquery': 'osquery', 'falco': 'Falco',
    # macOS
    'apple unified logging': 'Apple Unified Logging', 'apple unified log': 'Apple Unified Logging', 'oslog': 'Apple Unified Logging',
    'openbsm': 'OpenBSM', 'launchd': 'launchd', 'launchctl': 'launchctl', 'gatekeeper': 'Gatekeeper',
    ' tcc ': 'TCC', 'xprotect': 'XProtect', 'jamf': 'Jamf', 'santa': 'Santa', 'endpoint security': 'Endpoint Security', 'filevault': 'FileVault',
    # Network
    'zeek': 'Zeek', 'conn.log': 'Zeek', 'dns.log': 'Zeek', 'suricata': 'Suricata', 'eve.json': 'Suricata',
    'packetbeat': 'Packetbeat', 'netflow': 'NetFlow', 'ipfix': 'IPFIX', 'cisco asa': 'Cisco ASA', '%asa-': 'Cisco ASA',
    'cisco ios': 'Cisco IOS', '%sys-': 'Cisco IOS', '%sec-6-ipaccesslogp': 'Cisco IOS', 'nx-os': 'Cisco NX-OS', 'nexus': 'Cisco NX-OS',
    'firepower': 'Cisco Firepower', 'palo alto': 'Palo Alto', 'pan-os': 'Palo Alto', 'fortigate': 'Fortinet', 'fortinet': 'Fortinet',
    'check point': 'Check Point', 'sonicwall': 'SonicWall', 'pfsense': 'pfSense', 'opnsense': 'OPNsense',
    'squid': 'Squid', 'haproxy': 'HAProxy', ' f5 ': 'F5', 'big-ip': 'F5', 'wireless controller': 'Wireless Controller',
    ' vpn ': 'VPN', 'openvpn': 'VPN', 'anyconnect': 'VPN', 'globalprotect': 'VPN',
})

SOURCE_COMPONENTS.update({
    'Windows Security': ['Log Source: Windows Security', 'User Account Authentication', 'Logon Session', 'Process Creation', 'Scheduled Job', 'Service Creation', 'Registry Key Modification', 'Active Directory Object Modification'],
    'Windows System': ['Log Source: Windows System', 'Service Creation', 'Service Activity', 'Driver Load', 'System Service', 'Scheduled Job'],
    'Windows Application': ['Log Source: Windows Application', 'Application Log Content', 'Process Activity', 'Web Server Access'],
    'Sysmon': ['Log Source: Sysmon', 'Process Creation', 'Process Metadata', 'Network Connection Creation', 'File Creation', 'File Modification', 'Registry Key Modification', 'WMI Activity', 'Driver Load', 'Image Load', 'DNS Query'],
    'PowerShell Operational': ['Log Source: PowerShell Operational', 'PowerShell Script Block', 'Command Execution', 'Process Creation', 'Module Load'],
    'Defender': ['Log Source: Defender', 'Malware Detection', 'Process Activity', 'File Activity', 'Network Activity', 'Sensor Health'],
    'Defender for Endpoint': ['Log Source: Defender for Endpoint', 'Endpoint Detection Alert', 'Process Activity', 'File Activity', 'Network Activity', 'Registry Key Modification', 'Device Timeline'],
    'WinRM': ['Log Source: WinRM', 'Remote Service Session', 'Command Execution', 'PowerShell Remoting'],
    'WMI': ['Log Source: WMI', 'WMI Activity', 'Command Execution', 'Process Creation'],
    'SMB': ['Log Source: SMB', 'SMB Session', 'File Share Access', 'Network Share Discovery'],
    'Windows DNS': ['Log Source: Windows DNS', 'DNS Query', 'DNS Response'],
    'Windows DHCP': ['Log Source: Windows DHCP', 'DHCP Lease', 'Host Configuration'],
    'IIS': ['Log Source: IIS', 'HTTP Requests', 'Web Server Access', 'Web Script Execution'],
    'Task Scheduler': ['Log Source: Task Scheduler', 'Scheduled Job', 'Process Creation'],
    'Windows Firewall': ['Log Source: Windows Firewall', 'Firewall Events', 'Network Traffic Flow', 'Network Connection Creation'],
    'AppLocker': ['Log Source: AppLocker', 'Application Control Decision', 'Process Creation'],
    'Windows Event Forwarding': ['Log Source: Windows Event Forwarding', 'Forwarded Event', 'Windows Event Logs', 'User Account Authentication'],
    'RDP': ['Log Source: RDP', 'Remote Desktop Session', 'User Account Authentication', 'Logon Session'],
    'Active Directory': ['Log Source: Active Directory', 'Active Directory Object Modification', 'Directory Service Access', 'Kerberos Authentication'],
    'Certificate Services': ['Log Source: Certificate Services', 'Certificate Enrollment', 'PKI Activity'],
    'auth.log': ['Log Source: auth.log', 'User Account Authentication', 'SSH Session', 'Privilege Escalation'],
    'secure': ['Log Source: secure', 'User Account Authentication', 'SSH Session', 'Privilege Escalation'],
    'sudo': ['Log Source: sudo', 'Privilege Escalation', 'Command Execution'],
    'sshd': ['Log Source: sshd', 'SSH Session', 'User Account Authentication'],
    'cron': ['Log Source: cron', 'Scheduled Job', 'Command Execution'],
    'journald': ['Log Source: journald', 'Service Activity', 'User Account Authentication', 'System Activity'],
    'systemd': ['Log Source: systemd', 'Service Activity', 'System Service', 'System Boot'],
    'kernel': ['Log Source: kernel', 'Kernel Events', 'Driver Load', 'Network Interface'],
    'Apache': ['Log Source: Apache', 'HTTP Requests', 'Web Server Access'],
    'Nginx': ['Log Source: Nginx', 'HTTP Requests', 'Web Server Access'],
    'Docker': ['Log Source: Docker', 'Container Activity', 'Container Start', 'Container Exec'],
    'containerd': ['Log Source: containerd', 'Container Activity', 'Container Start', 'Container Exec'],
    'Podman': ['Log Source: Podman', 'Container Activity', 'Container Start', 'Container Exec'],
    'Kubernetes Audit': ['Log Source: Kubernetes Audit', 'Kubernetes API Request', 'Container Activity'],
    'SELinux': ['Log Source: SELinux', 'Access Control Decision', 'Process Activity'],
    'AppArmor': ['Log Source: AppArmor', 'Access Control Decision', 'Process Activity'],
    'Falco': ['Log Source: Falco', 'Runtime Detection Alert', 'Container Activity', 'Process Activity'],
    'Apple Unified Logging': ['Log Source: Apple Unified Logging', 'Process Activity', 'Authentication Logs', 'System Activity', 'Application Activity'],
    'OpenBSM': ['Log Source: OpenBSM', 'Process Creation', 'File Access', 'User Account Authentication', 'Privilege Escalation'],
    'Endpoint Security': ['Log Source: Endpoint Security', 'Process Activity', 'File Activity', 'Network Activity'],
    'Zeek': ['Log Source: Zeek', 'Network Traffic Flow', 'DNS Query', 'HTTP Requests', 'TLS SNI', 'SMB Session', 'SSH Session', 'File Transfer'],
    'Suricata': ['Log Source: Suricata', 'IDS Alerts', 'Network Traffic Content', 'Network Traffic Flow', 'DNS Query', 'HTTP Requests', 'TLS SNI'],
    'Cisco ASA': ['Log Source: Cisco ASA', 'Firewall Events', 'Network Traffic Flow', 'VPN Session', 'ACL Decision'],
    'Cisco IOS': ['Log Source: Cisco IOS', 'Network Device Logs', 'ACL Decision', 'Interface Status'],
    'Cisco NX-OS': ['Log Source: Cisco NX-OS', 'Network Device Logs', 'ACL Decision', 'Interface Status'],
    'Palo Alto': ['Log Source: Palo Alto', 'Firewall Events', 'Network Traffic Flow', 'Threat Alert', 'VPN Session'],
    'Fortinet': ['Log Source: Fortinet', 'Firewall Events', 'Network Traffic Flow', 'Threat Alert', 'VPN Session'],
    'Check Point': ['Log Source: Check Point', 'Firewall Events', 'Network Traffic Flow', 'Threat Alert', 'VPN Session'],
    'SonicWall': ['Log Source: SonicWall', 'Firewall Events', 'Network Traffic Flow', 'VPN Session'],
    'pfSense': ['Log Source: pfSense', 'Firewall Events', 'Network Traffic Flow', 'VPN Session'],
    'OPNsense': ['Log Source: OPNsense', 'Firewall Events', 'Network Traffic Flow', 'VPN Session'],
    'Squid': ['Log Source: Squid', 'HTTP Requests', 'Web Proxy Logs'],
    'HAProxy': ['Log Source: HAProxy', 'HTTP Requests', 'Network Traffic Flow'],
    'F5': ['Log Source: F5', 'HTTP Requests', 'Network Traffic Flow', 'Load Balancer Logs'],
    'DNS': ['Log Source: DNS', 'DNS Query', 'DNS Response'],
    'DHCP': ['Log Source: DHCP', 'DHCP Lease', 'Host Configuration'],
    'VPN': ['Log Source: VPN', 'VPN Session', 'User Account Authentication', 'Remote Access'],
    'Wireless Controller': ['Log Source: Wireless Controller', 'Wireless Association', 'User Account Authentication'],
})

# Component families are capability classes; they intentionally expand to broad
# ATT&CK coverage but still stay environment-scoped by build_enterprise...().
_COMPONENT_TACTIC_HINTS = {
    'Process': {'execution','persistence','privilege-escalation','defense-evasion','discovery','collection'},
    'Command': {'execution','defense-evasion','discovery','collection'},
    'PowerShell': {'execution','defense-evasion','lateral-movement','command-and-control'},
    'Authentication': {'initial-access','credential-access','lateral-movement','persistence','privilege-escalation'},
    'Logon': {'initial-access','credential-access','lateral-movement'},
    'Service': {'execution','persistence','privilege-escalation','defense-evasion','impact'},
    'Scheduled': {'execution','persistence','privilege-escalation'},
    'Registry': {'persistence','privilege-escalation','defense-evasion','credential-access'},
    'WMI': {'execution','persistence','lateral-movement','defense-evasion'},
    'File': {'collection','defense-evasion','persistence','credential-access','impact','exfiltration'},
    'DNS': {'reconnaissance','command-and-control','discovery'},
    'HTTP': {'initial-access','command-and-control','exfiltration','impact'},
    'TLS': {'command-and-control','exfiltration'},
    'SMB': {'lateral-movement','discovery','collection','exfiltration'},
    'SSH': {'lateral-movement','credential-access','initial-access'},
    'Firewall': {'reconnaissance','discovery','command-and-control','exfiltration','impact','defense-evasion'},
    'Network': {'reconnaissance','initial-access','discovery','lateral-movement','command-and-control','exfiltration','impact'},
    'IDS': {'reconnaissance','initial-access','command-and-control','exfiltration','impact'},
    'VPN': {'initial-access','lateral-movement','credential-access'},
    'Web': {'initial-access','execution','persistence','command-and-control','exfiltration','impact'},
    'Container': {'execution','persistence','privilege-escalation','defense-evasion','discovery'},
    'Kubernetes': {'execution','persistence','privilege-escalation','defense-evasion','discovery'},
    'Cloud': {'initial-access','persistence','privilege-escalation','defense-evasion','credential-access','discovery','exfiltration','impact'},
}

_SOURCE_CAPABILITY_TACTICS = {
    'Windows Security': set(TACTIC_DISPLAY_ORDER), 'Sysmon': set(TACTIC_DISPLAY_ORDER),
    'Defender for Endpoint': set(TACTIC_DISPLAY_ORDER), 'Defender': set(TACTIC_DISPLAY_ORDER),
    'Windows Event Forwarding': set(TACTIC_DISPLAY_ORDER), 'PowerShell Operational': {'execution','defense-evasion','lateral-movement','command-and-control','persistence','discovery'},
    'Zeek': {'reconnaissance','initial-access','discovery','lateral-movement','command-and-control','exfiltration','impact'},
    'Suricata': {'reconnaissance','initial-access','discovery','command-and-control','exfiltration','impact'},
    'Cisco ASA': {'reconnaissance','initial-access','discovery','lateral-movement','command-and-control','exfiltration','impact','defense-evasion'},
    'Cisco IOS': {'reconnaissance','discovery','command-and-control','exfiltration','impact'},
    'Cisco NX-OS': {'reconnaissance','discovery','command-and-control','exfiltration','impact'},
    'Cisco Firepower': {'reconnaissance','initial-access','discovery','command-and-control','exfiltration','impact'},
    'Palo Alto': {'reconnaissance','initial-access','discovery','command-and-control','exfiltration','impact','defense-evasion'},
    'Fortinet': {'reconnaissance','initial-access','discovery','command-and-control','exfiltration','impact','defense-evasion'},
    'Check Point': {'reconnaissance','initial-access','discovery','command-and-control','exfiltration','impact','defense-evasion'},
    'auditd': {'execution','persistence','privilege-escalation','defense-evasion','credential-access','discovery','collection','impact'},
    'osquery': {'execution','persistence','privilege-escalation','defense-evasion','credential-access','discovery','collection'},
    'Apple Unified Logging': {'execution','persistence','privilege-escalation','defense-evasion','credential-access','discovery','collection'},
    'OpenBSM': {'execution','persistence','privilege-escalation','defense-evasion','credential-access','discovery','collection'},
}


def _canon_source_name(name):
    if not name:
        return None
    return _CANONICAL_EQUIV.get(name, name)


def _canonical_log_sources(text):
    t = (text or '').lower()
    hits = set()
    for needle, canonical in LOG_SOURCE_ALIASES.items():
        if needle and needle in t:
            hits.add(_canon_source_name(canonical))
    return {h for h in hits if h}


def _canonical_log_source(text):
    hits = sorted(_canonical_log_sources(text))
    return hits[0] if hits else None


def _enhanced_source_hits_from_result(result):
    sources = set()
    result = result or {}

    def add(text):
        if text is not None:
            sources.update(_canonical_log_sources(str(text)))

    for item in result.get('log_sources', []) or []:
        for key in ('protocol','evidence','summary','technology','log_source','source_type','collector','host','parser','payload'):
            val = item.get(key, '')
            add(val)
            if key in ('technology','log_source','source_type') and val:
                sources.add(_canon_source_name(str(val)) or str(val))
        port = str(item.get('port') or '')
        proto = str(item.get('protocol') or '').lower()
        if proto == 'syslog' or port in ('514','6514'):
            sources.add('Syslog TLS' if port == '6514' else 'Syslog')

    for host in result.get('hosts', []) or []:
        protos = host.get('protocols', [])
        if not isinstance(protos, list):
            protos = [protos]
        add(' '.join(str(x) for x in protos))
        add(host.get('os',''))

    summary = result.get('normalized_event_summary') or {}
    for src in (summary.get('by_log_source') or {}).keys():
        sources.add(_canon_source_name(src) or src)
        add(src)
    for platform in (summary.get('by_platform') or {}).keys():
        add(platform)
    for ev in result.get('normalized_events', []) or []:
        src = ev.get('log_source')
        if src:
            sources.add(_canon_source_name(src) or src)
            add(src)
        plat = (ev.get('platform') or '').lower()
        if plat == 'windows': sources.add('Windows Security')
        if plat == 'linux': sources.add('Syslog')
        if plat == 'macos': sources.add('Apple Unified Logging')
        for key in ('event_type','raw','message','provider','channel'):
            add(ev.get(key,''))
        ev_evidence = ev.get('evidence') or {}
        if isinstance(ev_evidence, dict):
            add(' '.join(str(v) for v in ev_evidence.values()))

    for tech in result.get('techniques', []) or []:
        add(tech.get('source',''))
        for e in tech.get('evidence', []) or []:
            add(e)

    # Normalize and keep only sources with categories/components/mappings or known custom names.
    return sorted(_canon_source_name(s) or s for s in sources if s)


def detected_data_sources(result):
    return _enhanced_source_hits_from_result(result)


def _tactic_ids(tactics):
    tactics = set(tactics or [])
    return {tid for tid, meta in VALID_TECHNIQUES.items() if meta.get('tactic') in tactics}


def _component_technique_ids(component):
    out = set(COMPONENT_TECHNIQUES.get(component, []) or [])
    for needle, tactics in _COMPONENT_TACTIC_HINTS.items():
        if needle.lower() in str(component).lower():
            out.update(_tactic_ids(tactics))
    return {tid for tid in out if tid in VALID_TECHNIQUES}


def _source_technique_expansion(source):
    source = _canon_source_name(source) or source
    out = set()
    out.update(tid for tid in ENHANCED_SOURCE_TECHNIQUES.get(source, []) or [] if tid in VALID_TECHNIQUES)
    for tid, _tactic, _score, _reason in DATA_SOURCE_COVERAGE.get(source, []) or []:
        if tid in VALID_TECHNIQUES:
            out.add(tid)
    for comp in SOURCE_COMPONENTS.get(source, []) or []:
        out.update(_component_technique_ids(comp))
    if source in _SOURCE_CAPABILITY_TACTICS:
        out.update(_tactic_ids(_SOURCE_CAPABILITY_TACTICS[source]))
    # Preserve the explicit requirement that high-fidelity Windows endpoint logs
    # expand into broad ATT&CK coverage. These are still theoretical only and
    # later constrained to the detected enterprise environment.
    if SOURCE_CATEGORY.get(source) == 'Windows' and source in {'Windows Security','Sysmon','Defender','Defender for Endpoint','Windows Event Forwarding'}:
        out.update(VALID_TECHNIQUES.keys())
    return sorted(out)


def _attck_data_sources_for_source(source):
    ds = set()
    for comp in SOURCE_COMPONENTS.get(source, []) or []:
        clean = comp.replace('Log Source: ', '')
        if ':' in clean:
            ds.add(clean.split(':', 1)[0].strip())
        elif any(x in clean for x in ('Process','Command','PowerShell','WMI')):
            ds.add('Process')
        elif any(x in clean for x in ('Authentication','Logon','SSH','RDP','VPN')):
            ds.add('User Account')
        elif any(x in clean for x in ('Network','DNS','HTTP','TLS','SMB','Firewall','IDS')):
            ds.add('Network Traffic')
        elif any(x in clean for x in ('File','Registry')):
            ds.add(clean.split()[0])
        else:
            ds.add(clean)
    return sorted(ds)


def build_data_source_coverage(result):
    coverage = {}
    for source in detected_data_sources(result):
        source = _canon_source_name(source) or source
        category = SOURCE_CATEGORY.get(source, 'Other')
        components = set(SOURCE_COMPONENTS.get(source, []) or [])
        attck_data_sources = set(_attck_data_sources_for_source(source))
        for tid in _source_technique_expansion(source):
            meta = VALID_TECHNIQUES.get(tid)
            if not meta:
                continue
            score = 78
            if source in {'Sysmon','Defender for Endpoint','Windows Security','Zeek','Suricata'}:
                score = 88
            elif category in {'Windows','Linux','macOS'}:
                score = 76
            elif category == 'Network':
                score = 72
            if source in {'Syslog','Syslog TLS','rsyslog','syslog-ng'}:
                score = 58
            cur = coverage.setdefault(tid, {
                'techniqueID': tid,
                'name': meta.get('name', tid),
                'tactic': meta.get('tactic',''),
                'score': 0,
                'coverage': 'Theoretical',
                'data_sources': set(),
                'data_components': set(),
                'attack_data_sources': set(),
                'rationale': [],
            })
            cur['score'] = max(cur['score'], score)
            cur['data_sources'].add(source)
            cur['data_components'].update(components)
            cur['attack_data_sources'].update(attck_data_sources)
            cur['rationale'].append(f"{source} detected -> {len(components)} ATT&CK data components -> supports {meta.get('name', tid)} theoretically.")
    out = []
    for item in coverage.values():
        for key in ('data_sources','data_components','attack_data_sources'):
            item[key] = sorted(item[key])
        item['rationale'] = item['rationale'][:8]
        out.append(item)
    return sorted(out, key=lambda x: (-x['score'], x['tactic'], x['techniqueID']))


def _supporting_rules_by_tid(rules):
    out = {}
    for r in rules or []:
        if r.get('enabled') is False:
            continue
        for tid in r.get('attack', []) or r.get('techniques', []) or []:
            if tid in VALID_TECHNIQUES:
                out.setdefault(tid, []).append(r.get('name') or r.get('id') or 'Unnamed rule')
    return out


def build_enterprise_attack_coverage_model(result, rules=None):
    result = result or {}
    rules = rules or []
    data_source_items = result.get('data_source_coverage') or build_data_source_coverage(result)
    data_source_by_id = {x.get('techniqueID'): x for x in data_source_items if x.get('techniqueID') in VALID_TECHNIQUES}
    observed_raw = _attack_id_set_from_result(result)
    validated_raw, validated_details = _validated_ids_and_details(result)
    detected_sources = detected_data_sources(result)
    coverage_scope = _detected_coverage_scope(result, detected_sources)
    applicable_ids = {tid for tid, meta in VALID_TECHNIQUES.items() if _technique_in_detected_scope(tid, meta, coverage_scope) and not _is_external_visibility_tactic(meta.get('tactic',''))}
    external_visibility_ids = {tid for tid, meta in VALID_TECHNIQUES.items() if _is_external_visibility_tactic(meta.get('tactic',''))}
    theoretical_ids = {tid for tid, item in data_source_by_id.items() if _coverage_item_counts_as_theoretical(item)} & applicable_ids
    observed_ids = observed_raw & applicable_ids
    validated_ids = validated_raw & applicable_ids
    rule_names_by_tid = _supporting_rules_by_tid(rules)
    rule_techs = set(rule_names_by_tid)

    techniques = []
    tactic_totals = {t: 0 for t in TACTIC_DISPLAY_ORDER}
    tactic_observed = {t: 0 for t in TACTIC_DISPLAY_ORDER}
    tactic_theoretical = {t: 0 for t in TACTIC_DISPLAY_ORDER}
    tactic_validated = {t: 0 for t in TACTIC_DISPLAY_ORDER}
    tactic_strength_sum = {t: 0.0 for t in TACTIC_DISPLAY_ORDER}

    for tid, meta in sorted(VALID_TECHNIQUES.items()):
        tactic = meta.get('tactic','')
        external_visibility = _is_external_visibility_tactic(tactic)
        external_visibility_reason = _external_visibility_reason(tactic)
        applicable = (tid in applicable_ids) and not external_visibility
        ds = data_source_by_id.get(tid, {})
        score = float(ds.get('score', 0) or 0)
        obs = tid in observed_ids
        theo = tid in theoretical_ids
        val = tid in validated_ids
        detectable = applicable and (tid in rule_techs)
        if val and score < 90: score = 90.0
        elif obs and score < 70: score = 70.0
        if external_visibility:
            state, score = 'External Visibility', 0.0
        elif not applicable:
            state, score = 'Not Applicable', 0.0
        elif obs and theo:
            state = 'Observed + Theoretical'
        elif obs:
            state = 'Observed'
        elif val:
            state = 'Validated'
        elif theo and detectable:
            state = 'Theoretical + Detectable'
        elif theo:
            state = 'Theoretical'
        elif detectable:
            state = 'Detectable'
        else:
            state = 'Not Covered'
        if applicable:
            if tactic not in tactic_totals:
                tactic_totals[tactic] = tactic_observed[tactic] = tactic_theoretical[tactic] = tactic_validated[tactic] = 0
                tactic_strength_sum[tactic] = 0.0
            tactic_totals[tactic] += 1
            if obs: tactic_observed[tactic] += 1
            if theo:
                tactic_theoretical[tactic] += 1
                tactic_strength_sum[tactic] += score
            if val: tactic_validated[tactic] += 1
        evidence = []
        evidence.extend(ds.get('rationale', []) or [])
        evidence.extend((validated_details.get(tid, {}) or {}).get('evidence', []) or [])
        techniques.append({
            'techniqueID': tid, 'technique_id': tid, 'name': meta.get('name', tid), 'tactic': tactic,
            'applicable': applicable, 'observed': obs, 'theoretical': theo, 'detectable': detectable,
            'validated': val, 'validated_raw': tid in validated_raw, 'observed_raw': tid in observed_raw,
            'out_of_scope_validated_match': (tid in validated_raw) and not applicable,
            'out_of_scope_observed_match': (tid in observed_raw) and not applicable,
            'external_visibility': external_visibility, 'external_visibility_reason': external_visibility_reason,
            'not_applicable': (not applicable) and not external_visibility, 'state': state,
            'state_class': _coverage_state_class({'applicable': applicable, 'external_visibility': external_visibility, 'observed': obs, 'theoretical': theo, 'validated': val, 'rule': detectable, 'score': score}),
            'score': round(score, 1), 'confidence': round(score, 1), 'rule': detectable,
            'supporting_rules': sorted(rule_names_by_tid.get(tid, [])),
            'data_sources': sorted(ds.get('data_sources', []) or []),
            'data_components': sorted(ds.get('data_components', []) or []),
            'attack_data_sources': sorted(ds.get('attack_data_sources', []) or []),
            'evidence': evidence[:12], 'rationale': (ds.get('rationale', []) or [])[:8],
            'validated_rules': (validated_details.get(tid, {}) or {}).get('rules', []),
            'validated_evidence': (validated_details.get(tid, {}) or {}).get('evidence', []),
            'match_count': (validated_details.get(tid, {}) or {}).get('match_count', 0),
        })

    def rollup(kind):
        out = []
        for tac in TACTIC_DISPLAY_ORDER:
            total = tactic_totals.get(tac, 0)
            if kind == 'observed':
                covered, strength = tactic_observed.get(tac, 0), 100 if tactic_observed.get(tac, 0) else 0
            elif kind == 'validated':
                covered, strength = tactic_validated.get(tac, 0), 100 if tactic_validated.get(tac, 0) else 0
            else:
                covered = tactic_theoretical.get(tac, 0)
                strength = tactic_strength_sum.get(tac, 0.0) / covered if covered else 0
            pct = round((covered / total) * 100, 1) if total else 0
            score = pct if kind != 'theoretical' else (round((pct * 0.65) + (strength * 0.35), 1) if total else 0)
            out.append({'tactic': tac, 'name': _tactic_name(tac), 'covered': covered, 'total': total, 'not_applicable': len([x for x in techniques if x.get('tactic') == tac and not x.get('applicable') and not x.get('external_visibility')]), 'external_visibility': len([x for x in techniques if x.get('tactic') == tac and x.get('external_visibility')]), 'coverage_pct': pct, 'avg_strength': round(strength, 1), 'score': round(score, 1)})
        return out

    applicable_total = len(applicable_ids)
    theoretical_count = len(theoretical_ids)
    avg_strength = sum(t['score'] for t in techniques if t['theoretical']) / theoretical_count if theoretical_count else 0
    breadth = theoretical_count / applicable_total * 100 if applicable_total else 0
    overall = round((breadth * 0.65) + (avg_strength * 0.35), 1) if applicable_total else 0
    return {
        'basis': 'environment-scoped ATT&CK coverage model',
        'attack_version': ATTACK_DATASET_METADATA.get('version', ATTACK_VERSION), 'navigator_version': NAVIGATOR_VERSION,
        'dataset_label': ATTACK_DATASET_METADATA.get('dataset_label', 'ATT&CK Enterprise STIX'),
        'dataset_source': ATTACK_DATASET_METADATA.get('source'), 'coverage_scope': coverage_scope,
        'detected_log_sources': detected_sources,
        'scoped_technique_total': applicable_total, 'total_registry_techniques': len(VALID_TECHNIQUES),
        'not_applicable_count': len(VALID_TECHNIQUES) - applicable_total - len(external_visibility_ids),
        'external_visibility_count': len(external_visibility_ids),
        'external_visibility_ids': sorted(external_visibility_ids),
        'observed_count': len(observed_ids), 'theoretical_count': theoretical_count,
        'validated_count': len(validated_ids), 'detectable_count': len([tid for tid in applicable_ids if tid in rule_techs]),
        'out_of_scope_validated_count': len([tid for tid in validated_raw if tid not in applicable_ids]),
        'out_of_scope_observed_count': len([tid for tid in observed_raw if tid not in applicable_ids]),
        'observed_score': round((len(observed_ids) / applicable_total) * 100, 1) if applicable_total else 0,
        'theoretical_score': overall, 'validated_score': round((len(validated_ids) / applicable_total) * 100, 1) if applicable_total else 0,
        'overall_score': overall, 'maturity': 'High' if overall >= 75 else 'Moderate' if overall >= 55 else 'Basic' if overall >= 30 else 'Limited',
        'techniques': techniques,
        'rollups': {'observed': rollup('observed'), 'theoretical': rollup('theoretical'), 'validated': rollup('validated')},
        'observed_ids': sorted(observed_ids), 'theoretical_ids': sorted(theoretical_ids), 'validated_ids': sorted(validated_ids),
        'detectable_ids': sorted([tid for tid in applicable_ids if tid in rule_techs]), 'applicable_ids': sorted(applicable_ids),
    }


def theoretical_coverage_diagnostics(result):
    result = result or {}
    detected_sources = detected_data_sources(result)
    scope = _detected_coverage_scope(result, detected_sources)
    coverage = build_data_source_coverage(result)
    applicable_ids = {tid for tid, meta in VALID_TECHNIQUES.items() if _technique_in_detected_scope(tid, meta, scope)}
    theoretical_ids = {x.get('techniqueID') for x in coverage if x.get('techniqueID') in applicable_ids and _coverage_item_counts_as_theoretical(x)}
    component_map = {}
    attack_ds = {}
    source_rows = []
    for source in detected_sources:
        comps = SOURCE_COMPONENTS.get(source, []) or []
        tids = set(_source_technique_expansion(source)) & applicable_ids
        ds_names = _attck_data_sources_for_source(source)
        for comp in comps: component_map.setdefault(comp, set()).add(source)
        for ds in ds_names: attack_ds.setdefault(ds, set()).add(source)
        source_rows.append({'source': source, 'category': SOURCE_CATEGORY.get(source,'Other'), 'components': comps, 'attack_data_sources': ds_names, 'technique_count': len(tids), 'sample_techniques': sorted(tids)[:16]})
    unmapped = []
    for row in source_rows:
        if not row['components'] or row['technique_count'] == 0:
            src = row['source']
            cat = row['category']
            suggested = 'Add a parser that emits normalized_events[].log_source and source-specific evidence text.'
            suggested_comp = 'Process Creation' if cat in ('Windows','Linux','macOS') else 'Network Traffic Flow'
            unmapped.append({'source': src, 'reason': 'No component mapping found.' if not row['components'] else 'Components did not resolve to in-scope ATT&CK techniques.', 'suggested_parser': suggested, 'suggested_attack_data_component': suggested_comp})
    return {
        'detected_os_scope': scope,
        'detected_operating_systems': [s.replace('windows','Windows').replace('linux','Linux').replace('macos','macOS').replace('network','Network').replace('cloud','Cloud') for s in scope],
        'detected_log_sources': detected_sources,
        'source_rows': sorted(source_rows, key=lambda r: (r['category'], r['source'])),
        'components': [{'component': c, 'sources': sorted(s)} for c, s in sorted(component_map.items())],
        'attack_data_sources': [{'data_source': c, 'sources': sorted(s)} for c, s in sorted(attack_ds.items())],
        'supported_techniques': sorted(theoretical_ids),
        'supported_technique_count': len(theoretical_ids),
        'applicable_technique_count': len(applicable_ids),
        'theoretical_technique_count': len(theoretical_ids),
        'coverage_ratio': f"{len(theoretical_ids)} / {len(applicable_ids)}" if applicable_ids else '0 / 0',
        'unmapped_sources': [u['source'] for u in unmapped],
        'unmapped_details': unmapped,
        'pipeline': [
            'Detected Log Source', 'ATT&CK Data Components', 'ATT&CK Data Sources',
            'Supported ATT&CK Techniques', 'Unified Coverage Model', 'Heat Maps / Reports / Navigator'
        ],
    }


def enterprise_coverage_assessment(result, rules=None):
    result = result or {}
    rules = rules or []
    model = build_enterprise_attack_coverage_model(result, rules)
    diag = theoretical_coverage_diagnostics(result)
    enterprise = {
        'basis': model['basis'], 'attack_version': model['attack_version'], 'navigator_version': model['navigator_version'],
        'dataset_label': model.get('dataset_label'), 'dataset_source': model.get('dataset_source'),
        'overall_score': model['overall_score'], 'observed_score': model['observed_score'], 'theoretical_score': model['theoretical_score'], 'validated_score': model['validated_score'],
        'maturity': model['maturity'], 'detected_sources': diag['detected_log_sources'], 'coverage_scope': model['coverage_scope'],
        'scoped_technique_total': model['scoped_technique_total'], 'total_registry_techniques': model['total_registry_techniques'], 'not_applicable_count': model['not_applicable_count'],
        'observed_count': model['observed_count'], 'theoretical_count': model['theoretical_count'], 'validated_count': model['validated_count'], 'detectable_count': model['detectable_count'],
        'out_of_scope_validated_count': model.get('out_of_scope_validated_count',0), 'out_of_scope_observed_count': model.get('out_of_scope_observed_count',0),
        'telemetry_inventory': {}, 'data_components': diag['components'], 'attack_data_sources': diag['attack_data_sources'],
        'tactic_coverage': model['rollups']['theoretical'], 'tactic_rollups': model['rollups'], 'coverage_states': model['techniques'],
        'theoretical_diagnostics': diag, 'gaps': [], 'recommendations': [], 'rule_coverage': {}, 'readiness': [], 'executive_summary': '',
    }
    grouped = {}
    for source in diag['detected_log_sources']:
        grouped.setdefault(SOURCE_CATEGORY.get(source, 'Other'), []).append(source)
    for cat in sorted(set(list(grouped) + ['Windows','Linux','macOS','Network','Cloud','SIEM / Forwarding'])):
        enterprise['telemetry_inventory'][cat] = sorted(grouped.get(cat, []))
    for tc in enterprise['tactic_coverage']:
        if tc['total'] and tc['score'] < 50:
            enterprise['gaps'].append({'tactic': tc['name'], 'coverage': tc['score'], 'gap': 'Low theoretical telemetry coverage for this tactic.'})
        elif tc['total'] and tc['score'] < 70:
            enterprise['gaps'].append({'tactic': tc['name'], 'coverage': tc['score'], 'gap': 'Partial theoretical telemetry coverage; validate data components and rules.'})
        enterprise['readiness'].append({'tactic': tc['name'], 'readiness': 'Excellent' if tc['score'] >= 80 else 'Good' if tc['score'] >= 65 else 'Fair' if tc['score'] >= 45 else 'Poor', 'score': tc['score']})
    rule_techs = _rule_technique_ids(rules)
    enterprise['rule_coverage'] = {
        'techniques_with_rules': len(rule_techs),
        'applicable_techniques_with_rules': len([tid for tid in rule_techs if tid in model['applicable_ids']]),
        'detectable_techniques': model['detectable_count'],
        'covered_with_rules': len([tid for tid in rule_techs if tid in model['theoretical_ids']]),
        'applicable_without_rules': len([tid for tid in model['applicable_ids'] if tid not in rule_techs]),
        'validated_techniques': model['validated_count'],
    }
    enterprise['recommendations'] = environment_scoped_recommendations(result, diag['detected_log_sources'], 8)
    enterprise['executive_summary'] = (
        f"Scoped enterprise ATT&CK coverage is {model['overall_score']}% across {model['scoped_technique_total']} applicable techniques. "
        f"Observed: {model['observed_count']}; theoretical: {model['theoretical_count']}; detectable: {model['detectable_count']}; validated: {model['validated_count']}. "
        f"Detected log sources: {', '.join(diag['detected_log_sources']) if diag['detected_log_sources'] else 'none'}."
    )
    return enterprise


# ---------------------------------------------------------------------------
# Coverage engine selection and STIX-driven applicability/telemetry expansion.
# This block intentionally appears at the end of the module so it overrides the
# older heuristic definitions above while keeping them available as the optional
# legacy/heuristic engine.
# ---------------------------------------------------------------------------
_HEURISTIC_BUILD_DATA_SOURCE_COVERAGE = build_data_source_coverage

COVERAGE_ENGINE_STIX = 'stix'
COVERAGE_ENGINE_HEURISTIC = 'heuristic'
VALID_COVERAGE_ENGINES = {COVERAGE_ENGINE_STIX, COVERAGE_ENGINE_HEURISTIC}


def coverage_engine_from_result(result=None, coverage_engine=None):
    raw = coverage_engine
    if raw is None and isinstance(result, dict):
        raw = result.get('coverage_engine') or result.get('coverage_engine_mode') or result.get('coverage_model_engine')
    if raw is None:
        import os
        raw = os.getenv('PCAP_MAPPER_COVERAGE_ENGINE') or os.getenv('ATTACK_COVERAGE_ENGINE') or COVERAGE_ENGINE_STIX
    raw = str(raw or COVERAGE_ENGINE_STIX).strip().lower().replace('_', '-').replace(' ', '-')
    if raw in {'stix-driven', 'stix-v18', 'official-stix', 'official'}:
        raw = COVERAGE_ENGINE_STIX
    if raw in {'legacy-heuristic', 'legacy', 'old'}:
        raw = COVERAGE_ENGINE_HEURISTIC
    return raw if raw in VALID_COVERAGE_ENGINES else COVERAGE_ENGINE_STIX


def _norm_attack_string(value):
    return ' '.join(str(value or '').replace('_', ' ').replace('-', ' ').replace('/', ' ').replace(':', ' ').lower().split())


def _split_attack_data_source(value):
    value = str(value or '').strip()
    if ':' in value:
        ds, comp = value.split(':', 1)
        return ds.strip(), comp.strip()
    return value, ''


def _stix_component_catalog():
    comps = {}
    data_sources = {}
    for tid, meta in VALID_TECHNIQUES.items():
        for entry in meta.get('data_sources', []) or []:
            ds, comp = _split_attack_data_source(entry)
            if ds:
                data_sources.setdefault(_norm_attack_string(ds), {'name': ds, 'techniques': set()})['techniques'].add(tid)
            if comp:
                comps.setdefault(_norm_attack_string(comp), {'name': comp, 'data_source': ds, 'techniques': set()})['techniques'].add(tid)
    return comps, data_sources


def _detected_scope_to_stix_platforms(scope):
    scope = {_norm_attack_string(x) for x in (scope or [])}
    out = set()
    if 'windows' in scope:
        out.update({'windows'})
    if 'linux' in scope:
        out.update({'linux'})
    if 'macos' in scope or 'mac os' in scope:
        out.update({'macos', 'macos'})
    if 'network' in scope:
        out.update({'network', 'network device'})
    if 'cloud' in scope:
        out.update({'iaas', 'saas', 'office suite', 'identity provider', 'containers'})
    # Enterprise/network telemetry can often observe multi-platform traffic.
    if 'network' in scope:
        out.update({'windows', 'linux', 'macos'})
    return out


def _platform_to_scope_token(platform):
    p = _norm_attack_string(platform)
    if p in {'macos', 'mac os'}:
        return 'macos'
    if p in {'network device', 'network devices', 'network'}:
        return 'network device'
    return p


def _stix_technique_in_detected_scope(tid, meta, scope):
    """Applicability using STIX x_mitre_platforms only, not technique names."""
    platforms = {_platform_to_scope_token(p) for p in (meta.get('platforms') or []) if p}
    if not platforms:
        return True
    detected = _detected_scope_to_stix_platforms(scope)
    if not detected:
        return True
    if platforms & detected:
        return True
    # ATT&CK's PRE/external tactics are modeled separately from environment scope.
    if _is_external_visibility_tactic(meta.get('tactic', '')):
        return False
    return False


def _source_stix_matches(source):
    """Return ATT&CK data components/sources/techniques supported by a log source.

    This uses the official STIX x_mitre_data_sources strings from each technique
    and the app's parser/source inventory only to translate detected log names
    into canonical ATT&CK data component names. It does not use technique-name or
    tactic-name heuristics.
    """
    source = _canon_source_name(source) or source
    catalog_components, catalog_sources = _stix_component_catalog()
    configured_components = SOURCE_COMPONENTS.get(source, []) or []
    matched_components = {}
    matched_sources = {}
    techniques = set()

    for raw_comp in configured_components:
        raw = str(raw_comp or '').replace('Log Source:', '').strip()
        ds_hint, comp_hint = _split_attack_data_source(raw)
        candidates = []
        if comp_hint:
            candidates.append(comp_hint)
        candidates.append(raw)
        candidates.append(ds_hint)
        for cand in candidates:
            key = _norm_attack_string(cand)
            if not key:
                continue
            # Exact component/data-source matches first.
            if key in catalog_components:
                rec = catalog_components[key]
                matched_components[rec['name']] = rec
                techniques.update(rec['techniques'])
            if key in catalog_sources:
                rec = catalog_sources[key]
                matched_sources[rec['name']] = rec
                techniques.update(rec['techniques'])
            # Conservative substring match for app-specific phrases like
            # "Network Traffic Flow", "PowerShell Script Block", etc.
            for ckey, rec in catalog_components.items():
                if key and (key == ckey or key in ckey or ckey in key):
                    matched_components[rec['name']] = rec
                    techniques.update(rec['techniques'])
            for skey, rec in catalog_sources.items():
                if key and (key == skey or key in skey or skey in key):
                    matched_sources[rec['name']] = rec
                    techniques.update(rec['techniques'])

    # If the detected source itself is a canonical ATT&CK data source name, use it.
    source_key = _norm_attack_string(source)
    for skey, rec in catalog_sources.items():
        if source_key == skey or source_key in skey or skey in source_key:
            matched_sources[rec['name']] = rec
            techniques.update(rec['techniques'])

    # The bundled offline v18-compatible dataset may not include populated
    # x_mitre_data_sources. In that case, keep the STIX-driven platform
    # applicability path and use the app's ATT&CK component table as a local
    # STIX-compatibility backfill. Deployments that mount the official MITRE
    # STIX bundle through ATTACK_STIX_PATH will use x_mitre_data_sources above.
    if False and not techniques and not catalog_components and not catalog_sources:
        for raw_comp in configured_components:
            comp = str(raw_comp or '').replace('Log Source:', '').strip()
            if not comp:
                continue
            tids = set(COMPONENT_TECHNIQUES.get(comp, []) or [])
            if not tids:
                # Try a conservative exact-normalized lookup only.
                comp_norm = _norm_attack_string(comp)
                for known, known_tids in COMPONENT_TECHNIQUES.items():
                    if _norm_attack_string(known) == comp_norm:
                        tids.update(known_tids or [])
            if tids:
                matched_components.setdefault(comp, {'name': comp, 'data_source': '', 'techniques': set()})['techniques'].update(tids)
                techniques.update(tids)
        for ds_name in _attck_data_sources_for_source(source):
            matched_sources.setdefault(ds_name, {'name': ds_name, 'techniques': set()})

    # Derive data-source names from matched components where STIX supplied one.
    for rec in list(matched_components.values()):
        ds = rec.get('data_source')
        if ds:
            matched_sources.setdefault(ds, {'name': ds, 'techniques': set()})

    return {
        'source': source,
        'data_components': sorted(matched_components),
        'attack_data_sources': sorted(matched_sources),
        'techniques': {tid for tid in techniques if tid in VALID_TECHNIQUES},
    }



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
            'directly_detected': source in detected,
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
    network_visibility_sources = {'Zeek','Suricata','Packetbeat','NetFlow','IPFIX','Cisco ASA','Cisco IOS','Cisco NX-OS','Cisco Firepower','Palo Alto','Fortinet','Check Point','SonicWall','pfSense','OPNsense','Squid','HAProxy','F5','VPN','Wireless Controller'}
    if any(s in network_visibility_sources for s in detected):
        SOURCE_CATEGORY['Network Visibility Baseline'] = 'Network'
        SOURCE_COMPONENTS['Network Visibility Baseline'] = ['Network Traffic Flow','Network Traffic Content','DNS Query','HTTP Requests','TLS SNI','SMB Session','SSH Session','VPN Session','Firewall Events']
        add_record('Network Visibility Baseline', 'Network telemetry sensor detected; inferred enterprise network visibility capabilities.', 'medium', 72, SOURCE_COMPONENTS['Network Visibility Baseline'], True, 'network-baseline')
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
    # Strict STIX mode: techniques come only from x_mitre_data_sources in the
    # selected ATT&CK STIX bundle. Local component/source fallback mappings are
    # reserved for the legacy heuristic engine and diagnostics, not theoretical
    # heat-map coverage.
    techniques = set(match.get('techniques') or [])
    return {
        'source': source,
        'data_components': sorted(set(match.get('data_components') or []) | set(components)),
        'attack_data_sources': sorted(set(match.get('attack_data_sources') or []) | set(_attck_data_sources_for_source(source))),
        'techniques': {tid for tid in techniques if tid in VALID_TECHNIQUES},
    }


def _coverage_item_counts_as_theoretical(item):
    """Return True when telemetry evidence is strong enough for heat-map coverage.

    Expanded OS baseline profiles are useful context and drive recommendations,
    but by themselves they should not turn almost every applicable ATT&CK
    technique green. Directly observed log sources, detected products,
    product-implied capabilities, and concrete network sensors count. Pure
    low-confidence OS baselines remain diagnostics/potential coverage unless
    corroborated by another stronger source.
    """
    item = item or {}
    basis = set(item.get('capability_basis') or [])
    labels = set(item.get('confidence_labels') or [])
    score = float(item.get('score') or 0)
    strong_basis = {'detected product', 'detected log source', 'product-inferred source', 'network-baseline'}
    if basis & strong_basis:
        return True
    if 'os-baseline' in basis and not (basis - {'os-baseline'}):
        return False
    if 'low' in labels and not ('high' in labels or 'medium' in labels):
        return False
    return score >= 76

def build_data_source_coverage(result, coverage_engine=None):
    engine = coverage_engine_from_result(result, coverage_engine)
    if engine == COVERAGE_ENGINE_HEURISTIC:
        return _HEURISTIC_BUILD_DATA_SOURCE_COVERAGE(result)

    # Strict STIX source-only theoretical model:
    #   detected log source -> SOURCE_COMPONENTS canonical ATT&CK components
    #   -> selected STIX x_mitre_data_sources -> ATT&CK techniques.
    # No OS baseline, product-implied source, network baseline, technique-name,
    # or local source->technique expansion contributes to theoretical coverage.
    set_attack_version(attack_version_from_result(result))
    coverage = {}
    detected = [_canon_source_name(s) or s for s in detected_data_sources(result or {})]
    for source in sorted(set(detected)):
        components = list(dict.fromkeys(SOURCE_COMPONENTS.get(source, []) or []))
        record = {
            'source': source,
            'category': SOURCE_CATEGORY.get(source, 'Other'),
            'reason': f'{source} detected directly and mapped through selected ATT&CK STIX data-source metadata.',
            'confidence': 'high',
            'score': 88 if SOURCE_CATEGORY.get(source) != 'Network' else 82,
            'components': components,
            'inferred': False,
            'basis': 'detected log source',
            'directly_detected': True,
        }
        match = _match_capability_record_to_attack(record)
        # _match_capability_record_to_attack is intentionally STIX-only in this
        # engine; it returns only techniques derived from selected STIX metadata.
        for tid in match.get('techniques') or []:
            meta = VALID_TECHNIQUES.get(tid)
            if not meta:
                continue
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
                'attack_version': ATTACK_DATASET_METADATA.get('version', ATTACK_VERSION),
            })
            cur['score'] = max(cur['score'], int(record['score']))
            cur['data_sources'].add(source)
            cur['data_components'].update(match.get('data_components') or [])
            cur['attack_data_sources'].update(match.get('attack_data_sources') or [])
            cur['confidence_labels'].add('high')
            cur['capability_basis'].add('detected log source')
            cur['rationale'].append(
                f"Detected Log Source: {source} -> ATT&CK Data Components: {', '.join((match.get('data_components') or [])[:8]) or 'none'} -> ATT&CK Data Sources: {', '.join((match.get('attack_data_sources') or [])[:8]) or 'none'} -> STIX-supported Technique: {tid} {meta.get('name', '')}."
            )
    out = []
    for item in coverage.values():
        for key in ('data_sources', 'data_components', 'attack_data_sources', 'confidence_labels', 'capability_basis'):
            item[key] = sorted(item[key])
        item['counts_as_theoretical'] = True
        item['rationale'] = item['rationale'][:12]
        out.append(item)
    return sorted(out, key=lambda x: (-x['score'], x['tactic'], x['techniqueID']))


def _build_model_with_engine(result, rules=None, coverage_engine=None):
    result = result or {}
    rules = rules or []
    engine = coverage_engine_from_result(result, coverage_engine)
    set_attack_version(attack_version_from_result(result))
    data_source_items = result.get('data_source_coverage')
    if not data_source_items or result.get('coverage_engine') != engine:
        data_source_items = build_data_source_coverage({**result, 'coverage_engine': engine}, engine)
    data_source_by_id = {x.get('techniqueID'): x for x in data_source_items if x.get('techniqueID') in VALID_TECHNIQUES}
    observed_raw = _attack_id_set_from_result(result)
    validated_raw, validated_details = _validated_ids_and_details(result)
    detected_sources = detected_data_sources(result)
    coverage_scope = _detected_coverage_scope(result, detected_sources)
    if engine == COVERAGE_ENGINE_HEURISTIC:
        applicable_ids = {tid for tid, meta in VALID_TECHNIQUES.items() if _technique_in_detected_scope(tid, meta, coverage_scope) and not _is_external_visibility_tactic(meta.get('tactic', ''))}
        basis = 'environment-scoped ATT&CK coverage model using legacy heuristic applicability'
    else:
        applicable_ids = {tid for tid, meta in VALID_TECHNIQUES.items() if _stix_technique_in_detected_scope(tid, meta, coverage_scope) and not _is_external_visibility_tactic(meta.get('tactic', ''))}
        basis = 'environment-scoped ATT&CK coverage model using STIX platforms and x_mitre_data_sources'
    external_visibility_ids = {tid for tid, meta in VALID_TECHNIQUES.items() if _is_external_visibility_tactic(meta.get('tactic', ''))}
    theoretical_ids = {tid for tid, item in data_source_by_id.items() if _coverage_item_counts_as_theoretical(item)} & applicable_ids
    observed_ids = observed_raw & applicable_ids
    validated_ids = validated_raw & applicable_ids
    rule_names_by_tid = _supporting_rules_by_tid(rules)
    rule_techs = set(rule_names_by_tid)

    techniques = []
    tactic_totals = {t: 0 for t in TACTIC_DISPLAY_ORDER}
    tactic_observed = {t: 0 for t in TACTIC_DISPLAY_ORDER}
    tactic_theoretical = {t: 0 for t in TACTIC_DISPLAY_ORDER}
    tactic_validated = {t: 0 for t in TACTIC_DISPLAY_ORDER}
    tactic_strength_sum = {t: 0.0 for t in TACTIC_DISPLAY_ORDER}

    for tid, meta in sorted(VALID_TECHNIQUES.items()):
        tactic = meta.get('tactic', '')
        external_visibility = _is_external_visibility_tactic(tactic)
        external_visibility_reason = _external_visibility_reason(tactic)
        applicable = (tid in applicable_ids) and not external_visibility
        ds = data_source_by_id.get(tid, {})
        score = float(ds.get('score', 0) or 0)
        obs = tid in observed_ids
        theo = tid in theoretical_ids
        val = tid in validated_ids
        detectable = applicable and (tid in rule_techs)
        if val and score < 90:
            score = 90.0
        elif obs and score < 70:
            score = 70.0
        if external_visibility:
            state, score = 'External Visibility', 0.0
        elif not applicable:
            state, score = 'Not Applicable', 0.0
        elif obs:
            state = 'Observed + Theoretical' if theo else 'Observed'
        elif val:
            state = 'Validated'
        elif theo and detectable:
            state = 'Theoretical + Detectable'
        elif theo:
            state = 'Theoretical'
        elif detectable:
            state = 'Detectable'
        else:
            state = 'Not Covered'
        if applicable:
            if tactic not in tactic_totals:
                tactic_totals[tactic] = tactic_observed[tactic] = tactic_theoretical[tactic] = tactic_validated[tactic] = 0
                tactic_strength_sum[tactic] = 0.0
            tactic_totals[tactic] += 1
            if obs:
                tactic_observed[tactic] += 1
            if theo:
                tactic_theoretical[tactic] += 1
                tactic_strength_sum[tactic] += score
            if val:
                tactic_validated[tactic] += 1
        evidence = []
        evidence.extend(ds.get('rationale', []) or [])
        evidence.extend((validated_details.get(tid, {}) or {}).get('evidence', []) or [])
        techniques.append({
            'techniqueID': tid, 'technique_id': tid, 'name': meta.get('name', tid), 'tactic': tactic,
            'applicable': applicable, 'observed': obs, 'theoretical': theo, 'detectable': detectable,
            'validated': val, 'validated_raw': tid in validated_raw, 'observed_raw': tid in observed_raw,
            'out_of_scope_validated_match': (tid in validated_raw) and not applicable,
            'out_of_scope_observed_match': (tid in observed_raw) and not applicable,
            'external_visibility': external_visibility, 'external_visibility_reason': external_visibility_reason,
            'not_applicable': (not applicable) and not external_visibility, 'state': state,
            'state_class': _coverage_state_class({'applicable': applicable, 'external_visibility': external_visibility, 'observed': obs, 'theoretical': theo, 'validated': val, 'rule': detectable, 'score': score}),
            'score': round(score, 1), 'confidence': round(score, 1), 'rule': detectable,
            'supporting_rules': sorted(rule_names_by_tid.get(tid, [])),
            'data_sources': sorted(ds.get('data_sources', []) or []),
            'data_components': sorted(ds.get('data_components', []) or []),
            'attack_data_sources': sorted(ds.get('attack_data_sources', []) or []),
            'stix_platforms': meta.get('platforms', []) or [],
            'stix_data_sources': meta.get('data_sources', []) or [],
            'coverage_engine': engine,
            'evidence': evidence[:12], 'rationale': (ds.get('rationale', []) or [])[:8],
            'validated_rules': (validated_details.get(tid, {}) or {}).get('rules', []),
            'validated_evidence': (validated_details.get(tid, {}) or {}).get('evidence', []),
            'match_count': (validated_details.get(tid, {}) or {}).get('match_count', 0),
        })

    def rollup(kind):
        out = []
        for tac in TACTIC_DISPLAY_ORDER:
            total = tactic_totals.get(tac, 0)
            if kind == 'observed':
                covered, strength = tactic_observed.get(tac, 0), 100 if tactic_observed.get(tac, 0) else 0
            elif kind == 'validated':
                covered, strength = tactic_validated.get(tac, 0), 100 if tactic_validated.get(tac, 0) else 0
            else:
                covered = tactic_theoretical.get(tac, 0)
                strength = tactic_strength_sum.get(tac, 0.0) / covered if covered else 0
            pct = round((covered / total) * 100, 1) if total else 0
            score = pct if kind != 'theoretical' else (round((pct * 0.65) + (strength * 0.35), 1) if total else 0)
            out.append({'tactic': tac, 'name': _tactic_name(tac), 'covered': covered, 'total': total, 'not_applicable': len([x for x in techniques if x.get('tactic') == tac and not x.get('applicable') and not x.get('external_visibility')]), 'external_visibility': len([x for x in techniques if x.get('tactic') == tac and x.get('external_visibility')]), 'coverage_pct': pct, 'avg_strength': round(strength, 1), 'score': round(score, 1)})
        return out

    applicable_total = len(applicable_ids)
    theoretical_count = len(theoretical_ids)
    avg_strength = sum(t['score'] for t in techniques if t['theoretical']) / theoretical_count if theoretical_count else 0
    breadth = theoretical_count / applicable_total * 100 if applicable_total else 0
    overall = round((breadth * 0.65) + (avg_strength * 0.35), 1) if applicable_total else 0
    return {
        'basis': basis,
        'coverage_engine': engine,
        'attack_version': ATTACK_DATASET_METADATA.get('version', ATTACK_VERSION), 'navigator_version': NAVIGATOR_VERSION,
        'dataset_label': ATTACK_DATASET_METADATA.get('dataset_label', 'ATT&CK Enterprise STIX'),
        'dataset_source': ATTACK_DATASET_METADATA.get('source'), 'coverage_scope': coverage_scope,
        'detected_log_sources': detected_sources,
        'scoped_technique_total': applicable_total, 'total_registry_techniques': len(VALID_TECHNIQUES),
        'not_applicable_count': len(VALID_TECHNIQUES) - applicable_total - len(external_visibility_ids),
        'external_visibility_count': len(external_visibility_ids),
        'external_visibility_ids': sorted(external_visibility_ids),
        'observed_count': len(observed_ids), 'theoretical_count': theoretical_count,
        'validated_count': len(validated_ids), 'detectable_count': len([tid for tid in applicable_ids if tid in rule_techs]),
        'out_of_scope_validated_count': len([tid for tid in validated_raw if tid not in applicable_ids]),
        'out_of_scope_observed_count': len([tid for tid in observed_raw if tid not in applicable_ids]),
        'observed_score': round((len(observed_ids) / applicable_total) * 100, 1) if applicable_total else 0,
        'theoretical_score': overall, 'validated_score': round((len(validated_ids) / applicable_total) * 100, 1) if applicable_total else 0,
        'overall_score': overall, 'maturity': 'High' if overall >= 75 else 'Moderate' if overall >= 55 else 'Basic' if overall >= 30 else 'Limited',
        'techniques': techniques,
        'rollups': {'observed': rollup('observed'), 'theoretical': rollup('theoretical'), 'validated': rollup('validated')},
        'observed_ids': sorted(observed_ids), 'theoretical_ids': sorted(theoretical_ids), 'validated_ids': sorted(validated_ids),
        'detectable_ids': sorted([tid for tid in applicable_ids if tid in rule_techs]), 'applicable_ids': sorted(applicable_ids),
    }


def build_enterprise_attack_coverage_model(result, rules=None, coverage_engine=None):
    return _build_model_with_engine(result, rules, coverage_engine)


def theoretical_coverage_diagnostics(result, coverage_engine=None):
    result = result or {}
    engine = coverage_engine_from_result(result, coverage_engine)
    set_attack_version(attack_version_from_result(result))
    detected_sources = detected_data_sources(result)
    capability_records = [{'source': s, 'category': SOURCE_CATEGORY.get(s, 'Other'), 'components': SOURCE_COMPONENTS.get(s, []) or [], 'confidence': 'high', 'basis': 'detected log source', 'inferred': False, 'directly_detected': True, 'reason': f'{s} detected directly in the job.'} for s in detected_data_sources(result)]
    scope = _detected_coverage_scope(result, detected_sources)
    coverage = build_data_source_coverage({**result, 'coverage_engine': engine}, engine)
    if engine == COVERAGE_ENGINE_HEURISTIC:
        applicable_ids = {tid for tid, meta in VALID_TECHNIQUES.items() if _technique_in_detected_scope(tid, meta, scope) and not _is_external_visibility_tactic(meta.get('tactic', ''))}
    else:
        applicable_ids = {tid for tid, meta in VALID_TECHNIQUES.items() if _stix_technique_in_detected_scope(tid, meta, scope) and not _is_external_visibility_tactic(meta.get('tactic', ''))}
    theoretical_ids = {x.get('techniqueID') for x in coverage if x.get('techniqueID') in applicable_ids and _coverage_item_counts_as_theoretical(x)}
    component_map = {}
    attack_ds = {}
    source_rows = []
    diag_records = capability_records if engine != COVERAGE_ENGINE_HEURISTIC else [{'source': s, 'category': SOURCE_CATEGORY.get(s, 'Other'), 'components': SOURCE_COMPONENTS.get(s, []) or [], 'confidence': 'high', 'basis': 'detected log source', 'inferred': False} for s in detected_sources]
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
    unmapped = []
    for row in source_rows:
        if not row['components'] or row['technique_count'] == 0:
            src = row['source']; cat = row['category']
            suggested = 'Add or tune a parser that emits normalized_events[].log_source with canonical source names.'
            suggested_comp = 'Process: Process Creation' if cat in ('Windows', 'Linux', 'macOS') else 'Network Traffic: Network Traffic Flow'
            unmapped.append({'source': src, 'reason': 'No STIX data component/source mapping found.' if engine == COVERAGE_ENGINE_STIX and not row['components'] else 'Components did not resolve to in-scope ATT&CK techniques.', 'suggested_parser': suggested, 'suggested_attack_data_component': suggested_comp})
    return {
        'coverage_engine': engine,
        'detected_os_scope': scope,
        'detected_operating_systems': [s.replace('windows', 'Windows').replace('linux', 'Linux').replace('macos', 'macOS').replace('network', 'Network').replace('cloud', 'Cloud') for s in scope],
        'detected_log_sources': detected_sources,
        'telemetry_capabilities': sorted(source_rows, key=lambda r: (r.get('inferred', False), r['category'], r['source'])),
        'product_inferred_capability_count': len([r for r in source_rows if r.get('basis') in ('detected product', 'product-inferred source')]),
        'os_inferred_capability_count': len([r for r in source_rows if r.get('basis') in ('os-baseline', 'os-inferred source')]),
        'calibration_note': 'Theoretical coverage is source-only: directly detected log sources are mapped through the selected ATT&CK STIX bundle. OS baselines and product assumptions do not contribute to theoretical coverage.',
        'source_rows': sorted(source_rows, key=lambda r: (r['category'], r['source'])),
        'components': [{'component': c, 'sources': sorted(s)} for c, s in sorted(component_map.items())],
        'attack_data_sources': [{'data_source': c, 'sources': sorted(s)} for c, s in sorted(attack_ds.items())],
        'supported_techniques': sorted(theoretical_ids),
        'supported_technique_count': len(theoretical_ids),
        'applicable_technique_count': len(applicable_ids),
        'theoretical_technique_count': len(theoretical_ids),
        'coverage_ratio': f"{len(theoretical_ids)} / {len(applicable_ids)}" if applicable_ids else '0 / 0',
        'unmapped_sources': [u['source'] for u in unmapped],
        'unmapped_details': unmapped,
        'pipeline': ['Detected Log Source', 'Selected ATT&CK STIX Bundle', 'ATT&CK Data Components', 'ATT&CK Data Sources', 'Supported ATT&CK Techniques', 'Unified Coverage Model', 'Heat Maps / Reports / Navigator'],
    }



def _detected_environment_categories(result, detected_sources=None):
    """Return telemetry recommendation categories that match the detected environment.

    Network recommendations are included only when network telemetry/devices are
    detected.  SIEM/forwarding recommendations are included when any endpoint or
    network environment is present because forwarding is cross-platform.
    """
    result = result or {}
    detected_sources = set(detected_sources or detected_data_sources(result))
    scope = set(_detect_os_capability_tokens(result, detected_sources))
    cats = set()
    if 'windows' in scope: cats.add('Windows')
    if 'linux' in scope: cats.add('Linux')
    if 'macos' in scope: cats.add('macOS')
    if 'network' in scope: cats.add('Network')
    for src in detected_sources:
        cat = SOURCE_CATEGORY.get(_canon_source_name(src) or src, '')
        if cat in {'Windows','Linux','macOS','Network'}:
            cats.add(cat)
    if cats:
        cats.add('SIEM / Forwarding')
    return cats


def environment_scoped_recommendations(result, detected_sources=None, limit=8):
    """Telemetry recommendations constrained to the detected environment."""
    detected_sources = set(detected_sources or detected_data_sources(result or {}))
    allowed = _detected_environment_categories(result or {}, detected_sources)
    if not allowed:
        allowed = {'Network', 'SIEM / Forwarding'}
    out = []
    for rec in RECOMMENDATION_LIBRARY:
        source = rec.get('source')
        if source in detected_sources:
            continue
        cat = SOURCE_CATEGORY.get(source, rec.get('category', 'Other'))
        if cat in allowed:
            row = dict(rec)
            row.setdefault('category', cat)
            row.setdefault('environment_scoped', True)
            out.append(row)
    return sorted(out, key=lambda r: -int(r.get('gain', 0) or 0))[:limit]

def enterprise_coverage_assessment(result, rules=None, coverage_engine=None):
    result = result or {}
    rules = rules or []
    engine = coverage_engine_from_result(result, coverage_engine)
    model = build_enterprise_attack_coverage_model({**result, 'coverage_engine': engine}, rules, engine)
    diag = theoretical_coverage_diagnostics({**result, 'coverage_engine': engine}, engine)
    enterprise = {
        'basis': model['basis'], 'coverage_engine': engine,
        'attack_version': model['attack_version'], 'navigator_version': model['navigator_version'],
        'dataset_label': model.get('dataset_label'), 'dataset_source': model.get('dataset_source'),
        'overall_score': model['overall_score'], 'observed_score': model['observed_score'], 'theoretical_score': model['theoretical_score'], 'validated_score': model['validated_score'],
        'maturity': model['maturity'], 'detected_sources': diag['detected_log_sources'], 'coverage_scope': model['coverage_scope'],
        'scoped_technique_total': model['scoped_technique_total'], 'total_registry_techniques': model['total_registry_techniques'], 'not_applicable_count': model['not_applicable_count'],
        'external_visibility_count': model.get('external_visibility_count', 0),
        'observed_count': model['observed_count'], 'theoretical_count': model['theoretical_count'], 'validated_count': model['validated_count'], 'detectable_count': model['detectable_count'],
        'out_of_scope_validated_count': model.get('out_of_scope_validated_count', 0), 'out_of_scope_observed_count': model.get('out_of_scope_observed_count', 0),
        'telemetry_inventory': {}, 'data_components': diag['components'], 'attack_data_sources': diag['attack_data_sources'],
        'tactic_coverage': model['rollups']['theoretical'], 'tactic_rollups': model['rollups'], 'coverage_states': model['techniques'],
        'theoretical_diagnostics': diag, 'gaps': [], 'recommendations': [], 'rule_coverage': {}, 'readiness': [], 'executive_summary': '',
    }
    grouped = {}
    for source in diag['detected_log_sources']:
        grouped.setdefault(SOURCE_CATEGORY.get(source, 'Other'), []).append(source)
    for cat in sorted(set(list(grouped) + ['Windows', 'Linux', 'macOS', 'Network', 'Cloud', 'SIEM / Forwarding'])):
        enterprise['telemetry_inventory'][cat] = sorted(grouped.get(cat, []))
    for tc in enterprise['tactic_coverage']:
        if tc['total'] and tc['score'] < 50:
            enterprise['gaps'].append({'tactic': tc['name'], 'coverage': tc['score'], 'gap': 'Low theoretical telemetry coverage for this tactic.'})
        elif tc['total'] and tc['score'] < 70:
            enterprise['gaps'].append({'tactic': tc['name'], 'coverage': tc['score'], 'gap': 'Partial theoretical telemetry coverage; validate data components and rules.'})
        enterprise['readiness'].append({'tactic': tc['name'], 'readiness': 'Excellent' if tc['score'] >= 80 else 'Good' if tc['score'] >= 65 else 'Fair' if tc['score'] >= 45 else 'Poor', 'score': tc['score']})
    rule_techs = _rule_technique_ids(rules)
    enterprise['rule_coverage'] = {
        'techniques_with_rules': len(rule_techs),
        'applicable_techniques_with_rules': len([tid for tid in rule_techs if tid in model['applicable_ids']]),
        'detectable_techniques': model['detectable_count'],
        'covered_with_rules': len([tid for tid in rule_techs if tid in model['theoretical_ids']]),
        'applicable_without_rules': len([tid for tid in model['applicable_ids'] if tid not in rule_techs]),
        'validated_techniques': model['validated_count'],
    }
    enterprise['recommendations'] = environment_scoped_recommendations(result, diag['detected_log_sources'], 8)
    enterprise['executive_summary'] = (
        f"Scoped enterprise ATT&CK coverage is {model['overall_score']}% across {model['scoped_technique_total']} applicable techniques. "
        f"Engine: {'STIX-driven' if engine == COVERAGE_ENGINE_STIX else 'heuristic'}. "
        f"Observed: {model['observed_count']}; theoretical: {model['theoretical_count']}; detectable: {model['detectable_count']}; validated: {model['validated_count']}. "
        f"Detected log sources: {', '.join(diag['detected_log_sources']) if diag['detected_log_sources'] else 'none'}."
    )
    return enterprise

# ---------------------------------------------------------------------------
# v2 telemetry capability registry and potential coverage assessment
# ---------------------------------------------------------------------------
# This section intentionally sits at the end of the module so it can extend the
# older compatibility tables without disrupting legacy imports.  Theoretical
# coverage remains source-only: only directly detected log sources are eligible
# to mark a technique theoretical.  Potential coverage is broader and describes
# additional capabilities that detected telemetry products could provide if fully
# configured.

RICH_TELEMETRY_CAPABILITY_REGISTRY = {
    # Windows endpoint and server telemetry
    'Windows Security': ['User Account Authentication','Logon Session','Credential Validation','Kerberos Authentication','NTLM Authentication','Remote Logon','Special Privilege Assignment','Privilege Use','Account Management','User Account Creation','User Account Deletion','Account Lockout','Password Change','Group Membership Change','Object Access','Policy Change','Process Creation','Service Creation','Scheduled Job','Firewall Events'],
    'Windows System': ['Service Creation','Service Activity','Driver Load','System Boot','System Shutdown','Device Installation','Kernel Events','Time Change','System Service Start','System Service Stop'],
    'Windows Application': ['Application Logs','Application Error','Application Activity','Application Launch','Script Execution','Web Error'],
    'Sysmon': ['Process Creation','Process Termination','Process Metadata','Command Execution','Network Connection Creation','DNS Query','File Creation','File Modification','File Deletion','File Metadata','File Stream Creation','Registry Key Creation','Registry Key Modification','Registry Value Modification','Registry Key Deletion','Driver Load','Image Load','Named Pipe Creation','Named Pipe Connection','WMI Activity','WMI Event Subscription','WMI Event Consumer','WMI Event Filter','Process Access','Create Remote Thread','Raw Disk Read','Clipboard Data'],
    'PowerShell Operational Log': ['PowerShell Script Block','PowerShell Module','PowerShell Transcription','PowerShell Engine','PowerShell Remoting','AMSI Scan Result','Command Execution','Script Execution','Encoded Command'],
    'Defender': ['Malware Detection','Threat Quarantine','Suspicious Script','Exploit Detection','Ransomware Behavior','Tamper Protection','Attack Surface Reduction','Controlled Folder Access','Cloud Protection Event','AMSI Scan Result','Process Activity','File Activity','Network Activity','Registry Key Modification'],
    'Defender for Endpoint': ['Endpoint Detection Alert','Process Creation','Process Metadata','Command Execution','Script Execution','PowerShell Script Block','AMSI Scan Result','File Creation','File Modification','File Deletion','File Metadata','Registry Key Modification','Network Connection Creation','DNS Query','Module Load','Driver Load','User Account Authentication','Logon Session','Malware Detection','Suspicious Behavior','Exploit Detection','Credential Theft Detection','Ransomware Behavior','Sensor Health','Attack Surface Reduction'],
    'WinRM': ['Remote Shell','Remote Command','Remote Authentication','PowerShell Remoting','Remote Service Session','Network Connection Creation'],
    'WMI': ['WMI Query','Remote WMI','WMI Process Creation','WMI Event Subscription','WMI Event Consumer','WMI Event Filter','Command Execution'],
    'SMB': ['SMB Session','SMB File Access','File Share Access','Named Pipe Creation','Remote File Copy','Admin Share Access','SMB Authentication'],
    'Windows DNS': ['DNS Query','DNS Response','DNS Zone Change','DNS Server Log','DNS Security Event'],
    'Windows DHCP': ['DHCP Lease','DHCP Release','DHCP Reservation','Network Configuration'],
    'IIS': ['HTTP Requests','HTTP Response','URL Path','Query String','User Agent','Source IP','Web Authentication','Web Error','File Request','File Upload','Web Shell Indicator','Application Pool Event','Server-Side Script Execution'],
    'Task Scheduler': ['Scheduled Job','Scheduled Job Creation','Scheduled Job Modification','Scheduled Job Deletion','Scheduled Job Execution','Remote Task Creation'],
    'Windows Firewall': ['Firewall Events','Allowed Connection','Denied Connection','Firewall Rule Change','Firewall Profile Change','Network Connection Creation'],
    'AppLocker': ['Application Control Decision','Blocked Execution','Allowed Execution','Script Execution'],
    'Windows Event Forwarding': ['Windows Event Logs','Forwarded Event','User Account Authentication','PowerShell Logs','Service Activity','Process Creation','Logon Session'],
    'RDP': ['RDP Session','Remote Logon','Remote Authentication','User Account Authentication','Network Connection Creation'],
    'Active Directory': ['LDAP Query','Kerberos Authentication','NTLM Authentication','Directory Service Access','Active Directory Object Modification','Group Policy Change','Computer Account Change','Replication Activity','SPN Query','Account Management','Group Membership Change'],
    'Certificate Services': ['Certificate Enrollment','Certificate Request','Certificate Issuance','Certificate Template Change','Certificate Authentication'],

    # Linux telemetry
    'auditd': ['Process Creation','Command Execution','execve','File Access','File Modification','File Deletion','chmod','setuid','setgid','ptrace','Kernel Events','Kernel Module Load','User Account Authentication','User Account Creation','Group Membership Change','Sudo Command','SELinux AVC'],
    'auth.log': ['SSH Session','User Account Authentication','Failed Login','Sudo Command','su Command','PAM Event','User Session','Password Change','Account Lockout'],
    'secure': ['SSH Session','User Account Authentication','Failed Login','Sudo Command','su Command','PAM Event','User Session','Password Change','Account Lockout'],
    'sudo': ['Sudo Command','Privileged Command','Failed Sudo','User Not In Sudoers','Privilege Escalation','Command Execution'],
    'sshd': ['SSH Session','Remote Login','Failed Login','Public Key Authentication','Password Authentication','Port Forwarding','SFTP Activity'],
    'cron': ['Cron Job','Cron Job Creation','Cron Job Modification','Cron Job Execution','Scheduled Job'],
    'journald': ['Service Activity','User Account Authentication','System Boot','Command Execution','Kernel Events','System Logs'],
    'systemd': ['Systemd Service','Service Creation','Service Activity','Timer Creation','Unit File Modification','Daemon Reload','System Boot'],
    'kernel': ['Kernel Events','Kernel Module Load','Kernel Warning','Process Crash','Device Event','Network Interface','Filesystem Event'],
    'rsyslog': ['Syslog Message','Authentication Logs','Service Logs','System Logs','Application Logs'],
    'syslog-ng': ['Syslog Message','Authentication Logs','Service Logs','System Logs','Application Logs'],
    'Apache': ['HTTP Requests','HTTP Response','URL Path','Query String','User Agent','Source IP','Web Authentication','Web Error','File Request','File Upload','Web Shell Indicator'],
    'Nginx': ['HTTP Requests','HTTP Response','URL Path','Query String','User Agent','Source IP','Web Authentication','Web Error','File Request','File Upload','Reverse Proxy Activity','Web Shell Indicator'],
    'Docker': ['Container Creation','Container Start','Container Stop','Image Pull','Image Build','Exec Into Container','Volume Mount','Privileged Container','Container Network','Runtime Error'],
    'containerd': ['Container Creation','Container Start','Container Stop','Image Pull','Exec Into Container','Container Runtime Event'],
    'Podman': ['Container Creation','Container Start','Container Stop','Image Pull','Exec Into Container','Volume Mount','Privileged Container'],
    'Kubernetes Audit': ['Kubernetes API Request','Pod Creation','Pod Deletion','Exec Into Container','Secret Access','ConfigMap Access','RBAC Change','RoleBinding Created','ClusterRoleBinding Created','Service Account Use','Admission Controller Event','Namespace Activity','Deployment Change'],
    'SELinux': ['SELinux AVC','Policy Violation','Access Denial','Privilege Escalation'],
    'AppArmor': ['AppArmor Denial','Profile Violation','Policy Update','Access Denial'],
    'Falco': ['Runtime Alert','Container Escape Attempt','Reverse Shell','Sensitive File Read','Shell Spawned in Container','Privilege Escalation','Unexpected Binary Execution','Kubernetes API Request'],
    'osquery': ['Process Inventory','Process Creation','Listening Ports','Logged-in Users','File Metadata','File Hash','Package Inventory','Kernel Modules','Startup Items','Crontab Entries','User Account Metadata','Group Metadata','Network Connection Creation','Browser Extensions','Certificates','Mounts'],

    # macOS telemetry
    'Apple Unified Logging': ['Process Activity','Process Creation','Authentication Logs','Network Activity','Application Launch','System Extension Event','Security Policy Event','TCC Decision','Gatekeeper Decision','XProtect Event'],
    'OpenBSM': ['Process Creation','File Access','File Modification','User Account Authentication','Privilege Changes','User Session','System Configuration Change'],
    'launchd': ['Launch Agent Created','Launch Daemon Created','Service Loaded','Service Unloaded','Persistence Item Modified'],
    'launchctl': ['Launch Agent Created','Launch Daemon Created','Service Loaded','Service Unloaded','Persistence Item Modified'],
    'Gatekeeper': ['Downloaded File Assessment','Gatekeeper Decision','Quarantine Attribute','Security Policy Event'],
    'TCC': ['TCC Decision','Privacy Permission Grant','Camera Access','Microphone Access','Accessibility Permission','Full Disk Access'],
    'XProtect': ['XProtect Event','Malware Detection','Downloaded File Assessment'],
    'Jamf': ['MDM Event','Configuration Profile Change','Application Inventory','Policy Execution','Device Compliance'],
    'Santa': ['Application Control Decision','Blocked Execution','Allowed Execution','File Hash'],
    'Endpoint Security': ['Process Creation','Process Activity','File Access','File Modification','Network Activity','Authentication Logs','Security Policy Event'],
    'FileVault': ['Disk Encryption Event','Authentication Logs','Security Policy Event'],

    # Network and security telemetry
    'Zeek': ['Network Traffic Flow','Network Connection Creation','DNS Query','DNS Response','HTTP Requests','HTTP Response','TLS SNI','TLS Certificate','X.509 Certificate','SMB Session','SMB File Access','File Transfer','FTP Activity','SSH Session','RDP Session','Kerberos Authentication','NTLM Authentication','DHCP Lease','Software Identification','User Agent','JA3 Fingerprint','Notice Alert','Intel Match','Tunnel Activity','SMTP Activity'],
    'Suricata': ['IDS Alerts','Network Traffic Content','Network Traffic Flow','DNS Query','HTTP Requests','HTTP Response','TLS SNI','TLS Certificate','SMB Session','File Transfer','Exploit Attempt','Malware Callback','C2 Beaconing','Protocol Anomaly','Signature Match','EVE Flow','Fileinfo Event'],
    'Packetbeat': ['Network Traffic Flow','DNS Query','HTTP Requests','TLS SNI','SMB Session','Database Query','Application Protocol Metadata'],
    'NetFlow': ['Network Traffic Flow','Allowed Connection','Connection Metadata','Source IP','Destination IP','Port','Protocol'],
    'IPFIX': ['Network Traffic Flow','Allowed Connection','Connection Metadata','Source IP','Destination IP','Port','Protocol'],
    'Cisco ASA': ['Firewall Events','Allowed Connection','Denied Connection','Network Traffic Flow','NAT Translation','VPN Session','VPN Authentication','ACL Decision','Remote Access','Connection Teardown','Threat Alert'],
    'Cisco IOS': ['Network Device Logs','Network Device Authentication','Configuration Change','Interface Status','Routing Event','ACL Decision','SNMP Activity','NetFlow Export','Administrative Login','Command Execution'],
    'Cisco NX-OS': ['Network Device Logs','Network Device Authentication','Configuration Change','Interface Status','Routing Event','ACL Decision','SNMP Activity','NetFlow Export','Administrative Login','Command Execution'],
    'Cisco Firepower': ['Firewall Events','IDS Alerts','Threat Alert','Allowed Connection','Denied Connection','Network Traffic Flow','DNS Query','HTTP Requests','TLS SNI','SMB Session','File Transfer','Exploit Attempt','Malware Callback'],
    'Palo Alto': ['Firewall Events','Allowed Connection','Denied Connection','Threat Alert','URL Filtering','DNS Security Event','VPN Session','VPN Authentication','NAT Translation','Application Identification','TLS Inspection','IPS Alert','Malware Detection','User-ID Mapping'],
    'Fortinet': ['Firewall Events','Allowed Connection','Denied Connection','Threat Alert','URL Filtering','DNS Security Event','VPN Session','VPN Authentication','NAT Translation','Application Identification','TLS Inspection','IPS Alert','Malware Detection'],
    'Check Point': ['Firewall Events','Allowed Connection','Denied Connection','Threat Alert','URL Filtering','VPN Session','VPN Authentication','NAT Translation','Application Identification','TLS Inspection','IPS Alert','Malware Detection'],
    'SonicWall': ['Firewall Events','Allowed Connection','Denied Connection','Threat Alert','VPN Session','VPN Authentication','NAT Translation','Application Identification','IPS Alert'],
    'pfSense': ['Firewall Events','Allowed Connection','Denied Connection','VPN Session','VPN Authentication','NAT Translation','DNS Query','DHCP Lease'],
    'OPNsense': ['Firewall Events','Allowed Connection','Denied Connection','VPN Session','VPN Authentication','NAT Translation','DNS Query','DHCP Lease'],
    'Squid': ['HTTP Requests','HTTP Response','URL Filtering','User Agent','Source IP','Web Authentication','File Request'],
    'HAProxy': ['HTTP Requests','HTTP Response','Load Balancer Event','TLS SNI','Source IP','Connection Metadata'],
    'F5': ['HTTP Requests','HTTP Response','Load Balancer Event','TLS SNI','Source IP','Application Security Event','WAF Alert'],
    'DNS': ['DNS Query','DNS Response','DNS Zone Change','DNS Security Event'],
    'DHCP': ['DHCP Lease','DHCP Release','Network Configuration'],
    'VPN': ['VPN Session','VPN Authentication','Remote Access','User Account Authentication','Network Connection Creation'],
    'Wireless Controller': ['Wireless Authentication','Wireless Association','Wireless Roaming','Device Association','Network Connection Creation'],
}

# Additional aliases for richer log-source discovery.  These map strings seen in
# syslog payloads, event channels, Zeek/Suricata file names, and product banners
# to canonical source names used by the coverage engine.
LOG_SOURCE_ALIASES.update({
    'security.evtx': 'Windows Security', 'microsoft-windows-security-auditing': 'Windows Security', 'event id 4624': 'Windows Security', 'eventid 4624': 'Windows Security', 'event id 4625': 'Windows Security', 'eventid 4625': 'Windows Security',
    'system.evtx': 'Windows System', 'windows system': 'Windows System', 'application.evtx': 'Windows Application', 'windows application': 'Windows Application',
    'microsoft-windows-sysmon': 'Sysmon', 'sysmon event id': 'Sysmon', 'powershell/operational': 'PowerShell Operational Log', 'script block': 'PowerShell Operational Log', 'module logging': 'PowerShell Operational Log',
    'microsoft-windows-windows defender': 'Defender', 'microsoft defender for endpoint': 'Defender for Endpoint', 'mde': 'Defender for Endpoint', 'advanced hunting': 'Defender for Endpoint',
    'winrm': 'WinRM', 'windows remote management': 'WinRM', 'wmi': 'WMI', 'wmiprvse': 'WMI', 'task scheduler': 'Task Scheduler', 'scheduledtasks': 'Task Scheduler',
    'windows firewall': 'Windows Firewall', 'applocker': 'AppLocker', 'rdp': 'RDP', 'terminalservices': 'RDP', 'active directory': 'Active Directory', 'ntds': 'Active Directory', 'ldap': 'Active Directory', 'ad cs': 'Certificate Services', 'certsvc': 'Certificate Services',
    'auth.log': 'auth.log', '/var/log/auth': 'auth.log', '/var/log/secure': 'secure', 'sshd': 'sshd', 'sudo:': 'sudo', 'sudo[': 'sudo', 'cron': 'cron', 'crond': 'cron', 'systemd[': 'systemd', 'kernel:': 'kernel', 'audit:': 'auditd', 'type=execve': 'auditd', 'type=avc': 'SELinux', 'apparmor': 'AppArmor',
    'apache': 'Apache', 'httpd': 'Apache', 'nginx': 'Nginx', 'docker': 'Docker', 'containerd': 'containerd', 'podman': 'Podman', 'kubernetes audit': 'Kubernetes Audit', 'k8s audit': 'Kubernetes Audit', 'falco': 'Falco',
    'apple unified logging': 'Apple Unified Logging', 'unified log': 'Apple Unified Logging', 'launchd': 'launchd', 'launchctl': 'launchctl', 'gatekeeper': 'Gatekeeper', 'xprotect': 'XProtect', 'jamf': 'Jamf', 'santa': 'Santa', 'endpoint security': 'Endpoint Security', 'filevault': 'FileVault',
    'conn.log': 'Zeek', 'dns.log': 'Zeek', 'http.log': 'Zeek', 'ssl.log': 'Zeek', 'x509.log': 'Zeek', 'files.log': 'Zeek', 'smb.log': 'Zeek', 'kerberos.log': 'Zeek', 'ssh.log': 'Zeek', 'ntlm.log': 'Zeek', 'rdp.log': 'Zeek', 'notice.log': 'Zeek', 'weird.log': 'Zeek',
    'suricata eve': 'Suricata', 'eve.json': 'Suricata', 'suricata alert': 'Suricata', 'cisco asa': 'Cisco ASA', 'asa-': 'Cisco ASA', 'cisco ios': 'Cisco IOS', 'nx-os': 'Cisco NX-OS', 'firepower': 'Cisco Firepower', 'palo alto': 'Palo Alto', 'pan-os': 'Palo Alto', 'fortigate': 'Fortinet', 'fortinet': 'Fortinet', 'checkpoint': 'Check Point', 'check point': 'Check Point', 'sonicwall': 'SonicWall', 'pfsense': 'pfSense', 'opnsense': 'OPNsense', 'squid': 'Squid', 'haproxy': 'HAProxy', 'f5': 'F5', 'big-ip': 'F5', 'wireless controller': 'Wireless Controller',
})

SOURCE_CATEGORY.update({
    **{s: 'Windows' for s in ['Windows Security','Windows System','Windows Application','WinRM','WMI','SMB','Windows DNS','Windows DHCP','IIS','Task Scheduler','Windows Firewall','AppLocker','RDP','Active Directory','Certificate Services','Defender for Endpoint']},
    **{s: 'Linux' for s in ['auth.log','secure','sudo','sshd','cron','journald','systemd','kernel','Apache','Nginx','Docker','containerd','Podman','Kubernetes Audit','SELinux','AppArmor','Falco']},
    **{s: 'macOS' for s in ['launchd','launchctl','Gatekeeper','TCC','XProtect','Jamf','Santa','Endpoint Security','FileVault']},
    **{s: 'Network' for s in ['Cisco ASA','Cisco IOS','Cisco NX-OS','Cisco Firepower','Palo Alto','Fortinet','Check Point','SonicWall','pfSense','OPNsense','Squid','HAProxy','F5','DNS','DHCP','VPN','Wireless Controller']},
})

for _src, _components in RICH_TELEMETRY_CAPABILITY_REGISTRY.items():
    _base = list(SOURCE_COMPONENTS.get(_src, []) or [])
    for _component in _components:
        if _component not in _base:
            _base.append(_component)
    SOURCE_COMPONENTS[_src] = _base

# Fill in missing component backfills for common richer telemetry phrases. These
# are only used when the selected bundled STIX data source set is incomplete; if
# the official STIX bundle has x_mitre_data_sources, the STIX matches win.
COMPONENT_TECHNIQUES.update({
    'execve': ['T1059.004','T1059.006','T1059.003'], 'chmod': ['T1222.002'], 'setuid': ['T1548.001'], 'setgid': ['T1548.001'], 'ptrace': ['T1055','T1003.001'],
    'Remote Shell': ['T1021','T1059','T1059.001'], 'Remote Command': ['T1021','T1059','T1047'], 'WMI Query': ['T1047','T1082','T1057'], 'Remote WMI': ['T1047','T1021'], 'WMI Process Creation': ['T1047','T1059'],
    'Scheduled Job Creation': ['T1053','T1053.005','T1053.003'], 'Scheduled Job Modification': ['T1053'], 'Scheduled Job Deletion': ['T1070','T1053'], 'Scheduled Job Execution': ['T1053'],
    'Firewall Rule Change': ['T1562.004'], 'Firewall Profile Change': ['T1562.004'], 'Blocked Execution': ['T1204','T1059'], 'Allowed Execution': ['T1204','T1059'],
    'LDAP Query': ['T1087.002','T1069.002','T1482'], 'Directory Service Access': ['T1087.002','T1069.002','T1482'], 'Active Directory Object Modification': ['T1098','T1484.001'], 'Group Policy Change': ['T1484.001'], 'Replication Activity': ['T1003.006'], 'SPN Query': ['T1558.003'],
    'Certificate Enrollment': ['T1649','T1553.004'], 'Certificate Request': ['T1649','T1553.004'], 'Certificate Issuance': ['T1553.004'], 'Certificate Template Change': ['T1484','T1553.004'],
    'Failed Login': ['T1110','T1078'], 'Public Key Authentication': ['T1078','T1021.004'], 'Password Authentication': ['T1078','T1110','T1021.004'], 'Port Forwarding': ['T1090','T1021.004'], 'SFTP Activity': ['T1048','T1105'],
    'Cron Job Creation': ['T1053.003'], 'Cron Job Modification': ['T1053.003'], 'Cron Job Execution': ['T1053.003'], 'Timer Creation': ['T1053'], 'Unit File Modification': ['T1543.002','T1053'], 'Daemon Reload': ['T1543.002'],
    'AppArmor Denial': ['T1562.001','T1068'], 'Policy Violation': ['T1562.001'], 'Access Denial': ['T1562.001'], 'Runtime Alert': ['T1059','T1611','T1610'], 'Reverse Shell': ['T1059','T1105','T1071'],
    'Launch Agent Created': ['T1543.001'], 'Launch Daemon Created': ['T1543.004'], 'Service Loaded': ['T1543'], 'Service Unloaded': ['T1562.001'], 'Persistence Item Modified': ['T1543','T1547'],
    'TCC Decision': ['T1548','T1562.001'], 'Privacy Permission Grant': ['T1548','T1113','T1123'], 'Quarantine Attribute': ['T1553.001','T1222.002'], 'Downloaded File Assessment': ['T1204','T1189'],
    'Notice Alert': ['T1046','T1071','T1041'], 'Intel Match': ['T1071','T1105'], 'Tunnel Activity': ['T1090','T1572'], 'SMTP Activity': ['T1071.003','T1566'], 'EVE Flow': ['T1046','T1049','T1071'], 'Fileinfo Event': ['T1105','T1041'],
    'Wireless Authentication': ['T1078','T1110'], 'Wireless Association': ['T1016','T1049'], 'Device Association': ['T1016','T1049'], 'WAF Alert': ['T1190','T1505.003'], 'Application Security Event': ['T1190','T1505.003'],
})

_PRE_RICH_SOURCE_STIX_MATCHES = _source_stix_matches

def _source_stix_matches(source):
    """Resolve detected source capabilities through STIX data-source metadata.

    For official STIX bundles with populated x_mitre_data_sources, those matches
    are authoritative.  Bundled/offline compatibility bundles may have sparse
    data-source metadata, so a local component compatibility backfill is used
    only when no STIX technique match exists for a detected source component.
    """
    source = _canon_source_name(source) or source
    match = _PRE_RICH_SOURCE_STIX_MATCHES(source)
    if match.get('techniques'):
        return match
    components = list(dict.fromkeys(SOURCE_COMPONENTS.get(source, []) or []))
    techniques = set()
    data_components = set(match.get('data_components') or [])
    attack_sources = set(match.get('attack_data_sources') or [])
    for comp in components:
        data_components.add(comp)
        attack_sources.update(_attck_data_sources_for_component(comp))
        comp_norm = _norm_attack_string(comp)
        for known, tids in COMPONENT_TECHNIQUES.items():
            if _norm_attack_string(known) == comp_norm or comp_norm in _norm_attack_string(known) or _norm_attack_string(known) in comp_norm:
                techniques.update(tids or [])
    return {'source': source, 'data_components': sorted(data_components), 'attack_data_sources': sorted(attack_sources), 'techniques': {tid for tid in techniques if tid in VALID_TECHNIQUES}}


def telemetry_capability_assessment(result, coverage_engine=None):
    """Return observed and potential telemetry coverage details for reports/UI."""
    result = result or {}
    engine = coverage_engine_from_result(result, coverage_engine)
    detected = sorted(set(_canon_source_name(s) or s for s in detected_data_sources(result)))
    applicable = set((build_enterprise_attack_coverage_model({**result, 'coverage_engine': engine}, [], engine) or {}).get('applicable_ids') or [])
    observed_cov = build_data_source_coverage({**result, 'coverage_engine': engine}, engine)
    observed_ids = {x.get('techniqueID') for x in observed_cov if x.get('techniqueID') in applicable}
    product_rows = []
    potential_ids = set(observed_ids)
    for source in detected:
        comps = list(dict.fromkeys(RICH_TELEMETRY_CAPABILITY_REGISTRY.get(source) or SOURCE_COMPONENTS.get(source, []) or []))
        observed_components = set(SOURCE_COMPONENTS.get(source, []) or [])
        record = {'source': source, 'components': comps, 'category': SOURCE_CATEGORY.get(source, 'Other'), 'confidence': 'medium', 'basis': 'potential full product configuration', 'inferred': True}
        match = _match_capability_record_to_attack(record)
        tids = set(match.get('techniques') or []) & applicable
        potential_ids.update(tids)
        extra_tids = sorted(tids - observed_ids)
        product_rows.append({
            'source': source,
            'category': SOURCE_CATEGORY.get(source, 'Other'),
            'observed_components': sorted(observed_components),
            'potential_components': sorted(set(comps)),
            'additional_components': sorted(set(comps) - observed_components),
            'attack_data_sources': match.get('attack_data_sources') or [],
            'potential_techniques': sorted(tids),
            'additional_techniques': extra_tids[:50],
            'additional_technique_count': len(extra_tids),
            'recommendation': _potential_recommendation_for_source(source, sorted(set(comps) - observed_components), len(extra_tids)),
        })
    denominator = len(applicable)
    return {
        'coverage_engine': engine,
        'attack_version': ATTACK_DATASET_METADATA.get('version', ATTACK_VERSION),
        'detected_log_sources': detected,
        'applicable_technique_count': denominator,
        'observed_telemetry_technique_count': len(observed_ids),
        'potential_technique_count': len(potential_ids),
        'observed_telemetry_score': round((len(observed_ids) / denominator) * 100, 1) if denominator else 0,
        'potential_score': round((len(potential_ids) / denominator) * 100, 1) if denominator else 0,
        'potential_increase_score': round(((len(potential_ids) - len(observed_ids)) / denominator) * 100, 1) if denominator else 0,
        'potential_increase_techniques': max(0, len(potential_ids) - len(observed_ids)),
        'product_rows': sorted(product_rows, key=lambda r: (-r.get('additional_technique_count', 0), r.get('category',''), r.get('source',''))),
    }


def _potential_recommendation_for_source(source, missing_components, extra_count):
    if not missing_components and extra_count <= 0:
        return 'Observed telemetry already exposes the major known capabilities for this source.'
    examples = ', '.join((missing_components or [])[:6])
    if source in {'Sysmon','Defender for Endpoint','Defender','PowerShell Operational Log'}:
        return f'Validate collection/configuration for {examples or "advanced endpoint telemetry"}; this could add approximately {extra_count} ATT&CK techniques.'
    if source in {'Zeek','Suricata','Packetbeat'}:
        return f'Enable and retain protocol logs such as {examples or "DNS, HTTP, TLS, SMB, files, and alerts"}; this could add approximately {extra_count} ATT&CK techniques.'
    if SOURCE_CATEGORY.get(source) == 'Network':
        return f'Confirm forwarding for {examples or "VPN, firewall, DNS, and traffic-flow events"}; this could add approximately {extra_count} ATT&CK techniques.'
    return f'Confirm parser coverage and forwarding for {examples or "the listed telemetry capabilities"}; this could add approximately {extra_count} ATT&CK techniques.'

def _attck_data_sources_for_component(component):
    ds_hint, comp_hint = _split_attack_data_source(str(component or ''))
    if ds_hint and ds_hint != comp_hint:
        return [ds_hint]
    c = str(component or '').lower()
    if any(x in c for x in ['process','command','script','powershell','shell','module','driver']): return ['Process']
    if any(x in c for x in ['file','directory','hash','web shell','upload','download']): return ['File']
    if 'registry' in c: return ['Windows Registry']
    if any(x in c for x in ['dns','http','tls','smb','ssh','rdp','flow','connection','traffic','vpn','firewall','netflow','ipfix','wireless']): return ['Network Traffic']
    if any(x in c for x in ['authentication','logon','login','account','kerberos','ntlm','credential','sudo','pam']): return ['User Account']
    if any(x in c for x in ['service','systemd','launch','scheduled','cron','task']): return ['Service']
    if any(x in c for x in ['container','kubernetes','pod']): return ['Container']
    if any(x in c for x in ['cloud','iam']): return ['Cloud Service']
    return ['Telemetry']

# Potential-only capabilities are not part of strict theoretical heat-map
# coverage. They represent additional event classes or product modules that may
# exist but were not directly established by the detected log type in this job.
POTENTIAL_ONLY_COMPONENTS = {
    'Sysmon': ['Process Tampering','File Delete Archived','DNS Query Enrichment','Pipe Connected','Image Load Hashes','Process Memory Indicator'],
    'Defender': ['Exploit Guard','Advanced Hunting Alert','Behavioral Alert','Cloud Delivered Protection','Network Protection','EDR Block Mode'],
    'Defender for Endpoint': ['Advanced Hunting Alert','Behavioral Alert','Memory Protection','Exploit Guard','EDR Sensor Alert','DeviceTvmSoftwareEvidence','DeviceRegistryEvents','DeviceImageLoadEvents'],
    'Zeek': ['Zeek Intel Match','Zeek Weird','Zeek Notice','Zeek Tunnel','Zeek SMTP','Zeek RFB','Zeek SIP','Zeek Software Inventory'],
    'Suricata': ['Suricata Anomaly','Suricata Flowbit','Suricata JA3','Suricata File Extraction','Suricata Dataset Match'],
    'Windows Security': ['Detailed File Share','Detailed File Access','Audit Policy Change','Filtering Platform Packet Drop','Certificate Services Audit','Directory Service Replication'],
    'auditd': ['Audit Rule Watch','Audit Syscall Raw','Audit Netfilter','Audit Integrity','Audit AVC Extended'],
    'Kubernetes Audit': ['Admission Controller Decision','Impersonation Event','TokenReview Event','SubjectAccessReview Event','PodSecurity Event'],
    'Palo Alto': ['WildFire Alert','Threat Prevention Alert','DNS Security Alert','Decryption Event','User-ID Login Event'],
    'Fortinet': ['FortiGuard Alert','Web Filter Event','App Control Event','Sandbox Event','DLP Event'],
}
for _src, _extra in POTENTIAL_ONLY_COMPONENTS.items():
    _base = list(RICH_TELEMETRY_CAPABILITY_REGISTRY.get(_src) or SOURCE_COMPONENTS.get(_src, []) or [])
    for _comp in _extra:
        if _comp not in _base:
            _base.append(_comp)
    RICH_TELEMETRY_CAPABILITY_REGISTRY[_src] = _base
COMPONENT_TECHNIQUES.update({
    'Process Tampering': ['T1055','T1562.001'], 'File Delete Archived': ['T1070.004','T1485'], 'Process Memory Indicator': ['T1003','T1055'],
    'Advanced Hunting Alert': ['T1059','T1105','T1003','T1562.001','T1071.001'], 'Behavioral Alert': ['T1059','T1105','T1027','T1562.001'], 'Memory Protection': ['T1003','T1055'], 'EDR Sensor Alert': ['T1562.001','T1059'],
    'DeviceTvmSoftwareEvidence': ['T1518','T1518.001'], 'DeviceRegistryEvents': ['T1112','T1547.001'], 'DeviceImageLoadEvents': ['T1129','T1574'],
    'Zeek Intel Match': ['T1071','T1105'], 'Zeek Weird': ['T1571','T1095'], 'Zeek Notice': ['T1046','T1071'], 'Zeek Tunnel': ['T1090','T1572'], 'Zeek SMTP': ['T1071.003','T1566'], 'Zeek RFB': ['T1021.005'], 'Zeek SIP': ['T1123'], 'Zeek Software Inventory': ['T1518','T1518.001'],
    'Suricata Anomaly': ['T1571','T1095'], 'Suricata Flowbit': ['T1071','T1105'], 'Suricata JA3': ['T1071.001','T1573'], 'Suricata File Extraction': ['T1105','T1041'], 'Suricata Dataset Match': ['T1071','T1105'],
    'Detailed File Share': ['T1021.002','T1039','T1135'], 'Detailed File Access': ['T1005','T1083','T1039'], 'Audit Policy Change': ['T1562.002'], 'Filtering Platform Packet Drop': ['T1562.004','T1498'], 'Directory Service Replication': ['T1003.006'],
    'Audit Rule Watch': ['T1562.001','T1222.002'], 'Audit Syscall Raw': ['T1059.004','T1055'], 'Audit Netfilter': ['T1562.004'], 'Audit Integrity': ['T1036','T1027'], 'Audit AVC Extended': ['T1562.001'],
    'Admission Controller Decision': ['T1611','T1610'], 'Impersonation Event': ['T1078.004','T1098'], 'TokenReview Event': ['T1552','T1078.004'], 'SubjectAccessReview Event': ['T1613'], 'PodSecurity Event': ['T1611'],
    'WildFire Alert': ['T1105','T1071.001'], 'Threat Prevention Alert': ['T1190','T1203','T1071.001'], 'DNS Security Alert': ['T1071.004','T1568'], 'Decryption Event': ['T1573','T1071.001'], 'User-ID Login Event': ['T1078','T1110'],
    'FortiGuard Alert': ['T1190','T1071.001'], 'Web Filter Event': ['T1189','T1071.001'], 'App Control Event': ['T1071','T1046'], 'Sandbox Event': ['T1105','T1027'], 'DLP Event': ['T1041','T1567'],
})

# Load modular telemetry product plugins last so they extend all previous legacy
# aliases/components without disturbing backwards-compatible names.  The strict
# theoretical engine still requires the plugin source to be detected in the job;
# plugin potential capabilities are used for diagnostics and potential coverage.
try:
    from app.telemetry.registry import apply_registry_to_attack_globals as _apply_telemetry_plugins
    TELEMETRY_PLUGIN_SUMMARY = _apply_telemetry_plugins(globals())
except Exception as _telemetry_plugin_error:  # pragma: no cover - fail-open for old deployments
    TELEMETRY_PLUGIN_SUMMARY = {'plugin_count': 0, 'categories': {}, 'error': str(_telemetry_plugin_error)}

# Generic component-to-technique compatibility entries for modular telemetry
# plugins.  These are used only by the local compatibility backfill when the
# mounted ATT&CK STIX bundle has sparse x_mitre_data_sources for a detected
# plugin component.  Strict STIX metadata remains authoritative when present.
try:
    COMPONENT_TECHNIQUES.update({
        'SIEM Alert': ['T1059','T1071','T1105','T1110','T1562.001'],
        'Analytics Rule': ['T1059','T1071','T1105','T1110','T1562.001'],
        'Incident': ['T1059','T1071','T1105','T1110','T1562.001'],
        'Notable Event': ['T1059','T1071','T1105','T1110'],
        'Correlation Search': ['T1059','T1071','T1105','T1110'],
        'Threat Intelligence': ['T1071','T1105','T1566','T1589'],
        'Process Creation': ['T1059','T1059.001','T1059.003','T1059.004','T1106','T1047','T1053','T1543','T1055','T1569.002'],
        'Command Execution': ['T1059','T1059.001','T1059.003','T1059.004','T1047','T1106'],
        'Script Execution': ['T1059.001','T1059.003','T1059.004','T1059.005','T1027'],
        'Module Load': ['T1129','T1574','T1055'],
        'Image Load': ['T1129','T1574','T1036'],
        'Driver Load': ['T1068','T1014','T1547.006','T1562.001'],
        'File Creation': ['T1105','T1027','T1036','T1005','T1053','T1547'],
        'File Modification': ['T1112','T1222','T1070.004','T1036'],
        'File Deletion': ['T1070.004','T1485'],
        'File Metadata': ['T1083','T1005','T1039'],
        'Hash Inventory': ['T1036','T1027','T1518'],
        'Registry Key Modification': ['T1112','T1547.001','T1574.011','T1562.001'],
        'Network Connection Creation': ['T1049','T1046','T1021','T1071.001','T1071.004','T1105','T1041'],
        'DNS Query': ['T1071.004','T1568','T1046','T1016'],
        'User Account Authentication': ['T1078','T1110','T1021','T1133'],
        'Logon Session': ['T1078','T1110','T1021','T1133'],
        'Privilege Escalation': ['T1068','T1548','T1548.003','T1548.004'],
        'Service Creation': ['T1543','T1543.003','T1569.002'],
        'Scheduled Job Creation': ['T1053','T1053.003','T1053.005'],
        'Malware Detection': ['T1105','T1027','T1204','T1486'],
        'Endpoint Alert': ['T1059','T1105','T1562.001','T1003'],
        'Behavioral Alert': ['T1059','T1105','T1562.001','T1027'],
        'Network Traffic Flow': ['T1046','T1049','T1016','T1021','T1071','T1105','T1041','T1567'],
        'Network Traffic Content': ['T1071','T1105','T1041','T1567','T1203','T1190'],
        'HTTP Request': ['T1071.001','T1105','T1567','T1190','T1189'],
        'HTTP Response': ['T1071.001','T1105','T1567'],
        'TLS Connection': ['T1071.001','T1573','T1105'],
        'SMB Session': ['T1021.002','T1039','T1135','T1105'],
        'SSH Session': ['T1021.004','T1110','T1078'],
        'FTP Session': ['T1071.002','T1105','T1048'],
        'RDP Session': ['T1021.001','T1078','T1110'],
        'VPN Session': ['T1133','T1078','T1021'],
        'Firewall Events': ['T1046','T1049','T1021','T1071','T1562.004','T1498'],
        'IDS Alert': ['T1190','T1203','T1071','T1105','T1046'],
        'Protocol Anomaly': ['T1571','T1095','T1071'],
        'Cloud API': ['T1528','T1530','T1567.002','T1078.004','T1098.003','T1578'],
        'IAM Activity': ['T1078.004','T1098','T1136','T1530','T1552.005'],
        'Resource Modification': ['T1578','T1485','T1562.008'],
        'Object Storage Activity': ['T1530','T1567.002','T1078.004'],
        'Cloud Detection Alert': ['T1078.004','T1098','T1528','T1578'],
        'AssumeRole': ['T1078.004','T1098.003'],
        'Console Login': ['T1078.004','T1110'],
        'Access Key Activity': ['T1552.005','T1078.004'],
        'MFA Event': ['T1110','T1078','T1556'],
        'Conditional Access': ['T1556','T1078'],
        'Account Management': ['T1136','T1098','T1531'],
        'Group Membership': ['T1069','T1098'],
        'Email Message': ['T1566','T1566.001','T1566.002','T1114'],
        'Email Attachment': ['T1566.001','T1204.002'],
        'Email URL': ['T1566.002','T1189'],
        'Mailbox Login': ['T1078','T1110','T1114'],
        'Mailbox Rule': ['T1114.003','T1098'],
        'OAuth App Activity': ['T1528','T1550','T1098.003'],
        'SaaS Audit Log': ['T1078','T1098','T1114','T1530','T1567'],
        'File Upload': ['T1105','T1567','T1190'],
        'Web Server Logs': ['T1190','T1505.003','T1059','T1105'],
        'Web Error': ['T1190','T1505.003'],
        'Container Creation': ['T1610','T1611','T1613'],
        'Container Exec': ['T1611','T1059'],
        'Image Pull': ['T1612','T1105'],
        'Volume Mount': ['T1611','T1005'],
        'Kubernetes API': ['T1613','T1610','T1611','T1078.004'],
        'Service Account Activity': ['T1078.004','T1098.003','T1552.007'],
        'RBAC Change': ['T1098','T1078.004'],
        'Secret Access': ['T1552','T1552.007','T1530'],
        'Repository Activity': ['T1195','T1552','T1608'],
        'Pipeline Execution': ['T1195','T1059','T1105'],
        'Build Artifact': ['T1195','T1608'],
        'Webhook Activity': ['T1195','T1105'],
        'Database Authentication': ['T1078','T1110'],
        'Database Query': ['T1005','T1213'],
        'Database Object Access': ['T1005','T1213','T1530'],
        'Industrial Protocol': ['T0886','T0842','T0855'],
        'PLC Command': ['T0855','T0831','T0814'],
        'Protocol Metadata': ['T1046','T1049','T1071'],
        'Session Metadata': ['T1049','T1046','T1071'],
        'PCAP Index': ['T1049','T1046','T1071','T1105'],
        'Wireless Association': ['T1016','T1046','T1110'],
        'Wireless Authentication': ['T1078','T1110'],
        'VM Creation': ['T1578','T1098'],
        'Snapshot Activity': ['T1006','T1490','T1005'],
        'Host Login': ['T1078','T1110'],
        'Admin Activity': ['T1078','T1098','T1562'],
    })
except Exception:
    pass


# ---------------------------------------------------------------------------
# Upload-pipeline mapping hardening and color normalization patch
# ---------------------------------------------------------------------------
# Simulated PCAPs often carry ATT&CK IDs, provider/channel names, or synthetic
# telemetry product names directly inside payload text.  Ensure those observed
# signals are fed into the same source-only STIX mapping pipeline used by the
# heat maps and report exports.
_PRE_PIPELINE_ENHANCED_SOURCE_HITS = _enhanced_source_hits_from_result

def _enhanced_source_hits_from_result(result):
    sources = set(_PRE_PIPELINE_ENHANCED_SOURCE_HITS(result or {}) or [])
    result = result or {}
    def add_text(text):
        if text is None:
            return
        try:
            sources.update(_canonical_log_sources(str(text)))
        except Exception:
            pass
    for ev in result.get('normalized_events', []) or []:
        for key in ('log_source','platform','event_type','raw','message','provider','channel','transport_protocol'):
            add_text(ev.get(key, ''))
        if ev.get('log_source'):
            sources.add(_canon_source_name(ev.get('log_source')) or ev.get('log_source'))
        raw = str(ev.get('raw') or '')
        # Common simulated telemetry formats: source=Sysmon, product=Zeek, vendor=Cisco ASA, channel=Security.
        for m in re.findall(r'(?i)\b(?:source|log_source|product|provider|channel|vendor|sensor|parser)\s*[=:]\s*([A-Za-z0-9_. /+\-]+)', raw):
            add_text(m)
    for f in result.get('findings', []) or []:
        add_text(f.get('title',''))
        add_text(f.get('evidence',''))
    # If traffic itself is directly a telemetry protocol, keep it as a detected source.
    protos = result.get('protocols') or {}
    for proto in protos.keys() if isinstance(protos, dict) else []:
        add_text(proto)
    return sorted(_canon_source_name(s) or s for s in sources if s)

detected_data_sources = _enhanced_source_hits_from_result

_PRE_PIPELINE_ATTACK_ID_SET = _attack_id_set_from_result

def _attack_id_set_from_result(result):
    ids = set(_PRE_PIPELINE_ATTACK_ID_SET(result or {}) or [])
    result = result or {}
    def scan(value):
        if value is None:
            return
        try:
            for tid in re.findall(r'\bT\d{4}(?:\.\d{3})?\b', str(value), flags=re.I):
                tid = tid.upper()
                if tid in VALID_TECHNIQUES:
                    ids.add(tid)
        except Exception:
            pass
    for coll in ('normalized_events','findings','techniques'):
        for item in result.get(coll, []) or []:
            if isinstance(item, dict):
                for value in item.values():
                    scan(value)
    return ids

# Keep Navigator/report colors aligned with the web heat map request:
# observed = red, validated = yellow, covered/theoretical = green.
try:
    _PRE_COLOR_STRICT_UNIFIED_LAYER = strict_unified_coverage_layer
    _PRE_COLOR_STRICT_DATA_SOURCE_LAYER = strict_data_source_coverage_layer
except Exception:
    pass
