from pathlib import Path
import time, json
from app.config import RESULT_DIR
from app.utils import read_json, write_json
from app.attack.versioned import VALID_TECHNIQUES, VALID_TACTICS, ATTACK_TACTIC_COUNTS, ATTACK_DATASET_METADATA

# Expanded default rule library.  These rules intentionally stay within the
# app's lightweight Python/Flask/Scapy architecture: they operate on normalized
# flows and aggregate flow statistics, then map matching evidence to ATT&CK IDs.
BUILTIN_RULES = [

    # Reconnaissance - ATT&CK v18 coverage rules. These are intentionally
    # evidence-light because Reconnaissance is often pre-compromise and may be
    # visible only as DNS, HTTP/S, scanning, or mail/proxy flows in a PCAP.
    {'name':'Recon: Gather Victim Identity Information','description':'Web, mail, or directory activity may support enterprise identity-information gathering validation.','event_type':'flow','protocol_any':['HTTP','HTTPS','HTTP Alt','HTTPS Alt','SMTP','SMTPS','IMAP','IMAPS','LDAP','LDAP GC'],'severity':'low','confidence':'medium','attack':['T1589','T1589.001','T1589.002','T1589.003'],'rule_type':'network'},
    {'name':'Recon: Gather Victim Network Information','description':'DNS, LDAP, SMB, SNMP, NetFlow, IPFIX, or scan activity may support network-information gathering validation.','event_type':'flow','protocol_any':['DNS','LDAP','LDAP GC','SMB','SNMP','NetFlow','IPFIX','sFlow'],'severity':'low','confidence':'medium','attack':['T1590','T1590.001','T1590.002','T1590.003','T1590.004','T1590.005','T1590.006'],'rule_type':'network'},
    {'name':'Recon: Gather Victim Organization Information','description':'Web and mail traffic may support organization-information reconnaissance validation.','event_type':'flow','protocol_any':['HTTP','HTTPS','HTTP Alt','HTTPS Alt','SMTP','SMTPS','IMAP','IMAPS'],'severity':'low','confidence':'medium','attack':['T1591','T1591.001','T1591.002','T1591.003','T1591.004'],'rule_type':'network'},
    {'name':'Recon: Gather Victim Host Information','description':'Endpoint, management, and service-enumeration traffic may support host-information gathering validation.','event_type':'flow','protocol_any':['SMB','SSH','RDP','WinRM','WinRM TLS','SNMP','HTTP','HTTPS','Elastic Beats','Syslog','Syslog TLS'],'severity':'low','confidence':'medium','attack':['T1592','T1592.001','T1592.002','T1592.003','T1592.004'],'rule_type':'network'},
    {'name':'Recon: Search Open Websites and Domains','description':'HTTP/S or DNS activity may support open website/domain reconnaissance validation.','event_type':'flow','protocol_any':['HTTP','HTTPS','HTTP Alt','HTTPS Alt','DNS'],'severity':'low','confidence':'medium','attack':['T1593','T1593.001','T1593.002','T1593.003'],'rule_type':'network'},
    {'name':'Recon: Search Victim-Owned Websites','description':'HTTP/S traffic toward web services may support victim-owned website reconnaissance validation.','event_type':'flow','protocol_any':['HTTP','HTTPS','HTTP Alt','HTTPS Alt'],'severity':'low','confidence':'medium','attack':['T1594'],'rule_type':'network'},
    {'name':'Recon: Active Scanning','description':'A source contacted many hosts or ports, supporting active scanning reconnaissance validation.','aggregate':'port_scan','threshold':20,'severity':'medium','confidence':'high','attack':['T1595','T1595.001','T1595.002','T1595.003'],'rule_type':'network'},
    {'name':'Recon: Search Open Technical Databases','description':'DNS, HTTP/S, TLS, and scan-database-like traffic may support open technical database reconnaissance validation.','event_type':'flow','protocol_any':['DNS','HTTP','HTTPS','HTTP Alt','HTTPS Alt','TLS'],'severity':'low','confidence':'medium','attack':['T1596','T1596.001','T1596.002','T1596.003','T1596.004','T1596.005'],'rule_type':'network'},
    {'name':'Recon: Search Closed Sources','description':'Threat-intelligence, paid data, or closed-source lookup activity is approximated by external web/API flows in PCAP evidence.','event_type':'flow','protocol_any':['HTTP','HTTPS','HTTP Alt','HTTPS Alt'],'destination_is_external':True,'severity':'low','confidence':'low','attack':['T1597','T1597.001','T1597.002'],'rule_type':'network'},
    {'name':'Recon: Phishing for Information','description':'Mail and web flows may support phishing-for-information validation when correlated with enterprise evidence.','event_type':'flow','protocol_any':['SMTP','SMTPS','IMAP','IMAPS','POP3','POP3S','HTTP','HTTPS'],'severity':'medium','confidence':'medium','attack':['T1598','T1598.001','T1598.002','T1598.003'],'rule_type':'network'},


    # Resource Development - ATT&CK v18 coverage rules.  These are intentionally
    # telemetry/network oriented because Resource Development is usually external
    # to the enterprise.  They validate when corresponding proxy, DNS, HTTP/S,
    # mail, TLS, cloud, or network telemetry is present in analyzed captures.
    {'name':'Resource Development: Acquire Access','description':'External broker, marketplace, VPN, or remote-access related traffic can support Acquire Access coverage validation.','event_type':'flow','protocol_any':['HTTP','HTTPS','HTTP Alt','HTTPS Alt','RDP','SSH','WinRM','VPN','OpenVPN','WireGuard'],'destination_is_external':True,'severity':'low','confidence':'low','attack':['T1650'],'rule_type':'network'},
    {'name':'Resource Development: Acquire Infrastructure','description':'DNS, HTTP/S, TLS, cloud, serverless, advertising, and VPS-provider traffic can support acquired-infrastructure coverage.','event_type':'flow','protocol_any':['DNS','HTTP','HTTPS','HTTP Alt','HTTPS Alt','TLS','Proxy','OpenVPN','WireGuard'],'destination_is_external':True,'severity':'low','confidence':'medium','attack':['T1583','T1583.001','T1583.002','T1583.003','T1583.004','T1583.005','T1583.006','T1583.007','T1583.008'],'rule_type':'network'},
    {'name':'Resource Development: Compromise Accounts','description':'External web, mail, and cloud-service authentication flows can support compromised-account resource-development coverage.','event_type':'flow','protocol_any':['HTTP','HTTPS','HTTP Alt','HTTPS Alt','SMTP','SMTPS','IMAP','IMAPS','POP3','POP3S'],'destination_is_external':True,'severity':'low','confidence':'medium','attack':['T1586','T1586.001','T1586.002','T1586.003'],'rule_type':'network'},
    {'name':'Resource Development: Compromise Infrastructure','description':'Scanning, DNS, HTTP/S, and network-device management flows can support compromised-infrastructure coverage validation.','event_type':'flow','protocol_any':['DNS','HTTP','HTTPS','HTTP Alt','HTTPS Alt','SSH','SNMP','RDP','SMB','TLS'],'destination_is_external':True,'severity':'low','confidence':'medium','attack':['T1584','T1584.001','T1584.002','T1584.003','T1584.004','T1584.005','T1584.006','T1584.007','T1584.008'],'rule_type':'network'},
    {'name':'Resource Development: Develop Capabilities','description':'Outbound developer, repository, certificate, and vulnerability-research traffic can support developed-capability coverage validation.','event_type':'flow','protocol_any':['HTTP','HTTPS','HTTP Alt','HTTPS Alt','TLS','DNS'],'destination_is_external':True,'severity':'low','confidence':'low','attack':['T1587','T1587.001','T1587.002','T1587.003','T1587.004'],'rule_type':'detection'},
    {'name':'Resource Development: Establish Accounts','description':'External web, mail, SaaS, and cloud-account traffic can support established-account coverage validation.','event_type':'flow','protocol_any':['HTTP','HTTPS','HTTP Alt','HTTPS Alt','SMTP','SMTPS','IMAP','IMAPS','POP3','POP3S'],'destination_is_external':True,'severity':'low','confidence':'medium','attack':['T1585','T1585.001','T1585.002','T1585.003'],'rule_type':'network'},
    {'name':'Resource Development: Generate Content','description':'External web, SaaS, AI, and media/content-service traffic can support generated-content coverage validation.','event_type':'flow','protocol_any':['HTTP','HTTPS','HTTP Alt','HTTPS Alt'],'destination_is_external':True,'severity':'low','confidence':'low','attack':['T1683','T1683.001','T1683.002'],'rule_type':'detection'},
    {'name':'Resource Development: Obtain Capabilities','description':'Downloads from external web, repository, vulnerability, certificate, tool, malware-analysis, or AI services can support obtained-capability coverage.','event_type':'flow','protocol_any':['HTTP','HTTPS','HTTP Alt','HTTPS Alt','TLS','DNS'],'destination_is_external':True,'severity':'low','confidence':'medium','attack':['T1588','T1588.001','T1588.002','T1588.003','T1588.004','T1588.005','T1588.006','T1588.007'],'rule_type':'network'},
    {'name':'Resource Development: Stage Capabilities','description':'Outbound HTTP/S uploads, TLS setup, link-target, SEO, and staging-service flows can support staged-capability coverage validation.','event_type':'flow','protocol_any':['HTTP','HTTPS','HTTP Alt','HTTPS Alt','TLS','Proxy'],'destination_is_external':True,'severity':'medium','confidence':'medium','attack':['T1608','T1608.001','T1608.002','T1608.003','T1608.004','T1608.005','T1608.006'],'rule_type':'network'},


    # Initial Access - ATT&CK v18 TA0001 coverage rules.  These rules are
    # intentionally network/telemetry oriented so PCAP-derived flows can
    # validate Initial Access coverage without requiring endpoint agents.
    {'name':'Initial Access: Content Injection','description':'HTTP/S, TLS, or proxy traffic can support validation for malicious content injection through network traffic.','event_type':'flow','protocol_any':['HTTP','HTTPS','HTTP Alt','HTTPS Alt','TLS','Proxy'],'severity':'medium','confidence':'medium','attack':['T1659'],'rule_type':'network'},
    {'name':'Initial Access: Drive-by Compromise','description':'External web and DNS activity can support validation for drive-by compromise exposure.','event_type':'flow','protocol_any':['HTTP','HTTPS','HTTP Alt','HTTPS Alt','TLS','DNS'],'destination_is_external':True,'severity':'medium','confidence':'medium','attack':['T1189'],'rule_type':'network'},
    {'name':'Initial Access: Exploit Public-Facing Application','description':'Web service traffic can support validation for public-facing application exploitation attempts.','event_type':'flow','protocol_any':['HTTP','HTTPS','HTTP Alt','HTTPS Alt'],'severity':'high','confidence':'medium','attack':['T1190'],'rule_type':'network'},
    {'name':'Initial Access: External Remote Services','description':'Remote access service traffic can support validation for external remote service access paths.','event_type':'flow','protocol_any':['RDP','SSH','WinRM','WinRM TLS','VNC','OpenVPN','WireGuard','VPN','HTTPS'],'severity':'high','confidence':'medium','attack':['T1133'],'rule_type':'network'},
    {'name':'Initial Access: Hardware Additions','description':'New device, network management, DHCP, mDNS, or hardware-adjacent traffic can support validation for hardware-addition access paths.','event_type':'flow','protocol_any':['DHCP','mDNS','DNS','SNMP','SMB','HTTP','HTTPS'],'severity':'medium','confidence':'low','attack':['T1200'],'rule_type':'network'},
    {'name':'Initial Access: Phishing Delivery','description':'Mail, web, and third-party service traffic can support validation for phishing delivery paths and sub-techniques.','event_type':'flow','protocol_any':['SMTP','SMTPS','IMAP','IMAPS','POP3','POP3S','HTTP','HTTPS','HTTP Alt','HTTPS Alt'],'severity':'high','confidence':'medium','attack':['T1566','T1566.001','T1566.002','T1566.003','T1566.004'],'rule_type':'network'},
    {'name':'Initial Access: Replication Through Removable Media','description':'Endpoint telemetry, SMB, or system logging flows can support validation for removable-media replication scenarios.','event_type':'flow','protocol_any':['SMB','Elastic Beats','Syslog','Syslog TLS','WinRM','WinRM TLS'],'severity':'medium','confidence':'low','attack':['T1091'],'rule_type':'detection'},
    {'name':'Initial Access: Supply Chain Compromise','description':'External update, repository, certificate, dependency, and web service traffic can support validation for supply-chain compromise and sub-techniques.','event_type':'flow','protocol_any':['HTTP','HTTPS','HTTP Alt','HTTPS Alt','TLS','DNS'],'destination_is_external':True,'severity':'high','confidence':'medium','attack':['T1195','T1195.001','T1195.002','T1195.003'],'rule_type':'detection'},
    {'name':'Initial Access: Trusted Relationship','description':'Remote access, managed service, VPN, SSH, RDP, WinRM, or partner web flows can support validation for trusted-relationship access paths.','event_type':'flow','protocol_any':['HTTPS','RDP','SSH','WinRM','WinRM TLS','OpenVPN','WireGuard','VPN'],'severity':'high','confidence':'medium','attack':['T1199'],'rule_type':'network'},
    {'name':'Initial Access: Valid Accounts','description':'Authentication and remote service flows can support validation for abuse of valid accounts and account sub-types.','event_type':'flow','protocol_any':['Kerberos','LDAP','LDAP GC','SMB','SSH','RDP','WinRM','WinRM TLS','HTTPS','OpenVPN','WireGuard'],'severity':'high','confidence':'high','attack':['T1078','T1078.001','T1078.002','T1078.003','T1078.004'],'rule_type':'detection'},
    {'name':'Initial Access: Wi-Fi Networks','description':'Wireless-adjacent DHCP, DNS, mDNS, SNMP, captive portal, or management traffic can support validation for Wi-Fi network access paths.','event_type':'flow','protocol_any':['DHCP','DNS','mDNS','SNMP','HTTP','HTTPS','TLS'],'severity':'medium','confidence':'low','attack':['T1669'],'rule_type':'network'},

    # Execution - ATT&CK v18 TA0002 coverage rules. These rules are
    # telemetry/network oriented so PCAP-derived flows can validate Execution
    # coverage while keeping observed behavior separate from theoretical coverage.
    {'name': 'Execution: BITS Jobs', 'description': 'Windows telemetry or outbound web/TLS traffic can validate BITS job execution coverage.', 'event_type': 'flow', 'protocol_any': ['HTTP', 'HTTPS', 'HTTP Alt', 'HTTPS Alt', 'TLS', 'Elastic Beats', 'WinRM', 'WinRM TLS'], 'severity': 'medium', 'confidence': 'medium', 'attack': ['T1197'], 'rule_type': 'detection', 'requires': ['Windows Event Log']},
    {'name': 'Execution: Cloud Administration Command and APIs', 'description': 'Cloud management, API, serverless, and external web/TLS traffic can validate cloud command execution coverage.', 'event_type': 'flow', 'protocol_any': ['HTTP', 'HTTPS', 'HTTP Alt', 'HTTPS Alt', 'TLS', 'DNS'], 'destination_is_external': True, 'severity': 'medium', 'confidence': 'medium', 'attack': ['T1651', 'T1059.009', 'T1648'], 'rule_type': 'detection', 'requires': ['Network Traffic']},
    {'name': 'Execution: Windows Command and Script Interpreters', 'description': 'Windows telemetry, PowerShell, WinRM, or remote management flows can validate Windows command/script execution coverage.', 'event_type': 'flow', 'protocol_any': ['WinRM', 'WinRM TLS', 'Elastic Beats', 'SMB', 'RDP'], 'severity': 'high', 'confidence': 'high', 'attack': ['T1059', 'T1059.001', 'T1059.003', 'T1059.005', 'T1059.010'], 'rule_type': 'detection', 'requires': ['Windows Event Log']},
    {'name': 'Execution: Unix and Cross-Platform Script Interpreters', 'description': 'SSH, syslog, audit, or endpoint forwarding can validate Unix shell and interpreter execution coverage.', 'event_type': 'flow', 'protocol_any': ['SSH', 'Syslog', 'Syslog TLS', 'Elastic Beats'], 'severity': 'high', 'confidence': 'high', 'attack': ['T1059.002', 'T1059.004', 'T1059.006', 'T1059.007', 'T1059.011'], 'rule_type': 'detection', 'requires': ['Network Traffic']},
    {'name': 'Execution: Network, Hypervisor, and Container CLI/API', 'description': 'Management-plane traffic for network devices, hypervisors, Kubernetes, Docker, or container APIs can validate CLI/API execution coverage.', 'event_type': 'flow', 'protocol_any': ['SSH', 'HTTPS', 'HTTP', 'HTTP Alt', 'HTTPS Alt', 'TLS', 'SNMP', 'Elastic Beats'], 'severity': 'high', 'confidence': 'medium', 'attack': ['T1059.008', 'T1059.012', 'T1059.013', 'T1609', 'T1610', 'T1675'], 'rule_type': 'network', 'requires': ['Network Traffic']},
    {'name': 'Execution: Client and User-Driven Execution', 'description': 'External web, mail, download, and endpoint telemetry can validate client exploitation and user execution coverage.', 'event_type': 'flow', 'protocol_any': ['HTTP', 'HTTPS', 'HTTP Alt', 'HTTPS Alt', 'TLS', 'SMTP', 'SMTPS', 'IMAP', 'IMAPS', 'POP3', 'POP3S', 'Elastic Beats'], 'severity': 'high', 'confidence': 'medium', 'attack': ['T1203', 'T1204', 'T1204.001', 'T1204.002', 'T1204.003', 'T1204.004', 'T1204.005'], 'rule_type': 'detection'},
    {'name': 'Execution: Hijack Execution Flow - Windows', 'description': 'Windows endpoint telemetry can validate DLL, installer, PATH, service, registry, .NET, and GUI callback hijack coverage.', 'event_type': 'flow', 'protocol_any': ['Elastic Beats', 'WinRM', 'WinRM TLS', 'SMB'], 'severity': 'high', 'confidence': 'medium', 'attack': ['T1574', 'T1574.001', 'T1574.005', 'T1574.007', 'T1574.008', 'T1574.009', 'T1574.010', 'T1574.011', 'T1574.012', 'T1574.013', 'T1574.014'], 'rule_type': 'detection', 'requires': ['Windows Event Log']},
    {'name': 'Execution: Hijack Execution Flow - Linux/macOS', 'description': 'Linux and macOS telemetry can validate dylib and dynamic-linker hijacking coverage.', 'event_type': 'flow', 'protocol_any': ['Syslog', 'Syslog TLS', 'Elastic Beats', 'SSH'], 'severity': 'high', 'confidence': 'medium', 'attack': ['T1574.004', 'T1574.006'], 'rule_type': 'detection', 'requires': ['Network Traffic']},
    {'name': 'Execution: Input Injection', 'description': 'Endpoint or remote-control telemetry can validate input-injection execution coverage.', 'event_type': 'flow', 'protocol_any': ['VNC', 'RDP', 'SSH', 'Elastic Beats', 'Syslog', 'Syslog TLS'], 'severity': 'medium', 'confidence': 'medium', 'attack': ['T1674'], 'rule_type': 'detection'},
    {'name': 'Execution: Inter-Process Communication', 'description': 'Windows, macOS, and endpoint telemetry can validate COM, DDE, and XPC execution coverage.', 'event_type': 'flow', 'protocol_any': ['Elastic Beats', 'WinRM', 'WinRM TLS', 'Syslog', 'Syslog TLS'], 'severity': 'high', 'confidence': 'medium', 'attack': ['T1559', 'T1559.001', 'T1559.002', 'T1559.003'], 'rule_type': 'detection'},
    {'name': 'Execution: Native API', 'description': 'Endpoint telemetry can validate execution through native OS APIs.', 'event_type': 'flow', 'protocol_any': ['Elastic Beats', 'WinRM', 'WinRM TLS', 'Syslog', 'Syslog TLS'], 'severity': 'medium', 'confidence': 'medium', 'attack': ['T1106'], 'rule_type': 'detection'},
    {'name': 'Execution: Poisoned Pipeline Execution', 'description': 'CI/CD, repository, cloud, and web/API flows can validate poisoned pipeline execution coverage.', 'event_type': 'flow', 'protocol_any': ['HTTP', 'HTTPS', 'HTTP Alt', 'HTTPS Alt', 'TLS', 'DNS', 'Elastic Beats'], 'destination_is_external': True, 'severity': 'high', 'confidence': 'medium', 'attack': ['T1677'], 'rule_type': 'detection'},
    {'name': 'Execution: Scheduled Task and Job', 'description': 'Windows, Linux, macOS, systemd, cron, and container orchestration telemetry can validate scheduled execution coverage.', 'event_type': 'flow', 'protocol_any': ['WinRM', 'WinRM TLS', 'Elastic Beats', 'Syslog', 'Syslog TLS', 'SSH', 'HTTPS', 'HTTP'], 'severity': 'high', 'confidence': 'high', 'attack': ['T1053', 'T1053.002', 'T1053.003', 'T1053.005', 'T1053.006', 'T1053.007'], 'rule_type': 'detection'},
    {'name': 'Execution: Shared Modules', 'description': 'Endpoint telemetry can validate execution through shared module loading.', 'event_type': 'flow', 'protocol_any': ['Elastic Beats', 'Syslog', 'Syslog TLS', 'WinRM', 'WinRM TLS'], 'severity': 'medium', 'confidence': 'medium', 'attack': ['T1129'], 'rule_type': 'detection'},
    {'name': 'Execution: Software Deployment Tools', 'description': 'Enterprise software deployment, management, and endpoint telemetry can validate deployment-tool execution coverage.', 'event_type': 'flow', 'protocol_any': ['HTTPS', 'HTTP', 'TLS', 'WinRM', 'WinRM TLS', 'SMB', 'Elastic Beats'], 'severity': 'high', 'confidence': 'medium', 'attack': ['T1072'], 'rule_type': 'detection'},
    {'name': 'Execution: System Services', 'description': 'Service control and init-system telemetry can validate launchctl, Windows service, and systemctl execution coverage.', 'event_type': 'flow', 'protocol_any': ['WinRM', 'WinRM TLS', 'SMB', 'SSH', 'Syslog', 'Syslog TLS', 'Elastic Beats'], 'severity': 'high', 'confidence': 'high', 'attack': ['T1569', 'T1569.001', 'T1569.002', 'T1569.003'], 'rule_type': 'detection'},
    {'name': 'Execution: Trusted Developer Utilities Proxy Execution', 'description': 'Developer/build tool and endpoint telemetry can validate MSBuild, ClickOnce, and JamPlus proxy execution coverage.', 'event_type': 'flow', 'protocol_any': ['HTTP', 'HTTPS', 'HTTP Alt', 'HTTPS Alt', 'TLS', 'Elastic Beats', 'SMB'], 'severity': 'medium', 'confidence': 'medium', 'attack': ['T1127', 'T1127.001', 'T1127.002', 'T1127.003'], 'rule_type': 'detection'},
    {'name': 'Execution: Windows Management Instrumentation', 'description': 'WMI/DCOM and Windows telemetry can validate WMI execution coverage.', 'event_type': 'flow', 'protocol_any': ['WinRM', 'WinRM TLS', 'SMB', 'MSRPC', 'Elastic Beats'], 'severity': 'high', 'confidence': 'high', 'attack': ['T1047'], 'rule_type': 'detection', 'requires': ['Windows Event Log']},

    # Discovery
    {'name':'Network Service Scanning','description':'A source contacted many destination ports.','aggregate':'port_scan','threshold':20,'severity':'medium','attack':['T1046']},
    {'name':'Horizontal Scan','description':'A source contacted many hosts on the same destination port.','aggregate':'horizontal_scan','threshold':20,'severity':'medium','attack':['T1018','T1046']},
    {'name':'Vertical Scan','description':'A source contacted many destination ports on the same host.','aggregate':'vertical_scan','threshold':30,'severity':'medium','attack':['T1046']},
    {'name':'ICMP Remote System Discovery','description':'A source sent ICMP traffic to many destination hosts.','aggregate':'icmp_sweep','threshold':20,'severity':'medium','attack':['T1018']},
    {'name':'LDAP and Kerberos Account Discovery','description':'A source used both LDAP and Kerberos, consistent with account/domain discovery.','aggregate':'protocol_combo','protocols':['LDAP','LDAP GC','Kerberos'],'threshold':2,'severity':'medium','attack':['T1087','T1087.002','T1069.002']},
    {'name':'Domain Authentication Discovery Sequence','description':'Kerberos, LDAP, and SMB from one source indicate domain authentication and discovery activity.','aggregate':'protocol_combo','protocols':['Kerberos','LDAP','SMB'],'threshold':3,'severity':'medium','attack':['T1087.002','T1069.002','T1135']},

    # Credential Access
    {'name':'SSH Brute Force Candidate','description':'High-volume SSH traffic from one source to a destination.','aggregate':'service_volume','protocol':'SSH','threshold':20,'severity':'high','attack':['T1110']},
    {'name':'RDP Brute Force Candidate','description':'High-volume RDP traffic from one source to a destination.','aggregate':'service_volume','protocol':'RDP','threshold':20,'severity':'high','attack':['T1110']},
    {'name':'WinRM Brute Force Candidate','description':'High-volume WinRM traffic from one source to a destination.','aggregate':'service_volume','protocol':'WinRM','threshold':20,'severity':'high','attack':['T1110']},
    {'name':'Kerberoasting Candidate','description':'High-volume Kerberos traffic from a source to a domain service.','aggregate':'service_volume','protocol':'Kerberos','threshold':20,'severity':'high','attack':['T1558.003']},
    {'name':'LSASS Credential Access Evidence','description':'SMB/DC activity that may support LSASS credential-access validation in synthetic datasets.','event_type':'flow','protocol':'SMB','port':445,'severity':'high','attack':['T1003.001']},

    # Lateral Movement / Remote Services
    {'name':'SMB Remote Services','description':'SMB traffic may indicate remote services/lateral movement when suspicious in context.','event_type':'flow','protocol':'SMB','port':445,'severity':'medium','attack':['T1021.002'],'enabled':False,'coverage_only':True},
    {'name':'SMB Admin Share with Kerberos Context','description':'Same source used Kerberos and SMB, consistent with authenticated SMB remote services.','aggregate':'protocol_combo','protocols':['Kerberos','SMB'],'threshold':2,'severity':'high','attack':['T1021.002']},
    {'name':'RDP Remote Services','description':'Internal RDP flow observed.','event_type':'flow','protocol':'RDP','port':3389,'internal_to_internal':True,'severity':'medium','attack':['T1021.001']},
    {'name':'External RDP Exposure','description':'RDP to an external destination observed.','event_type':'flow','protocol':'RDP','port':3389,'destination_is_external':True,'severity':'critical','attack':['T1021.001']},
    {'name':'WinRM Remote Services','description':'WinRM observed.','event_type':'flow','protocol':'WinRM','port':5985,'severity':'medium','attack':['T1021.006']},
    {'name':'WinRM TLS Remote Services','description':'WinRM over TLS observed.','event_type':'flow','protocol':'WinRM TLS','port':5986,'severity':'medium','attack':['T1021.006']},
    {'name':'SSH Remote Services','description':'SSH observed.','event_type':'flow','protocol':'SSH','port':22,'severity':'low','attack':['T1021.004']},
    {'name':'VNC Remote Services','description':'Generic VNC/Screen Sharing coverage indicator. Disabled by default to avoid overlapping with OS-specific screen-sharing rules.','event_type':'flow','protocol':'VNC','port':5900,'severity':'medium','attack':['T1021.005'],'enabled':False,'coverage_only':True},
    {'name':'WMI/DCOM Lateral Movement Candidate','description':'MSRPC/DCOM traffic observed.','event_type':'flow','protocol':'MSRPC','port':135,'severity':'medium','attack':['T1021.003']},
    {'name':'Exploitation of Remote Services Candidate','description':'Broad remote-service indicator. Disabled by default to avoid overlapping with protocol-specific remote-service rules.','event_type':'flow','protocol_any':['SMB','RDP','WinRM','WinRM TLS','SSH','VNC','MSRPC'],'severity':'medium','attack':['T1210'],'enabled':False,'coverage_only':True},

    # Command and Control
    {'name':'DNS Application Layer Protocol','description':'Informational DNS coverage indicator. Disabled by default to avoid conflicting with DNS tunneling rules.','event_type':'dns','protocol':'DNS','port':53,'severity':'informational','attack':['T1071.004'],'enabled':False,'coverage_only':True},
    {'name':'DNS Tunneling Candidate','description':'High-volume DNS flow activity from a source.','aggregate':'service_volume','protocol':'DNS','threshold':25,'severity':'high','attack':['T1071.004','T1572']},
    {'name':'HTTP/S Application Layer Protocol','description':'Informational web coverage indicator. Disabled by default to avoid overlapping with beaconing, proxy, and ingress-transfer rules.','event_type':'flow','protocol_any':['HTTP','HTTPS','HTTP Alt','HTTPS Alt'],'severity':'informational','attack':['T1071.001'],'enabled':False,'coverage_only':True},
    {'name':'HTTPS Beacon Candidate','description':'High-packet web flow to a repeated destination.','event_type':'flow','protocol':'HTTPS','min_packets':20,'severity':'medium','attack':['T1071.001']},
    {'name':'HTTP Beacon Candidate','description':'High-packet HTTP flow to a repeated destination.','event_type':'flow','protocol_any':['HTTP','HTTP Alt'],'min_packets':20,'severity':'medium','attack':['T1071.001']},
    {'name':'Proxy / Web Service Use','description':'Proxy or alternate web service ports observed.','event_type':'flow','protocol_any':['HTTP Alt','HTTPS Alt'],'severity':'low','attack':['T1090','T1102','T1571']},
    {'name':'Non-Application Layer C2 Candidate','description':'Non-web tunnel or VPN-like protocol observed.','event_type':'flow','protocol_any':['WireGuard','NTP','SNMP'],'severity':'low','attack':['T1095']},
    {'name':'Ingress Tool Transfer Candidate','description':'External web download/upload style traffic observed. Requires packet volume to reduce overlap with generic web rules.','event_type':'flow','protocol_any':['HTTP','HTTPS','HTTP Alt','HTTPS Alt'],'destination_is_external':True,'min_packets':5,'severity':'medium','attack':['T1105']},

    # Exfiltration / Collection
    {'name':'Large Upload / Possible Exfiltration','description':'Large outbound flow volume observed.','event_type':'flow','min_bytes':500000,'destination_is_external':True,'severity':'high','attack':['T1041','T1567']},
    {'name':'Automated Exfiltration Candidate','description':'Very large outbound transfer observed.','event_type':'flow','min_bytes':5000000,'destination_is_external':True,'severity':'critical','attack':['T1020']},
    {'name':'Exfiltration Over Alternative Protocol','description':'Outbound non-standard protocol/port traffic with volume. Disabled by default because it is intentionally broad and overlaps large-upload rules.','event_type':'flow','min_bytes':500000,'destination_is_external':True,'severity':'high','attack':['T1048'],'enabled':False,'coverage_only':True},
    {'name':'Data Transfer Size Limits Candidate','description':'Repeated moderate-sized outbound transfers may indicate staged exfiltration.','aggregate':'service_volume','protocol':'HTTPS','threshold':25,'severity':'medium','attack':['T1030']},
    {'name':'SMB Collection from Network Share','description':'SMB flow activity can support network-share collection validation.','event_type':'flow','protocol':'SMB','port':445,'severity':'medium','attack':['T1039','T1135']},
    {'name':'Archive Collected Data Candidate','description':'SMB collection followed by outbound transfer pattern from the same source.','aggregate':'protocol_combo','protocols':['SMB','HTTPS'],'threshold':2,'severity':'medium','attack':['T1560','T1041']},
    {'name':'Data from Local or Database System','description':'Database protocol activity can support collection validation in synthetic datasets.','event_type':'flow','protocol_any':['MySQL','PostgreSQL','MSSQL','Oracle','MongoDB','Redis'],'severity':'medium','attack':['T1005']},

    # Persistence - ATT&CK v18 TA0003 coverage rules. Added to complete
    # Persistence coverage for the techniques/sub-techniques represented by
    # the app's strict ATT&CK v18 technique registry.
    {'name': 'Persistence: Create Account', 'description': 'Account creation or identity-management telemetry can validate Create Account persistence coverage.', 'event_type': 'flow', 'protocol_any': ['LDAP', 'LDAP GC', 'Kerberos', 'SMB', 'WinRM', 'WinRM TLS', 'Elastic Beats', 'Syslog', 'Syslog TLS', 'SSH', 'HTTP', 'HTTPS'], 'severity': 'high', 'confidence': 'medium', 'attack': ['T1136'], 'rule_type': 'detection', 'requires': ['Network Traffic']},
    {'name': 'Persistence: Registry Run Keys / Startup Folder', 'description': 'Windows endpoint telemetry, SMB, WinRM, or log forwarding can validate Registry Run Keys and Startup Folder persistence coverage.', 'event_type': 'flow', 'protocol_any': ['Elastic Beats', 'WinRM', 'WinRM TLS', 'SMB'], 'severity': 'high', 'confidence': 'medium', 'attack': ['T1547.001'], 'rule_type': 'detection', 'requires': ['Windows Event Log']},


    # Privilege Escalation - ATT&CK v18 TA0004 coverage rules. Added only to
    # complete Privilege Escalation coverage for the techniques/sub-techniques
    # represented by the app's strict ATT&CK v18 technique registry.
    {'name': 'Privilege Escalation: Process Injection', 'description': 'Endpoint telemetry, Windows event forwarding, Sysmon-like logging, or management-channel evidence can validate process injection privilege-escalation coverage.', 'event_type': 'flow', 'protocol_any': ['Elastic Beats', 'WinRM', 'WinRM TLS', 'Syslog', 'Syslog TLS', 'SMB'], 'severity': 'high', 'confidence': 'medium', 'attack': ['T1055'], 'rule_type': 'detection', 'requires': ['Network Traffic']},


    # Persistence / Execution / Defense Evasion
    {'name':'PowerShell Execution Candidate','description':'WinRM/PowerShell remoting channel observed.','event_type':'flow','protocol_any':['WinRM','WinRM TLS'],'severity':'high','attack':['T1059.001']},
    {'name':'Unix Shell Execution Candidate','description':'SSH channel observed to Linux/Unix-like systems.','event_type':'flow','protocol':'SSH','port':22,'severity':'medium','attack':['T1059.004']},
    {'name':'Cron Persistence Coverage Rule','description':'Linux telemetry/logging flow that can validate cron persistence scenarios in synthetic datasets.','event_type':'flow','protocol_any':['Syslog','Syslog TLS','Elastic Beats'],'severity':'medium','attack':['T1053.003']},
    {'name':'Scheduled Task Persistence Coverage Rule','description':'Windows telemetry flow that can validate scheduled task persistence scenarios in synthetic datasets.','event_type':'flow','protocol_any':['WinRM','WinRM TLS','Elastic Beats'],'severity':'medium','attack':['T1053.005']},
    {'name':'Systemd Service Persistence Coverage Rule','description':'Linux telemetry flow that can validate systemd service persistence scenarios.','event_type':'flow','protocol_any':['Syslog','Syslog TLS','Elastic Beats'],'severity':'medium','attack':['T1543.002']},
    {'name':'Windows Service Persistence Coverage Rule','description':'Windows telemetry flow that can validate Windows service creation/modification scenarios.','event_type':'flow','protocol_any':['WinRM','WinRM TLS','Elastic Beats'],'severity':'medium','attack':['T1543.003']},
    {'name':'macOS Launch Agent Persistence Coverage Rule','description':'macOS telemetry flow that can validate LaunchAgent persistence scenarios.','event_type':'flow','protocol_any':['Syslog','Syslog TLS','Elastic Beats'],'severity':'medium','attack':['T1543.001']},
    {'name':'Clear Windows Event Logs Candidate','description':'Windows telemetry flow can validate log clearing scenarios.','event_type':'flow','protocol_any':['Elastic Beats','WinRM','WinRM TLS'],'severity':'high','attack':['T1070.001','T1562.002']},
    {'name':'Clear Linux or macOS Logs Candidate','description':'Syslog/journald/audit forwarding can validate Linux or macOS log clearing scenarios.','event_type':'flow','protocol_any':['Syslog','Syslog TLS','Elastic Beats'],'severity':'high','attack':['T1070.002']},
    {'name':'Impair Defenses Candidate','description':'Security/logging telemetry channel observed; matching synthetic evidence can validate defensive impairment scenarios.','event_type':'flow','protocol_any':['Elastic Beats','Syslog','Syslog TLS'],'severity':'medium','attack':['T1562.001']},

    # macOS / remote access / credentials
    {'name':'macOS Screen Sharing','description':'VNC/Screen Sharing observed.','event_type':'flow','protocol':'VNC','port':5900,'severity':'medium','attack':['T1021.005','T1113']},
    {'name':'macOS Keychain Access Coverage Rule','description':'macOS telemetry flow can validate Keychain access scenarios in synthetic datasets.','event_type':'flow','protocol_any':['Elastic Beats','Syslog TLS'],'severity':'high','attack':['T1555.001']},
]

CUSTOM_RULES = RESULT_DIR / 'custom_rules.json'
RULE_STATE = RESULT_DIR / 'rule_state.json'
RULE_HISTORY = RESULT_DIR / 'rule_validation_history.json'
RULE_PACK_EXPORT = RESULT_DIR / 'rule_pack_export.json'
VALID_EVENT_TYPES = {'flow','dns','icmp','http','tls','network','normalized_event','log_event','process_creation','authentication_success','authentication_failure','service_creation','scheduled_task_created','network_connection','dns_query','file_created','file_deleted','registry_value_set','process_access'}
VALID_SEVERITIES = {'informational','low','medium','high','critical'}
VALID_AGGREGATES = {'port_scan','horizontal_scan','vertical_scan','icmp_sweep','service_volume','protocol_combo'}



def _official_rule_category(meta):
    """Choose detection vs network for generated ATT&CK coverage rules."""
    text = ' '.join([meta.get('name',''), meta.get('tactic','')] + list(meta.get('data_sources') or []) + list(meta.get('platforms') or [])).lower()
    network_words = ['network', 'traffic', 'dns', 'domain', 'ip address', 'web', 'proxy', 'email', 'remote service', 'exfiltration', 'command and control', 'scanning']
    if any(w in text for w in network_words):
        return 'network'
    return 'detection'


def _official_rule_protocols(meta):
    name = (meta.get('name') or '').lower()
    tactic = meta.get('tactic') or ''
    if 'dns' in name or 'domain' in name:
        return ['DNS']
    if 'web' in name or 'http' in name or 'browser' in name:
        return ['HTTP', 'HTTPS']
    if 'email' in name or 'phishing' in name:
        return ['SMTP', 'IMAP', 'POP3', 'HTTPS']
    if 'remote service' in name or 'rdp' in name:
        return ['RDP', 'SSH', 'SMB', 'WinRM', 'WinRM TLS']
    if 'smb' in name or 'windows admin' in name:
        return ['SMB']
    if 'kerberos' in name:
        return ['Kerberos']
    if 'ldap' in name or 'active directory' in name:
        return ['LDAP', 'LDAP GC']
    if 'exfiltration' in name:
        return ['HTTPS', 'HTTP', 'DNS']
    if 'command and control' in name or tactic == 'command-and-control':
        return ['HTTPS', 'HTTP', 'DNS']
    if tactic in ('reconnaissance','resource-development'):
        return ['DNS', 'HTTP', 'HTTPS']
    return ['Elastic Beats', 'Syslog', 'Syslog TLS', 'WinRM', 'WinRM TLS', 'SMB', 'SSH', 'HTTPS', 'DNS']


def _official_rule_requires(meta, category):
    ds = meta.get('data_sources') or []
    if ds:
        req = []
        joined = ' '.join(ds).lower()
        if 'network' in joined: req.append('Network Traffic')
        if 'windows' in joined: req.append('Windows Event Log')
        if 'process' in joined: req.append('Process Telemetry')
        if 'file' in joined: req.append('File Activity')
        if 'cloud' in joined: req.append('Cloud Audit Logs')
        if 'command' in joined: req.append('Command Execution Logs')
        return sorted(set(req)) or ['Network Traffic']
    return ['Network Traffic'] if category == 'network' else ['Endpoint or Log Telemetry']


def generated_official_coverage_rules(existing_rules=None):
    """Generate minimal built-in coverage rules for any official v18 technique
    or sub-technique that does not already have a rule mapping.

    These rules are conservative validation hooks: they do not claim an attack
    occurred. They let the rule engine validate ATT&CK heat-map coverage only
    when matching network/log evidence exists and the required telemetry is
    present.
    """
    existing = existing_rules or BUILTIN_RULES
    covered = set()
    for r in existing:
        for tid in _as_list(r.get('attack')):
            covered.add(tid)
    rules = []
    for tid, meta in sorted(VALID_TECHNIQUES.items()):
        if tid in covered:
            continue
        category = _official_rule_category(meta)
        protocols = _official_rule_protocols(meta)
        severity = 'medium'
        if meta.get('tactic') in {'credential-access','privilege-escalation','defense-evasion','impact','exfiltration'}:
            severity = 'high'
        rule = {
            'id': 'official-v18-' + tid.replace('.', '-'),
            'name': f"ATT&CK v18 Coverage: {tid} {meta.get('name', tid)}",
            'description': 'Generated from the official MITRE ATT&CK Enterprise v18 STIX dataset to ensure every technique/sub-technique has a validation-capable rule. It validates only when matching evidence exists.',
            'version': '18.0.1',
            'rule_category': category,
            'rule_type': category,
            'event_type': 'flow',
            'protocol_any': protocols,
            'severity': severity,
            'confidence': 'medium',
            'requires': _official_rule_requires(meta, category),
            'attack': [tid],
            'enabled': True,
            'generated_from': 'official Enterprise ATT&CK v18 STIX',
            'detection_logic': 'Match relevant normalized network/log flows and require the telemetry listed in requires.',
            'validation_logic': 'Rule contributes to Validated coverage only when enabled, dependencies are met, and at least one current analysis flow/event matches.',
            'evidence_fields': ['src_ip','dst_ip','protocol','dport','bytes','packets','first_seen','last_seen'],
            'coverage_score': 60,
        }
        rules.append(rule)
    return rules


def attack_coverage_report(rules=None):
    """Return an exact rule-coverage report for all loaded Enterprise ATT&CK v18 items.

    When the official STIX dataset is available, VALID_TECHNIQUES is populated
    directly from that dataset.  Generated official coverage rules are counted
    separately from hand-written built-in and custom rules so the report can
    explain exactly what was reused versus generated.
    """
    rules = rules or load_rules(include_disabled=True)
    by_tid = {}
    for r in rules:
        for tid in _as_list(r.get('attack')):
            by_tid.setdefault(tid, []).append(r)

    total_tech = 0
    total_sub = 0
    uncovered_tech = []
    uncovered_sub = []
    items = []
    by_tactic = {}
    existing_verified = 0
    generated_detection = 0
    generated_network = 0

    for tid, meta in sorted(VALID_TECHNIQUES.items()):
        is_sub = bool(meta.get('is_subtechnique')) or '.' in tid
        tactic_names = meta.get('tactics') or [meta.get('tactic','')]
        matched = by_tid.get(tid, [])
        if is_sub:
            total_sub += 1
        else:
            total_tech += 1
        if not matched:
            (uncovered_sub if is_sub else uncovered_tech).append(tid)

        existing = [r for r in matched if not str(r.get('id','')).startswith('official-v18-')]
        generated = [r for r in matched if str(r.get('id','')).startswith('official-v18-')]
        if existing:
            existing_verified += 1
        for r in generated:
            if (r.get('rule_type') or r.get('rule_category')) == 'network':
                generated_network += 1
            else:
                generated_detection += 1

        for tactic in tactic_names:
            if not tactic:
                continue
            t = by_tactic.setdefault(tactic, {
                'techniques': 0, 'subtechniques': 0, 'total': 0,
                'covered': 0, 'uncovered': 0,
                'existing_rules_verified': 0,
                'generated_detection_rules': 0,
                'generated_network_rules': 0,
            })
            if is_sub:
                t['subtechniques'] += 1
            else:
                t['techniques'] += 1
            t['total'] += 1
            if matched:
                t['covered'] += 1
            else:
                t['uncovered'] += 1
            if existing:
                t['existing_rules_verified'] += 1
            for r in generated:
                if (r.get('rule_type') or r.get('rule_category')) == 'network':
                    t['generated_network_rules'] += 1
                else:
                    t['generated_detection_rules'] += 1

        items.append({
            'id': tid,
            'name': meta.get('name', tid),
            'tactic': meta.get('tactic',''),
            'tactics': tactic_names,
            'is_subtechnique': is_sub,
            'existing_rule': bool(existing),
            'newly_generated_rule': bool(generated),
            'rules': [r.get('name') for r in matched],
            'rule_ids': [r.get('id') for r in matched],
            'rule_types': sorted(set(r.get('rule_type') or r.get('rule_category') or 'detection' for r in matched)),
            'supported_telemetry': sorted(set(x for r in matched for x in _as_list(r.get('requires')))),
            'validated_by_rule_engine': bool(matched),
        })

    return {
        'attack_enterprise_version': '18',
        'dataset': ATTACK_DATASET_METADATA,
        'strict_official_stix': bool(ATTACK_DATASET_METADATA.get('official')),
        'tactics': VALID_TACTICS,
        'tactic_counts': ATTACK_TACTIC_COUNTS,
        'coverage_by_tactic': by_tactic,
        'total_techniques': total_tech,
        'total_subtechniques': total_sub,
        'total_items': total_tech + total_sub,
        'existing_rules_verified': existing_verified,
        'new_detection_rules_generated': generated_detection,
        'new_network_rules_generated': generated_network,
        'total_rules_generated': generated_detection + generated_network,
        'remaining_uncovered_techniques': uncovered_tech,
        'remaining_uncovered_subtechniques': uncovered_sub,
        'items': items,
    }

RULE_TEMPLATES = [
    {'name':'Template: SMB Lateral Movement','description':'Kerberos plus SMB from same source.','aggregate':'protocol_combo','protocols':['Kerberos','SMB'],'threshold':2,'severity':'high','confidence':'high','attack':['T1021.002'],'requires':['Windows Event Log','Network Traffic']},
    {'name':'Template: HTTPS Beaconing','description':'Repeated HTTPS traffic to same destination.','event_type':'flow','protocol':'HTTPS','min_packets':20,'severity':'medium','confidence':'medium','attack':['T1071.001'],'requires':['Network Traffic']},
    {'name':'Template: DNS Tunneling','description':'High-volume DNS flow activity.','aggregate':'service_volume','protocol':'DNS','threshold':25,'severity':'high','confidence':'medium','attack':['T1071.004','T1572'],'requires':['DNS','Network Traffic']},
    {'name':'Template: Brute Force','description':'High-volume SSH/RDP/WinRM activity.','aggregate':'service_volume','protocol':'SSH','threshold':20,'severity':'high','confidence':'medium','attack':['T1110'],'requires':['Authentication Logs']},
    {'name':'Template: Large Upload Exfiltration','description':'Large outbound external flow.','event_type':'flow','min_bytes':500000,'destination_is_external':True,'severity':'high','confidence':'medium','attack':['T1041','T1567'],'requires':['Network Traffic']},
    {'name':'Template: Log Clearing','description':'Telemetry channel and log clearing evidence in dataset.','event_type':'flow','protocol_any':['Elastic Beats','Syslog','Syslog TLS','WinRM'],'severity':'high','confidence':'high','attack':['T1070.001','T1070.002'],'requires':['Windows Event Log','Syslog']},
]

def _default_confidence(severity):
    return {'critical':'high','high':'high','medium':'medium','low':'low','informational':'low'}.get(str(severity or '').lower(), 'medium')

def _as_list(value):
    if value in [None, '']:
        return []
    if isinstance(value, list):
        return [x for x in value if x not in [None, '']]
    return [x.strip() for x in str(value).split(',') if x.strip()]

def _normalize_rule_lists(rule):
    for key in ['attack','protocol_any','protocols','requires','exclude_src_ips','exclude_dst_ips','exclude_protocols']:
        if key in rule:
            rule[key] = _as_list(rule.get(key))
    return rule

def _coverage_weight(rule):
    sev = str(rule.get('severity_override') or rule.get('severity') or 'medium').lower()
    conf = str(rule.get('confidence') or _default_confidence(sev)).lower()
    sev_score = {'informational':1,'low':2,'medium':3,'high':4,'critical':5}.get(sev,3)
    conf_score = {'low':1,'medium':2,'high':3,'critical':4}.get(conf,2)
    return min(100, int((sev_score * 12) + (conf_score * 10) + (len(rule.get('attack') or []) * 3)))

def available_telemetry(result):
    vals=set(['Network Traffic'])
    for ls in result.get('log_sources', []) or []:
        text=' '.join(str(ls.get(k,'')) for k in ['name','source','technology','category','evidence']).lower() if isinstance(ls, dict) else str(ls).lower()
        if 'windows' in text or 'winlog' in text: vals.add('Windows Event Log')
        if 'sysmon' in text: vals.add('Sysmon')
        if 'powershell' in text: vals.add('PowerShell')
        if 'syslog' in text: vals.add('Syslog')
        if 'journal' in text or 'systemd' in text: vals.add('systemd-journald')
        if 'auditd' in text or 'auditbeat' in text: vals.add('auditd')
        if 'apple' in text or 'macos' in text or 'osquery' in text: vals.add('Apple Unified Logging')
        if 'zeek' in text: vals.add('Zeek')
        if 'suricata' in text: vals.add('Suricata')
        if 'dns' in text: vals.add('DNS')
    for f in result.get('flows', []) or []:
        proto=str(f.get('protocol') or '')
        if proto: vals.add(proto)
        if proto == 'DNS': vals.add('DNS')
    for ev in result.get('normalized_events', []) or []:
        src = str(ev.get('log_source') or '')
        etype = str(ev.get('event_type') or '')
        plat = str(ev.get('platform') or '')
        if src:
            vals.add(src)
        if etype:
            vals.add(etype)
        low = ' '.join([src, etype, plat, str(ev.get('raw') or '')]).lower()
        if 'windows' in low or 'winlog' in low or 'eventid' in low:
            vals.add('Windows Event Log')
        if 'sysmon' in low:
            vals.add('Sysmon')
        if 'powershell' in low:
            vals.add('PowerShell')
        if 'syslog' in low:
            vals.add('Syslog')
        if 'journal' in low or 'systemd' in low:
            vals.add('systemd-journald')
        if 'auditd' in low or 'auditbeat' in low:
            vals.add('auditd')
        if 'apple' in low or 'macos' in low or 'openbsm' in low:
            vals.add('Apple Unified Logging')
        if 'zeek' in low:
            vals.add('Zeek')
        if 'suricata' in low:
            vals.add('Suricata')
        if 'cloud' in low or 'cloudtrail' in low or 'azure' in low or 'gcp' in low:
            vals.add('Cloud Audit')
    return vals

def dependencies_met(rule, result):
    required=set(_as_list(rule.get('requires')))
    if not required:
        return True, []
    have=available_telemetry(result)
    missing=sorted(required - have)
    return len(missing)==0, missing

PRIVATE_PREFIXES = ('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.')


def is_private_ip(ip):
    return bool(ip) and str(ip).startswith(PRIVATE_PREFIXES)


def _rule_state():
    return read_json(RULE_STATE, {})


def _write_rule_state(state):
    write_json(RULE_STATE, state or {})


def load_rules(include_disabled=True):
    """Load built-in plus custom rules.

    Rules are enabled by default. Disabled state is stored separately so built-in
    rules can be disabled without modifying the bundled rule library.
    """
    rules = []
    state = _rule_state()
    custom_rules = read_json(CUSTOM_RULES, [])
    base_rules = BUILTIN_RULES + generated_official_coverage_rules(BUILTIN_RULES)
    for idx, rule in enumerate(base_rules + custom_rules):
        r = dict(rule)
        r.setdefault('id', f"builtin-{idx}" if idx < len(base_rules) else f"custom-{idx-len(base_rules)}")
        # Preserve existing custom IDs if present, but fall back to stable list IDs.
        rid = r.get('id')
        r['enabled'] = bool(state.get(rid, {}).get('enabled', r.get('enabled', True)))
        r['source'] = 'builtin' if (str(rid).startswith('builtin-') or str(rid).startswith('official-v18-')) else 'custom'
        r.setdefault('version', '1.0')
        r.setdefault('confidence', _default_confidence(r.get('severity')))
        r.setdefault('requires', [])
        r.setdefault('exclude_src_ips', [])
        r.setdefault('exclude_dst_ips', [])
        r.setdefault('exclude_protocols', [])
        r.setdefault('severity_override', '')
        if r.get('severity_override'):
            r['severity'] = r.get('severity_override')
        if include_disabled or r['enabled']:
            rules.append(r)
    return rules


def set_rule_enabled(rule_id, enabled):
    if not rule_id:
        return False, 'Missing rule id.'
    all_ids = {r.get('id') for r in load_rules(include_disabled=True)}
    if rule_id not in all_ids:
        return False, 'Rule not found.'
    state = _rule_state()
    state.setdefault(rule_id, {})['enabled'] = bool(enabled)
    _write_rule_state(state)
    return True, ''


def delete_rule(rule_id):
    """Delete a custom rule. Built-in rules cannot be deleted; disable them instead."""
    if not rule_id:
        return False, 'Missing rule id.'
    if str(rule_id).startswith('builtin-'):
        return False, 'Built-in rules cannot be deleted. Disable them instead.'
    rules = read_json(CUSTOM_RULES, [])
    kept = []
    removed = False
    for idx, r in enumerate(rules):
        rid = r.get('id') or f'custom-{idx}'
        if rid == rule_id:
            removed = True
            continue
        kept.append(r)
    if not removed:
        return False, 'Custom rule not found.'
    write_json(CUSTOM_RULES, kept)
    state = _rule_state()
    state.pop(rule_id, None)
    _write_rule_state(state)
    return True, ''


def validate_rule(rule):
    errors = []
    cleaned = dict(rule or {})
    cleaned['name'] = str(cleaned.get('name') or '').strip()
    if not cleaned['name']:
        errors.append('Rule name is required.')
    if cleaned.get('aggregate'):
        cleaned['aggregate'] = str(cleaned.get('aggregate')).strip().lower()
        if cleaned['aggregate'] not in VALID_AGGREGATES:
            errors.append('Unsupported aggregate rule type. Supported: ' + ', '.join(sorted(VALID_AGGREGATES)) + '.')
        try:
            cleaned['threshold'] = int(cleaned.get('threshold') or 15)
            if cleaned['threshold'] < 1:
                errors.append('Aggregate threshold must be greater than zero.')
        except Exception:
            errors.append('Aggregate threshold must be an integer.')
    else:
        cleaned['event_type'] = str(cleaned.get('event_type') or 'flow').strip().lower()
        if cleaned['event_type'] not in VALID_EVENT_TYPES:
            errors.append('Unsupported event_type. Use flow, dns, icmp, http, tls, or network.')
        if cleaned.get('port') not in [None, '']:
            try:
                cleaned['port'] = int(cleaned.get('port'))
                if cleaned['port'] < 1 or cleaned['port'] > 65535:
                    errors.append('Port must be between 1 and 65535.')
            except Exception:
                errors.append('Port must be an integer.')
        elif 'port' in cleaned:
            cleaned.pop('port', None)
        if cleaned.get('min_bytes') not in [None, '']:
            try:
                cleaned['min_bytes'] = int(cleaned.get('min_bytes'))
                if cleaned['min_bytes'] < 0:
                    errors.append('min_bytes cannot be negative.')
            except Exception:
                errors.append('min_bytes must be an integer.')
        if cleaned.get('min_packets') not in [None, '']:
            try:
                cleaned['min_packets'] = int(cleaned.get('min_packets'))
                if cleaned['min_packets'] < 0:
                    errors.append('min_packets cannot be negative.')
            except Exception:
                errors.append('min_packets must be an integer.')
    cleaned = _normalize_rule_lists(cleaned)
    sev = str(cleaned.get('severity') or 'medium').strip().lower()
    if sev not in VALID_SEVERITIES:
        errors.append('Unsupported severity. Use informational, low, medium, high, or critical.')
    cleaned['severity'] = sev
    if cleaned.get('severity_override'):
        over = str(cleaned.get('severity_override')).strip().lower()
        if over not in VALID_SEVERITIES:
            errors.append('Unsupported severity_override. Use informational, low, medium, high, or critical.')
        cleaned['severity_override'] = over
    conf = str(cleaned.get('confidence') or _default_confidence(sev)).strip().lower()
    if conf not in {'low','medium','high','critical'}:
        errors.append('Unsupported confidence. Use low, medium, high, or critical.')
    cleaned['confidence'] = conf
    cleaned['version'] = str(cleaned.get('version') or '1.0').strip()
    attack = cleaned.get('attack') or []
    for tid in attack:
        if tid not in VALID_TECHNIQUES:
            errors.append(f'Unknown or unsupported ATT&CK technique ID: {tid}')
    if not cleaned['attack']:
        errors.append('At least one ATT&CK technique ID is required for validation.')
    return (len(errors) == 0), errors, {k:v for k,v in cleaned.items() if v not in [None,'',[]]}


def add_rule(rule):
    ok, errors, cleaned = validate_rule(rule)
    if not ok:
        return False, errors
    rules = read_json(CUSTOM_RULES, [])
    # Keep custom IDs monotonic to avoid changing enable/disable state for
    # remaining custom rules after a deletion.
    existing = [str(r.get('id','')) for r in rules]
    next_idx = 0
    while f"custom-{next_idx}" in existing:
        next_idx += 1
    cleaned['id'] = f"custom-{next_idx}"
    cleaned['enabled'] = True
    rules.append(cleaned)
    write_json(CUSTOM_RULES, rules)
    return True, []


def _proto_matches(ev, r):
    ev_proto = str(ev.get('protocol') or '')
    if r.get('protocol') and ev_proto.upper() != str(r.get('protocol')).upper():
        return False
    if r.get('protocol_any') and ev_proto not in r.get('protocol_any'):
        return False
    return True



def _rule_excluded(ev, r):
    src=str(ev.get('src_ip') or '')
    dst=str(ev.get('dst_ip') or '')
    proto=str(ev.get('protocol') or '')
    if src and src in set(_as_list(r.get('exclude_src_ips'))):
        return True, f'excluded source IP {src}'
    if dst and dst in set(_as_list(r.get('exclude_dst_ips'))):
        return True, f'excluded destination IP {dst}'
    if proto and proto in set(_as_list(r.get('exclude_protocols'))):
        return True, f'excluded protocol {proto}'
    return False, ''

def explain_event_match(ev, r):
    reasons=[]
    if r.get('protocol'):
        reasons.append(f"protocol matched {r.get('protocol')}")
    if r.get('protocol_any'):
        reasons.append('protocol matched one of ' + ', '.join(_as_list(r.get('protocol_any'))))
    if r.get('port'):
        reasons.append(f"destination port matched {r.get('port')}")
    if r.get('min_bytes'):
        reasons.append(f"bytes {ev.get('bytes',0)} >= {r.get('min_bytes')}")
    if r.get('min_packets'):
        reasons.append(f"packets {ev.get('packets',0)} >= {r.get('min_packets')}")
    if r.get('internal_to_internal'):
        reasons.append('source and destination are private/internal')
    if r.get('destination_is_external'):
        reasons.append('destination is external')
    if r.get('requires'):
        reasons.append('required telemetry: ' + ', '.join(_as_list(r.get('requires'))))
    return reasons or ['flow matched rule conditions']
def _rule_matches_event(ev, r):
    if r.get('aggregate'):
        return False
    ev_type = (ev.get('type') or 'flow').lower()
    rule_type = (r.get('event_type') or 'flow').lower()
    # Most saved artifacts are flow rows. Treat network/http/tls rules as flow-like when protocol/port matches.
    if rule_type not in ['network','http','tls'] and ev_type != rule_type:
        return False
    if not _proto_matches(ev, r):
        return False
    if r.get('port') and int(ev.get('dport') or 0) != int(r.get('port')):
        return False
    if r.get('min_bytes') and int(ev.get('bytes') or 0) < int(r.get('min_bytes')):
        return False
    if r.get('min_packets') and int(ev.get('packets') or 1) < int(r.get('min_packets')):
        return False
    if r.get('internal_to_internal') and not (is_private_ip(ev.get('src_ip')) and is_private_ip(ev.get('dst_ip'))):
        return False
    if r.get('destination_is_external') and is_private_ip(ev.get('dst_ip')):
        return False
    return True


def match_event(ev, rules):
    out=[]
    for r in rules:
        if not r.get('enabled', True):
            continue
        if not _rule_matches_event(ev, r):
            continue
        flow_id = f"{ev.get('src_ip')}|{ev.get('dst_ip')}|{ev.get('protocol')}|{ev.get('dport')}"
        out.append({
            'title': r['name'], 'rule_name': r['name'], 'rule_id': r.get('id'),
            'description': r.get('description',''), 'severity': r.get('severity','low'),
            'attack': r.get('attack',[]), 'evidence': ev.get('summary'),
            'src_ip': ev.get('src_ip'), 'dst_ip': ev.get('dst_ip'),
            'protocol': ev.get('protocol'), 'dport': ev.get('dport'), 'flow_id': flow_id,
            'validated_by_rule': True,
        })
    return out


def _flow_summary(f):
    return f"{f.get('src_ip')} -> {f.get('dst_ip')} {f.get('protocol')}:{f.get('dport')} packets={f.get('packets',0)} bytes={f.get('bytes',0)}"


def _aggregate_matches(flows, r, max_matches=100):
    agg = r.get('aggregate')
    threshold = int(r.get('threshold', 15))
    matches = []
    if agg == 'port_scan':
        by_src = {}
        for f in flows:
            if f.get('dport'):
                by_src.setdefault(f.get('src_ip'), set()).add(f.get('dport'))
        for src, ports in by_src.items():
            if src and len(ports) >= threshold:
                matches.append({'src_ip': src, 'evidence': f'{src} contacted {len(ports)} unique destination ports'})
    elif agg == 'horizontal_scan':
        by_src_port = {}
        for f in flows:
            if f.get('dport'):
                by_src_port.setdefault((f.get('src_ip'), f.get('dport')), set()).add(f.get('dst_ip'))
        for (src, port), dsts in by_src_port.items():
            if src and port and len([d for d in dsts if d]) >= threshold:
                matches.append({'src_ip': src, 'dport': port, 'evidence': f'{src} contacted {len(dsts)} hosts on port {port}'})
    elif agg == 'vertical_scan':
        by_pair = {}
        for f in flows:
            if f.get('dport'):
                by_pair.setdefault((f.get('src_ip'), f.get('dst_ip')), set()).add(f.get('dport'))
        for (src, dst), ports in by_pair.items():
            if src and dst and len(ports) >= threshold:
                matches.append({'src_ip': src, 'dst_ip': dst, 'evidence': f'{src} contacted {dst} on {len(ports)} ports'})
    elif agg == 'icmp_sweep':
        by_src = {}
        for f in flows:
            if str(f.get('protocol')) == 'ICMP':
                by_src.setdefault(f.get('src_ip'), set()).add(f.get('dst_ip'))
        for src, dsts in by_src.items():
            if src and len([d for d in dsts if d]) >= threshold:
                matches.append({'src_ip': src, 'evidence': f'{src} sent ICMP traffic to {len(dsts)} hosts'})
    elif agg == 'service_volume':
        by_key = {}
        for f in flows:
            if _proto_matches(f, r):
                key = (f.get('src_ip'), f.get('dst_ip'), f.get('protocol'), f.get('dport'))
                by_key.setdefault(key, 0)
                by_key[key] += int(f.get('packets') or 0)
        for (src, dst, proto, port), packets in by_key.items():
            if src and packets >= threshold:
                matches.append({'src_ip': src, 'dst_ip': dst, 'protocol': proto, 'dport': port, 'evidence': f'{src} -> {dst} {proto}:{port} had {packets} packets'})
    elif agg == 'protocol_combo':
        required = set(r.get('protocols') or [])
        min_count = min(len(required), threshold)
        by_src = {}
        for f in flows:
            by_src.setdefault(f.get('src_ip'), set()).add(f.get('protocol'))
        for src, protos in by_src.items():
            overlap = sorted(required & protos)
            if src and len(overlap) >= min_count:
                matches.append({'src_ip': src, 'evidence': f'{src} used protocol combination: {", ".join(overlap)}'})
    return matches[:max_matches]


def aggregate_findings(ctx, rules):
    flows = list(ctx.flows.values())
    findings=[]
    for r in rules:
        if not r.get('enabled', True):
            continue
        if not r.get('aggregate'):
            continue
        for m in _aggregate_matches(flows, r):
            findings.append({
                'title': r['name'], 'rule_name': r['name'], 'rule_id': r.get('id'),
                'description': r.get('description',''), 'severity': r.get('severity','medium'),
                'attack': r.get('attack',[]), 'evidence': m.get('evidence',''),
                'src_ip': m.get('src_ip'), 'dst_ip': m.get('dst_ip'), 'protocol': m.get('protocol'), 'dport': m.get('dport'),
                'flow_query': m.get('src_ip'), 'validated_by_rule': True,
            })
    return findings


def build_validation_results(result, rules=None, max_matches=500):
    rules = rules or load_rules()
    flows = []
    for f in result.get('flows', []) or []:
        ev = dict(f)
        ev.setdefault('type', 'flow')
        ev.setdefault('summary', _flow_summary(ev))
        flows.append(ev)
    matches = []
    validated = {}

    def record_match(r, m):
        nonlocal matches, validated
        if len(matches) < max_matches:
            matches.append(m)
        for tid in r.get('attack', []):
            validated.setdefault(tid, {'techniqueID': tid, 'rules': set(), 'evidence': []})
            validated[tid]['rules'].add(r.get('name'))
            if len(validated[tid]['evidence']) < 25:
                validated[tid]['evidence'].append(m.get('evidence',''))

    for r in rules:
        if not r.get('enabled', True):
            continue
        ok, errors, _ = validate_rule(r)
        if not ok:
            continue
        if r.get('aggregate'):
            for am in _aggregate_matches(flows, r):
                m = {'rule': r.get('name'), 'rule_id': r.get('id'), 'attack': r.get('attack', []), 'evidence': am.get('evidence'), 'src_ip': am.get('src_ip'), 'dst_ip': am.get('dst_ip'), 'protocol': am.get('protocol'), 'dport': am.get('dport'), 'matched': True, 'confidence': r.get('confidence', _default_confidence(r.get('severity'))), 'severity': r.get('severity_override') or r.get('severity'), 'explanation': m.get('explanation') or []}
                record_match(r, m)
            continue
        for ev in flows:
            if _rule_matches_event(ev, r):
                flow_id = ev.get('flow_id') or f"{ev.get('src_ip')}|{ev.get('dst_ip')}|{ev.get('protocol')}|{ev.get('dport')}"
                m = {'rule': r.get('name'), 'rule_id': r.get('id'), 'attack': r.get('attack', []), 'evidence': ev.get('summary'), 'src_ip': ev.get('src_ip'), 'dst_ip': ev.get('dst_ip'), 'protocol': ev.get('protocol'), 'dport': ev.get('dport'), 'flow_id': flow_id, 'matched': True, 'confidence': r.get('confidence', _default_confidence(r.get('severity'))), 'severity': r.get('severity_override') or r.get('severity'), 'explanation': m.get('explanation') or []}
                record_match(r, m)
    out_validated = []
    for tid, item in validated.items():
        out_validated.append({'techniqueID': tid, 'rules': sorted(item['rules']), 'evidence': item['evidence'][:10], 'match_count': len(item['evidence'])})
    return {'summary': {'rules_evaluated': len([r for r in rules if r.get('enabled', True)]), 'matches_recorded': len(matches), 'validated_techniques': len(out_validated)}, 'matches': matches, 'validated_techniques': sorted(out_validated, key=lambda x: x['techniqueID'])}


def build_validation_results(result, rules=None, max_matches=500):
    rules = rules or load_rules()
    flows=[]
    for f in result.get('flows', []) or []:
        ev=dict(f); ev.setdefault('type','flow'); ev.setdefault('summary', _flow_summary(ev)); flows.append(ev)
    matches=[]; validated={}; disabled=0; skipped_dependencies=[]
    enabled=[r for r in rules if r.get('enabled', True)]
    def record_match(r, m):
        nonlocal matches, validated
        m.setdefault('confidence', r.get('confidence', _default_confidence(r.get('severity'))))
        m.setdefault('severity', r.get('severity_override') or r.get('severity'))
        m.setdefault('rule_version', r.get('version','1.0'))
        m.setdefault('coverage_score', _coverage_weight(r))
        if len(matches) < max_matches:
            matches.append(m)
        for tid in r.get('attack', []):
            validated.setdefault(tid, {'techniqueID': tid, 'rules': set(), 'evidence': [], 'coverage_score': 0, 'confidence': set()})
            validated[tid]['rules'].add(r.get('name'))
            validated[tid]['coverage_score'] = max(validated[tid]['coverage_score'], _coverage_weight(r))
            validated[tid]['confidence'].add(m.get('confidence','medium'))
            if len(validated[tid]['evidence']) < 25:
                validated[tid]['evidence'].append(m.get('evidence',''))
    for r in rules:
        if not r.get('enabled', True):
            disabled += 1; continue
        ok, errors, _ = validate_rule(r)
        if not ok: continue
        dep_ok, missing = dependencies_met(r, result)
        if not dep_ok:
            skipped_dependencies.append({'rule': r.get('name'), 'missing': missing})
            continue
        if r.get('aggregate'):
            for am in _aggregate_matches(flows, r):
                am['explanation'] = [am.get('evidence',''), 'aggregate=' + str(r.get('aggregate')), 'threshold=' + str(r.get('threshold'))]
                m={'rule':r.get('name'),'rule_id':r.get('id'),'attack':r.get('attack',[]),'evidence':am.get('evidence'),'src_ip':am.get('src_ip'),'dst_ip':am.get('dst_ip'),'protocol':am.get('protocol'),'dport':am.get('dport'),'matched':True,'explanation':am['explanation']}
                record_match(r,m)
            continue
        for ev in flows:
            if _rule_matches_event(ev,r):
                flow_id=ev.get('flow_id') or f"{ev.get('src_ip')}|{ev.get('dst_ip')}|{ev.get('protocol')}|{ev.get('dport')}"
                m={'rule':r.get('name'),'rule_id':r.get('id'),'attack':r.get('attack',[]),'evidence':ev.get('summary'),'src_ip':ev.get('src_ip'),'dst_ip':ev.get('dst_ip'),'protocol':ev.get('protocol'),'dport':ev.get('dport'),'flow_id':flow_id,'matched':True,'explanation':explain_event_match(ev,r)}
                record_match(r,m)
    out_validated=[]
    for tid,item in validated.items():
        out_validated.append({'techniqueID':tid,'rules':sorted(item['rules']),'evidence':item['evidence'][:10],'match_count':len(item['evidence']),'coverage_score':item['coverage_score'],'confidence':', '.join(sorted(item['confidence']))})
    history_item={'time':time.time(),'summary':{'rules_evaluated':len(enabled),'matches_recorded':len(matches),'validated_techniques':len(out_validated),'rules_skipped_dependencies':len(skipped_dependencies)}}
    hist=read_json(RULE_HISTORY, [])
    hist.append(history_item)
    write_json(RULE_HISTORY, hist[-100:])
    return {'summary':history_item['summary'],'matches':matches,'validated_techniques':sorted(out_validated,key=lambda x:x['techniqueID']),'skipped_dependencies':skipped_dependencies,'history':hist[-20:]}

def preview_rule(rule, result, max_matches=25):
    ok, errors, cleaned = validate_rule(rule)
    if not ok: return {'ok':False,'errors':errors,'matches':[]}
    cleaned['id'] = cleaned.get('id','preview')
    dep_ok, missing = dependencies_met(cleaned, result)
    if not dep_ok: return {'ok':False,'errors':['Missing required telemetry: '+', '.join(missing)],'matches':[]}
    tmp = build_validation_results(result, [cleaned], max_matches=max_matches)
    return {'ok':True,'errors':[],'matches':tmp.get('matches',[]),'summary':tmp.get('summary',{})}

def load_rule_history():
    return read_json(RULE_HISTORY, [])

def export_rules():
    data={'version':'1.0','exported_at':time.time(),'custom_rules':read_json(CUSTOM_RULES, []),'state':_rule_state()}
    write_json(RULE_PACK_EXPORT, data)
    return RULE_PACK_EXPORT

def import_rules_from_file(path):
    try:
        data=json.loads(Path(path).read_text())
    except Exception as e:
        return False, [f'Invalid JSON: {e}']
    imported=data.get('custom_rules') if isinstance(data, dict) else data
    if not isinstance(imported, list):
        return False, ['Rule pack must contain a custom_rules list or be a list of rules.']
    current=read_json(CUSTOM_RULES, [])
    errors=[]; added=0
    names={r.get('name') for r in current}
    for r in imported:
        r=dict(r); r.pop('id', None)
        ok, e, cleaned=validate_rule(r)
        if not ok:
            errors.extend([f"{r.get('name','unnamed')}: {x}" for x in e]); continue
        if cleaned.get('name') in names: continue
        existing=[str(x.get('id','')) for x in current]
        i=0
        while f'custom-{i}' in existing: i+=1
        cleaned['id']=f'custom-{i}'; cleaned['enabled']=True; current.append(cleaned); names.add(cleaned.get('name')); added+=1
    write_json(CUSTOM_RULES, current)
    return True, [f'Imported {added} rules.'] + errors

def _sig_values(rule, key):
    vals = set(_as_list(rule.get(key)))
    single = rule.get('protocol') if key == 'protocol_any' else None
    if single:
        vals.add(single)
    return vals


def _rules_have_actionable_overlap(a, b):
    """Return (bool, reason) for conflicts worth showing to the user.

    This keeps the conflict page focused on actionable cleanup items.  Rules
    that share an ATT&CK technique but validate it through different protocols
    are intentionally not treated as conflicts.
    """
    reasons = []
    if a.get('name') == b.get('name'):
        reasons.append('duplicate rule name')

    # Coverage-only/broad informational rules are intentionally allowed to
    # coexist with more specific validation rules, especially when disabled.
    if a.get('coverage_only') or b.get('coverage_only'):
        return (bool(reasons), ', '.join(reasons))

    same_attack = bool(set(a.get('attack') or []) & set(b.get('attack') or []))
    same_port = bool(a.get('port') and b.get('port') and a.get('port') == b.get('port'))
    aprotos = _sig_values(a, 'protocol_any')
    bprotos = _sig_values(b, 'protocol_any')
    same_proto = bool(aprotos and bprotos and (aprotos & bprotos))
    mutually_exclusive_scope = (
        (bool(a.get('internal_to_internal')) and bool(b.get('destination_is_external'))) or
        (bool(a.get('destination_is_external')) and bool(b.get('internal_to_internal')))
    )

    agg_duplicate = False
    if a.get('aggregate') and a.get('aggregate') == b.get('aggregate'):
        aprotocol_set = set(a.get('protocols') or [])
        bprotocol_set = set(b.get('protocols') or [])
        if aprotocol_set and bprotocol_set and aprotocol_set == bprotocol_set and a.get('threshold') == b.get('threshold'):
            agg_duplicate = True
        if a.get('protocol') and b.get('protocol') and a.get('protocol') == b.get('protocol') and a.get('threshold') == b.get('threshold'):
            agg_duplicate = True
        if agg_duplicate:
            reasons.append('duplicate aggregate condition')

    if same_attack and not mutually_exclusive_scope and (same_port or same_proto or agg_duplicate):
        reasons.append('same ATT&CK technique and overlapping evidence conditions')

    # Event rules with identical protocol/port and identical threshold knobs are
    # likely duplicates when they also map to the same ATT&CK technique.
    event_overlap = (same_port or same_proto) and not mutually_exclusive_scope and not a.get('aggregate') and not b.get('aggregate')
    if event_overlap:
        same_thresholds = all(a.get(k) == b.get(k) for k in ['min_bytes','min_packets','internal_to_internal','destination_is_external'])
        if same_thresholds and same_attack:
            reasons.append('duplicate event condition')

    # Broad enabled rules using protocol_any can shadow specific single-protocol
    # rules. Surface this only when both are enabled and share the same ATT&CK.
    broad_shadow = same_attack and same_proto and (len(aprotos) > 3 or len(bprotos) > 3)
    if broad_shadow:
        reasons.append('broad rule may shadow a more specific rule')

    return (bool(reasons), ', '.join(sorted(set(reasons))))

def rule_conflicts(rules=None):
    rules = rules or load_rules()
    out=[]
    enabled = [r for r in rules if r.get('enabled', True)]
    for i,a in enumerate(enabled):
        for b in enabled[i+1:]:
            overlap, reason = _rules_have_actionable_overlap(a, b)
            if overlap:
                out.append({'rule_a':a.get('name'),'rule_b':b.get('name'),'reason':reason})
    return out[:100]

def templates():
    return RULE_TEMPLATES


# PCAP Mapper v2 Phase 2 ----------------------------------------------------
# Normalized events are now first-class rule evidence.  Flow rules still work as
# before, but a rule can also validate when an event parser produced ATT&CK
# candidates that intersect the rule's mapped ATT&CK IDs.

def _event_summary(ev):
    host = ev.get('host') or ev.get('src_ip') or ''
    src = ev.get('log_source') or 'event'
    etype = ev.get('event_type') or 'log_event'
    raw = (ev.get('raw') or '')[:160]
    return f"{src} {etype} host={host} {raw}".strip()


def _normalized_event_to_rule_event(ev):
    out = dict(ev or {})
    out.setdefault('type', 'normalized_event')
    out.setdefault('protocol', out.get('transport_protocol') or out.get('log_source') or 'Log')
    out.setdefault('dport', out.get('dst_port') or 0)
    out.setdefault('sport', out.get('src_port') or 0)
    out.setdefault('bytes', len(str(out.get('raw') or '')))
    out.setdefault('packets', 1)
    out.setdefault('summary', _event_summary(out))
    out.setdefault('flow_id', out.get('event_id') or f"event|{out.get('host')}|{out.get('event_type')}")
    return out


def _rule_matches_normalized_event(ev, r):
    if r.get('aggregate'):
        return False
    attack = set(_as_list(r.get('attack')))
    candidates = set(_as_list(ev.get('attack_candidates')))
    if attack and candidates and attack & candidates:
        return True
    rule_type = str(r.get('event_type') or '').lower()
    if rule_type in ('normalized_event', 'log_event'):
        return True
    if rule_type and rule_type == str(ev.get('event_type') or '').lower():
        return True
    if r.get('log_source') and str(r.get('log_source')).lower() not in str(ev.get('log_source') or '').lower():
        return False
    contains = r.get('text_contains') or r.get('contains') or ''
    if contains and str(contains).lower() not in str(ev.get('raw') or '').lower():
        return False
    return bool(contains or r.get('log_source'))


def explain_normalized_event_match(ev, r):
    reasons=[]
    attack = set(_as_list(r.get('attack')))
    candidates = set(_as_list(ev.get('attack_candidates')))
    overlap = sorted(attack & candidates)
    if overlap:
        reasons.append('normalized event ATT&CK candidates matched rule mapping: ' + ', '.join(overlap))
    if ev.get('event_type'):
        reasons.append('event_type=' + str(ev.get('event_type')))
    if ev.get('log_source'):
        reasons.append('log_source=' + str(ev.get('log_source')))
    if ev.get('host'):
        reasons.append('host=' + str(ev.get('host')))
    if ev.get('source_event_id'):
        reasons.append('source_event_id=' + str(ev.get('source_event_id')))
    if r.get('requires'):
        reasons.append('required telemetry available: ' + ', '.join(_as_list(r.get('requires'))))
    return reasons or ['normalized event matched rule conditions']


def attack_pipeline_diagnostics(result, validations=None, rules=None):
    result = result or {}
    validations = validations or result.get('rule_validations') or {}
    rules = rules or load_rules()
    events = result.get('normalized_events') or []
    flows = result.get('flows') or []
    techniques = result.get('techniques') or []
    observed_ids = {x.get('techniqueID') or x.get('technique_id') for x in techniques if x.get('techniqueID') or x.get('technique_id')}
    event_ids = set()
    event_types = {}
    source_counts = {}
    unmapped = 0
    for ev in events:
        source_counts[ev.get('log_source') or 'Unknown'] = source_counts.get(ev.get('log_source') or 'Unknown', 0) + 1
        event_types[ev.get('event_type') or 'unknown'] = event_types.get(ev.get('event_type') or 'unknown', 0) + 1
        cands = [x for x in ev.get('attack_candidates') or [] if x]
        if cands:
            event_ids.update(cands)
        else:
            unmapped += 1
    val_items = validations.get('validated_techniques') or result.get('validated_techniques') or []
    validated_ids = {x.get('techniqueID') for x in val_items if x.get('techniqueID')}
    matches = validations.get('matches') or []
    event_matches = [m for m in matches if m.get('evidence_type') == 'normalized_event']
    flow_matches = [m for m in matches if m.get('evidence_type') != 'normalized_event']
    return {
        'flows_available': len(flows),
        'normalized_events_available': len(events),
        'normalized_events_mapped_to_attack': len([ev for ev in events if ev.get('attack_candidates')]),
        'normalized_events_unmapped': unmapped,
        'observed_attack_ids': len(observed_ids),
        'event_attack_ids': len(event_ids),
        'validated_attack_ids': len(validated_ids),
        'rules_enabled': len([r for r in rules if r.get('enabled', True)]),
        'rule_matches_total': len(matches),
        'rule_matches_from_flows': len(flow_matches),
        'rule_matches_from_normalized_events': len(event_matches),
        'event_types': dict(sorted(event_types.items(), key=lambda kv: (-kv[1], kv[0]))[:25]),
        'log_sources': dict(sorted(source_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:25]),
    }


def build_validation_results(result, rules=None, max_matches=500):
    rules = rules or load_rules()
    flows=[]
    for f in result.get('flows', []) or []:
        ev=dict(f); ev.setdefault('type','flow'); ev.setdefault('summary', _flow_summary(ev)); flows.append(ev)
    norm_events=[_normalized_event_to_rule_event(ev) for ev in (result.get('normalized_events') or [])]
    matches=[]; validated={}; disabled=0; skipped_dependencies=[]
    enabled=[r for r in rules if r.get('enabled', True)]
    def record_match(r, m):
        nonlocal matches, validated
        m.setdefault('confidence', r.get('confidence', _default_confidence(r.get('severity'))))
        m.setdefault('severity', r.get('severity_override') or r.get('severity'))
        m.setdefault('rule_version', r.get('version','1.0'))
        m.setdefault('coverage_score', _coverage_weight(r))
        if len(matches) < max_matches:
            matches.append(m)
        for tid in r.get('attack', []):
            validated.setdefault(tid, {'techniqueID': tid, 'rules': set(), 'evidence': [], 'coverage_score': 0, 'confidence': set(), 'evidence_types': set()})
            validated[tid]['rules'].add(r.get('name'))
            validated[tid]['coverage_score'] = max(validated[tid]['coverage_score'], _coverage_weight(r))
            validated[tid]['confidence'].add(m.get('confidence','medium'))
            if m.get('evidence_type'):
                validated[tid]['evidence_types'].add(m.get('evidence_type'))
            if len(validated[tid]['evidence']) < 25:
                validated[tid]['evidence'].append(m.get('evidence',''))
    for r in rules:
        if not r.get('enabled', True):
            disabled += 1; continue
        ok, errors, _ = validate_rule(r)
        if not ok: continue
        dep_ok, missing = dependencies_met(r, result)
        if not dep_ok:
            skipped_dependencies.append({'rule': r.get('name'), 'missing': missing})
            continue
        if r.get('aggregate'):
            for am in _aggregate_matches(flows, r):
                explanation = [am.get('evidence',''), 'aggregate=' + str(r.get('aggregate')), 'threshold=' + str(r.get('threshold'))]
                m={'rule':r.get('name'),'rule_id':r.get('id'),'attack':r.get('attack',[]),'evidence':am.get('evidence'),'src_ip':am.get('src_ip'),'dst_ip':am.get('dst_ip'),'protocol':am.get('protocol'),'dport':am.get('dport'),'matched':True,'explanation':explanation,'evidence_type':'flow_aggregate'}
                record_match(r,m)
            continue
        for ev in flows:
            if _rule_matches_event(ev,r):
                flow_id=ev.get('flow_id') or f"{ev.get('src_ip')}|{ev.get('dst_ip')}|{ev.get('protocol')}|{ev.get('dport')}"
                m={'rule':r.get('name'),'rule_id':r.get('id'),'attack':r.get('attack',[]),'evidence':ev.get('summary'),'src_ip':ev.get('src_ip'),'dst_ip':ev.get('dst_ip'),'protocol':ev.get('protocol'),'dport':ev.get('dport'),'flow_id':flow_id,'matched':True,'explanation':explain_event_match(ev,r),'evidence_type':'flow'}
                record_match(r,m)
        for ev in norm_events:
            if _rule_matches_normalized_event(ev, r):
                m={'rule':r.get('name'),'rule_id':r.get('id'),'attack':r.get('attack',[]),'evidence':ev.get('summary'),'src_ip':ev.get('src_ip'),'dst_ip':ev.get('dst_ip'),'protocol':ev.get('protocol'),'dport':ev.get('dport'),'flow_id':ev.get('flow_id'),'matched':True,'explanation':explain_normalized_event_match(ev,r),'evidence_type':'normalized_event','event_type':ev.get('event_type'),'log_source':ev.get('log_source'),'host':ev.get('host')}
                record_match(r,m)
    out_validated=[]
    for tid,item in validated.items():
        out_validated.append({'techniqueID':tid,'rules':sorted(item['rules']),'evidence':item['evidence'][:10],'match_count':len(item['evidence']),'coverage_score':item['coverage_score'],'confidence':', '.join(sorted(item['confidence'])),'evidence_types':sorted(item.get('evidence_types') or [])})
    summary={'rules_evaluated':len(enabled),'matches_recorded':len(matches),'validated_techniques':len(out_validated),'rules_skipped_dependencies':len(skipped_dependencies),'normalized_events_evaluated':len(norm_events),'flow_events_evaluated':len(flows),'matches_from_normalized_events':len([m for m in matches if m.get('evidence_type')=='normalized_event']),'matches_from_flows':len([m for m in matches if m.get('evidence_type')!='normalized_event'])}
    history_item={'time':time.time(),'summary':summary}
    hist=read_json(RULE_HISTORY, [])
    hist.append(history_item)
    write_json(RULE_HISTORY, hist[-100:])
    validations={'summary':summary,'matches':matches,'validated_techniques':sorted(out_validated,key=lambda x:x['techniqueID']),'skipped_dependencies':skipped_dependencies,'history':hist[-20:]}
    validations['attack_pipeline_diagnostics']=attack_pipeline_diagnostics(result, validations, rules)
    return validations
