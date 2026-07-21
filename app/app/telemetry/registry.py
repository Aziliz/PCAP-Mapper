"""Plugin-style telemetry capability registry.

Definitions in this module are data-only and use only the Python standard
library.  The ATT&CK coverage engine imports this registry once and merges the
aliases, categories, observed components, and potential components into the
existing STIX mapping pipeline.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

TELEMETRY_STORE = Path(__file__).resolve().parents[2] / 'results' / 'telemetry_plugins.json'



def _quality_label(observed, potential):
    observed = observed or []
    potential = potential or []
    total = len(set(observed) | set(potential))
    if total >= 16:
        return 'comprehensive'
    if total >= 10:
        return 'strong'
    if total >= 5:
        return 'partial'
    return 'minimal'


def _p(name, category, aliases, observed, potential=None, description=''):
    observed = list(dict.fromkeys(observed or []))
    potential = list(dict.fromkeys((potential or []) + observed))
    return {
        'name': name,
        'category': category,
        'aliases': list(dict.fromkeys([name.lower()] + [a.lower() for a in (aliases or [])])),
        'observed_components': observed,
        'potential_components': potential,
        'description': description or f'{name} telemetry plugin',
        'enabled': True,
        'source': 'built-in',
        'confidence': 'high',
        'quality': _quality_label(observed, potential),
    }

ENDPOINT_BASE = [
    'Process Creation','Process Termination','Command Execution','Script Execution','Module Load','Image Load','Driver Load',
    'File Creation','File Modification','File Deletion','File Metadata','Hash Inventory','Registry Key Modification',
    'Network Connection Creation','DNS Query','User Account Authentication','Logon Session','Privilege Escalation',
    'Service Creation','Scheduled Job Creation','Malware Detection','Endpoint Alert','Behavioral Alert'
]
NETWORK_BASE = [
    'Network Traffic Flow','Network Traffic Content','Network Connection Creation','DNS Query','HTTP Request','TLS Connection',
    'SMB Session','SSH Session','FTP Session','RDP Session','VPN Session','Firewall Events','IDS Alert','Protocol Anomaly'
]
CLOUD_BASE = ['Cloud API','IAM Activity','User Account Authentication','Resource Modification','Object Storage Activity','Network Traffic Flow','Cloud Detection Alert','Audit Log']
IDENTITY_BASE = ['User Account Authentication','MFA Event','IAM Activity','Conditional Access','Account Management','Group Membership','SaaS Audit Log']
EMAIL_BASE = ['Email Message','Email Attachment','Email URL','Mailbox Login','Transport Rule','Malware Detection','Phishing Detection','SaaS Audit Log']
WEB_BASE = ['HTTP Request','HTTP Response','Web Server Logs','Authentication Logs','File Upload','Web Error','User Agent','Source IP']
CONTAINER_BASE = ['Container Creation','Container Start','Container Stop','Container Exec','Image Pull','Volume Mount','Kubernetes API','Service Account Activity','RBAC Change','Secret Access']
DEVOPS_BASE = ['Repository Activity','Pipeline Execution','Build Artifact','Secret Access','IAM Activity','Webhook Activity','SaaS Audit Log']
DB_BASE = ['Database Authentication','Database Query','Database Object Access','Privilege Changes','Audit Log','Network Connection Creation']
ICS_BASE = ['Industrial Protocol','PLC Command','Engineering Workstation Activity','Device State','Network Traffic Flow','Protocol Anomaly']

TELEMETRY_PLUGINS = [

    # Built-in operating system telemetry: Windows / Windows Server / Linux / macOS
    _p('Windows Security','Windows',['windows security','security.evtx','security event log','event id 4624','event id 4625','event id 4688','event id 4689','event id 4672','event id 4720','event id 4732','event id 4768','event id 4769','event id 4776'], ['User Account Authentication','Logon Session','Account Management','Group Membership','Privilege Use','Process Creation','Process Termination','Kerberos Authentication','NTLM Authentication','Object Access','Policy Change','Service Installation','Scheduled Job Creation'], ['Account Lockout','Password Change','Special Privilege Assignment','Remote Logon','Credential Validation','Audit Policy Change','Directory Service Access','Share Access']),
    _p('Windows System','Windows',['windows system','system.evtx','system event log','service control manager','event id 7045'], ['Service Creation','Service Start','Service Stop','Driver Load','System Boot','System Shutdown','Device Installation','Kernel Event'], ['Time Change','Crash Event','Windows Update Event','Service Failure']),
    _p('Windows Application','Windows',['windows application','application.evtx','application event log'], ['Application Error','Application Activity','Service Activity','Script Execution','Process Activity'], ['Application Crash','COM Activity','.NET Runtime Event','Application Install']),
    _p('Windows PowerShell Operational','Windows',['powershell operational','microsoft-windows-powershell/operational','script block logging','module logging','event id 4103','event id 4104','event id 400','event id 600'], ['PowerShell Command','Script Block Logging','Module Logging','Script Execution','Command Execution'], ['PowerShell Remoting','Encoded Command','AMSI Scan Result','Pipeline Execution','Engine Lifecycle']),
    _p('Sysmon','Windows',['sysmon','sysmon.evtx','microsoft-windows-sysmon/operational','event id 1','event id 3','event id 7','event id 11','event id 13','event id 22'], ['Process Creation','Network Connection Creation','Image Load','Driver Load','File Creation','File Modification','File Deletion','Registry Key Modification','DNS Query','Process Access','Named Pipe Creation','WMI Event Subscription'], ['Process Termination','File Create Stream Hash','Raw Disk Read','Create Remote Thread','Clipboard Data','Pipe Connected','WMI Filter','WMI Consumer','WMI Binding','File Delete Archived']),
    _p('Windows Defender','Windows',['windows defender','microsoft defender antivirus','windefend','defender operational','microsoft-windows-windows defender/operational'], ['Malware Detection','Endpoint Alert','File Quarantine','Exploit Prevention','Script Scan','AMSI Scan Result'], ['Tamper Protection','Cloud Protection Event','Ransomware Behavior','Controlled Folder Access','Attack Surface Reduction','Remediation Event']),
    _p('Defender for Endpoint','Windows',['mde','mdatp','microsoft defender for endpoint','deviceprocessevents','devicenetworkevents','devicefileevents','deviceregistryevents'], ENDPOINT_BASE + ['AMSI Scan Result','Exploit Prevention','Behavioral Alert'], ['Advanced Hunting Alert','DeviceTvmSoftwareInventory','DeviceLogonEvents','DeviceEvents','AlertEvidence','DeviceImageLoadEvents']),
    _p('Windows Firewall','Windows',['windows firewall','wfplwfs','filtering platform','event id 5156','event id 5157','pfirewall.log'], ['Firewall Events','Allowed Connection','Blocked Connection','Network Connection Creation','Policy Change'], ['Firewall Rule Change','Profile Change','IPsec Event','WFP Filter Event']),
    _p('Task Scheduler','Windows',['task scheduler','microsoft-windows-taskscheduler/operational','event id 106','event id 140','event id 200'], ['Scheduled Job Creation','Scheduled Job Modification','Scheduled Job Execution','Scheduled Job Deletion'], ['Hidden Task Indicator','Remote Task Creation','Task Failure']),
    _p('WinRM','Windows',['winrm','windows remote management','microsoft-windows-winrm/operational','wsman'], ['Remote Command','Remote Shell','Remote Service Management','User Account Authentication','PowerShell Remoting'], ['Remote Session Creation','WinRS Command','WSMan Activity']),
    _p('WMI','Windows',['wmi','wmiprvse','microsoft-windows-wmi-activity/operational','event id 5857','event id 5861'], ['WMI Query','WMI Process Creation','WMI Event Subscription','Remote WMI','Command Execution'], ['WMI Consumer','WMI Filter','Permanent Event Subscription','WMI Provider Load']),
    _p('Windows SMB','Windows',['smb','windows smb','smbclient','admin share','c$','ipc$','microsoft-windows-smbserver'], ['SMB Session','File Share Access','Named Pipe Access','Remote File Copy','User Account Authentication'], ['Admin Share Access','SMB Service Control','Share Enumeration','NTLM over SMB']),
    _p('IIS','Windows Server',['iis','w3svc','inetpub','iis access log','u_ex'], WEB_BASE + ['Web Shell Indicator'], ['Application Pool Event','Module Load','Request Filtering','Failed Request Trace']),
    _p('Windows Event Forwarding','Windows',['wef','windows event forwarding','event collector','wecutil'], ['Forwarded Event','Windows Event Log','Log Collection','Security Event Forwarding'], ['Subscription Change','Collector Health']),
    _p('AppLocker','Windows',['applocker','microsoft-windows-applocker','appidsvc'], ['Application Control','Process Block','Script Block','Policy Change'], ['DLL Block','Packaged App Block','Rule Change']),
    _p('RDP','Windows',['rdp','terminalservices','remote desktop services','event id 1149'], ['RDP Session','Remote Logon','User Account Authentication','Network Connection Creation'], ['Clipboard Redirection','Drive Redirection','Remote Desktop Gateway']),
    _p('Active Directory Domain Services','Windows Server',['active directory','ad ds','domain controller','ntds','ds access','directory service'], ['LDAP Query','Kerberos Authentication','NTLM Authentication','Directory Service Changes','Directory Service Replication','Account Management','Group Membership','Group Policy Change'], ['DCSync','SPN Query','Domain Trust Discovery','Computer Account Change','Replication Metadata']),
    _p('Windows DNS Server','Windows Server',['windows dns','dns server','microsoft-windows-dns-server','dns debug log'], ['DNS Query','DNS Zone Change','DNS Record Change','Domain Name Resolution'], ['DNS Analytical Event','Dynamic Update','Zone Transfer']),
    _p('Windows DHCP Server','Windows Server',['windows dhcp','dhcp server','microsoft-windows-dhcp-server'], ['DHCP Lease','DHCP Reservation','IPAM Activity','Device Inventory'], ['Scope Change','DHCP NACK','Rogue DHCP Indicator']),
    _p('AD FS','Windows Server',['adfs','active directory federation services'], ['Federation Event','SAML Assertion','User Account Authentication','OAuth Event','Token Issuance'], ['Token Signing Certificate Change','Relying Party Trust Change']),
    _p('Windows Certificate Services','Windows Server',['adcs','certsrv','certutil','certificate services'], ['Certificate Enrollment','Certificate Template Change','CA Configuration','PKINIT','Directory Service Changes'], ['Certificate Request','Template ACL Change','CA Backup','ESC Misconfiguration Indicator']),

    _p('Linux auditd','Linux',['auditd','audit.log','type=execve','type=syscall','type=user_auth','type=cred_acq','ausearch'], ['Process Creation','Command Execution','File Access','File Modification','Privilege Use','User Account Authentication','Kernel Audit Event','SELinux AVC','Module Load'], ['User Account Creation','Group Membership','Sudo Execution','Ptrace','Setuid Setgid','Chmod','Chown','Mount Activity']),
    _p('Linux auth.log','Linux',['auth.log','/var/log/auth.log','linux auth','pam_unix','sshd'], ['User Account Authentication','SSH Session','Sudo Execution','su Command','PAM Event','Logon Session'], ['Failed Login','Password Change','Account Lockout','Public Key Authentication']),
    _p('Linux secure','Linux',['/var/log/secure','secure log','redhat secure','centos secure','rhel secure'], ['User Account Authentication','SSH Session','Sudo Execution','su Command','PAM Event'], ['Failed Login','Account Lockout','SELinux AVC']),
    _p('sshd','Linux',['openssh','sshd','ssh login','accepted publickey','accepted password','failed password'], ['SSH Session','User Account Authentication','Remote Access','Network Connection Creation'], ['Port Forwarding','SFTP Activity','Public Key Authentication','Password Authentication']),
    _p('sudo','Linux',['sudo log','sudo:', 'sudoers'], ['Sudo Execution','Privilege Escalation','Command Execution','User Account Authentication'], ['Failed Sudo','User Not In Sudoers','TTY Command']),
    _p('cron','Linux',['cron','crond','anacron','crontab'], ['Scheduled Job Creation','Scheduled Job Modification','Scheduled Job Execution','Scheduled Job Deletion'], ['User Crontab Change','System Crontab Change','Anacron Activity']),
    _p('systemd','Linux',['systemd','journalctl','systemctl','unit file'], ['Service Creation','Service Modification','Service Start','Service Stop','Scheduled Job Creation'], ['Timer Creation','Daemon Reload','Unit File Modification','User Service']),
    _p('journald','Linux',['journald','systemd-journal','journalctl'], ['System Log','Service Activity','Process Activity','Authentication Logs','Kernel Event'], ['Boot ID','Unit Event','Structured Log Field']),
    _p('Linux kernel','Linux',['kern.log','dmesg','kernel log','kmsg'], ['Kernel Event','Module Load','Device Event','Network Interface Event','Filesystem Event'], ['OOM Event','Kernel Warning','USB Device','Rootkit Indicator']),
    _p('rsyslog','Linux',['rsyslog','imfile','omfwd'], ['Syslog Event','Log Collection','Authentication Logs','System Log'], ['Forwarding Rule','Queue Status']),
    _p('syslog-ng','Linux',['syslog-ng'], ['Syslog Event','Log Collection','Authentication Logs','System Log'], ['Destination Health','Parser Event']),
    _p('Apache HTTP Server','Linux/Web',['apache','httpd','access_log','error_log','mod_security'], WEB_BASE, ['ModSecurity Alert','Virtual Host','Reverse Proxy Event']),
    _p('Nginx','Linux/Web',['nginx','nginx access','nginx error'], WEB_BASE, ['Reverse Proxy Event','Upstream Error','WAF Event']),
    _p('Docker','Container',['docker','dockerd','docker daemon','docker events'], ['Container Creation','Container Start','Container Stop','Container Exec','Image Pull','Volume Mount','Network Connection Creation'], ['Privileged Container','Docker API','Container Health','Image Build']),
    _p('containerd','Container',['containerd','ctr events'], ['Container Creation','Container Start','Container Stop','Image Pull','Container Exec'], ['Snapshotter Event','Runtime Event']),
    _p('Podman','Container',['podman'], ['Container Creation','Container Start','Container Stop','Container Exec','Image Pull','Volume Mount'], ['Rootless Container','Pod Event']),
    _p('Kubernetes Audit','Container',['kubernetes audit','k8s audit','apiserver audit'], CONTAINER_BASE + ['Pod Creation','Secret Read','ConfigMap Read'], ['Port Forward','Attach','Admission Review','Namespace Change','Deployment Change','Service Account Token Use']),
    _p('SELinux','Linux',['selinux','avc: denied','setroubleshoot'], ['SELinux AVC','Policy Violation','File Access','Process Activity'], ['Policy Update','Context Change']),
    _p('AppArmor','Linux',['apparmor','audit apparmor'], ['AppArmor Violation','Policy Violation','File Access','Process Activity'], ['Profile Load','Policy Update']),
    _p('Falco','Container',['falco','falco alert'], ['Runtime Security Alert','Process Creation','File Access','Network Connection Creation','Container Exec'], ['Container Escape','Reverse Shell','Sensitive File Read','Kubernetes Privilege Escalation']),

    _p('Apple Unified Logging','macOS',['apple unified logging','unified log','log show','oslog'], ['Process Activity','Application Activity','Authentication Logs','Network Connection Creation','Security Policy Event'], ['TCC Decision','Gatekeeper Decision','XProtect Event','System Extension Event']),
    _p('OpenBSM','macOS',['openbsm','audit_control','praudit'], ['Process Creation','File Access','User Account Authentication','Privilege Use','System Configuration Change'], ['User Session','Audit Policy Change']),
    _p('launchd','macOS',['launchd','launchctl','launch agent','launch daemon'], ['Service Creation','Service Modification','Service Start','Service Stop','Persistence Item Modified'], ['Launch Agent Created','Launch Daemon Created','Service Loaded','Service Unloaded']),
    _p('Gatekeeper','macOS',['gatekeeper','spctl','syspolicyd'], ['Security Policy Event','Downloaded File Assessment','Application Control'], ['Gatekeeper Bypass Indicator','Quarantine Attribute']),
    _p('TCC','macOS',['tcc','tccd','privacydb'], ['Privacy Permission Grant','File Access','Application Activity'], ['Full Disk Access','Accessibility Permission','Camera Access','Microphone Access']),
    _p('XProtect','macOS',['xprotect','xprotectservice'], ['Malware Detection','File Quarantine','Endpoint Alert'], ['YARA Match','Remediation Event']),
    _p('Jamf','macOS/MDM',['jamf','jamf pro','jamf protect'], ['MDM Activity','Device Inventory','Policy Execution','Endpoint Alert','File Access'], ['Configuration Profile Change','Smart Group Change']),
    _p('Santa','macOS',['santa binary authorization','santa'], ['Application Control','Process Block','Binary Allow','Binary Block'], ['Rule Change','Sync Event']),
    _p('macOS Endpoint Security','macOS',['endpoint security framework','eslogger'], ['Process Creation','File Access','Network Connection Creation','Code Signing Event','Endpoint Alert'], ['ES_AUTH_EXEC','ES_NOTIFY_OPEN','ES_NOTIFY_RENAME','ES_NOTIFY_MMAP']),
    _p('FileVault','macOS',['filevault','fdesetup'], ['Disk Encryption Event','Authentication Logs','Recovery Key Activity'], ['Encryption Status Change','Key Rotation']),

    # Deep network sensor and firewall telemetry
    _p('Zeek','Network',['zeek','bro','conn.log','dns.log','http.log','ssl.log','x509.log','files.log','ftp.log','smb.log','kerberos.log','ssh.log','ntlm.log','rdp.log','smtp.log','notice.log','weird.log'], ['Network Traffic Flow','DNS Query','HTTP Request','TLS Connection','X.509 Certificate','File Transfer','FTP Session','SMB Session','Kerberos Activity','SSH Session','NTLM Activity','RDP Session','SMTP Session','Zeek Notice','Protocol Anomaly'], ['Intel Match','Software Identification','User Agent','JA3 Fingerprint','DHCP Lease','Tunnel Activity']),
    _p('Suricata','Network',['suricata','eve.json','suricata alert','suricata dns','suricata http','suricata tls','suricata smb','suricata fileinfo'], ['IDS Alert','Network Traffic Flow','DNS Query','HTTP Request','TLS Connection','SMB Session','FTP Session','SSH Session','File Transfer','Protocol Anomaly'], ['Signature Match','Exploit Attempt','C2 Beaconing','Malware Callback','JA3 Fingerprint','Flow Event']),
    _p('Packetbeat','Network',['packetbeat'], ['Network Traffic Flow','DNS Query','HTTP Request','TLS Connection','Database Query','User Account Authentication'], ['Protocol Metadata','Transaction Timing']),
    _p('NetFlow','Network',['netflow','netflow v5','netflow v9'], ['Network Traffic Flow','Source IP','Destination IP','Network Connection Creation'], ['Byte Count','Flow Duration']),
    _p('IPFIX','Network',['ipfix','netflow v10'], ['Network Traffic Flow','Source IP','Destination IP','Network Connection Creation'], ['Application ID','Exporter Metadata']),
    _p('Cisco ASA','Firewall',['cisco asa','asa syslog','asa-','%asa','asa vpn'], ['Firewall Events','Allowed Connection','Blocked Connection','NAT Translation','VPN Session','User Account Authentication','ACL Decision'], ['Connection Teardown','Threat Detection','Failover Event','AnyConnect Session']),
    _p('Cisco IOS','Network Device',['cisco ios','ios syslog','%sys-','%sec_login','%config_i'], ['Network Device Authentication','Configuration Change','Interface Status','ACL Decision','Routing Event','SNMP Activity'], ['Command Accounting','NetFlow Export','Privilege Change']),
    _p('Cisco NX-OS','Network Device',['nx-os','nexus','cisco nxos'], ['Network Device Authentication','Configuration Change','Interface Status','ACL Decision','Routing Event'], ['VDC Event','Fabric Event']),
    _p('Cisco Firepower','Firewall',['firepower','ftd','fmc','sourcefire'], ['Firewall Events','IDS Alert','Malware Detection','Allowed Connection','Blocked Connection','VPN Session'], ['Intrusion Event','File Malware Event','Security Intelligence Match']),
    _p('Palo Alto Firewall','Firewall',['palo alto','pan-os','panos','traffic log','threat log','globalprotect'], ['Firewall Events','Allowed Connection','Blocked Connection','Threat Prevention Alert','URL Filtering','TLS Connection','VPN Session','Application Identification'], ['WildFire Alert','DNS Security Event','User-ID Mapping','Decryption Event']),
    _p('Fortinet FortiGate','Firewall',['fortigate','fortinet','fortios'], ['Firewall Events','Allowed Connection','Blocked Connection','VPN Session','IPS Alert','Antivirus Alert','Web Filter Event'], ['FortiGuard Match','Application Control','SSL Inspection']),
    _p('Check Point','Firewall',['checkpoint','check point','smartlog','log exporter'], ['Firewall Events','Allowed Connection','Blocked Connection','VPN Session','IPS Alert','Application Identification'], ['Threat Emulation','Anti-Bot Alert','Blade Event']),
    _p('SonicWall','Firewall',['sonicwall'], ['Firewall Events','Allowed Connection','Blocked Connection','VPN Session','IPS Alert','Web Filter Event'], ['Gateway AV Alert','Application Control']),
    _p('pfSense','Firewall',['pfsense','filterlog'], ['Firewall Events','Allowed Connection','Blocked Connection','VPN Session','DHCP Lease','DNS Query'], ['Suricata Package Alert','Snort Package Alert']),
    _p('OPNsense','Firewall',['opnsense'], ['Firewall Events','Allowed Connection','Blocked Connection','VPN Session','DHCP Lease','DNS Query'], ['Zenarmor Alert','Suricata Package Alert']),
    _p('Squid Proxy','Proxy',['squid','access.log squid'], ['HTTP Request','Proxy Event','User Account Authentication','URL Filtering','Source IP'], ['Cache Event','CONNECT Tunnel']),
    _p('HAProxy','Load Balancer',['haproxy'], ['HTTP Request','TLS Connection','Load Balancer Event','Source IP','User Agent'], ['Backend Health','Rate Limit Event']),
    _p('F5 BIG-IP','Load Balancer',['f5','big-ip','bigip','ltm','asm','apm'], ['Load Balancer Event','HTTP Request','TLS Connection','WAF Alert','VPN Session','User Account Authentication'], ['iRule Event','ASM Violation','Pool Member Health','APM Session']),
    _p('Wireless Controller','Network',['wireless controller','wlc','cisco wlc','unifi controller','ruckus','mist','meraki wireless'], ['Wireless Association','Wireless Authentication','RADIUS','Device Inventory','Network Traffic Flow'], ['Rogue AP','Client Roaming','SSID Change']),

    # Microsoft / SIEM / XDR
    _p('Microsoft Sentinel','SIEM',['sentinel','azure sentinel','log analytics','analytics rule','fusion alert','ueba'], ['SIEM Alert','Analytics Rule','Incident','Threat Intelligence','Watchlist','Automation Rule','SaaS Audit Log'], ['UEBA Alert','Fusion Alert','Hunting Query','SOAR Automation','Entity Behavior']),
    _p('Microsoft Defender XDR','EDR/XDR',['defender xdr','microsoft 365 defender','m365 defender','defender portal'], ENDPOINT_BASE + IDENTITY_BASE + EMAIL_BASE, ['Advanced Hunting Alert','DeviceProcessEvents','DeviceNetworkEvents','DeviceFileEvents','DeviceRegistryEvents','IdentityLogonEvents','CloudAppEvents','EmailEvents']),
    _p('Defender for Identity','Identity',['mdi','microsoft defender for identity','azure atp'], ['Kerberos Authentication','NTLM Authentication','LDAP Query','Directory Service Replication','Account Enumeration','Lateral Movement Alert','Identity Alert'], ['DCSync Detection','Kerberoasting Detection','AS-REP Roasting Detection','Suspicious LDAP','Honeytoken Alert']),
    _p('Defender for Office 365','Email',['mdo','defender for office','office 365 defender','safe links','safe attachments'], EMAIL_BASE, ['URL Detonation','Attachment Detonation','Mailbox Rule Alert','OAuth App Consent','Impersonation Detection']),
    _p('Defender for Cloud Apps','SaaS',['mcas','cloud app security','defender cloud apps'], ['SaaS Audit Log','Cloud App Activity','OAuth App Activity','File Access','User Account Authentication','Anomalous Login'], ['Impossible Travel','Mass Download','App Governance Alert']),
    _p('Defender for Cloud','Cloud',['azure defender','microsoft defender for cloud'], CLOUD_BASE + ['Container Alert','VM Alert'], ['Kubernetes Alert','Storage Alert','SQL Alert','Container Registry Alert']),
    _p('Active Directory Certificate Services','Identity',['ad cs','adcs','certificate services','certsrv','pkinit'], ['Certificate Enrollment','Certificate Template Change','CA Configuration','Kerberos Authentication','Directory Service Changes'], ['ESC1','ESC2','ESC3','ESC4','ESC5','ESC6','ESC7','ESC8','ESC9','ESC10','ESC11','ESC13','ESC15','ESC16']),

    # EDR / endpoint
    _p('CrowdStrike Falcon','EDR/XDR',['crowdstrike','falcon sensor','processrollup2','scriptcontrol','falcon detection'], ENDPOINT_BASE, ['ProcessRollup','ScriptControl','Sensor Health','USB Device','Detection Summary','Prevention Alert','IOA Alert']),
    _p('Carbon Black','EDR/XDR',['cb response','cb defense','vmware carbon black','carbonblack','cb edr'], ENDPOINT_BASE, ['Binary Reputation','Sensor Alert','Process Lineage','Watchlist Hit','Live Response']),
    _p('SentinelOne','EDR/XDR',['sentinelone','sentinel one','s1 agent','storyline'], ENDPOINT_BASE, ['Storyline','Rollback Event','Threat Event','Deep Visibility','Agent Health']),
    _p('Elastic Security','SIEM',['elastic agent','elastic endpoint','elastic security','fleet','beats','winlogbeat','auditbeat','filebeat','packetbeat'], ENDPOINT_BASE + NETWORK_BASE + ['File Integrity Monitoring'], ['EQL Alert','Endpoint Alert','Fleet Policy','Osquery Result']),
    _p('Splunk Enterprise Security','SIEM',['splunk es','enterprise security','splunk cim','notable event'], ['SIEM Alert','Notable Event','Correlation Search','CIM Authentication','CIM Network Traffic','CIM Endpoint','Threat Intelligence'], ['Risk Notable','UBA Finding','Adaptive Response']),
    _p('Tanium','Endpoint',['tanium threat response','tanium live response','tanium'], ENDPOINT_BASE + ['Package Inventory','Patch Inventory'], ['Live Response','Threat Response Alert','Comply Finding']),
    _p('Wazuh','Endpoint',['wazuh','ossec'], ['File Integrity Monitoring','Rootcheck','Authentication Logs','Process Activity','Malware Detection','Configuration Audit','Syscheck'], ['Vulnerability Detection','Docker Listener','SCA Finding']),
    _p('Trellix','EDR/XDR',['mcafee epo','trellix edr','trellix'], ENDPOINT_BASE, ['Exploit Prevention','ENS Alert','EPO Event']),
    _p('Trend Micro','EDR/XDR',['vision one','trend micro','deep security'], ENDPOINT_BASE, ['Behavior Monitoring','Exploit Prevention','Web Reputation','Integrity Monitoring']),
    _p('Sophos Intercept X','EDR/XDR',['sophos edr','sophos intercept','sophos central'], ENDPOINT_BASE, ['CryptoGuard Alert','Exploit Prevention','Peripheral Control']),
    _p('Cortex XDR','EDR/XDR',['palo alto cortex','cortex xdr'], ENDPOINT_BASE + NETWORK_BASE, ['BIOC Alert','XDR Incident','Causality Chain']),
    _p('Cybereason','EDR/XDR',['cybereason'], ENDPOINT_BASE, ['Malop','Process Tree','Threat Alert']),
    _p('Red Canary','EDR/XDR',['red canary'], ENDPOINT_BASE + ['Detection Engineering Alert'], ['Confirmed Threat','Atomic Test Result']),
    _p('osquery Fleet','Endpoint',['fleetdm','kolide','osquery fleet'], ['Process Inventory','Listening Ports','Logged-in Users','File Metadata','Package Inventory','Kernel Modules','Startup Items','Crontab Entries','Users and Groups','Network Connections','Certificates'], ['Browser Extensions','YARA Result','Distributed Query Result']),

    # Cloud
    _p('AWS CloudTrail','Cloud',['cloudtrail','aws api'], CLOUD_BASE + ['AssumeRole','Console Login','Access Key Activity'], ['Organizations Event','KMS Activity','Lambda Activity','EKS Audit']),
    _p('AWS GuardDuty','Cloud',['guardduty'], ['Cloud Detection Alert','DNS Query','VPC Flow','IAM Activity','Malware Detection'], ['EKS Runtime Alert','S3 Finding','RDS Login Finding']),
    _p('AWS Security Hub','Cloud',['security hub','aws securityhub'], ['Security Finding','Cloud Detection Alert','Compliance Finding'], ['ASFF Finding','Control Result']),
    _p('AWS Inspector','Cloud',['inspector2','aws inspector'], ['Vulnerability Finding','Package Inventory','Container Image Finding'], ['SBOM','Runtime Finding']),
    _p('AWS Config','Cloud',['aws config'], ['Resource Configuration','Configuration Change','Compliance Finding'], ['Relationship Change','Remediation Event']),
    _p('AWS IAM','Cloud',['aws iam','iam credential report'], ['IAM Activity','User Account Authentication','Access Key Activity','Policy Change','Role Change'], ['Credential Report','Service Last Accessed']),
    _p('AWS VPC Flow Logs','Cloud',['vpc flow logs','aws flow logs'], ['Network Traffic Flow','Firewall Events','Source IP','Destination IP'], ['Transit Gateway Flow','Rejected Flow']),
    _p('Route53 Resolver','Cloud',['route53','route 53','resolver query log'], ['DNS Query','Domain Name Resolution'], ['DNS Firewall Alert']),
    _p('Azure Activity','Cloud',['azureactivity','azure activity log'], CLOUD_BASE, ['Resource Lock Change','Policy Assignment','Role Assignment']),
    _p('Entra ID','Identity',['azure ad','entra id','aad signin','conditional access'], IDENTITY_BASE, ['Risky Sign-in','Service Principal Activity','App Registration','Consent Grant','Privileged Identity Management']),
    _p('Azure Key Vault','Cloud',['key vault','azure keyvault'], ['Secret Access','Key Access','Certificate Access','Cloud API','IAM Activity'], ['Purge Event','Backup Event']),
    _p('Azure Storage','Cloud',['azure storage logs','blob storage'], ['Object Storage Activity','Cloud API','File Access','Network Traffic Flow'], ['Blob Delete','SAS Token Use']),
    _p('Google Cloud Audit Logs','Cloud',['gcp audit','google cloud audit','cloudaudit.googleapis'], CLOUD_BASE, ['Service Account Activity','Admin Activity','Data Access']),
    _p('Google Security Command Center','Cloud',['security command center','gcp scc'], ['Security Finding','Cloud Detection Alert','IAM Activity'], ['Event Threat Detection','Container Threat Detection']),
    _p('Google VPC Flow Logs','Cloud',['gcp vpc flow','google vpc flow'], ['Network Traffic Flow','Source IP','Destination IP'], ['Firewall Rule Match']),
    _p('Google Cloud Armor','Cloud',['cloud armor'], ['HTTP Request','Firewall Events','WAF Alert','Network Traffic Content'], ['Bot Management','DDoS Alert']),

    # Identity / auth
    _p('Okta','Identity',['okta','okta system log'], IDENTITY_BASE, ['App Assignment','Device Trust','Risk Engine','Admin Activity','API Token Activity']),
    _p('Duo','Identity',['duo security','duo mfa'], ['MFA Event','User Account Authentication','Device Health','Trusted Endpoint','Admin Activity'], ['Bypass Code','Policy Deny']),
    _p('Ping Identity','Identity',['pingfederate','pingone','ping identity'], IDENTITY_BASE, ['Federation Event','SAML Assertion','OAuth Event']),
    _p('LDAP','Identity',['ldap bind','openldap','ldapsearch'], ['LDAP Query','User Account Authentication','Directory Object Access'], ['Anonymous Bind','Search Filter']),
    _p('RADIUS','Identity',['radius','freeradius'], ['User Account Authentication','VPN Session','Wireless Authentication'], ['Accounting Start','Accounting Stop']),
    _p('TACACS','Identity',['tacacs','tacacs+'], ['Network Device Authentication','Command Execution','Privilege Changes'], ['Command Accounting']),
    _p('FreeIPA','Identity',['freeipa','ipa server'], ['Kerberos Authentication','LDAP Query','User Account Authentication','Directory Service Changes'], ['HBAC Rule Change']),

    # Email / SaaS
    _p('Exchange','Email',['exchange server','owa','ews','exchange transport'], EMAIL_BASE + ['Admin Audit Log'], ['Mailbox Rule','EWS Activity','OWA Login']),
    _p('Exchange Online','Email',['exchange online','exo audit','office 365 audit'], EMAIL_BASE + ['SaaS Audit Log'], ['Unified Audit Log','OAuth Consent','Inbox Rule']),
    _p('Proofpoint','Email',['proofpoint','tap alert'], EMAIL_BASE, ['URL Rewrite','Attachment Sandbox','Impostor Alert']),
    _p('Mimecast','Email',['mimecast'], EMAIL_BASE, ['Impersonation Protection','URL Protect','Attachment Protect']),
    _p('Microsoft 365','SaaS',['m365 audit','office 365 management activity','o365 audit'], ['SaaS Audit Log','Email Activity','File Access','User Account Authentication','OAuth App Activity','Admin Activity'], ['Teams Activity','SharePoint File Activity','OneDrive File Activity']),
    _p('Google Workspace','SaaS',['google workspace','google admin audit','gmail audit'], ['SaaS Audit Log','Email Activity','File Access','User Account Authentication','Admin Activity'], ['Drive Sharing','OAuth App Activity']),
    _p('Slack','SaaS',['slack audit','slack enterprise'], ['SaaS Audit Log','User Account Authentication','File Access','App Installation','Admin Activity'], ['Data Export','Token Activity']),
    _p('Teams','SaaS',['microsoft teams','teams audit'], ['SaaS Audit Log','User Account Authentication','File Access','Chat Activity','Admin Activity'], ['App Installation','External User Activity']),
    _p('Zoom','SaaS',['zoom audit','zoom rooms'], ['SaaS Audit Log','User Account Authentication','Meeting Activity','Admin Activity'], ['Recording Access','App Marketplace Event']),

    # DNS / network security
    _p('Infoblox','DNS/DHCP',['infoblox','nios'], ['DNS Query','DHCP Lease','IPAM Activity','DNS Security Alert'], ['RPZ Hit','DGA Detection']),
    _p('Cisco Umbrella','DNS/DHCP',['umbrella','opendns'], ['DNS Query','Proxy Event','Malware Detection','User Account Authentication'], ['Destination List Match','Investigate Indicator']),
    _p('Corelight','Network',['corelight'], NETWORK_BASE + ['Zeek Notice','Zeek Intel Match','X.509 Certificate','Kerberos Activity','NTLM Activity'], ['Corelight Enrichment','Suricata Alert']),
    _p('Arkime','Network',['arkime','moloch'], ['Session Metadata','Network Traffic Flow','SPI Field','PCAP Index','HTTP Request','DNS Query','TLS Connection'], ['Hunt Query','Full Packet Capture']),
    _p('Security Onion','Network',['security onion'], NETWORK_BASE + ['Zeek Log','Suricata Alert','Stenographer PCAP','Fleet Osquery'], ['Hunt Alert','Case Event']),
    _p('ExtraHop RevealX','Network',['extrahop','revealx'], NETWORK_BASE + ['Protocol Metadata','Device Behavior','Threat Alert'], ['Decryption Metadata','Entity Behavior']),
    _p('Juniper SRX','Firewall',['juniper srx','junos security'], NETWORK_BASE + ['NAT Translation','ACL Decision'], ['IDP Alert','AppSecure Event']),
    _p('Sophos XG','Firewall',['sophos xg','sophos firewall'], NETWORK_BASE + ['Web Filter Event','VPN Session'], ['ATP Alert']),
    _p('Barracuda Firewall','Firewall',['barracuda firewall'], NETWORK_BASE + ['VPN Session','Web Filter Event'], ['Advanced Threat Protection']),
    _p('WatchGuard','Firewall',['watchguard','firebox'], NETWORK_BASE + ['VPN Session','IPS Alert'], ['APT Blocker Alert']),
    _p('Versa','Firewall',['versa director','versa analytics'], NETWORK_BASE + ['SD-WAN Event','VPN Session'], ['Secure Web Gateway Event']),
    _p('Aruba Wireless','Network',['aruba controller','aruba central'], ['Wireless Association','Wireless Authentication','RADIUS','Device Inventory','Network Traffic Flow'], ['Rogue AP','Client Health']),
    _p('AnyConnect','VPN',['cisco anyconnect'], ['VPN Session','User Account Authentication','Remote Access','Device Posture'], ['Secure Client Event']),
    _p('GlobalProtect','VPN',['globalprotect'], ['VPN Session','User Account Authentication','HIP Check','Remote Access'], ['Portal Login','Gateway Login']),
    _p('Pulse Secure','VPN',['pulse secure','ivanti connect secure'], ['VPN Session','User Account Authentication','Remote Access'], ['Host Checker']),
    _p('OpenVPN','VPN',['openvpn'], ['VPN Session','User Account Authentication','Remote Access'], ['TLS Handshake']),
    _p('WireGuard','VPN',['wireguard'], ['VPN Session','Network Traffic Flow','Remote Access'], ['Peer Handshake']),

    # Virtualization / infrastructure
    _p('VMware vCenter','Virtualization',['vcenter','vmware vcenter'], ['VM Creation','VM Deletion','Snapshot Activity','Host Login','Role Change','Task Event'], ['vMotion','Datastore Access']),
    _p('VMware ESXi','Virtualization',['esxi','vmkernel'], ['Host Login','VM Activity','Datastore Access','Network Traffic Flow','System Log'], ['SSH Enable','Shell Command']),
    _p('VMware NSX','Virtualization',['nsx-t','vmware nsx'], ['Firewall Events','Network Traffic Flow','Microsegmentation Event','VPN Session'], ['IDS Alert']),
    _p('Hyper-V','Virtualization',['hyper-v','vmms'], ['VM Creation','VM State Change','Virtual Switch Event','Host Login','Service Activity'], ['Checkpoint Activity']),
    _p('Nutanix Prism','Virtualization',['nutanix prism','ahv'], ['VM Creation','Snapshot Activity','Host Login','Storage Event','Network Event'], ['Prism Alert']),
    _p('NetApp','Storage',['netapp','ontap'], ['File Access','SMB Session','NFS Access','Authentication Logs','Snapshot Activity'], ['FPolicy Event']),
    _p('Dell Isilon','Storage',['isilon','powerscale'], ['File Access','SMB Session','NFS Access','Authentication Logs'], ['Audit Event']),
    _p('Synology','Storage',['synology'], ['File Access','SMB Session','Authentication Logs','Admin Activity'], ['Package Event']),
    _p('QNAP','Storage',['qnap'], ['File Access','SMB Session','Authentication Logs','Admin Activity'], ['Malware Remover Alert']),

    # Containers / DevOps
    _p('OpenShift','Container',['openshift','ocp audit'], CONTAINER_BASE, ['SecurityContextConstraints','Route Change','ImageStream Activity']),
    _p('Rancher','Container',['rancher'], CONTAINER_BASE + ['Admin Activity'], ['Cluster Role Change']),
    _p('AKS','Container',['aks audit','azure kubernetes'], CONTAINER_BASE + CLOUD_BASE, ['Azure RBAC for Kubernetes']),
    _p('EKS','Container',['eks audit','aws eks'], CONTAINER_BASE + CLOUD_BASE, ['IRSA Activity']),
    _p('GKE','Container',['gke audit','google kubernetes'], CONTAINER_BASE + CLOUD_BASE, ['Workload Identity Activity']),
    _p('GitHub Enterprise','DevOps',['github enterprise','github audit','github actions'], DEVOPS_BASE, ['Branch Protection Change','Dependabot Alert','Secret Scanning Alert']),
    _p('GitLab','DevOps',['gitlab audit','gitlab ci'], DEVOPS_BASE, ['Runner Activity','Merge Request Activity']),
    _p('Jenkins','DevOps',['jenkins'], DEVOPS_BASE, ['Job Configuration Change','Agent Connection']),
    _p('Azure DevOps','DevOps',['azure devops','ado audit'], DEVOPS_BASE + ['Work Item Activity'], ['Service Connection Change']),
    _p('Terraform','DevOps',['terraform cloud','terraform enterprise'], ['Infrastructure Plan','Infrastructure Apply','State Access','Secret Access','Cloud API'], ['Workspace Change']),
    _p('Ansible','DevOps',['ansible tower','awx','ansible automation'], ['Command Execution','Configuration Change','Credential Use','Inventory Activity'], ['Playbook Run']),

    # SIEMs
    _p('QRadar','SIEM',['qradar'], ['SIEM Alert','Offense','Correlation Rule','Network Flow','Asset Profile'], ['AQL Search']),
    _p('LogRhythm','SIEM',['logrhythm'], ['SIEM Alert','Alarm','Correlation Rule','User Activity'], ['SmartResponse']),
    _p('ArcSight','SIEM',['arcsight','esm'], ['SIEM Alert','Correlation Rule','CEF Event','User Activity'], ['Active List Match']),
    _p('Sumo Logic','SIEM',['sumo logic','sumologic'], ['SIEM Alert','Cloud SIEM Insight','Log Search','Network Traffic Flow'], ['Entity Criticality']),
    _p('Chronicle','SIEM',['google chronicle','secops','udm event'], ['SIEM Alert','UDM Event','Threat Intelligence','User Activity','Network Traffic Flow'], ['YARA-L Detection']),

    # Databases
    _p('SQL Server','Database',['mssql','sql server audit'], DB_BASE, ['Extended Events','SQL Agent Job']),
    _p('Oracle Database','Database',['oracle audit','oracle database'], DB_BASE, ['Unified Audit','TNS Listener']),
    _p('PostgreSQL','Database',['postgresql','postgres audit','pgaudit'], DB_BASE, ['DDL Event','Role Change']),
    _p('MySQL','Database',['mysql audit','mariadb audit'], DB_BASE, ['General Log','Slow Query Log']),

    # OT/ICS
    _p('Modbus','OT/ICS',['modbus'], ICS_BASE + ['Modbus Function Code'], ['Write Coil','Write Register']),
    _p('DNP3','OT/ICS',['dnp3'], ICS_BASE + ['DNP3 Function'], ['Control Relay Output Block']),
    _p('OPC-UA','OT/ICS',['opc ua','opc-ua'], ICS_BASE + ['OPC Method Call','OPC Subscription'], ['Write Request']),
    _p('BACnet','OT/ICS',['bacnet'], ICS_BASE + ['BACnet Object Access'], ['Write Property']),
    _p('Siemens S7','OT/ICS',['siemens s7','s7comm'], ICS_BASE + ['PLC Block Transfer'], ['Stop PLC','Download Block']),
    _p('Rockwell Automation','OT/ICS',['ethernet/ip','cip','rockwell'], ICS_BASE + ['CIP Command'], ['Controller Mode Change']),
    _p('Schneider Electric','OT/ICS',['schneider','modicon'], ICS_BASE + ['PLC Command'], ['Logic Download']),

    # Additional common telemetry plugins added during verification pass
    _p('MariaDB','Database',['mariadb','mariadb audit','mariadb server audit'], DB_BASE, ['General Log','Slow Query Log','Binary Log','Role Change']),
    _p('MongoDB','Database',['mongodb','mongod audit','mongo audit'], ['Database Authentication','Database Query','Database Object Access','Privilege Changes','Audit Log','Network Connection Creation','Collection Access'], ['Command Audit','Replica Set Event','Authz Failure']),
    _p('Redis','Database',['redis','redis audit','redis log'], ['Database Authentication','Database Query','Key Access','Configuration Change','Audit Log','Network Connection Creation'], ['Command Monitor','Module Load','Replication Event']),
    _p('OpenLDAP','Identity',['openldap','slapd','ldap audit'], ['LDAP Query','User Account Authentication','Directory Service Changes','Group Membership','Authentication Logs'], ['Bind Failure','Schema Change','Replication Activity']),
    _p('Google Cloud IAM','Cloud',['gcp iam','google cloud iam','gcloud iam'], CLOUD_BASE + ['IAM Policy Change','Service Account Activity','Key Creation'], ['Workload Identity Activity','Privileged Role Grant']),
    _p('Azure RBAC','Cloud',['azure rbac','role assignment write','microsoft.authorization'], CLOUD_BASE + ['IAM Policy Change','Role Assignment','Privileged Role Grant'], ['PIM Activation','Deny Assignment Change']),
    _p('Exchange Server','Email',['exchange server','exchange on-prem','owa','ews','exchange transport'], EMAIL_BASE + ['OWA Login','EWS Activity','Mailbox Audit'], ['Transport Agent Event','Admin Audit']),
    _p('Palo Alto PAN-OS','Firewall',['pan-os','palo alto pan-os','traffic log','threat log','url log'], NETWORK_BASE + ['Application Identification','URL Filtering','Threat Prevention Alert','VPN Session'], ['WildFire Alert','Decryption Event']),
    _p('Sophos Firewall','Firewall',['sophos firewall','sophos xgs','sophos utm'], NETWORK_BASE + ['Web Filter Event','VPN Session','IPS Alert'], ['ATP Alert','Sandbox Alert']),
    _p('Fortinet FortiAnalyzer','SIEM',['fortianalyzer','fortinet analyzer'], ['SIEM Alert','Firewall Events','VPN Session','Threat Prevention Alert','Log Collection'], ['Event Correlation','Report Event']),
]



def _split_csv(value):
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return [v.strip() for v in re.split(r'[,\n]+', str(value or '')) if v.strip()]


def normalize_plugin(plugin, source='custom'):
    name = str(plugin.get('name') or '').strip()
    category = str(plugin.get('category') or 'Custom').strip() or 'Custom'
    aliases = _split_csv(plugin.get('aliases'))
    observed = _split_csv(plugin.get('observed_components'))
    potential = _split_csv(plugin.get('potential_components'))
    desc = str(plugin.get('description') or '').strip()
    enabled = plugin.get('enabled', True)
    if isinstance(enabled, str):
        enabled = enabled.lower() not in ('0','false','no','off','disabled')
    out = _p(name, category, aliases, observed, potential, desc)
    out['enabled'] = bool(enabled)
    out['source'] = source
    out['confidence'] = str(plugin.get('confidence') or out.get('confidence') or 'high')
    out['quality'] = _quality_label(out.get('observed_components'), out.get('potential_components'))
    return out


def _load_store():
    try:
        if TELEMETRY_STORE.exists():
            data = json.loads(TELEMETRY_STORE.read_text())
            if isinstance(data, dict):
                data.setdefault('custom_plugins', [])
                data.setdefault('disabled_plugins', [])
                return data
    except Exception:
        pass
    return {'custom_plugins': [], 'disabled_plugins': []}


def _save_store(data):
    TELEMETRY_STORE.parent.mkdir(parents=True, exist_ok=True)
    TELEMETRY_STORE.write_text(json.dumps(data, indent=2, sort_keys=True))


def get_builtin_plugins():
    return [dict(p) for p in TELEMETRY_PLUGINS]


def get_plugins(include_disabled=True):
    store = _load_store()
    disabled = {str(x).casefold() for x in store.get('disabled_plugins', [])}
    merged = {p['name'].casefold(): dict(p) for p in get_builtin_plugins()}
    for raw in store.get('custom_plugins', []):
        try:
            cp = normalize_plugin(raw, source='custom')
            if cp.get('name'):
                merged[cp['name'].casefold()] = cp
        except Exception:
            continue
    out = []
    for key, plugin in merged.items():
        plugin['enabled'] = bool(plugin.get('enabled', True)) and key not in disabled
        if include_disabled or plugin['enabled']:
            out.append(plugin)
    return sorted(out, key=lambda x: (str(x.get('category','')).lower(), str(x.get('name','')).lower()))


def get_plugin(name):
    key = str(name or '').casefold()
    for p in get_plugins(include_disabled=True):
        if p.get('name','').casefold() == key:
            return p
    return None



# Environment profiles group telemetry plugins into common enterprise shapes.
# The selected profile is advisory: it explains which categories are most
# relevant for the active job and helps the UI prioritize recommendations.
ENVIRONMENT_PROFILES = {
    'Windows Enterprise': {
        'description': 'Windows workstation/server estate with Active Directory, endpoint security, email, SIEM, and perimeter controls.',
        'categories': ['Windows', 'Windows Server', 'EDR/XDR', 'SIEM', 'Identity', 'Email', 'Firewall', 'VPN', 'SaaS'],
        'signals': ['windows', 'sysmon', 'defender', 'active directory', 'iis', 'powershell', 'winrm', 'wmi', 'rdp', 'exchange', 'microsoft 365', 'entra', 'sentinel'],
        'recommended_plugins': ['Windows Security', 'Sysmon', 'Defender for Endpoint', 'Active Directory Domain Services', 'Windows PowerShell Operational', 'Windows Firewall', 'Microsoft Sentinel', 'Exchange Online', 'Entra ID'],
    },
    'Linux Server': {
        'description': 'Linux server environment with audit/authentication logs, service managers, web services, containers, and SIEM forwarding.',
        'categories': ['Linux', 'Network', 'SIEM', 'Container', 'Database', 'DevOps'],
        'signals': ['linux', 'auditd', 'auth.log', 'secure', 'sshd', 'sudo', 'cron', 'systemd', 'journald', 'apache', 'nginx', 'docker', 'kubernetes', 'falco'],
        'recommended_plugins': ['auditd', 'sshd', 'sudo', 'systemd', 'journald', 'Apache', 'Nginx', 'Docker', 'Kubernetes Audit', 'Falco', 'osquery'],
    },
    'macOS Fleet': {
        'description': 'macOS endpoint fleet with unified logging, management, application control, and endpoint security telemetry.',
        'categories': ['macOS', 'EDR/XDR', 'SIEM', 'SaaS'],
        'signals': ['macos', 'os x', 'apple unified logging', 'openbsm', 'jamf', 'santa', 'gatekeeper', 'xprotect', 'filevault', 'tcc'],
        'recommended_plugins': ['Apple Unified Logging', 'OpenBSM', 'Endpoint Security', 'Gatekeeper', 'XProtect', 'TCC', 'Jamf', 'Santa', 'FileVault'],
    },
    'Network Monitoring': {
        'description': 'Packet/network-centric monitoring with IDS, flow records, DNS/DHCP, VPN, firewall, and network device telemetry.',
        'categories': ['Network', 'Firewall', 'VPN', 'DNS/DHCP', 'SIEM'],
        'signals': ['zeek', 'suricata', 'packetbeat', 'netflow', 'ipfix', 'dns', 'dhcp', 'vpn', 'firewall', 'cisco asa', 'palo alto', 'fortinet', 'corelight', 'arkime'],
        'recommended_plugins': ['Zeek', 'Suricata', 'Packetbeat', 'NetFlow', 'IPFIX', 'Cisco ASA', 'Palo Alto PAN-OS', 'Fortinet FortiGate', 'Corelight', 'Arkime'],
    },
    'Cloud Hybrid': {
        'description': 'Hybrid enterprise with cloud audit logs, identity control planes, SaaS audit data, containers, and SIEM/XDR integrations.',
        'categories': ['Cloud', 'Identity', 'SaaS', 'SIEM', 'Container', 'DevOps', 'EDR/XDR'],
        'signals': ['aws', 'cloudtrail', 'guardduty', 'azure', 'entra', 'gcp', 'google cloud', 'kubernetes', 'm365', 'office 365', 'okta', 'sentinel', 'splunk'],
        'recommended_plugins': ['AWS CloudTrail', 'AWS GuardDuty', 'Azure Activity Logs', 'Entra ID', 'Google Cloud Audit Logs', 'Microsoft Sentinel', 'Okta', 'Kubernetes Audit'],
    },
    'Identity-Centric': {
        'description': 'Identity-heavy monitoring focused on authentication, MFA, federation, directory services, and privileged access.',
        'categories': ['Identity', 'Windows Server', 'SaaS', 'VPN', 'SIEM'],
        'signals': ['active directory', 'entra', 'azure ad', 'okta', 'duo', 'ping', 'radius', 'tacacs', 'ldap', 'mfa', 'kerberos', 'ntlm'],
        'recommended_plugins': ['Active Directory Domain Services', 'Entra ID', 'Okta', 'Duo', 'Ping Identity', 'RADIUS', 'TACACS+', 'OpenLDAP', 'FreeIPA'],
    },
    'EDR-heavy': {
        'description': 'Endpoint security program centered on EDR/XDR products across Windows, Linux, and macOS with SIEM integration.',
        'categories': ['EDR/XDR', 'Windows', 'Linux', 'macOS', 'SIEM'],
        'signals': ['crowdstrike', 'sentinelone', 'carbon black', 'defender for endpoint', 'cortex xdr', 'trellix', 'cybereason', 'trend micro', 'red canary', 'wazuh', 'osquery'],
        'recommended_plugins': ['CrowdStrike Falcon', 'SentinelOne', 'Carbon Black', 'Defender for Endpoint', 'Cortex XDR', 'Trellix', 'Cybereason', 'Wazuh', 'osquery'],
    },
    'Container Platform': {
        'description': 'Container and Kubernetes environment with runtime, orchestrator, admission, audit, and cloud/container security telemetry.',
        'categories': ['Container', 'Cloud', 'DevOps', 'Linux', 'SIEM'],
        'signals': ['kubernetes', 'docker', 'containerd', 'podman', 'openshift', 'rancher', 'aks', 'eks', 'gke', 'falco', 'container'],
        'recommended_plugins': ['Kubernetes Audit', 'Docker', 'containerd', 'Podman', 'OpenShift', 'Rancher', 'AKS', 'EKS', 'GKE', 'Falco'],
    },
    'OT/ICS': {
        'description': 'Operational technology / industrial control monitoring with industrial protocols, engineering workstations, and perimeter controls.',
        'categories': ['OT/ICS', 'Network', 'Firewall', 'SIEM'],
        'signals': ['modbus', 'dnp3', 'opc', 'bacnet', 'siemens', 'rockwell', 'schneider', 'plc', 'ics', 'scada'],
        'recommended_plugins': ['Modbus', 'DNP3', 'OPC-UA', 'BACnet', 'Siemens', 'Rockwell', 'Schneider', 'Zeek', 'Suricata'],
    },
    'SaaS Collaboration': {
        'description': 'SaaS and collaboration-focused monitoring for email, chat, file sharing, meetings, and cloud application audit data.',
        'categories': ['SaaS', 'Email', 'Identity', 'SIEM'],
        'signals': ['microsoft 365', 'office 365', 'google workspace', 'slack', 'teams', 'zoom', 'exchange online', 'proofpoint', 'mimecast'],
        'recommended_plugins': ['Microsoft 365', 'Google Workspace', 'Slack', 'Teams', 'Zoom', 'Exchange Online', 'Proofpoint', 'Mimecast'],
    },
    'Database Monitoring': {
        'description': 'Database audit and activity monitoring for SQL, NoSQL, caching layers, authentication, object access, and privilege changes.',
        'categories': ['Database', 'Linux', 'Windows Server', 'SIEM'],
        'signals': ['sql server', 'oracle', 'postgresql', 'mysql', 'mariadb', 'mongodb', 'redis', 'database'],
        'recommended_plugins': ['Microsoft SQL Server', 'Oracle Database', 'PostgreSQL', 'MySQL', 'MariaDB', 'MongoDB', 'Redis'],
    },
    'DevOps Platform': {
        'description': 'Source code, CI/CD, IaC, secret access, and build/deployment telemetry.',
        'categories': ['DevOps', 'Cloud', 'SaaS', 'Container', 'SIEM'],
        'signals': ['github', 'gitlab', 'jenkins', 'azure devops', 'terraform', 'ansible', 'pipeline', 'repository', 'ci/cd'],
        'recommended_plugins': ['GitHub Enterprise', 'GitLab', 'Jenkins', 'Azure DevOps', 'Terraform', 'Ansible'],
    },
}


def environment_profiles():
    """Return profile definitions with matched plugin counts populated."""
    plugins = get_plugins(include_disabled=True)
    by_name = {p.get('name'): p for p in plugins}
    out = {}
    for name, prof in ENVIRONMENT_PROFILES.items():
        recs = []
        for pname in prof.get('recommended_plugins', []):
            p = by_name.get(pname)
            recs.append({'name': pname, 'available': bool(p), 'enabled': bool(p and p.get('enabled', True)), 'category': (p or {}).get('category','')})
        out[name] = dict(prof, recommended_plugins=recs)
    return out


def _result_search_text(result):
    """Build a conservative text index from the active job's observed telemetry."""
    parts = []
    if not isinstance(result, dict):
        return ''
    for key in ('log_sources', 'detected_log_sources', 'data_sources'):
        for item in result.get(key, []) or []:
            parts.append(json.dumps(item, default=str) if isinstance(item, (dict, list)) else str(item))
    for key in ('normalized_events', 'events'):
        for item in (result.get(key, []) or [])[:5000]:
            parts.append(json.dumps(item, default=str) if isinstance(item, (dict, list)) else str(item))
    for key in ('assets', 'communications', 'flows', 'processed_files'):
        for item in (result.get(key, []) or [])[:2000]:
            parts.append(json.dumps(item, default=str) if isinstance(item, (dict, list)) else str(item))
    return '\n'.join(parts).casefold()


def observed_plugin_matches(result):
    """Return plugins whose aliases appear in observed job telemetry."""
    text = _result_search_text(result)
    matches = []
    if not text.strip():
        return matches
    for p in get_plugins(include_disabled=True):
        hit_aliases = []
        for alias in p.get('aliases') or []:
            a = str(alias).casefold().strip()
            if a and a in text:
                hit_aliases.append(alias)
        if hit_aliases:
            row = dict(p)
            row['matched_aliases'] = hit_aliases[:12]
            matches.append(row)
    return matches


def auto_select_environment_profile(result):
    """Score profiles from observed telemetry and return selected + ranked list."""
    text = _result_search_text(result)
    matches = observed_plugin_matches(result)
    observed_categories = {p.get('category') for p in matches if p.get('category')}
    observed_names = {p.get('name') for p in matches if p.get('name')}
    ranked = []
    for name, prof in ENVIRONMENT_PROFILES.items():
        cats = set(prof.get('categories') or [])
        rec_names = set(prof.get('recommended_plugins') or [])
        cat_hits = sorted(cats & observed_categories)
        plugin_hits = sorted(rec_names & observed_names)
        signal_hits = []
        for sig in prof.get('signals') or []:
            sig_l = str(sig).casefold().strip()
            if sig_l and sig_l in text:
                signal_hits.append(sig)
        score = (len(plugin_hits) * 5) + (len(cat_hits) * 3) + min(len(signal_hits), 20)
        ranked.append({
            'name': name,
            'description': prof.get('description',''),
            'categories': list(prof.get('categories') or []),
            'recommended_plugins': list(prof.get('recommended_plugins') or []),
            'score': score,
            'matched_categories': cat_hits,
            'matched_plugins': plugin_hits,
            'matched_signals': signal_hits[:20],
        })
    ranked.sort(key=lambda r: (-r['score'], r['name']))
    selected = ranked[0]['name'] if ranked and ranked[0]['score'] > 0 else 'No profile selected yet'
    return {
        'selected': selected,
        'ranked': ranked,
        'observed_plugins': matches,
        'observed_categories': sorted(observed_categories),
    }


def categories(include_all=False):
    cats = sorted({p.get('category','Custom') for p in get_plugins(include_disabled=True)})
    return (['All categories'] if include_all else []) + cats


def plugin_summary():
    by_cat = {}
    active = 0
    for p in get_plugins(include_disabled=True):
        by_cat.setdefault(p['category'], 0)
        by_cat[p['category']] += 1
        if p.get('enabled', True):
            active += 1
    return {'plugin_count': active, 'total_plugins': len(get_plugins(include_disabled=True)), 'categories': by_cat}


def upsert_custom_plugin(plugin):
    cp = normalize_plugin(plugin, source='custom')
    if not cp.get('name'):
        raise ValueError('Plugin name is required')
    store = _load_store()
    custom = [p for p in store.get('custom_plugins', []) if str(p.get('name','')).casefold() != cp['name'].casefold()]
    custom.append(cp)
    store['custom_plugins'] = custom
    disabled = {str(x).casefold() for x in store.get('disabled_plugins', [])}
    if cp.get('enabled', True):
        disabled.discard(cp['name'].casefold())
    else:
        disabled.add(cp['name'].casefold())
    store['disabled_plugins'] = sorted(disabled)
    _save_store(store)
    return cp


def delete_plugin(name):
    key = str(name or '').casefold()
    store = _load_store()
    before = len(store.get('custom_plugins', []))
    store['custom_plugins'] = [p for p in store.get('custom_plugins', []) if str(p.get('name','')).casefold() != key]
    # Built-ins are disabled rather than physically deleted so upgrades can restore them.
    if before == len(store.get('custom_plugins', [])):
        disabled = {str(x).casefold() for x in store.get('disabled_plugins', [])}
        disabled.add(key)
        store['disabled_plugins'] = sorted(disabled)
    _save_store(store)


def set_plugin_enabled(name, enabled=True):
    key = str(name or '').casefold()
    store = _load_store()
    disabled = {str(x).casefold() for x in store.get('disabled_plugins', [])}
    if enabled:
        disabled.discard(key)
    else:
        disabled.add(key)
    store['disabled_plugins'] = sorted(disabled)
    _save_store(store)


def export_plugins_json():
    """Export only user-managed telemetry data.

    Built-in plugins are intentionally excluded from backups and plugin exports.
    The receiving application already ships built-ins for its version; importing
    this payload overlays only custom/imported plugins and enable/disable state.
    """
    store = _load_store()
    return {
        'version': 2,
        'export_scope': 'custom_only',
        'custom_plugins': list(store.get('custom_plugins', []) or []),
        'disabled_plugins': list(store.get('disabled_plugins', []) or []),
    }


def import_plugins_json(data):
    if isinstance(data, dict):
        items = data.get('custom_plugins') or data.get('plugins') or []
        disabled_incoming = data.get('disabled_plugins') or []
    elif isinstance(data, list):
        items = data
        disabled_incoming = []
    else:
        items = []
        disabled_incoming = []
    count = 0
    for item in items:
        if isinstance(item, dict) and item.get('name'):
            # Imported plugins are always user-managed overlays.
            item = dict(item)
            item['source'] = item.get('source') if item.get('source') not in ('built-in', 'builtin') else 'imported'
            upsert_custom_plugin(item)
            count += 1
    if disabled_incoming:
        store = _load_store()
        disabled = {str(x).casefold() for x in store.get('disabled_plugins', [])}
        disabled.update(str(x).casefold() for x in disabled_incoming if str(x).strip())
        store['disabled_plugins'] = sorted(disabled)
        _save_store(store)
    return count


def validate_plugins():
    errors = []
    warnings = []
    aliases = {}
    names = set()
    valid_conf = {'low','medium','high'}
    for p in get_plugins(include_disabled=True):
        name = p.get('name') or ''
        if not name:
            errors.append('A plugin is missing a name.')
            continue
        key = name.casefold()
        if key in names:
            errors.append(f'Duplicate plugin name: {name}')
        names.add(key)
        if not p.get('category'):
            warnings.append(f'{name}: missing category.')
        if not p.get('aliases'):
            warnings.append(f'{name}: has no aliases, so auto-detection may be weak.')
        if not p.get('observed_components'):
            warnings.append(f'{name}: has no observed components.')
        if not p.get('potential_components'):
            warnings.append(f'{name}: has no potential components.')
        if str(p.get('confidence','high')).lower() not in valid_conf:
            warnings.append(f'{name}: confidence should be low, medium, or high.')
        for alias in p.get('aliases') or []:
            ak = str(alias).casefold()
            if ak in aliases and aliases[ak] != name:
                warnings.append(f'Alias "{alias}" is used by both {aliases[ak]} and {name}.')
            aliases[ak] = name
    return {'ok': not errors, 'errors': errors, 'warnings': warnings, 'plugin_count': len(get_plugins(True))}


def test_sample(sample):
    text = str(sample or '').casefold()
    matches = []
    if not text.strip():
        return []
    for p in get_plugins(include_disabled=False):
        hit_aliases = []
        for alias in p.get('aliases') or []:
            a = str(alias).casefold().strip()
            if a and a in text:
                hit_aliases.append(alias)
        if hit_aliases:
            matches.append({'plugin': p, 'matched_aliases': hit_aliases[:10]})
    return matches


def apply_registry_to_attack_globals(globs):
    """Merge plugins into app.attack.versioned module globals.

    The registry intentionally updates the existing maps so old code paths,
    strict STIX coverage, diagnostics, recommendations, and potential coverage
    all consume the same plugin definitions.
    """
    aliases = globs.setdefault('LOG_SOURCE_ALIASES', {})
    categories = globs.setdefault('SOURCE_CATEGORY', {})
    components = globs.setdefault('SOURCE_COMPONENTS', {})
    rich = globs.setdefault('RICH_TELEMETRY_CAPABILITY_REGISTRY', {})
    for plugin in get_plugins(include_disabled=False):
        name = plugin['name']
        categories[name] = plugin['category']
        for alias in plugin['aliases']:
            aliases[alias] = name
        current = list(components.get(name) or [])
        for comp in plugin['observed_components']:
            if comp not in current:
                current.append(comp)
        components[name] = current
        potential = list(rich.get(name) or current)
        for comp in plugin['potential_components']:
            if comp not in potential:
                potential.append(comp)
        rich[name] = potential
    return plugin_summary()
