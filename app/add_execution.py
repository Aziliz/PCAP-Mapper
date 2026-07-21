from pathlib import Path
import ast, textwrap, json, zipfile, os
root=Path('/mnt/data/execution_work')
engine=root/'app/rules/engine.py'
versioned=root/'app/attack/versioned.py'

execution_rules = [
    {'name':'Execution: BITS Jobs','description':'Windows telemetry or outbound web/TLS traffic can validate BITS job execution coverage.','event_type':'flow','protocol_any':['HTTP','HTTPS','HTTP Alt','HTTPS Alt','TLS','Elastic Beats','WinRM','WinRM TLS'],'severity':'medium','confidence':'medium','attack':['T1197'],'rule_type':'detection','requires':['Windows Event Log']},
    {'name':'Execution: Cloud Administration Command and APIs','description':'Cloud management, API, serverless, and external web/TLS traffic can validate cloud command execution coverage.','event_type':'flow','protocol_any':['HTTP','HTTPS','HTTP Alt','HTTPS Alt','TLS','DNS'],'destination_is_external':True,'severity':'medium','confidence':'medium','attack':['T1651','T1059.009','T1648'],'rule_type':'detection','requires':['Network Traffic']},
    {'name':'Execution: Windows Command and Script Interpreters','description':'Windows telemetry, PowerShell, WinRM, or remote management flows can validate Windows command/script execution coverage.','event_type':'flow','protocol_any':['WinRM','WinRM TLS','Elastic Beats','SMB','RDP'],'severity':'high','confidence':'high','attack':['T1059','T1059.001','T1059.003','T1059.005','T1059.010'],'rule_type':'detection','requires':['Windows Event Log']},
    {'name':'Execution: Unix and Cross-Platform Script Interpreters','description':'SSH, syslog, audit, or endpoint forwarding can validate Unix shell and interpreter execution coverage.','event_type':'flow','protocol_any':['SSH','Syslog','Syslog TLS','Elastic Beats'],'severity':'high','confidence':'high','attack':['T1059.004','T1059.006','T1059.007','T1059.011'],'rule_type':'detection','requires':['Network Traffic']},
    {'name':'Execution: Network, Hypervisor, and Container CLI/API','description':'Management-plane traffic for network devices, hypervisors, Kubernetes, Docker, or container APIs can validate CLI/API execution coverage.','event_type':'flow','protocol_any':['SSH','HTTPS','HTTP','HTTP Alt','HTTPS Alt','TLS','SNMP','Elastic Beats'],'severity':'high','confidence':'medium','attack':['T1059.008','T1059.012','T1059.013','T1609','T1610','T1675'],'rule_type':'network','requires':['Network Traffic']},
    {'name':'Execution: Client and User-Driven Execution','description':'External web, mail, download, and endpoint telemetry can validate client exploitation and user execution coverage.','event_type':'flow','protocol_any':['HTTP','HTTPS','HTTP Alt','HTTPS Alt','TLS','SMTP','SMTPS','IMAP','IMAPS','POP3','POP3S','Elastic Beats'],'severity':'high','confidence':'medium','attack':['T1203','T1204','T1204.001','T1204.002','T1204.003','T1204.004','T1204.005'],'rule_type':'detection'},
    {'name':'Execution: Hijack Execution Flow - Windows','description':'Windows endpoint telemetry can validate DLL, installer, PATH, service, registry, .NET, and GUI callback hijack coverage.','event_type':'flow','protocol_any':['Elastic Beats','WinRM','WinRM TLS','SMB'],'severity':'high','confidence':'medium','attack':['T1574','T1574.001','T1574.005','T1574.007','T1574.008','T1574.009','T1574.010','T1574.011','T1574.012','T1574.013','T1574.014'],'rule_type':'detection','requires':['Windows Event Log']},
    {'name':'Execution: Hijack Execution Flow - Linux/macOS','description':'Linux and macOS telemetry can validate dylib and dynamic-linker hijacking coverage.','event_type':'flow','protocol_any':['Syslog','Syslog TLS','Elastic Beats','SSH'],'severity':'high','confidence':'medium','attack':['T1574.004','T1574.006'],'rule_type':'detection','requires':['Network Traffic']},
    {'name':'Execution: Input Injection','description':'Endpoint or remote-control telemetry can validate input-injection execution coverage.','event_type':'flow','protocol_any':['VNC','RDP','SSH','Elastic Beats','Syslog','Syslog TLS'],'severity':'medium','confidence':'medium','attack':['T1674'],'rule_type':'detection'},
    {'name':'Execution: Inter-Process Communication','description':'Windows, macOS, and endpoint telemetry can validate COM, DDE, and XPC execution coverage.','event_type':'flow','protocol_any':['Elastic Beats','WinRM','WinRM TLS','Syslog','Syslog TLS'],'severity':'high','confidence':'medium','attack':['T1559','T1559.001','T1559.002','T1559.003'],'rule_type':'detection'},
    {'name':'Execution: Native API','description':'Endpoint telemetry can validate execution through native OS APIs.','event_type':'flow','protocol_any':['Elastic Beats','WinRM','WinRM TLS','Syslog','Syslog TLS'],'severity':'medium','confidence':'medium','attack':['T1106'],'rule_type':'detection'},
    {'name':'Execution: Poisoned Pipeline Execution','description':'CI/CD, repository, cloud, and web/API flows can validate poisoned pipeline execution coverage.','event_type':'flow','protocol_any':['HTTP','HTTPS','HTTP Alt','HTTPS Alt','TLS','DNS','Elastic Beats'],'destination_is_external':True,'severity':'high','confidence':'medium','attack':['T1677'],'rule_type':'detection'},
    {'name':'Execution: Scheduled Task and Job','description':'Windows, Linux, macOS, systemd, cron, and container orchestration telemetry can validate scheduled execution coverage.','event_type':'flow','protocol_any':['WinRM','WinRM TLS','Elastic Beats','Syslog','Syslog TLS','SSH','HTTPS','HTTP'],'severity':'high','confidence':'high','attack':['T1053','T1053.002','T1053.003','T1053.005','T1053.006','T1053.007'],'rule_type':'detection'},
    {'name':'Execution: Shared Modules','description':'Endpoint telemetry can validate execution through shared module loading.','event_type':'flow','protocol_any':['Elastic Beats','Syslog','Syslog TLS','WinRM','WinRM TLS'],'severity':'medium','confidence':'medium','attack':['T1129'],'rule_type':'detection'},
    {'name':'Execution: Software Deployment Tools','description':'Enterprise software deployment, management, and endpoint telemetry can validate deployment-tool execution coverage.','event_type':'flow','protocol_any':['HTTPS','HTTP','TLS','WinRM','WinRM TLS','SMB','Elastic Beats'],'severity':'high','confidence':'medium','attack':['T1072'],'rule_type':'detection'},
    {'name':'Execution: System Services','description':'Service control and init-system telemetry can validate launchctl, Windows service, and systemctl execution coverage.','event_type':'flow','protocol_any':['WinRM','WinRM TLS','SMB','SSH','Syslog','Syslog TLS','Elastic Beats'],'severity':'high','confidence':'high','attack':['T1569','T1569.001','T1569.002','T1569.003'],'rule_type':'detection'},
    {'name':'Execution: Trusted Developer Utilities Proxy Execution','description':'Developer/build tool and endpoint telemetry can validate MSBuild, ClickOnce, and JamPlus proxy execution coverage.','event_type':'flow','protocol_any':['HTTP','HTTPS','HTTP Alt','HTTPS Alt','TLS','Elastic Beats','SMB'],'severity':'medium','confidence':'medium','attack':['T1127','T1127.001','T1127.002','T1127.003'],'rule_type':'detection'},
    {'name':'Execution: Windows Management Instrumentation','description':'WMI/DCOM and Windows telemetry can validate WMI execution coverage.','event_type':'flow','protocol_any':['WinRM','WinRM TLS','SMB','MSRPC','Elastic Beats'],'severity':'high','confidence':'high','attack':['T1047'],'rule_type':'detection','requires':['Windows Event Log']},
]

# Insert rules after Initial Access rules and before Discovery.
text=engine.read_text()
marker="\n    # Discovery\n"
insert="\n    # Execution - ATT&CK v18 TA0002 coverage rules. These rules are\n    # telemetry/network oriented so PCAP-derived flows can validate Execution\n    # coverage while keeping observed behavior separate from theoretical coverage.\n"
for r in execution_rules:
    insert += "    " + repr(r) + ",\n"
if "# Execution - ATT&CK v18 TA0002 coverage rules" not in text:
    text=text.replace(marker, insert+marker, 1)
engine.write_text(text)

execution_techniques = {
'T1197':'BITS Jobs','T1651':'Cloud Administration Command','T1059.002':'Command and Scripting Interpreter: AppleScript','T1059.003':'Command and Scripting Interpreter: Windows Command Shell','T1059.005':'Command and Scripting Interpreter: Visual Basic','T1059.006':'Command and Scripting Interpreter: Python','T1059.007':'Command and Scripting Interpreter: JavaScript','T1059.008':'Command and Scripting Interpreter: Network Device CLI','T1059.009':'Command and Scripting Interpreter: Cloud API','T1059.010':'Command and Scripting Interpreter: AutoHotKey & AutoIT','T1059.011':'Command and Scripting Interpreter: Lua','T1059.012':'Command and Scripting Interpreter: Hypervisor CLI','T1059.013':'Command and Scripting Interpreter: Container CLI/API','T1609':'Container Administration Command','T1610':'Deploy Container','T1675':'ESXi Administration Command','T1203':'Exploitation for Client Execution','T1574':'Hijack Execution Flow','T1574.001':'Hijack Execution Flow: DLL','T1574.004':'Hijack Execution Flow: Dylib Hijacking','T1574.005':'Hijack Execution Flow: Executable Installer File Permissions Weakness','T1574.006':'Hijack Execution Flow: Dynamic Linker Hijacking','T1574.007':'Hijack Execution Flow: Path Interception by PATH Environment Variable','T1574.008':'Hijack Execution Flow: Path Interception by Search Order Hijacking','T1574.009':'Hijack Execution Flow: Path Interception by Unquoted Path','T1574.010':'Hijack Execution Flow: Services File Permissions Weakness','T1574.011':'Hijack Execution Flow: Services Registry Permissions Weakness','T1574.012':'Hijack Execution Flow: COR_PROFILER','T1574.013':'Hijack Execution Flow: KernelCallbackTable','T1574.014':'Hijack Execution Flow: AppDomainManager','T1674':'Input Injection','T1559':'Inter-Process Communication','T1559.001':'Inter-Process Communication: Component Object Model','T1559.002':'Inter-Process Communication: Dynamic Data Exchange','T1559.003':'Inter-Process Communication: XPC Services','T1106':'Native API','T1677':'Poisoned Pipeline Execution','T1053':'Scheduled Task/Job','T1053.002':'Scheduled Task/Job: At','T1053.006':'Scheduled Task/Job: Systemd Timers','T1053.007':'Scheduled Task/Job: Container Orchestration Job','T1648':'Serverless Execution','T1129':'Shared Modules','T1072':'Software Deployment Tools','T1569':'System Services','T1569.001':'System Services: Launchctl','T1569.002':'System Services: Service Execution','T1569.003':'System Services: Systemctl','T1127':'Trusted Developer Utilities Proxy Execution','T1127.001':'Trusted Developer Utilities Proxy Execution: MSBuild','T1127.002':'Trusted Developer Utilities Proxy Execution: ClickOnce','T1127.003':'Trusted Developer Utilities Proxy Execution: JamPlus','T1204':'User Execution','T1204.001':'User Execution: Malicious Link','T1204.002':'User Execution: Malicious File','T1204.003':'User Execution: Malicious Image','T1204.004':'User Execution: Malicious Copy and Paste','T1204.005':'User Execution: Malicious Library','T1047':'Windows Management Instrumentation'}
# T1059, .001, .004, .003? existing partial; T1053.003/005 existing. Add missing only.
text=versioned.read_text()
anchor=" 'T1069': {'name':'Permission Groups Discovery','tactic':'discovery'},"
block=""
for tid,name in execution_techniques.items():
    if f"'{tid}'" not in text:
        block += f" '{tid}': {{'name':'{name}','tactic':'execution'}},\n"
if block and "# Execution - ATT&CK v18 TA0002 additional technique IDs." not in text:
    text=text.replace(anchor, " # Execution - ATT&CK v18 TA0002 additional technique IDs.\n"+block+anchor, 1)
versioned.write_text(text)

# Verify through imports
import sys
sys.path.insert(0, str(root))
from app.rules.engine import BUILTIN_RULES
from app.attack.versioned import VALID_TECHNIQUES
ids=set()
for r in BUILTIN_RULES:
    ids.update(r.get('attack',[]) or [])
exec_ids=['T1197','T1651','T1059','T1059.001','T1059.002','T1059.003','T1059.004','T1059.005','T1059.006','T1059.007','T1059.008','T1059.009','T1059.010','T1059.011','T1059.012','T1059.013','T1609','T1610','T1675','T1203','T1574','T1574.001','T1574.004','T1574.005','T1574.006','T1574.007','T1574.008','T1574.009','T1574.010','T1574.011','T1574.012','T1574.013','T1574.014','T1674','T1559','T1559.001','T1559.002','T1559.003','T1106','T1677','T1053','T1053.002','T1053.003','T1053.005','T1053.006','T1053.007','T1648','T1129','T1072','T1569','T1569.001','T1569.002','T1569.003','T1127','T1127.001','T1127.002','T1127.003','T1204','T1204.001','T1204.002','T1204.003','T1204.004','T1204.005','T1047']
missing=[i for i in exec_ids if i not in ids]
invalid=[i for i in exec_ids if i not in VALID_TECHNIQUES]
coverage=f"""# Execution Rules Coverage\n\nExecution coverage verified against MITRE ATT&CK Enterprise tactic TA0002.\n\n- Techniques and sub-techniques covered: {len(exec_ids)-len(missing)}/{len(exec_ids)}\n- Rules added: {len(execution_rules)}\n- Missing after update: {len(missing)}\n- Unsupported IDs after update: {len(invalid)}\n\nAdded rules:\n"""
for r in execution_rules:
    coverage += f"- {r['name']}: {', '.join(r['attack'])}\n"
(root/'EXECUTION_COVERAGE.md').write_text(coverage)
print(coverage)
