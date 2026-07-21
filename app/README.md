# PCAP Mapper

Python/Flask/Scapy-only PCAP analysis app.

This build adds rule validation:
- Detection and Network rules are syntax-checked before saving.
- Rules can be validated against the current analysis from the Detection Rules or Network Rules pages.
- Validation records matching flows/evidence and mapped ATT&CK techniques.
- The MITRE heat map marks a technique as **Validated** only when telemetry coverage exists, the behavior was observed, and a mapped rule matched PCAP-derived evidence.
- On-demand reports include `rule_validation_results.json`.

Run:

```bash
docker build -t pcap-mapper .
mkdir -p uploads results
docker run --rm --name pcap-mapper -p 8000:8000 \
  -v "$PWD/uploads:/app/uploads:Z" \
  -v "$PWD/results:/app/results:Z" \
  --memory=8g pcap-mapper
```

Update: Expanded default ATT&CK rule library
- Added additional Detection and Network rules for discovery, brute force, Kerberoasting, lateral movement, C2, DNS tunneling, exfiltration, collection, persistence, defense evasion, macOS activity, and telemetry-backed validation.
- Added aggregate rule support for horizontal scans, vertical scans, ICMP sweeps, service-volume rules, and protocol-combination rules.
- Rules continue to use only Python standard library, Flask, and Scapy.

## Rule validation enhancements

This build expands the rule subsystem while keeping dependencies limited to Python, Flask, Scapy, and the standard library.

Added:
- Rule test preview before saving
- Per-match explanations showing why a flow matched
- Confidence scoring and severity override
- False-positive tuning with source, destination, and protocol exclusions
- Rule version field
- Required telemetry dependencies
- Per-rule/technique coverage scores
- Rule conflict detection
- Reusable rule templates
- Validation history
- Rule export/import as JSON rule packs

## Rule conflict cleanup

This build reduces noisy default rule conflicts by:
- disabling broad informational coverage-only rules by default,
- keeping protocol-specific ATT&CK validation rules separate,
- suppressing non-actionable same-technique overlaps when evidence conditions differ,
- reporting only actionable duplicate/shadowing conflicts.


## Resource Development rule coverage

This build adds/validates default Detection and Network Rules for all ATT&CK Enterprise v18 Resource Development techniques and sub-techniques under TA0042. The rules are intentionally conservative and telemetry/network-flow oriented because Resource Development is often external to the enterprise and may only be visible through DNS, proxy, web, mail, TLS, cloud, and management traffic.

## Official MITRE ATT&CK Enterprise v18 STIX dataset

This build switches the ATT&CK technique registry from hard-coded counts to the official MITRE ATT&CK Enterprise v18 STIX bundle.

The loader uses only the Python standard library. At startup it checks, in order:

1. `ATTACK_STIX_PATH` if set.
2. `app/attack/data/enterprise-attack-18.0.json` if present.
3. A best-effort download from the official MITRE ATT&CK STIX data GitHub repository if `ATTACK_STIX_AUTO_DOWNLOAD=1`.
4. Legacy fallback registry only when strict mode is not enabled.

Recommended production settings:

```bash
mkdir -p attack-data
curl -L \
  -o attack-data/enterprise-attack-18.0.json \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-18.0.json

docker run --rm --name pcap-mapper \
  -p 8000:8000 \
  -e ATTACK_STIX_PATH=/app/attack-data/enterprise-attack-18.0.json \
  -e ATTACK_STIX_STRICT=1 \
  -v "$PWD/attack-data:/app/attack-data:Z" \
  -v "$PWD/uploads:/app/uploads:Z" \
  -v "$PWD/results:/app/results:Z" \
  pcap-mapper
```

Strict mode prevents incomplete local fallback data from being used accidentally.

On-demand report generation now also writes:

- `attack_v18_rule_coverage_report.json`

That report is generated from the loaded STIX dataset and the current rule library.

## Complete ATT&CK v18 sub-technique coverage hard requirement

This build now treats the official MITRE ATT&CK Enterprise v18 STIX bundle as required for complete technique and sub-technique rule coverage.

Runtime defaults:

```bash
ATTACK_STIX_STRICT=1
ATTACK_STIX_AUTO_DOWNLOAD=1
```

If the container has internet access, it will try to download the official v18 Enterprise STIX release asset from the MITRE ATT&CK STIX data GitHub release. In offline or restricted environments, download the release asset separately and mount it into the container:

```bash
mkdir -p attack-data
curl -L \
  -o attack-data/enterprise-attack-18.0.json \
  https://github.com/mitre-attack/attack-stix-data/releases/download/v18.0/enterprise-attack.json

docker run --rm --name pcap-mapper \
  -p 8000:8000 \
  -e ATTACK_STIX_PATH=/app/attack-data/enterprise-attack-18.0.json \
  -e ATTACK_STIX_STRICT=1 \
  -v "$PWD/attack-data:/app/attack-data:Z" \
  -v "$PWD/uploads:/app/uploads:Z" \
  -v "$PWD/results:/app/results:Z" \
  pcap-mapper
```

Verification command:

```bash
python verify_attack_v18_subtechnique_coverage.py
```

The verification script writes:

- `results/OFFICIAL_ATTACK_V18_COMPLETE_RULE_COVERAGE.md`
- `results/official_attack_v18_complete_rule_coverage.json`

The script fails if:

- the official STIX bundle is not loaded,
- any official Enterprise v18 technique lacks a validating rule,
- any official Enterprise v18 sub-technique lacks a validating rule,
- unresolved actionable rule conflicts remain.

This preserves the existing Python/Flask/Scapy-only architecture while making complete sub-technique coverage an enforceable build/runtime check instead of an estimated count.


## v1.0 Consolidated Baseline

This build consolidates the accepted PCAP Mapper features into one baseline and restores the Dashboard **Start New Job** workflow. Previous analyses remain available from **Previous Results** until deleted.

### Start a fresh analysis

Use **Start New Job** on the Dashboard to create an empty current job without deleting previous results. Uploads made afterward are attached to that new job.

### Delete old analyses

Use **Previous Results > Delete** to remove a completed, failed, or empty previous result. Running jobs are not deleted.

## Deferred Rule Validation Performance Update

Full Detection/Network Rule validation is now deferred by default so large PCAP parsing completes faster. Analysis builds internal data first: hosts, flows, IOCs, log sources, ATT&CK evidence, and summaries. Use **Validate Rules** on Detection Rules, Network Rules, or MITRE Heat Map to run the full validation pass on demand.

To intentionally run full validation during parsing, either select the dashboard checkbox **Run full rule validation during analysis (slower)** before starting a job, or set:

```bash
-e VALIDATE_RULES_DURING_ANALYSIS=1
```



## PCAP Mapper v2 Baseline

This branch starts the v2 codebase. v1 is frozen at the previous baseline. Future ZIPs should be generated from v2 unless explicitly requested otherwise.

### v2 Phase 1: Event Normalization Engine

The application now includes a dependency-free Event Normalization Engine that parses forwarded telemetry visible in PCAP payloads and converts it into normalized event dictionaries. Supported heuristic log families include:

- Windows: Windows Event Log, Sysmon, PowerShell, Defender, Task Scheduler, IIS, RDP, SMB, WinRM, WMI.
- Linux: auditd, systemd/journald, rsyslog/syslog-ng, auth.log/secure, sshd, sudo, cron, kernel, iptables/nftables, Apache, Nginx, Docker/containerd, Kubernetes audit, SELinux/AppArmor, osquery, Falco.
- macOS: Apple Unified Logging, OpenBSM, launchd/launchctl, TCC, Gatekeeper, XProtect, Jamf, Santa, osquery, FileVault, SSH/screen sharing markers.
- Network: RFC3164/RFC5424 Syslog, Zeek, Suricata EVE, Packetbeat, NetFlow, IPFIX, sFlow, Cisco ASA/IOS/NX-OS, Palo Alto PAN-OS, Fortinet, Check Point, SonicWall, pfSense/OPNsense, F5, HAProxy, Squid/ProxySG, DNS/DHCP/VPN/Wireless logs.
- Cloud: AWS CloudTrail/GuardDuty/VPC-like logs, Azure Activity/Azure AD, GCP Audit, Workspace logs, Kubernetes audit.

Normalized events are stored with each job under `normalized_events` and summarized under `normalized_event_summary`. A minimal `/events` diagnostics page shows the parsed event inventory.

Phase 1 keeps parser logic centralized and lightweight. Later v2 phases can expand event-to-flow correlation, event-aware rules, and report evidence without reworking packet parsing again.


## v2 Phase 2: Normalized Event ATT&CK and Rule Integration

Phase 2 wires normalized events into the ATT&CK and rule-validation pipeline.
Forwarded Windows, Linux, macOS, network, and cloud logs captured inside PCAPs
can now contribute to Observed ATT&CK mappings and can validate Detection/Network
rules when their normalized event ATT&CK candidates intersect a rule mapping.

New diagnostics are shown on the MITRE Heat Map page:

- flows available
- normalized events parsed
- normalized events mapped to ATT&CK
- observed ATT&CK IDs
- validated ATT&CK IDs
- rule matches from flows vs normalized events
- top normalized event types and log sources

Validated coverage still requires clicking **Validate Rules**, but validation now
evaluates both flows and normalized events.

## v2 Phase 3 baseline

This build adds UI and reporting support for normalized events:
- searchable/filterable normalized Events page
- event detail panel with raw payload and related flow links
- event exports in JSON, CSV, Markdown, and Elastic NDJSON
- event-derived ATT&CK evidence on the MITRE Heat Map page
- combined flow/event/rule timeline
- event diagnostics in generated reports
- rule creation from normalized events
- enterprise coverage scoped to detected OS and log types

Enterprise total coverage is calculated against the detected operating systems and log types in the job. For example, Linux-only event evidence is not penalized for missing Windows-only telemetry.
