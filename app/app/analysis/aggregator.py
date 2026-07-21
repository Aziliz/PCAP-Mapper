from collections import Counter
from app.config import MAX_FLOWS, MAX_EVENTS, MAX_LOG_SOURCES, MAX_NORMALIZED_EVENTS
from app.events import normalize_event, summarize_normalized_events
from app.attack.versioned import VALID_TECHNIQUES

PRIVATE_PREFIXES = ('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.')
LOG_PROTOCOLS = {'Syslog', 'Syslog TLS', 'Elastic Beats', 'WinRM', 'NetFlow', 'IPFIX', 'sFlow', 'SNMP Trap'}

class AnalysisContext:
    def __init__(self):
        self.hosts = {}
        self.flows = {}
        self.protocols = Counter()
        self.iocs = {'ips': set(), 'domains': set(), 'urls': set()}
        self.events_seen = 0
        self.events_stored = 0
        self.findings = []
        self.log_sources = []
        self.techniques = {}
        self.normalized_events = []
        self.event_summary = {}
        self.dropped = {'flows': 0, 'events_over_cap': 0, 'log_sources': 0, 'normalized_events': 0}

    def add_event(self, ev):
        self.events_seen += 1
        if self.events_seen > MAX_EVENTS:
            self.dropped['events_over_cap'] += 1
            # Continue lightweight counters, but avoid high-cardinality growth after the cap.
            proto = ev.get('protocol') or 'Unknown'
            self.protocols[proto] += 1
            return
        self.events_stored += 1

        for side in ['src', 'dst']:
            ip = ev.get(f'{side}_ip')
            mac = ev.get(f'{side}_mac')
            if ip:
                h = self.hosts.setdefault(ip, {'ip': ip, 'macs': set(), 'bytes': 0, 'protocols': set(), 'first_seen': ev.get('ts'), 'last_seen': ev.get('ts'), 'role': 'Unknown'})
                if mac:
                    h['macs'].add(mac)
                h['bytes'] += int(ev.get('bytes') or 0)
                h['protocols'].add(ev.get('protocol',''))
                h['first_seen'] = min(h['first_seen'] or ev.get('ts'), ev.get('ts'))
                h['last_seen'] = max(h['last_seen'] or ev.get('ts'), ev.get('ts'))
                if not ip.startswith(PRIVATE_PREFIXES):
                    self.iocs['ips'].add(ip)

        proto = ev.get('protocol') or 'Unknown'
        self.protocols[proto] += 1
        key = f"{ev.get('src_ip')}|{ev.get('dst_ip')}|{proto}|{ev.get('dport')}"
        if key in self.flows or len(self.flows) < MAX_FLOWS:
            f = self.flows.setdefault(key, {'flow_id': key, 'src_ip': ev.get('src_ip'), 'dst_ip': ev.get('dst_ip'), 'protocol': proto, 'dport': ev.get('dport'), 'packets': 0, 'bytes': 0, 'first_seen': ev.get('ts'), 'last_seen': ev.get('ts')})
            f['packets'] += 1
            f['bytes'] += int(ev.get('bytes') or 0)
            f['last_seen'] = ev.get('ts')
        else:
            self.dropped['flows'] += 1

        q = (ev.get('evidence') or {}).get('query')
        if q:
            self.iocs['domains'].add(q)


        # PCAP Mapper v2 Phase 1: normalize forwarded logs and telemetry that
        # are visible inside packet payloads.  This is intentionally separate
        # from flow creation so later phases can correlate both flows and
        # normalized events without changing the packet reader again.
        normalized = normalize_event(ev)
        for nev in normalized:
            if len(self.normalized_events) < MAX_NORMALIZED_EVENTS:
                self.normalized_events.append(nev)
            else:
                self.dropped['normalized_events'] += 1
            for tid in nev.get('attack_candidates') or []:
                # Keep metadata lightweight here; the ATT&CK/STIX registry enriches
                # names/tactics later during heat-map/report rollup. Avoid importing
                # the STIX loader from the hot parser path.
                meta = VALID_TECHNIQUES.get(tid, {'name': tid, 'tactic': ''})
                self.techniques.setdefault(tid, {
                    'techniqueID': tid,
                    'name': meta.get('name', tid),
                    'tactic': meta.get('tactic', ''),
                    'score': 30,
                    'severity': 'low',
                    'confidence': 'Observed',
                    'evidence': [],
                    'hosts': set(),
                    'source': 'normalized_event',
                })
                evidence = {
                    'type': 'normalized_event',
                    'event_type': nev.get('event_type'),
                    'log_source': nev.get('log_source'),
                    'host': nev.get('host'),
                    'summary': (nev.get('raw') or '')[:180],
                }
                if nev.get('host'):
                    self.techniques[tid].setdefault('hosts', set()).add(nev.get('host'))
                if len(self.techniques[tid].setdefault('evidence', [])) < 10:
                    self.techniques[tid]['evidence'].append(str(evidence)[:300])

        if proto in LOG_PROTOCOLS:
            if len(self.log_sources) < MAX_LOG_SOURCES:
                self.log_sources.append({'host': ev.get('src_ip'), 'collector': ev.get('dst_ip'), 'protocol': proto, 'port': ev.get('dport'), 'confidence': 'Observed', 'evidence': ev.get('summary')})
            else:
                self.dropped['log_sources'] += 1

    def finalize_hosts(self):
        for h in self.hosts.values():
            ps = h['protocols']
            if {'Kerberos','LDAP','SMB'} & ps and 'Kerberos' in ps:
                h['role'] = 'Windows/AD Host'
            if 'SMB' in ps and 'Kerberos' in ps and 'LDAP' in ps:
                h['role'] = 'Possible Domain Controller'
            if 'HTTP' in ps or 'HTTPS' in ps:
                h['role'] = 'Web Client/Server'
            if {'MySQL','PostgreSQL','MSSQL','Oracle','MongoDB','Redis'} & ps:
                h['role'] = 'Database Host'
            if {'Syslog','NetFlow','IPFIX','sFlow'} & ps:
                h['role'] = 'Network/Telemetry Device'

    def to_dict(self):
        self.finalize_hosts()
        self.event_summary = summarize_normalized_events(self.normalized_events)
        return {
            'summary': {'hosts': len(self.hosts), 'flows': len(self.flows), 'events': self.events_seen, 'events_stored': self.events_stored, 'normalized_events': len(self.normalized_events), 'findings': len(self.findings), 'techniques': len(self.techniques), 'dropped': self.dropped},
            'hosts': [{**v, 'macs': sorted(v['macs']), 'protocols': sorted([p for p in v['protocols'] if p])} for v in self.hosts.values()],
            'flows': list(self.flows.values()),
            'protocols': dict(self.protocols),
            'iocs': {k: sorted(v) for k, v in self.iocs.items()},
            'findings': self.findings,
            'log_sources': self.log_sources,
            'techniques': list(self.techniques.values()),
            'normalized_events': self.normalized_events,
            'normalized_event_summary': self.event_summary,
        }
