from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw
from app.models import Event

PORT_PROTOCOLS = {
    20:'FTP',21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',67:'DHCP',68:'DHCP',80:'HTTP',88:'Kerberos',110:'POP3',123:'NTP',135:'MSRPC',137:'NetBIOS',138:'NetBIOS',139:'NetBIOS',143:'IMAP',161:'SNMP',162:'SNMP Trap',389:'LDAP',443:'HTTPS',445:'SMB',464:'Kerberos',514:'Syslog',587:'SMTP Submission',636:'LDAPS',993:'IMAPS',995:'POP3S',1433:'MSSQL',1521:'Oracle',2055:'NetFlow',3268:'LDAP GC',3306:'MySQL',3389:'RDP',4739:'IPFIX',5044:'Elastic Beats',5432:'PostgreSQL',5900:'VNC',5985:'WinRM',5986:'WinRM TLS',6379:'Redis',6514:'Syslog TLS',8080:'HTTP Alt',8443:'HTTPS Alt',9200:'Elasticsearch',27017:'MongoDB',51820:'WireGuard',6343:'sFlow'
}

def mac(pkt, field):
    return getattr(pkt[Ether], field, '') if Ether in pkt else ''

def payload_text(pkt):
    if Raw in pkt:
        try:
            return bytes(pkt[Raw].load[:4096]).decode('utf-8', 'ignore')
        except Exception:
            return ''
    return ''

def base_ips(pkt):
    if IP in pkt:
        return pkt[IP].src, pkt[IP].dst
    if IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst
    return '', ''

def infer_proto(sport, dport, transport):
    return PORT_PROTOCOLS.get(dport) or PORT_PROTOCOLS.get(sport) or transport

def parse_packet(pkt, ts):
    events = []
    if ARP in pkt:
        events.append(Event(type='arp', ts=ts, src_ip=pkt[ARP].psrc, dst_ip=pkt[ARP].pdst, src_mac=pkt[ARP].hwsrc, dst_mac=pkt[ARP].hwdst, protocol='ARP', bytes=len(pkt), summary='ARP activity').to_dict())
        return events
    src_ip, dst_ip = base_ips(pkt)
    src_mac, dst_mac = mac(pkt, 'src'), mac(pkt, 'dst')
    if TCP in pkt:
        sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
        proto = infer_proto(sport, dport, 'TCP')
        text = payload_text(pkt)
        events.append(Event(type='flow', ts=ts, src_ip=src_ip, dst_ip=dst_ip, src_mac=src_mac, dst_mac=dst_mac, protocol=proto, sport=sport, dport=dport, bytes=len(pkt), summary=f'{proto} TCP {src_ip}:{sport} -> {dst_ip}:{dport}', evidence={'payload_hint': text}).to_dict())
    elif UDP in pkt:
        sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
        proto = infer_proto(sport, dport, 'UDP')
        text = payload_text(pkt)
        ev = Event(type='flow', ts=ts, src_ip=src_ip, dst_ip=dst_ip, src_mac=src_mac, dst_mac=dst_mac, protocol=proto, sport=sport, dport=dport, bytes=len(pkt), summary=f'{proto} UDP {src_ip}:{sport} -> {dst_ip}:{dport}', evidence={'payload_hint': text}).to_dict()
        if DNS in pkt:
            q = ''
            try:
                q = pkt[DNSQR].qname.decode(errors='ignore').rstrip('.')
            except Exception:
                pass
            ev['type'] = 'dns'
            ev['evidence']['query'] = q
            ev['summary'] = f'DNS query {q}' if q else ev['summary']
        events.append(ev)
    elif ICMP in pkt:
        events.append(Event(type='icmp', ts=ts, src_ip=src_ip, dst_ip=dst_ip, src_mac=src_mac, dst_mac=dst_mac, protocol='ICMP', bytes=len(pkt), summary=f'ICMP {src_ip} -> {dst_ip}').to_dict())
    return events
