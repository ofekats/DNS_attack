from scapy.all import *
from scapy.layers.dns import DNSQR
from scapy.layers.dns import DNS
from scapy.layers.inet import IP
from scapy.layers.inet import UDP

MAX_FILE_SIZE = 1000000
if __name__ == "__main__":
    Qdsec = DNSQR(qname='twysw.example.com')
    dns = DNS(id=0xAAAA, qr=0, qdcount=1, ancount=0, nscount=0,
    arcount=0, qd=Qdsec)
    # ip = IP(dst='10.9.0.53', src='10.9.0.5')
    ip = IP(dst='127.0.0.1', src='10.9.0.5')
    udp = UDP(dport=53, sport=12345, chksum=0)
    request = ip/udp/dns
    # Save the packet to a file
    with open('ip_req.bin', 'wb') as f:
        f.write(bytes(request))

    # send(request)

