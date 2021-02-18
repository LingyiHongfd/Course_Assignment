from scapy.all import *
a = IP()
a.dst = '10.0.2.8'
a.ttl = 2
b = ICMP()
send(a/b)