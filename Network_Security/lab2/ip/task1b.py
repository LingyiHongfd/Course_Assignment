from scapy.all import *
# Construct IP header
k=5
ip1 = IP(src="1.2.3.4", dst="10.0.2.5",id=1000,frag=0,flags=1,)
ip2 = IP(src="1.2.3.4", dst="10.0.2.5",id=1000,frag=32-k,flags=1,)
ip3 = IP(src="1.2.3.4", dst="10.0.2.5",id=1000,frag=72,flags=0,)
udp = UDP(sport=7070, dport=9090)
udp.len = 96 # This should be the combined length of all fragments
# Construct payload
payload1 = 'A' * (32-k)+'Z'*k # Put 80 bytes in the first fragment
payload2 = 'Y'*k+'B' * (32-k)
payload3 = 'C' * 32
# Construct the entire packet and send it out
pkt1 = ip1/udp/payload1 # For other fragments, we should use ip/payload
pkt2 = ip2/payload2
pkt3=ip3/payload3
#pkt1[UDP].checksum = 0 # Set the checksum field to zero
send(pkt1, verbose=0)
send(pkt2, verbose=0)

send(pkt3, verbose=0)








