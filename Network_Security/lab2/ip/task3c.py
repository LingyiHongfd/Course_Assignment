from scapy.all import *
# Construct IP header
ip = IP(src="1.2.3.4", dst="192.168.60.5",id=1000,)
#ip.frag = 0 # Offset of this IP fragment
#ip.flags = 0 # Flags
# Construct UDP header
udp = UDP(sport=7070, dport=9090)
udp.len = 32 # This should be the combined length of all fragments
# Construct payload
payload1 = 'A' * 32 # Put 80 bytes in the first fragment
# Construct the entire packet and send it out
pkt1 = ip/payload1 # For other fragments, we should use ip/payload
#pkt1[UDP].chksum = 0 # Set the checksum field to zero
send(pkt1, verbose=0)






