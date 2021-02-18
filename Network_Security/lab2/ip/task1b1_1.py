from scapy.all import *
# Construct IP header
ip = IP(src="1.2.3.4", dst="10.0.2.5",id=1000,)

# Construct UDP header
udp = UDP(sport=7070, dport=9090)
udp.len = 232 # This should be the combined length of all fragments
# Construct payload
payload1 = 'A' * 80 # Put 80 bytes in the first fragment
payload2 = 'B' * 80
payload3 = 'C' * 80


# Construct the entire packet and send it out
ip.frag = 0 # Offset of this IP fragment
ip.flags = 1 # Flags
pkt1 = ip/udp/payload1 # For other fragments, we should use ip/payload
pkt1[UDP].chksum = 0 # Set the checksum field to zero
send(pkt1, verbose=0)

ip.frag = 8 # Offset of this IP fragment
ip.flags = 1 # Flags
pkt2 = ip/udp/payload2
pkt2[UDP].chksum = 0
send(pkt2, verbose=0)
ip.frag = 18 # Offset of this IP fragment
ip.flags = 0 # Flags
pkt3=ip/udp/payload3
pkt3[UDP].chksum = 0



send(pkt3, verbose=0)








