#!/usr/bin/python3
import fcntl
import struct
import os
import time
from scapy.all import *
import uuid

def get_mac_address(): 
    mac=uuid.UUID(int = uuid.getnode()).hex[-12:] 
    return ":".join([mac[e:e+2] for e in range(0,11,2)])

local_mac=get_mac_address()

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000
SERVER_IP="10.0.2.9"
SERVER_PORT=9090
# Create the tun interface
tun = os.open("/dev/net/tun",os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TAP | IFF_NO_PI)
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)
# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
sendsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
print("Interface Name: {}".format(ifname))
os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname))
#os.system("ip addr add 192.168.30.99/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))
os.system("ip route add  192.168.60.0/24  dev tun0 via 192.168.53.99")
#os.system("ip route add  192.168.60.0/24  dev tun0 via 192.168.30.99")

IP_U = "0.0.0.0"
U_PORT = 2345
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((IP_U, U_PORT))

'''
while True:
    # this will block until at least one interface is ready
    ready, _, _ = select([sock, tun], [], [])
    for fd in ready:
        if fd is sock:
            data, (ip, port) = sock.recvfrom(2048)
            pkt = IP(data)
            print("From socket <==: {} --> {}".format(pkt.src, pkt.dst))
            os.write(tun, bytes(pkt))






        if fd is tun:
            packet = os.read(tun, 2048)
            pkt = IP(packet)
            print("From tun ==>: {} --> {}".format(pkt.src,pkt.dst))
            print(pkt.summary())
            sendsock.sendto(packet, (SERVER_IP, SERVER_PORT))
'''


while True:
    packet = os.read(tun, 2048)
    if True:
        #print("--------------------------------")
        ether = Ether(packet)
        #print(ether.summary())
        # Send a spoofed ARP response
        if ARP in ether and ether[ARP].op == 1 :
            arp = ether[ARP]
            newether = Ether(src=local_mac,dst='FF:FF:FF:FF:FF:FF')
            newarp = ARP(op=2,hwsrc=local_mac,psrc=arp.pdst,hwdst=arp.hwsrc,pdst=arp.psrc)
            newpkt = newether/newarp
            print("***** Fake response: {}".format(newpkt.summary()))
            os.write(tun, bytes(newpkt))



