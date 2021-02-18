#!/usr/bin/python3
import fcntl
import struct
import os
import time
from scapy.all import *
from select import *


os.system("iptables -F")
os.system("iptables -t nat -F")
os.system("sudo iptables -t nat -A POSTROUTING -j MASQUERADE -o enp0s8")

IP_A = "0.0.0.0"
PORT = 9090
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((IP_A, PORT))

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

# Create the tun interface
tun = os.open("/dev/net/tun",os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)
# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

os.system("ip addr add 192.168.53.11/24 dev {}".format(ifname))
#os.system("ip addr add 192.168.60.11/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))
os.system("sysctl net.ipv4.ip_forward=1")

IP_U='10.0.2.8'
U_port=2345
sendsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


while True:
    # this will block until at least one interface is ready
    ready, _, _ = select([sock, tun], [], [])
    for fd in ready:
        if fd is sock:
            data, (ip, port) = sock.recvfrom(2048)
            pkt = IP(data)
            print("From socket <==: {} --> {}".format(pkt.src, pkt.dst))
            #print("{}:{} --> {}:{}".format(ip, port, IP_A, PORT))
            print(" Inside: {} --> {}".format(pkt.src, pkt.dst))
            #print('sock pkt',pkt.summary())
            newip = IP(src=pkt.src, dst=pkt.dst)
            newpkt = newip/pkt.payload
            #print ('sock newpkt',newpkt.summary())
            os.write(tun, bytes(newpkt))



        if fd is tun:
            packet = os.read(tun, 2048)
            pkt = IP(packet)
            print("From tun ==>: {} --> {}".format(pkt.src,pkt.dst))
            print('tun pkt',pkt.summary())
            #pkt.show()
            newip=IP(src='10.0.2.5',dst='10.0.2.4')
            udp = UDP(sport=7070, dport=9090)
            newpkt=newip/udp/pkt.payload
            sock.sendto(packet, (IP_U, U_port))
            #send(newpkt)







