#!/usr/bin/python3
import fcntl
import struct
import os
import time
from scapy.all import *

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
os.system("ip link set dev {} up".format(ifname))

os.system("sysctl net.ipv4.ip_forward=1")



while True:
    data, (ip, port) = sock.recvfrom(2048)
    print("{}:{} --> {}:{}".format(ip, port, IP_A, PORT))
    pkt = IP(data)
    print(" Inside: {} --> {}".format(pkt.src, pkt.dst))
    print('pkt',pkt.summary())
    newip = IP(src=pkt.src, dst=pkt.dst)
    newpkt = newip/pkt.payload
    print ('newpkt',newpkt.summary())
    os.write(tun, bytes(newpkt))

'''
while True:
# Get a packet from the tun interface
    packet = os.read(tun, 2048)
    if True:
        ip = IP(packet)
        print(ip.summary())
        newip = IP(src='10.0.2.5',dst=ip.src)
        newpkt = newip/ip.payload
        os.write(tun, bytes(newpkt))
'''