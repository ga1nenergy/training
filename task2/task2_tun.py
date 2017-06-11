#!/usr/bin/python
import os, sys
import time
from socket import *
from fcntl import ioctl
from select import select
import getopt, struct
from scapy.all import *

from pytun import TunTapDevice, IFF_TUN, IFF_NO_PI

def change_dst_ip(packet, new_ip):
	new_packet = packet.copy()
	new_packet[IP].dst = new_ip
	return new_packet

tun0 = TunTapDevice(name='tun0', flags=IFF_TUN + IFF_NO_PI)
#'127.0.0.1'
tun0.addr = '10.1.8.82'
tun0.dstaddr = '10.1.8.83'
tun0.netmask = '255.255.255.0'
tun0.mtu = 1500

ip = IP(src="192.168.1.2", dst="192.168.1.1")
udp = UDP(sport=4444, dport=4444)
payload = Raw(load="Hi! I'm UDP-packet")

packet = ip/udp/payload

packet.show()

new_packet = change_dst_ip(packet, "192.168.1.3")

new_packet.show()

try:
	tun0.up()

	while True:
		tun0.write(str(packet))
		#tun0.write("Hi! I'm UDP-packet")
		time.sleep(5)
		tun0.write(str(new_packet))
		time.sleep(5)
finally:
	tun0.close()
