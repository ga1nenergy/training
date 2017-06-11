#!/usr/bin/python
import os, sys
import time
from socket import *
from fcntl import ioctl
from select import select
import getopt, struct
from scapy.all import *

from pytun import TunTapDevice, IFF_TUN, IFF_NO_PI

tun0 = TunTapDevice(name='tun0', flags=IFF_TUN + IFF_NO_PI)
#'127.0.0.1'
tun0.addr = '10.1.8.82'
tun0.dstaddr = '10.1.8.83'
tun0.netmask = '255.255.255.0'
tun0.mtu = 1500

ip = IP(src='10.1.8.82', dst='10.1.8.83')
udp = UDP()
payload = Raw(load="Hi! I'm UDP-packet")

packet = ip/udp/payload

try:
	tun0.up()

	while True:
		tun0.write(str(packet))
		#tun0.write("Hi! I'm UDP-packet")
		time.sleep(5)
finally:
	tun0.close()
