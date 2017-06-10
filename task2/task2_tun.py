import os, sys
from socket import *
from fcntl import ioctl
from select import select
import getopt, struct

from pytun import TunTapDevice, IFF_TUN, IFF_NO_PI

tun0 = TunTapDevice(name='tun0', flags=IFF_TUN) #+ IFF_NO_PI)
#'127.0.0.1'
tun0.addr = '192.168.1.2'
tun0.dstaddr = '192.168.1.1'
tun0.netmask = '255.255.255.0'
tun0.mtu = 1500

try:
	tun0.up()

	tun0.write("Hi! I'm UDP-package!")
finally:
	tun0.close()