import os, sys
from socket import *
from fcntl import ioctl
from select import select
import getopt, struct

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001

TUNMODE = IFF_TUN

s = socket(AF_INET, SOCK_DGRAM)

f = os.open("/dev/net/tun", os.O_RDWR)
ifs = ioctl(f, TUNSETIFF, struct.pack("16sH", "tun%d", TUNMODE))
ifname = ifs[:16].strip("\x00")

print "Allocated interface %s. Configure it and use it" % ifname

os.write(f, "Hi! I'm UDP-package")

s.sendto(os.read(f,1500),("192.168.1.1",9090))

print "im here"
