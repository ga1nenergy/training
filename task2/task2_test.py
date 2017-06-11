#!/usr/bin/python
from pytun import TunTapDevice
from select import select
import time

tun1 = TunTapDevice()
tun2 = TunTapDevice()

print "Name %s" % tun1.name
tun1.addr = '10.8.0.1'
tun1.dstaddr = '10.8.0.2'
tun1.netmask = '255.255.255.0'
tun1.mtu = 1500
tun1.up()

print "Name %s" % tun2.name
tun2.addr = '10.8.0.2'
tun2.dstaddr = '10.8.0.1'
tun2.netmask = '255.255.255.0'
tun2.mtu = 1500
tun2.up()

while True:
    r = select([tun1, tun2], [], [])[0][0]
    try:
        buf = r.read(r.mtu)
        if r == tun1:
            read = tun1.name
            tun2.write("Hi tun1!")
        else:
            read = tun2.name
            tun1.write("Hi tun2!")
        print "Read from %s: %s" % (read, buf.encode('hex'))
		#time.sleep(5)

    except:
        tun1.close()
        tun2.close()
        exit()