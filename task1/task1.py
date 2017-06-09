#!/usr/bin/python

from scapy.all import *

ip = IP(src="192.168.1.4", dst="192.168.1.1")
udp = UDP(sport=4444, dport=4444)
payload = Raw(load="Hi! I'm UDP-package")

package = ip/udp/payload

package.show()

send(package)