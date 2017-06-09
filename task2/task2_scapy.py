#!/usr/bin/python

from scapy.all import *

def change_ip(package, new_ip):
    package[IP].src = new_ip

ip = IP(src="192.168.1.4", dst="192.168.1.1")
udp = UDP(sport=4444, dport=4444)
payload = Raw(load="Hi! I'm UDP-package")

package = ip/udp/payload

package.show()

send(package)

change_ip(package, "192.168.1.2")

package.show()

send(package)