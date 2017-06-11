#!/usr/bin/python

from scapy.all import *
from socket import *
from time import *

def change_dst_ip(packet, new_ip):
	new_packet = packet.copy()
	new_packet[IP].dst = new_ip
	return new_packet

ip = IP(src="192.168.1.2", dst="192.168.1.1")
udp = UDP(sport=4444, dport=4444)
payload = Raw(load="Hi! I'm UDP-packet")

packet = ip/udp/payload

packet.show()

new_packet = change_dst_ip(packet, "192.168.1.3")

new_packet.show()

s = socket(AF_INET, SOCK_DGRAM)

while True:
	sleep(5)
	s.sendto(str(packet), (packet[IP].dst, packet[UDP].dport))
	sleep(5)
	s.sendto(str(new_packet), (new_packet[IP].dst, new_packet[UDP].dport))
	#time.sleep(5)

s.close()