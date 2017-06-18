#!/usr/bin/python
import os, sys
import time
from socket import *
from fcntl import ioctl
from select import select
import getopt, struct
from scapy.all import *
import binascii

from pytun import TunTapDevice, IFF_TUN, IFF_NO_PI

tun0 = None

dash_number = 40

IP_layer = 1
UDP_layer = 2

#def dash(func, info = ''):
#	count = (dash_number - len(info)) / 2
#	print '-'*count + info + '-'*count
#
#	print '-'*dash_number

def line():
	print '\n'
	print '----------------------------------------'
	print '\n'

def to_hex(packet):
	as_hex = []

	i = 0

	for b in str(packet):
		hex_num = hex(ord(b))
		if len(hex_num) == 3:
			hex_num = hex_num[:2] + '0' + hex_num[2:]
		as_hex.append(hex_num)
	print("Packet as hex:")
	print as_hex
	line()
	return as_hex

def calculate_chksum(data, layer):
	MOD = 65536

	checksum = 0

	i = 0

	data_len = len(data)

	is_len_even = False

	print "Data for checksum:"
	print data
	print '\n'

	if data_len % 2 == 0:
		is_len_even = True

		if is_len_even:
			print "Number of bytes is even"
		else:
			print "Number of bytes is odd"

	if (layer == IP_layer):
		data[10] = "0x00"
		data[11] = "0x00"
	if (layer == UDP_layer):
		data[18] = "0x00"
		data[19] = "0x00"

	while i < data_len:
		if (i == data_len - 1) and (not(is_len_even)):
			pair = data[i] + "00"
		else:
			pair = data[i] + data[i+1][2:]
		checksum += int(pair, 16)
		i += 2

	#print checksum // MOD

	if (checksum // MOD) != 0:
		checksum = checksum % MOD + checksum // MOD

	checksum = (MOD - 1) - checksum

	print "Checksum: " +  hex(checksum)[2:]
	line()

	return checksum

def ip_calculate_chksum(packet):
	as_hex = to_hex(packet)

	return calculate_chksum(as_hex[0:int(as_hex[0][3], 16) * 4], IP_layer)

def test(packet):
	time.sleep(5)
	new_packet = packet.copy()
	change_version(new_packet, 6)
	tun0.write(str(new_packet)) 	#default: 4
	time.sleep(1)
	new_packet = packet.copy()
	change_ihl(new_packet, 10)
	tun0.write(str(new_packet))		#default: 5
	time.sleep(1)
	new_packet = packet.copy()
	change_tos(new_packet, 0x10)
	tun0.write(str(new_packet))	#default: 0 here: 00010000
	time.sleep(1)
	new_packet = packet.copy()
	change_len(new_packet, 60)
	tun0.write(str(new_packet))		#default: 46
	time.sleep(1)
	new_packet = packet.copy()
	change_frag(new_packet, 2)
	tun0.write(str(new_packet))		#default: 1
	time.sleep(1)
	#new_packet = packet.copy()
	#tun0.write(str(change_flags(new_packet, 6)))
	#tun.sleep(1)
	new_packet = packet.copy()
	change_ttl(new_packet, 1)
	tun0.write(str(new_packet))		#default: 64
	time.sleep(1)
	new_packet = packet.copy()
	change_proto(new_packet, 1)
	tun0.write(str(new_packet))	#default: 17
	time.sleep(1)
	new_packet = packet.copy()
	ip_change_chksum(new_packet, ip_calculate_chksum(new_packet))
	tun0.write(str(new_packet))	
	time.sleep(1)
	#new_packet = packet.copy()
	#tun0.write(str(change_options(new_packet, 6)))
	#tun.sleep(1)

#---------------IP---------------#

def change_version(packet, version):
	packet[IP].version = version

def change_ihl(packet, ihl):
	packet[IP].ihl = ihl

#111 - Network Control
#110 - Internetwork Control
#101 - CRITIC/ECP
#100 - Flash Override
#011 - Flash
#010 - Immediate
#001 - Priority
#000 - Routine

def change_tos(packet, tos):
	packet[IP].tos = tos

def change_len(packet, len):
	packet[IP].len = len

def change_id(packet, id):
	packet[IP].id = id

def change_flags(packet, flags):
	packet[IP].flags = flags

def change_frag(packet, frag):
	packet[IP].frag = frag

def change_ttl(packet, ttl):
	packet[IP].ttl = ttl

def change_proto(packet, proto):
	packet[IP].proto = proto

def ip_change_chksum(packet, chksum):
	packet[IP].chksum = chksum

def change_src(packet, src):
	packet[IP].src = src

def change_dst(packet, dst):
	packet[IP].dst = dst

def change_options(packet, options):
	packet[IP].options = options

#---------------UDP---------------#

def change_sport(packet, sport):
	packet[UDP].sport = sport

def change_dport(packet, dport):
	packet[UDP].dport = dport

def change_len(packet, len):
	packet[UDP].len = len

def udp_change_chksum(packet, chksum):
	packet[UDP].chksum = chksum

def udp_calculate_chksum(packet):
	as_hex = to_hex(packet)

	data = [											#pseudo_header
		as_hex[12], as_hex[13], as_hex[14], as_hex[15],	#source address
		as_hex[16], as_hex[17], as_hex[18], as_hex[19],	#destination address
		'0x00',											#zero
		as_hex[9],										#protocol
		as_hex[24], as_hex[25]]							#udp length

	data.extend(as_hex[int(as_hex[0][3], 16) * 4:])

	#print pseudo_header

	return calculate_chksum(data, UDP_layer)


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

print '\n'

print "IP Checksum: " + hex(ip_calculate_chksum(packet))

print "UDP Checksum: " + hex(udp_calculate_chksum(packet))

print '\n'
hexdump(packet)
line()

try:
	tun0.up()

	test(packet)

finally:
	tun0.close()
