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
	#print("Packet as hex:")
	#print as_hex
	#line()
	return as_hex

def to_char(as_hex):
	string = ''

	for i in range(len(as_hex)):
		string += chr(int(as_hex[i], 16))

	return string

def calculate_chksum(data, layer):
	MOD = 65536

	checksum = 0

	i = 0

	data_len = len(data)

	is_len_even = False

	#print "Data for checksum:"
	#print data
	#print '\n'

	if data_len % 2 == 0:
		is_len_even = True

		#if is_len_even:
		#	print "Number of bytes is even"
		#else:
		#	print "Number of bytes is odd"

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

	#print "Checksum: " +  hex(checksum)[2:]
	#line()

	return checksum

def ip_calculate_chksum(packet):
	as_hex = to_hex(packet)

	return calculate_chksum(as_hex[0:int(as_hex[0][3], 16) * 4], IP_layer)

def ip_calculate_chksum_hex(as_hex):
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

def udp_calculate_chksum_hex(as_hex):
	data = [											#pseudo_header
		as_hex[12], as_hex[13], as_hex[14], as_hex[15],	#source address
		as_hex[16], as_hex[17], as_hex[18], as_hex[19],	#destination address
		'0x00',											#zero
		as_hex[9],										#protocol
		as_hex[24], as_hex[25]]							#udp length

	data.extend(as_hex[int(as_hex[0][3], 16) * 4:])

	#print pseudo_header

	return calculate_chksum(data, UDP_layer)

def change_payload(packet, payload):
	packet[Raw].load = payload

#----------------------------------#
def change_src_manual(as_hex, src):
	nums = src.split('.')

	for i in range(0, 4):
		as_hex[12 + i] = '0x' + hex(int(nums[i], 10))[2:].zfill(2)

	#print "As hex:"
	#print as_hex

def change_dst_manual(as_hex, dst):
	nums = dst.split('.')

	for i in range(0, 4):
		as_hex[16 + i] = '0x'+hex(int(nums[i], 10))[2:].zfill(2)

def change_payload_manual(as_hex, payload):
	udp_size = hex(8 + len(payload))[2:].zfill(4)
	#print udp_size
	as_hex[24] = '0x' + udp_size[0:2]
	as_hex[25] = '0x' + udp_size[2:4]
	ip_size = hex(int(as_hex[0][3],10) * 4 + 8 + len(payload))[2:].zfill(4)
	#print 'ip size: '+ ip_size
	as_hex[2] = '0x' + ip_size[0:2]
	as_hex[3] = '0x' + ip_size[2:4]
	#print '\n'
	for char in payload:
		as_hex.append('0x' + hex(ord(char))[2:].zfill(2))
		#print as_hex

def ip_manual_change_checksum(as_hex, chksum):
	hex_chksum = hex(chksum)[2:].zfill(4)
	as_hex[10] = '0x' + hex_chksum[0:2]
	as_hex[11] = '0x' + hex_chksum[2:4]

def udp_manual_change_checksum(as_hex, chksum):
	hex_chksum = hex(chksum)[2:].zfill(4)
	as_hex[26] = '0x' + hex_chksum[0:2]
	as_hex[27] = '0x' + hex_chksum[2:4]



tun0 = TunTapDevice(name='tun0', flags=IFF_TUN + IFF_NO_PI)
#'127.0.0.1'
tun0.addr = '10.1.8.82'
tun0.dstaddr = '10.1.8.83'
tun0.netmask = '255.255.255.0'
tun0.mtu = 1500

ip = IP(src="0.0.0.0", dst="0.0.0.0")
udp = UDP(sport=4444, dport=4444)
payload = Raw(load="")

packet = ip/udp/payload

packet.show() 

#print list(str(packet))

#print '\n'

#print "IP Checksum: " + hex(ip_calculate_chksum(packet))

#print "UDP Checksum: " + hex(udp_calculate_chksum(packet))

#print '\n'
hexdump(packet)
line()

#print str(packet)

as_hex = to_hex(packet)

for i in range(len(as_hex)):
	as_hex[i] = chr(int(as_hex[i],16))

#print ''.join(as_hex)

try:
	tun0.up()

	packets = 100000
	print "Packets: " + str(packets)

	start = time.clock()

	for i in range(packets):

		packet1 = packet.copy()
		packet1[IP].src = '192.168.1.2'
		packet1[IP].dst = '192.168.1.1'
		packet1[Raw].load = "Hi! I'm UDP-packet"
		tun0.write(str(packet1))

	finish = time.clock()
	est_time = (finish - start)*1000000
	print "Scapy time: {0}, mcs: {1}".format(est_time, est_time/packets)

	start = time.clock()

	for i in range(packets):
		packet2 = packet.copy()
		as_hex = to_hex(packet2)
		change_src_manual(as_hex, '192.168.1.2')
		change_dst_manual(as_hex, '192.168.1.1')
		change_payload_manual(as_hex, "Hi! I'm UDP-packet")
		ip_manual_change_checksum(as_hex, ip_calculate_chksum_hex(as_hex))
		udp_manual_change_checksum(as_hex, udp_calculate_chksum_hex(as_hex))
		tun0.write(to_char(as_hex))

	finish = time.clock()
	est_time = (finish - start)*1000000
	print "Manual time: {0}, mcs: {1}".format(est_time, est_time/packets)

finally:
	tun0.close()