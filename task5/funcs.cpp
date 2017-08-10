#include "funcs.h"
#include <string>
#include <sstream>
#include <vector>
#include <iterator>
#include <cstdlib>
#include <math.h>

/*-----UTILS-----*/

template<typename Out>
void split(const std::string &s, char delim, Out result) {
    std::stringstream ss;
    ss.str(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        *(result++) = item;
    }
}


std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    split(s, delim, std::back_inserter(elems));
    return elems;
}

/*-----CUSTOM PACKET-----*/

CustomPacket::CustomPacket(Crafter::Packet& packet) {
	byte* raw = new byte[packet.GetSize()];
	v.resize(packet.GetSize());

	packet.GetData(raw);

	for (size_t i = 0; i < packet.GetSize(); i++) {
		v[i] = raw[i];
	}
}

CustomPacket::~CustomPacket() {}

void CustomPacket::setSrcIP(string srcIP) {
	vector<string> str_ip = split(srcIP, '.');

	for (int i = 0; i < (int)str_ip.size(); i++)
	{
		v[12+i] = (uint8_t)atoi(str_ip[i].c_str());
	}
}

void CustomPacket::setDstIP(string dstIP) {
	vector<string> str_ip = split(dstIP, '.');

	for (int i = 0; i < (int)str_ip.size(); i++)
	{
		v[16+i] = (uint8_t)atoi(str_ip[i].c_str());
	}
}

void CustomPacket::setSrcPort(uint16_t port) {
	v[20] = (uint8_t)(port >> 8);
	v[21] = (uint8_t)(port & 0xFF);
}

void CustomPacket::setDstPort(uint16_t port) {
	v[22] = (uint8_t)(port >> 8);
	v[23] = (uint8_t)(port & 0xFF);
}

void CustomPacket::setPayload(string payload) {
	char* c_payload = new char[payload.size()];
	strcpy(c_payload, payload.c_str());
	v.resize(20+8+payload.size());
	payload_size = payload.size();

	uint16_t datagram_size = 8 + payload.size();
	v[24] = (uint8_t)(datagram_size >> 8);
	v[25] = (uint8_t)(datagram_size & 0xFF);

	uint16_t packet_size = 20 + datagram_size;
	v[2] = (uint8_t)(packet_size >> 8);
	v[3] = (uint8_t)(packet_size & 0xFF);

	for (int i = 0; i < (int)payload.size(); i++)
	{
		v[28+i] = (uint8_t)c_payload[i];
	}
}

void CustomPacket::setUDPCheckSum() {
	vector<uint8_t> data;

	v[26] = v[27] = 0;
	//pseudo header
	for (int i = 12; i < 20; i++) {	//src and dest ip bytes
		data.push_back(v[i]);		//
	}
	data.push_back(0);

	data.push_back(v[9]); 			//protocol

	data.push_back(v[24]); 			//udp length
	data.push_back(v[25]); 			//
	//
	//udp + payload_
	//		        |
	//              V
	for (int i = 0; i < 8+payload_size; i++) {
		data.push_back(v[20+i]);
	}
	if (data.size() % 2) {
		data.push_back(0);
	}

	vector<uint16_t> pairs;
	for (int i = 0; i < data.size(); i += 2) {
		pairs.push_back((uint16_t)(data[i] << 8) + data[i + 1]);
	}

	uint32_t checksum_32 = 0;
	for (uint16_t pair : pairs) {
		checksum_32 = checksum_32 + pair;
	}

	uint16_t checksum = (uint16_t)checksum_32 + (checksum_32 >> 16);

	checksum = 0xFFFF-checksum;

	v[26] = checksum >> 8;
	v[27] = checksum & 0xFF;
}

void CustomPacket::setIPCheckSum() {
	vector<uint16_t> pairs;
	uint32_t checksum_32 = 0;
	v[10] = 0;
	v[11] = 0;

	for (int i = 0; i < (v[0] & 0xF)*4; i += 2) {
		pairs.push_back((uint16_t)(v[i] << 8) + v[i + 1]);
	}

	for (uint16_t pair : pairs) {
		checksum_32 = checksum_32 + pair;
	}

	uint16_t checksum = (uint16_t)checksum_32 + (checksum_32 >> 16);
	checksum = 0xFFFF-checksum;

	v[10] = checksum >> 8;
	v[11] = checksum & 0xFF;
}

vector<uint8_t> CustomPacket::data() {
	return v;
}
