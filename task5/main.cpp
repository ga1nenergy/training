#include <unistd.h>
#include <iostream>
#include <string>
#include <ctime>
#include <crafter.h>
#include "viface/viface.hpp"
#include "funcs.h"

using namespace std;
using namespace Crafter;
using namespace viface;

int main() {

	string enp5s0 = "enp5s0";
	VIface iface("tun%d", false, -1);
	iface.setIPv4("10.1.8.82");
	iface.setIPv4Netmask("255.255.255.0");

	//iface.up();

	IP ip_header;
	ip_header.SetSourceIP("0.0.0.0");
	ip_header.SetDestinationIP("0.0.0.0");

	UDP udp_header;
	udp_header.SetSrcPort(0);
	udp_header.SetDstPort(0);

	RawLayer raw_header;
	raw_header.SetPayload("");

	Packet blank_packet = ip_header / udp_header / raw_header;

	cout << endl << "This is my packet:" << endl;

	blank_packet.Print();

	cout << endl << "This is a hexdump:" << endl;

	blank_packet.HexDump();

	cout << endl << "This is raw data:" << endl;
	blank_packet.RawString(cout);

	cout << endl << "Here comes the magic!" << endl;

	try {
		iface.up();

		int packets = 100000;

		clock_t start_time = clock();

		for (int i = 0; i < packets; i++) {
			CustomPacket cp(blank_packet);

			cp.setSrcIP("192.168.1.2");
			cp.setDstIP("192.168.1.1");
			cp.setSrcPort(4444);
			cp.setDstPort(4444);
			cp.setPayload("Hi! I'm UDP-packet");
			cp.setUDPCheckSum();
			cp.setIPCheckSum();

			vector<uint8_t> data = cp.data();
			iface.send(data);
		}

		clock_t end_time = clock();

		cout.precision(5);

		cout << endl << dec << start_time << ' ' << end_time;

		cout << endl << "Custom time: " << (double)(end_time - start_time)/packets/CLOCKS_PER_SEC*1000000
				<< " mcs" << endl;

		start_time = clock();

		for (int i = 0; i < packets; i++)
		{
			Packet packet(blank_packet);

			packet.GetLayer<IP>()->SetSourceIP("192.168.1.2");
			packet.GetLayer<IP>()->SetDestinationIP("192.168.1.1");
			packet.GetLayer<UDP>()->SetSrcPort(4444);
			packet.GetLayer<UDP>()->SetDstPort(4444);
			packet.GetLayer<RawLayer>()->SetPayload("Hi! I'm UDP-packet");

			packet.Send(iface.getName());
		}

		end_time = clock();

		cout << endl << "Crafter time: " << dec << (double)(end_time - start_time)/packets/CLOCKS_PER_SEC*1000000
						<< " mcs" << endl;

	} catch (exception const &ex) {
		cerr << ex.what() << endl;
		iface.down();
		return -1;
	}
	iface.down();

	return 0;
}
