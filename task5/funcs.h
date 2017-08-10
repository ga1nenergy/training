#include <string>
#include <vector>
#include <crafter.h>
#include <cstddef>

using namespace std;

typedef unsigned char byte;

class CustomPacket {
	int payload_size;
	vector<uint8_t> v;
public:
	
	CustomPacket(Crafter::Packet& packet);
	~CustomPacket();

	void setSrcIP(string srcIP);
	void setDstIP(string dstIP);
	void setSrcPort(uint16_t port);
	void setDstPort(uint16_t port);
	void setPayload(string payload);
	void setIPCheckSum();
	void setUDPCheckSum();
	vector<uint8_t> data();
};
