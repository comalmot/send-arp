#include <cstdio>
#include <libnet.h>
#include <pcap.h>

#pragma pack(push, 1)
struct Arp_Packet {
    libnet_ethernet_hdr eth_;
    libnet_arp_hdr arp_;
};
#pragma pack(pop)

int send_arp(pcap_t *handle);
int recog_mac(pcap_t *handle);

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

    
    return 0;
}

int send_arp(pcap_t *handle) {
        struct Arp_Packet arp; 
        

}

int recog_mac(pcap_t *handle) { // recognize sender's mac address
    struct pcap_pkthdr *header;
    const u_char *packet;
    int protocol;
    int res = pcap_next_ex(handle, &header, &packet);
}
