#include "pcap-test.h"
void print_mac(u_int8_t *m){
	printf("%02x:%02x:%02x:%02x:%02x:%02x:\n",m[0],m[1],m[2],m[3],m[4],m[5]);
}

void print_ip(struct in_addr m){
	printf("%s\n",inet_ntoa(m));
}

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet; // Ehternet header start point
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		struct libnet_ether_hdr *eth_hdr =(struct libnet_ether_hdr *) packet;
		struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr *)(packet + sizeof    (struct libnet_ether_hdr));
		struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *)(packet + sizeof(struct libnet_ether_hdr) + sizeof(struct libnet_ipv4_hdr));

		if(ip_hdr->ip_p != 6)
			continue;

		printf("src mac : ");
		print_mac(eth_hdr->ether_shost);
		printf("dst mac : ");
		print_mac(eth_hdr->ether_dhost);

		printf("src ip : ");
		print_ip(ip_hdr->ip_src);
		printf("dst ip : ");
		print_ip(ip_hdr->ip_dst);

		printf("src tcp : %d\n",ntohs(tcp_hdr->th_sport));
		printf("dst tcp : %d\n",ntohs(tcp_hdr->th_dport));

		u_int8_t loc = (sizeof(struct libnet_ether_hdr) + sizeof(struct libnet_ipv4_hdr) + tcp_hdr->th_off * 4);

		if(header->len != loc)
		{
			printf("\n\n");
			continue;
		}
		printf("Payload data: ");
		for (int i = 0; i < 10  ; i++) {
			printf("%02x ",packet[loc + i]);
		}
		printf("\n\n");
	}
	pcap_close(pcap);
}
