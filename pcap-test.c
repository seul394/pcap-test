#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
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
	char name[] = "이슬";
	char mobile[] = "1509";
	printf("[bob11]pcap-test[%s%s]\n", name, mobile);
	
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		// header 구조체 선언
		struct pcap_pkthdr* header;
		struct libnet_ethernet_hdr* ethernet;
		struct libnet_ipv4_hdr* ip;
		struct libnet_tcp_hdr* tcp;

		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		
		// header 구조체 할당
		ethernet = (struct libnet_ethernet_hdr*)packet;
		ip = (struct libnet_ipv4_hdr*)(packet+sizeof(*ethernet));	// ip header의 위치는 packet + ethernet header 사이즈
		tcp = (struct libnet_tcp_hdr*)(packet+sizeof(*ethernet)+sizeof(*ip));	// tcp header의 위치는 packet + ip header 사이즈
		
		if (ip->ip_p != 6) {	// check tcp
			continue;
		}
		
		//Ethernet Header
		printf("src mac: ");	// src mac
		for (int i = 0; i < ETHER_ADDR_LEN; i++){	// src mac 6 바이트 출력
			if (i != ETHER_ADDR_LEN-1) {	// src mac 5 바이트까지 끝에 : 붙임
				printf("%02x:", ethernet->ether_shost[i]);
			}
			else {	// src mac 1 바이트 출력 후 줄 바꿈
				printf("%02x\n", ethernet->ether_shost[i]);
			}
		}

		printf("dst mac: ");	// dst mac
		for (int i = 0; i < ETHER_ADDR_LEN; i++){	// dst mac 6 바이트 출력
			if (i != ETHER_ADDR_LEN-1 ) {	// dst mac 5 바이트까지 끝에 : 붙임
				printf("%02x:", ethernet->ether_dhost[i]);
			}
			else {	// dst mac 1 바이트 출력 후 줄 바꿈
				printf("%02x\n", ethernet->ether_dhost[i]);
			}
		}

		// IP Header
		printf("src ip: ");	// src ip
		u_int32_t src_ip = ntohl(ip->ip_src.s_addr);	// network byte order -> host byte order
		u_int8_t n1 = (src_ip & 0xFF000000) >> 24;	// 1 바이트 씩 남김
		u_int8_t n2 = (src_ip & 0x00FF0000) >> 16;
		u_int8_t n3 = (src_ip & 0x0000FF00) >> 8;
		u_int8_t n4 = (src_ip & 0x000000FF);
		printf("%d.%d.%d.%d\n", n1, n2, n3, n4);	// 바이트를 정수로 출력

		printf("dst ip: ");	// dst ip
		u_int32_t dst_ip = ntohl(ip->ip_dst.s_addr);	// network byte order -> host byte order
		n1 = (dst_ip & 0xFF000000) >> 24;	// 1 바이트 씩 남김
		n2 = (dst_ip & 0x00FF0000) >> 16;
		n3 = (dst_ip & 0x0000FF00) >> 8;
		n4 = (dst_ip & 0x000000FF);
		printf("%d.%d.%d.%d\n", n1, n2, n3, n4);	// 바이트를 정수로 출력
		
		// TCP Header
		printf("src port: ");	// src port
		u_int16_t src_port = ntohs(tcp->th_sport);	// network byte order -> host byte order
		printf("%d\n", src_port);

		printf("dst port: ");	// dst port
		u_int16_t dst_port = ntohs(tcp->th_dport);	// network byte order -> host byte order
		printf("%d\n", dst_port);

		// Payload(Data)
		printf("payload: ");
		u_int32_t payload_addr = sizeof(*ethernet)+sizeof(*ip)+tcp->th_off*4;	// payload의 위치는 ethernet header사이즈 + ip header 사이즈 + (data offset * 4)
		u_int32_t payload_len = header->caplen - payload_addr;	// payload 길이는 패킷 전체 길이 - payload의 위치
		
		if (payload_len == 0){
			printf("No data");
		}

		for (int i = 0; i < payload_len; i++){	// payload 길이 만큼 출력
			if (i == 10) break;	// 10 바이트가 넘으면 출력 종료
			printf("%02x ", packet[payload_addr+i]);
			
		} 

		printf("\n\n");
	}

	pcap_close(pcap);
}
