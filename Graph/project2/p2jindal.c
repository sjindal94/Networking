#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination MAC address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source MAC address */
        u_short ether_type;                     /* type of packet IP,ARP,RARP,slow protocols etc. 0800=IP 0806=ARP 08dd=ipv6*/
};

struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)  (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)   (((ip)->ip_vhl) >> 4)

typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
		#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

struct sniff_udp{
	ushort uh_sport;
	ushort uh_dport;
	ushort uh_len;
	ushort uh_sum;
	#define UH_OFF(uh)  8
};
void print_ethernetdata(const u_char *packet){
	const u_char *ch;
	ch = packet;
	printf("Ethernet data: ");
	//for(i = 0; i < SIZE_ETHERNET; i++) {
	while(*ch!='\0'){
		printf("%02x ", *ch);
		ch++;
	}
	printf("\n");
}
/*
 * print data in rows of 16 bytes: 
 * offset                         hex                            ascii
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset){
	int i;
	int gap;
	const u_char *ch;
	printf("%05d   ", offset);
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))//printable character
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}
	printf("\n");
	return;
}

void print_payload(const u_char *payload, int len){
	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		line_len = line_width % len_rem;
		print_hex_ascii_line(ch, line_len, offset);
		len_rem = len_rem - line_len;
		ch = ch + line_len;
		offset = offset + line_width;
		if (len_rem <= line_width) {
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}
	return;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	static int count = 1;//packet counter
	const struct sniff_ethernet *ethernet;  
	const struct sniff_ip *ip;              
	const struct sniff_tcp *tcp;            
	const struct sniff_udp *udp;
	const struct icmphdr *ping;
	const u_char *payload; 
	int size_ip;
	int size_tcp;
	int size_udp;
	int size_icmp;
	//int size_icmp,icmp_count=0;
	int size_payload;
	printf("\nPacket number %d:\n", count);
	count++;
	ethernet = (struct sniff_ethernet*)(packet);
	//printf("%x",ethernet->ether_type);
	if(ethernet->ether_type==0xdd86){
		printf("IPv6 packet\n");
		return;//ipv6 packet
	}
	//print_ethernetdata(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	printf("       From: %s\n", inet_ntoa(ip->ip_src));//u_int32_t
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
			size_tcp = TH_OFF(tcp)*4;
			if (size_tcp < 20) {
				printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
				return;
			}
			printf("   Src port: %d\n", ntohs(tcp->th_sport));
			printf("   Dst port: %d\n", ntohs(tcp->th_dport));//uint16_t
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
			size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
			if (size_payload > 0) {
				printf("   Payload (%d bytes):\n", size_payload);
				print_payload(payload, size_payload);
			}
			return;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			udp=(struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
			if(ntohs(udp->uh_dport)==67 || ntohs(udp->uh_dport)==68) printf("   DHCP packet\n");
			size_udp=UH_OFF(udp);
			/*if(size_udp<8)  //fixed
			{
				printf(" *INVALID UDP HEADER LENGTH : %d bytes\n",size_udp);//possible attack here
				return;
			}*/
			printf("   Src Port : %d\n",ntohs(udp->uh_sport));
			printf("   Dsr Port : %d\n",ntohs(udp->uh_dport));
			payload=(u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
			size_payload=ntohs(ip->ip_len)-(size_ip + size_udp);
			if(size_payload>0)
			{
				printf(" Payload Size :%d bytes\n",size_payload);
				//if(ntohs(udp->uh_sport)==67)//dhcp
				print_payload(payload,size_payload);
			}
			return;
		case IPPROTO_ICMP:
			printf("   PROTOCOL : ICMP\n");
			//write(1,message,strlen(message));
			ping=(struct icmphdr*)(packet+SIZE_ETHERNET+size_ip);
			size_icmp=8;
        	payload=(u_char *)(packet + SIZE_ETHERNET + size_ip + size_icmp);
        	size_payload=ntohs(ip->ip_len)-(size_ip + size_icmp);
        	if (size_payload > 0) {
				printf("   Payload (%d bytes):\n", size_payload);
				print_payload(payload, size_payload);
			}
            return;
		default:
			printf("%d Protocol: unknown implementation\n",ip->ip_p);
			return;
	}
}

int main(int argc, char **argv){
	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */
	char filter_exp[] = "icmp";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 100;			/* number of packets to capture */
	/* check for capture device name on command-line */
	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		exit(EXIT_FAILURE);
	}
	else {
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf); 
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);//
	pcap_close(handle);
	printf("\nCapture complete.\n");
	return 0;
}

//10.10.49.153 is our dhcp server
//dhcpv6 uses 546 and 547 in ipv6 packet
