//http://www.beej.us/guide/bgnet/output/html/multipage/gethostbynameman.html
#include <stdio.h>
//#include <errno.h>
//#include <netdb.h>
//#include <sys/types.h>
//#include <sys/socket.h>
//#include <netinet/in.h>
/*#include <arpa/inet.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>*/
#include<netinet/ip_icmp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include "tcp.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
unsigned short in_cksum(unsigned short *addr, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}
	if (nleft == 1) {
		*(unsigned char *) (&answer) = *(unsigned char *) w;
		sum += answer;
	}
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}
int host( char argv[])
{
    struct hostent *he;
    struct in_addr ipv4addr;
    inet_pton(AF_INET,argv, &ipv4addr);
    he = gethostbyaddr(&ipv4addr, sizeof ipv4addr, AF_INET);
    if(he!=NULL)
    printf("Host name: %s\n", he->h_name);
}
void icmp(char s[])
{
	struct ip ip;
	struct udphdr udp;
	struct icmp icmp;
	int sd;
	const int on = 1;
	struct sockaddr_in sin;
	u_char *packet;
	packet = (u_char *)malloc(60);
	ip.ip_hl = 0x5;
	ip.ip_v = 0x4;
	ip.ip_tos = 0x0;
	ip.ip_len = htons(60);
	ip.ip_id = htons(12830);
	ip.ip_off = 0x0;
	ip.ip_ttl = 64;
	ip.ip_p = IPPROTO_ICMP;
	ip.ip_sum = 0x0;
	ip.ip_src.s_addr = inet_addr("172.24.20.62");//my source address
	ip.ip_dst.s_addr = inet_addr(s);
	ip.ip_sum = in_cksum((unsigned short *)&ip, sizeof(ip));
	memcpy(packet, &ip, sizeof(ip));
	icmp.icmp_type = ICMP_ECHO;
	icmp.icmp_code = 0;
	icmp.icmp_id = 1000;
	icmp.icmp_seq = 0;
	icmp.icmp_cksum = 0;
	icmp.icmp_cksum = in_cksum((unsigned short *)&icmp, 8);
	memcpy(packet + 20, &icmp, 8);
	if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror("raw socket");
		exit(1);
	}
	if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
		perror("setsockopt");
		exit(1);
	}
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ip.ip_dst.s_addr;
	if (sendto(sd, packet, 60, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0)  {
		perror("sendto");
		exit(1);
	}
	//sleep(1);
}
void got_packet(u_char *args,const struct pcap_pkthdr *header,const u_char *packet)
{
    static int count=1;
    const struct sniff_ethernet *ethernet;
    const struct sniff_ip *ip;
    const char *payload;
    int i,size_ip;
    ethernet=(struct sniff_ethernet*)packet;
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	printf("       From: %s\n", inet_ntoa(ip->ip_src));//u_int32_t
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));
	printf("yo");
	host(inet_ntoa(ip->ip_src));
}
int main(int argc,char *argv[])
{
    {
        char *dev="wlp6s0";//"wlan0";
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle;
        char filter_exp[]="icmp";
        struct bpf_program fp;
        bpf_u_int32 mask;
        bpf_u_int32 net;
        int num_packets=100;
        int i,p=fork();
        if(p==0)//child process
        {
            char s[12];
            for(i=1;i<255;i++)
            {
                sprintf(s,"172.24.18.%d",i);
                printf("%s\n",s);
                icmp(s);
            }
            printf("#########ICMP PACKETS SENT#########\n");
            //sleep(1);
            exit(1);
        }
        if(pcap_lookupnet(dev,&net,&mask,errbuf)==-1)
        {
            printf("Couldnet get mask for %s :%s\n",dev,errbuf);
            net=0;
            mask=0;
        }
        printf("DEVICE : %s\n",dev);
        printf("NUMBER OF PACKETS :%d\n",num_packets);
        printf("FILTER EXPRESSION :%s\n",filter_exp);
        handle=pcap_open_live(dev,SNAP_LEN,1,1000,errbuf);
        if(handle==NULL)
        {
            printf(" Couldn't Open Device %s:%s",dev,errbuf);
            exit(1);
        }
        if(pcap_datalink(handle)!=DLT_EN10MB)
        {
            printf(" %s is not ethernet\n",dev);
            exit(1);
        }
        if(pcap_compile(handle,&fp,filter_exp,0,net)==-1)
        {
            printf(" Couldn't Parse Filter\n");
            exit(1);
        }
        if(pcap_setfilter(handle,&fp)==1)
        {
            printf("Couldn't Pass Filter\n");
            exit(1);
        }
        pcap_loop(handle,num_packets,got_packet,NULL);
        //printf("ww");
        pcap_freecode(&fp);
        pcap_close(handle);
        printf("Capture Complete\n");
    }
    return 0;
}
