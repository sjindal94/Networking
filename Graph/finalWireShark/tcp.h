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
#include<netinet/ip_icmp.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "ethernet.h"
#include "print.h"
#include "udp.h"
struct sniff_tcp
{
    u_short th_sport;//source port number
    u_short th_dport;//destination port number
    tcp_seq th_seq;//sequence number
    tcp_seq th_ack;//acknowledgement number
    u_char th_offx2;//data offset
    #define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;//tcp flags
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x03
    #define TH_PUSH 0x04
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x30
    #define TH_CWR 0x40
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_PUSH|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    ushort th_win;//window size
    ushort th_sum;//checksum
    ushort th_urp;//urgent pointer
};
void print_tcp(const u_char *packet,int size_ip,const struct sniff_ip *ip)
{
        const struct sniff_tcp *tcp;
        tcp=(struct sniff_tcp*)(packet+SIZE_ETHERNET+size_ip);
        int size_tcp=TH_OFF(tcp)*4;
        if(size_tcp<20)
        {
            printf(" *INVALID TCP HEADER LENGTH :%d bytes\n",size_tcp);
            return;
        }
        printf("   Src Port : %d\n",ntohs(tcp->th_sport));
        printf("   Dst Port : %d\n",ntohs(tcp->th_dport));
        const char *payload=(u_char *)(packet+SIZE_ETHERNET+size_ip+size_tcp);
        int size_payload=ntohs(ip->ip_len)-(size_ip+size_tcp);
        if(size_payload>0)
        {
            printf(" Payload Size :%d bytes\n",size_payload);
            print_payload(payload,size_payload);
        }
}
