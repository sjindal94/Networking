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
#include <math.h>
#include "soclibc.c"
#include "tcp.h"
#include <time.h>
Socket_record *soc;
int soc_num;
clock_t begin, end;
static int tcp_num,ip_num,udp_num,icp_num,l;
void got_packet(u_char *args,const struct pcap_pkthdr *header,const u_char *packet)
{
    static int count=1;//packet counter
    const struct sniff_ethernet *ethernet;
    const struct sniff_ip *ip;
    const char *payload;
    int size_ip;
    char message [8192];
    printf("\nPacket Number %d\n",count);
    count++;
    ethernet=(struct sniff_ethernet*)packet;
    ip=(struct sniff_ip*)(packet+SIZE_ETHERNET);
    size_ip=IP_HL(ip)*4;
    if(size_ip<20)
    {
        printf(" *Invalid IP header length : %d bytes\n",size_ip);
        return;
    }
    float seconds_since_start;
    switch(ip->ip_p)
    {
        case IPPROTO_UDP:
            printf("   PROTOCOL : UDP\n");
            udp_num++;
            l++;
            end=clock();
            seconds_since_start =(float)(end-begin) ;
            sprintf( message, "%f %d\n",seconds_since_start/100, udp_num );
            Send_Socket( soc, message );
            
            print_udp(packet,size_ip,ip);
            break;
        case IPPROTO_ICMP:
            printf("   PROTOCOL : ICMP\n");
            icp_num++;
            l++;
            end=clock();
            seconds_since_start =(float)(end-begin) ;
            sprintf( message, "%f %d\n",seconds_since_start/100, icp_num );
            Send_Socket( soc, message );
            struct icmphdr *icphdr=(struct icmphdr*)(packet+SIZE_ETHERNET+size_ip);
            payload=(u_char*)(packet+SIZE_ETHERNET+size_ip);
            int size_payload=ntohs(ip->ip_len)-(size_ip);
            printf(" Payload Size :%d\n",size_payload);
        case IPPROTO_IP:
            printf("   PROTOCOL : IP\n");
            ip_num++;
            l++;
            end=clock();
            seconds_since_start =(float)(end-begin) ;
            sprintf( message, "%f %d\n",seconds_since_start/100 , ip_num );
            Send_Socket( soc, message );
            payload=(u_char *)(packet +SIZE_ETHERNET+size_ip);
            size_payload=ntohs((ip->ip_len))-(size_ip);
            if(size_payload>0)
            {
                printf(" Payload Size :%d\n",size_payload);
                print_payload(payload,size_payload);
            }
            return;
        case IPPROTO_TCP:
            printf("   PROTOCOL : TCP\n");
            tcp_num++;
            l++;
            end=clock();
            seconds_since_start =(float)(end-begin) ;
            sprintf( message, "%f %d\n",seconds_since_start/100, tcp_num );
            Send_Socket( soc, message );
            //Send_Socket( soc, "PAN_RIGHT\n" );
            print_tcp(packet,size_ip,ip);
            break;
        default:
            printf("   PROTOCOL : unknown\n");
            return;
    }
}
int main(int argc,char *argv[]){
	soc_num=atoi(argv[1]);
	soc = Setup_Client_Socket( "", 8000);//for xgraph
    {
        begin=clock();
        char *dev="wlp6s0";//"wlan0";
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle;
        char filter_exp[]="icmp";
        struct bpf_program fp;
        bpf_u_int32 mask;
        bpf_u_int32 net;
        int num_packets=1000;
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
        pcap_freecode(&fp);
        pcap_close(handle);
        printf("Capture Complete\n");
        Close_Socket( soc );
    }
}
