/* Sabse phele ham ip packet ka aur tcp packet ka structure bnaenge taki use apne hisab se read kr sake*/
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
/* default snap length (maximum bytes per packet to capture) */
//SNAP_LEN wo length hoti hai jo program ek baar mein packet ki length ko capture krega
#define SNAP_LEN 1518
//ether net address hamesha 14 bytes ka hota hai jaisa ki joban ma'am ne btaya tha
/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14
/* Ethernet addresses are 6 bytes */
//Ye point thoda confusing hai may get clear during program
#define ETHER_ADDR_LEN	6
#include <time.h>
clock_t begin, end;
static long long tcp_num,ip_num,udp_num,icp_num;
FILE *tp,*up,*ipp,*icp;
struct sniff_ethernet
{
    u_char ether_dhost[ETHER_ADDR_LEN]; //destination ka ethernet address
    u_char ether_shost[ETHER_ADDR_LEN]; //source ka ethernet address
    u_short ether_type; //type of packet IP,ARP,TCP etc.
};
struct sniff_ip
{
    u_char ip_vhl; //ip V4 ki header length
    u_char ip_tos; //type of service
    u_short ip_len; //total length
    u_short ip_id; //identification field
    u_short ip_off; //fragmentation offset
    #define IP_RF 0x8000 //reserved flag
    #define IP_DF 0x4000 //donot fragment flag
    #define IP_MF 0x2000 //more fragment flag
    #define IP_OFFMASK 0x1ff //mask forfragmentation bits
    u_char ip_ttl; //time to live
    u_char ip_p ;//protocol
    u_short ip_sum;//checksum
    struct in_addr ip_src,ip_dst;//source and destination ip addresses
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)  (((ip)->ip_vhl) >> 4)
typedef u_int tcp_seq;

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
struct sniff_udp
{
    ushort uh_sport;
    ushort uh_dport;
    ushort uh_len;
    ushort uh_sum;
    #define UH_OFF(uh) (((uh)->uh_len & 0xf0) >> 4 )
};
void print_hex_ascii_line(const u_char* payload,int len,int offset)
{
    int i;
    int gap;
    const u_char *ch;
    printf("%05d   ",offset);
    ch=payload;
    for(i=0;i<len;i++)
    {
        printf("%02x ",*ch);//ye payload data ki hexa decimal value print krega
        ch++;
        if(i==7)
        printf(" "); //ye thoda output sahi aaye isliye
    }
    if(len < 8)
    {
        printf(" ");
    }
    //ye hexa gap jo bytes rhe gyi hain unhe fill krne ke liye
    if(len < 16)
    {
        gap=len-16;
        for(i=0;i<gap;i++)
        printf(" ");
    }
    printf(" ");
    ch=payload;//ascii format mein print krne ke liye yadi use print kr sakte hain toh
    for(i=0;i<len;i++)
    {
        if(isprint(*ch))
        printf("%c",*ch);
        else
        printf(".");
        ch++;
    }
    printf("\n");
    return;
}
void print_payload(const u_char *payload,int len)
{
    int len_rem=len;
    int line_width =16;
    int line_len;
    int offset=0;
    const u_char *ch=payload;
    if(len<=0)
    return;
    if(len<=16)
    {
        print_hex_ascii_line(payload,len,offset);
        return;
    }
    for(;;)
    {
        line_len=line_width%len_rem;
        print_hex_ascii_line(ch,line_len,offset);
        len_rem=len_rem-line_len;
        ch=ch+line_len;
        if(len_rem<=line_width)
        {
            print_hex_ascii_line(ch,len_rem,offset);
            break;
        }
    }
    return ;
}
void got_packet(u_char *args,const struct pcap_pkthdr *header,const u_char *packet)
{
    static int count=1;//packet counter
    const struct sniff_ethernet *ethernet;
    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;
    const struct sniff_udp *udp;
    const char *payload;
    int size_ip;
    int size_tcp;
    int size_udp;
    int size_payload;
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
    printf("       FROM :%s\n",inet_ntoa(ip->ip_src));
    printf("         TO :%s\n",inet_ntoa(ip->ip_dst));
    float seconds_since_start;
    int f=0;
    switch(ip->ip_p)
    {
        case IPPROTO_UDP:
            printf("   PROTOCOL : UDP\n");
            udp_num++;
            end=clock();
            seconds_since_start =(float)(end-begin) ;
            fprintf(up,"%f %lld\n",seconds_since_start,udp_num);
            f=1;
            break;
        case IPPROTO_ICMP:
            printf("   PROTOCOL : ICMP\n");
            f=4;
            icp_num++;
            end=clock();
            seconds_since_start =(float)(end-begin) ;
            fprintf(icp,"%f %lld\n",seconds_since_start,icp_num);
            break;
        case IPPROTO_IP:
            printf("   PROTOCOL : IP\n");
            ip_num++;
            end=clock();
            seconds_since_start =(float)(end-begin) ;
            fprintf(ipp,"%f %lld\n",seconds_since_start,ip_num);
            f=3;
            break;
        case IPPROTO_TCP:
            printf("   PROTOCOL : TCP\n");
            tcp_num++;
            end=clock();
            seconds_since_start =(float)(end-begin) ;
            fprintf(tp,"%f %lld\n",seconds_since_start,tcp_num);
            f=2;
            break;
        default:
            printf("   PROTOCOL : unknown\n");
            return;
    }
    if(f==2)
    {
        tcp=(struct sniff_tcp*)(packet+SIZE_ETHERNET+size_ip);
        size_tcp=TH_OFF(tcp)*4;
        if(size_tcp<20)
        {
            printf(" *INVALID TCP HEADER LENGTH :%d bytes\n",size_tcp);
            return;
        }
        printf("   Src Port : %d\n",ntohs(tcp->th_sport));
        printf("   Dst Port : %d\n",ntohs(tcp->th_dport));
        payload=(u_char *)(packet+SIZE_ETHERNET+size_ip+size_tcp);
        size_payload=ntohs(ip->ip_len)-(size_ip+size_tcp);
        if(size_payload>0)
        {
            printf(" Payload Size :%d bytes\n",size_payload);
            print_payload(payload,size_payload);
        }
        return;
    }
    else if(f==1)
    {
        udp=(struct sniff_udp*)(packet+SIZE_ETHERNET+size_ip);
        size_udp=UH_OFF(udp)*4;
        if(size_tcp<20)
        {
            printf(" *INVALID UDP HEADER LENGTH : %d bytes\n",size_udp);
            return;
        }
        printf("   Src Port : %d\n",ntohs(udp->uh_sport));
        printf("   Dsr Port : %d\n",ntohs(udp->uh_dport));
        payload=(u_char *)(packet+SIZE_ETHERNET+size_ip+size_udp);
        size_payload=ntohs(ip->ip_len)-(size_ip+size_tcp);
        if(size_payload>0)
        {
            printf(" Payload Size :%d bytes\n",size_payload);
            print_payload(payload,size_payload);
        }
        return;
    }
    else if(f==3)
    {
        payload=(u_char *)(packet +SIZE_ETHERNET+size_ip);
        size_payload=ntohs((ip->ip_len))-(size_ip);
        if(size_payload>0)
        {
            printf(" Payload Size :%d\n",size_payload);
            print_payload(payload,size_payload);
        }
        return;
    }
    else if(f==4)
    {
        struct icmphdr *icphdr=(struct icmphdr*)(packet+SIZE_ETHERNET+size_ip);
        payload=(u_char*)(packet+SIZE_ETHERNET+size_ip);
        size_payload=ntohs(ip->ip_len)-(size_ip);
        printf(" Payload Size :%d\n",size_payload);
    }
}
int main(int argc,char *argv[])
{
   // while(1)
    {
        begin=clock();
        tp=fopen("tcp.txt","w");
        up=fopen("udp.txt","w");
        ipp=fopen("ip.txt","w");
        icp=fopen("icmp.txt","w");
        char *dev=NULL;
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle;
        char filter_exp[]="ip";
        struct bpf_program fp;
        bpf_u_int32 mask;
        bpf_u_int32 net;
        int num_packets=100;
        if(argc==2)
        {
            dev=argv[1];
        }
        else
        {
            dev=pcap_lookupdev(errbuf);
            if(dev==NULL)
            {
                printf(" Couldn't find Device :%s",errbuf);
                exit(1);
            }
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
        pcap_freecode(&fp);
        pcap_close(handle);
        printf("Capture Complete\n");
        fclose(tp);
        fclose(ipp);
        fclose(up);
        system("bash xgraph tcp.txt ip.txt udp.txt");
    }
}
