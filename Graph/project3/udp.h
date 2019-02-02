#include "ip.h"
struct sniff_udp
{
    ushort uh_sport;
    ushort uh_dport;
    ushort uh_len;
    ushort uh_sum;
    #define UH_OFF(uh) ((uh)->uh_len  )
};
void print_udp(const u_char *packet,int size_ip,const struct sniff_ip *ip)
{
        const struct sniff_udp *udp=(struct sniff_udp*)(packet+SIZE_ETHERNET+size_ip);
        int size_udp=8;
        if(size_udp<8)
        {
            printf(" *INVALID UDP HEADER LENGTH : %d bytes\n",size_udp);
            return;
        }
        printf("   Src Port : %d\n",ntohs(udp->uh_sport));
        printf("   Dsr Port : %d\n",ntohs(udp->uh_dport));
        const u_char *payload=(u_char *)(packet+SIZE_ETHERNET+size_ip);
        int size_payload=ntohs(ip->ip_len)-(size_ip);
        if(size_payload>0)
        {
            printf(" Payload Size :%d bytes\n",size_payload);
            print_payload(payload,size_payload);
        }
}
