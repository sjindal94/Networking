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
  //  #define IP_OFFMASK 0x1ff //mask forfragmentation bits
    u_char ip_ttl; //time to live
    u_char ip_p ;//protocol
    u_short ip_sum;//checksum
    struct in_addr ip_src,ip_dst;//source and destination ip addresses
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)  (((ip)->ip_vhl) >> 4)
typedef u_int tcp_seq;
