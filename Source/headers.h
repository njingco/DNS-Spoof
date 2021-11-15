#ifndef HEADERS_H
#define HEADERS_H

#include "utils.h"

struct eth_header
{
    unsigned char dst_mac[MAC_LEN];
    unsigned char src_mac[MAC_LEN];
    unsigned short eth_type;
};

struct pseudo_header
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short udp_length;
    struct udphdr udp;
};

struct my_ip
{
    u_int8_t ip_vhl; /* header length, version */
#define IP_V(ip) (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip) ((ip)->ip_vhl & 0x0f)
    u_int8_t ip_tos;               /* type of service */
    u_int16_t ip_len;              /* total length */
    u_int16_t ip_id;               /* identification */
    u_int16_t ip_off;              /* fragment offset field */
#define IP_DF 0x4000               /* dont fragment flag */
#define IP_MF 0x2000               /* more fragments flag */
#define IP_OFFMASK 0x1fff          /* mask for fragmenting bits */
    u_int8_t ip_ttl;               /* time to live */
    u_int8_t ip_p;                 /* protocol */
    u_int16_t ip_sum;              /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct udp_header
{
    u_short sport;
    u_short dport;
    u_short len;
    u_short sum;
};

#endif
