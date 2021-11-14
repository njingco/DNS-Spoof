#ifndef DNS_H
#define DNS_H

#include "utils.h"
#include "config.h"
#include "arp.h"

#define SNAP_LEN 1518

struct dns_header
{
    uint16_t xid;     /* Randomly chosen identifier */
    uint16_t flags;   /* Bit-mask to indicate request/response */
    uint16_t qdcount; /* Number of questions */
    uint16_t ancount; /* Number of answers */
    uint16_t nscount; /* Number of authority records */
};

struct dns_q
{
    char *name;        /* Pointer to the domain name in memory */
    uint16_t dnstype;  /* The QTYPE (1 = A) */
    uint16_t dnsclass; /* The QCLASS (1 = IN) */
};

struct udp_hdr
{
    struct iphdr ip;
    struct udphdr udp;
    char buffer[10000];
};

/*
 * Structure of an internet header, stripped of all options.
 *
 * This is taken directly from the tcpdump source
 *
 * We declare ip_len and ip_off to be short, rather than u_short
 * pragmatically since otherwise unsigned comparisons can result
 * against negative integers quite easily, and fail in subtle ways.
 */
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

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp
{
    u_short th_sport; /* source port */
    u_short th_dport; /* destination port */
    tcp_seq th_seq;   /* sequence number */
    tcp_seq th_ack;   /* acknowledgement number */
    u_char th_offx2;  /* data offset, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
    u_short th_win; /* window */
    u_short th_sum; /* checksum */
    u_short th_urp; /* urgent pointer */
};

void dns_sniff(struct config *c);
void pkt_callback(u_char *ptr_null, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void handle_IP(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void handle_TCP(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void handle_UDP(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);

u_int16_t handle_ethernet(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void print_payload(const u_char *payload, int len);
void print_hex_ascii_line(const u_char *payload, int len, int offset);

#endif
