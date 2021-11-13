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

void dns_sniff(struct config *c);
void pkt_callback(u_char *ptr_null, const struct pcap_pkthdr *pkthdr, const u_char *packet);

#endif
