#ifndef DNS_H
#define DNS_H

#include "utils.h"
#include "config.h"
#include "arp.h"
#include "headers.h"

#define SNAP_LEN 1518

struct dns_header
{
    uint16_t xid;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

struct dns_answer
{
    uint16_t name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t len;
    uint32_t addr;
};

struct dns_query
{
    char *name;
    char type[2];
    char class[2];
};

void dns_sniff(struct config *c);
void handle_packet(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void handle_IP(const struct pcap_pkthdr *pkthdr, const u_char *packet, struct my_ip *spoof_ip);
void handle_UDP(const u_char *packet, struct udp_header *spoof_udp);
void handle_DNS(struct config *c, const u_char *packet, u_char *dns_spoof);
unsigned short in_cksum(unsigned short *ptr, int nbytes);
void send_dns_answer(char *ip, u_short port, u_char *packet, int packlen);

#endif
