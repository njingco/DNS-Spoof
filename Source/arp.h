#ifndef ARP_H
#define ARP_H

#include "utils.h"
#include "config.h"

struct arp_header
{
    unsigned short hardware_type;
    unsigned short protocol_type;
    unsigned char hardware_len;
    unsigned char protocol_len;
    unsigned short opcode;
    unsigned char sender_mac[MAC_LEN];
    unsigned char sender_ip[IP_LEN];
    unsigned char target_mac[MAC_LEN];
    unsigned char target_ip[IP_LEN];
};

void arp_poison(struct config *c);

struct arp_header *build_arp(struct config *);

#endif
