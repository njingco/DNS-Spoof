#ifndef ARP_H
#define ARP_H

#include "utils.h"

#define MAC_LEN 17
#define IP_LEN 4
#define HARDWARE_LEN 6
#define ETH_HEADER_LENGTH 14
#define ARP_HEADER_LENGTH 28
#define BROADCAST_ADDR \
    (uint8_t[6]) { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }

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
} arp_header;

void arp_poison();
struct arp_header *build_arp();

#endif
