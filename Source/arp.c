#include "arp.h"

void arp_poison()
{
    while (1)
    {
        }
}

struct arp_header *build_arp(const uint16_t opcode,
                             const uint8_t *my_mac_addr,
                             const char *spoofed_ip_src,
                             const uint8_t *dest_mac_addr,
                             const char *dest_ip)
{
    struct arp_header *arp = malloc(sizeof(arp_header));

    arp->hardware_type = htons(1);
    arp->protocol_type = htons(ETH_P_IP);
    arp->hardware_len = HARDWARE_LEN;
    arp->protocol_len = IP_LEN;
    arp->opcode = htons(opcode);

    memcpy(&arp->sender_mac, my_mac_addr, sizeof(uint8_t) * HARDWARE_LEN);
    memcpy(&arp->target_mac, dest_mac_addr, sizeof(uint8_t) * HARDWARE_LEN);
    if (inet_pton(AF_INET, spoofed_ip_src, arp->sender_ip) != 1 || inet_pton(AF_INET, dest_ip, arp->target_ip) != 1)
        return (NULL);

    return arp;
}