#include "dns.h"

void dns_sniff(struct config *c)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *nic_descr;
    struct bpf_program fp; // holds compiled program
    bpf_u_int32 maskp;     // subnet mask
    bpf_u_int32 netp;      // ip
    char filter_exp[] = "udp and dst port domain";

    // Use pcap to get the IP address and subnet mask of the device
    pcap_lookupnet(c->interfaceName, &netp, &maskp, errbuf);

    // open the device for packet capture & set the device in promiscuous mode
    nic_descr = pcap_open_live(c->interfaceName, BUFSIZ, 1, -1, errbuf);
    if (nic_descr == NULL)
    {
        printf("pcap_open_live(): %s\n", errbuf);
        exit(1);
    }

    // Compile the filter expression
    if (pcap_compile(nic_descr, &fp, filter_exp, 0, netp) == -1)
    {
        fprintf(stderr, "Error calling pcap_compile\n");
        exit(1);
    }

    // Load the filter into the capture device
    if (pcap_setfilter(nic_descr, &fp) == -1)
    {
        fprintf(stderr, "Error setting filter\n");
        exit(1);
    }

    fprintf(stdout, "\n------------------------------\n\n");
    // Start the capture session
    pcap_loop(nic_descr, 0, pkt_callback, NULL);

    fprintf(stdout, "\nCapture Session Done\n");
}

// Check all the headers in the Ethernet frame
void pkt_callback(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    u_int16_t type = handle_ethernet(args, pkthdr, packet);

    if (type == ETHERTYPE_IP) // handle the IP packet
    {
        handle_IP(args, pkthdr, packet);
    }
}

// This function will parse the IP header and print out selected fields of interest
void handle_IP(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    const struct my_ip *ip;
    u_int length = pkthdr->len;
    u_int hlen, off, version;
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
    hlen = IP_HL(ip);   // get header length
    version = IP_V(ip); // get the IP version number

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

    // Ensure that the first fragment is present
    off = ntohs(ip->ip_off);
    if ((off & 0x1fff) == 0) // i.e, no 1's in first 13 bits
    {                        // print SOURCE DESTINATION hlen version len offset */
        fprintf(stdout, "Source IP: %s \n", inet_ntoa(ip->ip_src));
        fprintf(stdout, "Destination IP: %s \n", inet_ntoa(ip->ip_dst));
        fprintf(stdout, "Header Len: %d \n", hlen);
        fprintf(stdout, "Version: %d \n", version);
        fprintf(stdout, "IP Len: %d \n", len);
        fprintf(stdout, "Offmask: %d \n", off);
    }

    switch (ip->ip_p)
    {
    case IPPROTO_TCP:
        fprintf(stdout, "   Protocol: TCP\n");
        handle_TCP(args, pkthdr, packet);
        break;
    case IPPROTO_UDP:
        fprintf(stdout, "   Protocol: UDP\n");
        handle_UDP(args, pkthdr, packet);
        break;
    default:
        fprintf(stdout, "   Protocol: unknown\n");
        break;
    }
}

// This function will parse the IP header and print out selected fields of interest
void handle_TCP(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    const struct sniff_tcp *tcp = 0; // The TCP header
    const struct my_ip *ip;          // The IP header
    const u_char *payload;           // Packet payload

    int size_ip;
    int size_tcp;
    int size_payload;

    fprintf(stdout, "\n");
    fprintf(stdout, "TCP packet\n");

    ip = (struct my_ip *)(packet + ETH_HEADER_LENGTH);
    size_ip = IP_HL(ip) * 4;

    // define/compute tcp header offset
    tcp = (struct sniff_tcp *)(packet + ETH_HEADER_LENGTH + size_ip);
    size_tcp = TH_OFF(tcp) * 4;

    if (size_tcp < 20)
    {
        fprintf(stdout, "   * Control Packet? length: %u bytes\n", size_tcp);
        exit(1);
    }

    fprintf(stdout, "   Src port: %d\n", ntohs(tcp->th_sport));
    fprintf(stdout, "   Dst port: %d\n", ntohs(tcp->th_dport));

    // define/compute tcp payload (segment) offset
    payload = (const u_char *)(packet + ETH_HEADER_LENGTH + size_ip + size_tcp);

    // compute tcp payload (segment) size
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

    // Print payload data, including binary translation

    if (size_payload > 0)
    {
        printf("   Payload (%d bytes):\n", size_payload);
        print_payload(payload, size_payload);
    }
}

void handle_UDP(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
}

u_int16_t handle_ethernet(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    u_int caplen = pkthdr->caplen;
    struct ether_header *eptr; /* net/ethernet.h */
    u_short ether_type;

    if (caplen < ETH_HEADER_LENGTH)
    {
        fprintf(stdout, "Packet length less than ethernet header length\n");
        return -1;
    }

    // Start with the Ethernet header...
    eptr = (struct ether_header *)packet;
    ether_type = ntohs(eptr->ether_type);

    // Print SOURCE DEST TYPE LENGTH fields
    fprintf(stdout, "\n");
    fprintf(stdout, "ETH: \n");
    fprintf(stdout, "Src MAC: %s \n", ether_ntoa((struct ether_addr *)eptr->ether_shost));
    fprintf(stdout, "Dst MAC: %s \n", ether_ntoa((struct ether_addr *)eptr->ether_dhost));

    return ether_type;
}

// This function will print payload data
void print_payload(const u_char *payload, int len)
{

    int len_rem = len;
    int line_width = 16; // number of bytes per line
    int line_len;
    int offset = 0; // offset counter
    const u_char *ch = payload;

    if (len <= 0)
        return;

    // does data fits on one line?
    if (len <= line_width)
    {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    // data spans multiple lines
    for (;;)
    {
        // determine the line length and print
        line_len = line_width % len_rem;
        print_hex_ascii_line(ch, line_len, offset);

        // Process the remainder of the line
        len_rem -= line_len;
        ch += line_len;
        offset += line_width;

        // Ensure we have line width chars or less
        if (len_rem <= line_width)
        {
            //print last line
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }
}

// Print data in hex & ASCII
void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

    int i;
    int gap;
    const u_char *ch;

    // the offset
    fprintf(stdout, "%05d   ", offset);

    // print in hex
    ch = payload;
    for (i = 0; i < len; i++)
    {
        fprintf(stdout, "%02x ", *ch);
        ch++;
        if (i == 7)
            fprintf(stdout, " ");
    }

    // print spaces to handle a line size of less than 8 bytes
    if (len < 8)
        fprintf(stdout, " ");

    // Pad the line with whitespace if necessary
    if (len < 16)
    {
        gap = 16 - len;
        for (i = 0; i < gap; i++)
            fprintf(stdout, "   ");
    }
    fprintf(stdout, "   ");

    // Print ASCII
    ch = payload;
    for (i = 0; i < len; i++)
    {
        if (isprint(*ch))
            fprintf(stdout, "%c", *ch);
        else
            fprintf(stdout, ".");
        ch++;
    }

    fprintf(stdout, "\n");
}
