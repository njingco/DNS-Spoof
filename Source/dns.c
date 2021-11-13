#include "dns.h"

void dns_sniff(struct config *c)
{
    // char *nic_dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *nic_descr;
    struct bpf_program fp; // holds compiled program
    bpf_u_int32 maskp;     // subnet mask
    bpf_u_int32 netp;      // ip
    char filter_exp[] = "udp and dst port domain";

    // // find the first NIC that is up and sniff packets from it
    // nic_dev = pcap_findalldevs(&interfaces, errbuf);
    // if (nic_dev == NULL)
    // {
    //     printf("%s\n", errbuf);
    //     exit(1);
    // }

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

    // Start the capture session
    pcap_loop(nic_descr, 0, pkt_callback, (u_char *)c);

    fprintf(stdout, "\nCapture Session Done\n");
}

void pkt_callback(u_char *ptr_null, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    static int count = 1;
    fprintf(stdout, "%d.. ", count);
    fflush(stdout);
    count++;
}
