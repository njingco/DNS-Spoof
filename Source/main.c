/*-----------------------------------------------------------------------------
 * SOURCE FILE:     main
 *
 * PROGRAM:         main
 *
 * FUNCTIONS:       int main()
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
 * This file contains the 
 * 
 * Compile:
 * make
 * 
 * Before running:
 * echo 1 >> /proc/sys/net/ipv4/ip_forward
 * 
 * Run:
 * ./main
 * --------------------------------------------------------------------------*/
#include "arp.h"
#include "dns.h"
#include "config.h"

/*--------------------------------------------------------------------------
 * FUNCTION:        main
 *
 * DATE:            November 10, 2021
 *
 * REVISIONS:       N/A
 *
 * DESIGNER:        Nicole Jingco
 *
 * PROGRAMMER:      Nicole Jingco
 *
 * INTERFACE:       N/A
 *
 * RETURNS:         void
 *
 * NOTES:
 * This function is the main function that runs the program
 * -----------------------------------------------------------------------*/
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