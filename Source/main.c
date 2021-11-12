
/**
 * Compile:
 * make
 * 
 * Usage:
 * echo 1 >> /proc/sys/net/ipv4/ip_forward
 * ./main
 */

#include "spoof.h"
#include "arp.h"
#include "config.h"

int main()
{
    pthread_t thread_id;

    struct config *conf = (struct config *)malloc(sizeof(struct config));
    getConfig(conf);

    // Create threads
    pthread_create(&thread_id, NULL, (void *)arp_poison, (void *)conf);

    // // Do other things here

    // // Finish thread
    pthread_join(thread_id, NULL);

    return 0;
}