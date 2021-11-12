#include "spoof.h"
#include "arp.h"
#include "config.h"

int main()
{
    pthread_t thread_id;

    // if 1 start arp poison
    struct config *conf = (struct config *)malloc(sizeof(struct config));
    getConfig(conf);

        // Create threads
    pthread_create(&thread_id, NULL, (void *)arp_poison, (void *)conf);

    // // Do other things here

    // // Finish thread
    pthread_join(thread_id, NULL);

    return 0;
}