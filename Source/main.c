#include "spoof.h"
#include "arp.h"

void usage()
{
    fprintf(stdout, "Enter the source url and destination url\n\n");
    fprintf(stdout, "Example:\n");
    fprintf(stdout, "./main google.ca 192.168.1.74 \n");
}

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        usage();
        exit(0);
    }

    // check valid url

    // create thread

    // if 1 start arp poison

    return 0;
}