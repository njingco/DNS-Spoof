#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <pthread.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <libnet.h>
#include <linux/ip.h>
#include <sys/ioctl.h>

#define MAC_LEN 6
#define IP_LEN 4
#define HARDWARE_LEN 6
#define ETH_HEADER_LENGTH 14
#define ARP_HEADER_LENGTH 28
#define BROADCAST_ADDR \
    (uint8_t[6]) { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }

#endif
