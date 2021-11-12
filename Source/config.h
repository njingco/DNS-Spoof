#ifndef CONFIG_H
#define CONFIG_H

#include "utils.h"

struct config
{
    // int routerIP;
    // int routerMac[MAC_LEN];

    // int attackerIP;
    // int attackerMac[MAC_LEN];
    // char interfaceName[HARDWARE_LEN];

    // int victimIP;
    // int spoofIP;

    unsigned char routerIP[IP_LEN];
    unsigned char routerMac[MAC_LEN];

    unsigned char attackerIP[IP_LEN];
    unsigned char attackerMac[MAC_LEN];
    char interfaceName[HARDWARE_LEN + 1];

    unsigned char victimIP[IP_LEN];
    unsigned char victimMac[MAC_LEN];
    unsigned char spoofIP[IP_LEN];
};

void getConfig(struct config *);
void readConfigIP(FILE *file, unsigned char *);
void readConfigMac(FILE *file, unsigned char *c);
void readConfigInterface(FILE *file, char *c);
char *getIPString(unsigned char ipInt);

void printIP(unsigned char *c);
void printMAC(unsigned char *c);

#endif