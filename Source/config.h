#ifndef CONFIG_H
#define CONFIG_H

#include "utils.h"

struct config
{
    int routerIP;
    int routerMac[MAC_LEN];

    int attackerIP;
    int attackerMac[MAC_LEN];
    char interfaceName[HARDWARE_LEN];

    int victimIP;
    int spoofIP;
};

void getConfig(struct config *);
void readConfigIP(FILE *file, int *);
void readConfigMac(FILE *file, int *c);
void readConfigInterface(FILE *file, char *c);
char *getIPString(int ipInt);
void printMAC(int *c);

#endif