#include "config.h"

void getConfig(struct config *c)
{
    FILE *file = fopen("spoof.conf", "r");

    if (file == NULL)
    {
        perror("Can't open file\n");
        exit(1);
    }

    readConfigIP(file, c->routerIP);
    readConfigMac(file, c->routerMac);

    // Attacker
    readConfigIP(file, c->attackerIP);
    readConfigMac(file, c->attackerMac);
    readConfigInterface(file, c->interfaceName);

    // Victim
    readConfigIP(file, c->victimIP);
    readConfigMac(file, c->victimMac);

    // readConfigIP(file, c->spoofIP);

    // Print values
    printf("Router IP: ");
    printIP(c->routerIP);
    printf("Router MAC: ");
    printMAC(c->routerMac);

    printf("\nAttacker IP: ");
    printIP(c->attackerIP);
    printf("Attacker MAC: ");
    printMAC(c->attackerMac);
    printf("Attacker Interface: %s\n\n", c->interfaceName);

    printf("Victim IP: ");
    printIP(c->victimIP);
    printf("Victim MAC: ");
    printMAC(c->victimMac);
    // printf("Spoof IP: ");
    // printIP(c->spoofIP);
}

void readConfigIP(FILE *file, unsigned char *c)
{
    char line[31];
    fgets(line, sizeof(line), file);
    strtok(line, "=");
    sscanf(strtok(NULL, "\n"), "%hhd.%hhd.%hhd.%hhd", &c[0], &c[1], &c[2], &c[3]);
}

void readConfigMac(FILE *file, unsigned char *c)
{
    char line[31];
    fgets(line, sizeof(line), file);
    strtok(line, "=");

    sscanf(strtok(NULL, "\n"), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &c[0], &c[1], &c[2], &c[3], &c[4], &c[5]);
}

void readConfigInterface(FILE *file, char *c)
{
    char line[31];
    fgets(line, sizeof(line), file);
    strtok(line, "=");
    memset(c, 0, HARDWARE_LEN + 1);
    memcpy(c, strtok(NULL, "\n"), HARDWARE_LEN);
}

char *getIPString(unsigned char ipInt)
{
    struct in_addr ip_addr;
    ip_addr.s_addr = ipInt;
    return inet_ntoa(ip_addr);
}

void printMAC(unsigned char *c)
{
    for (int i = 0; i < MAC_LEN; i++)
    {
        printf("%x", c[i]);
        if (i < (MAC_LEN - 1))
            printf(":");
    }
    printf("\n");
}

void printIP(unsigned char *c)
{
    for (int i = 0; i < IP_LEN; i++)
    {
        printf("%d", c[i]);
        if (i < (IP_LEN - 1))
            printf(".");
    }
    printf("\n");
}