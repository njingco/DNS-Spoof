#include "config.h"

void getConfig(struct config *c)
{
    FILE *file = fopen("spoof.conf", "r");

    if (file == NULL)
    {
        perror("Can't open file\n");
        exit(1);
    }

    // char *token;

    readConfigIP(file, &c->routerIP);
    readConfigMac(file, c->routerMac);

    // Attacker
    readConfigIP(file, &c->attackerIP);
    readConfigMac(file, c->attackerMac);
    readConfigInterface(file, c->interfaceName);

    // Victim
    readConfigIP(file, &c->victimIP);
    readConfigIP(file, &c->spoofIP);

    // Print values
    printf("Router IP: %s\n", getIPString(c->routerIP));
    printf("Router int IP: %d\n", c->routerIP);
    printf("Router MAC: ");
    printMAC(c->routerMac);

    printf("\nAttacker IP: %s\n", getIPString(c->attackerIP));
    printf("Attacker int IP: %d\n", c->attackerIP);
    printf("Attacker MAC: ");
    printMAC(c->attackerMac);
    printf("Attacker Interface: %s\n\n", c->interfaceName);

    printf("Victim IP: %s\n", getIPString(c->victimIP));
    printf("Victim int IP: %d\n\n", c->victimIP);
    printf("Spoof IP: %s\n", getIPString(c->spoofIP));
    printf("Spoof int IP: %d\n\n", c->spoofIP);
}

void readConfigIP(FILE *file, int *c)
{
    char line[31];
    struct in_addr *addr = (struct in_addr *)malloc(sizeof(struct in_addr));

    fgets(line, sizeof(line), file);

    strtok(line, "=");

    inet_aton(strtok(NULL, "\n"), addr);
    memcpy(c, &addr->s_addr, IP_LEN);

    free(addr);
}

void readConfigMac(FILE *file, int *c)
{
    char line[31];
    fgets(line, sizeof(line), file);
    strtok(line, "=");

    sscanf(strtok(NULL, "\n"), "%x:%x:%x:%x:%x:%x", &c[0], &c[1], &c[2], &c[3], &c[4], &c[5]);
}

void readConfigInterface(FILE *file, char *c)
{
    char line[31];
    fgets(line, sizeof(line), file);
    strtok(line, "=");
    memcpy(c, strtok(NULL, "\n"), HARDWARE_LEN);
}

char *getIPString(int ipInt)
{
    struct in_addr ip_addr;
    ip_addr.s_addr = ipInt;
    return inet_ntoa(ip_addr);
}

void printMAC(int *c)
{
    for (int i = 0; i < MAC_LEN; i++)
    {
        printf("%x", c[i]);
        if (i < (MAC_LEN - 1))
            printf(":");
    }
    printf("\n");
}