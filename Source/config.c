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

    readConfigIP(file, c->spoofIP);
    readTargetURL(file, c->targetURL);
    c->targetLen = strlen(c->targetURL) + 1;

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

    printf("Spoof IP: ");
    printIP(c->spoofIP);
    printf("Target URL: ");
    fprintf(stdout, "%s %d\n", c->targetURL, c->targetLen);
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

void readTargetURL(FILE *file, char *c)
{
    char line[31];
    char temp[TARGET_LEN];
    fgets(line, sizeof(line), file);
    strtok(line, "=");

    memset(temp, 0, TARGET_LEN);
    memcpy(temp, strtok(NULL, "\n"), TARGET_LEN);

    memset(c, 0, TARGET_LEN);

    format_url(temp, c);
}

void format_url(char *temp, char *c)
{
    // char *www = strtok(temp, ".");
    // int wwwLen = 0;
    char *site = strtok(temp, ".");
    int siteLen = 0;
    char *end = strtok(NULL, "\n");
    int endLen = 0;

    siteLen = strlen(site);
    endLen = strlen(end);
    // wwwLen = strlen(www);

    // snprintf(c, TARGET_LEN + 2, "%d%s%d%s%d%s", wwwLen, www, siteLen, site, endLen, end);
    snprintf(c, TARGET_LEN + 2, "%d%s%d%s", siteLen, site, endLen, end);
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

char *getIPString(unsigned char *c)
{
    char *temp = (char *)malloc(14);
    memset(temp, 0, 14);
    snprintf(temp, 14, "%d.%d.%d.%d", c[0], c[1], c[2], c[3]);
    return temp;
}
