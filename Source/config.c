/*-----------------------------------------------------------------------------
 * SOURCE FILE:     config
 *
 * PROGRAM:         main
 *
 * FUNCTIONS:       void getConfig(struct config *);
 *                  void readConfigIP(FILE *file, unsigned char *);
 *                  void readConfigMac(FILE *file, unsigned char *c);
 *                  void readConfigInterface(FILE *file, char *c);
 *                  void readTargetURL(FILE *file, char *c);
 *                  void format_url(char *temp, char *c);
 *                  char *getIPString(unsigned char *c);
 *                  void printIP(unsigned char *c);
 *                  void printMAC(unsigned char *c);
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
 * This file contains the handles the config file and fills the config 
 * structure
 * --------------------------------------------------------------------------*/
#include "config.h"

/*--------------------------------------------------------------------------
 * FUNCTION:        getConfig
 *
 * DATE:            November 10, 2021
 *
 * REVISIONS:       N/A
 *
 * DESIGNER:        Nicole Jingco
 *
 * PROGRAMMER:      Nicole Jingco
 *
 * INTERFACE:       struct config *c
 *
 * RETURNS:         void
 *
 * NOTES:
 * This function fills the config structure with the data from the 
 * spoof.config file
 * -----------------------------------------------------------------------*/
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

/*--------------------------------------------------------------------------
 * FUNCTION:        readConfigIP
 *
 * DATE:            November 10, 2021
 *
 * REVISIONS:       N/A
 *
 * DESIGNER:        Nicole Jingco
 *
 * PROGRAMMER:      Nicole Jingco
 *
 * INTERFACE:       FILE *file - file pointer to config file
 *                  unsigned char *c - pointer to IP
 *
 * RETURNS:         void
 *
 * NOTES:
 * This function reads the an IP from the config file
 * -----------------------------------------------------------------------*/
void readConfigIP(FILE *file, unsigned char *c)
{
    char line[31];
    fgets(line, sizeof(line), file);
    strtok(line, "=");
    sscanf(strtok(NULL, "\n"), "%hhd.%hhd.%hhd.%hhd", &c[0], &c[1], &c[2], &c[3]);
}

/*--------------------------------------------------------------------------
 * FUNCTION:        readConfigMac
 *
 * DATE:            November 10, 2021
 *
 * REVISIONS:       N/A
 *
 * DESIGNER:        Nicole Jingco
 *
 * PROGRAMMER:      Nicole Jingco
 *
 * INTERFACE:       FILE *file - file pointer to config file
 *                  unsigned char *c - pointer to MAC 
 *
 * RETURNS:         void
 *
 * NOTES:
 * This function reads the an MAC address from the config file
 * -----------------------------------------------------------------------*/
void readConfigMac(FILE *file, unsigned char *c)
{
    char line[31];
    fgets(line, sizeof(line), file);
    strtok(line, "=");

    sscanf(strtok(NULL, "\n"), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &c[0], &c[1], &c[2], &c[3], &c[4], &c[5]);
}

/*--------------------------------------------------------------------------
 * FUNCTION:        readConfigInterface
 *
 * DATE:            November 10, 2021
 *
 * REVISIONS:       N/A
 *
 * DESIGNER:        Nicole Jingco
 *
 * PROGRAMMER:      Nicole Jingco
 *
 * INTERFACE:       FILE *file - file pointer to config file
 *                  unsigned char *c - pointer to Interface 
 *
 * RETURNS:         void
 *
 * NOTES:
 * This function reads the an interdace from the config file
 * -----------------------------------------------------------------------*/
void readConfigInterface(FILE *file, char *c)
{
    char line[31];
    fgets(line, sizeof(line), file);
    strtok(line, "=");
    memset(c, 0, HARDWARE_LEN + 1);
    memcpy(c, strtok(NULL, "\n"), HARDWARE_LEN);
}

/*--------------------------------------------------------------------------
 * FUNCTION:        readTargetURL
 *
 * DATE:            November 10, 2021
 *
 * REVISIONS:       N/A
 *
 * DESIGNER:        Nicole Jingco
 *
 * PROGRAMMER:      Nicole Jingco
 *
 * INTERFACE:       FILE *file - file pointer to config file
 *                  unsigned char *c - pointer to URL 
 *
 * RETURNS:         void
 *
 * NOTES:
 * This function reads the a url from the config file
 * -----------------------------------------------------------------------*/
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

/*--------------------------------------------------------------------------
 * FUNCTION:        format_url
 *
 * DATE:            November 10, 2021
 *
 * REVISIONS:       N/A
 *
 * DESIGNER:        Nicole Jingco
 *
 * PROGRAMMER:      Nicole Jingco
 *
 * INTERFACE:       char *temp - url string
 *                  char *c - pointer to the formated url
 *
 * RETURNS:         void
 *
 * NOTES:
 * This function formats a string to a dns url
 * ex
 * facebook.com -> 8facebook3com
 * -----------------------------------------------------------------------*/
void format_url(char *temp, char *c)
{
    char *site = strtok(temp, ".");
    int siteLen = 0;
    char *end = strtok(NULL, "\n");
    int endLen = 0;

    siteLen = strlen(site);
    endLen = strlen(end);

    snprintf(c, TARGET_LEN + 2, "%d%s%d%s", siteLen, site, endLen, end);
}

/*--------------------------------------------------------------------------
 * FUNCTION:        printMAC
 *
 * DATE:            November 10, 2021
 *
 * REVISIONS:       N/A
 *
 * DESIGNER:        Nicole Jingco
 *
 * PROGRAMMER:      Nicole Jingco
 *
 * INTERFACE:       unsigned char *c
 *
 * RETURNS:         void
 *
 * NOTES:
 * This function is to print the MAC adsress in proper format
 * -----------------------------------------------------------------------*/
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

/*--------------------------------------------------------------------------
 * FUNCTION:        printIP
 *
 * DATE:            November 10, 2021
 *
 * REVISIONS:       N/A
 *
 * DESIGNER:        Nicole Jingco
 *
 * PROGRAMMER:      Nicole Jingco
 *
 * INTERFACE:       
 *
 * RETURNS:         void
 *
 * NOTES:
 * This function is to print the IP in proper format
 * -----------------------------------------------------------------------*/
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

/*--------------------------------------------------------------------------
 * FUNCTION:        getIPString
 *
 * DATE:            November 10, 2021
 *
 * REVISIONS:       N/A
 *
 * DESIGNER:        Nicole Jingco
 *
 * PROGRAMMER:      Nicole Jingco
 *
 * INTERFACE:       unsigned char *c - ip 
 *
 * RETURNS:         void
 *
 * NOTES:
 * This function is to return the IP in string format
 * -----------------------------------------------------------------------*/
char *getIPString(unsigned char *c)
{
    char *temp = (char *)malloc(14);
    memset(temp, 0, 14);
    snprintf(temp, 14, "%d.%d.%d.%d", c[0], c[1], c[2], c[3]);
    return temp;
}
