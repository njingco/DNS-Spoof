
CC=gcc -Wall -g
CLIB = -lpthread -lrt
CPCAP = -lpcap

all: main 

main: main.o arp.o config.o dns.o
	$(CC) -o main main.o  arp.o config.o dns.o $(CLIB) $(CPCAP)

clean:
	rm -f *.o main arp config dns
	

main.o:
	$(CC) -c main.c 

arp.o:
	$(CC) -c arp.c 

config.o:
	$(CC) -c config.c 

dns.o:
	$(CC) -c dns.c 