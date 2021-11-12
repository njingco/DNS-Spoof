
CC=gcc -Wall -g
CLIB = -lpthread -lrt

all: main 

main: main.o spoof.o arp.o config.o
	$(CC) -o main main.o spoof.o arp.o config.o $(CLIB)

clean:
	rm -f *.o main spoof arp config
	

main.o:
	$(CC) -c main.c 

spoof.o:
	$(CC) -c spoof.c 

arp.o:
	$(CC) -c arp.c 

config.o:
	$(CC) -c config.c 