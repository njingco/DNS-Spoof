
CC=gcc -Wall -g
CLIB = -lpthread -lrt

all: main 

main: main.o spoof.o arp.o
	$(CC) -o main main.o spoof.o arp.o $(SSL)

clean:
	rm -f *.o main spoof arp 
	

main.o:
	$(CC) -c main.c 

spoof.o:
	$(CC) -c spoof.c 

arp.o:
	$(CC) -c arp.c 