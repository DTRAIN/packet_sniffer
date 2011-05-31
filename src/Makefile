CC=gcc
CFLAGS=-Wall -ggdb -lpcap
sniffer: main.o network.o errors.o
	$(CC) $(CFLAGS) main.o network.o errors.o -o sniffer

clean:
	rm -f *.o *.bak asgn2

main.o: main.c
	$(CC) $(CFLAGS) -O -c main.c

network.o: network.c
	$(CC) $(CFLAGS) -O -c network.c

errors.o: errors.c
	$(CC) $(CFLAGS) -O -c errors.c

