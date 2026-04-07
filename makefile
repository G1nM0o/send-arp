CC=gcc
LDLIBS=-lpcap

all: send-arp


main.o: main.c

send-arp: main.o
	$(CC) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp *.o
