CC=gcc
CFLAGS=-I/usr/include/SDL2
LDFLAGS=-lSDL2 -lSDL2_image -lcrypto

all: icsim controls

icsim: icsim.o lib.o secoc.o
	$(CC) -o icsim icsim.o lib.o secoc.o $(LDFLAGS)

controls: controls.o secoc.o
	$(CC) -o controls controls.o secoc.o $(LDFLAGS)

icsim.o: icsim.c
	$(CC) $(CFLAGS) -c icsim.c -o icsim.o

controls.o: controls.c
	$(CC) $(CFLAGS) -c controls.c -o controls.o

secoc.o: secoc.c secoc.h
	$(CC) -c secoc.c -o secoc.o

lib.o: lib.c lib.h
	$(CC) -c lib.c -o lib.o

clean:
	rm -f icsim controls icsim.o controls.o secoc.o lib.o
