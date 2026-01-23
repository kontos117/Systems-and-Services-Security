CC=gcc
CFLAGS=-Wall -g
LIBS= -lsodium
LIBG= -lgmp -lcrypto


all: ecdh rsa

ecdh: ecdh.c
	$(CC) $(CFLAGS) -o ecdh ecdh.c $(LIBS)

rsa: rsa.c
	$(CC) $(CFLAGS) -o rsa rsa.c $(LIBG)


clean:
	rm -f ecdh rsa *.o