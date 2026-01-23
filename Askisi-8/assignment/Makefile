CC=gcc
CFLAGS=-Wall -g
LIBS= -lsodium
LIBG= -lgmp -lcrypto


all: rsa audit_logger audit_monitor test_audit


audit_logger: audit_logger.c
	gcc -Wall -fPIC -shared -o audit_logger.so audit_logger.c -lcrypto -ldl


audit_monitor: audit_monitor.c 
	gcc audit_monitor.c -o audit_monitor


test_audit: test_audit.c 
	gcc test_audit.c -o test_audit


rsa: rsa.c
	$(CC) $(CFLAGS) -o rsa rsa.c $(LIBG)


run: audit_logger.so test_audit.c 
	LD_PRELOAD=./audit_logger.so ./ransomware.sh /home/student/data 10


clean:
	rm -rf audit_logger.so
	rm -rf test_audit
	rm -rf audit_monitor
	rm -rf tmp
	rm -rf rsa




	