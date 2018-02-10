override CFLAGS += -O3 -pthread -Wno-attributes
CC=gcc

all: secret meltdown

libkdump/libkdump.a:  libkdump/libkdump.c
	make -C libkdump

secret: secret.c libkdump/libkdump.a
	$(CC) $< -o $@ -Llibkdump -Ilibkdump -lkdump -static $(CFLAGS)

meltdown: meltdown.c
	$(CC) $< -o $@

clean:
	rm -f *.o secret meltdown
	make clean -C libkdump
