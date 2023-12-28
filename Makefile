CC=gcc
CFLAGS=-g -lcurl -ljson-c

INSTALL_BIN=/usr/local/bin

all: ipstat.c
	mkdir -p build
	$(CC) $(CFLAGS) $< -o build/ipstat

clean:
	rm -rf build

install:
	install build/ipstat $(INSTALL_BIN)

uninstall:
	rm $(INSTALL_BIN)/ipstat
