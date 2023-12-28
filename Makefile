CC=gcc
CFLAGS=-g
CLIBS=-lcurl -ljson-c

INSTALL_BIN=/usr/local/bin

all: ipstat.c
	mkdir -p build
	$(CC) -o build/ipstat $(CFLAGS) $< $(CLIBS)

clean:
	rm -rf build

install:
	install build/ipstat $(INSTALL_BIN)

uninstall:
	rm $(INSTALL_BIN)/ipstat
