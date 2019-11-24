CC = cc
CFLAGS = -Wall -Wextra -Os
LDFLAGS = -static -s -lcrypto

all: cryptdev
cryptdev: cryptdev.c
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean:
	rm -f cryptdev

.PHONY: all clean
