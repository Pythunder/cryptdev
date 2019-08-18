CC = gcc
CFLAGS = -I/home/dev/.local/include -O2 -Wall -Wextra
LDFLAGS = -s -static /home/dev/.local/lib/libcrypto.a
TARGET = cryptopen

all: $(TARGET)

$(TARGET): cryptopen.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

clean:
	$(RM) $(TARGET)

.PHONY: all clean
