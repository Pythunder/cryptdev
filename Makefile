CC = gcc
CFLAGS = -O2 -Wall -Wextra
LDFLAGS = -static -lcrypto -s
TARGET = cryptopen

all: $(TARGET)

$(TARGET): cryptopen.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

clean:
	$(RM) $(TARGET)

.PHONY: all clean
