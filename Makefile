CC = gcc
CFLAGS = -O2 -Wall -Wextra -fstack-protector-all -D_FORTIFY_SOURCE=2
LDFLAGS = -Wl,-z,relro,-z,now -static -lcrypto -s
TARGET = cryptdev

all: $(TARGET)

$(TARGET): cryptdev.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

clean:
	$(RM) $(TARGET)

.PHONY: all clean
