CC = gcc
CFLAGS = -Wall -Wextra -O2
TARGET = bufanalyzer
DAEMON = bufanalyzer-daemon

all: $(TARGET) $(DAEMON)

$(TARGET): src/main.c
	$(CC) $(CFLAGS) -o $@ $^

$(DAEMON): src/daemon.c
	$(CC) $(CFLAGS) -o $@ $^ || true

clean:
	rm -f $(TARGET) $(DAEMON)

.PHONY: all clean
