CC      ?= $(CROSS_COMPILE)gcc
LD      ?= $(CROSS_COMPILE)ld
AR      ?= $(CROSS_COMPILE)ar
NM      ?= $(CROSS_COMPILE)nm
OBJCOPY ?= $(CROSS_COMPILE)objcopy
OBJDUMP ?= $(CROSS_COMPILE)objdump
READELF ?= $(CROSS_COMPILE)readelf

CA_BINARY = keystone_example_openclaw_trusted_backend
SERVER_BINARY = keystone_example_openclaw_trusted_backend_server

CA_OBJS = main.o
SERVER_OBJS = backend_server_c.o

CFLAGS += -Wall -Wextra -I../include

CA_LDADD += -lcrypto
SERVER_LDADD += -lcrypto

.PHONY: all
all: $(CA_BINARY) $(SERVER_BINARY)

$(CA_BINARY): $(CA_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(CA_LDADD)

$(SERVER_BINARY): $(SERVER_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(SERVER_LDADD)

.PHONY: clean
clean:
	rm -f $(CA_OBJS) $(SERVER_OBJS) $(CA_BINARY) $(SERVER_BINARY)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
