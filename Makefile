# Kernel module
obj-m += firewall.o
KDIR := /lib/modules/$(shell uname -r)/build

# CLI application
CC = gcc
CFLAGS = -Wall -Wextra

all: module cli

module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

cli: firewall-cli.c
	$(CC) $(CFLAGS) -o firewall-cli firewall-cli.c

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f firewall-cli