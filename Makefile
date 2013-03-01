ifneq ($(KERNELRELEASE),)
obj-m += ipt_SYNPROXY.o
else
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all: ipt_SYNPROXY.ko libipt_SYNPROXY.so

ipt_SYNPROXY.ko: ipt_SYNPROXY.c
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

libipt_SYNPROXY.so: libipt_SYNPROXY.c
	$(CC) -Wall -fPIC -shared -o $@ $^

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	$(RM) -f *.so *.o
endif
