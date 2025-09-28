KSRC ?= /lib/modules/$(shell uname -r)/build

obj-m += knetstat.o

all:
	make -C $(KSRC) M=$(PWD) modules

clean:
	make -C $(KSRC) M=$(PWD) clean
