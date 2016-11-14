KBUILD_EXTRA_SYMBOLS := /lib/modules/$(shell uname -r)/build/Module.symvers
obj-m += knetstat.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
