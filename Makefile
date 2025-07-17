obj-m += perftop.o

KDIR := /lib/modules/$(shell uname -r)/build

all:
	make -C $(KDIR) M=$(PWD) KCFLAGS=-Wno-error modules

clean:
	make -C $(KDIR) M=$(PWD) clean

transfer:
	scp -P 2200 perftop.ko ubuntu@localhost:~/hw6/

load:
	sudo insmod perftop.ko

unload:
	sudo rmmod perftop