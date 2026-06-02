#obj-m += my_dm_target.o
obj-m += dm_xor_split.o

# This points to the kernel headers dynamically inside the target system
KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

