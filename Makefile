# The final kernel module output name
obj-m += dm_xor_split_mod.o

# Tell kbuild which object files compose the final module
dm_xor_split_mod-y := dm_xor_split.o xor_core.o

# Points to the kernel headers dynamically inside the target system
KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

# User-space Test configuration
test:
	gcc -Wall -O2 test_xor.c xor_core.c -o test_xor
	./test_xor
	rm -f test_xor
