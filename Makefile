# dm-xor: Device-mapper XOR split kernel module
#
# Targets:
#   make            — build the module
#   make clean      — remove build artifacts
#   make check      — build with sparse static analysis (requires sparse)
#   make test       — build and run user-space unit tests
#   make dkms-install   — register + build + install via DKMS
#   make dkms-uninstall — remove from DKMS

MODULE_NAME := dm-xor
MODULE_VERSION := 1.3.5

# The final kernel module output name
obj-m += dm-xor.o

# Tell kbuild which object files compose the final module
dm-xor-y := dm_xor.o xor_core.o

# Points to the kernel headers for the running kernel
KDIR ?= /lib/modules/$(shell uname -r)/build

# ---- Build targets ----

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

check:
	$(MAKE) C=1 -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

# ---- User-space test ----

test:
	gcc -Wall -O2 test_xor.c xor_core.c -o test_xor
	./test_xor
	rm -f test_xor

# ---- DKMS helpers ----

dkms-install:
	cp -r . /usr/src/$(MODULE_NAME)-$(MODULE_VERSION)
	dkms add $(MODULE_NAME)/$(MODULE_VERSION)
	dkms build $(MODULE_NAME)/$(MODULE_VERSION)
	dkms install $(MODULE_NAME)/$(MODULE_VERSION)

dkms-uninstall:
	dkms remove $(MODULE_NAME)/$(MODULE_VERSION) --all || true
	rm -rf /usr/src/$(MODULE_NAME)-$(MODULE_VERSION)

# ---- Version Bumping helper ----

bump:
	@./bump-version.sh $(VERSION)

.PHONY: all check clean test dkms-install dkms-uninstall bump

