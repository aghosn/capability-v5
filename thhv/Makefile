# SPDX-License-Identifier: GPL-2.0
#
# Out-of-tree build for thhv.ko
#
# Builds libthemis.a (Rust FFI static lib) then links it into the kernel module.
#
# Usage:
#   make                          # build against running kernel
#   make KDIR=/path/to/kernel     # build against specific kernel tree
#   make guest                    # build against mounted dom0 disk (auto-detect)
#   make guest DISK=path/to.img   # build against specific disk image
#   make guest COPY_TO_GUEST=/root  # build + copy .ko to guest disk
#   make tests                    # build userspace test binaries
#   make clean

KDIR     ?= /lib/modules/$(shell uname -r)/build
PWD      := $(shell pwd)

# Path to libthemis crate and workspace target dir.
LIBTHEMIS_DIR := $(PWD)/../themis/crates/libthemis
LIBTHEMIS_A   := $(PWD)/../themis/target/x86_64-unknown-none/release/liblibthemis.a

# Test binary output directory.
TEST_BINDIR := $(PWD)/test/bin
TEST_SRCS   := $(wildcard $(PWD)/test/test_*.c) $(wildcard $(PWD)/test/thhv_test.c)
TEST_BINS   := $(patsubst $(PWD)/test/%.c,$(TEST_BINDIR)/%,$(TEST_SRCS))

# All C and header sources — used to force kbuild re-invocation when any change.
THHV_SRCS := $(wildcard $(PWD)/src/*.c) $(wildcard $(PWD)/inc/*.h)

# Build libthemis.a as a no_std static lib with the "ffi" feature.
$(LIBTHEMIS_A):
	cd $(LIBTHEMIS_DIR) && \
	cargo build --release --features ffi --target x86_64-unknown-none

# Force our 'all' target as the default goal, even if Kbuild is present.
# Without this, GNU Make may pick up Kbuild's obj-m rules as the default goal.
.DEFAULT_GOAL := all

# Always re-invoke kbuild.  The kernel build system handles its own
# dependency tracking for C sources; we just need to ensure it runs.
all: $(LIBTHEMIS_A)
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	@test -f $(PWD)/thhv.ko || { echo "ERROR: thhv.ko not produced"; exit 1; }

# Build against kernel headers from a dom0 guest disk image.
# Mount the disk first with: sudo bash themis/scripts/mount-guest.sh
guest:
	bash $(PWD)/build-guest.sh $(if $(DISK),$(DISK),)

# Build all userspace test binaries into test/bin/.
tests: $(TEST_BINS)

$(TEST_BINDIR)/test_attestation: $(PWD)/test/test_attestation.c $(PWD)/inc/thhv.h
	@mkdir -p $(TEST_BINDIR)
	$(CC) -Wall -Wextra -O2 -I$(PWD)/inc -o $@ $< -lcrypto

$(TEST_BINDIR)/%: $(PWD)/test/%.c $(PWD)/inc/thhv.h
	@mkdir -p $(TEST_BINDIR)
	$(CC) -Wall -Wextra -O2 -I$(PWD)/inc -o $@ $<

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	cd $(LIBTHEMIS_DIR) && cargo clean
	rm -rf $(TEST_BINDIR)

# Remove build intermediates but keep thhv.ko
tidy:
	rm -f $(PWD)/src/*.o $(PWD)/src/.*.cmd
	rm -f $(PWD)/*.mod $(PWD)/*.mod.c $(PWD)/*.mod.o
	rm -f $(PWD)/*.o $(PWD)/.*.cmd
	rm -f $(PWD)/Module.symvers $(PWD)/modules.order
	rm -rf $(PWD)/.tmp_versions

.PHONY: all clean tidy guest tests
