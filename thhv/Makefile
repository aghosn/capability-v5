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
#   make clean

KDIR     ?= /lib/modules/$(shell uname -r)/build
PWD      := $(shell pwd)

# Path to libthemis crate and workspace target dir.
LIBTHEMIS_DIR := $(PWD)/../themis/crates/libthemis
LIBTHEMIS_A   := $(PWD)/../themis/target/x86_64-unknown-none/release/liblibthemis.a

# Build libthemis.a as a no_std static lib with the "ffi" feature.
$(LIBTHEMIS_A):
	cd $(LIBTHEMIS_DIR) && \
	cargo build --release --features ffi --target x86_64-unknown-none

default: $(LIBTHEMIS_A)
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Build against kernel headers from a dom0 guest disk image.
# Mount the disk first with: sudo bash themis/scripts/mount-guest.sh
guest:
	bash $(PWD)/build-guest.sh $(if $(DISK),$(DISK),)

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	cd $(LIBTHEMIS_DIR) && cargo clean

.PHONY: default clean guest
