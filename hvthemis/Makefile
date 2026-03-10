# SPDX-License-Identifier: GPL-2.0
#
# Out-of-tree build for hvthemis.ko
#
# Builds libthemis.a (Rust FFI static lib) then links it into the kernel module.
#
# Usage:
#   make                          # build against running kernel
#   make KDIR=/path/to/kernel     # build against specific kernel tree
#   make clean

KDIR     ?= /lib/modules/$(shell uname -r)/build
PWD      := $(shell pwd)

# Path to libthemis crate (relative to this Makefile).
LIBTHEMIS_DIR := $(PWD)/../themis/crates/libthemis
LIBTHEMIS_A   := $(LIBTHEMIS_DIR)/target/x86_64-unknown-none/release/liblibthemis.a

# Build libthemis.a as a no_std static lib with the "ffi" feature.
$(LIBTHEMIS_A):
	cd $(LIBTHEMIS_DIR) && \
	cargo build --release --features ffi --target x86_64-unknown-none

default: $(LIBTHEMIS_A)
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	cd $(LIBTHEMIS_DIR) && cargo clean

.PHONY: default clean
