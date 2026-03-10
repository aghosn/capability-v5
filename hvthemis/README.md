# hvthemis — Capability-Aware `/dev/mshv` Kernel Driver

Out-of-tree Linux kernel module that exposes Themis capability operations
through an ioctl interface modelled on Microsoft's MSHV driver, enabling
**cloud-hypervisor** to target the Themis capavisor with a thin backend swap.

## Architecture

```
/dev/mshv  (device fd)       ← hvthemis_main.c
  └─ partition fd            ← hvthemis_part.c   (1 per child domain)
       └─ vp fd              ← hvthemis_vp.c     (1 per virtual processor)
```

Each fd level has its own `file_operations` and ioctl dispatch.
Every ioctl translates to one or more Themis VMCALLs issued through
`libthemis` (Rust FFI static library) — no policy lives in the driver.

## Layout

```
hvthemis/
├── README.md
├── Makefile          # out-of-tree kbuild (also builds libthemis.a)
├── Kbuild            # kbuild object list + libthemis link flags
├── inc/
│   └── hvthemis.h    # ioctl numbers (magic 0xB8), uapi structs, driver structs
└── src/
    ├── hvthemis_main.c    # module init/exit, CPUID detection, /dev/mshv chardev
    ├── hvthemis_hvcall.c  # C shims + extern decls for libthemis FFI symbols
    ├── hvthemis_part.c    # partition fd lifecycle, partition-level ioctl stubs
    └── hvthemis_vp.c      # VP fd lifecycle, VP-level ioctl stubs
```

## Dependencies

- **libthemis** (`themis/crates/libthemis`): `no_std` Rust crate providing
  VMCALL inline assembly wrappers.  Compiled as a static library (`libthemis.a`)
  with `--features ffi` and linked into the kernel module.
- **themis-abi** (`themis/crates/themis-abi`): shared opcode constants, error
  codes, and register profile types (`VpRegister`, `VpGpRegs`, `VpCommPage`).

## Building

```bash
# Build against running kernel (requires kernel headers + Rust nightly):
cd hvthemis && make

# Build against a specific kernel tree:
cd hvthemis && make KDIR=/path/to/kernel/build
```

The Makefile automatically builds `libthemis.a` via Cargo before invoking kbuild.

## Status

**Skeleton** — all ioctls return `-ENOSYS`.  The three-level fd hierarchy,
data structures, and libthemis FFI linkage are fully wired.

See `todo.md` (Phase 15) for the implementation roadmap.

## Design

Full design document: `2026/docs/design/mshv_themis/mshv_themis.md`
