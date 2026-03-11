# thhv — Capability-Aware `/dev/thhv` Kernel Driver

Out-of-tree Linux kernel module that exposes Themis capability operations
through an ioctl interface modelled on Microsoft's THHV driver, enabling
**cloud-hypervisor** to target the Themis capavisor with a thin backend swap.

## Architecture

```
/dev/thhv  (device fd)       ← thhv_main.c
  └─ partition fd            ← thhv_part.c   (1 per child domain)
       └─ vp fd              ← thhv_vp.c     (1 per virtual processor)
```

Each fd level has its own `file_operations` and ioctl dispatch.
Every ioctl translates to one or more Themis VMCALLs issued through
`libthemis` (Rust FFI static library) — no policy lives in the driver.

## Layout

```
thhv/
├── README.md
├── Makefile          # out-of-tree kbuild (also builds libthemis.a)
├── Kbuild            # kbuild object list + libthemis link flags
├── inc/
│   └── thhv.h    # ioctl numbers (magic 0xB8), uapi structs, driver structs
└── src/
    ├── thhv_main.c    # module init/exit, CPUID detection, /dev/thhv chardev
    ├── thhv_hvcall.c  # C shims + extern decls for libthemis FFI symbols
    ├── thhv_part.c    # partition fd lifecycle, partition-level ioctl stubs
    └── thhv_vp.c      # VP fd lifecycle, VP-level ioctl stubs
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
cd thhv && make

# Build against a specific kernel tree:
cd thhv && make KDIR=/path/to/kernel/build
```

The Makefile automatically builds `libthemis.a` via Cargo before invoking kbuild.

## Status

**Skeleton** — all ioctls return `-ENOSYS`.  The three-level fd hierarchy,
data structures, and libthemis FFI linkage are fully wired.

See `todo.md` (Phase 15) for the implementation roadmap.

## Design

Full design document: `2026/docs/design/thhv_themis/thhv_themis.md`
