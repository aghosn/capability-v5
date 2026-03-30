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

### Against the running kernel

```bash
cd thhv && make                     # requires kernel headers + Rust nightly
cd thhv && make KDIR=/path/to/build # explicit kernel tree
```

### Against a dom0 guest disk (cross-build)

The `build-guest.sh` script mounts a dom0 cloud image, finds the kernel
headers inside it, and builds `thhv.ko` without needing root for the
compilation itself.

```bash
# 1. Mount the disk (requires sudo, only once)
sudo bash themis/scripts/mount-guest.sh                # auto-detect (Noble)
sudo DOM0_VERSION=jammy bash themis/scripts/mount-guest.sh  # explicit version

# 2. Build (no sudo needed — disk is already mounted at /tmp/mnt)
cd thhv
bash build-guest.sh                                     # auto-detect disk
DOM0_VERSION=jammy bash build-guest.sh                  # Jammy disk
bash build-guest.sh ../themis/guest/ubuntu-24.04-server-cloudimg-amd64.img  # explicit path

# 3. Build + copy .ko onto the guest filesystem
COPY_TO_GUEST=/root bash build-guest.sh                 # copies to /root/thhv.ko

# 4. Unmount when done
sudo bash themis/scripts/umount-guest.sh
```

Or via `make`:

```bash
make guest                          # auto-detect, disk must be mounted
make guest COPY_TO_GUEST=/root      # build + copy to guest
```

The Makefile automatically builds `libthemis.a` via Cargo before invoking kbuild.

## Status

- **Device ioctls**: `THHV_CREATE_PARTITION` (→ `CREATE_DOMAIN`),
  `THHV_QUERY` (META budget queries)
- **Partition ioctls**: `THHV_INITIALIZE_PARTITION` (pins shared META pages
  + `SEAL`), `THHV_CREATE_VP`, partition cleanup (→ `REVOKE_DOMAIN`)
- **VP ioctls**: `THHV_CREATE_VP` (pins per-VP META + COMM pages),
  `THHV_GET_VP_STATE` / `THHV_SET_VP_STATE` (→ `GET_REG` / `SET_REG`)
- **Remaining stubs**: `THHV_RUN_VP`, `THHV_SET_GUEST_MEMORY`, `THHV_IRQFD`,
  `THHV_IOEVENTFD`, VP `mmap()`

See `todo.md` (Phase 15) for the full implementation roadmap.

## Design

Full design document: `capa-engine/docs/design/thhv_themis/thhv_themis.md`
