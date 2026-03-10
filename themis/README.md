# Themis

**Themis** is a bare-metal Type-1 hypervisor written in Rust, built around a
capability-based security model.  It takes exclusive ownership of the hardware
at boot, then carves physical memory and CPU time into isolated *domains* whose
authority is governed by an unforgeable capability graph rather than by
discretionary access control.

The first domain created by Themis is **dom0** — a stock Linux kernel loaded
directly from the attached disk and granted a controlled view of the hardware.
From dom0, additional domains can be created by delegating sub-capabilities,
each forming a nested trust hierarchy enforced in hardware via Intel VT-x / EPT
(AMD SVM / NPT planned).

The design is documented in `../todo.md` and the EuroS&P paper draft in
`../2026/`.  This directory is the implementation root.

---

## Repository layout

```
themis/
├── capavisor/          # Main hypervisor binary (no_std, x86_64-unknown-none)
│   ├── src/main.rs     # BSP entry point, Limine protocol handling
│   ├── linker.ld       # Higher-half linker script (load at 0xffffffff80000000)
│   └── build.rs        # Emits absolute -T path for linker script
│
├── crates/
│   ├── themis-abi/     # Shared ABI: hypercall opcodes, error codes, VpRegister,
│   │                   #   META page constants (no_std, used by both capavisor
│   │                   #   and the future themis-vmm.ko Linux driver)
│   ├── ept/            # Extended Page Table mapper (stub; to be extracted from
│   │                   #   asterinas/hyperenclave — Apache-2.0, formally verified)
│   ├── capavisor-pt/   # Capavisor host page-table manager (stub; to be vendored
│   │                   #   from verified-nrkernel — Verus, SOSP'24 DA)
│   └── vtd/            # Intel VT-d IOMMU driver (ported from vmxvmm/crates/vtd)
│
├── guest/
│   ├── dom0/           # Provenance records for dom0 artifacts
│   ├── ubuntu-24.04-server-cloudimg-amd64.img  # Ubuntu root disk [gitignored; cargo fetch-dom0]
│   └── seed.img        # Cloud-init seed  [gitignored; cargo fetch-dom0]
│
├── scripts/
│   ├── build-iso.sh    # Build capavisor ELF → Limine-bootable ISO (target/themis.iso)
│   ├── run-qemu.sh     # Build ISO and boot under QEMU/KVM
│   ├── debug.sh        # Boot QEMU with -s -S and attach rust-gdb
│   ├── fetch-dom0.sh   # Download dom0 root disk + create cloud-init seed
│   ├── resize-disk.sh  # Grow a QCOW2 disk image by N GB
│   └── setup-limine.sh # Clone and build Limine v8.7.0 into tools/limine/
│
├── tools/
│   └── limine/         # Local Limine clone [gitignored; cargo setup-limine]
│
├── .cargo/config.toml  # Default target (x86_64-unknown-none), rustflags,
│                       #   Cargo aliases (iso / qemu / debug / fetch-dom0 / dom0 / setup-limine)
├── rust-toolchain.toml # Pins to nightly (required by x2apic → x86_64/nightly,
│                       #   acpi 6.x / allocator_api)
└── themis.gdbinit      # GDB init: symbol load, print-cr3 helper
```

The capability engine lives at `../2026/` and is referenced as a workspace
path dependency.

---

## Prerequisites

All dependencies are standard packages. Install them in one go:

```sh
sudo apt install qemu-system-x86 qemu-utils cloud-image-utils xorriso ovmf
```

| Tool | Purpose | Package |
|------|---------|---------|
| `rustup` + nightly | Build (`rust-toolchain.toml` selects it automatically) | `curl https://sh.rustup.rs \| sh` |
| `qemu-system-x86_64` | Run/debug the hypervisor | `qemu-system-x86` |
| `qemu-img` | Fetch dom0 disk | `qemu-utils` |
| `cloud-localds` | Create cloud-init seed | `cloud-image-utils` |
| `xorriso` | Create bootable ISO (ISO 9660 + El Torito) | `xorriso` |
| `OVMF` | UEFI firmware for QEMU | `ovmf` |
| `rust-gdb` | Debugging | ships with `rustup component add rust-src` |

### Limine setup

Limine is the BIOS/UEFI bootloader used to load the capavisor. It is cloned
and built locally inside `tools/limine/` — nothing is installed system-wide:

```sh
cargo setup-limine           # clones Limine v8.7.0 into tools/limine/, builds CLI
```

This is also run automatically the first time you run `cargo iso` or `cargo themis`
if `tools/limine/` doesn't exist yet.  Requires only `git` and `cc` (gcc/clang).

---

## Quick start

```sh
# 1. Install system dependencies
sudo apt install qemu-system-x86 qemu-utils cloud-image-utils xorriso

# 2. Set up Limine bootloader (local clone, nothing system-wide)
cargo setup-limine

# 3. Download Ubuntu dom0 disk + create cloud-init seed
cargo fetch-dom0

# 4. Seed the dom0 image (first boot — provisions user account)
#    Wait for the login prompt, log in (cloud / cloud123), then `sudo poweroff`.
SEED=1 cargo dom0

# 5. Boot Themis!
cargo themis
```

After step 4, the image is seeded and `cargo dom0` / `cargo themis` work without
the seed. If you re-download the image (`FORCE=1 cargo fetch-dom0`), repeat step 4.

---

## Commands

All commands are invoked via `cargo` from the workspace root (`themis/`).

### Build

```sh
cargo build                  # compile capavisor (debug, x86_64-unknown-none)
cargo build --release        # release build
cargo check                  # type-check without linking
```

### ISO & QEMU

```sh
cargo iso                    # build ISO → target/themis.iso

cargo themis                 # build ISO and boot Themis under QEMU/KVM
                             # dom0 disk attached automatically if present
```

QEMU boots via UEFI (OVMF) by default with the dom0 disk on virtio-blk.
Set `QEMU_BIOS=1` to fall back to legacy BIOS boot.

Environment knobs for `cargo themis` / `cargo themis-debug`:

| Variable | Default | Effect |
|----------|---------|--------|
| `QEMU_MEM` | `1G` | Guest RAM |
| `QEMU_CPUS` | `4` | vCPU count |
| `QEMU_ENABLE_KVM` | `1` | Use KVM+VMX acceleration |
| `QEMU_BIOS` | `0` | Set to `1` for legacy BIOS (default is UEFI/OVMF) |
| `PROFILE` | `debug` | `release` for optimised build |
| `QEMU_EXTRA_ARGS` | *(empty)* | Appended verbatim to QEMU command |

### Troubleshooting

**QEMU boots but no serial output at all (not even Limine):**
The OVMF NVRAM file can get into a corrupt state.  Delete it and re-run —
the build script recreates it from the template automatically:

```sh
rm target/ovmf_vars.fd
cargo themis
```

### Debugging

There are two ways to debug Themis with GDB:

**Option 1: All-in-one** — `cargo themis-debug` starts QEMU paused and
launches `rust-gdb` already connected in one command:

```sh
cargo themis-debug           # builds ISO, starts QEMU -s -S, attaches rust-gdb
                             # QEMU is killed automatically when you quit GDB
```

**Option 2: Separate terminals** — useful when you want QEMU running
independently (e.g. to see serial output in one terminal, GDB in another):

```sh
# Terminal 1: start QEMU with GDB stub enabled
QEMU_EXTRA_ARGS="-s -S" cargo themis

# Terminal 2: attach GDB
cargo gdb
```

Both options load `themis.gdbinit` automatically, which provides the
capavisor symbols and these custom commands:

| GDB command | Description |
|-------------|-------------|
| `load-vmlinux <path> [addr]` | Load Linux vmlinux symbols at a GPA (default: `0x1000000`) |
| `dmesg-hint` | Print hints for locating the dom0 kernel text and dmesg ring buffer |
| `print-cr3` | Print the current CR3 (page-table root) |
| `print-vmcs` | *(stub)* VMCS dump placeholder |

To attach GDB manually (without cargo):

```sh
rust-gdb -ex "target remote :1234" -x themis.gdbinit
```

### dom0 (standalone Linux, no Themis)

```sh
SEED=1 cargo dom0            # first boot: seed cloud-init (provisions user)
cargo dom0                   # subsequent boots: no seed needed
```

Login: `cloud` / `cloud123`.  The disk is attached as virtio-blk and cloud-init
runs only on the first seeded boot.

| Variable | Default | Effect |
|----------|---------|--------|
| `SEED` | `0` | Set to `1` to attach cloud-init seed |
| `QEMU_MEM` | `2G` | Guest RAM |
| `QEMU_CPUS` | `2` | vCPU count |
| `QEMU_ENABLE_KVM` | `1` | Use KVM acceleration |
| `QEMU_EXTRA_ARGS` | *(empty)* | Appended verbatim to QEMU command |

### dom0 disk

```sh
cargo fetch-dom0             # download Ubuntu Noble 24.04 cloud image + create seed.img
                             # output: guest/ubuntu-24.04-server-cloudimg-amd64.img  guest/seed.img
FORCE=1 cargo fetch-dom0     # re-download even if already present

cargo resize-disk guest/ubuntu-24.04-server-cloudimg-amd64.img 10   # grow disk by 10 GB
```

After resizing, boot the guest and expand the filesystem:

```sh
sudo growpart /dev/vda 1
sudo resize2fs /dev/vda1
```

The dom0 kernel and initrd are **not** downloaded separately — Limine reads them
directly from the disk at boot time:

```
module_path: fslabel(cloudimg-rootfs):/boot/vmlinuz
module_path: fslabel(cloudimg-rootfs):/boot/initrd.img
```

The disk is attached as a virtio-blk drive under UEFI (OVMF includes virtio
drivers). Limine accesses it via EFI block I/O protocols before the OS loads.

#### dom0 login credentials

The cloud-init seed (`seed.img`) created by `cargo fetch-dom0` provisions
a single user for console / SSH access:

| Field    | Value      |
|----------|------------|
| Username | `cloud`    |
| Password | `cloud123` |

The user has passwordless `sudo`. Password authentication over SSH is enabled
(`ssh_pwauth: True`). These are **development-only** credentials — change them
before any non-local use.

---

## Boot flow (summary)

```
Power on
  └─ Limine (BIOS/UEFI)
       ├─ loads  capavisor   from ISO
       ├─ loads  vmlinuz     from disk /boot/vmlinuz    (Limine module)
       └─ loads  initrd.img  from disk /boot/initrd.img (Limine module)

capavisor _start  (BSP, interrupts off)
  ├─ Phase 1: parse memory map, init heap, serial, ACPI, PCI
  ├─ Phase 2: VMXON, VMCS setup, EPT allocation
  ├─ Phase 7: read Limine modules, parse Linux boot header,
  │           populate boot_params, place kernel in dom0 EPT
  └─ VMENTRY → dom0 Linux kernel
                └─ loads themis-vmm.ko → hypercalls to Themis
                         └─ child domains created via capability delegation
```

See `../todo.md` for the full implementation plan (Phases 0–14).

---

## Status

| Phase | Description | Status |
|-------|-------------|--------|
| 0 | Workspace setup | ✅ done |
| 0.5 | dom0 Linux image & bootloader integration | ✅ done |
| 1 | Boot, memory, ACPI, PCI | ⬜ pending |
| 2 | VT-x foundation | ⬜ pending |
| 3–13 | Platform, APICv, IRQ routing, capability integration, AMD SVM | ⬜ pending |
| 14 | Custom dom0 image with `themis-vmm.ko` | ⬜ pending |
