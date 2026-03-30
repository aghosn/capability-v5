# Themis Scripts — Build & Deploy Reference

This directory contains the host-side scripts used to fetch dom0, build Themis artifacts, package them into `themis/guest/bins.img`, and boot or debug the resulting environment.

The **primary workflow** is running dom0 as a VM inside the Themis capavisor via
`cloud-hypervisor`.  For a top-level overview and quick-start guide, see the
[root README](../../README.md).  This document is the detailed reference for all
scripts and environment variables.

> All `cargo` commands in this document are run from the **`themis/` directory**
> (where `themis/.cargo/config.toml` defines the aliases), except `cargo build-bins`
> and `cargo build-bins-docker` which are run from the **repo root**.

## Prerequisites

### Native build path

One-time host setup:

```bash
sudo apt install e2fsprogs fuse2fs qemu-utils cloud-image-utils xorriso
```

You will also need a working Rust toolchain, `make`, and a C toolchain for `thhv`.

### Docker build path

Only Docker is required on the host. The container image provides the build environment.

## First-time setup (native path)

Run all commands from `themis/`:

1. Set up Limine boot assets (one-time):
   ```bash
   cargo setup-limine
   ```
2. Fetch the dom0 image and cloud-init seed:
   ```bash
   cargo fetch-dom0
   ```
3. Fetch the pinned dom0 kernel headers for `thhv.ko`:
   ```bash
   bash scripts/fetch-kheaders.sh
   ```
4. Create the artifact disk:
   ```bash
   bash scripts/create-bins.sh
   ```
5. Build everything and pack it into `bins.img` (run from **repo root**):
   ```bash
   cargo build-bins
   ```
6. First boot — run dom0 on Themis (cloud-init provision):
   ```bash
   SEED=1 cargo themis
   ```
7. Subsequent boots:
   ```bash
   cargo themis
   ```

## First-time setup (Docker path)

Run `cargo build-bins-docker` from the **repo root**; all other `cargo` commands from `themis/`:

1. Build the container image (from repo root):
   ```bash
   docker build -f Dockerfile.build -t themis-build:latest .
   ```
2. Set up Limine boot assets (from `themis/`):
   ```bash
   cargo setup-limine
   ```
3. Fetch the dom0 image and seed (from `themis/`):
   ```bash
   cargo fetch-dom0
   ```
4. Create the artifact disk (from `themis/`):
   ```bash
   bash scripts/create-bins.sh
   ```
5. Build and pack artifacts inside Docker (from repo root):
   ```bash
   cargo build-bins-docker
   ```
6. First boot (from `themis/`):
   ```bash
   SEED=1 cargo themis
   ```
7. Subsequent boots:
   ```bash
   cargo themis
   ```

## Day-to-day workflow

```bash
# From themis/ — full Themis + dom0 boot:
cargo themis

# After any code change — rebuild then reboot:
cargo build-bins && cargo themis           # native (build-bins from repo root)
cargo build-bins-docker && cargo themis   # Docker

# Run dom0 without Themis (faster, for guest-only iteration):
cargo dom0

# Debugging — boot with GDB stub:
cargo themis-debug
# In a second terminal:
cargo gdb
```

## Script reference

| Script | Purpose | Sudo required | Key env vars |
|---|---|---:|---|
| `build-bins.sh` | Build requested artifacts in dependency order, then refresh `bins.img` | No | `PROFILE`, `BINS_TARGETS`, `KHEADERS_DIR` |
| `build-bins-docker.sh` | Run `build-bins.sh` inside `themis-build:latest` | No | `PROFILE`, `BINS_TARGETS`, `KHEADERS_DIR` |
| `build-iso.sh` | Build `capavisor` and assemble `target/themis.iso` | No | `PROFILE`, `DOM0_VERSION`, `LIMINE_DIR`, `LIMINE_DEPLOY` |
| `create-bins.sh` | Create an empty sparse ext2 `guest/bins.img` | No | `BINS_SIZE` |
| `dom0-lib.sh` | Shared dom0 version helper sourced by other scripts | No (helper only) | `DOM0_VERSION` |
| `fetch-dom0.sh` | Download the dom0 QCOW2 and generate `guest/seed.img` | No | `DOM0_VERSION`, `FORCE` |
| `fetch-kheaders.sh` | Download and extract pinned kernel headers into `themis/target/kheaders/` | No | none |
| `gdb.sh` | Attach `rust-gdb`/`gdb` to a running QEMU GDB stub | No | `GDB`, `GDB_PORT` |
| `mount-guest.sh` | Mount the dom0 QCOW2 via NBD for manual inspection | Yes | `DOM0_VERSION` |
| `resize-disk.sh` | Grow a dom0 QCOW2 image | No | none |
| `run-dom0.sh` | Boot the dom0 image directly under QEMU | No | `SEED`, `QEMU_CPUS`, `QEMU_MEM`, `QEMU_ENABLE_KVM`, `QEMU_NET`, `QEMU_NET_FWD`, `QEMU_EXTRA_ARGS`, `DOM0_VERSION` |
| `run-qemu.sh` | Build ISO and boot full Themis + dom0 under QEMU | No | `PROFILE`, `QEMU_CPUS`, `QEMU_MEM`, `QEMU_ENABLE_KVM`, `QEMU_BIOS`, `QEMU_EXTRA_ARGS`, `DOM0_VERSION` |
| `setup-limine.sh` | Clone the pinned Limine release into `themis/tools/limine/` and build the CLI | No | none |
| `themis-debug.sh` | Boot Themis with a QEMU GDB stub and attach GDB | No | `QEMU_CPUS`, `QEMU_MEM`, `QEMU_ENABLE_KVM`, `QEMU_BIOS`, `QEMU_EXTRA_ARGS`, `GDB` |
| `umount-guest.sh` | Unmount `/tmp/mnt` and disconnect the NBD device | Yes | none |
| `update-bins.sh` | Pack built artifacts into `guest/bins.img` with `fuse2fs` | No | `PROFILE`, `BINS_TARGETS`, `NESTED_KERNEL`, `NESTED_ROOTFS` |

## Environment variables reference

The table below consolidates the variables documented in `CONTEXT.md` §6 plus the additional knobs used by the newer packaging scripts.

| Variable | Default | Description |
|---|---|---|
| `PROFILE` | `debug` | Build profile for Rust artifacts; `release` adds `--release`. |
| `BINS_TARGETS` | `all` | Comma-separated subset for `build-bins.sh`, e.g. `capavisor,chv,2026,thhv`. |
| `BINS_SIZE` | `2G` | Size of `themis/guest/bins.img` when running `create-bins.sh`. |
| `KHEADERS_DIR` | auto-detect | Explicit kernel headers tree for `thhv.ko`; otherwise `build-bins.sh` looks under `themis/target/kheaders/usr/src/linux-headers-*-generic`. |
| `NESTED_KERNEL` | unset | Optional nested guest kernel copied into `/opt/bins/nested/bzImage`. |
| `NESTED_ROOTFS` | unset | Optional nested guest rootfs copied into `/opt/bins/nested/rootfs.img`. |
| `DOM0_VERSION` | `noble` | Dom0 image family to use, currently `noble` or `jammy`. |
| `FORCE` | `0` | Re-download dom0 artifacts even if already present. |
| `SEED` | unset | `1` attaches `guest/seed.img` on the next `cargo dom0` boot. |
| `QEMU_CPUS` | `4` / `2` | vCPU count for `run-qemu.sh` / `run-dom0.sh`. |
| `QEMU_MEM` | `4G` | Guest memory size. |
| `QEMU_ENABLE_KVM` | `1` | Use hardware acceleration when `/dev/kvm` is available. |
| `QEMU_BIOS` | `0` | `1` forces legacy BIOS instead of UEFI for Themis boots. |
| `QEMU_NET` | `1` | Enable user-mode networking for `run-dom0.sh`. |
| `QEMU_NET_FWD` | unset | Extra `-netdev user,...` forwards appended to the dom0 QEMU invocation. |
| `QEMU_EXTRA_ARGS` | unset | Extra arguments appended to the QEMU command line. |
| `COPY_TO_GUEST` | unset | Legacy `thhv/build-guest.sh` copy destination inside the mounted guest. |
| `LIMINE_DIR` | auto-detect | Override where `build-iso.sh` looks for Limine boot assets. |
| `LIMINE_DEPLOY` | `${LIMINE_DIR}/limine` | Override the Limine deploy CLI path. |
| `OVMF_CODE` | distro default | Override the OVMF firmware code image path. |
| `OVMF_VARS_TEMPLATE` | distro default | Override the OVMF NVRAM template path. |
| `GDB_PORT` | `1234` | TCP port for a running QEMU GDB stub. |
| `GDB` | `rust-gdb` or `gdb` | Debugger binary override for `gdb.sh` / `themis-debug.sh`. |

## Dom0 access

- Login credentials: `cloud` / `cloud123`
- SSH access: `ssh -p 2222 cloud@localhost`
- `guest/seed.img` provisions `/opt/bins` as a read-only mount of `guest/bins.img`
- A convenience symlink is created at `/home/cloud/bins`

Key artifact locations inside dom0:

- `/opt/bins/thhv/thhv.ko`
- `/opt/bins/thhv/tests/*`
- `/opt/bins/cloud-hypervisor/cloud-hypervisor`
- `/opt/bins/capa-engine/capa-engine`
- `/opt/bins/capa-engine/tests/*` (if test binaries were built)
- `/opt/bins/nested/bzImage` and `/opt/bins/nested/rootfs.img` (optional)

## Troubleshooting

- **Older kernel host** → use the Docker path: `cargo build-bins-docker`
- **`fuse2fs` not found** → install it with:
  ```bash
  sudo apt install fuse2fs
  ```
- **`bins.img` already exists** warning from `create-bins.sh` → either delete and recreate it, or keep the existing image and run `bash themis/scripts/update-bins.sh` to refresh contents in place
- **`thhv.ko` will not load** → the kernel headers do not match the guest kernel ABI; re-run `bash themis/scripts/fetch-kheaders.sh` and rebuild
- **dom0 will not boot** → `bins.img` is mounted with `nofail`, so its absence should not block boot. If the guest still fails, inspect the serial console and confirm the root QCOW2 and seed image are valid

## Updating pinned kernel version

When the dom0 image is upgraded, update `themis/scripts/dom0-kernel-version.txt` so `fetch-kheaders.sh` downloads the matching Ubuntu headers.

Recommended flow:

1. Boot the refreshed dom0 image.
2. Inside dom0, check the running kernel:
   ```bash
   uname -r
   ```
3. Copy that exact value into `themis/scripts/dom0-kernel-version.txt`.
4. Refresh extracted headers:
   ```bash
   rm -rf themis/target/kheaders
   bash themis/scripts/fetch-kheaders.sh
   ```
5. Rebuild artifacts:
   ```bash
   cargo build-bins
   ```
