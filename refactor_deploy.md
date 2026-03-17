# Automated Build & Deploy — Feasibility Study

## Current State

```
themis/
  guest/
    ubuntu-24.04-server-cloudimg-amd64.img   ← dom0 QCOW2 root disk
    seed.img                                  ← cloud-init first-boot seed
  scripts/
    build-iso.sh         ← builds capavisor + Limine ISO
    run-qemu.sh          ← boots Themis ISO + dom0 disk under QEMU
    run-dom0.sh          ← boots dom0 standalone (sanity check)
    fetch-dom0.sh        ← downloads Ubuntu cloud image + seed
    mount-guest.sh       ← NBD-mounts the QCOW2 (NEEDS SUDO)
    umount-guest.sh      ← unmounts
    resize-disk.sh       ← grows the QCOW2

thhv/
  build-guest.sh         ← mounts dom0 disk, finds kernel headers, builds
                            thhv.ko, optionally copies .ko + test bins onto disk
                            (NEEDS SUDO: modprobe nbd, mount, chown)

cloud-hypervisor/        ← our fork (Rust, `cargo build`)
2026/                    ← CLI / test harness (Rust, `cargo build/test`)
```

### Pain points today
1. **sudo everywhere** — `modprobe nbd`, `mount`, `chown` are all root operations.
2. **Manual binary sync** — after building thhv.ko / cloud-hypervisor / tests you must
   manually mount the QCOW2 (sudo) and copy files in by hand.
3. **Fragile root disk** — any re-fetch of the Ubuntu image wipes all manually installed
   binaries (kernel module, tests, nested VM image, cloud-hypervisor).
4. **Cross-compilation friction** — building thhv.ko currently requires mounting dom0
   to extract kernel headers, which needs root.
5. **No single build command** — each component (capavisor, thhv, cloud-hypervisor,
   2026 CLI, test binaries) is built and deployed independently with no orchestration.

---

## Proposed Architecture

The core idea is a **separate "bins" artifact disk** that lives alongside the dom0 root
disk.  dom0 mounts it read-only at boot.  Because it is fully separate from the OS image,
we can destroy and recreate it at any time without touching the provisioned Ubuntu system.
All operations on this disk are done **without sudo** using FUSE or a plain host directory.

```
themis/guest/
  ubuntu-24.04-*.img   ← unchanged: dom0 OS (only re-fetched when Ubuntu changes)
  seed.img             ← unchanged: cloud-init first-boot only
  bins.img             ← NEW: ext2 raw image, rebuilt on every `cargo build-bins`
    /thhv/thhv.ko
    /thhv/tests/…
    /cloud-hypervisor/cloud-hypervisor
    /nested/bzImage  (optional nested guest kernel)
    /nested/rootfs.img (optional)
    /version.txt
```

Inside dom0, the image is exposed as `/dev/vdb` (second virtio-blk device) and mounted
**read-only** at `/opt/bins` via an fstab entry written by cloud-init on first boot.

---

## No-Sudo Feasibility

### Creating & updating `bins.img` without root

```
truncate -s 2G themis/guest/bins.img        # create sparse file (no sudo)
mkfs.ext2 -L bins themis/guest/bins.img     # format ext2 (no sudo)
fuse2fs themis/guest/bins.img /tmp/bins_mnt # FUSE mount (no sudo)
cp artifacts … /tmp/bins_mnt/
fusermount -u /tmp/bins_mnt                 # unmount (no sudo)
```

`fuse2fs` ships in the `e2fsprogs` package on Ubuntu ≥ 22.04 (already a build
dependency for many distros).  No kernel module, no privileges required.

**Alternative: virtio-fs (virtiofsd)**
Instead of a disk image, expose a plain host *directory* (`themis/guest/bins/`) to the
guest via `virtiofsd`.  Even simpler — no disk format at all — but requires `virtiofsd`
to be running as a side process during QEMU boot.  Either approach is viable; the raw
ext2 image is self-contained and easier to snapshot/archive.

### Building thhv.ko without root

The only reason `build-guest.sh` needs root today is to mount the QCOW2 to read kernel
headers.  This is avoidable:

**Option A — download the .deb directly from Ubuntu repos:**
```bash
# In a new script: scripts/fetch-kheaders.sh
KVER=$(ssh -p2222 cloud@localhost uname -r)   # or read from a version file
apt-get download linux-headers-${KVER} linux-headers-${KVER}-generic
dpkg-deb --extract linux-headers-${KVER}.deb   /tmp/kheaders
dpkg-deb --extract linux-headers-${KVER}-generic.deb /tmp/kheaders
# Then: make KDIR=/tmp/kheaders/usr/src/linux-headers-${KVER}-generic
```
All of `apt-get download` and `dpkg-deb --extract` work without sudo.

**Option B — ship a `kernel-version.txt` in the repo** pinned to the exact Ubuntu kernel
version for each dom0 image, so the headers can be downloaded without ever booting the
guest.  When the dom0 image is upgraded, update the file.

**Option C — build inside the VM over SSH** (the most robust long-term):
Once dom0 is booted with networking, `cargo build-bins` SSHs in, runs the build there,
then copies the artifacts back over `scp`.  No host-side cross-compilation needed; the
guest kernel headers are trivially available.  This also means the module ABI is always
correct.

Recommendation: **Option B for fast iteration** (no VM boot required), **Option C for
CI** (guaranteed ABI match).

### Nested VM image without root

If a nested Linux guest is needed, it can be built entirely with user-space tools:

- Kernel: `make bzImage` (no sudo)
- Minimal rootfs: `debootstrap --variant=minbase` into a directory, then package with
  `fakeroot`+`mke2fs` or `gen_init_cpio` for an initramfs — all without sudo.
- cloud-hypervisor itself is a Rust binary (`cargo build`) — no root required.

---

## Implementation Plan

### Phase 0 — Prerequisites (one-time host setup)

Install the following userspace tools (only `apt install` needs sudo, done once):
```
sudo apt install e2fsprogs fuse2fs qemu-utils cloud-image-utils
```
Everything after this point runs without sudo.

---

### Phase 1 — `bins.img` disk lifecycle scripts

**New file: `themis/scripts/create-bins.sh`**
- `truncate -s ${BINS_SIZE:-2G} guest/bins.img`
- `mkfs.ext2 -L bins guest/bins.img`
- Creates an empty directory structure: `thhv/`, `cloud-hypervisor/`, `nested/`
- Writes a `version.txt` with build metadata

**New file: `themis/scripts/update-bins.sh`**
- Mounts `bins.img` via `fuse2fs` onto `/tmp/bins_mnt`
- Copies in:
  - `thhv/thhv.ko`
  - `thhv/test/bin/*`
  - `cloud-hypervisor/target/.../cloud-hypervisor`
  - `2026/target/.../…` CLI / test binaries
  - Optionally a nested kernel/initrd
- Writes `version.txt` (git rev, timestamp)
- `fusermount -u`

Both scripts run with zero privileges.

---

### Phase 2 — QEMU integration

**Modify `themis/scripts/run-qemu.sh` and `run-dom0.sh`:**
- If `guest/bins.img` exists, add a second virtio-blk drive:
  ```bash
  BINS_ARGS=""
  if [[ -f "$WORKSPACE_ROOT/guest/bins.img" ]]; then
      BINS_ARGS="-drive id=bins,file=$WORKSPACE_ROOT/guest/bins.img,format=raw,if=none,readonly=on "
      BINS_ARGS+="-device virtio-blk-pci,drive=bins"
  fi
  ```
- This is already the pattern used for the dom0 disk; extend it naturally.

---

### Phase 3 — Guest auto-mount via cloud-init

**Modify `themis/scripts/fetch-dom0.sh` (the `user-data` section):**
Add to `runcmd` in cloud-init:
```yaml
runcmd:
  - mkdir -p /opt/bins
  - |
    cat >> /etc/fstab <<'EOF'
    LABEL=bins  /opt/bins  ext2  ro,nofail,x-systemd.automount  0 0
    EOF
```
The `nofail` flag means dom0 boots normally even if `bins.img` is absent (useful when
booting with seed only, before the bins disk is created).

Alternatively, use a udev rule to trigger mount when `/dev/disk/by-label/bins` appears.

---

### Phase 4 — No-sudo kernel headers fetch

**New file: `themis/scripts/fetch-kheaders.sh`**
- Reads `themis/scripts/dom0-versions.conf` or a new `dom0-kernel-version.txt` file to
  find the pinned kernel version for the active dom0 image.
- Downloads the matching `.deb` files from `http://archive.ubuntu.com/ubuntu/pool/main/l/linux/`
  or uses `apt-get download` (no sudo) into a temp dir.
- Extracts with `dpkg-deb --extract` into `themis/target/kheaders/`.
- Registers the result in a `dom0-versions.conf` field or a sidecar file.

**Modify `thhv/build-guest.sh`:**
- If `KHEADERS_DIR` is set or `themis/target/kheaders/` exists, use that instead of
  mounting the guest.
- Keep the existing NBD-mount path as a fallback (for developers who prefer it and have
  sudo).

---

### Phase 5 — Build orchestration

**New file: `themis/scripts/build-bins.sh`**
Orchestrates all component builds in order:
```
1. cargo build -p capavisor                  (already in build-iso.sh)
2. cargo build --release -p cloud-hypervisor  (in cloud-hypervisor/)
3. cargo build --release (2026 workspace)
4. cargo test --no-run (2026, collect test binaries)
5. make -C thhv KDIR=<kheaders>             (thhv.ko, no mount)
6. make -C thhv tests                        (thhv test binaries)
7. bash scripts/update-bins.sh               (pack everything into bins.img)
```
Exposes as `cargo build-bins` via the xtask alias.

**Flags / knobs:**
- `BINS_TARGETS=thhv,chv,2026`  — build only selected components
- `NESTED_KERNEL=path/to/bzImage`  — include a nested guest kernel
- `PROFILE=release`  — pass through to Rust components

---

### Phase 6 — Full end-to-end workflow (after this refactor)

```bash
# One-time setup (sudo once for tool install only)
sudo apt install e2fsprogs fuse2fs qemu-utils cloud-image-utils xorriso

# First-time project setup (all sudo-free after apt install)
cargo fetch-dom0           # download Ubuntu image + create seed
bash themis/scripts/fetch-kheaders.sh   # download + extract kernel headers
bash themis/scripts/create-bins.sh      # create empty bins.img

# Build everything and pack into bins.img
cargo build-bins

# Boot
SEED=1 cargo dom0          # first boot: provisions cloud user; bins.img attached
cargo dom0                 # subsequent boots

# After any code change, refresh binaries in ~30s:
cargo build-bins && cargo dom0
```

### Refreshing without a full reboot (stretch goal)

If the bins disk is mounted with `rw` inside the guest, a script could do:
```bash
# On host: rebuild + scp directly (no disk re-image needed)
cargo build thhv && scp -P2222 thhv/thhv.ko cloud@localhost:/opt/bins/thhv/
```
This requires dom0 networking (already configured in `run-dom0.sh` with SSH on
`localhost:2222`) and the bins partition to be writable.  Alternately, the image can be
recreated and the VM rebooted (fast with `-no-reboot` already in the QEMU invocations).

---

## Summary of sudo usage before / after

| Operation                        | Before        | After          |
|----------------------------------|---------------|----------------|
| Download Ubuntu image            | no sudo       | no sudo        |
| Create/grow bins disk            | N/A (manual)  | **no sudo**    |
| Update bins disk with artifacts  | sudo (mount)  | **no sudo** (fuse2fs) |
| Build thhv.ko                   | sudo (mount)  | **no sudo** (dpkg headers) |
| Boot dom0 / Themis under QEMU   | no sudo       | no sudo        |
| First-time tool install          | sudo (apt)    | sudo (apt) — once |

---

## Open Questions / Decisions Needed

1. **fuse2fs vs virtiofsd**: fuse2fs (disk image) is simpler to archive and snapshot.
   virtiofsd (shared directory) avoids disk image management but needs an extra process.
   Recommend fuse2fs for now; can migrate to virtiofsd later if live-sync becomes
   important.

2. **bins image size**: 2 GB is plenty for thhv.ko + tests + cloud-hypervisor binary.
   If a nested kernel + rootfs are included, 4–8 GB is safer.  The `create-bins.sh`
   script should make this configurable.

3. **Read-only vs read-write in dom0**: Mounting bins read-only avoids accidental
   corruption and is safe for CI.  For interactive development where you want to write
   scratch files inside the VM, a writable mount on a *copy* of the image (`qemu-img
   create -b bins.img -F raw -f qcow2 bins-rw.qcow2`) keeps the base image pristine.

4. **Kernel version pinning**: We need to decide where to record the guest kernel version
   (for `fetch-kheaders.sh`).  A `dom0-kernel-version.txt` sidecar next to `dom0-versions.conf`
   is the simplest option; alternatively add a `VERSION_noble_KVER` field to the conf file.

5. **Cloud-hypervisor nested image**: If we want a fully automated nested Linux guest,
   we need to decide whether to build it from source, download a prebuilt kernel, or
   reuse the dom0 kernel.  Reusing dom0's kernel (scp'd from the running guest) is the
   path of least resistance.
