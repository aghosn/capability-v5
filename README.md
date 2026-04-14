# Capability-v5 — Themis Capavisor

## Background

This project is a ground-up reimplementation of Tyche,
a security monitor that enforces capability-based isolation on x86_64 hardware.  The original
Tyche was built before the modern LLM era and before Rust's system-programming story had
matured to what it is today.  After completing that full end-to-end implementation — painfully
by hand — we decided to start fresh, using the lessons learned and the original code as a
reference, but rebuilt with modern tooling and AI-assisted development.

**What's different in this rewrite:**

- **Agent-assisted development.** The implementation is co-developed with LLM coding agents.
  This changes the economics of what's tractable: large, repetitive, or boilerplate-heavy
  subsystems (VMX exit handlers, ioctl dispatch, trait implementations) that were painful to
  write by hand are now fast to produce and iterate on.

- **Full heap inside the capavisor.** The original Tyche used a carefully hand-managed static
  memory model.  Here the capavisor has a `GlobalAlloc` backed by a bump-then-free allocator,
  so Rust's standard data structures (`Vec`, `Arc`, `BTreeMap`, …) work natively inside the
  hypervisor.  This dramatically simplifies the capability engine and reduces the surface area
  for manual memory bugs.

- **No KVM compatibility.** Tyche and our drivers maintained KVM compatibility, which imposed significant
  structural constraints.  This rewrite targets its own kernel driver (`thhv`) and VMCS
  management path, freed from the KVM interface.

- **Modern Rust idioms.** `alloc` is available throughout; the codebase uses `Arc`-based
  capability handles, `Result`-based error propagation, and trait objects where appropriate,
  rather than C-style struct-of-function-pointers and manual reference counting.

The original Tyche remains the authoritative reference for the security model, attestation
design, and hardware interaction patterns.  Where this rewrite diverges, the design rationale
is documented in [`CONTEXT.md`](CONTEXT.md) and the design docs under
[`capa-engine/docs/design/`](capa-engine/docs/design/).

---

## What it is

Themis is a bare-metal capability hypervisor targeting x86_64 (production) and
AArch64 (in progress).  It runs as the first OS layer
on the machine (loaded by Limine) and manages hardware resources as first-class capabilities
(memory regions, CPUs, I/O) handed out to guest domains.  **Dom0** is the first and
 guest domain, running a full Linux image (Ubuntu Noble) inside a VM managed
by a custom [cloud-hypervisor](cloud-hypervisor/) backend wired to the Themis
kernel driver (`thhv.ko`).

For design principles and architectural constraints see [`CONTEXT.md`](CONTEXT.md).

---

## Repository layout

```
themis/             Capavisor source (bare-metal Rust, x86_64-unknown-none)
  capavisor/        Main capavisor binary (hypervisor kernel)
  crates/           Shared crates: themis-abi, capability-engine, …
  scripts/          Host-side build & run scripts
  guest/            Runtime artifacts: dom0.qcow2, bins.img, seed.img (git-ignored)
  target/           Build output (git-ignored)
thhv/               Linux kernel module — Themis host-to-VM interface (/dev/thhv)
cloud-hypervisor/   Forked cloud-hypervisor with Themis VMM backend (submodule)
capa-engine/           Capability engine (no_std Rust library) (EuroS&P paper, design docs, tools)
Dockerfile.build    Build environment image (Ubuntu 24.04 + Rust nightly + LLVM)
```

---

## Quick start — running dom0 on Themis

This is the primary workflow: boot capavisor, which then starts dom0 as a VM

```
[Physical/QEMU machine]
  Limine bootloader
    └─► capavisor (bare-metal hypervisor)
          └─► dom0 Linux (Ubuntu Noble) as a Themis VM, i.e., a Dom
```

### Prerequisites

**Native build (recommended):**
```bash
sudo apt install e2fsprogs fuse2fs qemu-utils cloud-image-utils xorriso
# Also required: Rust nightly, make, gcc/clang toolchain
```

**Docker build (older-kernel hosts):**
```bash
# Only Docker is needed; all build tools are inside the container.
docker build -f Dockerfile.build -t themis-build:latest .
```

### First-time setup

All commands are run from the `themis/` subdirectory:

```bash
cd themis

# 1. Set up Limine boot assets (one-time)
cargo setup-limine

# 2. Fetch the dom0 Ubuntu image and cloud-init seed
cargo fetch-dom0

# 3. Fetch pinned kernel headers for thhv.ko
bash scripts/fetch-kheaders.sh

# 4. Create the artifact disk (bins.img)
bash scripts/create-bins.sh

# 5. Build all artifacts and pack into bins.img
cargo build-bins               # native
# or:
cargo build-bins-docker        # Docker (from repo root)
```

> **Docker note:** `cargo build-bins-docker` must be run from the **repo root**
> (not `themis/`), as `build-bins` aliases live in the root `.cargo/config.toml`.
> All other `cargo themis` / `cargo dom0` / etc. commands are run from `themis/`.

### Run dom0 on Themis

```bash
cd themis

# First boot: attach cloud-init seed to provision the guest
SEED=1 cargo themis

# All subsequent boots:
cargo themis
```

This builds the Themis ISO, launches QEMU with UEFI, boots capavisor, and starts
cloud-hypervisor inside dom0.

**Dom0 login:**
- Serial console (in the QEMU window)
- SSH: `ssh -p 2222 cloud@localhost`  (password: `cloud123`)

### Day-to-day workflow

```bash
cd themis

# After any code change — rebuild and reboot:
cargo build-bins && cargo themis

# Or with Docker for the build step:
cargo build-bins-docker && cargo themis
# (run cargo build-bins-docker from repo root, then cargo themis from themis/)
```

---

## Running dom0 without Themis (bare QEMU)

Useful for quickly iterating on dom0 configuration, cloud-init, or the `thhv` driver
without needing to rebuild the capavisor ISO.

```bash
cd themis

SEED=1 cargo dom0    # first boot (cloud-init)
cargo dom0           # subsequent boots
```

Dom0 still gets `bins.img` mounted at `/opt/bins`.

---

## Debugging

```bash
cd themis

# Boot Themis with a QEMU GDB stub (waits for debugger before starting)
cargo themis-debug

# In a second terminal, attach GDB:
cargo gdb
```

The GDB stub listens on `localhost:1234` by default (`GDB_PORT` to override).

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `PROFILE` | `debug` | `release` enables `--release` for Rust builds |
| `SEED` | unset | Set to `1` to attach `guest/seed.img` on next boot |
| `QEMU_CPUS` | `4` | vCPU count |
| `QEMU_MEM` | `4G` | Guest RAM |
| `QEMU_ENABLE_KVM` | `1` | Use KVM acceleration when available |
| `BINS_TARGETS` | `all` | Comma-separated subset: `capavisor,chv,capa-engine,thhv` |

Full variable reference: [`themis/scripts/README.md`](themis/scripts/README.md).

---

## Artifact locations inside dom0

After a successful boot, inside dom0:

```
/opt/bins/thhv/thhv.ko               Themis kernel module
/opt/bins/cloud-hypervisor/           cloud-hypervisor binary
/opt/bins/capa-engine/capa-engine  capability engine test binary
/home/cloud/bins -> /opt/bins         convenience symlink
```

To load the Themis driver:
```bash
sudo insmod /opt/bins/thhv/thhv.ko
ls /dev/thhv   # should appear
```

---

## Multi-ISA build (x86_64 / AArch64)

The capavisor and capability engine are structured for multi-ISA support.
Platform-specific code is behind `#[cfg(target_arch = "...")]` gates so that
architecture-agnostic logic compiles on any target.

### x86_64 (full build + run)

This is the primary development target. All binaries (capavisor, thhv.ko,
cloud-hypervisor) build and run on x86_64:

```bash
# Ensure the x86_64 bare-metal target is installed
rustup target add x86_64-unknown-none

# Build everything (capavisor, thhv.ko, cloud-hypervisor, bins.img)
cargo build-bins

# Run engine unit tests
cd capa-engine && cargo test

# Boot capavisor + dom0 under QEMU
cd themis && cargo themis
```

### AArch64 (cross-check — type-checks only)

The AArch64 backend is under development. You can cross-check that the
capavisor compiles for `aarch64-unknown-none` (no linker output yet):

```bash
# Install the AArch64 bare-metal target
rustup target add aarch64-unknown-none

# Type-check the capavisor (cargo check skips linking)
cd themis/capavisor && cargo check --target aarch64-unknown-none -p capavisor

# Type-check the capability engine library
cd capa-engine && cargo check --target aarch64-unknown-none --no-default-features --lib
```

> **Note:** `cargo build` for aarch64 fails at the link stage because there is
> no AArch64 linker script yet.  Use `cargo check` to verify compilation.
> The engine binary (`capa-engine` bin target) pulls in `parking_lot` which
> doesn't support `aarch64-unknown-none`; use `--lib` to check the library only.

### What compiles where

| Component | x86_64 | aarch64 | Notes |
|---|---|---|---|
| `capa-engine` (lib) | ✅ build + test | ✅ check | Platform-agnostic capability engine |
| `capa-engine` (bin) | ✅ build + test | ❌ | Binary pulls in std-dependent deps |
| `capavisor` | ✅ build + run | ✅ check | aarch64 has stubs, no linker script yet |
| `thhv.ko` | ✅ build | ❌ | Linux x86_64 kernel module |
| `cloud-hypervisor` | ✅ build | ❌ | x86_64 VMM (git submodule) |

### Architecture design docs

- [`themis/docs/platform-modularization.md`](themis/docs/platform-modularization.md) —
  trait-based platform abstraction, cfg-gating strategy, phase tracker
- [`themis/docs/arm-porting-design.md`](themis/docs/arm-porting-design.md) —
  AArch64 EL2 porting plan, GICv3, Stage-2 page tables, QEMU testbed

---

## Further reading

- [`CONTEXT.md`](CONTEXT.md) — design axioms, component map, hypercall ABI, conventions
- [`themis/scripts/README.md`](themis/scripts/README.md) — full script and variable reference
- [`capa-engine/docs/design/`](capa-engine/docs/design/) — design documents (attestation, address translation, interrupt virtualisation)
- [`todo.md`](todo.md) — implementation task tracker
