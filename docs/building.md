# Building Themis

This guide covers building all components of the Themis capability hypervisor.
Each component can be built independently. For detailed usage, see the
per-component READMEs linked below.

## Prerequisites

- **Rust** (nightly) — `rustup` with `x86_64-unknown-none` and `x86_64-unknown-linux-gnu` targets
- **C toolchain** — `gcc`, `make` (for `thhv.ko` kernel module)
- **QEMU** — for booting Themis and dom0
- **Host packages** (Ubuntu/Debian):
  ```bash
  sudo apt install e2fsprogs fuse2fs qemu-utils cloud-image-utils xorriso
  ```

### Optional

- **Lean 4** — for `lean-exec` differential testing (`elan` toolchain manager)
- **AArch64 cross toolchain** — `aarch64-linux-gnu-gcc` for ARM builds
- **Docker** — for containerized builds (`cargo build-bins-docker`)

## Quick Reference

All commands run from the **repo root** unless noted otherwise.

| Component | Command | Output | Details |
|-----------|---------|--------|---------|
| Capability engine tests | `cd capa-engine && cargo test` | — | [capa-engine/README](../capa-engine/README.md) |
| Concurrency tests (loom) | `cd capa-engine && cargo loom` | — | [capa-engine/README](../capa-engine/README.md) |
| CLI simulator | `cd capa-cli && cargo build --release` | `target/release/capa-cli` | [capa-cli/README](../capa-cli/README.md) |
| Lean executable model | `cd lean-exec && lake build` | `.lake/build/` | [lean-exec/README](../lean-exec/README.md) |
| Differential tests | `cd capa-cli && cargo test` | — | [capa-cli/README](../capa-cli/README.md) |
| Full binary build | `cargo build-bins` | `themis/guest/bins.img` | [themis/scripts/README](../themis/scripts/README.md) |
| CoCo guest kernel | `cargo build-kernel` | `themis/guest/kernel/bzImage` | [themis/scripts/README](../themis/scripts/README.md) |
| Themis ISO + QEMU boot | `cd themis && cargo themis` | boots in QEMU | [themis/README](../themis/README.md) |
| AArch64 (QEMU) | `cd themis && cargo aarch64-direct` | boots in QEMU | [docs/architecture/arm-porting](architecture/arm-porting.md) |

## First-Time Setup

### 1. Clone and prepare

```bash
git clone --recurse-submodules https://github.com/aghosn/capability-v5.git
cd capability-v5
```

### 2. Set up Limine boot assets

```bash
cd themis && cargo setup-limine && cd ..
```

### 3. Fetch dom0 image

```bash
cd themis && cargo fetch-dom0 && cd ..
```

### 4. Fetch kernel headers (for thhv.ko)

```bash
bash themis/scripts/fetch-kheaders.sh
```

### 5. Create artifact disk

```bash
bash themis/scripts/create-bins.sh
```

### 6. Build everything

```bash
cargo build-bins
```

### 7. Boot

```bash
cd themis
SEED=1 cargo themis    # first boot (cloud-init provision)
cargo themis           # subsequent boots
```

## Component Details

### Capability Engine (`capa-engine/`)

The platform-agnostic capability engine. Pure Rust, `no_std` compatible.

```bash
cd capa-engine
cargo test              # unit + integration tests
cargo loom              # deterministic concurrency tests
```

### CLI Simulator (`capa-cli/`)

Interactive command-line interface for the capability engine. Also used for
differential testing against the Lean executable model.

```bash
cd capa-cli
cargo build --release                       # build
cargo run --release                         # interactive REPL
cargo run --release -- -f tutos/01-*.txt    # run a tutorial script
cargo test                                  # differential tests (Rust vs Lean)
```

### Lean Executable Model (`lean-exec/`)

Executable Lean 4 specification of the capability engine, used for formal
verification and differential testing.

```bash
cd lean-exec
lake build       # build the Lean model
lake exe repl    # interactive REPL
```

### Capavisor + thhv + CHV (`cargo build-bins`)

Builds the bare-metal hypervisor (capavisor), Linux kernel module (thhv.ko),
and cloud-hypervisor fork (CHV), then packs them into `themis/guest/bins.img`.

```bash
# From repo root:
cargo build-bins                           # native build
cargo build-bins-docker                    # Docker build (if host toolchain issues)

# Build individual targets:
BINS_TARGETS=capavisor cargo build-bins    # capavisor only
BINS_TARGETS=thhv cargo build-bins         # thhv.ko only
BINS_TARGETS=chv cargo build-bins          # cloud-hypervisor only
```

See [themis/scripts/README](../themis/scripts/README.md) for the full script
reference and environment variables.

### CoCo Guest Kernel (`cargo build-kernel`)

Custom Linux kernel with `CONFIG_THEMIS_COCO` for confidential child domains.
Requires the [aghosn/linux](https://github.com/aghosn/linux) fork on branch
`v6.19.14-themis` cloned next to this repo.

```bash
# From repo root:
cargo build-kernel                                    # bzImage only
TARGETS=all cargo build-kernel                        # bzImage + modules
LINUX_DIR=/custom/path JOBS=16 cargo build-kernel     # custom path
```

Output: `themis/guest/kernel/bzImage`

See [themis/scripts/README](../themis/scripts/README.md) §Building the Themis
CoCo guest kernel for full details.

### AArch64

Cross-compile and boot the capavisor on QEMU aarch64:

```bash
cd themis
cargo aarch64-direct    # direct EL2 boot (current default)
```

See [docs/architecture/arm-porting](architecture/arm-porting.md) for the porting
design and milestone status.

## Day-to-Day Workflow

```bash
# Edit code → rebuild → reboot:
cargo build-bins && cd themis && cargo themis

# Run dom0 without Themis (faster iteration):
cd themis && cargo dom0

# Debug with GDB:
cd themis && cargo themis-debug
# In another terminal:
cd themis && cargo gdb
```

## Docker Build Path

If you don't want to install the full native toolchain:

```bash
# One-time: build the container image
docker build -f Dockerfile.build -t themis-build:latest .

# Build artifacts inside Docker:
cargo build-bins-docker
```
