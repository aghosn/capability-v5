# Themis — Capability-Based Bare-Metal Hypervisor

Themis is a bare-metal capability hypervisor for x86_64 and AArch64
(in progress). It enforces capability-based composable isolation at the hardware level:
memory regions, CPUs, and I/O are first-class capabilities handed out to guest
domains. No domain — including dom0 — has special privileges.

```
L2  Nested Guest (Linux VM)      ← managed by cloud-hypervisor
L1  Dom0 (Ubuntu + thhv.ko)     ← first domain, NOT privileged
L0  Capavisor (Themis)           ← bare-metal, capability-enforced
    Hardware (x86-64 VT-x/VT-d)
```

For the full architecture, design axioms, and invariants see
[`CONTEXT.md`](CONTEXT.md).

## Background

This is a ground-up reimplementation of
[Tyche](https://music.epfl.ch/publications/), rebuilt with modern Rust tooling
and AI-assisted development. Key differences from the original:

- **Full heap inside the capavisor** — `Vec`, `Arc`, `BTreeMap` work natively
- **No KVM compatibility** — own kernel driver (`thhv`), freed from KVM constraints
- **Formal verification** — executable Lean 4 model with 83 proved safety theorems
- **Multi-ISA** — platform-agnostic engine, AArch64 porting underway instead of the original RISC-V

## Repository Layout

| Directory | Description | README |
|-----------|-------------|--------|
| [`capa-engine/`](capa-engine/) | Capability engine — platform-agnostic `no_std` Rust library | [README](capa-engine/README.md) |
| [`capa-cli/`](capa-cli/) | Interactive CLI simulator with Rust & Lean backends | [README](capa-cli/README.md) |
| [`lean-exec/`](lean-exec/) | Executable Lean 4 model for differential testing & formal verification | [README](lean-exec/README.md) |
| [`themis/`](themis/) | Capavisor (bare-metal hypervisor) + build scripts | [README](themis/README.md) |
| [`thhv/`](thhv/) | Linux kernel module — dom0↔capavisor interface (`/dev/thhv`) | [README](thhv/README.md) |
| [`cloud-hypervisor/`](cloud-hypervisor/) | Forked cloud-hypervisor with Themis VMM backend (submodule) | — |
| [`docs/`](docs/) | Project-wide documentation | see below |

### Documentation (`docs/`)

| Path | Contents |
|------|----------|
| [`docs/building.md`](docs/building.md) | **Unified build guide** — all components, first-time setup, day-to-day workflow |
| [`docs/architecture/`](docs/architecture/) | Design documents: confidential VMs, address translation, interrupts, attestation, ARM porting, platform modularization |
| [`docs/capability-engine/`](docs/capability-engine/) | Engine deep-dive: semantics, implementation details, CLI tutorials |
| [`docs/domain-comm.md`](docs/domain-comm.md) | Domain communication protocol (thhv ↔ capavisor ABI) |
| [`docs/archive/`](docs/archive/) | Historical docs: old implementation plans, superseded semantics, session notes |

## Getting Started

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt install e2fsprogs fuse2fs qemu-utils cloud-image-utils xorriso
# Also: Rust nightly, make, gcc
```

### First boot

```bash
cd themis
cargo setup-limine              # one-time: Limine boot assets
cargo fetch-dom0                # one-time: Ubuntu Noble image
bash scripts/fetch-kheaders.sh  # one-time: kernel headers for thhv.ko
bash scripts/create-bins.sh     # one-time: create artifact disk

cargo build-bins                # build capavisor + thhv + CHV (from repo root)
SEED=1 cargo themis             # first boot (cloud-init provision)
cargo themis                    # subsequent boots
```

**Dom0 login:** SSH `ssh -p 2222 cloud@localhost` (password: `cloud123`)

For the full build guide covering all components see
[**docs/building.md**](docs/building.md).

## Key Components

### Capability Engine

Platform-agnostic `no_std` library that validates all resource operations before
any hardware change. Domain creation, memory carve/alias/send/revoke, VP
switching, channels — all mediated through capabilities.

```bash
cd capa-engine && cargo test    # unit + integration tests
cd capa-engine && cargo loom    # deterministic concurrency tests
```

### Differential Testing (Lean ↔ Rust)

Two independent implementations of the same spec: the Rust production engine and
an executable Lean 4 model. Both consume the same CLI scripts and must produce
identical output.

```bash
cd capa-cli
cargo build --release --features lean-backend
bash regression/run-diff.sh --with-tutos     # run all differential tests
```

See [capa-cli/README](capa-cli/README.md) and [lean-exec/README](lean-exec/README.md).

### Multi-ISA (x86_64 / AArch64)

| Component | x86_64 | AArch64 |
|-----------|--------|---------|
| capa-engine (lib) | ✅ build + test | ✅ check |
| capavisor | ✅ build + run | ✅ QEMU boot (M6) |
| thhv.ko | ✅ build | — |
| cloud-hypervisor | ✅ build | — |

AArch64 boots Linux on QEMU (EL2, GICv3, Stage-2, PSCI). See
[docs/architecture/arm-porting.md](docs/architecture/arm-porting.md).

## Further Reading

- [`CONTEXT.md`](CONTEXT.md) — axioms, architecture, design decisions, hypercall ABI
- [`docs/building.md`](docs/building.md) — unified build guide
- [`docs/architecture/`](docs/architecture/) — design documents
- [`themis/scripts/README.md`](themis/scripts/README.md) — full script & variable reference
- [`todo.md`](todo.md) — implementation task tracker
