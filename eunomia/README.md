# Eunomia

A minimal `no_std` Rust micro-kernel for x86-64 designed to run as a guest
domain inside the [Themis](../README.md) capability-based hypervisor.

Named after the Greek goddess of lawful order, daughter of Themis.

## Overview

Eunomia boots via the PVH protocol (used by Cloud Hypervisor), sets up a
64-bit execution environment with GDT, TSS, and IDT, and dispatches to a
workload-defined `app_main` entry point.  It is intentionally tiny — the full
kernel fits in a few hundred lines of Rust plus a small assembly boot stub.

Key properties:

- **PVH boot**: 32→64 bit transition, identity-mapped page tables (4 GiB)
- **GDT + TSS**: code/data segments, IST1 for double-fault isolation
- **IDT**: 32 exception vectors with full register-dump handler, timer ISR
- **LAPIC timer**: one-shot mode, tick counter
- **Bump allocator**: `GlobalAlloc` — `Box`, `Vec`, `String` work out of the box
- **Workload model**: independent crates linked against the eunomia runtime
- **Test harness**: declarative tests, clean exit on both QEMU and CHV

See [docs/architecture/eunomia.md](../docs/architecture/eunomia.md) for the
full design document.  See [docs/architecture/eunomia-roadmap.md](../docs/architecture/eunomia-roadmap.md)
for the roadmap (CHV boot, CoCo, core-gapping).

## Prerequisites

- Rust nightly (managed by `rust-toolchain.toml`)
- QEMU with KVM (`qemu-system-x86_64`) — for local testing
- Cloud Hypervisor (`cloud-hypervisor`) — for real PVH boot testing
- KVM access (`/dev/kvm`)

## Project Structure

```
eunomia/
├── Cargo.toml              # Kernel library crate
├── .cargo/config.toml      # x86_64-unknown-none target, QEMU runner
├── rust-toolchain.toml     # Nightly toolchain (independent from themis/)
├── build.rs                # Linker script path
├── linker.ld               # PVH layout: load at 0x100000, PT_NOTE segment
├── src/
│   ├── lib.rs              # Crate root, re-exports all modules
│   ├── boot.rs             # PVH boot asm, rust_main, panic handler
│   ├── serial.rs           # COM1 UART driver, print!/println! macros
│   ├── timer.rs            # LAPIC one-shot timer driver
│   ├── mm.rs               # Bump allocator with GlobalAlloc
│   ├── gdt.rs              # GDT with TSS, IST1 double-fault stack
│   ├── idt.rs              # IDT, 32 exception stubs, timer ISR
│   ├── sched.rs            # Cooperative round-robin scheduler
│   ├── hv.rs               # HypervisorInterface trait, Themis/Stub backends
│   └── test_harness.rs     # TestCase, runner, VMM-aware exit
├── scripts/
│   ├── run-chv.sh          # Standalone CHV launcher (takes ELF path)
│   └── run-chv-runner.sh   # Cargo-compatible CHV runner (used by alias)
└── workloads/
    ├── smoke/              # Smoke tests: serial, GDT, IDT, stack
    ├── timer/              # Timer interrupt test
    ├── memory/             # Heap allocator tests (Box, Vec, alignment)
    ├── sched/              # Cooperative scheduler context-switch tests
    ├── hypercall/          # Hypervisor interface trait + constant tests
    └── pvh-info/           # PVH hvm_start_info validation (CHV-specific)
```

## Building

```bash
cd eunomia/

# Build the kernel library
cargo build --release

# Build a workload
cd workloads/smoke && cargo build --release
```

## Running Workloads

Each workload is an independent binary crate under `workloads/`.
Two runners are available:

| Command | VMM | Boot path | Notes |
|---------|-----|-----------|-------|
| `cargo run --release` | QEMU microvm | Linux boot protocol | Default, fast iteration |
| `cargo run-chv` | Cloud Hypervisor | Real PVH boot | Validates hvm_start_info, ACPI shutdown |

### Under QEMU (default)

```bash
cd workloads/smoke && cargo run --release
```

### Under Cloud Hypervisor

```bash
cd workloads/smoke && cargo run-chv
```

Requires `cloud-hypervisor` in PATH, or set `CHV=/path/to/cloud-hypervisor`.
You can also tune resources: `CHV_CPUS=2 CHV_MEM=256M cargo run-chv`.

For standalone use (without cargo alias):
```bash
scripts/run-chv.sh workloads/smoke/target/x86_64-unknown-none/release/eunomia-smoke
```

### Available workloads

| Workload | Tests | Description |
|----------|-------|-------------|
| `smoke` | 4 | Serial, GDT, IDT, stack sanity |
| `timer` | 1 | LAPIC one-shot timer interrupt |
| `memory` | 5 | Heap: Box, Vec, alignment, stats |
| `sched` | 4 | Cooperative scheduler context switching |
| `hypercall` | 5 | HypervisorInterface trait + constants |
| `pvh-info` | 5 | hvm_start_info parsing (magic, memmap, RSDP) |

Example — run any workload:
```bash
cd workloads/<name> && cargo run-chv    # Cloud Hypervisor (PVH)
cd workloads/<name> && cargo run --release  # QEMU (microvm)
```

### Writing a new workload

Create a new crate under `workloads/`:

```
workloads/mywork/
├── Cargo.toml    # depends on eunomia = { path = "../.." }
├── build.rs      # points to ../../linker.ld
└── src/main.rs
```

The `main.rs` must define `app_main`:

```rust
#![no_std]
#![no_main]
extern crate eunomia;

#[no_mangle]
pub fn app_main(services: &eunomia::KernelServices) -> ! {
    eunomia::println!("Hello from my workload!");
    loop { unsafe { core::arch::asm!("hlt"); } }
}
```

## Exit Mechanism

The test harness uses a VMM-aware exit sequence:

1. **CHV**: ACPI shutdown (port `0x600`, S5 sleep) — clean exit, code 0
2. **QEMU**: `isa-debug-exit` (port `0xF4`) — exit code 1 = success, 3 = failure
3. **Fallback**: HLT loop

## Notes

- **QEMU microvm ≠ PVH**: QEMU's microvm uses SeaBIOS / Linux boot protocol.
  The 32→64 transition works, and basic hvm_start_info is populated, but the
  full PVH experience (RSDP, memory map) is best tested under CHV.
- **No SSE**: floating-point / SIMD is disabled (`-C target-feature=-sse,-sse2`)
  since the FPU is not explicitly initialised.
- Eunomia is a standalone crate, independent from the `themis/` workspace.
