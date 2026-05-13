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
- **Test harness**: declarative tests, QEMU `isa-debug-exit` for CI

See [docs/architecture/eunomia.md](../docs/architecture/eunomia.md) for the
full design document (trait-based configurable core, future phases).

## Prerequisites

- Rust nightly (managed by `rust-toolchain.toml`)
- QEMU with KVM (`qemu-system-x86_64`)
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
│   └── test_harness.rs     # TestCase, runner, QEMU exit codes
└── workloads/
    ├── smoke/              # Smoke tests: serial, GDT, IDT, stack
    ├── timer/              # Timer interrupt test
    └── memory/             # Heap allocator tests (Box, Vec, alignment)
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
Run with `cargo run --release` from the workload directory.

### Smoke tests

Verifies serial output, GDT, IDT, and stack are operational.

```bash
cd workloads/smoke && cargo run --release
```

### Timer test

Verifies the LAPIC one-shot timer fires and increments the tick counter.

```bash
cd workloads/timer && cargo run --release
```

### Memory allocator test

Verifies heap allocation: Box, Vec, large allocations, alignment, heap stats.

```bash
cd workloads/memory && cargo run --release
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

## Exit Codes

The test harness uses QEMU's `isa-debug-exit` device (port `0xF4`):

| Write value | QEMU exit code | Meaning |
|-------------|----------------|---------|
| `0x00`      | `1`            | All tests passed |
| `0x01`      | `3`            | One or more tests failed |

## Notes

- **QEMU microvm ≠ PVH**: the QEMU runner uses SeaBIOS, not true PVH boot.
  The 32→64 transition runs correctly, but `hvm_start_info` is not valid.
  Real PVH boot testing requires Cloud Hypervisor as the VMM.
- **No SSE**: floating-point / SIMD is disabled (`-C target-feature=-sse,-sse2`)
  since the FPU is not explicitly initialised.
- Eunomia is a standalone crate, independent from the `themis/` workspace.
