# Eunomia

A minimal `no_std` Rust micro-kernel for x86-64 designed to run as a guest
domain inside the [Themis](../README.md) capability-based hypervisor.

Named after the Greek goddess of lawful order, daughter of Themis.

## Overview

Eunomia boots via the PVH protocol (used by Cloud Hypervisor), sets up a
64-bit execution environment with GDT, TSS, and IDT, and dispatches to a
compile-time-selected **workload**.  It is intentionally tiny — the full
kernel fits in a few hundred lines of Rust plus a small assembly boot stub.

Key properties:

- **PVH boot**: 32→64 bit transition, identity-mapped page tables (4 GiB)
- **GDT + TSS**: code/data segments, IST1 for double-fault isolation
- **IDT**: 32 exception vectors with full register-dump handler, timer ISR
- **LAPIC timer**: one-shot mode, tick counter
- **Workload model**: feature-gated workloads with `app_main` entry point
- **Test harness**: declarative tests, QEMU `isa-debug-exit` for CI

See [docs/architecture/eunomia.md](../docs/architecture/eunomia.md) for the
full design document (trait-based configurable core, future phases).

## Prerequisites

- Rust nightly (managed by `rust-toolchain.toml`)
- QEMU with KVM (`qemu-system-x86_64`)
- KVM access (`/dev/kvm`)

## Building

```bash
cd eunomia/

# Build the default workload (smoke tests)
cargo build --release

# Build a specific workload
cargo build --release --no-default-features --features "console-serial,app-timer"
```

The binary is produced at `target/x86_64-unknown-none/release/eunomia`.

## Project Structure

```
eunomia/
├── Cargo.toml          # lib+bin crate, feature-based workload selection
├── .cargo/config.toml  # x86_64-unknown-none target, QEMU runner
├── rust-toolchain.toml # Nightly toolchain (independent from themis/)
├── build.rs            # Linker script path
├── linker.ld           # PVH layout: load at 0x100000, PT_NOTE segment
└── src/
    ├── lib.rs           # KernelServices, re-exports serial/timer/test_harness
    ├── main.rs          # PVH boot asm, GDT/IDT init, workload dispatch
    ├── serial.rs        # COM1 UART driver, print!/println! macros
    ├── timer.rs         # LAPIC one-shot timer driver
    ├── gdt.rs           # GDT with TSS, IST1 double-fault stack
    ├── idt.rs           # IDT, 32 exception stubs, timer ISR
    ├── test_harness.rs  # TestCase, runner, QEMU exit codes
    └── workloads/
        ├── mod.rs       # Feature-gated dispatch to workload app_main
        ├── smoke.rs     # Smoke tests: serial, GDT, IDT, stack
        └── timer.rs     # Timer interrupt test
```

## Running Workloads

Each workload is selected at compile time via Cargo features.  `cargo run`
boots Eunomia under QEMU (configured in `.cargo/config.toml`).

### Smoke tests (default)

Verifies serial output, GDT, IDT, and stack are operational.

```bash
cargo run --release
```

Expected output:

```
Eunomia v0.1.0 booted
[ok] GDT loaded (with TSS)
[ok] IDT loaded (32 exception vectors)
--- running 4 tests ---
test serial_output ... ok
test gdt_loaded ... ok
test idt_loaded ... ok
test stack_sanity ... ok
--- results: 4 passed, 0 failed ---
```

### Timer test

Verifies the LAPIC one-shot timer fires and increments the tick counter.

```bash
cargo run --release --no-default-features --features "console-serial,app-timer"
```

Expected output:

```
--- running 1 tests ---
test timer_fires ... ok
--- results: 1 passed, 0 failed ---
```

### Writing a new workload

1. Create `src/workloads/mywork.rs` with a `pub fn app_main(_: &eunomia::KernelServices) -> !`
2. Add a feature `app-mywork = []` in `Cargo.toml`
3. Wire it in `src/workloads/mod.rs` with `#[cfg(feature = "app-mywork")]`
4. Run: `cargo run --release --no-default-features --features "console-serial,app-mywork"`

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
