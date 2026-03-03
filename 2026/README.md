# Capability Engine V2

A `no_std`-compatible, thread-safe Rust implementation of a capability-based security system for composable isolation, based on the research paper *"Composable Isolation as a Foundation to Manage Trust in the Cloud"* (EuroS&P 2026).

## Overview

The capability engine provides a principled mechanism for partitioning resources — memory and execution — into mutually isolated **trust domains**. Every resource is represented as a node in a tree called the **Capability Derivation Tree (CDT)**. Authority flows strictly downward: a child can hold at most the rights its parent holds. This single rule is the foundation of all security properties the engine provides.

The engine is designed for use in hypervisors, monitors, and bare-metal runtimes. It has no OS dependencies (only `alloc` is required) and exposes a clean `Platform` trait so that hardware-specific operations (page-table updates, TLB shootdowns, IPI delivery) can be plugged in separately from the capability logic.

For detailed design and semantics documentation, see [`docs/`](docs/).

## Source Code Layout

```
src/
├── lib.rs          — crate entry point; re-exports the public API
├── error.rs        — CapaError type and Result alias
├── capability.rs   — generic Capability<T> struct, CDT traversal, address-space view
├── memory.rs       — MemoryRegion, Access, Rights, Attributes, carve/alias logic
├── domain.rs       — Domain, DomainPolicy, MonitorAPI, VProcessorState, interrupt policy
├── update.rs       — Update enum, UpdateBatch, UpdateProcessor (simulation helper)
├── platform.rs     — Platform trait, execute() helper and IPI/barrier protocol
├── switch.rs       — SwitchManager, CoreContext, VP call-chain and interrupt routing
├── attest.rs       — attestation report generation for domains and memory regions
├── view.rs         — compute the merged address-space view for a domain
└── sync.rs         — internal RwLock abstraction (parking_lot / spin / loom)
```

## Build and Test

### Build

```bash
# Hosted environment (default — uses parking_lot)
cargo build --lib

# Bare-metal target (no OS, no libc)
cargo build --no-default-features --lib --target x86_64-unknown-none

# Check no_std compatibility without cross-compiling
cargo check --lib --no-default-features
```

### Tests

```bash
# Run all unit and integration tests
cargo test

# Run a specific test suite
cargo test --test unit_memory
cargo test --test integration_revoke
```

### Loom (exhaustive concurrency testing)

[loom](https://github.com/tokio-rs/loom) systematically explores every valid thread interleaving. Run in release mode — loom's bookkeeping is CPU-intensive.

```bash
cargo test --test loom_concurrency --features loom --release
cargo test --test loom_e2e        --features loom --release
cargo test --test loom_vp_switch  --features loom --release
```

### Coverage

[cargo-tarpaulin](https://github.com/xd009642/tarpaulin) is configured as a custom cargo command:

```bash
# Summary printed to stdout; lcov report written to target/tarpaulin/lcov.info
cargo coverage
```

The lcov report can be consumed by editors and CI pipelines, or converted to HTML via `genhtml`.
