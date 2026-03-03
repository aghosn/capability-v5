# Implementation Overview

This document describes how the capability engine's modules fit together.

## Module Map

```
┌─────────────────────────────────────────────────────────────────┐
│                        capability-engine                         │
│                                                                  │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐ │
│  │  memory.rs   │   │  domain.rs   │   │     switch.rs        │ │
│  │ MemoryRegion │   │   Domain     │   │   SwitchManager      │ │
│  │ Rights       │   │ DomainPolicy │   │   VP states          │ │
│  │ Attributes   │   │ MonitorAPI   │   │   interrupt routing  │ │
│  └──────┬───────┘   └──────┬───────┘   └──────────────────────┘ │
│         │                  │                                      │
│         └──────────┬───────┘                                      │
│                    ▼                                              │
│           ┌─────────────────┐                                     │
│           │  capability.rs  │                                     │
│           │  Capability<T>  │  ← generic tree node               │
│           │  CDT traversal  │                                     │
│           │  carve/alias/   │                                     │
│           │  send/revoke    │                                     │
│           └────────┬────────┘                                     │
│                    │ produces                                      │
│                    ▼                                              │
│           ┌─────────────────┐                                     │
│           │   update.rs     │  ← hardware change descriptors     │
│           │ UpdateBatch     │                                      │
│           │ UpdateProcessor │  ← simulation queue helper         │
│           └────────┬────────┘                                     │
│                    │ applied via                                   │
│                    ▼                                              │
│           ┌─────────────────┐                                     │
│           │  platform.rs    │  ← hardware abstraction            │
│           │  Platform trait │                                     │
│           │  execute()      │  ← lock + operate + IPI            │
│           └─────────────────┘                                     │
│                                                                   │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐  │
│  │   view.rs    │   │  attest.rs   │   │      sync.rs         │  │
│  │ address-space│   │ attestation  │   │ RwLock abstraction   │  │
│  │ view compute │   │ reports      │   │ (parking_lot/spin/   │  │
│  └──────────────┘   └──────────────┘   │       loom)          │  │
│                                         └──────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Module Roles

| Module | Role |
|--------|------|
| `memory.rs` | Defines `MemoryRegion`, `Access`, `Rights`, `Attributes`, `RegionKind`, `RegionStatus`. Contains the carve and alias logic (containment checks, overlap rejection). |
| `domain.rs` | Defines `Domain`, `DomainPolicy`, `MonitorAPI`, `InterruptPolicy`, `VProcessorState`, `VpRunState`. Implements the domain lifecycle (Unsealed → Sealed → Revoked) and the pending-capability queue. |
| `capability.rs` | Generic `Capability<T>` tree node. Implements the CDT operations (carve, alias, send, revoke for memory; create/revoke for domains). Provides `MemoryCapabilityExt` and `DomainCapabilityExt` extension traits. Also hosts `compute_address_space`. |
| `update.rs` | `Update` enum and `UpdateBatch` for describing hardware changes produced by capability operations. `UpdateProcessor` is a simulation helper that distributes batches to per-core queues. |
| `platform.rs` | `Platform` trait that hardware backends implement. `execute()` wraps a capability tree mutation in the full lock-acquire → operate → IPI-barrier → apply-updates → release cycle. |
| `switch.rs` | `SwitchManager` and `CoreContext` for tracking core-to-domain assignment. VP call-chain management (forward switch, return switch). Interrupt routing up the domain CDT. |
| `view.rs` | `compute_address_space` and `compute_view_from_capabilities` — walk the capability tree to produce a merged `AddressSpaceView` for a domain. |
| `attest.rs` | Generate human-readable attestation reports for domains and memory regions. `enumerate_domain_tree` walks the domain CDT for an inventory. |
| `sync.rs` | Internal `RwLock` alias. Resolves to `parking_lot::RwLock` (hosted), `loom::sync::RwLock` (loom testing), or `spin::RwLock` (bare-metal). All engine code goes through this alias, so switching backends requires no changes outside `sync.rs`. |
| `error.rs` | `CapaError` enum and `Result<T>` alias. |

## Data Flow for a Typical Capability Operation

```
Caller
  │
  ├─ capability.rs : carve_child(parent, access, owner, handle)
  │     ├─ domain.rs : validate_operation(MonitorAPI::CARVE)    ← sealed + permission check
  │     ├─ memory.rs : MemoryRegion::carve(access)             ← containment + overlap check
  │     ├─ add child to parent.children
  │     └─ return (CapabilityRef<MemoryRegion>, UpdateBatch)
  │
  ├─ platform.rs : execute(platform, exclusive=false, || carve_child(...))
  │     ├─ platform.acquire_shared_lock()
  │     ├─ run the closure → get (result, batch)
  │     ├─ if any affected domain runs on a remote core:
  │     │     send_ipi(core) → sync_barrier(0) → apply_update(u)... → sync_barrier(1)
  │     └─ drop lock guard
  │
  └─ UpdateBatch returned to caller for optional inspection
```

## Threading Model

- **Multiple concurrent non-destructive operations** (carve, alias, send): hold shared lock, run in parallel.
- **Any revoke operation**: holds exclusive lock, blocks all others until complete.
- **Within a single tree node**: `Arc<RwLock<Capability<T>>>` serialises concurrent readers/writers.
- **Loom testing**: `sync.rs` switches all `RwLock` / `Arc` / atomic types to loom equivalents via a feature flag, enabling exhaustive interleaving exploration without modifying any engine logic.

For the full threading and locking design, see [concurrency.md](concurrency.md).
