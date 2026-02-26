# Concurrency, Updates, and the Platform Abstraction

**Date**: 2026-02-26  
**Status**: Implemented  
**Relates to**: `2026/src/platform.rs`, `2026/src/update.rs`, `2026/src/capability.rs`,
`CLI-2026/src/platform.rs`, `2026/tests/common/mod.rs`

---

## 1. Problem Statement

The capability engine is a trusted state machine intended to run on multi-core
systems—most importantly as a security monitor in root mode, isolating
non-root domains from each other.

Capability operations (carve, alias, send, revoke) must appear **atomic**
across all cores: a core that is interrupted or preempted mid-operation must
never observe a partially-applied state.  This atomicity requirement has two
dimensions:

1. **Intra-core (within the capability tree)** – the Rust `Arc<RwLock<…>>`
   data structures give sequential consistency; a single lock held for the
   whole tree mutation is sufficient.

2. **Cross-core (hardware state)** – memory mappings, TLB entries, and domain
   execution state live in per-core hardware registers.  Changing them
   requires coordination: the initiating core cannot simply write new EPT
   entries while another core is actively using the old ones.

Additionally, the engine must run in radically different environments—bare-metal
monitor, unit-test harness, CLI simulator—each with its own primitives for
interrupts, barriers, and core-state management.  A **Platform trait** provides
the abstraction boundary.

---

## 2. Design Goals

| Goal | Description |
|---|---|
| **G1** | Capability operations are linearizable: each appears to take effect atomically at a single point in time. |
| **G2** | No two conflicting operations may execute concurrently (mutual exclusion). |
| **G3** | Domain objects are not freed until all cores have acknowledged their revocation. |
| **G4** | The capability engine is platform-independent; hardware details live behind a trait. |
| **G5** | A `TestPlatform` enables multi-threaded unit tests without any real hardware. |
| **G6** | A `CliPlatform` ports the existing CLI simulator to the new abstraction. |

---

## 3. The `Platform` Trait

Defined in `2026/src/platform.rs`, the trait cleanly separates
**what the engine needs** from **how the hardware provides it**:

```rust
pub trait Platform: Send + Sync {
    // Serialisation
    fn acquire_op_locks(&self, domains: &BTreeSet<DomainId>) -> Result<Box<dyn OpLockGuard>>;

    // Cross-core synchronisation
    fn send_ipi(&self, core_id: CoreId);
    fn sync_barrier(&self, id: u8, participants: usize);

    // Hardware-state update
    fn apply_update(&self, update: &Update);

    // Domain lifecycle
    fn on_domain_revoked(&self, domain_id: DomainId, fallback: Option<DomainId>);
    fn register_domain(&self, domain_id: DomainId, parent_id: Option<DomainId>);

    // Core-domain tracking
    fn set_core_domain(&self, core_id: CoreId, domain_id: DomainId);
    fn clear_core_domain(&self, core_id: CoreId);
    fn domain_core(&self, domain_id: DomainId) -> Option<CoreId>;
}
```

### 3.1 Operation-Lock Guard

```rust
pub trait OpLockGuard: Send {}
```

A RAII handle returned by `acquire_op_locks`.  Dropping it releases all
per-domain serialisation locks.  The guard is designed to be `'static`
(no lifetime parameter) by using `parking_lot::lock_api::ArcMutexGuard`, so
it can be boxed and stored without borrow-checker friction.

---

## 4. The `execute()` Wrapper

All capability mutations flow through `execute()`, which implements the full
cross-core synchronisation protocol:

```rust
pub fn execute<F, R>(
    platform: &dyn Platform,
    affected_domains: &BTreeSet<DomainId>,
    op: F,
) -> Result<(R, UpdateBatch)>
where
    F: FnOnce() -> Result<(R, UpdateBatch)>;
```

### 4.1 Two-Barrier Protocol (§5.2 of the research paper)

```
Initiating core                     Affected cores
──────────────────────────────────────────────────
acquire_op_locks(affected_domains)
  └─ TOCTOU check: domain still alive?
op()  ← pure tree mutation, returns UpdateBatch
for each affected core: send_ipi(core_id)         ← preempt
sync_barrier(0, n+1)               →  sync_barrier(0, n+1) ← stopped
for each update: apply_update(u)   ← apply EPT/zero/TLB changes
sync_barrier(1, n+1)               →  sync_barrier(1, n+1) ← apply local state
for RevokeDomain: on_domain_revoked(…)
drop _guard  ← release all op_locks
```

**Barrier 0** guarantees all affected cores are stopped before the initiating
core changes shared hardware state.  
**Barrier 1** releases cores once the new state is globally visible, allowing
each core to apply its local state (e.g. TLB flush, VMX reload).

### 4.2 Local Fast-Path

If `platform.domain_core(d)` returns `None` for every domain in the
`UpdateBatch`, no IPI is sent and no barrier is touched.  This is the common
case when the affected domain is not currently scheduled on any core, and it
avoids all cross-core overhead.

---

## 5. Serialisation and Conflict Identification

### 5.1 Per-Domain Operation Locks

Locks are **per-domain**, acquired in **sorted (domain-ID) order** to prevent
deadlocks when two operations race on overlapping domain sets.

The implementation uses `Arc<Mutex<()>>` for each domain entry.  The Arc
ensures the lock object stays alive even after the domain is removed from the
registry during revocation—a thread that is waiting on the lock still holds
a valid Arc.  After acquiring the lock, the thread does a **TOCTOU check**
(reads `domain_entry.revoked`) and returns `CapaError::DomainRevoked` if the
domain was revoked while waiting.

### 5.2 Conflict Table

The following pairs of operations require serialisation (they share at least
one domain in their affected-domain sets):

| Operation A | Operation B | Shared domain |
|---|---|---|
| `revoke(child_mem)` | `carve(parent_mem)` | owner of `parent_mem` |
| `send(mem, dst)` | `revoke(mem)` | owner of `mem` |
| `send(mem, dst)` | `revoke(dst_domain)` | `dst_domain` |
| `create_child_domain(parent)` | `revoke(parent_domain)` | `parent_domain` |
| `revoke(domain_A)` | `revoke(domain_A)` | `domain_A` |
| `revoke(subtree_root)` | `revoke(subtree_root)` | `subtree_root` |

Non-conflicting operations (different, non-overlapping domain sets) may
proceed concurrently—their lock acquisitions are disjoint.

---

## 6. Domain Memory Lifecycle

### 6.1 The Problem

When a domain is revoked, its capability node is removed from the CDT and its
memory is freed.  But a core that was running the domain may still be executing
in that domain's address space at the instant of revocation.  It must be
redirected to a safe fallback domain before the domain object can be
deallocated.

### 6.2 Solution: Two-Barrier + Arc

1. **Two-barrier protocol** (§4.1) ensures all cores stop executing the revoked
   domain before the initiating core removes its mappings.  By the time
   `on_domain_revoked` is called (after barrier 1), every core has already
   switched away.

2. **`Arc` reference counting** keeps Rust heap objects alive.  The platform
   holds an `Arc<Mutex<()>>` per domain; the `OpLockGuard` clones this Arc into
   itself.  If the domain is removed from the registry while a thread is
   waiting on the lock, the Arc in the guard keeps the mutex alive until the
   lock is released.  The subsequent TOCTOU check detects the revocation and
   returns `DomainRevoked` without touching any freed state.

3. **`CapabilityRef<Domain>` = `Arc<RwLock<Capability<Domain>>>`** is kept alive
   by callers' own Arc references through the entire duration of the operation,
   including the IPI/barrier window.

### 6.3 Fallback Domain

`Update::RevokeDomain` carries a `fallback: Option<DomainId>`:

```rust
RevokeDomain {
    domain: DomainId,
    fallback: Option<DomainId>,
}
```

- **CDT revocation** (`revoke_child_domain`): `fallback = Some(parent.data.id)`.
  The parent of the revoked subtree root is the natural fallback because it is
  the first non-revoked ancestor for every domain in the subtree.

- **Vital-memory revocation** (a domain owning a vital memory capability is
  transitively revoked): `fallback = None`.  The platform looks up the parent
  from its own domain-parent map (set via `register_domain`).

All nodes in a revoked subtree receive the **same** fallback value.  This
means the engine only walks the CDT once (at revocation time, in
`revoke_domain_subtree`), not at interrupt/IPI time.

`platform.on_domain_revoked(domain_id, fallback)` is called after barrier 1
for each `RevokeDomain` update; by then every core has left the revoked domain.
The platform uses `fallback` to update its core-domain mapping without
needing CDT access.

---

## 7. Platform Implementations

### 7.1 `TestPlatform` (`2026/tests/common/mod.rs`)

Designed for unit and multi-threaded integration tests.

**Two-lock design** avoids deadlocks:
- `op_lock: Arc<Mutex<()>>` — held for the full `execute()` duration via
  `lock_arc()` (returns `ArcMutexGuard`, no lifetime parameter).
- `inner: Arc<Mutex<TestPlatformInner>>` — held briefly for individual
  reads/writes.  Never held at the same time as any other `op_lock`.

`TestPlatformInner` contains:
- `domains: BTreeMap<DomainId, DomainEntry>` — `revoked: bool` + `parent_id`
- `core_to_domain` / `domain_to_core` — bidirectional core-domain mappings
- `applied_updates: Vec<Update>` — captured by `apply_update` for assertions

`send_ipi` and `sync_barrier` are no-ops (sequential tests do not require
real preemption; multi-threaded tests rely on Rust's `Arc<Mutex>` for ordering).

#### Platform Test Coverage

| Test | Scenario verified |
|---|---|
| `test_execute_local_no_cores` | Local fast-path, no updates |
| `test_execute_apply_update_is_called` | `apply_update` dispatched for each update |
| `test_execute_revoke_redirects_core_to_fallback` | `on_domain_revoked` updates core state |
| `test_execute_toctou_domain_revoked` | TOCTOU check returns `DomainRevoked` |
| `test_execute_vital_revoke_none_fallback_uses_parent_map` | `fallback=None` → platform walks parent map |
| `test_revoke_child_domain_carries_fallback` | Engine propagates `Some(parent_id)` in `RevokeDomain` |

### 7.2 `CliPlatform` (`CLI-2026/src/platform.rs`)

The CLI simulator platform.  Same two-lock design as `TestPlatform`.

`CliPlatformInner` additionally contains the `SwitchManager` (moved from
`CliState`), which tracks domain-switching context for each simulated core.

Key differences from `TestPlatform`:

| Aspect | `TestPlatform` | `CliPlatform` |
|---|---|---|
| `domain_core()` | Uses actual core-domain map | Always returns `None` (local fast-path only) |
| `send_ipi` / `sync_barrier` | No-op | No-op |
| `apply_update` | Records to `Vec` for assertions | No-op (output in `process_updates`) |
| `on_domain_revoked` | Updates core-domain map | Updates `SwitchManager` via `CoreState` |
| `SwitchManager` | Not present | Owned inside `inner` |

`domain_core()` returning `None` means `execute()` always uses the local
fast-path in the CLI.  This is correct: the CLI has no real parallel core
execution, so IPI and barrier primitives are never needed.

Public delegation methods (`switch`, `route_interrupt`, `get_core`,
`num_cores`) allow CLI commands to access `SwitchManager` functionality
through `state.platform` without exposing the inner lock directly.

---

## 8. Update Subsystem Changes

### 8.1 `Update::RevokeDomain`

Added `fallback: Option<DomainId>` field (see §6.3).

### 8.2 `UpdateBatch`

Added `add_revoke_domain_with_fallback(domain, fallback)`.  
`add_revoke_domain(domain)` is kept as a backward-compatible wrapper that
passes `None`.

### 8.3 `CapaError::DomainRevoked`

New error variant, returned by `acquire_op_locks` when the TOCTOU check
detects that a domain in the requested lock set has been revoked since the
caller determined its domain set.

---

## 9. CLI Architecture After Refactor

```
CLI command (cmd_revoke, cmd_carve, cmd_send)
    │
    ├─ Clone Arcs for affected capabilities
    ├─ Determine affected_domain set
    │
    ▼
execute(&*state.platform, &affected, || {
    // Pure capability tree mutation
    capability_operation(...)    →  Result<(R, UpdateBatch)>
})
    │
    ├─ acquire_op_locks  (TOCTOU check)
    ├─ op()              (tree mutation)
    ├─ apply_update ×N   (no-op in CLI)
    ├─ on_domain_revoked (updates SwitchManager via fallback)
    └─ returns (R, UpdateBatch)
    │
    ▼
process_updates(state, &batch)
    │  (CliState HashMap cleanup only — remove domains/memories)
    └─ Print MMU update summary
```

`CliState` no longer holds a raw `SwitchManager`; all core-state access goes
through `state.platform`.

---

## 10. Invariants and Safety Properties

| Property | How it is maintained |
|---|---|
| **No stale domain access** | TOCTOU check after lock acquisition; `DomainRevoked` before any tree access |
| **No partial updates** | All `apply_update` calls happen inside the IPI window (between barriers) |
| **No dangling core reference** | `on_domain_revoked` runs after barrier 1; all cores have left the domain |
| **No deadlock** | Locks acquired in sorted domain-ID order; `op_lock` and `inner` never held in inverse order |
| **No capability tree mutation during IPI window** | `op_lock` is held; no other thread can call `acquire_op_locks` for the same domains |
| **Subtree revocation is atomic** | All `RevokeDomain` updates in a batch carry the same `fallback`; no core can observe a partially-revoked subtree because all updates are applied between the two barriers |

---

## 11. File Map

| File | Role |
|---|---|
| `2026/src/platform.rs` | `Platform` trait, `OpLockGuard` trait, `execute()` |
| `2026/src/update.rs` | `Update::RevokeDomain` with `fallback`, `add_revoke_domain_with_fallback` |
| `2026/src/capability.rs` | `revoke_domain_subtree(fallback)`, vital-memory revoke |
| `2026/src/error.rs` | `CapaError::DomainRevoked` |
| `2026/src/lib.rs` | Exports `platform` module |
| `2026/tests/common/mod.rs` | `TestPlatform` |
| `2026/tests/platform_tests.rs` | Platform integration tests (6 tests) |
| `CLI-2026/src/platform.rs` | `CliPlatform` with embedded `SwitchManager` |
| `CLI-2026/src/state.rs` | `CliState` with `platform: Arc<CliPlatform>` |
| `CLI-2026/src/update_processor.rs` | `process_updates` — HashMap cleanup only |
