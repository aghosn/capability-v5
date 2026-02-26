# Concurrency, Updates, and the Platform Abstraction

**Date**: 2026-02-26 (revised)
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
   data structures give sequential consistency.

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
| **G5** | Callers do not need to enumerate affected domain IDs; the lock model handles this automatically. |
| **G6** | A `TestPlatform` enables multi-threaded unit tests without any real hardware. |
| **G7** | A `CliPlatform` ports the existing CLI simulator to the new abstraction. |

---

## 3. The `Platform` Trait

Defined in `2026/src/platform.rs`, the trait cleanly separates
**what the engine needs** from **how the hardware provides it**:

```rust
pub trait Platform: Send + Sync {
    // Global RW lock
    fn acquire_shared_lock(&self) -> Result<Box<dyn OpLockGuard>>;
    fn acquire_exclusive_lock(&self) -> Result<Box<dyn OpLockGuard>>;

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

A RAII handle returned by `acquire_shared_lock` or `acquire_exclusive_lock`.
Dropping it releases the lock.  The guard is designed to be `'static`
(no lifetime parameter) by using `parking_lot::lock_api::ArcRwLock*Guard`, so
it can be boxed and stored without borrow-checker friction.

---

## 4. Locking Model — Global Read-Write Lock

### 4.1 Why per-domain locks are insufficient

An earlier design used per-domain operation locks, requiring callers to declare
the set of affected domain IDs before each operation.  This had two problems:

1. **Revoke is unbounded**: `revoke_child_domain` recursively revokes an entire
   subtree.  The caller cannot enumerate all descendant domain IDs without
   first traversing the tree — which itself requires holding locks.

2. **Race condition**: `send_to(cap, dst)` locks `{sender, dst}`, while
   `revoke_child_domain(parent, handle)` locks `{parent}`.  If `dst` is a
   descendant of `parent` but `sender ≠ parent`, the two lock sets are
   disjoint and the operations can proceed concurrently — a race.

### 4.2 The solution: global RW lock

The platform exposes a **global read-write lock**:

| Operation | Lock kind | Rationale |
|---|---|---|
| carve, alias, send | **Shared** | Multiple non-destructive ops may run concurrently. Each individual capability node is already protected by its own `Arc<RwLock<…>>`. |
| Any revoke (domain or memory) | **Exclusive** | Ensures the full subtree revocation is atomic. No other operation can race into the subtree being revoked. |

On bare metal, `acquire_shared_lock` maps to `rwlock_read_lock` and
`acquire_exclusive_lock` maps to `rwlock_write_lock` — standard hardware
primitives on any SMP architecture.

### 4.3 No TOCTOU check required

With the RW lock:

- A shared-lock holder is guaranteed that no revocation is in-flight
  (exclusive lock is blocked while any shared lock is held).
- An exclusive-lock holder (revoke) is guaranteed that no other operation
  is in-flight (exclusive blocks until all shared locks are released).

No per-domain revocation check ("TOCTOU check") is needed.

---

## 5. The `execute()` Wrapper

All capability mutations flow through `execute()`:

```rust
pub fn execute<F, R>(
    platform: &dyn Platform,
    exclusive: bool,   // true for revoke, false for carve/alias/send
    op: F,
) -> Result<(R, UpdateBatch)>
where
    F: FnOnce() -> Result<(R, UpdateBatch)>;
```

### 5.1 Two-Barrier Protocol (§5.2 of the research paper)

```
Initiating core                     Affected cores
──────────────────────────────────────────────────
acquire_shared_lock()   (or exclusive for revoke)
op()  ← pure tree mutation, returns UpdateBatch
for each affected core: send_ipi(core_id)         ← preempt
sync_barrier(0, n+1)               →  sync_barrier(0, n+1) ← stopped
for each update: apply_update(u)   ← apply EPT/zero/TLB changes
sync_barrier(1, n+1)               →  sync_barrier(1, n+1) ← apply local state
for RevokeDomain: on_domain_revoked(…)
drop _guard  ← release shared or exclusive lock
```

**Barrier 0** guarantees all affected cores are stopped before the initiating
core changes shared hardware state.
**Barrier 1** releases cores once the new state is globally visible, allowing
each core to apply its local state (e.g. TLB flush, VMX reload).

### 5.2 Local Fast-Path

If `platform.domain_core(d)` returns `None` for every domain in the
`UpdateBatch`, no IPI is sent and no barrier is touched.  This is the common
case when the affected domain is not currently scheduled on any core.

### 5.3 Caller API

```rust
// Non-destructive operation — shared lock
execute(&platform, false, || {
    Capability::send_to(&cap, new_owner, handle, Attributes::NONE)
        .map(|b| ((), b))
});

// Revoke — exclusive lock (no need to enumerate subtree domain IDs)
execute(&platform, true, || {
    Capability::revoke_child_domain(&root, child_handle)
        .map(|u| ((), u))
});
```

Callers never compute or pass domain ID sets.

---

## 6. Domain Memory Lifecycle

### 6.1 The Problem

When a domain is revoked, its capability node is removed from the CDT.
A core running in that domain must be redirected to a safe fallback before
any memory is freed.

### 6.2 Solution: Two-Barrier + Arc

1. **Exclusive lock** prevents any concurrent operation from entering the
   revoked subtree.

2. **Two-barrier protocol** (§5.1) ensures all cores stop executing the
   revoked domain before the initiating core removes its mappings.  By the
   time `on_domain_revoked` is called (after barrier 1), every core has
   already switched away.

3. **`Arc` reference counting** keeps Rust heap objects alive through the
   full duration of the operation.

### 6.3 Fallback Domain

`Update::RevokeDomain` carries a `fallback: Option<DomainId>`:

```rust
RevokeDomain {
    domain: DomainId,
    fallback: Option<DomainId>,
}
```

- **CDT revocation** (`revoke_child_domain`): `fallback = Some(parent.data.id)`.
- **Vital-memory revocation**: `fallback = None`.  The platform looks up the
  parent from its own domain-parent map (set via `register_domain`).

---

## 7. Platform Implementations

### 7.1 `TestPlatform` (`2026/tests/common/mod.rs`)

Uses `parking_lot::RwLock<()>` for the global op lock.
`read_arc()` / `write_arc()` return arc-owning guards with no lifetime
parameter, suitable for boxing as `Box<dyn OpLockGuard>`.

`send_ipi` and `sync_barrier` are no-ops (sequential tests do not require
real preemption).

#### Platform Test Coverage

| Test | Scenario verified |
|---|---|
| `test_execute_local_no_cores` | Local fast-path, no updates |
| `test_execute_apply_update_is_called` | `apply_update` dispatched for each update |
| `test_execute_revoke_redirects_core_to_fallback` | `on_domain_revoked` updates core state |
| `test_execute_exclusive_blocks_shared` | Exclusive lock prevents concurrent shared-lock entry |
| `test_execute_vital_revoke_none_fallback_uses_parent_map` | `fallback=None` → platform walks parent map |
| `test_revoke_child_domain_carries_fallback` | Engine propagates `Some(parent_id)` in `RevokeDomain` |

### 7.2 `CliPlatform` (`CLI-2026/src/platform.rs`)

Same RW lock design as `TestPlatform`.

`domain_core()` always returns `None` (CLI has no real parallel core
execution), so `execute()` always uses the local fast-path.

---

## 8. Update Subsystem

### 8.1 `Update::RevokeDomain`

Carries `fallback: Option<DomainId>` (see §6.3).

### 8.2 `UpdateBatch`

`add_revoke_domain_with_fallback(domain, fallback)` for explicit fallback.
`add_revoke_domain(domain)` is a backward-compatible wrapper passing `None`.

---

## 9. CLI Architecture

```
CLI command (cmd_revoke, cmd_carve, cmd_send)
    │
    ├─ Clone Arcs for affected capabilities
    │
    ▼
execute(&*state.platform, exclusive, || {
    // exclusive = true for revoke, false for carve/send
    capability_operation(...)    →  Result<(R, UpdateBatch)>
})
    │
    ├─ acquire_shared_lock / acquire_exclusive_lock
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

---

## 10. Invariants and Safety Properties

| Property | How it is maintained |
|---|---|
| **No stale domain access during revoke** | Exclusive lock blocks all other operations for the full duration of revocation |
| **No partial updates** | All `apply_update` calls happen inside the IPI window (between barriers) |
| **No dangling core reference** | `on_domain_revoked` runs after barrier 1; all cores have left the domain |
| **No deadlock** | A single RW lock; no nested lock acquisition |
| **No capability tree mutation during IPI window** | Op lock is held; no other thread can call `execute` for the same or conflicting domains |
| **Subtree revocation is atomic** | Exclusive lock covers the full traversal and all `RevokeDomain` updates are applied between the two barriers |

---

## 11. File Map

| File | Role |
|---|---|
| `2026/src/platform.rs` | `Platform` trait, `OpLockGuard` trait, `execute()` |
| `2026/src/update.rs` | `Update::RevokeDomain` with `fallback`, `add_revoke_domain_with_fallback` |
| `2026/src/capability.rs` | `revoke_domain_subtree(fallback)`, vital-memory revoke |
| `2026/src/error.rs` | `CapaError` variants |
| `2026/src/lib.rs` | Exports `platform` module |
| `2026/tests/common/mod.rs` | `TestPlatform` |
| `2026/tests/platform_tests.rs` | Platform integration tests (6 tests) |
| `2026/tests/crosscore_tests.rs` | Cross-core IPI/barrier tests (7 tests) |
| `CLI-2026/src/platform.rs` | `CliPlatform` with embedded `SwitchManager` |
| `CLI-2026/src/state.rs` | `CliState` with `platform: Arc<CliPlatform>` |
| `CLI-2026/src/update_processor.rs` | `process_updates` — HashMap cleanup only |

