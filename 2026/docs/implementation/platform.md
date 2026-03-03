# Platform

## What the Platform Trait Does

The `Platform` trait is the boundary between the capability engine and the underlying hardware. It abstracts:

- **Global operation locking** — serialise capability tree mutations via a RW lock.
- **Cross-core synchronisation** — IPI delivery, two-barrier protocol, update-application lock.
- **Hardware state changes** — apply individual updates (map, unmap, zero memory, flush TLB).
- **Domain lifecycle** — register newly created domains, handle revocation callbacks.
- **Core state tracking** — record which domain and VP are running on each core.

The engine calls into the platform; the platform never calls back into the engine during normal operation (except that `on_domain_revoked` may need to inspect the domain CDT via data already in scope).

---

## Full API Reference

### Locking

```rust
fn acquire_shared_lock(&self) -> Result<Box<dyn OpLockGuard>>;
fn acquire_exclusive_lock(&self) -> Result<Box<dyn OpLockGuard>>;
```

Shared lock: held by carve, alias, send. Multiple holders can coexist.
Exclusive lock: held by any revoke. Blocks until all other holders have released.

Dropping the returned `Box<dyn OpLockGuard>` releases the lock (RAII).

### Cross-Core Synchronisation

```rust
fn send_ipi(&self, core_id: CoreId);
fn sync_barrier(&self, id: u8, participants: usize);
fn try_acquire_update_lock(&self) -> bool;   // default: always true
fn release_update_lock(&self);               // default: no-op
fn poll_and_respond_cross_core(&self);       // default: no-op
```

`try_acquire_update_lock` / `release_update_lock` serialise the IPI-barrier-apply sequence when multiple initiating cores are in flight concurrently. Without this lock, two cores could send IPIs to each other and deadlock at their respective barriers. The default implementations (always-true / no-op) are correct for single-core and simulation platforms.

`poll_and_respond_cross_core` is called in the spin loop while waiting for the update lock. On bare metal with interrupts disabled, a core that is waiting for the update lock must still respond to IPIs from other initiating cores, which it does by calling this method.

`sync_barrier` is a two-phase barrier:
- `id = 0` ("pre-update"): initiating core waits until all IPIed cores have stopped.
- `id = 1` ("post-update"): cores are released to apply local state (TLB flush).

### Hardware State Changes

```rust
fn apply_update(&self, update: &Update);
```

Called by the initiating core between the two barriers, while all affected cores are stopped. This is the window in which EPT modifications, memory zeroing, and page-table changes must happen.

### Domain Lifecycle

```rust
fn register_domain(&self, domain_id: DomainId, parent_id: Option<DomainId>);
fn on_domain_revoked(&self, domain_id: DomainId, fallback: Option<DomainId>);
```

`register_domain`: called immediately after a domain capability is created. The platform stores the parent ID so it can resolve fallback domains for vital-memory-triggered revocations (where `fallback = None` in the `RevokeDomain` update).

`on_domain_revoked`: called after hardware updates are applied for each `RevokeDomain` update. The platform must:
1. Redirect any core currently executing `domain_id` to `fallback` (or idle it if `fallback` is `None`).
2. Unregister the domain from internal tracking.

### Core State Tracking

```rust
fn set_core_domain(&self, core_id: CoreId, domain_id: DomainId);
fn clear_core_domain(&self, core_id: CoreId);
fn domain_core(&self, domain_id: DomainId) -> Option<CoreId>;
```

The engine uses `domain_core` to determine whether a domain's core must receive an IPI before hardware updates are applied. `set_core_domain` / `clear_core_domain` are called by `SwitchManager` when execution moves between domains.

---

## Reference Implementations

### `TestPlatform` (`tests/common/mod.rs`)

Used by all unit and integration tests. A minimal in-process implementation:

- Shared lock: `parking_lot::RwLock<()>` read guard.
- Exclusive lock: `parking_lot::RwLock<()>` write guard.
- `send_ipi`: no-op (single core in tests).
- `sync_barrier`: no-op.
- `apply_update`: no-op (or logs for debugging).
- Domain tracking: `BTreeMap<DomainId, Option<DomainId>>` for parent lookup.

### `LoomPlatform` (`tests/concurrency/loom_*.rs`)

Used by loom exhaustive-interleaving tests. Identical structure to `TestPlatform` but uses `loom::sync::RwLock` so loom can intercept all synchronisation decisions.

### `CliPlatform` (`CLI-2026/src/platform.rs`)

Used by the interactive CLI simulator. A hosted, multi-core-simulating implementation:

- Shared / exclusive lock: `parking_lot::RwLock<()>` arc-guards (arc_lock feature for `Box<dyn OpLockGuard>`).
- `SwitchManager` embedded for VP-aware switch and interrupt routing.
- Domain registry: `BTreeMap<DomainId, CliDomainEntry>` with `revoked` flag and `parent_id`.
- Register storage: `BTreeMap<(DomainId, vp_id, reg_id), u64>` for VP register simulation.
- `apply_update`: drives `UpdateProcessor` to push updates to simulated per-core queues.

---

## How to Create a New Platform

1. Define a struct that holds your lock primitive, IPI mechanism, and domain-parent map.
2. Implement `Platform` for it:
   - `acquire_shared_lock` / `acquire_exclusive_lock`: return RAII guards wrapping your hardware RW lock.
   - `apply_update`: modify your EPT / page tables for `Map`, `Unmap`, `ChangeRights`; zero physical memory for `ZeroMemory`; flush TLB for `FlushTLB`; update core routing tables for `RevokeDomain`.
   - `register_domain` / `on_domain_revoked`: maintain a parent map; redirect cores on revocation.
   - `set_core_domain` / `clear_core_domain` / `domain_core`: maintain a core→domain map.
   - `send_ipi` / `sync_barrier`: use your platform's IPI and barrier primitives. For single-core platforms, these can be no-ops.
3. If your platform is multi-core, implement `try_acquire_update_lock` / `release_update_lock` / `poll_and_respond_cross_core` to prevent cross-core deadlocks in `execute()`.
