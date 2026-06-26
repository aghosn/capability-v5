# Capability Engine — Implementation

> Consolidated from `capa-engine/docs/implementation/` (platform, updates, translation, capabilities, switch, concurrency).

---

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

### `CliPlatform` (`CLI-capa-engine/src/platform.rs`)

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

---

# Updates

## Why Updates Exist

Capability operations (carve, send, revoke) change *who owns what memory*. These logical changes must eventually be reflected in hardware: page tables must be modified, TLBs flushed, and physical memory may need to be zeroed. Rather than performing hardware operations inline — which would couple the capability engine to a specific architecture — every operation returns an `UpdateBatch`. The platform applies the batch when it is safe to do so.

---

## The `Update` Enum

```rust
pub enum Update {
    /// Set access rights for a memory range in a domain.
    /// `rights == Rights::NONE` means no access (full unmap).
    /// `shootdown_required` must be `true` when rights are reduced or the
    /// mapping is fully removed; `false` for additive changes (new mapping
    /// or rights upgrade).
    /// `physical` is the backing physical address; ignored when
    /// `rights == Rights::NONE`.
    ChangeRights {
        domain:             DomainId,
        address:            u64,
        size:               u64,
        physical:           u64,
        rights:             Rights,
        shootdown_required: bool,
    },

    /// Zero a physical memory range (emitted for `CLEAN`-attributed revocations).
    /// Carries no domain ID — it is a physical operation independent of any address space.
    ZeroMemory { address: u64, size: u64 },

    /// Revoke a domain entirely.
    /// `fallback` is the first non-revoked ancestor domain ID computed by the
    /// capability engine. `None` when triggered by vital-memory revocation
    /// (the platform must look up the parent from its own domain-parent map).
    RevokeDomain { domain: DomainId, fallback: Option<DomainId> },

    /// Monitor maps its own access to a domain's COMM page (via HHDM).
    /// Emitted by `register_comm`. Carries no `affected_domain` — the
    /// platform applies this to its own internal mappings only; no IPI is needed.
    CommRegion { domain_id: DomainId, phys: u64, size: u64 },

    /// Monitor unmaps its access to a domain's COMM page.
    /// Emitted during revocation of a COMM-attributed capability, BEFORE the
    /// corresponding `RevokeDomain` update so the monitor safely relinquishes
    /// its mapping before the domain is torn down.
    UncommRegion { domain_id: DomainId, phys: u64, size: u64 },

    /// Flush TLB entries for a domain.
    FlushTLB { domain: DomainId },
}
```

`ChangeRights` is the single variant for all mapping changes. Setting `rights` to `Rights::NONE` is equivalent to the former `Unmap`; setting it to any non-zero `Rights` value with `shootdown_required: false` is equivalent to the former `Map`. This unification removes the distinction at the engine level — the platform sees one variant for all address-space mutations.

| Variant | When emitted | `shootdown_required` |
|---------|-------------|---------------------|
| `ChangeRights` (rights → NONE) | Domain loses access to a range (send, carved child revoked after transfer) | `true` |
| `ChangeRights` (rights → non-NONE) | Domain gains access to a range (send recipient; parent regains access after carved child revoked) | `false` |
| `ChangeRights` (rights downgraded) | Access rights are narrowed on an existing mapping | `true` |
| `ZeroMemory` | A `CLEAN`-attributed capability is revoked | n/a — physical op |
| `RevokeDomain` | A domain is revoked (explicit or via `VITAL` trigger) | n/a |
| `CommRegion` | `register_comm` — monitor maps its HHDM access to the COMM page | n/a — platform-internal |
| `UncommRegion` | COMM-attributed revocation — monitor unmaps its HHDM access (emitted before `RevokeDomain`) | n/a — platform-internal |
| `FlushTLB` | Platform must invalidate TLB entries for a domain | n/a |

`Rights` is a bitfield with constants `Rights::NONE`, `Rights::R`, `Rights::RW`, `Rights::RX`, and `Rights::RWX` (bits: read=0, write=1, execute=2).

---

## `UpdateBatch`

```rust
pub struct UpdateBatch {
    updates:          Vec<Update>,
    affected_domains: BTreeSet<DomainId>,
    snapshots:        BTreeMap<DomainId, Vec<u8>>,  // reserved for rollback
}
```

Key properties:

- **Ordered**: updates within a batch are applied in insertion order. This matters: `ZeroMemory` must precede the `ChangeRights` that restores parent access.
- **Merged**: sub-operations (e.g., each node in a recursive revocation) produce their own small batches and merge them into a single batch via `UpdateBatch::merge`. The final batch delivered to the platform is the union of all sub-operation updates.
- **Affected-domain index**: `affected_domains` is maintained automatically as updates are added. The platform uses this set to determine which cores must be preempted before hardware changes are applied (see [concurrency.md § execute()](concurrency.md#the-execute-function)).

Convenience constructors on `UpdateBatch`:

| Method | What it adds |
|--------|-------------|
| `add_change_rights(domain, address, size, physical, rights, shootdown_required)` | `ChangeRights` entry |
| `add_zero_memory(address, size)` | `ZeroMemory` entry |
| `add_revoke_domain(domain)` | `RevokeDomain` with `fallback: None` |
| `add_revoke_domain_with_fallback(domain, fallback)` | `RevokeDomain` with explicit fallback |
| `add_comm_region(domain_id, phys, size)` | `CommRegion` entry (monitor maps HHDM access) |
| `add_uncomm_region(domain_id, phys, size)` | `UncommRegion` entry (monitor unmaps HHDM access) |

### Ordering guarantees within a revocation batch

For any subtree node, updates appear in this order:

1. All updates from the node's children (recursive, leaves first).
2. `UncommRegion` for this node (if `COMM`).
3. `ZeroMemory` for this node (if `CLEAN`).
4. `ChangeRights` pair — remove access from the loser, restore access to the winner (if `Carve` and ownership transferred).
5. `RevokeDomain` for the owning domain (if `VITAL`).

`UncommRegion` is placed before `ZeroMemory` and `RevokeDomain` so the monitor relinquishes its own HHDM mapping before the physical memory is zeroed and before the domain is torn down.

---

## `UpdateProcessor` — Simulation Helper

`UpdateProcessor` is used by test environments and the CLI simulator to distribute update batches to per-core queues without requiring real hardware:

```rust
pub struct UpdateProcessor {
    core_queues:    Arc<RwLock<BTreeMap<CoreId, Vec<CoreUpdate>>>>,
    domain_to_core: Arc<RwLock<BTreeMap<DomainId, CoreId>>>,
}

pub struct CoreUpdate {
    pub batch:  UpdateBatch,
    pub status: UpdateStatus,  // Pending | InProgress | Completed
}
```

**Domain-to-core tracking**: the processor maintains a `domain_to_core` map that callers update explicitly:

```
register_domain_on_core(domain_id, core_id)   // domain starts running on core
unregister_domain(domain_id)                  // domain stopped running
get_domain_core(domain_id) → Option<CoreId>
```

**Workflow**:

```
submit_updates(batch) → BTreeSet<CoreId>
  → for each DomainId in batch.affected_domains:
        look up which core it is running on
        push CoreUpdate { batch, status: Pending } to that core's queue
  → return the set of notified cores

get_pending_updates(core_id)           → Vec<CoreUpdate> (Pending only)
mark_in_progress(core_id, batch_index) → bool
mark_completed(core_id, batch_index)   → bool
clean_completed(core_id)               → remove Completed entries
has_pending_updates(core_id)           → bool
get_cores_with_pending_updates()       → Vec<CoreId>
```

This is the simulation-side analogue of the IPI + barrier protocol used in real deployments. The CLI platform (`CLI-capa-engine/src/platform.rs`) uses `UpdateProcessor` to drive simulated address-space changes.

---

# Address Translation — Implementation

## Feature Gates

Address translation is opt-in via Cargo features:

```toml
[features]
address_translation = []
cache_coloring = ["address_translation"]   # implies address_translation
```

- `address_translation` — enables `AddressMap`, `MapEntry`, `MappingEntry`, `insert_view_aware`, and all translation hooks in `capability.rs`.
- `cache_coloring` — adds `ColorBitmap` to `MappingEntry` for cache-partition-aware mapping.

Struct fields use `#[cfg(feature = "address_translation")]` so that the engine binary stays unchanged when the feature is off.

---

## Module: `translation.rs`

Core data structures:

```rust
pub struct AddressMap {
    entries: BTreeMap<u64, MapEntry>,   // keyed by GPA
}

pub enum MapEntry {
    Mapped(MappingEntry),
    Blocked { hpa_start: u64, size: u64 },
}

pub struct MappingEntry {
    pub gpa_start: u64,
    pub hpa_start: u64,
    pub size:      u64,
    pub rights:    Rights,
    #[cfg(feature = "cache_coloring")]
    pub color_bitmap: Option<ColorBitmap>,
}
```

### Key methods

| Method | Signature | Purpose |
|--------|-----------|---------|
| `insert` | `(hpa, size, rights, gpa_hint) → Result` | Insert a new Mapped entry. Rejects overlaps with any existing entry. |
| `split` | `(gpa, offset, new_rights)` | Split an entry at a boundary when carve produces different rights. |
| `block` | `(gpa)` | Convert a Mapped entry to Blocked (sent carve). |
| `unblock` | `(gpa)` | Convert a Blocked entry back to Mapped (revoked carve). Calls `try_coalesce`. |
| `remove` | `(gpa)` | Remove an entry entirely (revoked alias in receiver's map). |
| `translate` | `(hpa, size) → (gpa, size, rights)` | Look up the GPA for a given HPA range. |
| `find_gpa_for_hpa` | `(hpa, size) → Option<gpa>` | Like translate but also searches Blocked entries. |
| `overlaps` | `(gpa, size) → bool` | Check if a range conflicts with any existing entry. |

### Coalescing

After `unblock`, `try_coalesce` checks the left and right neighbours. If they are Mapped with matching rights and contiguous HPAs, they are merged into a single entry. This restores the pre-split state when a carved child is revoked.

**Implication for tests**: after revoke + unblock, the restored entry may have been absorbed into a larger entry. Tests must use `translate()` rather than `entries().get(&gpa)` to find the mapping.

---

## Hooks in `capability.rs`

### `carve` → `split`

When a carve produces a child with **different** rights than the parent, the parent's AddressMap entry is split at the carve boundary. Same-rights carves skip the split (the parent's entry already covers the child's range with the same rights).

### `send` / `send_at` → `block` + `insert_view_aware`

1. **Validate**: check that the full GPA range doesn't overlap the receiver's existing entries. Return `RegionOverlap` on conflict (cap is rolled back to sender).
2. **Block sender** (carve only): convert the sender's entry to Blocked. Aliases don't remove sender access.
3. **Insert into receiver**: `insert_view_aware` walks the capability's `compute_view()` output, inserting Mapped entries for visible ranges and Blocked entries for carved-away gaps.

### `accept` / `accept_at` → same as send path

Same validation and view-aware insert. The GPA comes from `gpa_override.or(pending.gpa_hint)`.

### `revoke` → `unblock` + `remove`

In `revoke_subtree`, for each revoked node:
- **Receiver's map**: entries are removed (the cap no longer belongs to that domain).
- **Sender's map**: Blocked entries are unblocked (parent regains access).

---

## `insert_view_aware` Helper

```rust
fn insert_view_aware(
    map: &mut AddressMap,
    hpa_start: u64,
    size: u64,
    gpa_base: u64,
    view: &[Access],   // from compute_view(), sorted by HPA
)
```

Walks the full HPA range `[hpa_start, hpa_start + size)`:
- Visible ranges (in `view`) → `Mapped` at corresponding GPA offset.
- Gaps between view ranges → `Blocked` at corresponding GPA offset.
- Trailing gap after last visible range → `Blocked`.

This ensures the receiver's AddressMap accurately reflects what the domain can and cannot access.

---

## `fixup_domain_addresses`

```rust
fn fixup_domain_addresses(updates: &mut UpdateBatch, domain_id: DomainId, map: &AddressMap)
```

Rewrites the `address` field of every `ChangeRights` update for `domain_id` from HPA to GPA using `AddressMap::find_gpa_for_hpa`. Called **after** all AddressMap mutations but **before** dropping domain write locks.

**Not called in `revoke_subtree`** — the subtree doesn't know all domains' maps. Instead, top-level `revoke()`, `send()`, and `accept()` apply the fixup while locks are held.

---

## Deadlock Avoidance in `revoke_subtree`

### The problem

`revoke_subtree` iterates a capability's descendants, acquiring read/write locks on their owner domains to update AddressMaps. When a descendant is owned by the **same domain** that initiated the revoke (e.g., a carved region that was never sent), the top-level `revoke()` already holds that domain's write lock → deadlock.

### The solution

`revoke_subtree` uses `try_read()` / `try_write()` (non-blocking lock attempts) for AddressMap operations:
- If the lock is acquired → perform the map update normally.
- If the lock cannot be acquired (self-ownership) → skip gracefully.

Top-level `revoke()` compensates by processing unblock updates for the caller's own AddressMap after `revoke_subtree` returns.

**Critical**: `revoke()` must **not** process removal updates (alias unmaps) — alias unmaps don't have their own AddressMap entries. Removing would delete the Blocked carve entry before unblock can restore it.

### Lock ordering

Domain locks are always acquired in domain-ID order (lower ID first). Domain IDs are monotonically increasing (global `AtomicUsize`, root=0), so parents always have lower IDs than children. This prevents ABBA deadlocks between different domain pairs.

---

## PendingCapability: GPA Hint Storage

For sealed-domain sends, the GPA hint is stored in the `PendingCapability` struct:

```rust
pub struct PendingCapability {
    pub cap:              Weak<RwLock<Capability<MemoryRegion>>>,
    pub sender_domain_id: DomainId,
    pub sender_handle:    LocalHandle,
    pub sender_domain:    Weak<RwLock<Capability<Domain>>>,
    #[cfg(feature = "address_translation")]
    pub gpa_hint:         Option<u64>,
}
```

At `accept_at` time: `effective_gpa = gpa_override.or(pending.gpa_hint)`.

---

## Test Coverage

### Unit tests (`tests/unit/translation.rs`)

18 tests covering AddressMap operations: insert, split, block, unblock, remove, translate, coalescing, overlap rejection, find_gpa_for_hpa.

### Integration tests (`tests/integration/translation.rs`)

18 tests covering engine hooks end-to-end:
- Carve split, send block, alias no-block, revoke unblock
- `send_at` / `accept_at` with GPA hints
- GPA fidelity (ChangeRights carries correct GPA)
- Adversarial: conflicting GPA, blocked gap prevents insert
- View-aware insert: carved children create blocked gaps in receiver
- Deadlock regression: never-sent carve, alias subtree

### Tutorial test (`CLI-capa-engine/tests/tutorial_tests.rs`)

Tutorial 08 (GPA Address Translation) runs as part of `cargo test` in the CLI.

### Feature-combo totals

| Feature | Tests |
|---------|-------|
| Default | 251 |
| `address_translation` | 287 |
| `cache_coloring` | 290 |

---

# Capabilities — Implementation

## The `Capability<T>` Struct

Every node in the Capability Derivation Tree is a `Capability<T>` where `T` is either `MemoryRegion` or `Domain`:

```rust
pub struct Capability<T> {
    pub owned:    Ownership,            // owner domain, handle, attributes
    pub data:     T,                    // the resource
    pub parent:   CapabilityWeak<T>,    // weak → no ownership cycle
    pub children: Vec<CapabilityRef<T>>, // strong → parent owns children
}
```

`Capability<T>` is always heap-allocated and reference-counted:

| Type alias | Rust type | Semantics |
|------------|-----------|-----------|
| `CapabilityRef<T>` | `Arc<RwLock<Capability<T>>>` | Strong reference — capability stays alive |
| `CapabilityWeak<T>` | `Weak<RwLock<Capability<T>>>` | Weak reference — does not prevent deallocation |

The `RwLock` wrapper allows concurrent reads (e.g., two threads inspecting the same capability) while serialising writes (e.g., adding a child during carve, removing a child during revocation).

## Ownership

```rust
pub struct Ownership {
    pub owner:            DomainId,
    pub attributes:       Attributes,
    pub owner_domain:     Option<CapabilityWeak<Domain>>,
    /// Set only on channel capabilities while in-transit (send_channel).
    pub pending_receiver: Option<CapabilityWeak<Domain>>,
}
```

`owner_domain` is a weak back-reference to the owning domain's capability. It is used by `validate_operation` to enforce:

1. The domain has not been revoked (upgrade succeeds).
2. The domain is `Sealed`.
3. The domain's `MonitorAPI` includes the required permission bit.

Root capabilities in tests and in the root domain itself set `owner_domain = None`, which skips the check entirely.

`LocalHandle`s are not stored on the capability itself — they are per-domain keys in the owner's `memory_capabilities` / `domain_capabilities` tables.

## CDT Operations

Static methods on `Capability<T>` are the low-level CDT primitives. Most public API code should go through the domain-mediated entry points instead (`Capability::carve`, `alias`, `send_memory_*`, `revoke`, `create`, `revoke_domain`, `send_channel`, `accept_channel`), which handle handle allocation, table updates and the `UpdateBatch`.

```rust
// Memory primitives
Capability::alias_child(&parent, access, owner_id)?;
Capability::carve_child(&parent, access, owner_id)?;
Capability::send_to(&region, caller_id, new_owner_id, attributes)?;
Capability::revoke_child(&parent, child_sub)?;
Capability::revoke_child_ref(&parent, &child_ref)?;

// Domain primitives
//
// `create_child_domain` takes a `&mut Capability<Domain>` reborrowed from a
// write guard the caller already holds — it does NOT acquire any lock on
// `parent`. This is required because the public `Capability::create` must
// also allocate a `LocalHandle` and insert the child into the parent's
// domain table inside the same write region, which would deadlock if the
// helper tried to reacquire the lock.
let mut w = parent.write();
let child = Capability::create_child_domain(&mut *w, &parent, policy, owner_id)?;

Capability::revoke_child_domain(&parent, child_sub)?;
```

## `compute_address_space`

`capability.rs` hosts `compute_address_space(domain_ref)`, which returns the
domain's current merged `AddressSpaceView`:

```rust
let view: AddressSpaceView = compute_address_space(&domain_ref);
```

This acquires a write lock on the domain and calls `ensure_view_fresh()` to
lazily recompute the view if dirty (see below). See `view.rs` for the merge
algorithm.

### View caching and dirty tracking

Each `Domain` holds a `cached_view: AddressSpaceView` and a `view_dirty: bool`
flag. Mutations that affect the view (add/remove memory capability, address-map
changes) set `view_dirty = true` without recomputing. The view is recomputed
lazily when actually read:

- **`ensure_view_fresh()`** — if dirty, walks `memory_capabilities`, upgrades
  weak refs, calls `compute_view_from_cap_arcs`, clears the flag.
- **`snapshot_view()`** (internal) — calls `ensure_view_fresh()`, then
  optionally translates the HPA-based view to GPA via `translate_view_to_gpa`
  when `address_translation` is enabled.
- **`compute_address_space()`** (public) — acquires write lock, calls
  `ensure_view_fresh()`, returns clone of `cached_view`.

### GPA-aware view_diff

When `address_translation` is enabled, the same HPA can be mapped at multiple
GPAs (e.g., VTOM double-mapping). The HPA-based `cached_view` cannot detect
these duplicates. `snapshot_view()` translates through the domain's `AddressMap`
to produce a GPA-keyed view, so `view_diff` naturally emits distinct
`ChangeRights` updates for each GPA mapping.

`ViewRegion` carries a `physical_start` field (the HPA) alongside the
GPA-based `address`/`size`, so `ChangeRights` updates contain both the GPA
(for EPT mapping) and the HPA (for the physical backing).

## Root Capabilities

Root capabilities are created directly by the monitor (not derived from anything):

```rust
let root_domain = Domain::new_root(num_cores);
let root_cap = Capability::new_root(owner_id, handle, root_domain);

let root_mem = MemoryRegion::new_root(start, size);
let mem_cap  = Capability::new_root(owner_id, handle, root_mem);
```

Root capabilities have:
- A dangling/empty `parent` weak reference (no parent).
- `children` starting empty.
- `owner_domain = None` (permission checks skipped).

---

# Switching and Interrupts

This document describes the `SwitchManager`, VP (virtual processor) states, domain switching, and interrupt routing. For the policy configuration that governs interrupt routing, see [semantics/domain.md § Interrupt Policy](../semantics/domain.md#interrupt-policy).

---

## `SwitchManager`

`SwitchManager` owns one `CoreContext` per physical core:

```rust
pub struct SwitchManager {
    cores: Vec<Arc<CoreContext>>,
}

pub struct CoreContext {
    pub state:       RwLock<CoreState>,     // Idle | Running(domain_id)
    pub core_id:     u64,
    pub running_vp:  RwLock<Option<u64>>,  // VP ID currently executing
}
```

`CoreState::Running(domain_id)` records which domain is executing on each core. This is used by:

- `execute()` in `platform.rs` to determine whether an affected domain is running on a remote core (and therefore needs an IPI).
- `switch` precondition checks to validate that the calling domain is actually running on the requested core.

---

## VP States

Each sealed domain has a set of **virtual processors** (VPs), one per logical execution context. VP states are stored in `domain.policy.vprocessor_states` after sealing.

A VP progresses through the following states:

```
Available
    │ switch (forward, into this domain)
    ▼
Running ──── switch (forward, out of this domain) ──► Locked
    │         │
    │         │ interrupt fires while Locked
    │         ▼
    │     Suspended ◄──── callee VP → Interrupted
    │                         │
    │                         │ switch to Suspended VP
    │                         │ (frees Interrupted callee → Available)
    │                         ▼
    └── switch (return) ─► Available
```

| State | Meaning |
|-------|---------|
| `Available` | VP is idle; can be switched to via a forward switch. |
| `Running { core, caller }` | VP is executing on `core`. `caller` records which VP switched to this one. |
| `Locked { callee_domain_id, callee_vp_id, prev_caller }` | VP has done a forward switch out; waiting for the callee to return. |
| `Suspended { callee_domain_id, callee_vp_id, vector }` | VP was `Locked` when an interrupt fired and preempted the callee chain. Claimable by a forward switch (same as `Available`); claiming it also frees its `Interrupted` callee to `Available`. |
| `Interrupted { vector }` | VP was `Running` when an interrupt fired. Cannot be directly resumed. Freed to `Available` when its `Suspended` parent is claimed. |

**Key rule**: you cannot switch directly to an `Interrupted` VP. You must first switch to its `Suspended` caller, which atomically frees the interrupted VP to `Available`.

CLI example (from [Tutorial 5 — Interrupt Routing](../cli/tutorials.md)):

```
# After interrupt 55 fires on core 0 while child VP[0] is Running:
#   child  VP[0]: Running → Interrupted
#   parent VP[0]: Locked  → Suspended
#   root   VP[0]: Locked  → Running (handler)

# WRONG — direct resume fails:
cap> switch child 0 0
✗ Error: child VP[0] is Interrupted — not directly resumable

# CORRECT — reschedule the Suspended caller first:
cap> switch parent 0 0
✓ parent VP[0]: Suspended → Running; child VP[0]: Interrupted → Available

cap> switch child 0 0
✓ child VP[0]: Available → Running
```

---

## Domain Switching

### Forward Switch (`switch <domain> <core> <vp_id>`)

**Preconditions** (all must hold):

| Check | Error |
|-------|-------|
| `from` domain is currently `Running` on `core_id` | `InvalidOperation` |
| `to` domain is `Sealed` | `DomainNotSealed` |
| `to.policy.cores` has bit `core_id` set | `PermissionDenied` |
| `to` is a **direct child or direct parent** of `from` in the domain CDT | `InvalidOperation` |
| Selected VP is `Available` (or the VP is `Suspended` — see VP recovery rule) | `InvalidOperation` |

The CDT-adjacency check uses `Arc::ptr_eq` (not ID comparison) to avoid TOCTOU races. A domain can only switch one level at a time in the hierarchy.

**Effect**:
1. Source VP transitions: `Running → Locked { callee = to }`.
2. Target VP transitions: `Available → Running { core, caller = from VP }`.
3. `CoreContext::state` updated to `Running(to_domain_id)`.

### Return Switch (`switch <core>`)

Passing no target domain resolves the parent via the `from` domain's weak parent pointer. If `from` has no parent (root domain), returns `InvalidOperation`.

- Source VP: `Running → Available`.
- Parent VP: `Locked → Running`.

---

## Interrupt Routing

When interrupt vector `v` fires on core `c` running domain `D`, the engine walks the domain CDT upward from `D` to find the handler:

```
route_interrupt(vector, interrupted_domain, core_id):
  current ← interrupted_domain
  reported_to ← []

  loop:
    policy ← current.policy.interrupts.get_policy(vector)

    DELIVER   → return (current.id, reported_to)
    REPORT    → reported_to.push(current.id); current ← current.parent
    NOTREPORT → current ← current.parent

    if current is root and root policy is not DELIVER:
      error: "No interrupt handler found"
```

`reported_to` is the ordered list of domain IDs (from interrupted domain upward) that have `REPORT` visibility and must be notified.

The root domain's default policy is always `DELIVER` — any interrupt that reaches the root is handled there.

### VP Call-Chain Suspension

When an interrupt is delivered via the VP-aware path (`deliver_interrupt_vp`), the engine atomically suspends the entire VP call chain:

1. Walk the `Running` VP on `core_id` and all its `caller` links upward.
2. For each intermediate VP (`Running` or `Locked`):
   - If it is the `Running` leaf: transition to `Interrupted { vector }`.
   - If it is `Locked`: transition to `Suspended { callee_domain, callee_vp_id, vector }`.
3. The handler VP (first ancestor with `DELIVER` policy): transition `Locked → Running`.

This atomic state transition ensures that neither the interrupted VP nor any intermediate locked VP can be resumed by a stale `switch` call — the engine enforces ordering through the VP state machine.

### Resuming After an Interrupt

After the handler finishes (`resume_after_interrupt`), the engine walks back down from handler to the originally interrupted domain, collecting all domains with `REPORT` visibility. These are the domains to notify that the interrupt is complete.

---

## `VProcessorState` and Register Masks

Each VP's saved state is a `VProcessorState`:

```rust
pub struct VProcessorState {
    pub id:            u64,
    pub registers:     BTreeMap<u64, u64>,  // reg_id → value
    pub platform_data: Vec<u8>,             // platform-specific context
    pub run_state:     VpRunState,
}
```

`DomainPolicy.interrupts` carries per-vector `read_set` / `write_set` bitmasks:

```rust
pub struct VectorPolicy {
    pub visibility: InterruptVisibility,
    pub read_set:   u64,   // registers a parent may read during handling
    pub write_set:  u64,   // registers a parent may write during handling
}
```

The `VECTOR_AVAILABLE` sentinel (`0xFF`) is used for register-access policy lookups in the non-interrupt state (`Available`, `Locked`). This unifies policy lookup: a parent configures register visibility for normal execution the same way it configures it for an interrupt vector — no special-casing.

**Allowed VP states for GET/SET register access:**

| VP state      | Access allowed |
|---------------|---------------|
| `Available`   | Yes (bitmap checked against `VECTOR_AVAILABLE`) |
| `Locked`      | Yes (bitmap checked against `VECTOR_AVAILABLE`) |
| `Interrupted` | Yes (bitmap checked against interrupt vector) |
| `Suspended`   | Yes (bitmap checked against interrupt vector) |
| `Running`     | **No** — always denied regardless of bitmaps |

A VP in the `Running` state is actively executing on a core; reading or writing its registers is not safe. The engine returns `RegisterAccessDenied` immediately without consulting the bitmap.

Policy enforcement (actually checking read/write access against these masks) is delegated to the platform implementation. The engine records and exposes the masks but does not enforce them internally.

See [semantics/domain.md § Interrupt Policy](../semantics/domain.md#interrupt-policy) for the policy configuration API and CLI examples.

---

# Concurrency

## Overview

The capability engine is designed to run safely across multiple cores. Concurrency is managed at two levels:

1. **Per-node locking**: each `Capability<T>` node is wrapped in `Arc<RwLock<>>`. Concurrent readers can hold simultaneous read locks; any write (e.g., adding a child) takes the write lock.

2. **Global operation lock**: a single coarse-grained RW lock serialises all capability tree mutations. This is exposed through the `Platform` trait and is the primary concurrency primitive for the engine.

---

## Global RW Lock — Shared vs. Exclusive

All capability operations fall into one of two categories:

| Category | Lock type | Operations |
|----------|-----------|------------|
| Non-destructive | **Shared** | carve, alias, send |
| Destructive | **Exclusive** | any revoke (memory or domain) |

Multiple non-destructive operations can run concurrently. Any revoke takes an exclusive lock — it blocks until all shared-lock holders have released, then runs alone.

**Why exclusive for revoke?** Revocation cascades through an arbitrarily deep subtree whose nodes and domain IDs are not known to the caller in advance. An exclusive lock ensures the full traversal is atomic with respect to every other operation. No TOCTOU checks or domain-set enumeration are required.

On bare metal these map directly to a hardware RW spinlock (`rwlock_read_lock` / `rwlock_write_lock`).

---

## The `execute()` Function

`execute()` in `platform.rs` is the single entry point that wraps a capability tree mutation in the full cross-core atomicity protocol:

```
execute(platform, exclusive, op):

  1. LOCK     acquire shared or exclusive lock (exclusive=true for revoke)
  2. OPERATE  (result, batch) = op()              ← pure tree mutation
  3. SYNC     for each core running an affected domain:
                  send_ipi(core)                  ← preempt affected cores
                  sync_barrier(0, n)              ← wait: all cores paused
                  apply_update(u) for u in batch  ← EPT / page-table changes
                  sync_barrier(1, n)              ← release: cores flush TLBs
              (if no remote cores affected, skip IPI/barrier entirely)
  4. REVOKE   on_domain_revoked(id, fallback)      ← for each RevokeDomain in batch
  5. UNLOCK   drop lock guard
```

The local path (step 3 `else` branch — no remote cores) skips IPI/barrier overhead entirely. This is the common case when operating on domains that are not currently running on another core.

**Usage**:

```rust
// Non-destructive (shared lock)
execute(&platform, /*exclusive=*/false, || {
    Capability::send_to(&cap, caller, new_owner, handle, Attributes::NONE)
        .map(|batch| ((), batch))
})?;

// Destructive (exclusive lock)
execute(&platform, /*exclusive=*/true, || {
    Capability::revoke_child_domain(&root, child_handle)
        .map(|batch| ((), batch))
})?;
```

---

## Lock Acquisition Order and TOCTOU

When multiple domain locks must be held simultaneously (e.g., sender + receiver for `send`), locks are always acquired in **ascending domain-ID order** to prevent deadlocks.

After each lock is acquired, the implementation checks whether the domain was revoked while waiting. If so, all already-acquired locks are released and `CapaError::DomainRevoked` is returned. This prevents operating on stale state without needing any additional TOCTOU checks.

---

## `sync.rs` — Lock Backend Abstraction

All internal engine code uses `crate::sync::RwLock` rather than any concrete lock type. `sync.rs` resolves this alias based on compile-time configuration:

| Condition | Backend |
|-----------|---------|
| `feature = "hosted"` (default) | `parking_lot::RwLock` — OS-backed, efficient, writer-preferring |
| `feature = "loom"` | `loom::sync::RwLock` — cooperative scheduler for exhaustive testing |
| neither | `spin::RwLock` — pure busy-wait, `no_std` compatible |

`Arc` and atomic types are similarly aliased, so the loom backend can intercept all synchronisation operations without any `#[cfg(loom)]` annotations in engine logic.

---

## Loom: Exhaustive Interleaving Testing

[loom](https://github.com/tokio-rs/loom) replaces `std::sync` with a cooperative scheduler and systematically explores every valid thread interleaving. Because each scenario involves 2–3 threads and a small number of synchronisation points, the state space is tractable.

```bash
cargo test --test loom_concurrency --features loom --release
cargo test --test loom_e2e        --features loom --release
cargo test --test loom_vp_switch  --features loom --release
```

The `--release` flag is important: loom's bookkeeping is CPU-intensive and release mode is 5–10× faster.

The loom test files live in `tests/concurrency/`. They cover:
- `loom_concurrency.rs` — raw RW lock scenarios (exclusive blocks shared, shared concurrency, revoke ordering).
- `loom_e2e.rs` — end-to-end capability operations (carve + send + revoke) under loom.
- `loom_vp_switch.rs` — VP switch and interrupt delivery under concurrent revocation.

---

## Scenario Reference

| Scenario | Expected behaviour |
|----------|--------------------|
| Two concurrent carves (shared + shared) | Both succeed in parallel |
| Revoke while carve in flight (exclusive vs. shared) | Carve blocks until revoke completes |
| Two concurrent revokes (exclusive + exclusive) | Serialised; second revoke sees the result of the first |
| Carve after domain revoked | Returns `CapaError::DomainRevoked` |
| Send while receiver is running on a remote core | IPI preempts receiver; update applied; receiver resumes |

