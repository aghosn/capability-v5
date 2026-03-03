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

### Ordering guarantees within a revocation batch

For any subtree node, updates appear in this order:

1. All updates from the node's children (recursive, leaves first).
2. `ZeroMemory` for this node (if `CLEAN`).
3. `ChangeRights` pair — remove access from the loser, restore access to the winner (if `Carve` and ownership transferred).
4. `RevokeDomain` for the owning domain (if `VITAL`).

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

This is the simulation-side analogue of the IPI + barrier protocol used in real deployments. The CLI platform (`CLI-2026/src/platform.rs`) uses `UpdateProcessor` to drive simulated address-space changes.
