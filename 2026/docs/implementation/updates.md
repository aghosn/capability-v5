# Updates

## Why Updates Exist

Capability operations (carve, send, revoke) change *who owns what memory*. These logical changes must eventually be reflected in hardware: page tables must be modified, TLBs flushed, and physical memory may need to be zeroed. Rather than performing hardware operations inline — which would couple the capability engine to a specific architecture — every operation returns an `UpdateBatch`. The platform applies the batch when it is safe to do so.

---

## The `Update` Enum

```rust
pub enum Update {
    Unmap        { domain: DomainId, address: u64, size: u64 },
    Map          { domain: DomainId, address: u64, size: u64,
                   physical: u64, read: bool, write: bool, execute: bool },
    ChangeRights { domain: DomainId, address: u64, size: u64,
                   read: bool, write: bool, execute: bool },
    ZeroMemory   { address: u64, size: u64 },
    RevokeDomain { domain: DomainId, fallback: Option<DomainId> },
    FlushTLB     { domain: DomainId },
}
```

| Variant | When emitted | Notes |
|---------|-------------|-------|
| `Unmap` | A domain loses access to a range (send to another domain; carved child revoked after transfer) | Address is virtual |
| `Map` | A domain gains access to a range (send recipient; parent regains access after carved child revoked) | Currently identity-mapped: `physical == address` |
| `ChangeRights` | Access rights change on an existing mapping | Defined for future use; not yet emitted |
| `ZeroMemory` | A `CLEAN`-attributed capability is revoked | Physical address operation; must complete before the `Map` that restores parent access |
| `RevokeDomain` | A domain is revoked (explicit or via `VITAL` trigger) | `fallback` is the first non-revoked ancestor; `None` when triggered by vital memory revocation |
| `FlushTLB` | Platform must invalidate TLB entries for a domain | Emitted explicitly by platform implementations after mapping changes |

`ZeroMemory` carries no domain ID — it is a physical operation independent of any address space.

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

- **Ordered**: updates within a batch are applied in insertion order. This matters: `ZeroMemory` must precede the `Map` that restores parent access.
- **Merged**: sub-operations (e.g., each node in a recursive revocation) produce their own small batches and merge them into a single batch via `UpdateBatch::merge`. The final batch delivered to the platform is the union of all sub-operation updates.
- **Affected-domain index**: `affected_domains` is maintained automatically as updates are added. The platform uses this set to determine which cores must be preempted before hardware changes are applied (see [concurrency.md § execute()](concurrency.md#the-execute-function)).

### Ordering guarantees within a revocation batch

For any subtree node, updates appear in this order:

1. All updates from the node's children (recursive, leaves first).
2. `ZeroMemory` for this node (if `CLEAN`).
3. `Unmap` / `Map` pair for access restoration (if `Carve` and ownership transferred).
4. `RevokeDomain` for the owning domain (if `VITAL`).

---

## `UpdateProcessor` — Simulation Helper

`UpdateProcessor` is used by test environments and the CLI simulator to distribute update batches to per-core queues without requiring real hardware:

```rust
pub struct UpdateProcessor {
    core_queues: Vec<Mutex<VecDeque<CoreUpdate>>>,
}

pub struct CoreUpdate {
    pub batch:  UpdateBatch,
    pub status: UpdateStatus,  // Pending | InProgress | Completed
}
```

**Workflow**:

```
submit_updates(batch)
  → for each DomainId in batch.affected_domains:
        look up which core it is running on
        push CoreUpdate { batch, status: Pending } to that core's queue
  → return the set of notified cores

get_pending_updates(core_id)  → iterator over Pending CoreUpdates for that core
mark_completed(core_id, update_id)
clean_completed(core_id)       → remove Completed entries
```

This is the simulation-side analogue of the IPI + barrier protocol used in real deployments. The CLI platform (`CLI-2026/src/platform.rs`) uses `UpdateProcessor` to drive simulated address-space changes.
