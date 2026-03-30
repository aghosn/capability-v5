# Address-Space Updates

## Why Updates Exist

Capability operations (carve, send, revoke, …) change *who owns what memory*. These logical changes must be reflected in hardware: page tables must be modified, TLBs must be flushed, memory may need to be zeroed. Rather than performing hardware operations inline (which would couple the capability engine tightly to a specific architecture), every operation returns an `UpdateBatch` — a pure description of what hardware work must be done. The platform then applies the batch when it is safe to do so.

---

## `Update` — the unit of hardware change

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
| `Unmap` | A domain loses access to a region (send to another domain; revocation of a carved child that was transferred away) | Address is virtual |
| `Map` | A domain gains access to a region (send target; carved child restored to parent on revocation) | `physical` is currently identity-mapped (`physical == address`) |
| `ChangeRights` | Access rights on an existing mapping change | Not yet emitted by current operations but defined for future use |
| `ZeroMemory` | A capability with `CLEAN` attribute is revoked | Operates on physical addresses; must complete before the `Map` that restores parent access |
| `RevokeDomain` | A domain is revoked (directly or as the result of a `VITAL` memory revocation) | `fallback` is the first non-revoked ancestor; `None` when triggered by a vital capability |
| `FlushTLB` | Platform needs to invalidate TLB entries for a domain | Emitted explicitly by platform implementations after mapping changes |

`ZeroMemory` does not carry a domain ID — it is a physical memory operation independent of any particular domain's address space.

---

## `UpdateBatch` — a transactional set of updates

```rust
pub struct UpdateBatch {
    updates:          Vec<Update>,
    affected_domains: BTreeSet<DomainId>,
    snapshots:        BTreeMap<DomainId, Vec<u8>>,  // reserved for rollback
}
```

Key properties:
- **Ordered**: updates within a batch are applied in insertion order, which matters (e.g. `ZeroMemory` before the `Map` that restores parent access).
- **Merged**: sub-operations (e.g. recursive revocation) produce their own batches and merge them together with `UpdateBatch::merge`. The final batch delivered to the platform is the union of all sub-operation updates.
- **Affected-domain index**: `affected_domains` is maintained automatically as updates are added. The platform uses this set to know which cores must be preempted before hardware changes can be applied safely.

---

## `UpdateProcessor` — per-core update queues

`UpdateProcessor` is an in-process structure (used by test/simulation environments and the CLI) that distributes batches to the cores that need to process them:

```
submit_updates(batch)
  → looks up which core each affected domain is running on
  → pushes a CoreUpdate { batch, status: Pending } into that core's queue
  → returns the set of cores to notify
```

Each `CoreUpdate` progresses through three states:

```
Pending → InProgress → Completed
```

Cores poll `get_pending_updates(core_id)`, process each batch, call `mark_completed`, and eventually call `clean_completed` to remove finished entries. This is the simulation-side analogue of the IPI + barrier protocol used in real hardware deployments.

---

## The `Platform` Trait and `execute()`

In a real deployment, `UpdateProcessor` is replaced by the `Platform` trait. The engine's `execute()` function is the single entry point that wraps a capability tree mutation in the full cross-core atomicity protocol:

### Protocol (§5.2 of the paper)

```
execute(platform, affected_domains, op):

  1. LOCK     acquire_op_locks(affected_domains)   ← sorted order, TOCTOU check
  2. OPERATE  (result, batch) = op()               ← pure tree mutation
  3. SYNC     if any affected domain is running on another core:
                 send_ipi(core)                    ← preempt affected cores
                 sync_barrier(0, n)                ← wait: all cores stopped
                 apply_update(u) for u in batch    ← EPT / memory changes
                 sync_barrier(1, n)                ← release: cores flush TLBs
              else:
                 apply_update(u) for u in batch    ← local path, no IPI needed
  4. REVOKE   on_domain_revoked(id, fallback)       ← for each RevokeDomain update
  5. UNLOCK   drop guard                            ← release all locks
```

**Local vs cross-core path**: if no domain in `affected_domains` is currently running on another core, the IPI/barrier overhead is skipped entirely — steps 3 is taken as the `else` branch.

### `acquire_op_locks` and TOCTOU

Locks are acquired in **ascending domain-ID order** to prevent deadlocks when two cores race with overlapping domain sets. After each lock is acquired, the implementation must check whether the domain was revoked while waiting — if so, all already-acquired locks are released and `CapaError::DomainRevoked` is returned. This prevents the caller from operating on stale state.

### Conflicting operation pairs

Operations on the same domain must be serialised. The table below lists the scenarios the lock protocol protects against:

| Scenario | Domains that must be locked |
|----------|-----------------------------|
| `send` while receiver runs on another core | sender + receiver |
| `send` rejected by receiver (rollback) | sender + receiver |
| `carve`/`alias` vs concurrent `revoke` of parent | parent domain |
| `create_child_domain` vs concurrent revoke of parent | parent domain |
| Concurrent revoke of overlapping subtrees | root parent |

### `on_domain_revoked`

After applying all hardware updates the platform's `on_domain_revoked(domain_id, fallback)` is called for each `RevokeDomain` update. The platform must:
1. Redirect any core running `domain_id` to `fallback` (or set it idle if `fallback` is `None` and there is no parent).
2. Unregister `domain_id` from its internal tracking.

`fallback` is provided by the capability engine when revocation originates from `revoke_child_domain` — the engine pre-computes the first non-revoked ancestor at the time of revocation. When revocation is triggered by a `VITAL` memory capability the engine has no domain CDT context, so `fallback = None` and the platform looks up the parent via the map populated by `register_domain`.
