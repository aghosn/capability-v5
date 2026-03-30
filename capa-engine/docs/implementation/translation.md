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
