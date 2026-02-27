# Tests to Port to Domain-Mediated API

All tests below still call low-level `pub #[doc(hidden)]` primitives. They must be ported before
those primitives can be made `pub(crate)`.

## Low-level functions to eliminate from external tests

| Primitive | Replace with |
|-----------|-------------|
| `Capability::carve_child` | `Capability::carve_memory` |
| `Capability::alias_child` | `Capability::alias_memory` |
| `Capability::revoke_child` | `Capability::revoke_memory_child` |
| `Capability::revoke_child_ref` | `Capability::revoke_memory_child` (use saved SubHandle) |
| `Capability::send_to` | `Capability::send_memory` |
| `Capability::create_child_domain` | `Capability::create_domain` |
| `Capability::revoke_child_domain` | `Capability::revoke_domain` |
| `domain.write().data.seal()` | `Capability::seal_domain_op(parent, child_h)` |
| `cap.read().compute_view()` | no domain-mediated equivalent yet — leave as-is |

## Domain-mediated API signatures

```rust
// Returns (child_LocalHandle, child_SubHandle, UpdateBatch)
pub fn carve_memory(caller: &CapabilityRef<Domain>, parent: LocalHandle, access: Access) -> Result<(LocalHandle, SubHandle, UpdateBatch)>

// Returns (child_LocalHandle, child_SubHandle)
pub fn alias_memory(caller: &CapabilityRef<Domain>, parent: LocalHandle, access: Access) -> Result<(LocalHandle, SubHandle)>

// Revoke using SubHandle — stable across sends
pub fn revoke_memory_child(caller: &CapabilityRef<Domain>, parent: LocalHandle, child_sub: SubHandle) -> Result<UpdateBatch>

// Create unsealed child domain; returns LocalHandle in parent's domain table
pub fn create_domain(parent: &CapabilityRef<Domain>, policy: DomainPolicy) -> Result<LocalHandle>

// Revoke child domain via its LocalHandle in parent's domain table
pub fn revoke_domain(parent: &CapabilityRef<Domain>, child: LocalHandle) -> Result<UpdateBatch>

// Seal the child domain at the given LocalHandle in parent's domain table
pub fn seal_domain_op(caller: &CapabilityRef<Domain>, cap: LocalHandle) -> Result<()>
```

## Setup helper pattern (use in all ported tests)

```rust
fn make_dm_mem(size: u64) -> (CapabilityRef<Domain>, LocalHandle, CapabilityRef<MemoryRegion>) {
    let dom: CapabilityRef<Domain> = Capability::new_root(0, 0, Domain::new_root(1));
    let owner_id = dom.read().data.id;
    let h: LocalHandle = 1;
    let mem = Capability::new_root(owner_id, h, MemoryRegion::new_root(0x0, size));
    dom.write().data.add_memory_capability(h, std::sync::Arc::downgrade(&mem));
    (dom, h, mem)
}
```

**Critical:** `_mem` must stay alive for the test duration — the domain table holds only a `Weak` ref.
`Domain::new_root(n)` creates an already-sealed domain. `owner_id` comes from `dom.read().data.id`.

To access the child Arc after carve/alias:
```rust
let (child_lh, child_sub, _) = Capability::carve_memory(&dom, mem_h, access)?;
let child_ref = dom.read().data.get_memory_capability(child_lh).unwrap().upgrade().unwrap();
```

For nested carve/alias (child is auto-registered in dom's table, so use `child_lh` as parent):
```rust
let (c1_lh, _, _) = Capability::carve_memory(&dom, mem_h, c1_access)?;
let (c2_lh, _, _) = Capability::carve_memory(&dom, c1_lh, c2_access)?;
```

For `send_memory`, register a receiver in dom's domain_capabilities table:
```rust
let receiver = Capability::new_root(0, 0, Domain::new(DomainPolicy::new_root(1)));
dom.write().data.add_domain_capability(recv_h, std::sync::Arc::downgrade(&receiver));
Capability::send_memory(&dom, child_lh, recv_h, Attributes::NONE)?;
```

In loom tests: use `std::sync::Arc::downgrade` (not `Arc::downgrade`) because `Arc` in loom scope = `loom::sync::Arc`.

---

## Files to port

### tests/unit/capability.rs (41 calls)

Tests and their target replacements:

- `test_alias_child` → `alias_memory`; check `children.len()` + `has_parent()` on looked-up child ref
- `test_carve_child` → `carve_memory`; check `children.len()`; **drop the `updates.is_empty()` assert** (domain-mediated carve produces updates)
- `test_revoke_child` → `carve_memory` + `revoke_memory_child`; check `children.len() == 0`
- `test_nested_carve` → `carve_memory` twice (nested via child_lh); check `data.kind`, `data.status`, `data.access`
- `test_nested_alias` → same with `alias_memory`
- `test_carve_then_alias_then_carve` → chain of domain-mediated ops
- `test_revoke_complex_subtree` → domain-mediated ops
- `test_revoke_nonexistent` → `revoke_memory_child` with a SubHandle that doesn't exist → Err
- `test_compute_view_with_carves` → **leave `compute_view()` as-is** (no domain-mediated equivalent)
- `test_view_with_aliases_unchanged` → **leave as-is**
- `test_create_child_domain` → `create_domain`; child is UNSEALED — adjust any `is_sealed()` assertion
- `test_revoke_child_domain` → `create_domain` + `revoke_domain`; `!updates.is_empty()` still holds
- `test_domain_tree_revocation` → `create_domain` + `seal_domain_op` + nested `create_domain` + `revoke_domain`
- `test_send_capability` → `carve_memory` + `send_memory` (unsealed receiver = immediate transfer); check `owned.owner` changed and Map update present
- `test_send_with_attributes` → same; check `owned.attributes.vital()` and `.clean()`

**Move to `src/capability.rs` as `#[cfg(test)] mod unit_internal_tests`** (call MemoryRegion methods directly, unreachable via domain API):
- `test_carve_out_of_bounds` — calls `root.read().data.carve(access)` directly
- `test_alias_excessive_rights` — sets `data.access.rights` directly + calls `data.alias()`
- `test_nested_carve_invalid_due_to_rights` — calls `carve.read().data.carve(invalid)` directly

---

### tests/concurrency/basic.rs (11 calls)

- `test_concurrent_child_creation` (line 61) → `create_domain`
- `test_concurrent_memory_operations` (line 105) → `alias_memory`; check `data.status` via looked-up ref
- `test_concurrent_carve_operations` (line 147) → `carve_memory`; check `data.status`; **drop updates assert**
- `test_concurrent_read_write_mix` (line 200) → `create_domain`
- `test_concurrent_revocation` (line 233, 246) → `create_domain`, track returned LocalHandles; `revoke_domain`
- `test_memory_view_computation_concurrent` (lines 277-278) → `carve_memory`; `compute_view()` **leave as-is**
- `test_attestation_concurrent` (line 316) → `create_domain`
- `test_stress_test_mixed_operations` (lines 375, 390) → `create_domain`, `alias_memory`

Note: most of these don't need `make_dm_mem` — if the test operates without a caller domain (e.g. just checks `children.len()`), create a sealed domain and register the memory cap at startup.

---

### tests/concurrency/platform.rs (6 calls)

One test: `test_revoke_child_domain_carries_fallback`

- Replace `create_child_domain(&root, policy, ROOT_ID)` → `create_domain(&root, policy)` → returns `child_h`
- Get child ref via `root.read().data.get_domain_capability(child_h).unwrap().upgrade().unwrap()`
- Replace `child.write().data.seal()` → `seal_domain_op(&root, child_h)`
- Replace `revoke_child_domain(&root, CHILD_HANDLE)` → `revoke_domain(&root, child_h)`
- Test still verifies `RevokeDomain` update with `fallback = Some(ROOT_ID)` — unchanged

---

### tests/concurrency/crosscore.rs (13 calls)

- `test_crosscore_send_triggers_ipi` (lines 297, 301) → `carve_memory` + `send_memory`; need sealed domain for sender + receiver registered in domain table
- `test_crosscore_revoke_with_fallback` (lines 335, 351) → `create_domain` + `seal_domain_op` + `revoke_domain`
- `test_barrier_calls_during_crosscore_operation` (lines 390, 393) → `carve_memory` + `send_memory`
- `test_concurrent_operations_with_different_cores` (line 440) → `carve_memory`; each domain needs its own mem cap in its own domain context
- `test_multiple_cores_affected_by_single_operation` (lines 487, 491, 497) → `carve_memory` + `send_memory` twice (sender→recv1, recv1→recv2); need chained domain contexts
- `test_ipi_not_sent_for_local_operations` (line 535) → `carve_memory`
- `test_exclusive_lock_serializes_revoke` (lines 569, 578) → `create_domain` + `seal_domain_op` + `revoke_domain`

---

### tests/concurrency/loom_concurrency.rs (47 calls, 6 test functions)

The file already has `dm_make_root` helper (line 1275) — use it.
Tests in §7.4 (basic RwLock) and §7.7 (send/accept/reject) already use domain-mediated API — leave them.
Tests in §7.8 (`loom_dm_*`) already use domain-mediated API — leave them.

Only §7.6 primitive tests need porting:

| Test (line) | Operations | Port to |
|-------------|-----------|---------|
| `revoke_vs_carve` (265) | `carve_child` + `revoke_child_ref` | `carve_memory` + `revoke_memory_child` |
| `concurrent_sends` (313) | `carve_child` + `send_to` ×2 | `carve_memory` + `send_memory` ×2 |
| `send_vs_carve_same_parent` (361) | `carve_child` + `send_to` + `carve_child` | same |
| `concurrent_aliases_non_overlapping` (420) | `alias_child` ×2 | `alias_memory` ×2 |
| `alias_vs_carve_overlapping` (474) | `carve_child` + `alias_child` | `carve_memory` + `alias_memory` |
| `alias_while_sibling_revoked` (526) | `carve_child` + `revoke_child_ref` + `alias_child` | `carve_memory` + `revoke_memory_child` + `alias_memory` |
| `double_send_same_capability` (594) | `carve_child` + `send_to` ×2 | `carve_memory` + `send_memory` ×2 |
| `revoke_after_send` (665) | `carve_child` + `send_to` + `revoke_child_ref` | `carve_memory` + `send_memory` + `revoke_memory_child` |
| `region_reuse_after_revoke` (732) | `carve_child` + `revoke_child_ref` + `carve_child` | `carve_memory` + `revoke_memory_child` + `carve_memory` |
| `concurrent_domain_creation` (809) | `create_child_domain` ×2 | `create_domain` ×2 |
| `domain_revoke_vs_creation` (864) | `create_child_domain` + `revoke_child_domain` + `create_child_domain` | `create_domain` + `revoke_domain` + `create_domain` |

For `send_memory` in loom tests: need a receiver domain in the caller's domain_capabilities table.
Use existing `make_sealed_send_domain()` helper + `dom.write().data.add_domain_capability(recv_h, std::sync::Arc::downgrade(&receiver))`.

**Also:** `concurrent_carves_non_overlapping` (187) and `concurrent_carves_overlapping` (224) also call `carve_child` — port those too.

---

## After all files are ported

Run:
```sh
grep -rn "carve_child\|alias_child\|send_to\b\|revoke_child\b\|create_child_domain\|revoke_child_domain\|revoke_child_ref\b" tests/ --include="*.rs"
# should output nothing
```

Then in `src/capability.rs`, change each `#[doc(hidden)]\npub fn` to `pub(crate) fn` for:
- `set_owner_domain`, `add_child`, `alias_child`, `carve_child`, `send_to`, `revoke_child_ref`, `revoke_child`, `compute_view`, `create_child_domain`, `revoke_child_domain`

Run full test suite to confirm:
```sh
cargo test
cargo test --test loom_concurrency --features loom --release
```

---

## What is NOT being ported

- `tests/concurrency/basic.rs::test_memory_view_computation_concurrent` — calls `compute_view()` which has no domain-mediated equivalent; leave the `compute_view()` call as-is even after porting the setup
- `tests/unit/capability.rs::test_compute_view_with_carves` and `test_view_with_aliases_unchanged` — same reason

These 3 tests will keep calling `compute_view()` after porting. If `compute_view` must also become `pub(crate)`, a domain-mediated wrapper `compute_address_space` would need to be added first.
