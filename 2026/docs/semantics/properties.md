# Monotonicity and Safety Properties

This article enumerates the invariants the capability engine maintains and explains why each matters for security.

---

## P1 — Capability Derivation Monotonicity

> Every child capability is *at most as powerful* as its parent.

Enforced at creation time for every derivation operation:

| Dimension | Enforcement point |
|-----------|------------------|
| Memory address range | `Access::contained_in` in `MemoryRegion::alias` / `carve` |
| Memory access rights | `Access::rights_subset_of` in `MemoryRegion::alias` / `carve` |
| Domain core bitmap | `(child.cores & !parent.cores) == 0` in `DomainPolicy::is_subset_of` |
| Domain API bitmap | `MonitorAPI::is_subset_of` in `DomainPolicy::is_subset_of` |

Because derivation is the only way to create a non-root capability, and each step is checked, the property holds for all nodes at any depth by induction.

---

## P2 — Memory Exclusivity

> At any point in time, at most one domain has exclusive (writable/executable) access to any given physical page, unless that access is explicitly shared via `alias`.

How it is maintained:

- **Carve overlap rejection**: `carve_child` scans all existing children and rejects any new carve that overlaps an existing child (carved or aliased). This prevents two exclusive children from covering the same range.
- **Alias-over-carve rejection**: `alias_child` rejects any alias that overlaps an existing *carved* child. The carved child has exclusive ownership; an alias would silently share that range.
- **Access restoration on revocation**: when a carved child that was transferred to another domain is revoked, a `Map` update is emitted for the parent *after* the child is unmapped, restoring the invariant that exactly one domain holds the range.

---

## P3 — Capability Confinement

> A domain cannot forge capabilities. The only way to obtain a capability is to receive one from a domain that already holds it.

Enforced structurally: capabilities are `Arc<RwLock<Capability<T>>>` values. They cannot be constructed by value (all constructors are internal to the engine). A domain can only act on capabilities it explicitly holds in its `memory_capabilities` or `domain_capabilities` maps.

---

## P4 — Operation Authority

> A domain may only invoke a capability operation if its policy explicitly permits it.

The `Ownership::validate_operation(required_api)` check is called at the top of every operation:
1. The owning domain must be reachable (not revoked).
2. The owning domain must be `Sealed`.
3. The owning domain's `MonitorAPI` bitmap must have the required bit set.

If any check fails the operation is rejected before any tree mutation occurs.

---

## P5 — Domain Hierarchy Confinement for Switches

> A domain can only switch execution to its direct parent or one of its direct children.

Enforced by the CDT-adjacency check in `SwitchManager::switch` using `Arc::ptr_eq`. This prevents a domain from jumping to an arbitrary peer domain, which could bypass the policy hierarchy.

---

## P6 — Revocation Completeness

> Revoking a capability destroys all capabilities derived from it, transitively.

Enforced by the recursive `revoke_subtree` / `revoke_domain_subtree` algorithms. Children are removed before the node itself is processed, so no live child can escape destruction by holding a dangling parent reference. After revocation the `Arc` reference count for each node in the subtree drops to zero (no external strong references remain) and the memory is freed.

---

## P7 — No Authority Amplification via `send`

> Sending a capability to another domain does not increase the total authority in the system. The sender loses access (subject to the parent-retention rule); the receiver gains exactly what was sent.

The `send_to` implementation transfers ownership without changing the `MemoryRegion`'s `access` or rights. The emitted `Unmap` / `Map` pair is a bookkeeping update, not an authority change.

---

## P8 — Sealed-Domain Immutability

> Once a domain is sealed, its policy cannot be changed and its capability set can only grow via the explicit `RECEIVE_AFTER_SEAL` mechanism.

After `seal()` succeeds:
- `create_child_domain` requires the parent to be sealed (not the child being created).
- The `pending_capabilities` queue is the only route by which a sealed domain can receive new capabilities, and only if its `MonitorAPI` has `RECEIVE_AFTER_SEAL` set.
- No operation re-opens or modifies a sealed domain's policy.

---

## What the Engine Does Not Enforce

For completeness, the following properties are **outside** the capability engine and are delegated to the platform:

| Property | Platform responsibility |
|----------|------------------------|
| Physical isolation (page-table enforcement) | `Platform::apply_update` must correctly modify EPT/page tables |
| TLB coherence after mapping changes | `Platform::apply_update` / `sync_barrier` / TLB shootdown |
| Cross-core atomicity of hardware updates | Two-barrier protocol in `execute()` and `Platform::sync_barrier` |
| Core-to-domain binding at runtime | `Platform::set_core_domain` / `clear_core_domain` |
| Fallback resolution for vital revocations | `Platform::register_domain` parent map |
