# Operations

This article describes the semantics of each operation the capability engine exposes, the preconditions it enforces, and the side-effects it produces.

## General Precondition: Sealed Owner with API Permission

Before any operation is accepted, the engine validates the *owning domain* of the capability being operated on:

1. The `Ownership::owner_domain` weak reference is upgraded. If the domain has been revoked the upgrade fails and `CapaError::PermissionDenied` is returned.
2. The domain must be **Sealed** (`DomainNotSealed` otherwise).
3. The domain's `MonitorAPI` bitmap must include the required permission bit (`ApiNotAllowed` otherwise).

If `owner_domain` is `None` (e.g. root capabilities in tests), the check is skipped.

---

## Memory Operations

### Alias

**API bit**: `MonitorAPI::ALIAS`

Creates a *shared* child memory capability covering a sub-range of the parent.

**Preconditions**:
- Requested `access` is contained within parent's `access`.
- Requested rights are a subset of parent's rights.
- Requested range does **not** overlap any existing *carved* child of the parent (a carved child has exclusive ownership; sharing into that range would break exclusivity).

**Effects**:
- A new `MemoryRegion` with `kind = Alias`, `status = Aliased` is created.
- The child is added to the parent's `children` list.
- The parent retains its own access — no `Unmap` is emitted.
- **No `UpdateBatch` is returned** (the parent's mapping is unchanged).

**Overlap rules with existing children**:

| Existing child kind | Overlap allowed? |
|---------------------|-----------------|
| `Alias` | Yes — multiple aliases may cover the same range |
| `Carve` | No — `CapaError::InvalidAccess` |

---

### Carve

**API bit**: `MonitorAPI::CARVE`

Creates an *exclusive* child memory capability. The parent logically loses access to the carved range.

**Preconditions**:
- Requested `access` is contained within parent's `access`.
- Requested rights are a subset of parent's rights.
- Requested range does **not** overlap any existing child of the parent (neither carved nor aliased).

**Effects**:
- A new `MemoryRegion` with `kind = Carve`, `status` inherited from parent is created.
- The child is added to the parent's `children` list.
- If child owner == parent owner (same domain): no address-space change is needed — the domain already has access through the parent capability. **Empty `UpdateBatch` returned.**
- If the child is subsequently `send`-ed to another domain, the parent loses access at that point (see Send).

**Key insight**: carving alone does not unmap anything. The address-space effect happens only when ownership changes via `send`.

---

### Send

**API bit**: `MonitorAPI::SEND`

Transfers ownership of a capability to another domain.

**Preconditions**: owner domain is sealed with `SEND` permission.

**Effects**:
1. `Ownership.owner` and `Ownership.handle` are updated to the new owner. `owner_domain` is cleared (the new owner must set it).
2. If the old owner's **parent capability** covers the same range (i.e. the old owner retains access through the parent), no `Unmap` is emitted.
3. Otherwise an `Unmap` is emitted for the old owner.
4. A `Map` is always emitted for the new owner (identity mapping: `physical == virtual`).

---

### Revoke (memory)

**API bit**: `MonitorAPI::REVOKE`

Removes a child capability and recursively destroys its entire subtree.

**Algorithm** (depth-first, children first):

```
revoke_subtree(node):
  for each child of node:
      revoke_subtree(child)           // recurse first
  if node.attributes.CLEAN:
      emit ZeroMemory(node.access)
  if node.kind == Carve and node.owner != parent.owner:
      emit Unmap(node.owner, node.access)    // child domain loses access
      emit Map(parent.owner, node.access)    // parent regains access
  if node.attributes.VITAL:
      emit RevokeDomain(node.owner, fallback=None)
```

- **CLEAN**: physical memory is zeroed *before* the mapping is removed.
- **VITAL**: revoking this capability also revokes the domain that owns it. The platform must look up the parent domain for the fallback (the engine has no domain CDT context during vital revocation).
- **Carve restore**: a carved region that was sent to another domain means the parent previously lost access. Revocation restores that access by emitting a `Map` for the parent. If the carved child was never sent (same owner as parent), no address-space change is needed.

Two variants exist:
- `revoke_child(parent, child_handle)` — looks up the child by its current `LocalHandle`.
- `revoke_child_ref(parent, child_ref)` — identifies the child by `Arc` pointer equality (safe even if the child was sent and its handle changed).

---

## Domain Operations

### Create Child Domain

**API bit**: `MonitorAPI::CREATE`  
**Additional precondition**: parent domain must be **Sealed** (not just the owner check — the parent's own `data.is_sealed()` is verified separately).

**Preconditions**:
- `child_policy.cores` ⊆ `parent_policy.cores`
- `child_policy.api` ⊆ `parent_policy.api`  
  (`MonotonicityViolation` if either fails)

**Effects**:
- A new `Domain` with `status = Unsealed` is created.
- The child domain capability is added to the parent's `children` list.
- No `UpdateBatch` is produced (the child has no memory yet and is not yet executable).

---

### Seal

**Called on**: `Domain` directly (via `domain.write().data.seal()`), not through the CDT operation layer.

**Precondition**: domain status is `Unsealed` (`DomainSealed` error if already sealed).

**Effect**: status transitions to `Sealed`. The domain becomes executable and may now invoke `MonitorAPI` operations.

---

### Revoke Child Domain

**API bit**: `MonitorAPI::REVOKE`

Recursively revokes a domain and all its descendants.

**Algorithm** (depth-first, children first):

```
revoke_domain_subtree(node, fallback):
  for each child:
      revoke_domain_subtree(child, fallback)
  node.data.revoke()                          // status → Revoked
  emit RevokeDomain(node.data.id, fallback)
```

`fallback` is the parent's `id` at the time `revoke_child_domain` is called. Every node in the subtree receives the *same* fallback so the platform never needs to walk the CDT to find a safe redirect target — the engine has already done that work at revocation time.

---

## Monotonicity Summary

Every derivation step enforces that the child is *weaker* than or equal to the parent:

| Dimension | Rule |
|-----------|------|
| Memory address range | child range ⊆ parent range |
| Memory rights | child rights ⊆ parent rights |
| Domain core bitmap | child cores ⊆ parent cores |
| Domain API bitmap | child API ⊆ parent API |
