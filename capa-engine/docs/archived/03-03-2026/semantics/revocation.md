# Revocation

Revocation is the act of permanently destroying a capability and all capabilities derived from it. It is depth-first, recursive, and produces a single `UpdateBatch` describing all resulting hardware changes.

---

## Memory Capability Revocation

### Entry points

| Function | How the child is identified |
|----------|----------------------------|
| `Capability::revoke_child(parent, child_handle)` | By the child's current `LocalHandle` |
| `Capability::revoke_child_ref(parent, child_ref)` | By `Arc` pointer equality |

Use `revoke_child_ref` when the capability may have been `send`-ed (its handle changes on transfer).

Both entry points require `MonitorAPI::REVOKE` on the owning domain (see [Operations](operations.md)).

### Algorithm

```
revoke_subtree(node):
    children ← take node.children          // atomically remove all children
    for child in children:
        revoke_subtree(child)              // depth-first: leaves first

    if node.owned.attributes.CLEAN:
        emit ZeroMemory { address: node.data.access.start,
                          size:    node.data.access.size }

    if node.data.kind == Carve:
        parent ← node.parent.upgrade()
        if parent exists and parent.owner ≠ node.owner:
            // child was sent to a different domain → parent lost access at send time
            emit Unmap { domain:  node.owner,
                         address: node.data.access.start,
                         size:    node.data.access.size }
            emit Map   { domain:  parent.owner,
                         address: node.data.access.start,
                         size:    node.data.access.size,
                         physical: same as address (identity),
                         rights:  parent.data.access.rights }

    if node.owned.attributes.VITAL:
        emit RevokeDomain { domain: node.owned.owner, fallback: None }
```

### Ordering guarantees

Within the merged batch, updates appear in this order for a given subtree node:
1. All updates from the node's children (recursive).
2. `ZeroMemory` for this node (if CLEAN).
3. `Unmap` / `Map` for access restoration (if Carve and ownership changed).
4. `RevokeDomain` for the owning domain (if VITAL).

This ordering ensures memory is zeroed before the parent mapping is re-established, and domain revocation occurs after the domain has been unmapped.

---

## The CLEAN Attribute

When a capability with `CLEAN` set in its ownership attributes is revoked:

- A `ZeroMemory { address, size }` update is emitted for the physical range.
- The platform applies this before re-mapping the range to the parent, so the parent receives zeroed memory.
- `ZeroMemory` does not carry a domain ID — it is a physical operation, not a virtual-address operation.

Intended use: sensitive data regions (keys, secrets, credentials) that must not be visible to the parent or any future holder after the child is done with them.

---

## The VITAL Attribute

When a capability with `VITAL` set in its ownership attributes is revoked:

- A `RevokeDomain { domain: owner, fallback: None }` update is emitted.
- The platform calls `on_domain_revoked(owner, None)` and must resolve the fallback from its own `register_domain` parent map (the engine has no domain CDT context during vital revocation).
- The domain revocation is itself cascading (see Domain Revocation below).

Intended use: the memory region is the domain's "life support" — if that memory is taken away, the domain cannot continue to exist safely.

---

## Domain Capability Revocation

Domain revocation is triggered either:
- **Explicitly**: via `Capability::revoke_child_domain(parent, child_handle)`.
- **Implicitly**: as a side-effect of a `VITAL` memory capability revocation.

### Algorithm

```
revoke_domain_subtree(node, fallback):
    children ← take node.children
    for child in children:
        revoke_domain_subtree(child, fallback)   // same fallback for whole subtree

    node.data.revoke()                            // status → Revoked
    emit RevokeDomain { domain: node.data.id, fallback }
```

The `fallback` is the parent domain's `id` at the time `revoke_child_domain` is called (i.e. the first non-revoked ancestor). Every node in the subtree gets the **same fallback** — the engine pre-computes it once so the platform does not need to traverse the CDT during interrupt/IPI handling.

### Consequences

- Once `status = Revoked`, all operations on the domain return errors.
- All `CapabilityWeak` references to the domain's capability (stored in `Domain::domain_capabilities` of other domains) will fail to upgrade.
- The platform is responsible for evicting the domain from any core it is currently running on via `on_domain_revoked`.

---

## Memory Capability vs Domain Capability Revocation

| Aspect | Memory revocation | Domain revocation |
|--------|------------------|-------------------|
| Initiated by | Parent's `revoke_child` / `revoke_child_ref` | Parent's `revoke_child_domain` or VITAL trigger |
| Recurses into | Sub-capabilities of same type | Sub-domains (domain CDT) |
| Emits | `Unmap`, `Map`, `ZeroMemory`, optionally `RevokeDomain` | `RevokeDomain` for every node |
| `fallback` | Always `None` (platform looks up parent) | Pre-computed from direct parent at call time |
| Domain status change | None (unless VITAL) | `Revoked` for every node in subtree |

---

## Aliased vs Carved: Access Restoration

| Child kind | Ownership changed via `send`? | On revocation |
|------------|------------------------------|---------------|
| `Alias` | N/A (alias doesn't transfer exclusive ownership) | Nothing to restore; parent always had access |
| `Carve`, same owner | No | Parent never lost access; nothing to restore |
| `Carve`, different owner | Yes | `Unmap` from child owner + `Map` back to parent |
