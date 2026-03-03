# Memory Region Capabilities

## The MemoryRegion Type

A memory capability wraps a `MemoryRegion` describing a contiguous address range:

```
MemoryRegion {
    kind:    RegionKind   (Carve | Alias)
    status:  RegionStatus (Exclusive | Aliased)
    access:  Access { start: u64, size: u64, rights: Rights }
}
```

`kind` records how the region was derived; `status` records whether it is exclusively or jointly held. The `access` field provides containment and overlap arithmetic used by every derivation check.

---

## Access Rights

Rights are a three-bit bitmap:

| Flag | Meaning |
|------|---------|
| `R` | Region may be read |
| `RW` | Region may be read and written |
| `RX` | Region may be read and executed |
| `RWX` | Full access |

**Monotonicity rule**: a child's rights must be a *subset* of the parent's. Attempting to create a child with broader rights is rejected with `InvalidAccess`.

---

## Ownership Attributes

Attributes are per-ownership metadata set at `send` time. They affect behaviour at revocation:

| Attribute | Effect at revocation |
|-----------|---------------------|
| `CLEAN` | Zero physical memory before restoring parent access |
| `VITAL` | Also revoke the domain that owns this capability |
| `HASH` | Region content is/should be hashed for attestation |
| `META` | Informational: this region holds monitor metadata |

---

## Carve vs. Alias — Effect on Parent Access

These two operations differ in what they do to the **parent**:

- **Carve** — the parent **loses access** to the carved range. That range is handed off exclusively to the child. The parent regains access only when the child is revoked.
- **Alias** — the parent **retains access**. Both parent and child can access the same range simultaneously. Revoking an alias restores nothing to the parent (the parent never lost access).

## Exclusive vs. Aliased

`RegionStatus` records whether the region is exclusively held or shared. This is a property of the **derivation chain**, not just the immediate operation:

### Exclusive (`RegionStatus::Exclusive`)

A region is Exclusive when it was obtained through an **unbroken chain of carves** from the root. No alias appears anywhere in its ancestry. This guarantees that at most one party holds access to the physical range at any point.

### Aliased (`RegionStatus::Aliased`)

A region is Aliased when an **alias appears somewhere in its derivation chain** — meaning at least one ancestor retained access when the region was derived. The physical memory is therefore shared (or potentially shared) with other holders above the alias point.

The status propagates downward: carving from an aliased region produces an `Aliased` carved child. The carve still removes access from the immediate parent, but the grandparent (and any ancestor above the alias) still has access. The region is not exclusively held.

**Example — alias then carve:**

```
cap> alias r0 shared 0x10000 0x10000 RW
# shared: kind=Alias, status=Aliased   — r0 still has access to [0x10000..0x20000)

cap> carve shared sub 0x10000 0x4000 RW
# sub:    kind=Carve, status=Aliased   — 'shared' loses access to [0x10000..0x14000)
#                                        but r0 still has access through the original alias
```

`sub` is Aliased, not Exclusive: `r0` retained access when `shared` was created, so exclusive physical ownership is not guaranteed regardless of what happens below.

---

## Containment Invariant

For every non-root memory capability `C` with parent `P`:

> `C.access` is contained within `P.access`
> `C.access.rights` ⊆ `P.access.rights`

This is validated at creation and never re-checked — the invariant is structural and cannot be broken once established.

---

## Allowed Operations

### `carve` — Create an Exclusive Child

**Requires**: `CARVE` API permission on the operating domain.

**Preconditions**:
- Requested range is fully contained within the parent region.
- Requested rights are a subset of the parent's rights.
- Requested range does not overlap any existing child of the parent (neither carved nor aliased).

**Effect**: a new `Carve`-kind child is created. The parent logically loses access to the carved range (the hardware update is deferred until the capability is sent to a different domain).

#### ✓ Success example

```
cap> init root 0x100000
cap> carve r0 region1 0x10000 0x10000 RWX
✓ Carved memory region 'region1' [0x10000..0x20000)

cap> carve r0 region2 0x40000 0x20000 RW
✓ Carved memory region 'region2' [0x40000..0x60000)
```

#### ✗ Failure: out-of-bounds range

```
cap> carve r0 bad 0xF0000 0x20000 RWX
✗ Error: access out of bounds — [0xF0000..0x110000) exceeds parent [0x0..0x100000)
```

#### ✗ Failure: overlap with existing child

```
cap> carve r0 region1 0x10000 0x10000 RWX
cap> carve r0 overlap 0x15000 0x10000 RW
✗ Error: invalid access — range [0x15000..0x25000) overlaps existing child 'region1'
```

#### ✗ Failure: rights amplification

```
cap> carve r0 ro_region 0x20000 0x10000 R      # R parent
cap> carve ro_region wide 0x20000 0x1000 RWX
✗ Error: invalid access — requested rights RWX exceed parent rights R
```

#### What it looks like in code

```rust
// Static form: explicit owner domain and handle
let (child, updates) = Capability::carve_child(&parent, access, owner_id, handle)?;

// Extension trait form: infers owner from the capability itself
let (child, updates) = parent_ref.carve(access, handle)?;
```

---

### `alias` — Create a Shared Child

**Requires**: `ALIAS` API permission on the operating domain.

**Preconditions**:
- Requested range is fully contained within the parent region.
- Requested rights are a subset of the parent's rights.
- Requested range does not overlap any existing *carved* child of the parent.

**Effect**: a new `Alias`-kind child is created. The parent retains its access. No hardware update is emitted.

#### ✓ Success example

```
cap> init root 0x100000
cap> alias r0 shared1 0x10000 0x10000 RW
✓ Aliased memory region 'shared1' [0x10000..0x20000)

# Overlapping aliases are allowed
cap> alias r0 shared2 0x15000 0x8000 R
✓ Aliased memory region 'shared2' [0x15000..0x1D000)
```

#### ✗ Failure: overlap with a carved child

```
cap> carve r0 exclusive 0x10000 0x10000 RWX
cap> alias r0 shared 0x15000 0x8000 R
✗ Error: invalid access — range [0x15000..0x1D000) overlaps carved child 'exclusive'
```

#### What it looks like in code

```rust
// Static form
let child = Capability::alias_child(&parent, access, owner_id, handle)?;

// Extension trait form
let child = parent_ref.alias(access, handle)?;
```

---

### `send` — Transfer Ownership to a Domain

**Requires**: `SEND` API permission on the operating domain.

**Effect**:
1. Ownership is transferred to the target domain.
2. If the old owner retains access through the parent (same-owner carve), no hardware unmap is emitted.
3. Otherwise an `Unmap` is emitted for the old owner and a `Map` for the new owner.

#### ✓ Success: send carved memory to a child domain

```
cap> init root 0x1000000
cap> create-domain root app 0b1111 GET,ATTEST,SWITCH
cap> carve r0 app_mem 0x100000 0x100000 RWX
cap> send app_mem app CLEAN
✓ Sent 'app_mem' to unsealed domain 'app' with auto-allocated handle 1
```

#### ✓ Success: send aliased memory (shared with two domains)

```
cap> create-domain root dom1 0b1111 GET,ATTEST
cap> create-domain root dom2 0b1111 GET,ATTEST
cap> alias r0 shared 0x800000 0x10000 RW
cap> send shared dom1
cap> send shared dom2
```

#### ✗ Failure: send to a sealed domain without RECEIVE_AFTER_SEAL

```
cap> seal app
cap> carve r0 extra 0x500000 0x10000 RW
cap> send extra app
✗ Error: domain is sealed and does not have RECEIVE_AFTER_SEAL permission
```

#### What it looks like in code

```rust
let updates = Capability::send_to(&region, caller_domain, new_owner_id, new_handle, Attributes::CLEAN)?;
// Extension trait form
let updates = region_ref.send(new_owner_id, new_handle, Attributes::CLEAN)?;
```

---

### `revoke` — Destroy a Child and its Descendants

**Requires**: `REVOKE` API permission on the operating domain.

**Effect**: depth-first recursive destruction of the child and all capabilities derived from it. For each node:
1. Recursively revoke all its children.
2. If `CLEAN`: emit `ZeroMemory` for the physical range.
3. If `Carve` and ownership changed (capability was sent): emit `Unmap` for current owner, `Map` to restore parent.
4. If `VITAL`: emit `RevokeDomain` for the owning domain.

#### ✓ Success: revoke a carved region, parent regains access

```
cap> init root 0x1000000
cap> create-domain root app 0b1111 GET,ATTEST
cap> carve r0 app_mem 0x100000 0x100000 RWX
cap> send app_mem app
cap> seal app
cap> revoke r0 app_mem
✓ Revoked 'app_mem'. Parent 'r0' regains access to [0x100000..0x200000).
```

#### ✓ Success: CLEAN attribute zeros memory on revocation

```
cap> carve r0 secret 0x200000 0x10000 RWX
cap> send secret app CLEAN
cap> revoke r0 secret
✓ Revoked 'secret'. Memory [0x200000..0x210000) was zeroed before parent regained access.
```

#### ✓ Success: VITAL attribute revokes the owning domain

```
cap> carve r0 lifeline 0x300000 0x10000 RWX
cap> send lifeline app VITAL
cap> revoke r0 lifeline
✓ Revoked 'lifeline'. Domain 'app' was also revoked (VITAL attribute).
```

#### ✗ Failure: revoking a non-child (handle not found)

```
cap> revoke r0 unrelated_region
✗ Error: capability 'unrelated_region' is not a child of 'r0'
```

#### What it looks like in code

```rust
// Revoke by handle
let updates = Capability::revoke_child(&parent, child_handle)?;

// Revoke by Arc pointer (safe if the capability was sent and its handle changed)
let updates = Capability::revoke_child_ref(&parent, &child_ref)?;
```
