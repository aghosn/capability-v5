# Memory Capabilities

## The MemoryRegion Type

A memory capability wraps a `MemoryRegion` that describes a contiguous range of address space:

```
MemoryRegion {
    kind:         RegionKind   (Alias | Carve)
    status:       RegionStatus (Exclusive | Aliased)
    access:       Access { start: u64, size: u64, rights: Rights }
    content_hash: Option<[u8; 32]>
}
```

`Access` provides the address arithmetic (containment, overlap, end address) used by every derivation check.

---

## Access Rights

Rights are a three-bit bitmap:

| Constant | Bit | Meaning |
|----------|-----|---------|
| `Rights::READ` | 0 | Region may be read |
| `Rights::WRITE` | 1 | Region may be written |
| `Rights::EXECUTE` | 2 | Region may be executed |

Composite shorthands: `R`, `RW`, `RX`, `RWX`, `NONE`.

**Monotonicity rule**: a child's rights must be a *subset* of the parent's rights. Attempting to create a child with broader rights returns `CapaError::InvalidAccess`.

---

## Attributes

Attributes are per-*ownership* metadata (stored in `Ownership.attributes`, not in `MemoryRegion` itself). They affect behaviour at revocation time:

| Constant | Bit | Effect |
|----------|-----|--------|
| `HASH` | 0 | The region's content is (or should be) hashed and stored in `content_hash` for attestation. |
| `CLEAN` | 1 | When this capability is revoked, the physical memory it covers is zeroed before the mapping is removed. |
| `VITAL` | 2 | If this capability is revoked, the domain that *owns* it is also revoked (cascade). |
| `META` | 3 | This region is used for monitor metadata (informational). |

These flags are set at `send` time and travel with the capability as ownership changes.

---

## Exclusive vs. Aliased

A memory region is either **exclusive** or **aliased**. This determines who may access the memory at any given moment:

### Exclusive (`RegionStatus::Exclusive`)

- Only one domain has access at a time.
- Created by the **carve** operation.
- When an exclusive child is revoked, the parent *regains* access.
- Two carved regions from the same parent must not overlap (enforced at creation time).

### Aliased (`RegionStatus::Aliased`)

- Multiple domains may hold read/write access simultaneously.
- Created by the **alias** operation.
- Revoking an aliased child does not restore anything to the parent (the parent already retained access).
- A new alias is rejected if it overlaps with an existing *carved* sub-region of the same parent (that region is exclusively held by a child; sharing it would break exclusivity).

---

## Kind

`RegionKind` records *how* a region was derived:

| Kind | Created by | Determines |
|------|-----------|------------|
| `Carve` | `carve` operation | Parent loses access to the carved range; restored on revocation |
| `Alias` | `alias` operation | Parent retains access; child gets a shared view |

The kind is used during revocation to decide whether to emit a `Map` update to restore parent access (see [Revocation](revocation.md)).

---

## Root Memory Regions

A root memory region is created directly by the monitor (not derived from anything). It is always:
- `kind = Carve`, `status = Exclusive`
- Rights: `RWX` by default
- No parent (`parent` is a dangling `Weak`)

Root regions represent the physical memory inventory managed by the monitor.

---

## Containment Invariant

At all times the following holds for every non-root memory capability `C` with parent `P`:

> `C.access` is contained within `P.access`  
> `C.access.rights` ⊆ `P.access.rights`

The engine validates this at creation (`alias` / `carve`). It is never re-checked later — the invariant is structural and cannot be broken once established.
