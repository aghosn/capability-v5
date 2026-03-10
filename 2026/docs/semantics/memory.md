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

Attributes are per-ownership metadata. `CLEAN`, `VITAL`, `HASH`, and `META` are set at `send` time. `COMM` is set by `register_comm`. They affect behaviour at revocation:

| Attribute | How set | Effect at revocation |
|-----------|---------|---------------------|
| `CLEAN` | `send` | Zero physical memory before restoring parent access |
| `VITAL` | `send` | Also revoke the domain that owns this capability |
| `HASH` | `send` | Region content is/should be hashed for attestation |
| `META` | `send` | Monitor metadata: excluded from address space; implies `CLEAN` + `VITAL` |
| `COMM` | `register_comm` | Domain COMM page: implies `CLEAN` + `VITAL`; emits `UncommRegion` before domain teardown |

---

## META — Monitor Metadata Regions

> 📖 **Try it:** [Tutorial 7 — META Regions](../cli/tutorials.md) demonstrates all META semantics interactively.

A region sent with `META` is **metadata memory allocated for the monitor's use** within the receiving domain. It has a distinct set of semantics compared to ordinary sent regions:

| Property | Behaviour |
|----------|-----------|
| Address space | **Excluded** — the receiver gets no MMU mapping; no `ChangeRights` is emitted for it |
| Attestation | **Included** — appears in the attestation report like a normal region entry |
| Source requirement | Source must be `RegionStatus::Exclusive` (unbroken chain of carves) |
| Re-send / carve / alias | **Rejected** — once a region is META in a domain, it cannot be used for any further derivation operations |
| Revocation | Implies `CLEAN` + `VITAL`: zeroes the physical range and revokes the owning domain |
| Sealed receiver | Goes through the normal pending/accept flow; the receiver must explicitly `accept` or `reject` |

At `send` time the engine automatically materialises `META` into `META | CLEAN | VITAL` so that revocation needs no META-specific logic.

### ✓ Success: send a META region to a sealed domain

```
cap> carve r0 monitor_scratch 0x500000 0x10000 RW
# RegionStatus::Exclusive — unbroken chain of carves ✓

cap> send monitor_scratch app META
# app is sealed → enqueued as pending; caller handle frozen
cap> accept-capability app <pending_id>
✓ Accepted META region 'monitor_scratch'. No MMU mapping granted.
```

`monitor_scratch` appears in `attest(app)` but is not accessible from `app`'s address space.

### ✗ Failure: META on an aliased region

```
cap> alias r0 shared 0x600000 0x10000 RW   # status = Aliased
cap> send shared app META
✗ Error: PermissionDenied — only Exclusive regions may be sent as META
```

### ✗ Failure: re-send or carve a META region

```
# Inside app — monitor_scratch is already META
cap> send monitor_scratch other_domain
✗ Error: PermissionDenied — META regions cannot be re-sent, carved, or aliased
```

### Revocation

Revoking a META region triggers the same sequence as `CLEAN | VITAL`:

1. `ZeroMemory` — physical range is zeroed.
2. Parent regains access (if carved).
3. `RevokeDomain` — the domain that held the META capability is revoked.

```
cap> revoke r0 monitor_scratch
✓ Zeroed [0x500000..0x510000). Domain 'app' revoked (META implies VITAL).
```

---

## COMM — Domain Communication Buffer

A domain registers a COMM page to establish a **shared memory channel between itself and the monitor**. Unlike META (which is sent by the parent and hidden from the domain), a COMM page is:

- **Registered by the domain itself**, using a cap it already owns.
- **Stayed mapped in the domain's address space** — the domain can read and write it.
- **Also accessible to the monitor** — the platform maps its physical address (e.g. via HHDM) after receiving the `CommRegion` update.

| Property | Behaviour |
|----------|-----------|
| Registration | Domain calls `register_comm(handle)` on an exclusive carve it owns |
| Source requirement | Must be `RegionKind::Carve` with `RegionStatus::Exclusive` |
| Attributes set | `COMM \| CLEAN \| VITAL` (canonicalized at registration time) |
| Carved / aliased / sent | **Rejected** once COMM is set |
| One-shot | A domain may register a COMM page **exactly once**; replacement is not allowed |
| Revocation — `UncommRegion` | Emitted **before** `RevokeDomain` so the monitor unmaps its access first |
| Revocation — `ZeroMemory` | Emitted because CLEAN is implied |
| Revocation — `RevokeDomain` | Emitted because VITAL is implied |

### One-shot semantics

Replacing a COMM page is intentionally disallowed. The COMM attribute implies VITAL; revoking the old cap to replace it would tear down the domain. Restoring the original attributes of the old cap is also ambiguous (they were discarded when COMM was applied). The safe design is: register once, replace by revoking the domain and creating a new one.

### ✓ Success: register a COMM page

```
cap> carve child_ram comm0 0x0 0x1000 RW
cap> register-comm comm0
✓ 'comm0' registered as COMM page for domain 'child'
  ℹ COMM: 1 page(s) registered with monitor
```

`comm0` now carries `COMM|CLEAN|VITAL`. The monitor receives a `CommRegion` update and maps `[0x0, 0x1000)` for its own access.

### ✗ Failure: second register-comm call rejected

```
cap> register-comm comm0
✗ Error: InvalidOperation — COMM page already registered; revoke the domain to change it
```

### ✗ Failure: carve or alias a COMM cap

```
cap> carve comm0 sub 0x0 0x100 R
✗ Error: PermissionDenied — COMM regions cannot be carved, aliased, or sent
```

### Revocation

Revoking the COMM cap (by the parent that owns the memory tree) produces three updates in order:

1. `UncommRegion` — monitor unmaps its access to the COMM page.
2. `ZeroMemory` — physical range is zeroed (CLEAN).
3. `RevokeDomain` — the domain that registered the COMM page is revoked (VITAL).

```
cap> revoke child_ram comm0
✓ Revoked 'comm0'. Monitor unmapped COMM page. Memory zeroed. Domain 'child' revoked.
```

---



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

> 📖 **Try it:** Tutorials [1 (carve)](../cli/tutorials.md), [2 (alias)](../cli/tutorials.md), and [3 (send)](../cli/tutorials.md) walk through these operations interactively.

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
// Domain-mediated public API
let (child_handle, child_sub, updates) = Capability::<Domain>::carve(&caller, parent_handle, access)?;
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
// Domain-mediated public API
let (child_handle, child_sub) = Capability::<Domain>::alias(&caller, parent_handle, access)?;
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
// Domain-mediated public API
let updates = Capability::<Domain>::send(&caller, cap_handle, receiver_handle, Attributes::CLEAN)?;

// With GPA hint (address translation)
let updates = Capability::<Domain>::send_at(&caller, cap_handle, receiver_handle, Attributes::CLEAN, Some(0xA0000))?;
```

> 📖 For GPA placement, view-aware insert, and accept-side overrides, see [Translation semantics](translation.md).

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
// Domain-mediated public API (child_sub is the SubHandle returned by carve/alias)
let updates = Capability::<Domain>::revoke(&caller, parent_handle, child_sub)?;
```
