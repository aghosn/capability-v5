# Address Translation

## Overview

When a memory capability is sent to a domain, the engine must decide *where* in the domain's guest-physical address space (GPA) the physical memory (HPA) appears. By default, the mapping is **identity**: `GPA = HPA`. With address translation, the hypervisor (or the receiving domain itself) can place memory at any GPA, decoupling the guest's view from the physical layout.

This document describes the semantics of the translation layer: what it tracks, how the API controls it, and the invariants it maintains.

---

## Two Address Spaces

| Term | Meaning |
|------|---------|
| **HPA** (Host Physical Address) | The physical address of the memory on the host. Stored in `Access.start`. Immutable after creation. |
| **GPA** (Guest Physical Address) | The address at which a domain *sees* the memory. Stored in the domain's `AddressMap`. Can differ from HPA. |

Every domain has an `AddressMap` that records the GPA→HPA translation for each region of memory it currently owns. Operations that change ownership (send, accept, revoke) automatically maintain this map.

---

## AddressMap Entries

Each entry in the map is keyed by GPA and can be in one of two states:

| Entry | Meaning |
|-------|---------|
| `Mapped(MappingEntry)` | Active mapping: `GPA → HPA` with size and rights. The domain can access this range. |
| `Blocked { hpa_start, size }` | Reserved range. The GPA slot is occupied but the domain has no access. Used for carved-away sub-regions. |

**Invariant**: entries never overlap. An insert that would overlap any existing entry (Mapped or Blocked) is rejected with `RegionOverlap`.

---

## API: `send_at` and `accept_at`

The engine provides two API variants for controlling GPA placement:

### `send_at(caller, cap, receiver, attrs, gpa_hint)`

Send a memory capability with an optional GPA hint.

- If `gpa_hint` is `Some(gpa)`, the receiver's AddressMap places the region at `gpa`.
- If `gpa_hint` is `None`, the region is placed at `GPA = HPA` (identity mapping).
- `send()` delegates to `send_at(None)` — zero churn on existing callers.

```
cap> send mem1 guest at 0xA0000
✓ Sent 'mem1' to domain 'guest' at GPA 0xa0000
```

### `accept_at(receiver, pending_id, gpa_override)`

Accept a pending capability with an optional GPA override.

- If `gpa_override` is `Some(gpa)`, the receiver overrides the sender's hint and places the region at `gpa`.
- If `gpa_override` is `None`, the sender's hint is used (which defaults to identity if the sender didn't specify one).
- `accept()` delegates to `accept_at(None)`.

```
cap> accept-capability enclave 0 at 0xC0000
✓ Accepted pending memory capability 0 as handle 1 at GPA 0xc0000
```

### Priority

| Sender provides | Receiver provides | Result GPA |
|----------------|-------------------|------------|
| `None` | `None` | HPA (identity) |
| `Some(X)` | `None` | X |
| `None` | `Some(Y)` | Y |
| `Some(X)` | `Some(Y)` | Y (receiver wins) |

---

## GPA Conflict: `RegionOverlap` Error

If the requested GPA range `[gpa, gpa+size)` overlaps any existing entry in the receiver's AddressMap (whether Mapped or Blocked), the operation returns `CapaError::RegionOverlap`.

- For `send_at`: the capability is rolled back to the sender's table. No mutation occurs.
- For `accept_at`: the pending entry is re-inserted. The receiver can retry with a different GPA.

```
cap> send fill_attempt guest at 0xD4000
✗ Failed to send: RegionOverlap
```

---

## View-Aware Insert

When a sent capability has carved children, the receiver's AddressMap must reflect the **view** — the visible ranges after subtracting carved-away sub-regions.

Given a capability `C` with access `[hpa_start, hpa_start + size)` and a carved child at `[carved_start, carved_start + carved_size)`:

```
Full range:   |--- Mapped ---|--- Blocked ---|--- Mapped ---|
              hpa_start      carved_start     carved_end     hpa_end
GPA offset:   gpa_base       gpa_base+Δ₁     gpa_base+Δ₂   gpa_base+size
```

The receiver gets:
- `Mapped` entries for the visible parts (before and after the carved gap).
- `Blocked` entries for the carved-away gap.

This ensures the receiver cannot fill the gap with another capability — the Blocked entry causes any overlapping insert to fail.

When the carved child is later revoked, the `unblock` mechanism restores the parent entry, merging adjacent entries via coalescing.

### Example

> 📖 **Try it:** [Tutorial 8 — GPA Address Translation](../cli/tutorials.md) demonstrates this interactively.

```
cap> carve r0 parent_mem 0x40000 0x10000 RW
cap> carve parent_mem sub_carve 0x44000 0x4000 RW
cap> send parent_mem guest at 0xD0000
✓ Sent 'parent_mem' to domain 'guest' at GPA 0xd0000

cap> view guest
GPA Address Space:
  GPA 0xd0000..0xd4000 → HPA 0x40000 RW-
  GPA 0xd4000..0xd8000 → BLOCKED (HPA 0x44000)
  GPA 0xd8000..0xe0000 → HPA 0x48000 RW-
```

---

## AddressMap Lifecycle

Each operation maintains the AddressMap:

| Operation | Effect on sender's map | Effect on receiver's map |
|-----------|----------------------|-------------------------|
| `carve` (same rights) | No change | n/a |
| `carve` (different rights) | Split entry at carve boundary | n/a |
| `send` (carve) | Block the sent range | Insert (view-aware: Mapped + Blocked) |
| `send` (alias) | No change (aliases don't remove sender access) | Insert (Mapped) |
| `accept` | Block the sent range on sender | Insert (view-aware: Mapped + Blocked) |
| `revoke` (carve, sent) | Unblock (restore parent entry) | Remove entry |
| `revoke` (alias) | No map change | Remove entry |

---

## Attestation

When the `address_translation` feature is enabled, the attestation report includes:

1. **Per-capability GPA**: each owned memory capability shows its GPA (with `(identity)` annotation when `GPA = HPA`).
2. **GPA Address Space summary**: a full listing of all entries in the domain's AddressMap, showing Mapped and Blocked entries.

```
Owned Memory Capabilities:
  Handle 1: [0x10000..0x20000) RWX (kind: Carve, attrs: )
    GPA: 0x10000 (identity)
  Handle 2: [0x20000..0x30000) RW- (kind: Carve, attrs: )
    GPA: 0xa0000 (HPA 0x20000)

GPA Address Space:
  GPA 0x10000..0x20000 → HPA 0x10000 RWX (identity)
  GPA 0xa0000..0xb0000 → HPA 0x20000 RW-
```

---

## The `address` Field in Updates

When address translation is enabled, the `address` field in `ChangeRights` updates carries the **GPA**, not the HPA. The `physical` field always carries the HPA. This allows the platform to configure page tables correctly:

| Field | Without translation | With translation |
|-------|-------------------|-----------------|
| `address` | HPA | GPA |
| `physical` | HPA | HPA |

The `fixup_domain_addresses` function rewrites `address` from HPA to GPA using the domain's AddressMap, and is called after all map mutations but before dropping domain write locks.
