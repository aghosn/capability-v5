# Capabilities and the CDT

## What is a Capability?

A **capability** is an unforgeable token that simultaneously names a resource and specifies the rights the holder has over it. In this engine there are exactly two kinds of resource:

- **Memory regions** — a contiguous range of physical/virtual address space together with access rights.
- **Trust domains** — execution environments with policies governing what they may do and which cores they may run on.

Capabilities are generic (`Capability<T>` where `T` is `MemoryRegion` or `Domain`). Every capability carries:

| Field | Type | Meaning |
|-------|------|---------|
| `owned` | `Ownership` | Who owns this capability (domain ID + local handle + attributes) |
| `data` | `T` | The resource itself |
| `parent` | `CapabilityWeak<T>` | Weak reference to the parent (no ownership cycle) |
| `children` | `Vec<CapabilityRef<T>>` | Strong references to derived children |

## The Capability Derivation Tree (CDT)

All capabilities of the same type form a **tree** called the Capability Derivation Tree:

```
Root memory region  [0x0 .. 0x100000, RWX]
  ├─ Carved child   [0x10000 .. 0x20000, RWX]   (sent to domain 2)
  │    └─ Carved grandchild [0x10000 .. 0x14000, R]
  └─ Aliased child  [0x50000 .. 0x60000, R]     (shared with domain 3)
```

```
Root domain  (id=0, sealed)
  └─ Child domain  (id=1, sealed)
       └─ Grandchild domain  (id=2, unsealed)
```

The CDT enforces two invariants:
1. **Authority flows down only** — a child's rights are always a subset of its parent's.
2. **Ownership is explicit** — each node records exactly one owner (a domain ID and a local handle). There is no ambient authority.

## Handles and Ownership

Within a domain, capabilities are referenced by a **local handle** (`LocalHandle = u64`). A handle is meaningful only inside the domain that owns it — two domains can hold handles with the same numeric value that name entirely different capabilities.

The `Ownership` struct records:

```rust
pub struct Ownership {
    pub owner: DomainId,       // domain that holds this capability
    pub handle: LocalHandle,   // domain-local index
    pub attributes: Attributes,// CLEAN, VITAL, HASH, META flags on this ownership
    pub owner_domain: Option<CapabilityWeak<Domain>>, // optional back-ref for API validation
}
```

The `owner_domain` back-reference is used to enforce that only **sealed** domains with the appropriate **MonitorAPI** permission may invoke a given operation (see [Domain Capabilities](domain-capabilities.md) and [Operations](operations.md)).

## Reference Counting and Lifetimes

Capabilities are heap-allocated and reference-counted:

| Type | Rust type | Semantics |
|------|-----------|-----------|
| `CapabilityRef<T>` | `Arc<RwLock<Capability<T>>>` | Strong reference — keeps the capability alive |
| `CapabilityWeak<T>` | `Weak<RwLock<Capability<T>>>` | Weak reference — does not prevent deallocation |

Parent → child edges are **strong** (parent owns children). Child → parent edges are **weak** (prevents reference cycles). When the last strong reference to a capability is dropped — because it was revoked and removed from its parent's children list — the capability is freed automatically.

## Summary

- A capability = resource identity + rights + ownership, arranged in a tree.
- The CDT is the single source of truth for "who may do what to which resource".
- Authority is strictly monotone: derivation can only restrict, never amplify.
