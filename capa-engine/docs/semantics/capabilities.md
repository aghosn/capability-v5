# Capabilities and the CDT

## What is a Capability?

A **capability** is an unforgeable token that simultaneously names a resource and specifies the rights the holder has over that resource. The engine has exactly two kinds of resource:

- **Memory regions** — a contiguous range of address space with access rights (read / write / execute).
- **Trust domains** — isolated execution environments governed by a policy.

Capabilities are generic: `Capability<T>` where `T` is either `MemoryRegion` or `Domain`. Every capability carries:

| Field | Meaning |
|-------|---------|
| `owned` | Who holds this capability: domain ID, local handle, and ownership attributes |
| `data` | The resource itself (the memory region or domain) |
| `parent` | Weak reference to the parent capability — no ownership cycle |
| `children` | Strong references to all derived children — parent owns children |

## The Capability Derivation Tree (CDT)

All capabilities of the same type form a **tree** rooted at an initial resource created by the monitor. This tree is called the Capability Derivation Tree:

```
Root memory region  [0x0 .. 0x100000, RWX]
  ├─ Carved child   [0x10000 .. 0x20000, RWX]   (sent to domain 2)
  │    └─ Carved grandchild [0x10000 .. 0x14000, R]
  └─ Aliased child  [0x50000 .. 0x60000, R]     (shared with domain 3)

Root domain  (id=0, sealed)
  └─ Child domain  (id=1, sealed)
       └─ Grandchild domain  (id=2, unsealed)
```

The CDT enforces two invariants:

1. **Authority flows down only** — a child's rights are always a subset of its parent's.
2. **Ownership is explicit** — each node records exactly one owner. There is no ambient authority.

## Handles and Ownership

Within a domain, capabilities are referenced by a **local handle** (`LocalHandle = u64`). A handle is meaningful only inside the domain that owns it — two domains can hold handles with the same numeric value naming entirely different capabilities.

The `Ownership` struct records:

```
owned.owner      — DomainId of the domain holding this capability
owned.handle     — domain-local index (assigned at creation or send time)
owned.attributes — CLEAN, VITAL, HASH, META flags (applied at revocation)
```

## Reference Counting and Lifetimes

| Type | Semantics |
|------|-----------|
| `CapabilityRef<T>` = `Arc<RwLock<Capability<T>>>` | Strong reference — keeps the capability alive |
| `CapabilityWeak<T>` = `Weak<RwLock<Capability<T>>>` | Weak reference — does not prevent deallocation |

Parent → child edges are **strong** (parent owns children). Child → parent edges are **weak** (prevents cycles). When the last strong reference to a capability is dropped — because it was revoked and removed from its parent's children list — the capability is freed automatically.

## Safety Properties

The CDT model provides the following guarantees:

### P1 — Derivation Monotonicity
Every child capability is *at most as powerful* as its parent. Enforced at creation time for every derivation (carve, alias, create-domain). Because derivation is the only way to obtain a non-root capability, the property holds for all nodes by induction.

### P2 — Memory Exclusivity
At any point in time, at most one domain has exclusive access to any physical page, unless access was explicitly shared via alias. Enforced by overlap checks at carve and alias time, and by access-restoration updates at revocation time.

### P3 — Capability Confinement
A domain cannot forge capabilities. The only way to obtain one is to receive it from a domain that already holds it (via carve, alias, or send). Capabilities are opaque heap objects; they cannot be constructed by value from outside the engine.

### P4 — Operation Authority
A domain may only invoke a capability operation if its policy explicitly grants the corresponding `MonitorAPI` permission bit. Every operation validates the owning domain's sealed status and API bitmap before touching the tree.

### P5 — Revocation Completeness
Revoking a capability destroys all capabilities derived from it, transitively. The recursive revocation algorithm removes children before the node itself, so no derived capability can outlive its ancestor.

### P6 — No Authority Amplification
Sending a capability to another domain does not increase total authority. The sender loses (or loses exclusive) access; the receiver gains exactly what was sent, with identical rights.

### P7 — Sealed-Domain Immutability
Once a domain is sealed its policy is frozen. Its capability set can only grow through the explicit `RECEIVE_AFTER_SEAL` mechanism, and only for capabilities the domain itself chooses to accept.
