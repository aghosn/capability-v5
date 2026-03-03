# Capabilities — Implementation

## The `Capability<T>` Struct

Every node in the Capability Derivation Tree is a `Capability<T>` where `T` is either `MemoryRegion` or `Domain`:

```rust
pub struct Capability<T> {
    pub owned:    Ownership,            // owner domain, handle, attributes
    pub data:     T,                    // the resource
    pub parent:   CapabilityWeak<T>,    // weak → no ownership cycle
    pub children: Vec<CapabilityRef<T>>, // strong → parent owns children
}
```

`Capability<T>` is always heap-allocated and reference-counted:

| Type alias | Rust type | Semantics |
|------------|-----------|-----------|
| `CapabilityRef<T>` | `Arc<RwLock<Capability<T>>>` | Strong reference — capability stays alive |
| `CapabilityWeak<T>` | `Weak<RwLock<Capability<T>>>` | Weak reference — does not prevent deallocation |

The `RwLock` wrapper allows concurrent reads (e.g., two threads inspecting the same capability) while serialising writes (e.g., adding a child during carve, removing a child during revocation).

## Ownership

```rust
pub struct Ownership {
    pub owner:        DomainId,
    pub handle:       LocalHandle,
    pub attributes:   Attributes,
    pub owner_domain: Option<CapabilityWeak<Domain>>,
}
```

`owner_domain` is a weak back-reference to the owning domain's capability. It is used by `validate_operation` to enforce:

1. The domain has not been revoked (upgrade succeeds).
2. The domain is `Sealed`.
3. The domain's `MonitorAPI` includes the required permission bit.

Root capabilities in tests and in the root domain itself set `owner_domain = None`, which skips the check entirely.

## CDT Operations — Static vs. Extension Trait

Every CDT operation is available in two forms:

### Static methods on `Capability<T>`

Explicit about every parameter. Used when the caller constructs ownership details manually:

```rust
// Memory
Capability::alias_child(&parent, access, owner_id, handle)?;
Capability::carve_child(&parent, access, owner_id, handle)?;
Capability::send_to(&region, caller, new_owner_id, new_handle, attributes)?;
Capability::revoke_child(&parent, child_handle)?;
Capability::revoke_child_ref(&parent, &child_ref)?;

// Domain
Capability::create_child_domain(&parent, policy, owner_id, handle)?;
Capability::revoke_child_domain(&parent, child_handle)?;
```

### Extension traits

Infer ownership from the capability itself. Cleaner for higher-level code:

```rust
// MemoryCapabilityExt — implemented on CapabilityRef<MemoryRegion>
parent_ref.alias(access, handle)?;
parent_ref.carve(access, handle)?;
region_ref.send(new_owner_id, new_handle, attributes)?;
parent_ref.revoke(child_handle)?;

// DomainCapabilityExt — implemented on CapabilityRef<Domain>
parent_ref.create_child(policy, handle)?;
parent_ref.revoke_child(child_handle)?;
```

The extension trait methods are thin wrappers: they read `self`'s current owner information and forward to the static methods.

## `compute_address_space`

`capability.rs` also hosts `compute_address_space(domain_ref)`, which walks the capability tree rooted at a domain and produces a merged `AddressSpaceView`:

```rust
let view: AddressSpaceView = compute_address_space(&domain_ref);
```

This is the basis for the `view <domain>` CLI command. See `view.rs` for the merge algorithm.

## Root Capabilities

Root capabilities are created directly by the monitor (not derived from anything):

```rust
let root_domain = Domain::new_root(num_cores);
let root_cap = Capability::new_root(owner_id, handle, root_domain);

let root_mem = MemoryRegion::new_root(start, size);
let mem_cap  = Capability::new_root(owner_id, handle, root_mem);
```

Root capabilities have:
- A dangling/empty `parent` weak reference (no parent).
- `children` starting empty.
- `owner_domain = None` (permission checks skipped).
