# Capability Engine V2

**DISCLAIMER:** I used the paper description and the manual implementations from 2025 to generate a new implementation using Claude. The code and document in this subfolder is auto-generated and will be inspected.

A thread-safe, `no_std` compatible Rust implementation of a capability-based security system for managing trust domains with composable isolation, based on the research paper "Composable Isolation as a Foundation to Manage Trust in the Cloud".

## Features

- **Thread-Safe**: Uses `Arc<RwLock<T>>` and parking_lot for concurrent operations across cores
- **no_std Compatible**: Works in embedded and bare-metal environments (requires `alloc`)
- **Composable Isolation**: Hierarchical capability trees with parent-child relationships
- **Memory Capabilities**: Exclusive and aliased memory regions with carve/alias operations
- **Domain Capabilities**: Trust domains with policies, virtual processor states, and sealing
- **Atomic Updates**: Track all address space modifications for multiple domains
- **Switch & Interrupt Routing**: Full support for context switching and interrupt handling
- **Attestation**: Generate cryptographic attestation reports for domains and capabilities

## Architecture

The implementation consists of several key modules:

### Core Types

#### Capabilities (`capability.rs`)

Generic capability structure with:
- **Owner**: Domain ID and local handle
- **Data**: Either a `MemoryRegion` or `Domain`
- **Parent**: Weak reference to parent capability (prevents cycles)
- **Children**: Strong references to child capabilities (ownership)

Thread-safe types:
- `CapabilityRef<T> = Arc<RwLock<Capability<T>>>` - Strong reference (owned)
- `CapabilityWeak<T> = Weak<RwLock<Capability<T>>>` - Weak reference (borrowed)

#### Memory Capabilities (`memory.rs`)

Memory regions support:
- **Access Rights**: Read, Write, Execute
- **Attributes**: HASH, CLEAN, VITAL, META
- **Status**: Exclusive or Aliased
- **Operations**:
  - `alias()` - Create aliased child (shared access)
  - `carve()` - Create exclusive child (removes from parent)

Physical address remapping:
- Identity mapping (virtual == physical)
- Explicit remapping to physical addresses

#### Domain Capabilities (`domain.rs`)

Trust domains with:
- **Policies**:
  - Core bitmap (which physical cores can run the domain)
  - Monitor API permissions (CREATE, SET, GET, SEND, SEAL, ATTEST, ENUMERATE, SWITCH, ALIAS, CARVE, REVOKE, GETCHAN, RECEIVE_AFTER_SEAL)
  - Interrupt routing policies (per-vector: Deliver, Report, NotReport; with per-vector `read_set`/`write_set` register masks)
  - `RECEIVE_AFTER_SEAL` flag — when set, capabilities can be sent to this domain even after it is sealed; they are queued as pending and the domain calls `accept_pending_capability()` / `reject_pending_capability()` to process them
- **Virtual Processor States**: Platform-specific register sets
- **Status**: Unsealed, Sealed, or Revoked

### Operations

#### Memory Operations

```rust
// Static methods (explicit owner)
let child = Capability::alias_child(&parent, access, owner_id, handle)?;
let (child, updates) = Capability::carve_child(&parent, access, owner_id, handle)?;
let updates = Capability::send_to(&region, new_owner, new_handle, attributes)?;
let updates = Capability::revoke_child(&parent, child_handle)?;

// Extension trait (MemoryCapabilityExt) — infers owner from the capability itself
let child = parent_ref.alias(access, handle)?;
let (child, updates) = parent_ref.carve(access, handle)?;
let updates = region_ref.send(new_owner, new_handle, attributes)?;
let updates = parent_ref.revoke(child_handle)?;
```

#### Domain Operations

```rust
// Static methods (explicit owner)
let child = Capability::create_child_domain(&parent, policy, owner_id, handle)?;
let updates = Capability::revoke_child_domain(&parent, child_handle)?;

// Extension trait (DomainCapabilityExt) — infers owner from the capability itself
let child = parent_ref.create_child(policy, handle)?;
let updates = parent_ref.revoke_child(child_handle)?;

// Seal a domain (make it executable)
domain.seal()?;
```

#### Switch Operations

```rust
// Create a switch manager
let mgr = SwitchManager::new(num_cores);

// Switch from one domain to another (pass None to return to parent)
let ctx = mgr.switch(core_id, &from_domain, Some(&to_domain))?;
let ctx = mgr.switch(core_id, &from_domain, None)?; // return to parent

// Route an interrupt through the domain hierarchy
let (handler_id, reported_to) = mgr.route_interrupt(vector, &interrupted, core_id)?;
```

### Update Tracking (`update.rs`)

All capability operations that modify address spaces produce `UpdateBatch`:

```rust
pub enum Update {
    Unmap { domain, address, size },
    Map { domain, address, size, physical, read, write, execute },
    ChangeRights { domain, address, size, read, write, execute },
    ZeroMemory { address, size },
    RevokeDomain { domain, fallback: Option<DomainId> },
    FlushTLB { domain },
}
```

Updates are atomic and can affect multiple domains simultaneously.

### Attestation (`attest.rs`)

Generate attestation reports for domains and memory regions:

```rust
// Attest a domain and its policies — returns AttestationReport
let report: AttestationReport = attest_domain(&domain_ref);
println!("{}", report.report);

// Attest a memory region — returns String
let report: String = attest_memory_region(&region_ref);

// Enumerate all domains in a subtree
let domain_ids: Vec<u64> = enumerate_domain_tree(&root_domain);
```

### Platform Abstraction (`platform.rs`)

The `Platform` trait abstracts hardware operations and serialisation primitives.
Capability operations are serialised via a **global read-write lock**:

```rust
pub trait Platform: Send + Sync {
    // Global RW lock — maps to rwlock_read/write_lock on bare metal
    fn acquire_shared_lock(&self) -> Result<Box<dyn OpLockGuard>>;   // carve/alias/send
    fn acquire_exclusive_lock(&self) -> Result<Box<dyn OpLockGuard>>; // any revoke

    fn send_ipi(&self, core_id: CoreId);
    fn sync_barrier(&self, id: u8, participants: usize);
    fn apply_update(&self, update: &Update);
    fn on_domain_revoked(&self, domain_id: DomainId, fallback: Option<DomainId>);
    fn register_domain(&self, domain_id: DomainId, parent_id: Option<DomainId>);
    fn set_core_domain(&self, core_id: CoreId, domain_id: DomainId);
    fn clear_core_domain(&self, core_id: CoreId);
    fn domain_core(&self, domain_id: DomainId) -> Option<CoreId>;
}

// execute() acquires the appropriate lock, runs the operation, and drives the
// two-barrier IPI protocol for cross-core hardware updates.
// Pass exclusive=false for carve/alias/send, exclusive=true for any revoke.
execute(&platform, /*exclusive=*/false, || {
    Capability::send_to(&cap, new_owner, handle, Attributes::NONE).map(|b| ((), b))
});
execute(&platform, /*exclusive=*/true, || {
    Capability::revoke_child_domain(&root, child_handle).map(|u| ((), u))
});
```

**Why shared/exclusive?** Revocation may cascade through an arbitrarily deep
subtree whose domain IDs are unknown to the caller in advance. An exclusive lock
ensures the full revocation is atomic with respect to all other operations —
no TOCTOU checks or domain-set enumeration required. On bare metal this maps
directly to a hardware RW spinlock (`rwlock_read_lock` / `rwlock_write_lock`).

### Address Space View (`view.rs`)

Compute the set of memory regions accessible to a domain at any point:

```rust
// Walk the capability tree rooted at a domain and produce a merged view
let view: AddressSpaceView = compute_address_space(&domain_ref);

// Alternatively, build a view from an explicit list of CapabilityRef<MemoryRegion>
let view: AddressSpaceView = compute_view_from_capabilities(domain_id, &caps);

// Inspect the view
for region in &view.regions {
    println!("{:#x} - {:#x} ({:?})", region.start(), region.end(), region.rights());
}
```

## Revocation

Revocation is cascading and depth-first:

1. **Memory Capabilities**: Revoke all children recursively
2. **Apply Attributes**:
   - `CLEAN`: Zero memory on revocation
   - `VITAL`: Revoke owning domain if this region is revoked
3. **Restore Parent Access**: For carved regions, map back to parent
4. **Generate Updates**: Collect all address space modifications

```rust
let updates = Capability::revoke_child(&parent, child_handle)?;
// Updates now contains all Unmap, Map, ZeroMemory, and RevokeDomain operations
```

## Example Usage

```rust
use capability_engine::*;

// Create root domain (pre-sealed, owns 4 cores)
let root_domain = Domain::new_root(4);
let root = Capability::new_root(0, 0, root_domain);

// Create root memory region (0x0 - 0x100000)
let root_region = MemoryRegion::new_root(0x0, 0x100000);
let mem_root = Capability::new_root(0, 1, root_region);

// Create a child domain
let child_policy = DomainPolicy::new_restricted(
    0b1111, // cores 0-3
    MonitorAPI::NONE
);
let child = Capability::create_child_domain(&root, child_policy, 1, 0)?;

// Carve memory for the child (exclusive)
let child_access = Access::new(0x10000, 0x10000, Rights::RWX);
let (child_mem, updates) = Capability::carve_child(&mem_root, child_access, 1, 0)?;

// Apply updates to modify address spaces
for update in updates.updates() {
    // Platform-specific: update page tables, TLBs, etc.
}

// Seal the child domain
child.write().data.seal()?;

// Attest the child
let attestation = attest_domain(&child);
println!("{}", attestation.report);
```

## Thread Safety

All operations are thread-safe:
- `Arc<RwLock<T>>` for shared ownership
- `Weak<RwLock<T>>` for non-owning references
- Global RW lock via `Platform::acquire_shared_lock` / `acquire_exclusive_lock`
- `AtomicUsize` for domain ID generation (portable to 32-bit targets)

Multiple cores can concurrently run non-destructive operations (carve, alias,
send) under a shared lock, while any revoke takes an exclusive lock to
atomically quiesce all other operations before cascading through the subtree.

## no_std / Bare-Metal Support

The library is `no_std` compatible (only `alloc` required).  The locking
backend is selected at compile time via a feature flag:

| Feature | Lock backend | When to use |
|---|---|---|
| `hosted` *(default)* | `parking_lot::RwLock` | OS environments (Linux, macOS, Windows) |
| *(none)* `--no-default-features` | `spin::RwLock` | Bare-metal, no OS, no libc |

### Adding to a bare-metal project

```toml
[dependencies]
capability-engine = { version = "0.1", default-features = false }
```

You must also provide a global allocator (e.g. `linked_list_allocator`, your
own slab allocator, etc.) since the crate uses `alloc`:

```rust
#[global_allocator]
static ALLOCATOR: MyAllocator = MyAllocator::new();
```

### Build check

```sh
# Hosted (default)
cargo build

# x86-64 bare-metal monitor (no OS)
cargo build --no-default-features --lib --target x86_64-unknown-none
```

### Collections used

- `alloc::vec::Vec`
- `alloc::collections::BTreeMap` / `BTreeSet`
- `alloc::sync::{Arc, Weak}`
- `alloc::string::String`

## Verification

The implementation is designed to be simple enough for formal verification with Lean or Aeneas:

- Pure functional core logic
- Minimal unsafe code (none in capability engine itself)
- Clear separation between policy (capabilities) and mechanism (platform updates)
- Explicit state transitions
- No hidden global state (except domain ID counter)

## Design Differences from Reference Implementation

1. **Thread-Safety**: Uses `Arc<RwLock<T>>` instead of `Rc<RefCell<T>>`
2. **no_std**: Compatible with embedded/bare-metal environments
3. **Explicit Updates**: All operations return `UpdateBatch` instead of implicit modifications
4. **Switch Manager**: Centralized switch/interrupt routing instead of distributed logic
5. **Attestation Module**: Separate module for attestation functionality

## Project Structure

```
src/
├── lib.rs              # Main library entry point
├── error.rs            # Error types
├── memory.rs           # Memory capabilities and rights
├── domain.rs           # Domain capabilities and policies
├── capability.rs       # Generic capability structure
├── update.rs           # Update tracking for address space changes
├── switch.rs           # Switch and interrupt routing
├── attest.rs           # Attestation support
├── platform.rs         # Platform abstraction trait and execute helper
└── view.rs             # Address space view computation
```

## Building

```bash
# Build library
cargo build --lib

# Run tests
cargo test

# Check for no_std compatibility
cargo check --lib --no-default-features
```

## Test Coverage

[cargo-tarpaulin](https://github.com/xd009642/tarpaulin) is used for unit test coverage measurement.

```bash
# Generate coverage report (summary printed to stdout, lcov report at target/tarpaulin/lcov.info)
cargo coverage
```

- Runs all lib and integration tests with `--no-fail-fast` so a single failing test does not abort the report.
- The lcov report can be consumed by editors, CI pipelines, or converted to HTML via `genhtml`.
## License

This is a research prototype implementation.
