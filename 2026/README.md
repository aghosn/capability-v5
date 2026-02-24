# Capability Engine V2

**DISCLAIMER:** I used the paper description and the manual implementations from 2025 to generate a new implementation using Claude. The code and document in this subfolder is auto-generated and will be inspected.

A thread-safe, `no_std` compatible Rust implementation of a capability-based security system for managing trust domains with composable isolation, based on the research paper ["Composable Isolation as a Foundation to Manage Trust in the Cloud"](eurosp2026-paper181.pdf).

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
  - Monitor API permissions (CREATE, SET, GET, SEND, SEAL, etc.)
  - Interrupt routing policies (per-vector: Deliver, Report, NotReport)
  - Receive-after-seal flag
- **Virtual Processor States**: Platform-specific register sets
- **Status**: Unsealed, Sealed, or Revoked

### Operations

#### Memory Operations

```rust
// Create an aliased child (shared access)
let child = Capability::alias_child(&parent, access, owner_id, handle)?;

// Create a carved child (exclusive access, removes from parent)
let (child, updates) = Capability::carve_child(&parent, access, owner_id, handle)?;

// Transfer ownership to another domain
let updates = Capability::send_to(&region, new_owner, new_handle, attributes)?;

// Revoke a child and all descendants
let updates = Capability::revoke_child(&parent, child_handle)?;
```

#### Domain Operations

```rust
// Create a child domain
let child = Capability::create_child_domain(&parent, policy, owner_id, handle)?;

// Seal a domain (make it executable)
domain.seal()?;

// Revoke a domain and all descendants
let updates = Capability::revoke_child_domain(&parent, child_handle)?;
```

#### Switch Operations

```rust
// Create a switch manager
let mgr = SwitchManager::new(num_cores);

// Switch from one domain to another
let ctx = mgr.switch(core_id, &from_domain, Some(&to_domain))?;

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
    RevokeDomain { domain },
    FlushTLB { domain },
}
```

Updates are atomic and can affect multiple domains simultaneously.

### Attestation (`attest.rs`)

Generate attestation reports for domains and memory regions:

```rust
// Attest a domain and its policies
let report = attest_domain(&domain_ref);

// Attest a memory region
let report = attest_memory_region(&region_ref);

// Enumerate all domains in a subtree
let domain_ids = enumerate_domain_tree(&root_domain);
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

// Create root domain
let root_policy = DomainPolicy::new_root();
let root_domain = Domain::new_root();
let root = Capability::new_root(0, 0, root_domain);

// Create root memory region (0x0 - 0x100000)
let root_region = MemoryRegion::new_root(0x0, 0x100000);
let mem_root = Capability::new_root(0, 1, root_region);

// Create a child domain
let child_policy = DomainPolicy::new_restricted(
    0b1111, // cores 0-3
    MonitorAPI::NONE
);
let child_domain = Domain::new(child_policy);
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
- `parking_lot::RwLock` for efficient reader-writer locking
- `AtomicU64` for domain ID generation

Multiple cores can concurrently:
- Read capability trees
- Create/revoke capabilities (with proper locking)
- Execute switch operations
- Generate attestations

## no_std Support

The crate is `no_std` compatible but requires `alloc`:

```toml
[dependencies]
capability-engine = { version = "0.1", default-features = false }
```

Collections used:
- `alloc::vec::Vec`
- `alloc::collections::BTreeMap` (ordered map)
- `alloc::collections::BTreeSet` (ordered set)
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
└── attest.rs           # Attestation support
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
## License

This is a research prototype implementation.
