# Domain Capabilities

## The Domain Type

A domain is an isolated execution environment with a unique identity, a lifecycle state, and a policy that governs what it may do.

```
Domain {
    id:                  u64         — globally unique, auto-incremented
    status:              DomainStatus (Unsealed | Sealed | Revoked)
    policy:              DomainPolicy
    memory_capabilities: map(LocalHandle → MemoryRegion capability)
    domain_capabilities: map(LocalHandle → Domain capability)
    pending_capabilities: map(u64 → PendingCapability)
}
```

---

## Domain Lifecycle

```
             create-domain
                   │
             ┌─────▼──────┐
             │  Unsealed   │  ← being configured; cannot execute
             └─────┬───────┘
               seal│
             ┌─────▼──────┐
             │   Sealed    │  ← executable; policy frozen
             └─────┬───────┘
            revoke │
             ┌─────▼──────┐
             │  Revoked    │  ← permanently destroyed
             └────────────┘
```

Transitions are **one-way**: `Unsealed → Sealed → Revoked`. There is no un-sealing or restoring a revoked domain.

- **Unsealed**: the domain is being set up. Capabilities can be carved/aliased/sent to it. Interrupt policies can be configured. The domain cannot be switched to or invoke MonitorAPI operations.
- **Sealed**: the domain is frozen and executable. It can invoke MonitorAPI operations (subject to its policy), be switched to on a core, and receive interrupts.
- **Revoked**: the domain and all its descendants are permanently torn down. All weak references to the domain's capability fail to upgrade.

---

## DomainPolicy

The policy encodes the domain's authority and is **immutable after sealing**.

### Core Bitmap

```
policy.cores: u64   — bit i = 1 means core i may run this domain
```

A domain can only execute on a core if the corresponding bit is set. Validated by `SwitchManager` at switch time.

### Monitor API

```
policy.api: MonitorAPI   — 13-bit permission bitmap
```

Operations a domain is permitted to invoke:

| Flag | Permitted operation |
|------|-------------------|
| `CREATE` | Create child domains (`create-domain`) |
| `SET` | Configure capabilities |
| `GET` | Inspect capabilities |
| `SEND` | Transfer capabilities to other domains (`send`) |
| `SEAL` | Seal child domains (`seal`) |
| `ATTEST` | Generate attestation reports (`attest`) |
| `ENUMERATE` | Walk the domain subtree |
| `SWITCH` | Switch execution to a child or parent (`switch`) |
| `ALIAS` | Create aliased memory children (`alias`) |
| `CARVE` | Create exclusive memory children (`carve`) |
| `REVOKE` | Revoke child capabilities (`revoke`) |
| `GETCHAN` | Obtain communication channels |
| `RECEIVE_AFTER_SEAL` | Accept capability transfers after sealing (see below) |

A child domain's API must be a *subset* of its parent's. Attempting to grant the child broader permissions returns `MonotonicityViolation`.

### Interrupt Policy

Each domain has an interrupt policy that controls how interrupts are routed through the domain hierarchy. Policies are set **before sealing**:

```
cap> set-interrupt-policy <domain> <vector> <visibility>
cap> set-default-interrupt-policy <domain> <visibility>
```

Visibility options:

| Visibility | Behaviour |
|------------|-----------|
| `DELIVER` | This domain handles the interrupt. Routing stops here. |
| `REPORT` | Domain is notified; routing continues to the parent. |
| `NOTREPORT` | Domain is silently skipped; routing continues. |

The interrupt routing algorithm walks the domain CDT upward from the interrupted domain until it finds a `DELIVER` domain. For details on the routing algorithm, VP call-chain suspension, and interrupt recovery, see [implementation/switch.md](../implementation/switch.md#interrupt-routing).

### Virtual Processor States (VPS)

Each sealed domain has a set of **virtual processor states** (VPs), one per logical execution context. A VP tracks which core it is currently assigned to, its run state (Available, Running, Locked, Suspended, Interrupted), and its saved register context.

VPs are allocated automatically at seal time (one per core bit set in the core bitmap by default). They represent the execution contexts the domain can occupy.

For full VP state machine details, see [implementation/switch.md § VP States](../implementation/switch.md#vp-states).

---

## Pending Capabilities (`RECEIVE_AFTER_SEAL`)

By default, a sealed domain's capability set is frozen. The `RECEIVE_AFTER_SEAL` API flag lifts this restriction:

1. Another domain calls `send` targeting a sealed domain with `RECEIVE_AFTER_SEAL`.
2. The capability lands in the target domain's pending queue.
3. The target domain later calls:
   - `accept-capability <domain> <pending_id>` — activates the capability.
   - `reject-capability <domain> <pending_id>` — discards it.

```
cap> enumerate-pending receiver
Pending capabilities for 'receiver': [0: app_mem (RW, 0x10000)]

cap> accept-capability receiver 0
✓ Accepted pending capability 0 as handle 2

cap> reject-capability receiver 1
✓ Rejected pending capability 1
```

---

## The Root Domain

The root domain is the system's trust anchor:

- `id = 0` (reserved, never generated).
- Created **Sealed** — always executable.
- Policy: `MonitorAPI::ALL`, all cores enabled.
- Has no parent in the CDT; it is the root of the domain tree.

All other domains must be derived (directly or indirectly) from the root domain.

---

## Allowed Operations

### `create-domain` — Create a Child Domain

**Requires**: `CREATE` API permission; parent domain must be **Sealed**.

**Preconditions**:
- `child.cores` ⊆ `parent.cores`
- `child.api` ⊆ `parent.api`

#### ✓ Success

```
cap> init root 0x1000000
cap> create-domain root child 0b1111 CREATE,SEAL,CARVE,SEND,ATTEST
✓ Created domain 'child' (ID: 1, cores: 0b1111)
```

#### ✗ Failure: broader core mask than parent

```
cap> create-domain root sub 0b11111111 GET
✗ Error: monotonicity violation — requested cores 0b11111111 exceed parent cores 0b1111
```

#### ✗ Failure: API permission not held by parent

```
# root was created with limited API
cap> create-domain root sub 0b1111 CARVE,REVOKE,SEND
✗ Error: monotonicity violation — requested API includes permissions not held by parent
```

#### What it looks like in code

```rust
let child = Capability::create_child_domain(&parent, child_policy, owner_id, handle)?;
// Extension trait form
let child = parent_ref.create_child(child_policy, handle)?;
```

---

### `seal` — Seal a Domain

**Called on the domain directly** (not through the CDT operation layer).

**Precondition**: domain status is `Unsealed`.

#### ✓ Success

```
cap> seal child
✓ Sealed domain 'child'
```

#### ✗ Failure: already sealed

```
cap> seal child
✗ Error: domain is already sealed
```

#### What it looks like in code

```rust
domain_ref.write().data.seal()?;
```

---

### `revoke` — Revoke a Child Domain

**Requires**: `REVOKE` API permission on the operating domain.

**Effect**: depth-first recursive revocation. For each node in the subtree:
1. Recursively revoke all child domains.
2. Set domain status to `Revoked`.
3. Emit `RevokeDomain(id, fallback)` — `fallback` is the direct parent domain ID, pre-computed once and shared across the entire subtree.

#### ✓ Success

```
cap> init root 0x1000000
cap> create-domain root app 0b1111 GET,ATTEST
cap> seal app
cap> revoke root app
✓ Revoked domain 'app' and all its children.
```

#### ✓ Success: cascade through grandchildren

```
cap> create-domain root parent 0b1111 CREATE,SEAL,REVOKE
cap> create-domain parent child 0b1111 GET,ATTEST
cap> seal child
cap> seal parent
cap> revoke root parent
✓ Revoked 'child' (ID: 2), then 'parent' (ID: 1). Fallback: root (ID: 0).
```

#### ✗ Failure: revoking a non-child

```
cap> revoke root grandchild
✗ Error: 'grandchild' is not a direct child of 'root' in the domain CDT
```

#### What it looks like in code

```rust
let updates = Capability::revoke_child_domain(&parent, child_handle)?;
// Extension trait form
let updates = parent_ref.revoke_child(child_handle)?;
```
