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

The root domain is the **initial domain on the machine** — the first execution environment that exists when the system starts. It is not inherently trusted by design; trust relationships are established by the system software that runs in it.

- `id = 0` (reserved, never generated by `generate_domain_id()`).
- Created **Sealed** — always executable from the start.
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

**Domain-mediated operation**: `seal` is invoked by the **parent** (or owner) domain using the handle it holds for the child domain in its domain capability table. The caller must be Sealed and hold the child domain capability.

**Precondition**: target domain status is `Unsealed`.

#### ✓ Success

```
cap> init root 0x1000000
cap> create-domain root child 0b1111 GET,ATTEST,SWITCH
# root holds a handle to 'child' in its domain capability table
cap> seal child
✓ Sealed domain 'child'
```

#### ✗ Failure: already sealed

```
cap> seal child
✗ Error: domain is already sealed
```

#### ✗ Failure: sealing an unsealed domain from a non-owner

Only the domain that holds the child capability handle can seal it. Attempting to seal through a domain that does not hold the handle returns `NotFound`.

#### What it looks like in code

```rust
// Domain-mediated: caller is the parent domain; cap_handle is the handle
// caller holds for the target domain in its domain capability table.
Capability::seal_domain(&caller_domain, child_cap_handle)?;
```

Internally `seal_domain` looks up the child by handle in the caller's domain capability table, then calls `child.write().data.seal()`. The lookup enforces that only a domain which actually holds the child capability can seal it.

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

---

### `get-chan` — Obtain a Channel Capability

**Requires**: `GETCHAN` API permission; caller must be Sealed; target domain must be Sealed.

A **channel** is a restricted child capability that allows one domain to communicate with another without granting administrative control. Channels can be used to attest the target domain, send memory capabilities to it, and be transferred to other domains. They cannot be used to switch to, seal, revoke, or administer the target domain.

In the CDT a channel is a **child of the target domain** (not of the caller). Revoking the target domain therefore automatically revokes all channels pointing to it.

#### ✓ Success

```
cap> create-domain root dom1 0b1111 GET,ATTEST,GETCHAN,RECEIVE_AFTER_SEAL,SEND
cap> seal dom1
cap> get-chan root dom1
✓ Created channel capability to 'dom1' (handle: 2)
```

#### ✗ Failure: caller lacks GETCHAN

```
cap> create-domain root restricted 0b1111 GET,ATTEST
cap> seal restricted
cap> get-chan root restricted
✗ Error: API not allowed — GETCHAN permission required
```

#### ✗ Failure: target not sealed

```
cap> create-domain root unsealed_dom 0b1111 GET,ATTEST
# dom not yet sealed
cap> get-chan root unsealed_dom
✗ Error: domain not sealed
```

#### Channel permission set

A channel capability carries a fixed restricted permission set: `ATTEST | GETCHAN | SEND`. Attempting to use a channel handle for `seal`, `revoke`, or `switch` returns `ApiNotAllowed`.

Channel-mediated operations check the **holder's** (caller's) permissions, not the target domain's:
- `attest` via channel: caller must be Sealed and have `ATTEST`
- `send` via channel: caller must have `SEND`; target must have `RECEIVE_AFTER_SEAL`

#### Transfer semantics (move)

Channels use **move semantics** on transfer. Once `send-channel` is called, the sender's handle is frozen until the receiver accepts or rejects:

```
cap> send-channel dom0 chan1 dom2       # sealed path: enqueued as pending
cap> accept-channel dom2 <pending_id>  # dom2 accepts; dom0's handle cleared
cap> reject-channel dom2 <pending_id>  # dom2 rejects; dom0's handle unfrozen
```

#### Revocation cascade

Revoking the **target** domain revokes all its channel capabilities automatically (CDT invariant). If a channel is in-transit (frozen, pending acceptance) when the target is revoked, the pending entry is cancelled and the sender's handle is unfrozen.

```
cap> revoke root dom1
✓ Revoked 'dom1' and all its children — channels pointing to 'dom1' are also revoked.
```

#### What it looks like in code

```rust
// Obtain a channel to a child domain
let chan_h = Capability::get_chan(&caller, child_handle)?;

// Attest caller itself (requires caller Sealed + ATTEST)
let self_report = Capability::<Domain>::attest_self(&caller)?;

// Attest target via channel (requires caller Sealed + ATTEST)
let report = Capability::<Domain>::attest(&caller, chan_h)?;

// Send memory to target via channel
Capability::<Domain>::send_memory(&caller, mem_handle, chan_h, Attributes::NONE)?;

// Transfer the channel to another domain (move semantics)
Capability::<Domain>::send_channel(&caller, chan_h, receiver_handle, Attributes::NONE)?;
// receiver accepts:
let new_h = Capability::<Domain>::accept_channel(&receiver, pending_id)?;
// or rejects:
Capability::<Domain>::reject_channel(&receiver, pending_id)?;
```

---

### `get-chan` — Obtain a Channel Capability

**Requires**: `GETCHAN` API permission; caller must be Sealed; target domain must be Sealed.

A **channel** is a restricted capability that allows one domain to communicate with another without granting administrative control. Channels can be used to attest the target domain, send memory capabilities to it, and be transferred to other domains. Channels cannot be used to switch to, seal, revoke, or administer the target domain.

In the CDT, a channel is a **child of the target domain** (not of the caller). This means revoking the target domain automatically revokes all channels pointing to it.

#### ✓ Success

```
cap> create-domain root dom1 0b1111 GET,ATTEST,GETCHAN,RECEIVE_AFTER_SEAL,SEND
cap> seal dom1
cap> get-chan root dom1
✓ Created channel capability to 'dom1' (handle: 2)
```

#### ✗ Failure: caller lacks GETCHAN

```
cap> create-domain root restricted 0b1111 GET,ATTEST
cap> seal restricted
cap> get-chan root restricted
✗ Error: API not allowed — GETCHAN permission required
```

#### ✗ Failure: target not sealed

```
cap> create-domain root unsealed_dom 0b1111 GET,ATTEST
# dom not yet sealed
cap> get-chan root unsealed_dom
✗ Error: domain not sealed
```

#### Channel permissions

A channel capability carries a fixed restricted permission set: `ATTEST | GETCHAN | SEND`. Attempting to use a channel handle for `seal`, `revoke`, or `switch` returns `ApiNotAllowed`.

Channel-mediated operations check the **holder's** (caller's) permissions, not the target domain's:
- `attest` via channel: checks caller has `ATTEST`
- `send` via channel: checks caller has `SEND` and target has `RECEIVE_AFTER_SEAL`

#### Transfer semantics (move)

Channels use **move semantics** on transfer. Once `send-channel` is called, the sender's handle is frozen until the receiver accepts or rejects:

```
cap> send-channel dom0 chan1 dom2      # transfer chan1 from dom0 to dom2 (sealed path: pending)
cap> accept-channel dom2 <pending_id> # dom2 accepts; dom0's handle cleared
```

```
cap> reject-channel dom2 <pending_id> # dom2 rejects; dom0's handle unfrozen
```

#### Revocation cascade

Revoking the **target** domain revokes all its channel capabilities automatically (CDT invariant):

```
cap> revoke root dom1
✓ Revoked 'dom1' and all its children — channels pointing to 'dom1' are also revoked.
```

If a channel is in-transit (frozen, awaiting acceptance) when its target is revoked, the pending entry is cancelled and the sender's handle is unfrozen.

#### What it looks like in code

```rust
// Obtain a channel to child_dom
let chan_h = Capability::get_chan(&caller, child_handle)?;

// Attest target via channel (checks caller has ATTEST)
let report = Capability::<Domain>::attest(&caller, chan_h)?;

// Attest caller itself
let self_report = Capability::<Domain>::attest_self(&caller)?;

// Send memory to target via channel
Capability::<Domain>::send_memory(&caller, mem_handle, chan_h, Attributes::NONE)?;

// Transfer the channel to another domain (move semantics)
Capability::<Domain>::send_channel(&caller, chan_h, receiver_handle, Attributes::NONE)?;
// receiver accepts:
let new_h = Capability::<Domain>::accept_channel(&receiver, pending_id)?;
// or rejects:
Capability::<Domain>::reject_channel(&receiver, pending_id)?;
```
