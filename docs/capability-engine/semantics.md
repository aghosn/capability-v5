# Capability Engine — Semantics

> Consolidated from `capa-engine/docs/semantics/` (api, capabilities, domain, memory, translation).

---

# API Operations — End-to-End Flow

This document describes the full lifecycle of a capability system session using the CLI command vocabulary. It shows how operations compose and depend on one another.

The CLI (`CLI-capa-engine/`) is the reference interactive environment for experimenting with these operations. All examples below use `cap>` to denote CLI prompts. See the [tutorial index](../cli/tutorials.md) for 13 interactive walkthroughs covering each operation.

---

## The Full Lifecycle

### 1. Initialization

Every session starts with `init`, which creates the root domain and the root memory region (`r0`):

```
cap> init root 0x1000000
✓ Created root domain 'root' and memory region 'r0' (size: 0x1000000)
```

The root domain is **pre-sealed** and owns all cores. `r0` is an exclusive, RWX memory region covering the entire physical inventory.

---

### 2. Domain Creation

Child domains are created under a sealed parent. The child's core mask and API permissions must be subsets of the parent's:

```
cap> create-domain root app 0b1111 CREATE,SEAL,CARVE,SEND,ATTEST
✓ Created domain 'app' (ID: 1, cores: 0b1111)
```

A newly created domain is **unsealed**. It cannot execute, and capability operations cannot be called from it yet. The domain can be configured (memory carved and sent to it, interrupt policies set) before sealing.

---

### 3. Carving and Aliasing Memory

Memory is distributed by creating children of an existing memory region:

**Carve** — exclusive ownership. The parent loses access to the carved range:

```
cap> carve r0 app_mem 0x100000 0x200000 RWX
✓ Carved memory region 'app_mem' [0x100000..0x300000)
```

**Alias** — shared access. Both parent and child can access the range simultaneously:

```
cap> alias r0 shared_buf 0x800000 0x10000 RW
✓ Aliased memory region 'shared_buf' [0x800000..0x810000)
```

Rights can be attenuated (narrowed) at any derivation step but never amplified.

---

### 4. Sending Capabilities to Domains

A memory region is sent to a domain to grant it access. Handles are auto-allocated:

```
cap> send app_mem app
✓ Sent 'app_mem' to unsealed domain 'app' with auto-allocated handle 1
```

Optional ownership attributes can be set at send time:
- `CLEAN` — zero the memory before restoring parent access on revocation.
- `VITAL` — if this region is revoked, also revoke the domain that owns it.

```
cap> send app_mem app CLEAN,VITAL
```

Sending to an unsealed domain is the normal setup path. Sending to a **sealed** domain requires the domain to have `RECEIVE_AFTER_SEAL` in its API — the capability lands in a pending queue and must be explicitly accepted (see [domain.md § Pending Capabilities](domain.md#pending-capabilities--receive_after_seal)).

---

### 4b. Registering a COMM Page

> 📖 **Try it:** [Tutorial 9 — COMM Page](../cli/tutorials.md) walks through the full registration and revocation lifecycle interactively.

A parent domain registers a **COMM page** — a shared memory buffer bound to a child domain's VP. The region is NOT mapped in the child's EPT; apart from the parent, only the monitor (capavisor) accesses it via its HHDM mapping. Multiple COMM pages may be registered per child domain.

```
cap> carve r0 comm0 0x0 0x1000 rw
cap> register-comm comm0 child 0
✓ 'comm0' registered as COMM page for domain 'child' VP 0
```

`comm0` now carries `COMM|CLEAN` (not VITAL). The monitor receives a `CommRegion` update with the target domain ID and VP index, and establishes its own mapping to the physical page.

**Preconditions**: the capability must be a `Carve`-kind region with `Exclusive` status, owned by the calling domain, and not already carrying the `COMM` attribute. The child domain handle and VP index must be valid.

---

### 5. Sealing Domains

Once configured, a domain is sealed to make it executable:

```
cap> seal app
✓ Sealed domain 'app'
```

Sealing is one-way. After sealing:
- The domain's policy is frozen.
- The domain can now invoke `MonitorAPI` operations (subject to its policy).
- The domain can be switched to on a core.

---

### 6. Inspecting State

```
cap> list
# Prints all domains, memory regions, and current core assignments.

cap> view app
# Prints the merged address-space view for domain 'app'.

cap> attest app
# Generates and prints an attestation report for domain 'app'.
```

---

### 6b. Channels

A channel is a restricted capability that grants communication access to a domain without administrative control. It is obtained via `get-chan`:

```
cap> get-chan root dom1
✓ Created channel capability to 'dom1' (handle: 2)
```

Once obtained, a channel can be used to attest or send memory to the target:

```
cap> attest chan1          # report is for dom1; checks root has ATTEST
cap> send mem1 chan1       # forwards to dom1; checks root has SEND
```

Channels can be transferred to other domains (move semantics):

```
cap> send-channel dom0 chan1 dom2
✓ Channel in transit (pending ID: 1)

cap> accept-channel dom2 1
✓ dom2 now holds channel to dom1
```

See [domain.md § get-chan](domain.md#get-chan--obtain-a-channel-capability) for full semantics.

---

### 7. Switching and Interrupts

Execution is transferred between domains via explicit switches. A switch can only move one level in the domain hierarchy at a time (parent ↔ direct child):

```
cap> switch app 0 0
✓ Core 0 now executing domain 'app' (VP 0)
```

Interrupt routing is handled automatically based on per-domain interrupt policies set before sealing:

```
cap> set-interrupt-policy app 42 REPORT
cap> set-default-interrupt-policy app NOTREPORT
cap> seal app

cap> interrupt 42 0
✓ Interrupt 42 routed: app(REPORT) → root(DELIVER)
```

See [semantics/domain.md § Interrupt Policy](domain.md#interrupt-policy) and [implementation/switch.md](../implementation/switch.md) for the full interrupt routing rules.

---

### 8. Revocation

Revoking a child capability destroys it and all capabilities derived from it:

```
cap> revoke r0 app_mem
✓ Revoked 'app_mem' and all its descendants. Parent 'r0' regains access.
```

Domain revocation cascades through the domain subtree:

```
cap> revoke root app
✓ Revoked domain 'app' and all child domains.
```

---

## Operation Dependency Summary

```
init
 └─ create-domain        (parent must be sealed)
     └─ seal             (after configuration)
          ├─ get-chan     (requires GETCHAN; target must be sealed)
          │   └─ send-channel / accept-channel / reject-channel
          ├─ switch      (requires sealed target)
          └─ revoke      (requires REVOKE API permission on caller)

init
 └─ carve / alias        (parent memory must exist)
     ├─ send             (memory region + target domain must exist)
     │   └─ revoke       (parent must hold the REVOKE permission)
     └─ register-comm    (parent binds COMM page to child VP; multiple allowed)
         └─ revoke       (emits UncommRegion → ZeroMemory; no RevokeDomain)
```

All capability operations (carve, alias, send, revoke on memory; create-domain, revoke on domains) require the **operating domain** to be sealed and to hold the corresponding `MonitorAPI` permission bit. Root domain capabilities bypass this check (root is always sealed with all permissions).

---

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

---

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
             │  Unsealed  │  ← being configured; cannot execute
             └─────┬──────┘
               seal│
             ┌─────▼──────┐
             │   Sealed   │  ← executable; policy frozen
             └─────┬──────┘
            revoke │
             ┌─────▼──────┐
             │  Revoked   │  ← permanently destroyed
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

> 📖 **Try it:** [Tutorial 6 — Pending Capabilities](../cli/tutorials.md) demonstrates the full pending lifecycle.

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
// Domain-mediated public API
let child_handle = Capability::<Domain>::create(&parent, child_policy)?;
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
Capability::<Domain>::seal(&caller_domain, child_cap_handle)?;
```

Internally `seal` looks up the child by handle in the caller's domain capability table, then calls `child.write().data.seal()`. The lookup enforces that only a domain which actually holds the child capability can seal it.

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
// Domain-mediated public API (child_handle is the LocalHandle in caller's table)
let updates = Capability::<Domain>::revoke_domain(&caller, child_handle)?;
```

---

### `get-chan` — Obtain a Channel Capability

> 📖 **Try it:** Tutorials [12 (sibling attestation)](../cli/tutorials.md) and [13 (driver channels)](../cli/tutorials.md) show channels in realistic architectures.

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
Capability::<Domain>::send(&caller, mem_handle, chan_h, Attributes::NONE)?;

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
Capability::<Domain>::send(&caller, mem_handle, chan_h, Attributes::NONE)?;

// Transfer the channel to another domain (move semantics)
Capability::<Domain>::send_channel(&caller, chan_h, receiver_handle, Attributes::NONE)?;
// receiver accepts:
let new_h = Capability::<Domain>::accept_channel(&receiver, pending_id)?;
// or rejects:
Capability::<Domain>::reject_channel(&receiver, pending_id)?;
```

---

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
| `COMM` | `register_comm` | Parent-owned COMM page bound to child VP: implies `CLEAN`; emits `UncommRegion` on revocation. Does NOT imply `VITAL`. |

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

## COMM — Parent-Owned Communication Buffer

A parent domain registers a COMM page to establish a **shared memory buffer bound to a child domain's VP**. Unlike META (which is sent by the parent and hidden from the domain), a COMM page is:

- **Registered by the parent**, targeting a specific child domain VP.
- **NOT mapped in the child's address space** — only the monitor (capavisor) accesses it via HHDM.
- **Multiple pages per child** are allowed (e.g. one per VP, or separate pages for messages and event flags).

| Property | Behaviour |
|----------|-----------|
| Registration | Parent calls `register_comm(handle, child_domain_handle, vp_id)` on an exclusive carve it owns |
| Source requirement | Must be `RegionKind::Carve` with `RegionStatus::Exclusive` |
| Attributes set | `COMM \| CLEAN` (canonicalized at registration time; NOT VITAL) |
| Carved / aliased / sent | **Rejected** while COMM binding is active |
| Multiple per domain | Allowed; one binding per `(child, vp_id)` |
| Revocation — `UncommRegion` | Emitted so the monitor unmaps its access |
| Revocation — `ZeroMemory` | Emitted because CLEAN is implied |
| Child revocation | Bindings auto-released: COMM attribute cleared, `UncommRegion` emitted |

### ✓ Success: register a COMM page

```
cap> carve r0 comm0 0x0 0x1000 rw
cap> register-comm comm0 child 0
✓ 'comm0' registered as COMM page for domain 'child' VP 0
```

`comm0` now carries `COMM|CLEAN`. The monitor receives a `CommRegion` update with `target_domain_id` and `vp_id`, and maps `[0x0, 0x1000)` for its own access.

### ✓ Multiple COMM pages

```
cap> carve r0 comm1 0x1000 0x1000 rw
cap> register-comm comm1 child 1
✓ 'comm1' registered as COMM page for domain 'child' VP 1
```

### ✗ Failure: re-register same cap

```
cap> register-comm comm0 child 0
✗ Error: InvalidOperation — capability already carries the COMM attribute
```

### ✗ Failure: carve or alias a COMM cap

```
cap> carve comm0 sub 0x0 0x100 R
✗ Error: PermissionDenied — COMM regions cannot be carved, aliased, or sent
```

### Revocation

Revoking a COMM cap produces two updates (not three — COMM does not imply VITAL):

1. `UncommRegion` — monitor unmaps its access to the COMM page.
2. `ZeroMemory` — physical range is zeroed (CLEAN).

The owning domain is **not** revoked (no `RevokeDomain`).

```
cap> revoke r0 comm0
✓ Revoked 'comm0'. Monitor unmapped COMM page. Memory zeroed.
```

### Child revocation auto-releases bindings

When a child domain is revoked, any parent-owned COMM pages bound to it are automatically released: the `COMM` attribute and `comm_binding` are cleared, and `UncommRegion` updates are emitted. The parent retains the underlying memory capability with no special attributes.

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

---

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

