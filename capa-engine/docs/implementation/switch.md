# Switching and Interrupts

This document describes the `SwitchManager`, VP (virtual processor) states, domain switching, and interrupt routing. For the policy configuration that governs interrupt routing, see [semantics/domain.md § Interrupt Policy](../semantics/domain.md#interrupt-policy).

---

## `SwitchManager`

`SwitchManager` owns one `CoreContext` per physical core:

```rust
pub struct SwitchManager {
    cores: Vec<Arc<CoreContext>>,
}

pub struct CoreContext {
    pub state:       RwLock<CoreState>,     // Idle | Running(domain_id)
    pub core_id:     u64,
    pub running_vp:  RwLock<Option<u64>>,  // VP ID currently executing
}
```

`CoreState::Running(domain_id)` records which domain is executing on each core. This is used by:

- `execute()` in `platform.rs` to determine whether an affected domain is running on a remote core (and therefore needs an IPI).
- `switch` precondition checks to validate that the calling domain is actually running on the requested core.

---

## VP States

Each sealed domain has a set of **virtual processors** (VPs), one per logical execution context. VP states are stored in `domain.policy.vprocessor_states` after sealing.

A VP progresses through the following states:

```
Available
    │ switch (forward, into this domain)
    ▼
Running ──── switch (forward, out of this domain) ──► Locked
    │         │
    │         │ interrupt fires while Locked
    │         ▼
    │     Suspended ◄──── callee VP → Interrupted
    │                         │
    │                         │ switch to Suspended VP
    │                         │ (frees Interrupted callee → Available)
    │                         ▼
    └── switch (return) ─► Available
```

| State | Meaning |
|-------|---------|
| `Available` | VP is idle; can be switched to via a forward switch. |
| `Running { core, caller }` | VP is executing on `core`. `caller` records which VP switched to this one. |
| `Locked { callee_domain_id, callee_vp_id, prev_caller }` | VP has done a forward switch out; waiting for the callee to return. |
| `Suspended { callee_domain_id, callee_vp_id, vector }` | VP was `Locked` when an interrupt fired and preempted the callee chain. Claimable by a forward switch (same as `Available`); claiming it also frees its `Interrupted` callee to `Available`. |
| `Interrupted { vector }` | VP was `Running` when an interrupt fired. Cannot be directly resumed. Freed to `Available` when its `Suspended` parent is claimed. |

**Key rule**: you cannot switch directly to an `Interrupted` VP. You must first switch to its `Suspended` caller, which atomically frees the interrupted VP to `Available`.

CLI example (from [Tutorial 5 — Interrupt Routing](../cli/tutorials.md)):

```
# After interrupt 55 fires on core 0 while child VP[0] is Running:
#   child  VP[0]: Running → Interrupted
#   parent VP[0]: Locked  → Suspended
#   root   VP[0]: Locked  → Running (handler)

# WRONG — direct resume fails:
cap> switch child 0 0
✗ Error: child VP[0] is Interrupted — not directly resumable

# CORRECT — reschedule the Suspended caller first:
cap> switch parent 0 0
✓ parent VP[0]: Suspended → Running; child VP[0]: Interrupted → Available

cap> switch child 0 0
✓ child VP[0]: Available → Running
```

---

## Domain Switching

### Forward Switch (`switch <domain> <core> <vp_id>`)

**Preconditions** (all must hold):

| Check | Error |
|-------|-------|
| `from` domain is currently `Running` on `core_id` | `InvalidOperation` |
| `to` domain is `Sealed` | `DomainNotSealed` |
| `to.policy.cores` has bit `core_id` set | `PermissionDenied` |
| `to` is a **direct child or direct parent** of `from` in the domain CDT | `InvalidOperation` |
| Selected VP is `Available` (or the VP is `Suspended` — see VP recovery rule) | `InvalidOperation` |

The CDT-adjacency check uses `Arc::ptr_eq` (not ID comparison) to avoid TOCTOU races. A domain can only switch one level at a time in the hierarchy.

**Effect**:
1. Source VP transitions: `Running → Locked { callee = to }`.
2. Target VP transitions: `Available → Running { core, caller = from VP }`.
3. `CoreContext::state` updated to `Running(to_domain_id)`.

### Return Switch (`switch <core>`)

Passing no target domain resolves the parent via the `from` domain's weak parent pointer. If `from` has no parent (root domain), returns `InvalidOperation`.

- Source VP: `Running → Available`.
- Parent VP: `Locked → Running`.

---

## Interrupt Routing

When interrupt vector `v` fires on core `c` running domain `D`, the engine walks the domain CDT upward from `D` to find the handler:

```
route_interrupt(vector, interrupted_domain, core_id):
  current ← interrupted_domain
  reported_to ← []

  loop:
    policy ← current.policy.interrupts.get_policy(vector)

    DELIVER   → return (current.id, reported_to)
    REPORT    → reported_to.push(current.id); current ← current.parent
    NOTREPORT → current ← current.parent

    if current is root and root policy is not DELIVER:
      error: "No interrupt handler found"
```

`reported_to` is the ordered list of domain IDs (from interrupted domain upward) that have `REPORT` visibility and must be notified.

The root domain's default policy is always `DELIVER` — any interrupt that reaches the root is handled there.

### VP Call-Chain Suspension

When an interrupt is delivered via the VP-aware path (`deliver_interrupt_vp`), the engine atomically suspends the entire VP call chain:

1. Walk the `Running` VP on `core_id` and all its `caller` links upward.
2. For each intermediate VP (`Running` or `Locked`):
   - If it is the `Running` leaf: transition to `Interrupted { vector }`.
   - If it is `Locked`: transition to `Suspended { callee_domain, callee_vp_id, vector }`.
3. The handler VP (first ancestor with `DELIVER` policy): transition `Locked → Running`.

This atomic state transition ensures that neither the interrupted VP nor any intermediate locked VP can be resumed by a stale `switch` call — the engine enforces ordering through the VP state machine.

### Resuming After an Interrupt

After the handler finishes (`resume_after_interrupt`), the engine walks back down from handler to the originally interrupted domain, collecting all domains with `REPORT` visibility. These are the domains to notify that the interrupt is complete.

---

## `VProcessorState` and Register Masks

Each VP's saved state is a `VProcessorState`:

```rust
pub struct VProcessorState {
    pub id:            u64,
    pub registers:     BTreeMap<u64, u64>,  // reg_id → value
    pub platform_data: Vec<u8>,             // platform-specific context
    pub run_state:     VpRunState,
}
```

`DomainPolicy.interrupts` carries per-vector `read_set` / `write_set` bitmasks:

```rust
pub struct VectorPolicy {
    pub visibility: InterruptVisibility,
    pub read_set:   u64,   // registers a parent may read during handling
    pub write_set:  u64,   // registers a parent may write during handling
}
```

The `VECTOR_AVAILABLE` sentinel (`0xFF`) is used for register-access policy lookups in the non-interrupt state (`Available`, `Locked`). This unifies policy lookup: a parent configures register visibility for normal execution the same way it configures it for an interrupt vector — no special-casing.

**Allowed VP states for GET/SET register access:**

| VP state      | Access allowed |
|---------------|---------------|
| `Available`   | Yes (bitmap checked against `VECTOR_AVAILABLE`) |
| `Locked`      | Yes (bitmap checked against `VECTOR_AVAILABLE`) |
| `Interrupted` | Yes (bitmap checked against interrupt vector) |
| `Suspended`   | Yes (bitmap checked against interrupt vector) |
| `Running`     | **No** — always denied regardless of bitmaps |

A VP in the `Running` state is actively executing on a core; reading or writing its registers is not safe. The engine returns `RegisterAccessDenied` immediately without consulting the bitmap.

Policy enforcement (actually checking read/write access against these masks) is delegated to the platform implementation. The engine records and exposes the masks but does not enforce them internally.

See [semantics/domain.md § Interrupt Policy](../semantics/domain.md#interrupt-policy) for the policy configuration API and CLI examples.
