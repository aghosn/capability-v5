# Code Review: Interrupt Handling in Capavisor

**Date:** 2026-03-27  
**Scope:** All interrupt-related code paths across capavisor, thhv, and capability engine  
**Commit base:** 796c048 + uncommitted changes

---

## Executive Summary

The current interrupt handling code has **fundamental design issues**. The capability
engine provides a rich interrupt model (`InterruptPolicy`, `route_interrupt()`,
`deliver_interrupt_vp()`, `VectorPolicy` with Deliver/Report/NotReport visibility),
but the capavisor largely bypasses it. The uncommitted changes add further ad-hoc
mechanisms (deferred vectors, preemption timer yield) that deviate from the designed
lazy-unwind model (A3).

The nested-virtualization scheduling problem (dom0's LAPIC timer preempts the child
before it executes any instructions) is real, but the current approach conflates
interrupt routing correctness with scheduling workarounds.

---

## Architecture: What the Capability Engine Provides

The engine (under `capa-engine/src/`) has a complete interrupt model that the capavisor
should be using:

### InterruptPolicy & VectorPolicy (`domain.rs`)

Every domain carries a `DomainPolicy.interrupts: InterruptPolicy` with:
- A **default** `VectorPolicy` for all interrupt vectors
- **Per-vector overrides** in a `BTreeMap<u8, VectorPolicy>`

Each `VectorPolicy` contains:
- `visibility: InterruptVisibility` — `Deliver` / `Report` / `NotReport`
- `read_set: RegBitmap` — which registers the parent may read during interrupt handling
- `write_set: RegBitmap` — which registers the parent may write

Default policies:
- Root domains: `Deliver` for all vectors (handle locally)
- Restricted domains: `Report` for all vectors (parent handles)

### `route_interrupt()` (`switch.rs:221-262`)

Walks up the domain hierarchy from the interrupted domain:
```
For each domain in chain (interrupted → root):
  Deliver   → STOP: this domain is the handler
  Report    → record domain, continue to parent
  NotReport → skip, continue to parent
```
Returns `(handler_domain_id, Vec<reported_to_domains>)`.

### `deliver_interrupt_vp()` (`capability.rs:2725-2886`)

The VP-level state machine for interrupt delivery:
1. Finds the running VP on the core
2. Walks up the VP call chain to the handler domain
3. Transitions leaf VP to `Interrupted { vector }`
4. Transitions intermediate VPs to `Suspended { vector }`
5. Transitions handler VP to `Running`
6. Updates platform core tracking

### `resume_after_interrupt()` (`switch.rs:267-309`)

Walks back down after interrupt handling, notifying Report-policy domains.

### VP State Machine (`domain.rs:267-306`)

- `Available` → `Running { core, caller }` → `Locked { callee }` →
  `Interrupted { vector }` / `Suspended { vector }`

---

## Finding 1: `route_interrupt()` is NEVER Called

**Severity: Critical (A9 violation)**

The capability engine provides `SwitchManager::route_interrupt()` which walks the
domain hierarchy consulting `InterruptPolicy` to find the correct handler.

**The capavisor never calls it.** Instead:

- `forward_interrupt_to_handler()` (hypercall.rs:1435-1437) hardcodes
  `platform.dom0_cap()` as the handler:
  ```rust
  let dom0_cap = platform.dom0_cap();
  let dom0_domain_id = dom0_cap.read().data.id;
  ```
- `yield_child_to_dom0()` (hypercall.rs:1529-1530) does the same.

**Consequences:**
- `InterruptPolicy` is set on domains but never used for routing decisions.
- If dom1 creates a dom2, interrupts would still route to dom0 (wrong — should
  route to dom1 as dom2's parent).
- The Report/NotReport distinction is completely ignored.
- Register access policies (`read_set`/`write_set`) are ignored for interrupt delivery
  (though `forward_child_exit()` does use `read_set` for non-interrupt exits — partial
  correctness).

**What should happen:** Call `route_interrupt(vector, &child_cap, core_id)` to determine
the handler domain, then pass that domain_id to `deliver_interrupt_vp()`.

---

## Finding 2: DEFERRED_HOST_VECTOR Violates A3 Lazy-Unwind

**Severity: Critical (A3 violation)**

CONTEXT.md §A3 defines the lazy-unwind model:
> "When a physical interrupt arrives while a child VP runs, the SWITCH call returns
> early with RDI = preempting vector. The parent handles it via its own interrupt
> handler."

The current (uncommitted) code does the **opposite** for child VPs:

1. Stores the vector in a per-core static array:
   ```rust
   // vmexit.rs:360-361
   DEFERRED_HOST_VECTOR[cid as usize].store(vector as u32, Ordering::Relaxed);
   return; // VMRESUME child
   ```
2. Re-enters the child immediately
3. Waits for a VMX preemption timer to fire (~1ms at 3M ticks)
4. Only then yields to dom0 via `yield_child_to_dom0()`

**Problems:**

- **Vector loss:** Only one slot per core. If two physical interrupts fire before
  the preemption timer, the first vector is overwritten and **permanently lost**.
  There is no recovery mechanism.

- **Latency:** Dom0's interrupt handler doesn't run until the next preemption timer
  fires, adding up to 1ms latency to every physical interrupt. This delays dom0's
  scheduler tick, network interrupts, disk completions, etc.

- **Invisible to capability engine:** The defer/consume cycle is entirely ad-hoc
  global state (`static DEFERRED_HOST_VECTOR`), invisible to the VP state machine.
  The engine thinks the child VP is still `Running`; in reality it's running with a
  consumed-but-undelivered host interrupt.

- **Dom0 starvation:** With approach A (20ms quantum), dom0's scheduler tick never
  fires → RCU stalls. With approach C (1ms quantum), the overhead of
  VMCLEAR/VMPTRLD every 1ms causes hung_task warnings.

**Why it was added:** Nested virtualization overhead (QEMU+KVM) makes
VMCLEAR/VMPTRLD so slow (~100s of μs) that dom0's LAPIC timer deadline is already
past by the time the child's VMRESUME completes → KVM immediately exits → child
executes 0 instructions. This is real, but the solution should not violate A3.

---

## Finding 3: `yield_child_to_dom0()` Passes Dummy vector=0

**Severity: High (correctness issue)**

`yield_child_to_dom0()` (hypercall.rs:1534-1538) calls `deliver_interrupt_vp()`
with `vector=0`:
```rust
let intr_ctx = match Capability::deliver_interrupt_vp(
    &child_cap,
    dom0_domain_id,
    core_id,
    0, // dummy vector
    platform,
) { ... };
```

The engine records this as `Interrupted { vector: 0 }` in the VP state, which:
- **Corrupts the VP state machine** — vector 0 is not a valid interrupt vector.
- **Breaks `effective_vector()` lookups** — register access policy checks for
  vector 0 may return unexpected results.
- **Splits truth:** The actual vector (from `DEFERRED_HOST_VECTOR`) is injected via
  `VMENTRY_INTERRUPTION_INFO_FIELD` separately. The engine and the hardware disagree
  on what happened.

---

## Finding 4: `forward_interrupt_to_handler()` Doesn't Return Vector in RDI

**Severity: Medium (A3 deviation)**

CONTEXT.md says: "SWITCH call returns early with RDI = preempting vector."

Current code (hypercall.rs:1498-1501):
```rust
handler_active.set_reg(Reg::Rax, errors::ERR_RETRY);
handler_active.set_reg(Reg::Rdi, 0);  // ← should be vector
handler_active.set_reg(Reg::Rsi, 0);
handler_active.set_reg(Reg::Rdx, 0);
```

The vector IS injected via `VMENTRY_INTERRUPTION_INFO_FIELD` (line 1481), so dom0's
IDT fires transparently. This is arguably correct for dom0 (Linux expects interrupts
via IDT, not VMCALL return values), but:
- It deviates from the documented contract.
- The VMM (CHV) doesn't know which vector preempted its child — it only sees
  `themis_switch()` returning `-EAGAIN` with no vector info.
- On real hardware, the VMM might need the vector to decide whether to re-arm
  a timer, process an I/O completion, etc.

Note: `do_switch()` (line 900-902) does correctly set `Rdi = vector` for multi-hop
interrupt return (`switch_ctx.interrupt_return`), so the contract IS implemented for
the resume path, just not for the initial interrupt delivery to the parent.

---

## Finding 5: `do_inject_interrupt()` Bypasses `apply_update()` for PIR Writes

**Severity: Medium (A1 partial violation)**

`do_inject_interrupt()` goes through hypercall dispatch (capability resolution via
`execute()`), but the actual PIR write is a direct hardware operation:
```rust
unsafe { inject_via_pid(pid_phys, hhdm, vector, false) };
```

There is no `Update::InjectInterrupt` variant. The engine validates the caller's
permission to hold the child domain handle, but:
- **No per-vector injection policy enforcement** at the hardware level.
- **Not auditable** through the capability engine's update path.
- The `InterruptPolicy` on the target domain is not checked — any parent holding a
  child handle can inject any vector regardless of the child's `VectorPolicy`.

The PIR page is META-pool memory (A5-safe), and the capability lookup provides
coarse authorization, so this is a partial rather than full violation.

---

## Finding 6: Preemption Timer Conflates Scheduling with Interrupt Delivery

**Severity: Medium (design concern)**

The VMX preemption timer (3M ticks ≈ 1ms) was added as a scheduling mechanism for
nested virt. The timer firing path:

```rust
// vmexit.rs:386-395
EXIT_REASON_VMX_PREEMPTION_TIMER => {
    vcpu.set(vmcs::guest::VMX_PREEMPTION_TIMER_VALUE, PREEMPTION_TIMER_TICKS);
    crate::hypercall::yield_child_to_dom0(vcpu);
    return;
}
```

Issues:
- **Not part of the capability model** — the engine has no concept of time quanta
  or scheduling quantum.
- **Uses interrupt delivery for non-interrupts** — `yield_child_to_dom0()` calls
  `deliver_interrupt_vp()` with a fake vector just to do a context switch. This is
  an abuse of the interrupt delivery mechanism.
- **Fragile** — 1ms quantum causes dom0 hung_task warnings due to context-switch
  overhead. The right quantum depends on nested-virt overhead, which varies.

On real hardware with posted interrupts, this mechanism is unnecessary — dom0's
timer would NOT cause a child VM exit at all. The fix should degrade gracefully.

---

## Finding 7: `forward_child_exit()` Partially Uses Interrupt Policy (Correct)

**Severity: Low (positive finding)**

`forward_child_exit()` (hypercall.rs:940-954) reads the child's interrupt policy
`read_set` for the exit reason:
```rust
let policy = c.data.policy.interrupts.get_policy(exit_reason as u8);
policy.read_set
```

This is correct use of the policy model for determining which registers to expose
to the parent during exit forwarding. It uses `Capability::switch()` (not
`deliver_interrupt_vp()`) for the context switch, which is also correct for
non-interrupt exits.

This is the **one place** where interrupt policy IS consulted correctly.

---

## Finding 8: Debug Logging Is Ungated

**Severity: Low (hygiene)**

The uncommitted changes add extensive `serial_println!` logging:
- AP exit log (vmexit.rs:214-242): logs every child VP1 exit
- Dirty mask log (hypercall.rs:685-691)
- VMENTRY log for every AP entry (hypercall.rs:869-893)
- EFER fix log (hypercall.rs:1709-1714)
- Denied register log (hypercall.rs:710-715)

None are gated by a debug feature flag. Serial I/O is already the dominant source
of boot latency (~10min for dom1 boot). These logs will make it significantly worse.

---

## Summary Table

| # | Finding | Severity | Axiom |
|---|---------|----------|-------|
| 1 | `route_interrupt()` never called; handler hardcoded to dom0 | Critical | A9 |
| 2 | `DEFERRED_HOST_VECTOR` violates lazy-unwind; loses vectors | Critical | A3 |
| 3 | `yield_child_to_dom0()` passes dummy vector=0 | High | — |
| 4 | RDI=0 on interrupt return instead of vector | Medium | A3 |
| 5 | PIR writes bypass `apply_update()` | Medium | A1 |
| 6 | Preemption timer conflates scheduling with interrupt delivery | Medium | — |
| 7 | `forward_child_exit()` correctly uses interrupt policy | Low (✅) | — |
| 8 | Ungated debug logging | Low | — |

---

## Recommended Rewrite Plan

### Principle

Separate two concerns that are currently tangled:
1. **Interrupt routing correctness** — use the capability engine's model.
2. **Nested-virt scheduling** — work around VMCLEAR/VMPTRLD overhead separately.

### Phase 1: Correct Interrupt Routing

**Goal:** Every physical interrupt during child execution is routed through the
capability engine's policy walk, not hardcoded to dom0.

Changes:
- In `forward_interrupt_to_handler()`:
  - Call `route_interrupt(vector, &child_cap, core_id)` to find handler domain.
  - Pass `handler_domain_id` to `deliver_interrupt_vp()`.
  - Remove hardcoded `platform.dom0_cap()`.
- Set `Rdi = vector` on ERR_RETRY return (per A3 contract).
- Verify `forward_child_exit()` also routes through `route_interrupt()` for
  exit-reason-based policy (it currently uses `read_set` but not routing).

**Files:** `hypercall.rs`

### Phase 2: Remove DEFERRED_HOST_VECTOR and yield_child_to_dom0()

**Goal:** Return to A3 lazy-unwind model. Every physical interrupt immediately
yields to the handler domain.

Changes:
- In `vmexit.rs` `EXIT_REASON_EXTERNAL_INTERRUPT` for child domains:
  - Always call `forward_interrupt_to_handler(vcpu, vector)`.
  - Remove the deferral path entirely.
- Remove `DEFERRED_HOST_VECTOR` array.
- Remove `yield_child_to_dom0()` function.
- In `EXIT_REASON_VMX_PREEMPTION_TIMER`: just reset the timer (or remove it
  entirely if the scheduling fix is in thhv).

**Files:** `vmexit.rs`, `hypercall.rs`

### Phase 3: Fix Nested-Virt Scheduling (Separate Concern)

**Goal:** Give the child enough execution time between dom0 timer ticks, without
modifying interrupt routing.

This is the real problem: on QEMU+KVM, VMCLEAR/VMPTRLD takes so long that dom0's
LAPIC timer is already past deadline when the child VMRESUME completes.

Options (from simplest to most complex):

**S1 — `schedule_timeout(1)` in thhv EAGAIN loop (RECOMMENDED FIRST TRY):**
- In `thhv_vp.c`, replace `cond_resched()` with `schedule_timeout(1)` (1 jiffy).
- This guarantees dom0 processes its timer tick and rearms it before retrying SWITCH.
- The child then gets a full ~4ms quantum (at 250Hz) before the next timer interrupt.
- Simplest change, entirely in thhv, no capavisor modification needed.

**S2 — Capavisor-side drain (`sti; nop; cli` before child VMRESUME):**
- Before VMRESUME in `do_switch()`, briefly enable interrupts in VMX root mode.
- This lets the pending LAPIC timer fire and be handled by the capavisor IDT.
- More complex (requires capavisor IDT to handle the interrupt correctly).

**S3 — Combined: forward every interrupt (A3) + `schedule_timeout(1)`:**
- If S1 alone doesn't give enough quantum, combine with approach B (forward all
  interrupts to dom0) which is the correct A3 model.
- `schedule_timeout(1)` ensures the timer rearms; A3 forwarding ensures correctness.

**Files:** `thhv/src/thhv_vp.c` (S1), `themis/capavisor/src/hypercall.rs` (S2)

### Phase 4: Clean Up

- Remove all ungated `serial_println!` debug logging; gate behind `cfg!(feature = "debug-interrupts")` or similar.
- Consider adding `Update::InjectInterrupt` for audit trail (lower priority).
- Add integration test: dom1 with 2 CPUs boots to login, dom0 stays stable.
- Update CONTEXT.md if any A3 semantics change.

### Phase 5: Future — Posted Interrupts on Real Hardware

On real hardware with VT-x posted interrupts:
- Dom0's timer does NOT exit the child (PI handles it in hardware).
- The entire scheduling problem disappears.
- The `schedule_timeout` workaround becomes a no-op (no EAGAIN returned).
- `route_interrupt()` + `deliver_interrupt_vp()` remain correct regardless.

---

## Key Files Reference

| File | Role in Interrupt Handling |
|------|---------------------------|
| `capa-engine/src/switch.rs` | `route_interrupt()`, `resume_after_interrupt()` — **NOT USED** |
| `capa-engine/src/capability.rs` | `deliver_interrupt_vp()` — used but with wrong handler |
| `capa-engine/src/domain.rs` | `InterruptPolicy`, `VectorPolicy`, `VpRunState` |
| `themis/capavisor/src/vmexit.rs` | Exit dispatch, DEFERRED_HOST_VECTOR, preemption timer |
| `themis/capavisor/src/hypercall.rs` | `forward_interrupt_to_handler`, `yield_child_to_dom0`, `do_inject_interrupt`, `inject_via_pid`, `do_switch` PIR drain |
| `thhv/src/thhv_vp.c` | `thhv_run_vp` EAGAIN loop, HLT wait/wake |
| `thhv/src/thhv_irqfd.c` | eventfd → VMCALL interrupt injection |
