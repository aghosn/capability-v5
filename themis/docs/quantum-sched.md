# Quantum Scheduling (`feature = "quantum-sched"`)

> **Status**: Planned, not yet implemented.
> **Gate**: Cargo feature `quantum-sched` in `themis/capavisor/`.
> **Purpose**: Give child VPs guaranteed execution quanta on platforms
> where host timer interrupts preempt children after near-zero instructions.

## Problem

On nested virtualization (QEMU/KVM dev environment), the capavisor's
VMRESUME into a child VP takes ~100μs due to nested VMCS overhead. Dom0's
LAPIC timer fires at ~250Hz (every 4ms), but KVM often has the timer
already pending by the time the child's VMRESUME completes. Result:

- `EXIT_REASON_EXTERNAL_INTERRUPT` fires immediately after VMRESUME
- `forward_interrupt_to_handler()` does full lazy-unwind: VMCLEAR child,
  VMPTRLD dom0, inject timer vector (0xEC)
- Child VP executes ~10 instructions per 4ms timer period
- Dom1's BSP still boots (slowly) because its workload is I/O-heavy —
  each EPT violation exit advances it regardless of preemption
- Dom1's AP **cannot boot**: CPU-intensive init needs sustained compute
  time, and Linux has a ~5s timeout for AP check-in

The capavisor code is **architecturally correct** — same path for BSP and
AP, same capability model checks, same `forward_interrupt_to_handler`.
The issue is purely throughput under nested virtualization.

On **real hardware**: VMRESUME takes ~1μs, and posted interrupts suppress
timer exits entirely. This problem does not exist. `quantum-sched` should
NOT be enabled on bare metal.

## Design

### Core Idea

Instead of immediately switching back to dom0 on every external interrupt,
**defer** parent-bound interrupts and re-enter the child. Deliver the
deferred interrupt when the VMX preemption timer fires (~20ms), giving
the child a guaranteed quantum.

### Flow: `EXIT_REASON_EXTERNAL_INTERRUPT` (child VP)

```
Current behavior (always):
  1. ACK_INTERRUPT_ON_EXIT gives us the vector
  2. forward_interrupt_to_handler() → route_interrupt()
  3. If handler is parent: VMCLEAR child, VMPTRLD parent, inject vector
  4. Child VP loses its turn

With quantum-sched enabled:
  1. ACK_INTERRUPT_ON_EXIT gives us the vector
  2. route_interrupt() → handler is parent domain?
  3a. YES (parent-bound, e.g. dom0 timer):
      - Store vector in per-core deferred_vector slot
      - Return immediately (re-enter child via monitor loop)
  3b. NO (child owns it, or IPI, or device interrupt):
      - forward_interrupt_to_handler() as before
```

### Flow: `EXIT_REASON_VMX_PREEMPTION_TIMER` (child VP)

```
Current behavior:
  1. Reset preemption timer to PREEMPTION_TIMER_TICKS
  2. Return (re-enter child)

With quantum-sched enabled:
  1. Check deferred_vector for this core
  2a. Vector deferred:
      - forward_interrupt_to_handler(vcpu, deferred_vector)
      - Dom0 gets its timer, scheduler_tick() runs
      - Child is suspended (lazy-unwind)
      - thhv retries SWITCH → child gets another quantum
  2b. No deferred vector:
      - Reset preemption timer (current behavior)
```

### Multiple Interrupts

If `deferred_vector` is already set when a new parent-bound interrupt
arrives, the existing deferred vector must be flushed first (via
`forward_interrupt_to_handler`), then the new one stored. This prevents
lost interrupts. In practice, only one dom0 timer fires per ~4ms, and
our quantum is ~20ms, so at most ~5 deferred timers accumulate — but
we handle the general case correctly.

## Per-Core State

```rust
// In platform.rs, added to CoreContext:
pub struct CoreContext {
    pub domain_id: AtomicU64,
    pub vp_id: AtomicU32,
    pub domain_cap: Mutex<Option<CapabilityRef<Domain>>>,
    pub deferred_vector: AtomicU16,  // NEW: 0 = none, 1-255 = vector
}
```

Helper methods on `ThemisPlatform`:
- `set_deferred(core_id, vector)` — store a deferred vector
- `take_deferred(core_id) -> Option<u8>` — atomically take (swap to 0)

## Constraints

- **Dom0 has no PID page** — cannot use `inject_via_pid()` for dom0.
  Must use the existing lazy-unwind path (`forward_interrupt_to_handler`)
  which does VMCLEAR/VMPTRLD and injects via `VMENTRY_INTR_INFO`.
- **Only parent-bound interrupts deferred** — child-owned (Deliver
  visibility) and device interrupts forwarded immediately.
- **Preemption timer quantum** — currently 60M ticks (~20ms at rate
  divisor 5, 3GHz TSC). Adjustable via `PREEMPTION_TIMER_TICKS`.
- **A3 lazy-unwind preserved** — the interrupt IS delivered, just
  batched to the quantum boundary. Same delivery path, same capability
  checks, same vector injection.

## Files Modified

| File | Change |
|------|--------|
| `themis/capavisor/Cargo.toml` | Add `quantum-sched = []` feature |
| `themis/capavisor/src/platform.rs` | `deferred_vector` in CoreContext |
| `themis/capavisor/src/vmexit.rs` | Conditional deferral in ext-intr and preemption-timer handlers |

## Prior Art (what failed)

**Approach A** (deferred + preemption timer, earlier in development):
- Deferred ALL interrupts, stored in `DEFERRED_HOST_VECTOR` per-core
- Never delivered the vector to dom0's IDT → `scheduler_tick()` never ran
- Dom0 scheduler starved → RCU stalls at ~688s
- **Root cause**: the deferred vector was consumed (ACK'd from LAPIC) but
  never re-injected into dom0

**This design avoids the failure** by:
1. Using `forward_interrupt_to_handler()` for delivery — proven path
2. Only deferring parent-bound interrupts (not all)
3. Guaranteeing delivery on preemption timer (no lost vectors)
4. Flushing if a second interrupt arrives before delivery
