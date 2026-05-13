# Core-Gapping — Design Document

## 1. Problem Statement

Today Themis uses **synchronous same-core scheduling** (`THHV_SCHED_SYNC`):
dom0 VP on core 0 calls `VMCALL_SWITCH`, which parks the dom0 VMCS and loads
the child VMCS on the **same core**.  On child exit, the capavisor swaps back
to dom0 on the same core and returns the exit reason in registers.

This model works but has two fundamental problems:

1. **Performance — switch-per-event overhead**: every child event (I/O exit,
   MMIO, interrupt) requires a full context switch back to dom0 on the same
   core.  Each switch involves saving/restoring VMCS state, and critically,
   requires **microarchitectural flushes** (TLB, L1D, branch predictors) to
   prevent the parent from observing the child's state.  For I/O-heavy
   workloads this dominates runtime.

2. **Security — cache side channels and single-stepping attacks**: because
   dom0 regains control on the child's core after every event, a malicious
   parent can observe the child's cache state (L1D, L2) between switches —
   this is the basis of cache-based side-channel attacks (e.g., Prime+Probe,
   Flush+Reload).  Without core-gapping, each switch requires expensive
   L1D/L2 flushes to prevent leakage.  Furthermore, a malicious parent can
   single-step the child instruction by instruction (e.g., by programming
   an interrupt to fire after each instruction), combining cache observation
   with fine-grained control flow leakage.

### Goal

Implement **core-gapping**: run a child domain on a **dedicated core**
(core 1) while the parent handles the child's events **remotely from its own
core** (core 0) via shared memory and IPIs.  The parent never takes back
control on the child's core during normal operation, eliminating both the
switch overhead and the single-stepping attack surface.

---

## 2. Architecture Overview

```
Core 0 (parent / dom0)                Core 1 (child)
──────────────────────                ───────────────
dom0 runs normally                    child VP runs
  │                                     │
  │                                     │ child exits (I/O, MMIO, etc.)
  │                                     │ capavisor checks policy:
  │                                     │
  │  ← hardware IPI ──────────────────  │ Forward(core_0, sync):
  │                                     │   write event to shared page
  │  Linux ISR: read event queue        │   poll on response variable
  │  wake virtio/device thread          │   ...
  │  emulate device operation           │   read response
  │  write response to shared page ──→  │   VMRESUME child
  │                                     │
  │  ← hardware IPI ──────────────────  │ Forward(core_0, async):
  │                                     │   write event to shared page
  │  Linux ISR: read event queue        │   VMRESUME child immediately
  │  process asynchronously             │
  ▼                                     ▼
```

**Key insight**: dom0 never takes back control on core 1.  The child's core
belongs to the child + capavisor.  All event handling happens remotely.  This
eliminates microarchitectural flushes on the child's core and prevents
single-stepping.

---

## 3. How It Works

### 3.1 Sync Mode (current — unchanged)

```
dom0 thread → VMCALL_SWITCH → [capavisor swaps VMCS] → child runs on same core
                                                        child exits →
              ← VMCALL returns ← [capavisor swaps back] ←
```

Same-core, blocking, requires flush on every switch.  This mode remains as-is
for simple configurations and backward compatibility.

### 3.2 Core-Gapping Mode

Core-gapping is **not a different scheduling model** — the entry mechanism is
the same `VMCALL_SWITCH`.  What changes is **event handling inside the
capavisor**.

**Setup:**
1. Dom0 (Linux) takes core 1 offline from the scheduler, disables watchdogs,
   ensures only the switching thread remains on core 1.
2. The dom0 thread on core 1 calls `VMCALL_SWITCH` into the child domain —
   same as today.
3. The child starts running on core 1.

**Event handling:**
When the child exits (I/O, MMIO, interrupt, etc.), the capavisor on core 1
checks the **interrupt/event policy** for this event type.  The policy now has
a new variant:

```
Forward(target_core, synchronous: bool)
```

Instead of switching back to dom0 (as `Deliver` would do), `Forward`:
1. Writes the event information to a **shared notification area** (meta page).
2. Sends a **hardware IPI** from core 1 to core 0 (doorbell).
3. If `synchronous = true`: polls a shared variable until dom0 writes a response,
   then VMRESUMEs the child.
4. If `synchronous = false`: VMRESUMEs the child immediately.

**Dom0 side (core 0):**
The IPI arrives as a regular hardware interrupt in dom0's Linux kernel.
A registered interrupt handler reads the event queue from the shared page,
wakes the appropriate kernel thread (e.g., virtio device handler), which
processes the event.  If the event was synchronous, dom0 writes the response
to the shared page (setting a flag or variable that core 1 is polling).

**Core recovery:**
To recover core 1 (e.g., for domain teardown), dom0 does not need a special
VMCALL.  An interrupt whose policy is `Deliver` (return to parent) suffices —
the capavisor switches back to dom0 on core 1, and dom0 can bring the core
back online in the Linux scheduler.

### 3.3 Policy-Driven Behavior

Core-gapping behavior **emerges from the policies**, not from an explicit
"gap a core" command.  If all events for a child domain are configured with
`Forward(core_0, ...)`, the child naturally never yields core 1 back to dom0.
If some events use `Deliver`, those events cause a traditional switch back
(breaking core-gapping for that event type).

This is configured via the interrupt/event policy in the capability engine.
The policy is associated with the parent-child relationship and defines per-
event-type routing.

---

## 4. Event Policy Extension

### 4.1 Current Policy Enum

Today, the policy for an event can be:
- `Deliver` — return to parent domain (same-core switch)
- `Report` — record and continue

### 4.2 New Variant

```rust
enum InterruptPolicy {
    Deliver,
    Report,
    Forward {
        target_core: CoreId,
        synchronous: bool,
    },
}
```

- `Forward { target_core: 0, synchronous: true }` — write event to shared
  page, IPI core 0, poll until response, then VMRESUME.  For events that
  need emulation (I/O port, MMIO, CPUID).
- `Forward { target_core: 0, synchronous: false }` — write event to shared
  page, IPI core 0, VMRESUME immediately.  For notifications that don't
  need a response (e.g., device interrupts the parent should know about).

The target domain is implicit — the policy is defined on the parent-child
capability relationship.

### 4.3 Blocking vs Non-blocking

The `synchronous` flag determines what core 1's capavisor does after
forwarding:

- **Synchronous (blocking)**: capavisor on core 1 polls a shared variable.
  Dom0 writes the response and sets the variable.  Core 1 reads it and
  VMRESUMEs.  Used for virtio I/O that requires emulation before the guest
  can proceed.

- **Asynchronous (non-blocking)**: capavisor on core 1 VMRESUMEs immediately.
  Dom0 processes the event independently.  Used for notifications, logging,
  or events where the guest doesn't need to wait.

Which events are synchronous vs asynchronous depends on the device model:
- **Virtio devices**: depends on the virtio implementation — some operations
  are inherently synchronous (e.g., config reads), others asynchronous
  (e.g., virtqueue kicks).
- **Timer interrupts**: potentially paravirtualized (similar to Hyper-V's
  synthetic timer), making them asynchronous or handled locally by the
  capavisor without forwarding.
- **Direct device access**: no forwarding needed — the child handles the
  device directly.

---

## 5. Shared Notification Area

The shared notification area is the **data plane** for forwarded events.  It
carries event information from the capavisor on core 1 to dom0 on core 0,
and responses back.

### 5.1 Layout (per child VP, conceptual)

```
Offset    Size    Field
──────    ────    ─────
0x000     64B     Control: status, response_ready flag, synchronous flag
0x040     448B    Event info: exit_reason, exit_qual, guest_rip,
                  port/MMIO addr, instruction bytes, register snapshot
0x200     256B    Response area: updated registers, inject info
0x300     256B    Reserved
```

This can be the existing **VpCommPage / meta page** (already allocated from
META pool, A5-compliant).  The meta page is mapped into the parent's EPT only;
the child cannot access it.

### 5.2 Forward Flow (synchronous)

**Core 1 (capavisor, on child exit):**
1. Save relevant VP state to shared page event area.
2. Write event info (exit reason, qualification, RIP, instruction bytes).
3. Set `status = EVENT_PENDING`, `synchronous = true`.
4. Send hardware IPI to core 0.
5. Poll: `while response_ready == false { spin_loop(); }`
6. Read response from shared page (register updates, inject requests).
7. Apply register updates to child VMCS.
8. VMRESUME child.

**Core 0 (dom0 Linux):**
1. IPI arrives → Linux interrupt handler fires.
2. Handler reads shared page, sees `EVENT_PENDING`.
3. Wakes appropriate kernel thread (e.g., virtio handler) or processes inline.
4. Thread handles event (device emulation, etc.).
5. Writes response to shared page response area.
6. Sets `response_ready = true`.
   (Core 1 picks it up via polling — no return IPI needed.)

### 5.3 Forward Flow (asynchronous)

Same as synchronous except step 5-8 on core 1 are replaced by:
5. VMRESUME child immediately.

Dom0 still processes the event but the child doesn't wait.

---

## 6. Dom0 Preparation

Before switching a child onto a gapped core, dom0 must prepare:

### 6.1 Taking Core Offline

Dom0's Linux kernel must remove core 1 from the scheduler so that no other
threads (user or kernel) run there.  Steps:

1. **CPU hotplug offline**: `echo 0 > /sys/devices/system/cpu/cpu1/online`
   or equivalent kernel API.  This migrates all threads off core 1.
2. **Disable watchdogs**: NMI watchdog and softlockup detector must be
   disabled for core 1 (they would fire while the child runs).
3. **Pin switching thread**: the thhv driver thread that will call
   `VMCALL_SWITCH` must be affinity-pinned to core 1.

### 6.2 Registering the Doorbell Handler

The thhv driver registers an interrupt handler on core 0 for the doorbell
IPI vector.  When core 1 sends an IPI after forwarding an event:

```c
static irqreturn_t thhv_doorbell_isr(int irq, void *data)
{
    struct thhv_partition *part = data;
    /* Read event from shared page. */
    /* Wake appropriate waitqueue / tasklet. */
    wake_up(&part->event_wq);
    return IRQ_HANDLED;
}
```

The dom0 VMM (cloud-hypervisor) thread sleeps on `event_wq`, wakes when an
event arrives, processes it, and writes the response.

### 6.3 Bringing Core Back Online

When the child domain is torn down (or an event with `Deliver` policy causes
a switch back), the thhv driver thread returns on core 1.  Dom0 then:
1. Brings core 1 back online in the Linux scheduler.
2. Re-enables watchdogs.

---

## 7. TLB Flushes

Core-gapping does **not** change TLB flush semantics.  The capability engine's
INIT IPI barrier protocol for TLB shootdowns (REVOKE, UNMAP) works exactly as
today:

1. The capavisor on the revoking core sends INIT IPI to all cores with stale
   TLB entries (including core 1 if it runs the affected child).
2. Core 1 takes a VMEXIT (INIT signal), responds to the barrier, executes
   INVEPT, and VMRESUMEs.
3. The revoking core waits for all barriers to complete.

The key difference vs sync mode is that **routine event handling** no longer
causes switches (and thus no longer needs flushes).  Only capability engine
operations that modify EPT still require the barrier protocol.

---

## 8. Interrupt Routing

### 8.1 Dom0 Interrupts

With core-gapping, dom0 interrupts should be routed **away from core 1**:

- **LAPIC timer**: per-core, so core 1's timer belongs to whatever is loaded
  there (the child).  Dom0's timer fires on core 0.  No conflict.
- **IOAPIC/MSI**: routed by VT-d IRTE to specific APIC IDs.  Dom0's
  interrupts target core 0 (or other cores running dom0).  Must ensure no
  dom0 device interrupts target core 1.
- **IPI from dom0 to core 1**: should not occur while child runs.  Linux
  taking core 1 offline prevents scheduler IPIs.

### 8.2 Child Interrupts

For virtio devices emulated by dom0, interrupts for the child flow:
1. Dom0 (CHV) decides to inject an interrupt into the child.
2. Dom0 writes to the child's PIR (Posted Interrupt Request).
3. Dom0 sends a notification IPI to core 1.
4. Core 1 picks up PIR on VMRESUME and injects into the child.

This works the same as today — PIR + notification vector.

---

## 9. Security Properties

Core-gapping provides significant security improvements:

- **No single-stepping**: dom0 never gets control on core 1 between child
  instructions.  A malicious parent cannot program a timer to fire after
  each instruction and observe microarchitectural state.  The capavisor
  handles events without switching to dom0 on core 1.

- **No cache side channels**: since dom0 never runs on core 1 during child
  execution, L1D and L2 cache contents remain exclusively the child's.
  There is no window for the parent to perform Prime+Probe, Flush+Reload,
  or similar cache-based attacks.  Without core-gapping, every switch back
  to dom0 would require flushing L1D (and ideally L2) to prevent leakage —
  core-gapping eliminates this attack surface entirely.

- **No microarchitectural flush overhead**: because the parent never executes
  on the child's core, there is no need to flush L1D, L2, TLB, branch
  predictors, etc. after each event.  The child's microarchitectural state
  remains undisturbed.  This is both a performance and security win.

- **Capability enforcement**: all policies go through the capability engine
  (A1).  The `Forward` policy variant is validated the same way as `Deliver`
  and `Report`.  Dom0 cannot bypass policy to gain control on core 1.

- **META pool isolation** (A5): the shared notification area is in the META
  pool, mapped only into the parent's EPT.  The child cannot read or tamper
  with event data.

---

## 10. Paravirtualized Timer Design

With core-gapping, the child's timer is one of the most critical events to
handle efficiently.  Forwarding every timer tick to core 0 would negate much
of core-gapping's benefit.  This section proposes designs for handling timers
locally on the gapped core.

### 10.1 Current Timer Path (Sync Mode)

Today, dom1's timer works as follows:
1. Dom1's Linux kernel uses TSC-deadline mode (WRMSR to IA32_TSC_DEADLINE,
   MSR 0x6E0).
2. The capavisor traps this WRMSR (MSR bitmap) and reports it to the parent.
3. CHV (cloud-hypervisor) receives the WRMSR exit, reads the deadline value,
   and arms a host `timerfd` with the corresponding absolute time.
4. When the `timerfd` fires: eventfd → thhv workqueue → `INJECT_INTERRUPT`
   VMCALL → capavisor sets the PIR bit for the timer vector.
5. On the next VMRESUME of the child, PIR is drained and the timer interrupt
   is injected.

This path involves: WRMSR exit → switch to dom0 → ioctl to userspace → CHV
processes → timerfd fires → eventfd → kernel → VMCALL → PIR → VMRESUME.
Multiple context switches, multiple IPIs, kernel-userspace transitions.

### 10.2 Design Options

#### Option A: LAPIC Timer Passthrough on Gapped Core

Since dom0 does NOT run on core 1, core 1's physical LAPIC timer is unused.
The capavisor can program it directly for the child:

```
Child WRMSR 0x6E0 (TSC-deadline) → VMEXIT to capavisor (core 1)
  → capavisor reads deadline value from guest ECX:EDX
  → capavisor programs core 1's PHYSICAL IA32_TSC_DEADLINE MSR
  → VMRESUME child

Physical timer fires → EXIT_REASON_EXTERNAL_INTERRUPT (core 1)
  → capavisor recognizes it as the LAPIC timer vector
  → sets PIR bit for child's timer vector
  → VMRESUME child (PIR drained on entry → timer injected)
```

**Pros**:
- Fastest possible path: 1 WRMSR exit + 1 external-interrupt exit per timer
  tick.  No IPI, no shared memory, no dom0 involvement.
- No guest kernel changes needed — dom1 uses standard TSC-deadline mode.
- The LAPIC timer on core 1 has nanosecond precision (TSC-based).

**Cons**:
- The capavisor must manage a translation between the child's virtual TSC
  and the physical TSC (if TSC offsetting is used).
- If the child is parked (synchronous Forward for an I/O exit), the timer
  may fire while the capavisor is polling.  The capavisor must check for
  pending LAPIC timer interrupts before VMRESUME.
- LAPIC timer vector must be known to the capavisor (fixed at setup time).

#### Option B: Synthetic Timer (Hyper-V Style)

Define Themis-specific synthetic timer MSRs.  The child guest uses a
paravirtualized clockevent driver instead of the native LAPIC timer.

```
Synthetic timer MSRs (per VP):
  THEMIS_STIMER_CONFIG  (0x400000A0)  — enable, periodic/one-shot, vector
  THEMIS_STIMER_COUNT   (0x400000A1)  — deadline (in reference time units)

Child WRMSR THEMIS_STIMER_COUNT → VMEXIT to capavisor (core 1)
  → capavisor converts reference time to TSC ticks
  → programs core 1's physical LAPIC timer (or VMX preemption timer)
  → VMRESUME child

Timer fires → capavisor injects the configured synthetic vector directly
```

**Pros**:
- Clean abstraction: supports multiple timers (4 per VP, like Hyper-V).
- Can use the VMX preemption timer instead of LAPIC timer (no external
  interrupt exit — uses EXIT_REASON_VMX_PREEMPTION_TIMER which is cheaper).
- Periodic mode built in: capavisor auto-rearms without guest exit.
- Well-understood model (Hyper-V enlightened Linux already has a driver:
  `drivers/clocksource/hyperv_timer.c`).

**Cons**:
- Requires a guest kernel driver (clocksource + clockevent).
- More complex capavisor code (timer state machine, multiple timers).
- Adds a Themis-specific paravirt interface that guests must opt into.

#### Option C: Shared-Page Timer (kvmclock-Inspired)

Use a shared page for timer registration.  The child writes deadlines to a
shared memory region instead of through MSR exits.

```
Shared timer page (mapped into child's GPA):
  offset 0x00: timer_deadline (uint64, TSC value)
  offset 0x08: timer_vector   (uint32)
  offset 0x0C: timer_armed    (uint32, set by guest, cleared by capavisor)

Child writes deadline to shared page → no VMEXIT
Capavisor checks timer_armed on every VMRESUME (or uses preemption timer)
```

**Pros**:
- Zero exit overhead for timer arming (memory write, no WRMSR exit).
- Simple guest driver (just memory writes).

**Cons**:
- Capavisor must poll or use a secondary mechanism to notice new deadlines.
- If using preemption timer as backing, precision depends on the preemption
  timer rate divisor.
- Security concern: the shared page is in the child's GPA space, so the
  child can manipulate it freely.  Need to validate deadline values.

### 10.3 Recommendation

**Option A (LAPIC passthrough) for the initial implementation**, with
Option B as a future enhancement.

Rationale:
- Option A requires **zero guest kernel changes** — dom1 uses standard
  TSC-deadline mode, which it already does today.
- Option A is the simplest capavisor change: intercept WRMSR 0x6E0, write
  the value to the physical MSR, handle the resulting timer interrupt locally.
- Option A is the fastest: one VMEXIT for arming, one VMEXIT for firing,
  everything handled locally on core 1.
- The LAPIC timer is already per-core and naturally belongs to whatever
  domain owns core 1 in the gapped model.

Option B becomes valuable when:
- We want periodic timers without per-tick WRMSR exits.
- We need multiple independent timers per VP.
- We want CoCo-aware guests with a Themis-specific clocksource.

### 10.4 Implementation Details (Option A)

#### Capavisor Changes

1. **WRMSR 0x6E0 handler (core 1, child exit)**:
   ```rust
   fn handle_child_tsc_deadline_wrmsr(deadline: u64) {
       // Convert child's virtual TSC to physical TSC if offset is used.
       let phys_deadline = deadline + tsc_offset;
       // Program core 1's physical LAPIC timer.
       unsafe { wrmsr(IA32_TSC_DEADLINE, phys_deadline); }
       // Advance child RIP past the WRMSR instruction.
       advance_guest_rip();
       // VMRESUME child — no forwarding to dom0.
   }
   ```

2. **External interrupt handler (core 1, timer fires)**:
   ```rust
   fn handle_timer_interrupt_on_gapped_core(vector: u8) {
       if vector == LAPIC_TIMER_VECTOR {
           // This is the child's timer — inject directly via PIR.
           set_pir_bit(child_timer_guest_vector);
           // VMRESUME: PIR will be drained automatically on VM entry.
       } else {
           // Not the timer — handle per existing interrupt policy.
           handle_external_interrupt_per_policy(vector);
       }
   }
   ```

3. **Parked state handling**: if the child is parked (synchronous Forward for
   an I/O exit) and the timer fires, the capavisor must:
   - ACK the interrupt (EOI the LAPIC).
   - Set the PIR bit for the child's timer vector.
   - The timer injection happens on the next VMRESUME when the child unparks.

#### TSC Offset Handling

The child's virtual TSC may be offset from the physical TSC (VMCS field
`TSC_OFFSET`).  The child writes `virtual_deadline` to MSR 0x6E0.  The
capavisor must add the TSC offset to get the physical deadline:

```
physical_deadline = virtual_deadline + tsc_offset
```

The `tsc_offset` is already stored in the VMCS and known to the capavisor.

#### LAPIC Timer Vector

The child's Linux kernel configures its LAPIC timer with a specific LVT
vector (typically 0xEC for `LOCAL_TIMER_VECTOR`).  The capavisor doesn't
need to know this — it programs the physical LAPIC timer and when it fires
as EXIT_REASON_EXTERNAL_INTERRUPT, the vector in the exit info identifies
it.  The capavisor then injects that same vector into the child via PIR.

Actually, the physical LAPIC timer vector is set by the **capavisor** (it
owns the physical LAPIC on core 1).  The child's virtual LAPIC timer vector
(in its virtual LVT) is what gets injected via PIR.  The capavisor must
read the child's virtual LVT timer entry to know which vector to inject.

#### Dom0 / thhv Changes

**None for the timer path.**  Dom0 is completely out of the loop.  The
timerfd/irqfd path in CHV is still used for sync mode but is bypassed
entirely when core-gapping is active.

#### Dom1 Kernel Changes

**None.**  Dom1 uses standard TSC-deadline mode.  From the guest's
perspective, it writes MSR 0x6E0 and eventually receives a timer interrupt
— indistinguishable from native hardware.

### 10.5 How Deadlines Are Registered and Triggered

Summary of the complete timer lifecycle on a gapped core:

```
          Dom1 (guest, core 1)         Capavisor (core 1)        Dom0 (core 0)
          ──────────────────           ─────────────────          ──────────────
1. hrtimer arms LAPIC timer:
   WRMSR 0x6E0 = deadline
          ──── VMEXIT ────→
                                  2. Read deadline from
                                     guest ECX:EDX
                                  3. Add TSC offset
                                  4. WRMSR 0x6E0 (physical)
                                  5. Advance guest RIP
          ←── VMRESUME ────
                                                                  (not involved)
   ... guest runs ...

                                  6. Physical LAPIC timer fires
          ──── VMEXIT ────→          EXIT_REASON_EXTERNAL_INTERRUPT
                                  7. ACK interrupt (EOI)
                                  8. Read child's virtual LVT
                                     timer vector
                                  9. Set PIR bit for that vector
          ←── VMRESUME ────
10. Timer interrupt injected
    via PIR drain on VM entry
    hrtimer callback runs
    next deadline programmed → back to step 1
```

**Total exits per timer tick: 2** (WRMSR + external interrupt).
**Dom0 involvement: zero.**
**IPIs: zero.**

Compare to the current sync path which requires: WRMSR exit → switch to
dom0 → ioctl → userspace timerfd → eventfd → workqueue → VMCALL →
PIR → switch → VMRESUME = **6+ context transitions per tick**.

---

## 11. Open Design Questions

1. **Per-event-type policy granularity**: do we need per-exit-reason policy
   entries (e.g., I/O on port 0x60 → Forward sync, CPUID → Forward async)?
   Or is a per-domain global policy sufficient?

2. **Multiple children**: if dom0 manages multiple children on multiple
   gapped cores, how does core 0 handle concurrent event queues?  Likely
   one shared page per child VP, one doorbell vector per child (or a single
   vector + event queue with source identification).

3. **Synchronous polling overhead**: if core 1 polls a shared variable while
   waiting for dom0's response, this burns CPU cycles.  Alternatives:
   - Dom0 sends an IPI back to core 1 when the response is ready (but
     interrupts are disabled in capavisor, so this would need special
     handling — e.g., NMI or checking in the poll loop).
   - Accept the polling cost since the alternative (switch back) is worse.

4. **START_VP / RESUME_VP / STOP_VP VMCALLs**: with the policy-driven model,
   are these needed?  The existing SWITCH + policy system may suffice:
   - SWITCH starts the child (same as today).
   - `Forward` policy prevents switches back.
   - An event with `Deliver` policy recovers the core.
   - Whether explicit START/RESUME/STOP VMCALLs add value is TBD.

---

## 12. Implementation Plan

### Phase G1: Policy extension

**Scope**: Add `Forward { target_core, synchronous }` variant to the event
policy enum in `capa-engine`.  Update policy validation and serialization.
No runtime behavior change yet.

**Files**: `capa-engine/src/gen/`, policy-related modules

**Depends on**: nothing.

### Phase G2: Shared notification area

**Scope**: Define the shared page layout for forwarded events.  Implement
write (capavisor side) and read (thhv side) helpers.  Can reuse or extend
existing VpCommPage / meta page.

**Files**: `capavisor/src/` (shared page write), `thhv/` (shared page read)

**Depends on**: G1 (to know which events get forwarded).

### Phase G3: Capavisor event forwarding

**Scope**: In the capavisor's exit handler, when policy is `Forward`:
write event to shared page, send hardware IPI, poll or VMRESUME based on
`synchronous` flag.  This is the core behavioral change.

**Files**: `capavisor/src/hypercall.rs`, exit handling path

**Depends on**: G1, G2.

### Phase G4: thhv doorbell handler

**Scope**: Register an interrupt handler in thhv.ko on the parent's core
for the doorbell IPI.  Read event queue, wake appropriate thread.  Implement
response write-back path for synchronous events.

**Files**: `thhv/src/thhv_vp.c`, `thhv/include/`

**Depends on**: G2, G3.

### Phase G5: Dom0 core preparation

**Scope**: Add logic in thhv.ko to take a core offline before SWITCH and
bring it back online on teardown.  Disable watchdogs, pin thread.

**Files**: `thhv/src/thhv_part.c`

**Depends on**: G4.

### Phase G6: Testing

- Forwarded event round-trip: child exits, event appears on core 0,
  response returns, child resumes.
- Synchronous vs asynchronous forward behavior.
- Core recovery via `Deliver` policy.
- TLB flush barrier while child is core-gapped.
- Security: verify dom0 never executes on core 1 during child run.

**Depends on**: G5.

---

## 13. References

- `docs/architecture/mshv-themis.md` §4 (ThemIC), §6.1–6.2 (sync/async
  scheduling), §15f (RUN_VP)
- `docs/architecture/interrupt-virtualization.md` Phase 3 (core-gapping),
  §Key Design Constraint (LAPIC timer), §Nested Virtualization Scheduling
  (timer flood analysis)
- `docs/domain-comm.md` (DomainComm rings, message types)
- Hyper-V TLFS: SynIC (Chapter 11), Root Scheduler (Chapter 14),
  Timers (Chapter 10 — synthetic timers, reference TSC page)
- KVM timekeeping: `docs.kernel.org/virt/kvm/x86/timekeeping.html`
  (TSC, kvmclock, pvclock structure)
- Linux clocksource: `drivers/clocksource/hyperv_timer.c` (Hyper-V
  synthetic timer guest driver — reference for Option B)
- Intel SDM Vol 3C §25.5.1 (VMX preemption timer), §10.5.4 (LAPIC timer,
  TSC-deadline mode)
- vmxvmm/monitor/tyche: `monitor.rs` (CoreUpdate, CORE_REMAP),
  `calls.rs` (SWITCH, CONFIGURE_CORE)
