# Interrupt Virtualization Design

## Goals

1. Timer and IPI interrupts destined for dom0 must never be lost when a child domain is running.
2. Interrupts a child domain "owns" (VectorPolicy = `Deliver`) must be delivered to it without requiring capavisor involvement.
3. Interrupts with `Report` policy must notify parent domains via the SWITCH return mechanism (not at EOI time).
4. The design must map cleanly to the `VectorPolicy` model already defined in the capability engine.
5. Minimize VM exits on the critical path; leverage APIC virtualization hardware wherever possible.

---

## Background: Relevant VT-x APIC Virtualization Features

### Virtual APIC Page (VAPIC)

Each VP gets a 4 KB physical page that mirrors the LAPIC register layout at offsets matching the xAPIC MMIO map (`0xFEE00000`). Key fields used by the processor:

| Offset | Name | Role |
|--------|------|------|
| `0x080` | vTPR | Virtual Task Priority Register |
| `0x0A0` | vPPR | Virtual Processor Priority (written by hardware) |
| `0x0B0` | vEOI | Virtual EOI (write triggers EOI logic) |
| `0x100–0x170` | vISR | Virtual In-Service Register (256 bits) |
| `0x200–0x270` | vIRR | Virtual Interrupt Request Register (256 bits) |

VMCS pointer: `VIRTUAL_APIC_ADDR`.

### APIC Register Virtualization (Secondary Proc-Based, bit 8)

Redirects guest reads of APIC registers to the VAPIC page instead of the physical LAPIC. Eliminates exits on `RDMSR IA32_X2APIC_*` and on reads of the APIC-access page. Does **not** by itself handle virtual interrupt delivery.

### Virtual Interrupt Delivery — VID (Secondary Proc-Based, bit 9)

When enabled, the processor evaluates pending virtual interrupts on every VM entry and after every EOI. If `vIRR` has a pending bit whose priority exceeds `vPPR`, the processor delivers it directly to the guest IDT — **no VM exit**.

Key consequence: the hypervisor can inject an interrupt by setting a bit in `vIRR` (in the VAPIC page) and then doing VMENTRY; the hardware delivers it without further action.

**Important**: when the capavisor writes `vIRR[V] = 1`, it does **not** need to manually update `GUEST_INTERRUPT_STATUS.RVI` in the VMCS. On every VM entry with VID enabled, the processor automatically evaluates `vIRR`, computes the highest pending vector, and updates `GUEST_INTERRUPT_STATUS` itself before delivery. A plain memory write to the VAPIC page is sufficient.

### EOI-Exit Bitmap (VMCS 0x201C–0x2022, four 64-bit words = 256 bits)

Controls what happens when a guest writes to the virtual EOI register:

- **Bit V = 0**: EOI for vector V is handled entirely in hardware. The processor clears the vISR bit, recomputes vPPR, and (for level-triggered interrupts) sends a directed EOI to the IOAPIC. **Capavisor is not involved.**
- **Bit V = 1**: EOI for vector V causes a VM exit (`EXIT_REASON_EOI_INDUCED`, reason 45). Hardware has already sent the physical EOI before the exit. In the current design this is **not used** (all bits = 0; see §Report Policy Semantics).

This is the primary per-vector hardware knob available to us.

### Posted Interrupts — PPI (Pin-Based, bit 7)

Each VP has a 64-byte **Posted Interrupt Descriptor (PID)**:

```
Bytes  0–31 (256 bits): PIR — Posted Interrupt Requests (pending vectors to deliver)
Byte  32, bit 0:        ON  — Outstanding Notification
Byte  33, bit 0:        SN  — Suppress Notification
Bytes 34–63:            reserved
```

VMCS pointers: `POSTED_INTR_NOTIFICATION_VECTOR` (one reserved physical vector, e.g. 0xF2), `POSTED_INTR_DESCRIPTOR_ADDR`.

**Injection flow** (hypervisor → running VP, no VM exit):

1. Atomically set bit V in `PID.PIR`.
2. If `PID.ON` was 0: atomically set `ON=1`, send IPI to the VP's core using the notification vector.
3. The processor receives the IPI (sees it is the notification vector), atomically moves `PIR` bits into the VAPIC `vIRR`, clears `ON`, and delivers the highest-priority pending interrupt.
4. No VM exit occurs.

When the target VP is **not currently running** on any core, the IPI just lands on whatever domain is running. The `ON` bit stays set; on the next VM entry for that VP, the processor processes the PID before resuming.

---

## `Report` Policy Semantics: The SWITCH Return Mechanism

This is the central design insight. `Report` does **not** mean "send a message at EOI time". It means the domain gets a synthetic early return from its SWITCH call, with the interrupt vector as the reason, indistinguishable in form from a normal child exit.

### Full Example: d0 → d1 → d2

- d0: `Deliver` for vector V (handles V)
- d1: `Report` for V (wants to observe V, participates in call chain)
- d2: `NotReport` for V (irrelevant to V; resumes transparently)

**Steady state**: d0 SWITCHed to d1; d1 SWITCHed to d2. VP states:
```
d0 VP: Locked { callee=d1, prev_caller=None }   VMCS: in d0's slot
d1 VP: Locked { callee=d2, prev_caller=None }   VMCS: in d1's slot
d2 VP: Running { core=C, caller=d1 }             VMCS: active on core C
```

**Interrupt V fires on core C** (`EXIT_REASON_EXTERNAL_INTERRUPT`):

```
1. capavisor: route_interrupt(V, d2) → [d1=Report, d0=Deliver] → handler=d0

2. capavisor: write d2's register state (per d2's VectorPolicy.read_set) to d2's COMM page
               as InterceptMessage { exit_reason=V }
               (d1 will read this after it is woken)

3. deliver_interrupt_vp(d2_cap, handler=d0, core=C, vector=V):
     chain = [d2, d1, d0]   (n=3)
     d2 VP: Running    → Interrupted { vector: V }
     d1 VP: Locked     → Suspended { callee=d2, callee_vp_id=0, vector=V }
     d0 VP: Locked     → Running { core=C, caller=None }  (prev_caller restored)
     platform.set_core_context(C, d0_cap, d0_vp_id)

4. capavisor: VMCLEAR d2 → store in d2's VP slot
              take d0's VMCS from d0's slot → VMPTRLD d0
              set bit V in d0's VAPIC.vIRR
              // do NOT advance d0's RIP (still at the SWITCH VMCALL to d1)
              VMRESUME d0

5. d0 runs:  VID delivers V on VM entry → d0's IDT handler fires
             d0's interrupt handler processes V (timer tick, IPI, etc.)
             d0 writes EOI → hardware handles it (EOI-exit bit=0, no exit)
             iret → d0 is back at the SWITCH VMCALL instruction

6. d0 re-executes SWITCH to d1 (same VMCALL, same handle):
     do_switch: Capability::switch_domain_forward(d0→d1)
       d1 VP is Suspended { callee=d2, vector=V }
       → suspended_callee = (d2_weak, d2_vp_id, V)    ← SwitchContext carries V
       d1 VP: Suspended → Running { core=C, caller=d0_vp_ctx }
       d2 VP: Interrupted → Available               ← freed by the Suspended→Running transition
       d0 VP: Running → Locked { callee=d1, prev_caller=None }
       platform.set_core_context(C, d1_cap, d1_vp_id)

     do_switch: activate d1's VMCS
       // d1's SWITCH to d2 "returns" — set return registers:
       RAX = SUCCESS
       RDI = V   (the interrupt vector — d1 sees "d2 returned due to interrupt V")
       advance d1's RIP past the SWITCH VMCALL
       // d2's COMM page already has InterceptMessage(exit_reason=V) from step 2

7. d1 runs:  sees SWITCH returned with RDI=V (interrupt reason, not normal d2 exit)
             reads d2's COMM page: register state at interrupt time (per read_set)
             d1's interrupt handler observes / records the event
             d1 re-issues SWITCH to d2 (d2's VP is now Available)

8. d2 resumes from its saved VMCS state (RIP, RSP, registers preserved by VMCLEAR)
   d2 is completely unaware the interrupt occurred.
```

**To d0**: an ordinary interrupt V fired. It handled it the same way it handles any V.
**To d1**: its SWITCH to d2 returned early with RDI=V (analogous to getting exit_reason=V from d2). D1 can read d2's COMM page for the snapshot.
**To d2**: completely transparent. Resumes from saved VMCS state.

### Required Change to `SwitchContext`

`Capability::switch_domain_forward` must carry the interrupted vector when the target VP is Suspended. This is needed so `do_switch` can set the correct return registers for d1:

```rust
pub struct SwitchContext {
    pub from_domain: DomainId,
    pub to_domain: DomainId,
    pub core_id: CoreId,
    pub is_return: bool,
    pub from_vp_id: Option<u64>,
    pub to_vp_id: Option<u64>,
    /// If the target VP was Suspended from an interrupt, the vector that caused it.
    /// do_switch uses this to set RDI=vector (interrupt return) vs RDI=exit_reason (normal return).
    pub interrupt_return: Option<u8>,
}
```

### EOI-Exit Bitmap Role (Revised)

In this model, `Report` domains are notified via the SWITCH return path — not at EOI time. Therefore, **the EOI-exit bitmap is set to 0 for all vectors** in the initial design. No EOI exits are needed; the physical and virtual EOI are handled entirely in hardware.

| VectorPolicy | EOI-Exit bit | Rationale |
|---|---|---|
| `Deliver` | **0** | Hardware handles EOI; no capavisor involvement |
| `Report` | **0** | Notification via SWITCH return, not EOI exit |
| `NotReport` | **0** | Fully transparent |

The EOI-exit bitmap becomes relevant only if a future use case requires the capavisor to observe EOI events independently of the domain call chain (e.g. for hardware interrupt accounting). That is left for future design.

---



## Per-Domain-Type VMCS Configuration

### Dom0

Dom0 is the root domain; Linux expects to own the hardware interrupt state.

| Setting | Value | Rationale |
|---|---|---|
| `EXTERNAL_INTERRUPT_EXITING` | **0** | Physical interrupts delivered directly to dom0; no capavisor involvement. |
| `VIRTUAL_APIC_ADDR` | dom0 VAPIC page | Efficient APIC register access without MMIO exits. |
| `APIC_REGISTER_VIRT` | 1 | APIC reads go to VAPIC page. |
| `VID` | 1 | Enables `vIRR`-based injection on VM entry (needed when re-injecting forwarded interrupts from children). |
| `PROCESS_POSTED_INTERRUPTS` | 1 | Allows other cores / the capavisor to inject into a running dom0 VP without causing an exit. |
| EOI-exit bitmap | **all 0** | Dom0 handles all EOIs natively; no capavisor notification. |
| `TPR_THRESHOLD` | 0 | No TPR-shadow exits; all interrupts delivered. |

Dom0 owns the physical APIC. Its vTPR, vISR, vIRR reflect the real LAPIC state.

### Child Domains

| Setting | Value | Rationale |
|---|---|---|
| `EXTERNAL_INTERRUPT_EXITING` | **1** | All physical interrupts exit for routing. |
| `ACKNOWLEDGE_INTERRUPT_ON_EXIT` | **1** | ACKs the LAPIC on exit so the interrupt is consumed; prevents re-fire on VMRESUME. |
| `VIRTUAL_APIC_ADDR` | per-VP VAPIC page | Child's virtual LAPIC state. |
| `APIC_REGISTER_VIRT` | 1 | APIC reads go to child's VAPIC. |
| `VID` | 1 | `Deliver` interrupts re-injected via `vIRR`; hardware delivers on VM entry. |
| `PROCESS_POSTED_INTERRUPTS` | 1 | Hypervisor can inject `Deliver` vectors without causing an exit. |
| EOI-exit bitmap | **all 0** | `Report` notification uses SWITCH return, not EOI exits (see §Report Policy Semantics). |
| `POSTED_INTR_NOTIFICATION_VECTOR` | reserved vector (e.g. 0xF2) | Notification IPI for posted interrupt delivery. |
| `POSTED_INTR_DESCRIPTOR_ADDR` | per-VP PID page | 64-byte PID structure. |

---

## Interrupt Routing Flows

### Physical interrupt arrives while a domain is running

```
Physical interrupt (vector V) → VMEXIT (EXIT_REASON_EXTERNAL_INTERRUPT)
  Read V from VMEXIT_INTERRUPTION_INFO[7:0]
  running_policy = running_domain.InterruptPolicy.get_policy(V)

  if running_policy == Deliver:
    // This domain owns V — re-inject and resume immediately
    Set bit V in running VAPIC.vIRR
    VMRESUME  (VID delivers V on next VM entry, no domain switch)

  else:  // Report or NotReport — route upward to Deliver ancestor
    Write running domain's register snapshot to its COMM page
      as InterceptMessage { exit_reason=V }
    handler_id = route_interrupt(V, running_cap)
    deliver_interrupt_vp(running_cap, handler_id, core_id, V)
      // state transitions per lazy-unwind model (see example above)
    VMCLEAR running domain → store in its VP slot
    Take handler domain's VMCS from its slot → VMPTRLD
    Set bit V in handler's VAPIC.vIRR
    // Do NOT advance handler's RIP (stays at its SWITCH VMCALL)
    VMRESUME handler
      → handler processes interrupt (V fires via VID on VM entry)
      → handler iret → re-executes SWITCH down the call chain
      → each Suspended VP in the chain becomes Running with RDI=V
        (interrupt return, not normal exit)
      → each NotReport/Report VP resumes, may re-SWITCH to callee
      → Interrupted leaf VP transitions to Available on first Suspended→Running
```

### Guest EOI for `Deliver` vector

```
Guest writes EOI → EOI-exit bitmap bit=0 → handled entirely in hardware
  Hardware: clears vISR[V], recomputes vPPR
  For level-triggered: hardware sends directed EOI to IOAPIC
  Capavisor: not involved
```

### Hypervisor injects interrupt into a running VP (Posted Interrupts, Phase 2)

```
Hypervisor wants to inject vector V into VP (running or not):
  policy(V) == Deliver:
    Atomically set bit V in VP's PID.PIR
    If PID.ON was 0: set ON=1, send notification IPI to VP's core
    → If VP is running: hardware delivers V via vIRR with no exit
    → If VP is not running: PID.PIR set; processed on next VMENTRY
  policy(V) != Deliver:
    // Do not inject directly; route through domain hierarchy
```

---

## Physical APIC State Invariant

**Dom0 holds the physical APIC state.** When dom0 is Running on a core:
- The physical LAPIC timer, LVT entries, IRR/ISR state all belong to dom0's execution context.
- APIC register virtualization means reads/writes go to dom0's VAPIC, but the physical LAPIC is in sync.

Dom0 uses **two distinct interrupt delivery paths** that coexist:

1. **Physical interrupt path** (`EXTERNAL_INTERRUPT_EXITING=0`): the physical LAPIC delivers the interrupt directly to dom0 via the hardware IDT mechanism on VM entry. The processor updates vISR/vIRR in dom0's VAPIC automatically. The capavisor is not involved.

2. **Capavisor injection path**: when a child domain's interrupt is routed to dom0, the capavisor sets a bit in dom0's `vIRR` VAPIC page, then VMRESUMEs dom0. VID evaluates `vIRR` on VM entry and delivers the interrupt through the same IDT path as physical interrupts. To dom0, both paths look identical.

Both paths are handled correctly by VID and APIC register virtualization. No capavisor action is needed to reconcile them.

When a child runs on a core, the physical LAPIC context is "borrowed" by the child's VMCS for the duration of the switch. Interrupts that arrive for dom0 (vectors not in the child's `Deliver` set) are forwarded back to dom0 via the routing flow above, restoring the invariant.

---

## Implementation Phases

### Phase 1 — VAPIC + VID (no Posted Interrupts, no EOI exits)

- Enable APIC register virtualization and VID for all domains.
- EOI-exit bitmap = all 0 for all domains (no EOI exits needed).
- On `EXIT_REASON_EXTERNAL_INTERRUPT` during child execution: check vector policy, re-inject or lazy-unwind to Deliver ancestor.
- `Report` domain notification is entirely via the SWITCH return path — no separate EOI handling.
- Dom0: `EXTERNAL_INTERRUPT_EXITING=0`; physical interrupts delivered directly.

### Phase 2 — Posted Interrupts

- Allocate PID page per VP; choose notification vector.
- Enable `PROCESS_POSTED_INTERRUPTS` in VMCS.
- Implement PID-based injection path in capavisor for `Deliver` vectors.
- This enables zero-exit delivery of hypervisor-injected interrupts to running VPs.

### Phase 3 — VT-d Interrupt Remapping (**required for correct `Deliver` passthrough**)

Without VT-d, a child domain with a mixed policy (some `Deliver`, some `Report`) still exits on every physical interrupt arrival because `EXTERNAL_INTERRUPT_EXITING` is a single bit. The capavisor re-injects `Deliver` vectors immediately, but the exit overhead is unavoidable and becomes a bottleneck for latency-sensitive workloads with device interrupts.

VT-d interrupt remapping is **required** to achieve the design goal of zero-exit passthrough for `Deliver` vectors:

- Each physical device IRQ gets an Interrupt Remapping Table Entry (IRTE).
- For a `Deliver` vector assigned to child VP: IRTE is programmed to post the interrupt directly to the child VP's PID. Hardware delivers it to the running VP without any exit.
- For `Report` / `NotReport` vectors: IRTE routes through a reserved "hypervisor notification" IRTE, which generates a notification interrupt on the target core → capavisor exit → route upward.
- **This is the only way to achieve per-vector exit avoidance for physical device interrupts.** It must be implemented before device assignment to child domains can be considered correct.

---

## Delivering Interrupts to a Non-Running Domain

When the capability engine routes an interrupt to handler domain H, H may not be running on the current core (or on any core). There are three sub-cases:

### Case A — H is the domain currently running on this core (same-core, Running)

The VP is Running; inject via VMENTRY. Set bit V in H's VAPIC `vIRR` and do not advance RIP. On the next VM entry VID delivers the interrupt automatically. This is the same-core forward path described in the routing flow above.

### Case B — H is not running anywhere (VP state = Available or Interrupted)

The VP has no loaded VMCS. The capavisor:
1. **Sets bit V in H's VAPIC page `vIRR`** (byte offset `0x200 + (V/32)*16`, bit `V % 32`). This is a plain memory write to a physical page — no VMCS operation needed.
2. Takes no further action. When H's VP is next activated (VMPTRLD + VMLAUNCH/VMRESUME), VID evaluates the vIRR on VM entry and delivers the pending interrupt to the guest's IDT.

This works because the VAPIC page persists across deactivations. VMCLEAR saves all VMCS state to memory but does **not** zero the VAPIC page.

### Case C — H is running on a *different* core C2 (cross-core)

The VP is Running on core C2. The capavisor on the current core cannot touch C2's loaded VMCS directly. The correct path is Posted Interrupts:

1. Atomically set bit V in H's `PID.PIR`.
2. If `PID.ON` was 0: atomically set `ON=1`, send an IPI to C2 using H's `POSTED_INTR_NOTIFICATION_VECTOR`.
3. C2's processor receives the IPI, recognises it as the notification vector, atomically moves `PIR` bits into the VAPIC `vIRR` of the currently-loaded VMCS (which is H's VP), clears `ON`, and delivers the interrupt to H — **no VM exit on C2**.

This is why Phase 2 (Posted Interrupts) is required before cross-core interrupt delivery is correct. Without PID support, the only fallback is to queue the interrupt in H's VAPIC `vIRR` (Case B path) and rely on H eventually being re-entered on some core; this is correct but loses the "interrupt fires promptly" guarantee.

### Case D — H is Locked or Suspended (H called a callee, interrupt preempts it)

H's VP state is Locked (waiting for a child it SWITCHed to) or Suspended (preempted by a prior interrupt further up the chain). Delivering the interrupt to H requires unwinding the call chain via `deliver_interrupt_vp` (the capability engine lazy-unwind model), which transitions H's VP to Running and the callee(s) to Interrupted/Suspended. After the unwind, the situation reduces to Case A: H's VP is now Running on its core and the interrupt can be injected via `vIRR`.

---

## Cross-Core Interrupt Virtualization

### The Problem

In a multi-core system, a VP of domain D may be Running on core 0, while an interrupt arrives on core 1 destined for D. The capavisor on core 1 cannot write to core 0's loaded VMCS without synchronisation. Two mechanisms are needed:

1. **Injection without exit** (for `Deliver` vectors on a running VP): Posted Interrupts.
2. **Notification and routing** (for `Report`/`NotReport` vectors, or for non-running VPs): IPI + COMM page.

### Same-Destination Injection via Posted Interrupts (Phase 2+)

For a `Deliver` vector destined for a VP running on another core, the capavisor sets `PID.PIR[V]` and sends a notification IPI (see Case C above). This is entirely transparent to the receiving domain — no COMM page involvement, no VM exit on the receiving core.

### Cross-Core Notification via COMM Page + IPI

For `Report` vectors in the cross-core case, the full lazy-unwind still applies, but the unwind happens on the **core where the interrupt fires** (since `deliver_interrupt_vp` transitions domain VP states in shared memory). The capavisor on that core:

1. Performs the lazy-unwind state transitions (shared atomic operations on VP states).
2. Writes the InterceptMessage to the interrupted domain's COMM page.
3. Sends a notification IPI to the Deliver ancestor's core to trigger its SWITCH re-execution.

The core-ownership transitions are safe because VP state transitions go through the capability engine's lock-free atomic operations. Detailed locking is deferred to the multi-core Phase 2 implementation.

### Cross-Core IPI Virtualization

Linux sends IPIs to other cores using `LAPIC ICR` writes (vector 0xFD–0xFF typically). In a virtualised system:

- **Dom0 → Dom0**: IPIs between dom0 VPs on different cores pass through normally. The LAPIC ICR write goes to the VAPIC, but with APIC-access virtualization the hardware delivers it via the physical ICR. No capavisor involvement needed.

- **Child → Dom0 (or child → child)**: A child's ICR write would go to its VAPIC. With `APIC_REGISTER_VIRT`, reads/writes to the VAPIC are virtualised but ICR writes are a special case: they cause an APIC-write VM exit (if `APIC_WRITE_VMEXIT` is enabled in secondary proc-based controls). The capavisor can then:
  1. Check the destination APIC ID and vector.
  2. Map the APIC ID to a VP / domain.
  3. If allowed by the domain policy: deliver via PID (Posted Interrupts) to the target VP.
  4. If not allowed: inject a `#GP` or silently discard.
  This gives the capavisor full control over inter-domain IPIs.

- **Dom0 → Child**: Dom0 may want to deliver a virtual interrupt to a child VP. The hypervisor uses the PID path (set `PIR[V]`, send notification IPI if VP is running). This is the same path used for virtual device interrupt injection.

### COMM Page Role Summary

| Scenario | Mechanism | COMM Page involved? |
|---|---|---|
| Physical interrupt → `Deliver` domain, running | vIRR bit set, VID delivers | No |
| Physical interrupt → `Deliver` domain, not running | vIRR bit set, delivered on next VM entry | No |
| Physical interrupt → `Deliver` domain, running on other core | PID.PIR set, notification IPI | No |
| Physical interrupt → `Report` / `NotReport` ancestor present | Lazy unwind; snapshot written to interrupted domain's COMM page | **Yes** — InterceptMessage in the *interrupted* (leaf) domain's COMM page; its parent reads it when SWITCH returns with RDI=V |
| Normal child exit forwarded to parent (HLT, EPT fault, etc.) | `forward_child_exit` | **Yes** — InterceptMessage in child's COMM page, parent reads on SWITCH return |
| Cross-domain IPI child→dom0 | APIC-write exit, PID injection or route upward | Only if the IPI vector has Report/NotReport ancestors |

---

## Integration with the THHV Driver

The THHV driver is the boundary between userspace and the capavisor. The full interrupt configuration and delivery pipeline is:

```
Userspace (VMM / device model)
        │
        │  THHV ioctls (SET_INTR_POLICY, IRQFD, MSI_ROUTING, RUN_VP)
        ▼
  THHV kernel driver
        │  translates to hypercalls + VMCS updates
        ▼
  Capability engine  (VectorPolicy in InterruptPolicy)
        │  drives
        ▼
  VAPIC / EOI-exit bitmap / VMCS controls / VT-d IRTE configuration
```

### Configuration Flow: Userspace → Hardware

**1. Set interrupt policy** (`THEMIS_HC_SET_INTR_POLICY` / `THEMIS_HC_SET_DEF_INTR_POLICY` hypercalls):

Userspace sets per-vector or default-visibility policies for a domain's VP. The driver calls `Capability::set_policy` in the capability engine, which updates the domain's `InterruptPolicy`. The capavisor then:
- Recomputes the EOI-exit bitmap for the affected VP's VMCS.
- Updates the PID notification configuration if Posted Interrupts are enabled.
- For VT-d (Phase 3): reprograms the relevant IRTEs.

This update must be applied to the live VMCS if the VP is currently running, which requires an IPI + barrier (same mechanism as EPT updates).

**2. Register physical interrupt → domain mapping** (`THHV_MSI_ROUTING` / `THHV_IRQFD`):

`THHV_MSI_ROUTING` tells the driver which physical GSI or MSI vectors are assigned to which partition. The driver translates each entry to:
- **Phase 1/2**: an entry in a routing table consulted when `EXIT_REASON_EXTERNAL_INTERRUPT` fires for that vector.
- **Phase 3**: an IRTE that posts the interrupt directly to the target VP's PID — no exit needed.

`THHV_IRQFD` allows userspace (e.g. a device emulator) to inject an interrupt by writing to an eventfd. The driver maps this fd write to a work item that sets the bit in the target VP's PID and sends the notification IPI if the VP is currently running. This is the primary injection path for virtual devices.

**3. ioeventfd for MMIO exits** (`THHV_IOEVENTFD`):

When a child writes to a specific GPA (emulated MMIO), the capavisor takes an EPT violation exit and the driver writes to the registered eventfd. Userspace handles the device operation and uses `THHV_IRQFD` to inject the interrupt response. Together these form the virtual device loop without requiring the child to exit for interrupt delivery — the response is posted via PID.

### Delivery Flow: Hardware → Userspace

**For `Deliver` policy (fully in-VM, Phase 1/2):**
- Interrupt fires → hardware delivers via VID (no exit), or capavisor re-injects via vIRR on `EXIT_REASON_EXTERNAL_INTERRUPT`.
- Guest handles interrupt, writes virtual EOI.
- EOI-exit bitmap bit = 0 → hardware handles EOI; no exit.
- **RUN_VP ioctl does NOT return.** Userspace never sees this interrupt.

**For `Report` policy:**
- Interrupt fires → capavisor lazy-unwinds the call chain to the `Deliver` ancestor.
- The `Deliver` ancestor handles the interrupt natively (via vIRR injection).
- The `Deliver` ancestor re-executes SWITCH down the chain. Each `Report` domain's SWITCH call "returns early" with `RDI = interrupt vector` — indistinguishable in structure from a normal child exit.
- The interrupted domain's COMM page contains `InterceptMessage { exit_reason=V, registers per read_set }` written at interrupt time.
- **RUN_VP ioctl returns** for the `Report` domain with the synthetic SWITCH return; userspace reads the interrupt reason from `RDI` and the register snapshot from the interrupted domain's COMM page.
- The `Report` domain then re-issues SWITCH to its callee to continue execution.

**For `NotReport` policy:**
- Interrupt fires → capavisor routes to handler, re-injects. No COMM page message, no RUN_VP return. Transparent.

### What the Driver Must Provide to the Capavisor

The driver must communicate three things to the capavisor that are not knowable at compile time:

1. **The notification vector** — a physical interrupt vector reserved at driver load time, before any VMs run. Must not conflict with Linux's allocator (typically `0xF0–0xFF`). Passed via boot parameter or a dedicated hypercall at driver init.
2. **PID physical addresses** — one 64-byte structure per VP, allocated when the VP is created. Passed alongside the VMCS and VAPIC addresses in the `ADD_VP` hypercall.
3. **MSI routing table** — updated whenever `THHV_MSI_ROUTING` is called, so the capavisor's exit handler knows which domain to route each physical vector to.

### Implementation Status

*(Updated 2026-03-30)*

| Component | Status | Notes |
|---|---|---|
| Phase 1: VAPIC + VID + forwarding | ⚠️ Partial | Hardware configured (`intr-p1-*` commits), but capavisor does NOT call `route_interrupt()` — handler hardcoded to dom0 (A9 violation, see §Gap Analysis). `DEFERRED_HOST_VECTOR` removed in `c2820b5`. |
| Phase 2: Posted Interrupts + PID | ✅ Done | `intr-p2-*` commits; `inject_via_pid`, notification vector `0xF2`, cross-core IPI |
| Phase 3: VT-d Interrupt Remapping | ✅ Done | `intr-p3-*` commits; IRTE alloc, IR enable, `program_domain_irtes` at seal/revoke |
| APICv: VIRTUALIZE_X2APIC (bit 4) | ✅ Done | `e6ebc30`; x2APIC MSR reads via VAPIC page, no exit |
| APICv: `inject_virtual_interrupt` | ✅ Done | `c1a0c1a`; sets VIRR + RVI in VAPIC page |
| APICv: APIC access page + exit handler | ✅ Done | `3e58f7a`; `EXIT_REASON_APIC_ACCESS=44` emulated via VAPIC |
| NMI_EXITING for child VPs | ✅ Done | `8d282ad`; NMI forwarded to dom0 via `forward_interrupt_to_handler` |
| EOI_INDUCED exit handler | ✅ Not needed | Lazy-unwind model: physical EOI issued by dom0; REPORT domains notified via COMM page. EOI-exit bitmap stays 0. |
| `SET_INTR_POLICY` hypercall | ✅ Done | `do_set_intr_policy` wired; EOI-exit bitmap update still deferred (see Open Q4) |
| COMM page register snapshot on exit | ✅ Done | `forward_child_exit` writes all `read_set` registers to `VpCommPage` |
| PID allocation per VP | ✅ Done | `pid_phys` in `VcpuSlot`, allocated from META at `ADD_VP` time |
| Notification vector | ✅ Done | `NOTIFY_VEC = 0xF2` reserved in `hypercall.rs` |
| GET_REG / SET_REG via COMM page | ✅ Done | `get_vp_register`/`set_vp_register` read/write `VpCommPage` directly |
| `IRTE.NDST` sync on VP activation | ✅ Done | `sync_irte_ndst` called in `do_switch` after VMPTRLD; updates NDST for all Deliver-vector IRTEs. **Needs end-to-end test once real device assignment is in use.** |
| Deliver fast-path in vmexit handler | ❌ Not done | `EXIT_REASON_EXTERNAL_INTERRUPT` always routes upward; no VectorPolicy check for `Deliver` re-inject (see §Gap Analysis) |
| `route_interrupt()` used by capavisor | ❌ Not done | `forward_interrupt_to_handler()` hardcodes `platform.dom0_cap()` instead of calling engine's `route_interrupt()` (see §Gap Analysis) |
| `do_inject_interrupt` policy check | ❌ Not done | PIR write bypasses `apply_update()` — no per-vector injection policy enforcement (partial A1 violation) |
| EOI-exit bitmap update on policy change | ❌ Open | See Open Question 4; requires VMPTRLD+vmwrite on target VP's VMCS |
| `THHV_IRQFD` fd-triggered injection | ✅ Done | `thhv_irqfd.c`: eventfd → workqueue → `VMCALL_INJECT_INTERRUPT` → `inject_via_pid`. Implemented. |
| `THHV_IOEVENTFD` MMIO exit → eventfd | ✅ Done | `thhv_ioeventfd.c`: doorbell GPA → capavisor EPT fast-path → DomainComm → `eventfd_signal`. Implemented. |
| Virtio I/O end-to-end (virtio_blk) | ❌ Broken | dom1 reaches virtio_blk probe but first I/O never completes. Zero INJECT_INTERRUPT VMCALLs observed. See §Virtio I/O Path. |

### Key Design Constraint: LAPIC Timer Interrupts

The LAPIC timer (TSC deadline timer, vector configured by Linux) is a *local* interrupt, not an IOAPIC or MSI interrupt. It cannot be remapped via VT-d. When a child is running on a core, LAPIC timer interrupts will **always** cause an `EXIT_REASON_EXTERNAL_INTERRUPT` exit — even in Phase 3. The only mitigation is to make the re-injection path as fast as possible (set vIRR bit + VMRESUME). This is a fundamental architectural constraint of VT-x for core-local interrupts.

---

## Open Questions

1. **Notification vector**: ✅ Resolved — `NOTIFY_VEC = 0xF2` reserved in `hypercall.rs`.

2. **APIC-access page**: ✅ Resolved — APIC access page implemented (P5b); x2APIC path also
   enabled (VIRTUALIZE_X2APIC). Both are in place.

3. **vTPR / TPR threshold interaction**: ✅ Resolved — `TPR_THRESHOLD=0` set for all child
   VPs in `vmcs.rs`; all interrupts deliverable regardless of guest CR8.

4. **EOI-exit bitmap updates on policy change**: ✅ Resolved — **not needed**. In the
   lazy-unwind model the physical EOI is issued by dom0's interrupt handler before the
   unwind chain returns to REPORT domains. REPORT domains learn about the interrupt via
   the COMM page `InterceptMessage`, not through virtual EOI. The EOI-exit bitmap can
   remain all-zero.

---

## Implementation Plan

Implementation is split into three phases matching the design. Phase 1 is the immediate work item and unblocks the lost-timer-interrupt regression. Phases 2 and 3 can proceed independently once Phase 1 is stable.

### Phase 1 — VAPIC + VID + Core Interrupt Forwarding  (`intr-p1-*`)

**Goal**: Fix the lost-timer-interrupt RCU stall. Route physical interrupts to their handler domain via lazy-unwind. All interrupt delivery goes through `vIRR` injection and VID. No posted interrupts yet.

**Step 1 — Allocate VAPIC page per VP and enable VAPIC + VID in VMCS** (`intr-p1-vmcs`)
- Allocate a 4 KB VAPIC page per VP at `add_vp` time (or lazily on first VMCS activation). Store HPA in `VpState`.
- Write `VIRTUAL_APIC_ADDR` in `write_control_fields` for all VPs (dom0 and child).
- Enable `APIC_REGISTER_VIRT` (secondary bit 8) and `VID` (secondary bit 9) for all VPs.
- Set `EOI_EXIT_BITMAP` fields = 0 for all VPs (four 64-bit VMCS fields).
- Dom0: `EXTERNAL_INTERRUPT_EXITING=0` (already), verify `VID=1`.
- Children: `EXTERNAL_INTERRUPT_EXITING=1`, `ACKNOWLEDGE_INTERRUPT_ON_EXIT=1` (already set).
- Set `TPR_THRESHOLD=0` for all VPs (no TPR-threshold exits).
- Files: `vmcs.rs` (`write_control_fields`, `write_guest_state`), `platform.rs` (VP allocation).

**Step 2 — Interrupt routing table + `SET_INTR_POLICY` hypercall** (`intr-p1-routing-table`)
- Add `interrupt_policy: [VectorPolicy; 256]` (or a sparse BTreeMap) per VP in `VpState` in `platform.rs`.
- Implement `THEMIS_HC_SET_INTR_POLICY` VMCALL handler in `hypercall.rs`: parse `(vp_handle, vector, policy)` from guest registers, update `VpState.interrupt_policy`.
- Implement `route_interrupt(V: u8, running_cap: &CapRef) -> CapRef` in `hypercall.rs`: walks the domain's caller chain to find the first ancestor with `policy == Deliver`.
- Files: `hypercall.rs`, `platform.rs`.

**Step 3 — `forward_interrupt_to_handler` in vmexit.rs** (`intr-p1-forward`)
- On `EXIT_REASON_EXTERNAL_INTERRUPT` during child VP execution:
  - Read V from `VMEXIT_INTERRUPTION_INFO[7:0]`.
  - Look up child's policy for V.
  - **Deliver path**: policy == `Deliver` → set `vIRR[V]` in child's VAPIC, `VMRESUME`. Done.
  - **Route-upward path**: policy != `Deliver`:
    1. Write register snapshot to child's COMM page as `InterceptMessage { exit_reason=V, registers per read_set }`.
    2. `handler = route_interrupt(V, child_cap)`.
    3. `Capability::deliver_interrupt_vp(child_cap, handler, core, V)` — lazy-unwind VP state transitions.
    4. `VMCLEAR` child VMCS → store in child VP slot.
    5. `VMPTRLD` handler VMCS from handler VP slot.
    6. Set `vIRR[V]` in handler's VAPIC page (`VAPIC base + 0x200 + (V/32)*16`, bit `V%32`).
    7. Do NOT advance handler's RIP (stays at the SWITCH VMCALL).
    8. `VMRESUME` handler.
- Files: `vmexit.rs`, `hypercall.rs`.

**Step 4 — `SwitchContext.interrupt_return` and `do_switch` update** (`intr-p1-switch-ctx`)
- Add `interrupt_return: Option<u8>` to `SwitchContext` in `capa-engine/src/switch.rs`.
- In `switch_domain_forward` (`capa-engine/src/capability.rs` ~line 2544): when the target VP is `Suspended { vector, .. }`, populate `SwitchContext.interrupt_return = Some(vector)`.
- In `do_switch` (`hypercall.rs` ~line 506): after `Capability::switch` returns, if `SwitchContext.interrupt_return == Some(V)`, set guest `RDI = V as u64` (interrupt return reason) and `RAX = SUCCESS`, then advance RIP. This is how `Report` domains discover their callee was interrupted.
- Files: `capa-engine/src/switch.rs`, `capa-engine/src/capability.rs`, `themis/capavisor/src/hypercall.rs`.

**Step 5 — Phase 1 validation** (`intr-p1-test`)
- Run existing C7 test (`test_child_hlt.c`): confirm no RCU stall after the test completes.
- Write a new userspace test (`test_intr_forward.c`): dom0 runs a child that loops; confirm timer ticks are received by dom0 at the expected rate while the child is active.
- Run `cargo test` in `capa-engine/` to confirm no regressions in the capability engine unit tests.

---

### Phase 2 — Posted Interrupts  (`intr-p2-*`)

**Goal**: Zero-exit delivery of capavisor-injected interrupts to running VPs, and correct cross-core `Deliver` delivery.

**Step 1 — PID allocation** (`intr-p2-pid`)
- Allocate a 64-byte aligned `PostedInterruptDescriptor` page per VP at `add_vp` time. Store HPA in `VpState`.
- Write `POSTED_INTR_DESCRIPTOR_ADDR` VMCS field in `write_control_fields` for child VPs.
- Write `POSTED_INTR_NOTIFICATION_VECTOR` (reserved vector, TBD) for child VPs.
- Enable `PROCESS_POSTED_INTERRUPTS` (pin-based control bit 7) for child VPs.
- Files: `vmcs.rs`, `platform.rs`.

**Step 2 — Notification vector reservation** (`intr-p2-notify-vec`)
- Reserve a vector at capavisor init that won't be allocated by Linux (e.g. probe `0xF2`; confirm not in use via the IVT / interrupt descriptor table at boot).
- Store as a capavisor global; use in `POSTED_INTR_NOTIFICATION_VECTOR` writes.
- Files: `main.rs`, `vmcs.rs`.

**Step 3 — PID-based injection path** (`intr-p2-inject`)
- Implement `inject_via_pid(pid: &mut PID, V: u8, target_core: Option<CoreId>)`:
  - Atomically set `pid.PIR[V]`.
  - If target VP is running (core known) and `pid.ON` was 0: set `ON=1`, send IPI to target core using notification vector.
  - If target VP is not running: PIR bit set; processed on next VMENTRY.
- Replace direct `vIRR` writes (from Phase 1 `forward_interrupt_to_handler`) with `inject_via_pid` for cross-core running VPs (Case C from §Delivering Interrupts).
- Files: `hypercall.rs`, `platform.rs`.

**Step 4 — Phase 2 validation** (`intr-p2-test`)
- Test cross-core `Deliver` delivery with a multi-core child domain scenario.
- Measure interrupt latency improvement vs Phase 1 vIRR injection (qualitative).

---

### Phase 3 — VT-d Interrupt Remapping  (`intr-p3-*`)

**Goal**: True per-vector exit avoidance for physical device interrupts assigned to child domains. Required before device passthrough is correct.

This is a large separate milestone, tracked under its own phase. The primary steps are:
- Enumerate DMAR ACPI table; map the IOMMU at boot.
- Enable interrupt remapping: build Interrupt Remapping Table (IRT).
- For child `Deliver` vectors: program IRTE to post directly to child's PID.
- For `Report`/`NotReport` vectors: IRTE routes to hypervisor notification vector → capavisor exit → lazy-unwind.
- Must be implemented before `MSHV_ASSIGN_DEVICE` (Phase 16e) is correct.

See todo items `intr-p3-*` for detailed breakdown (added when Phase 2 is complete).

---

## Virtio I/O Path

*(Added 2026-03-30)*

Virtio block I/O is the first real end-to-end test of the interrupt injection
pipeline. Understanding the full data flow is essential for diagnosing the current
virtio_blk hang (dom1 probes the device but first disk I/O never completes).

### Full Virtio Request–Completion Pipeline

```
dom1 guest (L2)                 capavisor (L0)           thhv driver (L1 kernel)    CHV (L1 userspace)
───────────────                 ──────────────           ───────────────────────    ──────────────────

1. virtio_blk submits I/O
   Guest writes descriptors
   to virtqueue (shared memory)

2. Guest writes virtio kick
   register (MMIO notification
   address, typically
   GPA 0xd0000000 + offset)
   ────────────────────────────→ 3. EPT violation VMEXIT
                                    (EXIT_REASON=48)
                                    GPA = kick register addr

                                 Check doorbell table:
                                 ┌─ Match found (fast-path):
                                 │  a. Write DoorbellNotify
                                 │     to parent DomainComm
                                 │     RX ring
                                 │  b. Advance child RIP
                                 │  c. VMRESUME child
                                 │     (child resumes immediately)
                                 │
                                 └─ No match (slow path):
                                    forward_child_exit()
                                    → SWITCH returns to dom0
                                    → thhv copies exit info
                                    → CHV handles as MMIO

4. (Child resumed, continues)

                                                          5. thhv_drain_domcomm_rx()
                                                             after SWITCH returns, or
                                                             on next DomainComm poll
                                                             → sees DOORBELL_NOTIFY
                                                             → matches doorbell_id
                                                               to eventfd
                                                             → eventfd_signal(fd)
                                                          ─────────────────────────→ 6. CHV virtio worker
                                                                                       wakes on eventfd
                                                                                       Processes virtqueue:
                                                                                       reads descriptors,
                                                                                       does actual disk I/O,
                                                                                       writes completion
                                                                                       descriptors back

                                                                                    7. CHV signals IRQFD
                                                                                       eventfd (completion
                                                                                       interrupt for dom1)
                                                          ←─────────────────────────
                                                          8. thhv_irqfd_inject()
                                                             workqueue handler fires
                                                             Looks up GSI→vector
                                                             from MSI routing table
                                                             → themis_inject_interrupt
                                                               (domain, vp_id, vector)
                                                             = VMCALL(INJECT_INTERRUPT)
                                 ←────────────────────────
                                 9. do_inject_interrupt()
                                    Validates child cap
                                    Gets pid_phys from
                                    VcpuSlot
                                    → inject_via_pid(
                                        pid_phys, hhdm,
                                        vector, false)
                                    PIR[vector] = 1

10. On next VMRESUME of dom1:
    do_switch step 7b drains
    PIR → vIRR. VID delivers
    interrupt to guest IDT.
    virtio_blk completion ISR
    fires → I/O completes.
```

### Current Failure Point (2026-03-30)

Zero `INJECT_INTERRUPT` (opcode 0x1B) VMCALLs are observed during dom1 boot.
This means the pipeline is broken somewhere between steps 2–8. The failure
could be at any link:

| Link | Hypothesis | How to verify |
|------|-----------|---------------|
| Step 2→3 | Doorbell GPA not registered (IOEventFd not set up) | Instrument `VMCALL_REGISTER_DOORBELL` in capavisor; check if CHV calls `register_ioeventfd` |
| Step 3 | EPT violation occurs but no doorbell match → falls to slow path | Add doorbell-miss counter in `handle_ept_violation` |
| Step 5 | DomainComm RX ring not drained (thhv doesn't poll it, or ring is full) | Instrument `thhv_drain_domcomm_rx` — is it called? Does it find messages? |
| Step 5→6 | eventfd not signaled (doorbell_id → eventfd mapping missing) | Instrument eventfd_signal path in thhv_ioeventfd.c |
| Step 6→7 | CHV processes virtqueue but doesn't signal completion eventfd | Instrument CHV's virtio completion path |
| Step 7→8 | IRQFD eventfd fires but workqueue handler doesn't run | Instrument `thhv_irqfd_inject` entry |
| Step 8→9 | VMCALL reaches capavisor but fails validation | Instrument `do_inject_interrupt` entry + return code |

**Debugging strategy**: Instrument from the middle outward. Start at step 5
(`thhv_drain_domcomm_rx`) since it's the bridge between capavisor and userspace.
If DomainComm messages are arriving but eventfds aren't signaled, the problem is
in thhv's doorbell→eventfd mapping. If no DomainComm messages arrive, the problem
is in the capavisor's doorbell fast-path or in IOEventFd registration.

---

## Implementation Gap Analysis

*(Added 2026-03-30. Based on code review in `themis/docs/interrupt-handling-review.md`)*

The hardware infrastructure (VAPIC, VID, PID, VT-d IR) is fully implemented and
working. The gaps are in the **software wiring** — the capavisor does not use the
capability engine's interrupt model. This section catalogues the gaps between the
design (above) and the current implementation.

### Gap 1: `route_interrupt()` Not Called (Critical — A9 Violation)

**Design**: `forward_interrupt_to_handler()` should call `route_interrupt(vector,
&child_cap, core_id)` to walk the domain CDT and find the handler domain based on
`VectorPolicy`.

**Reality**: The handler is hardcoded to `platform.dom0_cap()`:
```rust
// hypercall.rs — CURRENT (WRONG)
let dom0_cap = platform.dom0_cap();
let dom0_domain_id = dom0_cap.read().data.id;
```

**Consequence**: Interrupts always route to dom0 regardless of `InterruptPolicy`.
Works for the current 2-level hierarchy (dom0 → dom1) but is fundamentally broken
for deeper hierarchies (dom0 → dom1 → dom2) and violates A9.

**Fix**: Replace the hardcoded dom0 lookup with:
```rust
let (handler_domain_id, _reported_to) = route_interrupt(vector, &child_cap, core_id);
```

### Gap 2: No `Deliver` Fast-Path in VMEXIT Handler (Performance)

**Design** (§Interrupt Routing Flows): When a physical interrupt fires during child
execution and the child's `VectorPolicy` for that vector is `Deliver`, the capavisor
should set `vIRR[V]` in the child's VAPIC and VMRESUME immediately — no domain
switch, no lazy-unwind.

**Reality**: All child external interrupts go through `forward_interrupt_to_handler()`,
which always does a full domain switch to the handler (dom0). There is no
VectorPolicy check at the point where `EXIT_REASON_EXTERNAL_INTERRUPT` is handled.

**Consequence**: Even interrupts the child "owns" (e.g., virtual device interrupts
posted via IRQFD that happen to fire physically while the child runs) cause a full
VMCLEAR/VMPTRLD/domain-switch cycle. This is the exact opposite of the design goal
(§Goal 2: "Interrupts a child domain 'owns' must be delivered without requiring
capavisor involvement").

**Fix**: In `vmexit.rs` `EXIT_REASON_EXTERNAL_INTERRUPT` handler for child VPs:
```rust
let policy = child_domain.policy.interrupts.get_policy(vector);
match policy.visibility {
    InterruptVisibility::Deliver => {
        // Fast-path: re-inject into child, no domain switch
        set_virr_bit(child_vapic_hpa, vector);
        return; // VMRESUME child
    }
    _ => {
        // Route upward via lazy-unwind
        forward_interrupt_to_handler(vcpu, vector);
    }
}
```

### Gap 3: `do_inject_interrupt()` Bypasses `apply_update()` (A1 Partial Violation)

**Design** (A1): "Capability engine validates before any hardware change."

**Reality**: `do_inject_interrupt()` validates that the caller holds a capability to
the child domain, but the actual PIR write is a direct hardware operation:
```rust
unsafe { inject_via_pid(pid_phys, hhdm, vector, false) };
```

There is no `Update::InjectInterrupt` variant, so:
- No per-vector injection policy enforcement at the hardware level
- Not auditable through the capability engine's update path
- The `InterruptPolicy` on the target domain is not checked — any parent holding
  a child handle can inject any vector

**Fix** (lower priority): Add `Update::InjectInterrupt { domain_id, vp_id, vector }`
to the update enum. The engine checks that the injecting domain's `VectorPolicy`
for that vector permits injection (e.g., a domain with `NotReport` policy for vector
V should not be able to inject V into a child).

### Gap 4: RDI Not Set to Vector on Interrupt Return

**Design** (A3): "SWITCH call returns early with RDI = preempting vector."

**Reality**: `forward_interrupt_to_handler()` sets `RDI = 0`:
```rust
handler_active.set_reg(Reg::Rdi, 0);  // should be vector
```

The vector IS injected via `VMENTRY_INTERRUPTION_INFO_FIELD`, so dom0's IDT fires
correctly. But the VMM (CHV) doesn't know which vector preempted its child — it
only sees `themis_switch()` returning `-EAGAIN` with no vector info.

**Fix**: Set `RDI = vector as u64` in the ERR_RETRY return path.

---

## Directvisor-Inspired Optimizations

*(Added 2026-03-30)*

**Reference**: Kevin Cheng, Spoorti Doddamani, Tzi-cker Chiueh, Yongheng Li, and
Kartik Gopalan. "Directvisor: Virtualization for Bare-Metal Cloud." VEE 2020,
pp. 45–58.

Directvisor demonstrates that **interrupt virtualization is the minimal abstraction**
needed for multi-tenant bare-metal isolation. VMs execute directly on hardware with
the hypervisor intervening only for interrupt delivery. This architectural principle
maps directly onto Themis's capability-based interrupt model.

### Architectural Alignment

| Directvisor Concept | Themis Equivalent | Gap |
|---------------------|-------------------|-----|
| Per-VM interrupt bitmap (which vectors belong to which VM) | `VectorPolicy` per domain per vector (`Deliver`/`Report`/`NotReport`) | ❌ Capavisor doesn't consult `VectorPolicy` on `EXIT_REASON_EXTERNAL_INTERRUPT` (Gap 2) |
| Direct execution (no hypervisor for most operations) | `Deliver` policy: guest handles interrupt natively via vIRR/VID | ❌ Not implemented — all interrupts route through handler domain switch |
| Posted interrupt injection (VMM → guest, zero exit) | `inject_via_pid()` + PIR + notification IPI | ✅ Implemented |
| Interrupt remapping (device → guest, zero exit) | VT-d IRTE programmed per domain at seal time | ✅ Implemented |
| Minimal hypervisor interposition | Lazy-unwind: only interpose for `Report`/`NotReport` vectors | ✅ Designed; ❌ not wired |

### Key Directvisor Insight for Themis

Directvisor's contribution is showing that a hypervisor can achieve near-native
performance by virtualizing **only** interrupt delivery while letting VMs execute
directly on hardware for everything else. Themis goes further: the capability model
provides per-vector, per-domain granularity via `VectorPolicy`, and the CDT hierarchy
enables multi-level delegation (a feature Directvisor's flat model lacks).

The current implementation gap is that Themis has all the right infrastructure but
doesn't use it — every interrupt exits to the full handler-domain-switch path
regardless of `VectorPolicy`. Closing Gap 2 (the `Deliver` fast-path) is the
single highest-impact optimization and brings Themis in line with Directvisor's
performance model.

### Optimization O1: Deliver Fast-Path (Directvisor Parity)

When a physical interrupt fires during child VP execution and the child's policy
for that vector is `Deliver`:

```
Current:  VMEXIT → forward_interrupt_to_handler → VMCLEAR child → VMPTRLD dom0
          → inject to dom0 → dom0 handles → dom0 re-SWITCHes to child
          Total: 2 × VMCS swap + dom0 scheduling overhead

Optimized: VMEXIT → check VectorPolicy → set vIRR[V] → VMRESUME child
           Total: 1 vIRR write (~10 cycles) + VMRESUME
```

This is the exact model Directvisor uses for interrupts belonging to a VM. The
~1000× reduction in interrupt handling latency (VMCS swap overhead vs vIRR write)
is the primary performance benefit.

**Capability semantics**: The `Deliver` fast-path is safe because the capability
engine already validated the child's `VectorPolicy` when it was set (at seal time
or via `SET_INTR_POLICY`). The capavisor is merely respecting the policy that was
already authorized through the capability interface.

### Optimization O2: Paravirtualized Virtio Notification (Beyond Directvisor)

Standard virtio notification path:
```
Guest MMIO write → EPT violation VMEXIT → doorbell lookup → DomainComm → IPI → eventfd
```

PV optimization (future, P16.6d3):
```
Guest VMCALL (PV kick) → capavisor direct doorbell dispatch → return to guest
```

The PV path eliminates the EPT fault/walk overhead (~200 cycles on real hardware).
This goes beyond Directvisor's model (which relies on trap-and-emulate for device
I/O) by using an explicit hypercall interface for the performance-critical virtio
kick notification.

**Capability semantics**: The PV kick hypercall must validate that the calling
domain holds a capability that permits doorbell notifications (doorbell_id is
resolved through the capability engine). This is a natural extension of the existing
`VMCALL_REGISTER_DOORBELL` mechanism.

**Prerequisite**: Requires a modified guest virtio-pci driver (or a PV transport)
that uses VMCALL for kick instead of MMIO write. This is a medium-term optimization.

### Optimization O3: Interrupt Coalescing for Batched I/O

For high-throughput virtio workloads (storage, network), the guest may generate
many I/O requests in rapid succession. Each request triggers a separate doorbell
notification → separate eventfd signal → separate interrupt injection.

**Coalescing strategy** (inspired by Directvisor's batched interrupt delivery):
1. **Doorbell coalescing**: If a doorbell notification is already pending in the
   DomainComm RX ring for the same doorbell_id, skip the duplicate notification.
   The VMM will process all pending virtqueue entries when it wakes.
2. **Interrupt injection coalescing**: If a PIR bit for the same vector is already
   set (the previous interrupt hasn't been delivered yet), skip the notification
   IPI. The interrupt will be delivered on the next VMRESUME.

Both forms of coalescing are naturally supported by the existing hardware:
- PIR is a bitmap — setting an already-set bit is a no-op.
- `PID.ON` prevents duplicate notification IPIs (if ON=1, no IPI is sent).

No code change is needed for the PIR-level coalescing; it's inherent in the
Posted Interrupt hardware design. DomainComm-level coalescing requires a
"pending notification" bitmap per doorbell_id (future optimization).

---

## Phase 4 — Correct Routing + Deliver Fast-Path (`intr-p4-*`)

*(Added 2026-03-30)*

**Goal**: Close the gap between the design (above) and the implementation.
Wire `route_interrupt()` and add the `Deliver` fast-path. This phase has no
hardware changes — it is purely software wiring in the capavisor.

**Step 1 — Wire `route_interrupt()` in `forward_interrupt_to_handler()`** (`intr-p4-route`)
- Replace hardcoded `platform.dom0_cap()` with `route_interrupt(vector, &child_cap, core_id)`.
- Pass the returned `handler_domain_id` to `deliver_interrupt_vp()`.
- Set `RDI = vector` on ERR_RETRY return.
- Remove any remaining references to hardcoded dom0 handler.
- Files: `hypercall.rs`.

**Step 2 — Add `Deliver` fast-path in VMEXIT handler** (`intr-p4-deliver`)
- In `vmexit.rs` `EXIT_REASON_EXTERNAL_INTERRUPT` for child VPs:
  1. Read V from `VMEXIT_INTERRUPTION_INFO[7:0]`.
  2. Look up child's `VectorPolicy` for V.
  3. If `Deliver`: set `vIRR[V]` in child's VAPIC page, VMRESUME (no domain switch).
  4. If `Report`/`NotReport`: call `forward_interrupt_to_handler(vcpu, V)` (which now
     uses `route_interrupt()`).
- Files: `vmexit.rs`.

**Step 3 — Add `Update::InjectInterrupt` for capability audit trail** (`intr-p4-audit`)
- Add `InjectInterrupt { domain_id, vp_id, vector }` to the `Update` enum.
- In `do_inject_interrupt()`: go through `execute()` with an operation that produces
  `Update::InjectInterrupt`, then `apply_update()` performs the PIR write.
- The engine checks that the calling domain's `VectorPolicy` for the target vector
  permits injection.
- Files: `capa-engine/src/capability.rs`, `capa-engine/src/domain.rs`,
  `themis/capavisor/src/platform.rs`, `themis/capavisor/src/hypercall.rs`.

**Step 4 — Phase 4 validation** (`intr-p4-test`)
- Unit test: `route_interrupt()` returns correct handler for 3-level hierarchy
  (d0→d1→d2) with mixed policies.
- Integration test: dom1 boot with `Deliver` fast-path enabled — timer interrupts
  for dom0 are routed up, virtio interrupts for dom1 are re-injected.
- Run `cargo test` in `capa-engine/` to confirm no regressions.

### Phase 4 Dependency on Virtio Debugging

Phase 4 is independent of the virtio_blk debugging (which is about the *injection*
pipeline, not *routing*). However, Phase 4 Step 2 (Deliver fast-path) could mask
the virtio_blk bug by re-injecting dom0's timer interrupts faster, giving the child
more execution time. **Debug the virtio_blk pipeline first** (see §Virtio I/O Path)
to establish a clean baseline, then apply Phase 4 for correctness.

