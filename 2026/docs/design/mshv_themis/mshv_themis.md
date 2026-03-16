# mshv-themis: Capability-Aware `/dev/mshv` Driver & Cloud-Hypervisor Backend

## 1. Executive Summary

This document defines the design and implementation plan for **mshv-themis**: a Linux
kernel driver exposing `/dev/mshv` with an ioctl ABI compatible with Microsoft's MSHV
driver, backed by Themis capability operations (VMCALLs).  The goal is to let
**cloud-hypervisor** (CH) create and manage VMs on top of Themis with minimal backend
changes, while preserving the capability engine's security invariants.

The design addresses two scheduling models:

| Mode | Description | Use-case |
|------|-------------|----------|
| **Synchronous (same-core)** | dom0 VP yields its core to a child domain VP via `VMCALL_SWITCH`; the core re-enters the monitor and launches the child VMCS. | Low-latency, 1:1 pinning, real-time workloads. |
| **Asynchronous (cross-core)** | dom0 VP on core A controls a child domain VP running on core B; cross-core IPIs signal events. | Overcommit, independent scheduling, multi-tenant. |

Both modes use the **same ioctl surface** — the scheduling policy is selected at
partition creation time and is transparent to cloud-hypervisor.

---

## 2. Background: What MSHV Does Today

### 2.1 Architecture

The upstream Linux MSHV driver (`drivers/hv/mshv_root_main.c`) exposes a three-level
fd hierarchy:

```
/dev/mshv  (device fd)
  └─ partition fd      (MSHV_CREATE_PARTITION)
       └─ vp fd        (MSHV_CREATE_VP)
```

Each level has its own `file_operations` and ioctl dispatch.

### 2.2 Key IOCTLs (magic 0xB8)

**Device level:**
- `MSHV_CREATE_PARTITION` → returns partition fd
- `MSHV_ROOT_HVCALL` → raw hypercall passthrough

**Partition level:**
- `MSHV_INITIALIZE_PARTITION` → finalise partition config
- `MSHV_CREATE_VP` → returns vp fd
- `MSHV_SET_GUEST_MEMORY` → map/unmap GPA regions
- `MSHV_IRQFD` → eventfd → virtual interrupt injection
- `MSHV_IOEVENTFD` → eventfd on I/O port / MMIO access
- `MSHV_SET_MSI_ROUTING` → GSI → MSI address/data table
- `MSHV_GET_GPAP_ACCESS_BITMAP` → dirty page tracking

**VP level:**
- `MSHV_RUN_VP` → enter guest, block until intercept, return message
- `MSHV_GET_VP_STATE` / `MSHV_SET_VP_STATE` → LAPIC, XSAVE, SynIC state
- `mmap()` → map VP register page, intercept message page

### 2.3 VP Execution Model

MSHV supports two scheduler modes:

1. **Hypervisor scheduler**: driver clears suspend registers, then
   `wait_event_interruptible()` until the hypervisor kicks the VP on intercept.
2. **Root scheduler**: driver calls `HVCALL_DISPATCH_VP` in a loop; the hypercall
   blocks the calling thread until the VP produces an intercept or is preempted.

In both cases, the intercept message (HLT, I/O, MMIO, CPUID, MSR, shutdown, etc.)
is copied to a userspace buffer.  Cloud-hypervisor's `MshvVcpu::run()` reads this
buffer and translates it to its `VcpuExit` enum.

### 2.4 SynIC (Synthetic Interrupt Controller)

SynIC provides per-VP:
- **SIMP** (Synthetic Interrupt Message Page): 16 message slots (one per SINT).
- **SIEFP** (Synthetic Interrupt Event Flags Page): bitmap of pending events.
- **SIRBP** (Synthetic Interrupt Request Block Page): ring-buffer event delivery.
- **SINT registers** (0–15): each maps to an IDT vector, with auto-EOI, masking.

SynIC is the mechanism by which the Hyper-V hypervisor notifies the root partition
(dom0 / L1) about VP intercepts and doorbell events.  It is always enabled in MSHV
and is integral to the VP run loop — the ISR on `HYPERVISOR_CALLBACK_VECTOR` wakes
the sleeping VP thread.

---

## 3. Themis vs Hyper-V: Fundamental Differences

| Aspect | Hyper-V / MSHV | Themis |
|--------|---------------|--------|
| **Hypervisor type** | Proprietary Microsoft hypervisor | Bare-metal Type-1, Intel VT-x |
| **Communication** | MSR-based hypercalls + SynIC pages | VMCALL with register convention |
| **Memory model** | Flat GPA space, hypervisor maps | Capability-based: CARVE + SEND |
| **VP scheduling** | Hypervisor schedules or root dispatches | Core yields via SWITCH or cross-core IPI |
| **Security model** | VTL (Virtual Trust Levels) | CDT (Capability Derivation Tree) |
| **Interrupt notification** | SynIC SINT → IDT vector → ISR | INIT assert → VMEXIT → barrier protocol |
| **VP state access** | Register page (mmap'd GPA) | META VP-state page (Phase 10) or VMCALL |
| **Partition lifecycle** | Stateless: create + init + configure | Unsealed → configured → Sealed |

**Key insight**: MSHV assumes a flat GPA namespace where the hypervisor is an opaque
box that maps pages and dispatches VPs.  Themis has an explicit capability graph where
every memory grant is a capability transfer.  The driver must bridge this gap.

---

## 4. ThemIC — Themis Interrupt Controller

ThemIC is the capability-aware replacement for Hyper-V's SynIC.  Where SynIC is a
per-VP synthetic interrupt controller baked into the hypervisor's MSR interface,
ThemIC is a **message-passing + doorbell** system built on shared pages and
capability-gated registrations, designed to support both synchronous domain
transitions and the asynchronous cross-core model described in §6.2.

### 4.1 What SynIC Does (and What We Need to Replace)

SynIC provides three services that are load-bearing for the MSHV/cloud-hypervisor
stack:

1. **VP intercept notification** — When a child VP exits (I/O, MMIO, CPUID, etc.),
   the Hyper-V hypervisor writes an intercept message to the per-VP **SIMP** (Synthetic
   Interrupt Message Page), then raises a **SINT** (Synthetic Interrupt source) which
   delivers a fixed IDT vector (`HYPERVISOR_CALLBACK_VECTOR`) to the root partition.
   The ISR in `mshv_synic.c` calls `kick_vp()` → `wake_up()` to unblock the driver
   thread sleeping in `mshv_run_vp_with_root_scheduler()`.

2. **Doorbell fast-path** — For IOEventFd (virtio kick notifications), MSHV registers
   "doorbells" with the hypervisor: a {GPA, size, datamatch, flags} tuple.  When the
   guest writes to the doorbell GPA, the hypervisor bypasses the full VMEXIT→userspace
   round-trip; instead it writes an event to the per-VP **event ring** and raises
   SINT[5] (the doorbell SINT).  The ISR invokes the registered callback which signals
   the eventfd, waking the VMM's virtio worker thread.  This is ~10× faster than a
   full VMEXIT dispatch.

3. **Event flags** — A lightweight bitmap (SIEFP, Synthetic Interrupt Event Flags
   Page) providing 16 × 256 = 4096 flag bits.  Used for VMBus channel signaling.
   Less relevant for cloud-hypervisor but architecturally important.

### 4.2 ThemIC Architecture

ThemIC provides equivalent services through two complementary layers, both of
which already exist in the codebase:

```
Per-DOMAIN notification state (one per parent domain):

┌──────────────────────────────────────────────────────────────────────┐
│  DomainComm region (already implemented, per parent domain)          │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │ Header page: magic, version, notify_vector, TX/RX ring meta  │    │
│  ├──────────────────────────────────────────────────────────────┤    │
│  │ TX ring (domain → capavisor): hypercall requests             │    │
│  ├──────────────────────────────────────────────────────────────┤    │
│  │ RX ring (capavisor → domain): VP_EXIT, DOORBELL_NOTIFY, ...  │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                                                                       │
│  Doorbell table: capavisor-internal Vec<DoorbellEntry>               │
│  (stored in PlatformDomain; not a shared page)                       │
└──────────────────────────────────────────────────────────────────────┘

Per-VP register sync state (one VpCommPage per child VP):

┌──────────────────────────────────────────────────────────────────────┐
│  VpCommPage (4 KB, per child VP, mapped via REGISTER_COMM)           │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │ dirty_mask / allowed_mask (bytes 0–63)                        │    │
│  ├──────────────────────────────────────────────────────────────┤    │
│  │ Register storage area (bytes 64–511)                         │    │
│  ├──────────────────────────────────────────────────────────────┤    │
│  │ Intercept message @ offset 512 (written on sync VP exit)     │    │
│  └──────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────┘
```

The earlier design proposed three new per-VP pages (message page, event flag
page, doorbell table) but this was superseded.  DomainComm already provides
the per-domain ring channel needed for doorbell notifications; no additional
shared pages are required.  VpCommPage handles the per-VP register sync and
synchronous intercept message delivery.

### 4.3 ThemIC Data Structures

```rust
// === DomainComm additions (themis-abi/src/domcomm.rs) ===
// Shared between capavisor, driver, and userspace.

// New message type on the DomainComm RX ring:
pub const MSG_DOORBELL_NOTIFY: u32 = 0x0007;

/// DOORBELL_NOTIFY payload (capavisor → domain, on the DomainComm RX ring).
/// Sent instead of stopping the child VP.
#[repr(C)]
pub struct DoorbellNotify {
    pub doorbell_id: u32,   // matches registered doorbell entry
    pub reserved: u32,
    pub gpa: u64,           // address that was written
    pub value: u64,         // data that was written
    pub size: u32,          // write size in bytes
    pub reserved2: u32,
}
```

```c
/* === Capavisor-internal (PlatformDomain, NOT a shared page) === */

#define THEMIC_MAX_DOORBELLS                    128
#define THEMIC_DOORBELL_FLAG_TRIGGER_ANY_VALUE  (1 << 0)
#define THEMIC_DOORBELL_FLAG_TRIGGER_SIZE_ANY   (1 << 1)
#define THEMIC_DOORBELL_FLAG_PIO                (1 << 2)  /* PIO (else MMIO) */

struct themic_doorbell_entry {
    __u64 gpa;         /* guest physical address to monitor */
    __u64 datamatch;   /* value to match (if not ANY_VALUE) */
    __u32 size;        /* access size (1/2/4/8) */
    __u32 flags;       /* THEMIC_DOORBELL_FLAG_* */
    __u32 doorbell_id; /* assigned at registration */
    __u32 reserved;
};
```

The VpCommPage intercept message (offset 512, written on synchronous VP exit
by `forward_child_exit`) is defined in `themis-abi/src/regs.rs` as
`InterceptMessage` / `ThemicMessageHeader`.  It is only used on the
synchronous `VMCALL_SWITCH` path and is not sent through DomainComm.

### 4.4 ThemIC Notification Protocol

ThemIC uses the existing **DomainComm RX ring + IPI** protocol rather than a
dedicated per-VP event flag page:

```
Producer (capavisor on any core):
  1. Write DoorbellNotify message to parent domain's DomainComm RX ring
  2. Send IPI at notify_vector (stored in DomainComm header) to parent core
     // fixed vector, NOT INIT; default 0xF0

Consumer (dom0 on target core):
  1. Receive IPI → IDT handler fires (vector = notify_vector)
  2. Drain DomainComm RX ring: dequeue pending messages
  3. For each DOORBELL_NOTIFY message:
     a. Extract doorbell_id, gpa, value, size
     b. Dispatch: signal eventfd, wake VMM thread, etc.
```

**The notify_vector IPI** is a dedicated fixed-vector interrupt that is **not
intercepted** by the capavisor for dom0.  Because dom0's VMCS has
`EXTERNAL_INTERRUPT_EXITING = 0`, the IPI is delivered directly to dom0's IDT
without a VMEXIT.  The mshv-themis.ko driver registers the handler for this
vector via `VMCALL_SET_THEMIC_VECTOR`.

This is architecturally identical to how MSHV uses `HYPERVISOR_CALLBACK_VECTOR`
— a fixed IDT vector is raised and the kernel ISR (`synic_isr`) drains the ring.
ThemIC replaces the SynIC SINT mechanism with the DomainComm RX ring.

**Key difference from the INIT IPI protocol**: The INIT IPI is reserved for the
capability engine's cross-core barrier protocol (EPT updates, revocation).  The
ThemIC notify IPI is a regular fixed-vector interrupt that does not trigger
barriers — it is a lightweight "you have mail" signal.

### 4.5 ThemIC Doorbell Fast-Path

The doorbell fast-path eliminates the full VMEXIT→userspace round-trip for
virtio kick notifications.  It mirrors MSHV's doorbell mechanism:

```
MSHV doorbell chain (for comparison):
  Guest writes doorbell GPA → Hypervisor recognizes doorbell →
  Write event to event_ring → Raise SINT[5] → ISR → RCU callback →
  eventfd_signal() → VMM wakes

ThemIC doorbell chain:
  Guest writes doorbell GPA → EPT violation VMEXIT → Capavisor:
    1. Look up GPA in child domain's capavisor-internal doorbell table
    2. If match:
       a. Write DoorbellNotify message to parent's DomainComm RX ring
       b. Send notify_vector IPI to parent's core
       c. Advance child's RIP past the write instruction
       d. VMRESUME child immediately (no parent involvement needed)
    3. If no match: full intercept path → forward_child_exit
```

**Critical property**: In the doorbell fast-path, the child VP is **not stopped**.
The capavisor handles the entire doorbell notification in the VMEXIT handler and
resumes the child.  This is what makes it fast — the child doesn't wait for the
parent to process the event.

### 4.6 COMM Capability Redesign — DONE

> **Status: COMPLETE (P11-comm-a through P11-comm-f all done).**
> This section is retained for historical context.

The COMM capability redesign was implemented to support **VpCommPage** — the
per-VP register snapshot page used by the synchronous `VMCALL_SWITCH` path.
The four changes made:

1. **COMM no longer implies VITAL** — `canonicalize()` sets `COMM | CLEAN`.
   Revoking a COMM page zeros memory but does not kill the owning domain.

2. **Multiple COMM per domain** — `Domain` carries `comm_bindings: Vec<CapabilityWeak<MemoryRegion>>`
   (child-side weak refs to parent COMM caps bound to this domain).

3. **Binding target on `register_comm`** — signature is now
   `register_comm(caller, handle, child_domain_handle, vp_id)`.
   `MemoryRegion` carries `comm_binding: Option<CommBinding>` where
   `CommBinding = { target_domain_id, vp_id }`.  Emits `CommRegion` update with
   target domain and VP ID so the platform can record `comm_hpas[vp_id]`.

4. **Auto-release on child revocation** — revocation iterates
   `child.comm_bindings`, clears COMM attribute + binding, emits `UncommRegion`.

**ThemIC notifications do NOT use per-VP COMM pages.**  Doorbell events flow
through the existing per-domain DomainComm RX ring, which is initialized at
domain creation and is entirely separate from COMM capabilities.  No per-VP
ThemIC message page or event flag page is allocated.

### 4.7 ThemIC Registration VMCALLs

ThemIC requires only doorbell-specific VMCALLs.  No new COMM pages are needed
since notifications flow through DomainComm.

```
VMCALL_REGISTER_DOORBELL(child_domain_handle, gpa, size, datamatch, flags)
  → doorbell_id
  Register a doorbell entry for a child domain.  The capavisor adds this
  to the child's capavisor-internal doorbell table (no shared page) and
  will fast-path matching EPT violations from that domain.

VMCALL_UNREGISTER_DOORBELL(child_domain_handle, doorbell_id)
  Remove a previously registered doorbell entry.

VMCALL_SET_THEMIC_VECTOR(vector)
  Write the capavisor-to-dom0 IPI vector into the caller's DomainComm
  header notify_vector field.  Called once during driver init.  Default: 0xF0.
```

The doorbell VMCALLs are platform-level (capavisor only), not capability engine
API.  The caller must hold a capability to the child domain (validated by the
capavisor before adding entries).

### 4.8 ThemIC vs SynIC Mapping

| SynIC concept | ThemIC equivalent | Notes |
|--------------|-------------------|-------|
| SIMP (message page, per-VP) | VpCommPage | Per-VP COMM cap; register sync + intercept message (sync path only) |
| SIEFP (event flag page) | DomainComm RX ring | Per-domain ring; no separate event flag page |
| SINT[0] (interception) | VpCommPage intercept msg @ offset 512 | Sync: written by `forward_child_exit`; parent reads after SWITCH returns |
| SINT[5] (doorbell) | DomainComm `DOORBELL_NOTIFY` message | Written to RX ring on doorbell EPT violation |
| Event ring | DomainComm RX ring | Per-domain, not per-VP |
| HYPERVISOR_CALLBACK_VECTOR | `notify_vector` in DomainComm header | Configured via `VMCALL_SET_THEMIC_VECTOR`; default 0xF0 |
| MSR-based SINT config | `VMCALL_REGISTER_DOORBELL` | Capability-gated, not MSR-based |
| Auto-EOI | x2APIC EOI in ISR | Standard EOI; no synthetic auto-EOI needed |
| SynIC enable (SCONTROL MSR) | DomainComm initialized at domain creation | Per-domain; always available |
| Doorbell port/connection | `VMCALL_REGISTER_DOORBELL` | Same concept: {GPA, data, size} → fast-path |

### 4.9 ThemIC in Synchronous vs Asynchronous Mode

**Synchronous mode** (current): ThemIC is **not used for VP intercepts**.
`VMCALL_SWITCH` blocks the dom0 VP and returns directly with exit reason in
registers; dom0 reads VpCommPage (offset 512) for the full intercept detail.
ThemIC **is** used for doorbells — the EPT violation fast-path writes a
`DOORBELL_NOTIFY` to the DomainComm RX ring and sends a `notify_vector` IPI,
allowing dom0 to process doorbell events asynchronously while the child
continues running.

**Asynchronous mode** (future): VP exits would also be routed through DomainComm
as `VP_EXIT` messages + `notify_vector` IPI, eliminating the synchronous SWITCH
block.  VpCommPage still holds the register snapshot.  The VP_EXIT message type
is already defined in `domcomm.rs` but `forward_child_exit` does not yet write to
the ring (it uses the synchronous SWITCH return path).

---

## 5. Architecture

### 5.1 Component Stack

```
┌──────────────────────────────────────────────────────┐
│  cloud-hypervisor (userspace VMM)                    │
│  ┌──────────────────────────────────────────────┐    │
│  │  hypervisor crate                             │    │
│  │  ┌──────────┐  ┌──────────┐  ┌────────────┐  │    │
│  │  │ KVM      │  │ MSHV     │  │ Themis     │  │    │
│  │  │ backend  │  │ backend  │  │ backend    │  │    │
│  │  └──────────┘  └──────────┘  └─────┬──────┘  │    │
│  └────────────────────────────────────┼──────────┘    │
│                                       │  ioctl(2)     │
├───────────────────────────────────────┼──────────────┤
│  Linux kernel (dom0)                  │              │
│  ┌────────────────────────────────────┴────────────┐ │
│  │  mshv-themis.ko                                 │ │
│  │  /dev/mshv  →  partition fd  →  vp fd           │ │
│  │                                                 │ │
│  │  Translates ioctls to Themis VMCALLs:           │ │
│  │  CREATE_PARTITION → VMCALL_CREATE_DOMAIN        │ │
│  │  SET_GUEST_MEMORY → VMCALL_CARVE + VMCALL_SEND  │ │
│  │  RUN_VP → VMCALL_SWITCH (sync) or IPI (async)   │ │
│  └─────────────────────────┬───────────────────────┘ │
│                             │  VMCALL                 │
├─────────────────────────────┼────────────────────────┤
│  Themis capavisor (VMX root mode)                    │
│  ┌──────────────────────────┴───────────────────┐    │
│  │  Capability Engine + Platform                 │    │
│  │  CDT enforcement, EPT management, IPI barrier │    │
│  └───────────────────────────────────────────────┘    │
│  Hardware: Intel VT-x + EPT + x2APIC                │
└──────────────────────────────────────────────────────┘
```

### 5.2 Cloud-Hypervisor Trait Hierarchy

Cloud-hypervisor abstracts backends via three traits:

```rust
// hypervisor/src/lib.rs
trait Hypervisor: Send + Sync {
    fn create_vm(&self) -> Result<Arc<dyn Vm>>;
    fn check_required_extensions(&self) -> Result<()>;
    // ...
}

trait Vm: Send + Sync {
    fn create_vcpu(&self, id: u8, vm_fd: Option<..>) -> Result<Arc<dyn Vcpu>>;
    fn set_user_memory_region(&self, region: MemoryRegion) -> Result<()>;
    fn create_irq_chip(&self) -> Result<()>;
    fn register_irqfd(&self, fd: &EventFd, gsi: u32) -> Result<()>;
    fn register_ioeventfd(&self, fd: &EventFd, addr: &IoEventAddress, ...) -> Result<()>;
    fn set_gsi_routing(&self, entries: &[IrqRoutingEntry]) -> Result<()>;
    fn get_dirty_log(&self, slot: u32, memory_size: u64) -> Result<Vec<u64>>;
    // ...
}

trait Vcpu: Send + Sync {
    fn run(&self) -> Result<VcpuExit>;
    fn set_regs(&self, regs: &StandardRegisters) -> Result<()>;
    fn get_regs(&self) -> Result<StandardRegisters>;
    fn set_sregs(&self, sregs: &SpecialRegisters) -> Result<()>;
    fn get_sregs(&self) -> Result<SpecialRegisters>;
    // ... (CPUID, MSRs, FPU, LAPIC, etc.)
}
```

The **Themis backend** plugs into this hierarchy using `/dev/mshv` ioctls from
mshv-themis.ko.  Because the ioctl ABI mirrors MSHV, much of the existing
`hypervisor/src/mshv/` code can be reused or forked.

---

## 6. Scheduling Models

### 6.1 Synchronous (Same-Core Domain Transition)

```
Core 0 (dom0)                         Core 0 (child)
─────────────                         ───────────────
CH: vcpu.run()
  → ioctl(RUN_VP)
    → mshv_themis_run_vp()
      → VMCALL_SWITCH(child, vp_id)
        ── VMEXIT to Themis ──
        Themis: save dom0 VMCS
                load child VMCS
                VMRESUME child
                                      child executes...
                                      I/O port access
                                      ── VMEXIT to Themis ──
        Themis: save child VMCS
                load dom0 VMCS
                write exit info
                VMRESUME dom0
      ← VMCALL returns (rax=exit_reason)
    → copy exit info to userspace
  ← ioctl returns
CH: handle VcpuExit::IoOut
```

**Properties:**
- Zero IPI overhead — pure VMCS swap on same core.
- dom0 VP is blocked for the duration of the child VP's execution quantum.
- 1:1 pinning: one dom0 thread per child VP, each pinned to a physical core.
- The capability engine's `switch()` validates hierarchy (child must be direct
  child of current domain) and core affinity (child's policy.cores must include
  this core).

**VP State Machine Transitions:**
```
dom0 VP: Running{core=0} → Locked{callee=child_vp}
child VP: Available → Running{core=0, caller=dom0_vp}
  [on exit]
child VP: Running → Available
dom0 VP: Locked → Running{core=0}
```

### 6.2 Asynchronous (Cross-Core Control)

In asynchronous mode, the child VP runs on a remote core (Core B) while the parent
dom0 controls it from its own core (Core A).  When the child VP exits, the capavisor
on Core B enqueues a ThemIC message and sends a **doorbell IPI** (fixed vector, not
INIT) to Core A.  The parent processes the message and decides whether to **resume**
the child on Core B or **recover** Core B for dom0.

```
Core A (dom0 / parent)                 Core B (child executor)
──────────────────────                 ────────────────────────

CH: vcpu.run()
  → ioctl(RUN_VP)
    → mshv_themis_run_vp_async()
      If child not yet launched:
        VMCALL_START_VP(child, vp, core=B)
                                       ── Capavisor (Core B) ──
                                       Load child VMCS
                                       VMRESUME → child runs
                                       ...
      wait_event(vp->exit_wq,
                 vp->exit_pending)
                                       Child: I/O port write
                                       ── VMEXIT to Capavisor (Core B) ──
                                       1. Save child VP state
                                       2. Build themic_intercept_message:
                                          exit_reason, port, rax, rip, ...
                                       3. Write to ThemIC message page
                                          slot[THEMIC_CHAN_INTERCEPT]
                                       4. Set event flag:
                                          flags[CHAN_INTERCEPT] |= 1
                                       5. Send doorbell IPI to Core A
                                          (x2APIC ICR, fixed vector 0xF0)
                                       6. Spin/park: wait for parent decision
                                          on resume_cmd atomic flag

  ── doorbell IPI arrives (vector 0xF0) ──
  dom0 IDT: themic_isr()
    1. Read event_flag_page.flags[]
    2. flags[CHAN_INTERCEPT] set →
       read message from slot[0]
    3. Clear flag
    4. kick_vp(vp): set exit_pending,
       wake_up(vp->exit_wq)

  VP thread wakes:
    copy exit info to userspace
  ← ioctl returns

CH: handle VcpuExit::IoOut
  emulate I/O port write
CH: vcpu.run()    (resume)
  → ioctl(RUN_VP)
    → VMCALL_RESUME_VP(child, vp)
                                       ── Capavisor (Core A) ──
                                       Send resume signal to Core B:
                                         resume_cmd[core_B] = RESUME
                                         doorbell IPI → Core B

                                       ── Capavisor (Core B) ──
                                       Read resume_cmd → RESUME
                                       Inject any pending interrupts
                                       VMRESUME child
                                       child continues execution...
```

**Recovery path** (parent wants to take over Core B):
```
CH: decides to stop the child (e.g., shutdown, error)
  → ioctl(STOP_VP) or close(vp_fd)
    → VMCALL_RECOVER_CORE(child, vp, core=B)
                                       ── Capavisor (Core B) ──
                                       Read resume_cmd → SWITCH_TO_PARENT
                                       Load dom0 VMCS on Core B
                                       VMRESUME dom0 on Core B
                                       (Core B now runs dom0)
```

**Properties:**
- Child VP runs independently; dom0 is not blocked during child execution.
- **Doorbell IPI** (fixed vector 0xF0), not INIT IPI — no barrier protocol overhead.
- Dom0 receives the IPI directly in its IDT (no VMEXIT), like MSHV's SynIC path.
- Parent decides per-exit: resume child or recover the core.
- Supports overcommit: multiple child VPs can time-share a core (capavisor queues
  start/stop requests).
- Core B is parked in VMX root mode (capavisor) between exit and resume decision.

**New VMCALLs for async mode:**
- `VMCALL_START_VP(domain, vp, target_core)` — launch VP on a remote core.
- `VMCALL_RESUME_VP(domain, vp)` — signal remote core to resume a stopped child VP.
- `VMCALL_RECOVER_CORE(domain, vp, core)` — switch remote core back to parent domain.
- `VMCALL_STOP_VP(domain, vp)` — request VP stop at next exit (no resume possible).

**Capavisor per-core async state:**
```rust
pub enum AsyncCoreState {
    Idle,                              // core available
    RunningChild {
        domain_id: DomainId,
        vp_id: u32,
    },
    ParkedWaitingDecision {            // child exited, waiting for parent
        domain_id: DomainId,
        vp_id: u32,
        resume_cmd: AtomicU32,         // 0=waiting, 1=resume, 2=switch_to_parent
    },
}
```

**Core B spin loop (capavisor, VMX root mode):**
```rust
fn async_park_loop(core_state: &AsyncCoreState) {
    // After writing ThemIC message + sending doorbell IPI:
    loop {
        let cmd = core_state.resume_cmd.load(Ordering::Acquire);
        match cmd {
            RESUME_CHILD => {
                // Inject pending interrupts, VMRESUME child
                break;
            }
            SWITCH_TO_PARENT => {
                // Load dom0 VMCS, VMRESUME dom0 on this core
                break;
            }
            WAITING => {
                // Also check for INIT IPI (capability engine barrier)
                // in case a concurrent revocation/update is happening
                if ipi_pending[self_core].load(Ordering::Acquire) {
                    poll_and_respond_cross_core();
                }
                core::hint::spin_loop();
            }
        }
    }
}
```

**Integration with capability engine barrier protocol:**
While Core B is parked waiting for the parent's decision, it must still respond to
INIT IPIs from the capability engine's cross-core barrier protocol (e.g., for EPT
updates during revocation).  The spin loop checks `ipi_pending` and calls
`poll_and_respond_cross_core()` as needed.  This ensures the async parking does not
deadlock the capability engine.

### 6.3 Scheduling Policy Selection

```c
struct mshv_create_partition {
    __u64 pt_flags;
    __u64 pt_isolation;
    /* Themis extension: */
    __u32 sched_policy;        // MSHV_THEMIS_SCHED_SYNC or MSHV_THEMIS_SCHED_ASYNC
    __u32 rsvd;
};
```

- `MSHV_THEMIS_SCHED_SYNC` (default): `RUN_VP` uses `VMCALL_SWITCH`.
- `MSHV_THEMIS_SCHED_ASYNC`: `RUN_VP` uses `VMCALL_START_VP` + waitqueue.

This is transparent to cloud-hypervisor — the CH backend just calls `vcpu.run()`.

---

## 7. IOCTL → VMCALL Translation Table

### 7.1 Device-Level IOCTLs

| MSHV ioctl | mshv-themis translation | Notes |
|-----------|------------------------|-------|
| `MSHV_CREATE_PARTITION` | `VMCALL_CREATE_DOMAIN` + store domain handle | Returns partition fd |
| `MSHV_CHECK_EXTENSION` | Feature flag lookup (static table) | |
| `MSHV_ROOT_HVCALL` | Reject or whitelist specific hypercalls | Security: no raw passthrough |

### 7.2 Partition-Level IOCTLs

| MSHV ioctl | mshv-themis translation | Notes |
|-----------|------------------------|-------|
| `MSHV_INITIALIZE_PARTITION` | `VMCALL_SEAL(domain_handle)` | Seals the domain (policy frozen) |
| `MSHV_CREATE_VP` | Allocate VP slot; VP count set at create time | VPs pre-allocated in capability engine |
| `MSHV_SET_GUEST_MEMORY` (map) | `VMCALL_CARVE(parent_mem, range)` + `VMCALL_SEND(carved_cap, child_domain)` | Capability transfer: parent carves memory region and sends to child |
| `MSHV_SET_GUEST_MEMORY` (unmap) | `VMCALL_REVOKE_MEM(cap_handle)` | Revokes the memory capability (and all descendants) |
| `MSHV_IRQFD` | Register eventfd → workqueue → `VMCALL_ASSERT_INTERRUPT` (or PI write) | Uses driver-side MSI routing table |
| `MSHV_IOEVENTFD` | `VMCALL_REGISTER_DOORBELL` → ThemIC doorbell fast-path | Capavisor handles; child resumes immediately |
| `MSHV_SET_MSI_ROUTING` | Build GSI → {vector, dest} table in driver | Pure driver-side; no VMCALL |
| `MSHV_GET_GPAP_ACCESS_BITMAP` | Walk EPT dirty bits or capability engine tracking | Phase 6+ |

### 7.3 VP-Level IOCTLs

| MSHV ioctl | mshv-themis translation | Notes |
|-----------|------------------------|-------|
| `MSHV_RUN_VP` | Sync: `VMCALL_SWITCH`. Async: `VMCALL_START_VP` + wait | Returns exit info |
| `MSHV_GET_VP_STATE` (registers) | `VMCALL_GET_REG(vp, reg_name)` or read META page | |
| `MSHV_SET_VP_STATE` (registers) | `VMCALL_SET_REG(vp, reg_name, value)` or write META page | |
| `MSHV_GET_VP_STATE` (LAPIC) | `VMCALL_GET_REG` for APIC state registers | |
| `MSHV_SET_VP_STATE` (XSAVE) | Bulk register transfer via META page | |
| `mmap(VP_MMAP_OFFSET_REGISTERS)` | Map META VP-state page into userspace | Phase 10 required |
| `mmap(VP_MMAP_OFFSET_INTERCEPT_MESSAGE)` | Map intercept message area of META page | |

### 7.4 Memory Mapping: Capability Flow

The most significant translation is `MSHV_SET_GUEST_MEMORY` → capability operations:

```
Userspace: mmap(size) → gets host VA (userspace_addr)
  → ioctl(MSHV_SET_GUEST_MEMORY, {guest_pfn, userspace_addr, size, flags})

Driver (mshv-themis.ko):
  1. Pin pages: pin_user_pages(userspace_addr, nr_pages)
  2. Get HPAs: page_to_phys(pages[i]) for each page
  3. Find dom0's memory capability covering these HPAs
     (dom0 owns all usable RAM via root capability)
  4. VMCALL_CARVE(dom0_mem_cap, hpa_start, size)
     → capability engine splits dom0's region
     → returns carved_cap_handle
  5. VMCALL_SEND(carved_cap_handle, child_domain, guest_pfn_offset)
     → capability engine grants region to child
     → UpdateBatch: ChangeRights removes from dom0 EPT,
                    ChangeRights adds to child EPT at guest_pfn
  6. Track {guest_pfn → carved_cap_handle} in driver for later unmap

Unmap:
  1. VMCALL_REVOKE_MEM(carved_cap_handle)
     → capability engine revokes + zeros (if CLEAN) + restores to dom0
  2. Unpin pages
```

**Important**: The capability engine enforces that dom0 can only carve from memory it
actually owns, and that the carved region's rights are ≤ the parent's.  This is the
key security advantage over MSHV's flat mapping model.

---

## 8. Interrupt Delivery & IRQ Router Integration

This section describes how cloud-hypervisor's interrupt routing abstractions map
to ThemIC and the mshv-themis driver.

### 8.1 MSHV IRQ Router (How It Works Today)

Cloud-hypervisor's interrupt path uses three layers:

```
Layer 1: VMM interrupt manager (vmm/src/interrupt.rs)
  Allocates GSIs (Global System Interrupts), creates eventfds, manages
  routing table entries.  Devices (virtio, VFIO) request GSIs and get
  back an InterruptGroup with eventfds to signal.

Layer 2: Hypervisor Vm trait (hypervisor/src/vm.rs)
  - register_irqfd(fd, gsi): Bind eventfd → GSI for in-kernel injection
  - set_gsi_routing(entries): Upload GSI → MSI routing table
  - register_ioevent(fd, addr): Bind eventfd → guest MMIO/PIO write

Layer 3: Kernel driver (mshv_eventfd.c)
  - IRQFD: eventfd wakeup → lookup GSI in MSI table → extract {vector,
    dest_apic} → hv_call_assert_virtual_interrupt(partition, vector, dest)
  - IOEventFd: register doorbell with hypervisor → guest writes doorbell
    GPA → event ring → ISR → callback → eventfd_signal()
```

The full IRQFD chain in MSHV:
```
Device emulation:  eventfd_signal(irq_fd)
  → Kernel: poll wakeup → mshv_irqfd_wakeup() [mshv_eventfd.c:293]
    → Schedule irqfd_inject work item
      → irqfd_inject() [mshv_eventfd.c:210]:
        Lock seqlock, read cached MSI entry for this GSI
        → hv_call_assert_virtual_interrupt(partition_id, vector, dest_vp)
          [mshv_root_hv_call.c: HVCALL_ASSERT_VIRTUAL_INTERRUPT]
        → Hypervisor injects interrupt into guest VP
```

The full IOEventFd/doorbell chain in MSHV:
```
Guest: writes to doorbell GPA (e.g., virtio kick register)
  → Hypervisor: recognizes registered doorbell
    → Writes event to per-CPU event ring [SINT 5]
    → Raises doorbell SINT interrupt
      → Linux ISR: mshv_root_isr() [mshv_synic.c:394]
        → Scans event ring for doorbell events
        → Calls registered callback: ioeventfd_mmio_write() [mshv_eventfd.c:631]
          → Finds matching ioeventfd entry by doorbell_id
          → eventfd_signal(fd)
            → VMM: virtio worker thread wakes, processes queue
```

### 8.2 ThemIC IRQ Router Mapping

The mshv-themis driver provides the same three interfaces to cloud-hypervisor
but translates them to ThemIC and Themis VMCALLs:

**IRQFD (VMM → Guest interrupt injection):**

```
Cloud-hypervisor: register_irqfd(fd, gsi)
  → ioctl(MSHV_IRQFD, {fd, gsi})

Driver (mshv-themis.ko):
  1. Create irqfd tracking entry: {fd, gsi, cached_msi}
  2. Register poll wakeup on eventfd

On eventfd signal:
  irqfd_wakeup():
    1. Read GSI → MSI routing entry: {address_lo, address_hi, data}
    2. Extract vector = data & 0xFF
    3. Extract dest_apic = (address_lo >> 12) & 0xFF

    Sync mode:
      Store pending interrupt in driver; will be injected on next RUN_VP.
      (Child VP is not running between RUN_VP calls.)

    Async mode (child VP running on remote core):
      VMCALL_INJECT_INTERRUPT(domain, vp, vector, dest_apic)
      → Capavisor on initiating core:
        a. Write to child VP's posted-interrupt descriptor (PI desc)
           or set pending interrupt in child's VMCS interrupt-window
        b. Send notification IPI to child's core (fixed vector for PI,
           or INIT for full preemption)
      → Child's core:
        If posted interrupts enabled: hardware injects automatically
        Else: VMEXIT → inject interrupt → VMRESUME
```

**IOEventFd (Guest → VMM doorbell notification):**

```
Cloud-hypervisor: register_ioevent(fd, addr, datamatch)
  → ioctl(MSHV_IOEVENTFD, {fd, addr, len, datamatch, flags})

Driver (mshv-themis.ko):
  1. VMCALL_REGISTER_DOORBELL(domain, vp, addr, len, datamatch, flags)
     → Returns doorbell_id
  2. Store {doorbell_id → eventfd} mapping in driver

Guest writes doorbell GPA:
  → EPT violation VMEXIT on child's core
  → Capavisor: lookup GPA in child's doorbell table
  → Match found → doorbell fast-path:
    1. Write themic_doorbell_message to ThemIC message page
    2. Set event flag for CHAN_DOORBELL
    3. Send doorbell IPI (vector 0xF0) to parent's core
    4. Advance child RIP, VMRESUME child immediately

  → Parent core (dom0): receives doorbell IPI
    themic_isr():
      1. Read event flags → CHAN_DOORBELL pending
      2. Read doorbell message → doorbell_id
      3. Lookup doorbell_id → eventfd
      4. eventfd_signal(fd)
      → VMM: virtio worker thread wakes
```

**GSI Routing Table:**

```
Cloud-hypervisor: set_gsi_routing(entries)
  → ioctl(MSHV_SET_MSI_ROUTING, {nr, entries[]})

Driver (mshv-themis.ko):
  1. Store routing table in driver (same as MSHV)
  2. IRQFD wakeup handler uses this table for vector/dest lookup
  3. No VMCALL needed — routing is purely a driver-side table
```

### 8.3 Interrupt Injection Paths (Summary)

| Path | Trigger | ThemIC channel | Child VP state |
|------|---------|---------------|----------------|
| IRQFD (sync) | eventfd signal | N/A (stored in driver) | Stopped; injected on next RUN_VP |
| IRQFD (async) | eventfd signal | N/A (direct VMCALL) | Running; PI desc or IPI |
| IOEventFd | Guest writes doorbell GPA | THEMIC_CHAN_DOORBELL | Running; child resumes immediately |
| VP exit (sync) | Child hits I/O/MMIO/HLT | N/A (VMCALL_SWITCH returns) | Stopped |
| VP exit (async) | Child hits I/O/MMIO/HLT | THEMIC_CHAN_INTERCEPT | Parked on remote core |

### 8.4 IOEventFd: ThemIC Doorbell vs Full Exit

The doorbell fast-path is critical for virtio performance.  Without it, every
virtio kick (guest writes to MMIO notification register) would require a full
exit → parent processes → resume cycle.  With ThemIC doorbells:

1. The capavisor handles the entire notification in ~100 cycles (lookup + message
   write + IPI + RIP advance).
2. The child VP resumes immediately — it doesn't wait for the parent.
3. The parent processes the doorbell asynchronously (signals eventfd, wakes VMM
   worker thread).

This is the same optimization that MSHV's doorbell mechanism provides, and it is
essential for achieving competitive virtio throughput.

### 8.5 Interrupt Exiting (Guest → VMM)

When a guest VP takes an external hardware interrupt:

**Synchronous mode:**
- Themis's interrupt policy (`InterruptVisibility::Deliver`) routes it to the parent.
- The `VMCALL_SWITCH` return includes the interrupt vector as part of the exit info.
- The driver translates it to an `HVMSG_X64_INTERRUPT_INTERCEPT` message.

**Asynchronous mode:**
- The interrupt causes a VMEXIT on the child's core.
- The capavisor writes a `themic_intercept_message` with the interrupt vector.
- Doorbell IPI to parent's core → ThemIC ISR → wake VP thread → userspace exit.

---

## 9. VP State & Exit Information

### 9.1 Exit Reason Encoding

The driver must translate Themis VMEXIT reasons to MSHV-compatible intercept messages.
Cloud-hypervisor expects `hv_message` format in the `mshv_run_vp.msg_buf`.

```c
/* Themis exit reasons (from vmexit.rs) mapped to MSHV message types: */
struct themis_exit_to_mshv {
    /* VMX exit reason         → MSHV message type */
    EXIT_REASON_HLT            → HVMSG_X64_HALT_INTERCEPT
    EXIT_REASON_IO_INSTRUCTION → HVMSG_X64_IO_PORT_INTERCEPT
    EXIT_REASON_EPT_VIOLATION  → HVMSG_GPA_INTERCEPT (MMIO)
    EXIT_REASON_CPUID          → HVMSG_X64_CPUID_INTERCEPT
    EXIT_REASON_MSR_READ/WRITE → HVMSG_X64_MSR_INTERCEPT
    EXIT_REASON_TRIPLE_FAULT   → HVMSG_X64_EXCEPTION_INTERCEPT
    EXIT_REASON_SHUTDOWN       → HVMSG_X64_HALT_INTERCEPT (shutdown)
    EXIT_REASON_EXTERNAL_INT   → (re-inject or route via policy)
    EXIT_REASON_PREEMPT_TIMER  → (internal: yield / heartbeat)
};
```

### 9.2 META VP-State Page Layout (Phase 10)

```
Offset  Size  Field
──────  ────  ─────
0x000   8     rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi (64 bytes)
0x040   8     r8–r15 (64 bytes)
0x080   8     rip
0x088   8     rflags
0x090   8     cr0, cr3, cr4, efer (32 bytes)
0x0B0   4     exit_reason (VMX exit reason)
0x0B4   8     exit_qualification
0x0BC   8     guest_physical_address (for EPT violations)
0x0C4   4     instruction_length
0x0C8   8     instruction_info
0x0D0   8     dirty bitmask (atomic: which fields changed)
0x0D8   64    pi_desc: PostedInterruptDescriptor (64B-aligned)
0x118   4     interrupt_pending (for doorbell/notification)
0x11C   4     exit_pending (atomic flag for async mode)
0x120   -     reserved / future fields
```

Without Phase 10, the driver falls back to `VMCALL_GET_REG` / `VMCALL_SET_REG` for
individual register access (slower but functional).

---

## 10. CPUID Hypervisor Identification

To allow dom0 to detect Themis, the capavisor intercepts CPUID leaves
`0x40000000`–`0x40000005`:

```
Leaf 0x40000000:
  EAX = 0x40000005  (max leaf)
  EBX:ECX:EDX = "ThemisCapa"  (vendor string, 12 bytes)

Leaf 0x40000001:
  EAX = version (major.minor)
  EBX = features bitmap:
    bit 0: sync scheduling supported
    bit 1: async scheduling supported
    bit 2: META VP-state pages available
    bit 3: ThemIC (event flags + doorbell) available
    bit 4: device assignment (VT-d) available

Leaf 0x40000003:
  EAX = max VPs per partition
  EBX = max partitions
  ECX = max memory regions
```

The driver checks `0x40000000` on module load (`cpuid("ThemisCapa")`) to confirm it
is running under Themis.

---

## 11. Driver Internal Data Structures

```c
/* Per-partition state */
struct mshv_themis_partition {
    u64 domain_handle;              /* Capability handle from CREATE_DOMAIN */
    u64 domain_id;                  /* DomainId from capability engine */
    u32 sched_policy;               /* SYNC or ASYNC */
    u32 num_vps;
    struct mshv_themis_vp *vps;     /* VP array */

    /* Memory capability tracking */
    struct {
        spinlock_t lock;
        struct rb_root regions;     /* guest_pfn → mem_cap_handle */
    } mem;

    /* Interrupt routing (GSI → MSI table, driver-side) */
    struct {
        struct mutex lock;
        struct mshv_user_irq_entry *table;
        u32 nr_entries;
        seqlock_t seq;              /* Protects routing lookups in IRQ context */
    } msi_routing;

    /* IRQfd tracking */
    struct list_head irqfds;
    struct mutex irqfd_lock;

    /* IOEventFd / doorbell tracking */
    struct {
        struct list_head list;
        struct mutex lock;
        /* doorbell_id → {eventfd, gpa, datamatch} */
    } ioeventfds;

    struct file *file;
    struct kref refcount;
};

/* Per-VP state */
struct mshv_themis_vp {
    u32 vp_index;
    struct mshv_themis_partition *partition;
    struct mutex run_lock;          /* Serialise RUN_VP calls */

    /* ThemIC pages (capability-backed META memory) */
    struct {
        struct themic_message_page *msg_page;     /* capavisor-shared */
        struct themic_event_flag_page *flag_page; /* capavisor-shared */
        u64 msg_page_hpa;
        u64 flag_page_hpa;
    } themic;

    /* Sync mode: no extra state; VMCALL_SWITCH blocks */

    /* Async mode: */
    wait_queue_head_t exit_wq;      /* Woken by ThemIC ISR */
    atomic_t exit_pending;          /* Set by themic_isr on CHAN_INTERCEPT */

    /* META VP-state page (Phase 10, optional) */
    u64 meta_page_hpa;
    void *meta_page_va;            /* Kernel mapping of META page */

    /* Exit info buffer (for userspace copy) */
    struct {
        u8 msg_buf[256];            /* MSHV_RUN_VP_BUF_SZ */
    } exit;

    struct file *file;
};

/* Memory region tracking */
struct mshv_themis_mem_region {
    struct rb_node node;
    u64 guest_pfn;                  /* GPA >> 12 */
    u64 nr_pages;
    u64 userspace_addr;
    u64 cap_handle;                 /* Capability handle from CARVE */
    struct page **pages;            /* Pinned pages */
    u8 flags;
};
```

---

## 12. Implementation Plan

### Phase 15a — CPUID Hypervisor Leaf

**Capavisor change** (themis/capavisor/src/vmexit.rs):
- Intercept CPUID `0x40000000`–`0x40000005` in the VMEXIT handler.
- Return Themis vendor string and feature flags.
- No capability engine changes needed.

**Depends on**: existing CPUID intercept infrastructure.

### Phase 15b — Character Device & Module Init

**New file**: `drivers/hv/mshv_themis.c` (or as out-of-tree module in `themis/driver/`)

- Module init: `cpuid(0x40000000)` → verify "ThemisCapa".
- Register `/dev/mshv` character device with `file_operations`.
- `open()` → allocate device context.
- `release()` → cleanup.
- `unlocked_ioctl()` → dispatch to device/partition/VP handlers.
- **ThemIC vector setup**:
  1. `VMCALL_SET_THEMIC_VECTOR(THEMIC_VECTOR)` to tell capavisor which IDT vector
     to use for doorbell IPIs.
  2. Register IDT handler for `THEMIC_VECTOR` (e.g., 0xF0) via `alloc_intr_gate()`
     or a hypervisor callback mechanism.
  3. The ISR (`themic_isr`) scans event flag pages for all active VPs, dispatches
     pending messages, and calls `kick_vp()` to wake sleeping VP threads.

**Depends on**: Phase 15a.

### Phase 15c — Partition Lifecycle (CREATE / DELETE)

- `MSHV_CREATE_PARTITION`:
  1. Parse `mshv_create_partition` struct (flags, isolation, sched_policy).
  2. `VMCALL_CREATE_DOMAIN(num_vps, cores_bitmap, api_flags)`.
  3. Store domain handle in `mshv_themis_partition`.
  4. Return partition fd (`anon_inode_getfile`).

- `MSHV_INITIALIZE_PARTITION`:
  1. `VMCALL_SEAL(domain_handle)`.
  2. Mark partition as sealed.

- Partition fd release:
  1. `VMCALL_REVOKE_DOMAIN(domain_handle)`.
  2. Unpin all memory, cleanup.

**Depends on**: Phase 15b, capavisor P9a (CREATE_DOMAIN).

### Phase 15d — VP Management (CREATE / GET / SET State)

- `MSHV_CREATE_VP`:
  1. Validate vp_index < num_vps.
  2. Allocate ThemIC pages for this VP from dom0 memory:
     a. Allocate pages (message page, event flag page).
     b. `VMCALL_REGISTER_COMM(msg_page_handle, child_domain_handle, vp_id)`.
     c. `VMCALL_REGISTER_COMM(flag_page_handle, child_domain_handle, vp_id)`.
     d. Map pages into kernel VA for ISR access.
  3. Initialise `exit_wq`, `exit_pending` for async mode.
  4. Return vp fd.

- `MSHV_GET_VP_STATE` / `MSHV_SET_VP_STATE`:
  1. If META page available: read/write directly.
  2. Else: `VMCALL_GET_REG(domain, vp, reg_name)` / `VMCALL_SET_REG(...)`.
  3. Handle bulk register transfers (LAPIC state, XSAVE).

- VP fd `mmap()`:
  1. If Phase 10 (META pages): map META page into userspace via `remap_pfn_range`.
  2. Else: allocate kernel page, populate on demand.

**Depends on**: Phase 15c, capavisor P10 (META pages, optional).

### Phase 15e — Memory Mapping

- `MSHV_SET_GUEST_MEMORY` (map):
  1. `pin_user_pages()` to get HPAs.
  2. Locate dom0's memory capability for these HPAs.
  3. `VMCALL_CARVE(dom0_cap, hpa_range)` → `carved_handle`.
  4. `VMCALL_SEND(carved_handle, child_domain, attributes)` → child gets memory.
  5. Track in rb-tree: `{guest_pfn → carved_handle, pages}`.

- `MSHV_SET_GUEST_MEMORY` (unmap):
  1. Lookup carved_handle by guest_pfn.
  2. `VMCALL_REVOKE_MEM(carved_handle)`.
  3. `unpin_user_pages()`.
  4. Remove from rb-tree.

**Design note**: The capability model requires that dom0 tracks which of its own
memory capabilities cover the HPAs being mapped.  The driver maintains a sorted
list of dom0's memory capabilities (initialised from the capability tree at module
load) and performs range lookups to find the covering capability for each CARVE.

**Depends on**: Phase 15c, capavisor P9b (CARVE+SEND for child domains).

### Phase 15f — VP Execution (RUN_VP)

**Synchronous mode:**
1. Acquire `vp->run_lock`.
2. Flush any pending register writes (SET_VP_STATE) to META page or via VMCALL.
3. `VMCALL_SWITCH(child_domain, vp_index)`.
   - Blocks: Themis swaps VMCS, runs child, returns on exit.
4. Read exit reason from VMCALL return registers (rax = exit_reason, rdi/rsi/rdx = details).
5. Translate to `hv_message` format.
6. `copy_to_user(ret_msg, &vp->exit.msg_buf, sizeof(hv_message))`.

**Asynchronous mode:**
1. Acquire `vp->run_lock`.
2. If child VP not running: `VMCALL_START_VP(child_domain, vp_index, target_core)`.
3. If resuming: `VMCALL_RESUME_VP(child_domain, vp_index)`.
4. `wait_event_interruptible(vp->exit_wq, atomic_read(&vp->exit_pending))`.
5. On wake (ThemIC ISR set `exit_pending`): read exit info from ThemIC message page
   `vp->themic.msg_page->slots[THEMIC_CHAN_INTERCEPT]`.
6. `atomic_set(&vp->exit_pending, 0)`.
7. Translate `themic_intercept_message` → `hv_message` format + copy to userspace.

**Signal handling**: if interrupted by a signal during wait, request VP stop
(`VMCALL_STOP_VP`) and return `-EINTR`.

**Depends on**: Phase 15d, capavisor SWITCH (P9c) or START_VP (new).

### Phase 15g — Interrupt Injection

- `MSHV_IRQFD`:
  1. Create `eventfd_ctx` + irqfd tracking entry.
  2. Register `poll` callback on the eventfd.
  3. On eventfd signal: lookup MSI routing → extract vector + destination.
  4. `VMCALL_ASSERT_INTERRUPT(domain, vp_index, vector)`.
  5. If async mode and VP running: IPI to child's core to trigger VMEXIT for
     interrupt window injection.

- `MSHV_ASSERT_INTERRUPT` (direct):
  1. `VMCALL_ASSERT_INTERRUPT(domain, vp_index, vector)`.

- Posted interrupts (Phase 10+):
  1. Write directly to PI descriptor in META page.
  2. Send notification vector IPI to child's core.
  3. Hardware injects interrupt without VMEXIT (best performance).

**Depends on**: Phase 15f, capavisor interrupt injection.

### Phase 15h — IOEventFd / ThemIC Doorbell Integration

1. On `MSHV_IOEVENTFD` ioctl:
   a. `VMCALL_REGISTER_DOORBELL(domain, vp, addr, len, datamatch, flags)` → doorbell_id.
   b. Store `{doorbell_id → eventfd}` mapping in partition's ioeventfd list.

2. Capavisor doorbell fast-path (see §4.5):
   Guest writes doorbell GPA → capavisor matches → ThemIC message + IPI →
   dom0 ThemIC ISR → lookup doorbell_id → `eventfd_signal()`.
   Child VP resumes immediately (no userspace round-trip).

3. On `MSHV_IOEVENTFD` deassign:
   a. `VMCALL_UNREGISTER_DOORBELL(domain, vp, doorbell_id)`.
   b. Remove from ioeventfd list.

4. Fallback for unregistered addresses: full intercept path in RUN_VP exit handling —
   check if address matches any registered ioeventfd, signal eventfd, advance RIP,
   resume VP (no userspace return).

**Depends on**: Phase 15f, capavisor ThemIC doorbell registration (P11b).

### Phase 15i — Device Assignment

- `MSHV_ASSIGN_DEVICE`:
  1. `VMCALL_ASSIGN_DEVICE(domain, pci_bdf)`.
  2. Themis configures VT-d IOMMU for device isolation.

**Depends on**: capavisor Phase 4 (VT-d IOMMU).

---

## 13. Cloud-Hypervisor Themis Backend (Phase 16)

### 13.1 Module Structure

```
hypervisor/src/
├── lib.rs          (Hypervisor, Vm, Vcpu traits)
├── kvm/            (existing KVM backend)
├── mshv/           (existing MSHV backend)
└── themis/         (new Themis backend)
    ├── mod.rs      (ThemisHypervisor)
    ├── vm.rs       (ThemisVm)
    └── vcpu.rs     (ThemisVcpu)
```

### 13.2 Strategy: Fork MSHV Backend

Because the ioctl ABI is intentionally compatible, the Themis backend starts as a
fork of `hypervisor/src/mshv/` with these changes:

1. **Detection**: `ThemisHypervisor::new()` opens `/dev/mshv` and calls
   `cpuid(0x40000000)` to verify "ThemisCapa" vendor string.

2. **Partition creation**: pass `sched_policy` extension in `mshv_create_partition`.

3. **SynIC → ThemIC**: strip SynIC initialisation code (Themis uses ThemIC instead).
   The existing MSHV backend calls `MSHV_ENABLE_PARTITION_VTL` and sets up SynIC
   pages — these are replaced with ThemIC page registration (`register_comm` bindings)
   and doorbell setup.  The `enable_hyperv_synic()` method becomes a no-op.

4. **Exit handling**: map Themis exit reasons to `VcpuExit` enum.  Most mappings
   are identical (HLT, I/O, MMIO, CPUID, MSR, shutdown).

5. **Memory mapping**: identical ioctl interface; the driver handles capability
   translation transparently.

6. **Interrupt injection**: identical IRQFD/IOEventFd interface.

### 13.3 What Can Be Reused Unchanged

| Component | Reusable? | Notes |
|-----------|-----------|-------|
| `GuestMemoryMmap` setup | ✅ Yes | Standard memory region management |
| Virtio device backends | ✅ Yes | Guest-kernel ↔ VMM, hypervisor-independent |
| Serial console | ✅ Yes | I/O port emulation in VMM |
| Direct kernel boot | ✅ Mostly | VP register setup may differ slightly |
| IRQFD / IOEventFd | ✅ Yes | Same ioctl interface |
| Dirty page tracking | ⚠️ Partial | Different capability-based tracking |
| CPUID filtering | ⚠️ Partial | Some leaves Themis-specific |
| PCI passthrough | ⚠️ Partial | VT-d path differs |
| Live migration | ❌ Later | Needs capability state serialisation |

---

## 14. Phased Delivery & Dependencies

```
                    ┌─────────────────┐
                    │  P15a: CPUID    │
                    │  (capavisor)    │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  P15b: /dev/mshv│
                    │  char device    │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
     ┌────────▼──────┐ ┌────▼─────┐ ┌──────▼───────┐
     │ P15c: Partition│ │P15d: VP  │ │ P15e: Memory │
     │ CREATE/DELETE  │ │GET/SET   │ │ MAP/UNMAP    │
     └────────┬──────┘ └────┬─────┘ └──────┬───────┘
              │              │              │
              └──────────────┼──────────────┘
                             │
                    ┌────────▼────────┐
                    │  P15f: RUN_VP   │
                    │  (sync + async) │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
     ┌────────▼──────┐ ┌────▼─────┐ ┌──────▼───────┐
     │ P15g: IRQFD   │ │P15h:     │ │ P15i: Device │
     │ Interrupts    │ │IOEventFd │ │ Assignment   │
     └───────────────┘ └──────────┘ └──────────────┘
              │              │
              └──────┬───────┘
                     │
            ┌────────▼────────┐
            │  P16: Cloud-    │
            │  Hypervisor     │
            │  Themis backend │
            └─────────────────┘

Capavisor dependencies:
  P15c depends on: P9a (CREATE_DOMAIN), P9c (SEAL)
  P15d depends on: COMM redesign (register_comm with child binding)
  P15e depends on: P9b (CARVE+SEND to child)
  P15f (sync) depends on: P9c (SWITCH)
  P15f (async) depends on: ThemIC (COMM pages + doorbell IPI), START_VP/RESUME_VP VMCALLs
  P15g depends on: interrupt injection VMCALLs
  P15h depends on: VMCALL_REGISTER_DOORBELL (capavisor doorbell table)
  P15i depends on: P4 (VT-d IOMMU)

Parallel work:
  P15b (driver skeleton) can start NOW — no capavisor dependency.
  P16 (CH backend) can start NOW — stub missing ioctls with -ENOSYS.
  COMM redesign can start NOW — small change to capability engine.
  P10 (META pages) is nice-to-have; driver falls back to VMCALL_GET/SET_REG.
  P15f sync mode can work WITHOUT ThemIC (VMCALL_SWITCH returns exit info directly).
```

---

## 15. Open Design Questions

1. **dom0 memory capability discovery**: How does the driver discover dom0's
   memory capabilities at load time?  Options:
   - (a) Themis provides a `VMCALL_ENUMERATE_MEMORY` that returns the list.
   - (b) The driver reads the capability tree via a series of `VMCALL_GET_*` calls.
   - (c) Themis maps a read-only "capability table" page into dom0 at boot.

2. **GPA ≠ HPA mapping**: MSHV uses `guest_pfn` to specify the GPA where memory
   appears in the guest.  Themis capabilities use HPA ranges.  The SEND operation
   needs a target GPA offset — should this be:
   - (a) A new VMCALL parameter: `VMCALL_SEND_AT(cap, domain, target_gpa)`.
   - (b) Use the existing address translation module (`translation.rs`).
   - (c) Encode in the CARVE operation (carve specifies GPA layout).

3. **Async mode: who runs the idle loop on the child's core?**
   - (a) Themis runs a stub idle domain (current design: `IDLE_DOMAIN`).
   - (b) The child's core runs a thin Themis-managed scheduler loop.
   - (c) The core halts (MWAIT) and is woken by IPI when a VP needs to run.

4. **Multiple children per partition fd**: MSHV has one partition = one VM.
   Should mshv-themis support creating nested children from a partition?
   - Recommendation: No. One partition fd = one child domain.  Nesting is done
     by the child domain loading its own mshv-themis.ko.

5. **Dirty page tracking**: The capability engine tracks access via EPT A/D bits.
   Should the driver expose this via `MSHV_GET_GPAP_ACCESS_BITMAP` or a
   capability-native API?
   - Recommendation: Support the MSHV ioctl for CH compatibility; implement via
     EPT A/D bit scanning in the capavisor.

---

## 16. Security Considerations

1. **No raw hypercall passthrough**: `MSHV_ROOT_HVCALL` must be rejected or
   heavily filtered.  Allowing arbitrary hypercalls would bypass capability
   enforcement.

2. **Capability handle isolation**: partition fds must not leak capability handles
   across partitions.  Each partition fd has its own handle namespace.

3. **Memory safety**: `pin_user_pages` + `VMCALL_CARVE` must be atomic with
   respect to page migration.  Use MMU notifiers or pin-only mode.

4. **VP execution isolation**: in async mode, the driver must ensure that only
   the controlling dom0 thread can read/write the child VP's state.  The
   `run_lock` mutex serialises this.

5. **Revocation cascade**: when a partition fd is closed (or process exits),
   `VMCALL_REVOKE_DOMAIN` must transitively revoke all memory capabilities
   and stop all VPs.  This is guaranteed by the capability engine's P5 property
   (revocation completeness).

---

## 17. Testing Strategy

1. **Unit tests** (driver):
   - CPUID detection (mock `cpuid` instruction).
   - Partition create/delete lifecycle.
   - Memory map/unmap with capability tracking.
   - VP state get/set round-trip.

2. **Integration tests** (driver + capavisor):
   - Create partition → create VP → set registers → run VP → handle HLT exit.
   - Map memory → guest reads/writes → verify EPT mapping.
   - IRQFD → inject interrupt → guest receives.
   - IOEventFd → guest writes I/O port → VMM notified.

3. **End-to-end** (cloud-hypervisor + driver + capavisor):
   - Boot Linux guest with virtio-blk root disk.
   - Serial console I/O.
   - SSH into guest.
   - Sync vs async mode comparison.

4. **Security tests**:
   - Verify raw hypercall passthrough is rejected.
   - Verify partition A cannot access partition B's memory.
   - Verify revocation zeros memory (CLEAN attribute).
   - Verify capability rights monotonicity (child ≤ parent).

---

## 18. Future Work: Monitor-Provided Hypercall Library

### Motivation

The mshv-themis kernel driver needs to issue VMCALLs to the capavisor for all
capability operations (create domain, carve, alias, send, etc.).  These wrappers
already exist in `libthemis` (a no\_std Rust crate).  Maintaining a second
implementation in the kernel driver — whether in C inline assembly or via FFI —
creates a versioning coupling: the driver must be compiled against the same ABI
version as the running capavisor.

### Proposal: COMM-Injected Hypercall Stubs

Use the COMM page mechanism to have the capavisor provide a pre-compiled
hypercall stub library to the parent domain at runtime:

1. **Parent registers a COMM page** with the capavisor (via `register_comm`),
   bound to a well-known VP slot reserved for this purpose.

2. **Capavisor writes libthemis code** into the COMM page.  Since the monitor
   has write access to COMM pages, it can populate the page with a
   position-independent flat binary containing the VMCALL wrappers.

3. **Parent maps the page executable** and calls into it at known offsets.
   A function table at offset 0 provides entry points for each operation
   (create\_domain, carve, alias, send, etc.).

4. **Version match is guaranteed**: the capavisor always provides stubs matching
   its own ABI — no compile-time coupling between driver and capavisor.

### Design Considerations

- **Position-independent code**: libthemis must be compiled as a flat PIC binary
  (e.g., `cargo rustc --crate-type=cdylib` with a custom linker script) so it
  can be loaded at any GPA chosen by the parent.

- **Function discovery**: the first bytes of the page should contain a jump table
  or function descriptor array at well-known offsets, keyed by opcode.  Example
  layout:

  ```
  Offset 0x000: magic (u64)       — identifies the page as a Themis stub library
  Offset 0x008: version (u64)     — ABI version
  Offset 0x010: entry[0] (u64)    — offset to carve()
  Offset 0x018: entry[1] (u64)    — offset to alias()
  ...
  Offset 0x100: <code begins>
  ```

- **Size**: libthemis functions are thin wrappers (~20 instructions each).  The
  entire library should fit in 1–2 pages.  If it exceeds one page, the parent
  registers a contiguous COMM region.

- **Trust model**: the parent already trusts the capavisor (it is the TCB).
  Executing capavisor-provided code is no different from executing a VMCALL
  instruction that traps into the capavisor.

- **COMM semantics**: COMM pages are currently designed for data buffers (message
  slots, event flags).  Using them for executable code is a semantic stretch.
  An alternative is a dedicated `VMCALL_MAP_HYPERCALL_PAGE` that maps a
  capavisor-owned read-only+execute page into the caller's address space,
  similar to Hyper-V's hypercall page mechanism.

### Alternative Approaches

Before implementing the COMM-injection approach, simpler alternatives should be
evaluated:

1. **Rust kernel module**: write mshv-themis in Rust (Linux ≥ 6.1) and depend
   on `libthemis` directly as a crate.  Zero duplication, compile-time ABI match.

2. **FFI static library**: add `#[no_mangle] pub extern "C"` wrappers to
   libthemis, compile as `libthemis.a`, link into the C kernel module.  Same
   build tree ensures version match.

3. **Hyper-V-style hypercall page**: capavisor maps a single read-only page
   (discovered via CPUID) containing `mov rax, OPCODE; vmcall; ret` stubs.
   Simpler than full libthemis but still capavisor-provided.

4. **Generated C header**: auto-generate a C header from `themis-abi` constants
   at build time.  The inline assembly is trivial (~5 lines) and stable; only
   opcode numbers need updating.

### Status

**Deferred** — explore in Phase 18 after the core driver (Phase 15) and
cloud-hypervisor backend (Phase 16) are functional.
