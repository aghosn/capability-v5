# Core-Gapping & Root Scheduler — Design Document

## 1. Problem Statement

Today Themis uses **synchronous same-core scheduling** (`THHV_SCHED_SYNC`):
dom0 VP on core A calls `VMCALL_SWITCH`, which parks the dom0 VMCS and loads
the child VMCS on the **same core**.  On child exit, the capavisor swaps back
to dom0 on the same core and returns the exit reason in registers.

This model is simple and low-latency but has fundamental limitations:

1. **Core monopolisation**: while the child runs, dom0 cannot use that core.
   The dom0 VMM thread (cloud-hypervisor) is blocked in the kernel, consuming
   a whole physical core even when the child is doing I/O waits.

2. **TLB flush coupling**: any EPT update (memory revocation, new mapping)
   requires a TLB shootdown IPI to the core running the child, which means
   a VMEXIT + barrier + VMRESUME cycle.  In the sync model this is unavoidable
   since the child is pinned to the calling core.

3. **Overcommit impossible**: you cannot run more child VPs than physical cores.
   Multi-tenant scenarios (e.g., many small VMs on a few cores) don't work.

4. **Interrupt overhead**: dom0 timer and device interrupts cause VMEXITs on
   the core running the child, requiring the full interrupt-forward pipeline
   even for interrupts that are irrelevant to the child.

### Goal

Implement **core-gapping**: the ability to run a child domain's VP on a
**different physical core** from its parent (dom0), and route events and
interrupts back to the parent core via shared-memory pages (meta page /
VpCommPage) and a SynIC-inspired notification mechanism, avoiding TLB flushes
and VMEXITs on the child core for parent-directed events.

---

## 2. Architecture Overview

```
Core A (dom0)                          Core B (child)
─────────────                          ──────────────
dom0 VP runs normally                  child VP runs independently
  │                                      │
  │  ← doorbell IPI (vector 0xF0) ──────┤ child exits (I/O, MMIO, etc.)
  │                                      │ capavisor writes exit info
  │  read VpCommPage / DomainComm        │   to shared page
  │  handle exit in userspace (CHV)      │ capavisor parks core B
  │                                      │   (spin-wait for resume cmd)
  │  write resume decision ──────────→   │
  │  send resume IPI ───────────────→    │ capavisor reads cmd
  │                                      │ VMRESUME child
  ▼                                      ▼
```

**Key insight**: the child core never needs to know about dom0's interrupts
or EPT state.  Events flow **unidirectionally** from child→parent (exit
notifications) and parent→child (resume/stop commands).  The meta page acts
as the data plane; IPIs act as the signal plane.

---

## 3. Scheduling Modes

### 3.1 Sync Mode (current — `THHV_SCHED_SYNC`)

```
dom0 thread → VMCALL_SWITCH → [capavisor swaps VMCS] → child runs on same core
                                                        child exits →
              ← VMCALL returns ← [capavisor swaps back] ←
```

- **1:1 core pinning**: one dom0 thread per child VP, same core.
- **Low latency**: no IPI, no shared-memory protocol.
- **Blocking**: dom0 thread cannot do anything while child runs.

### 3.2 Async Mode (new — `THHV_SCHED_ASYNC`)

```
dom0 thread → VMCALL_START_VP(child, vp, target_core=B)
                capavisor: load child VMCS on core B, VMRESUME
              → dom0 thread sleeps on waitqueue (or polls)

              [child runs independently on core B]

              child exits → capavisor (core B):
                1. save VP state to VpCommPage
                2. write exit msg to DomainComm RX ring
                3. send doorbell IPI (0xF0) to core A
                4. park: spin on resume_cmd atomic

              dom0 ISR (core A): wake thread
              dom0 thread: read exit, emulate, decide
              dom0 thread → VMCALL_RESUME_VP(child, vp)
                capavisor: set resume_cmd on core B
                core B: read cmd, inject pending interrupts, VMRESUME
```

- **Core independence**: dom0 and child on separate cores.
- **Non-blocking**: dom0 thread sleeps (not spinning) while child runs.
- **Overcommit**: multiple child VPs can time-share core B.

### 3.3 Selection

Policy is set at partition creation time via `sched_policy` field in
`THHV_CREATE_PARTITION`.  The ioctl surface (`THHV_RUN_VP`) is identical —
the driver translates to `VMCALL_SWITCH` (sync) or `VMCALL_START_VP` (async)
internally.  Cloud-hypervisor is unaware of the scheduling mode.

---

## 4. Core-Gapping: Avoiding TLB Flushes

The primary benefit of core-gapping is **decoupling the child core from
parent-side state changes**, specifically EPT/TLB management.

### 4.1 The Flush Problem (Sync Mode)

In sync mode, when a capability operation modifies the EPT (e.g., REVOKE
removes a page from a child's address space), the capability engine emits a
`FlushTLB` update.  The capavisor must:

1. Send an INIT IPI to every core that may have stale TLB entries.
2. Wait for those cores to reach the barrier (VMEXIT if running a guest).
3. Each core executes INVEPT.
4. Release the barrier.

If the child is running on the same core as the thread performing the
revocation, that core must VMEXIT the child, flush, then VMRESUME — adding
latency to what should be a parent-only operation.

### 4.2 Core-Gapping Solution

With async scheduling, the child runs on core B.  When dom0 (core A)
performs a capability operation:

1. **EPT updates are applied by the capavisor on core A** (the core that
   holds the engine lock).  Core B's TLB may be stale.
2. **The capavisor marks core B as "flush-pending"** in the per-core async
   state.
3. **Core B checks the flush-pending flag** at two points:
   - In the `async_park_loop` (between child exit and resume).
   - On VMRESUME: if flush-pending, execute INVEPT before entering the child.
4. **No synchronous IPI to core B is needed** for the common case — the
   flush piggybacks on the next exit/resume cycle.

**When is a synchronous flush still required?**

- On `REVOKE` operations that remove memory the child is actively accessing.
  The child must be stopped first (VMCALL_STOP_VP) before the revocation
  completes — this is a capability engine invariant (A1: validate before
  hardware change).
- On urgent security operations (domain destruction).

For these cases, the async park loop already checks `ipi_pending` for the
capability engine's barrier protocol.  The existing INIT IPI mechanism
works unchanged.

### 4.3 Interrupt Re-routing

In sync mode, dom0 timer interrupts and device interrupts cause VMEXITs
on the core running the child.  The capavisor must route them back to dom0
via `forward_interrupt_to_handler`.

In async mode, **dom0 interrupts never arrive on core B** if dom0 is not
loaded there:

- **LAPIC timer**: the timer is per-core.  Core B's timer belongs to
  whatever domain is loaded on core B.  Dom0's timer fires on core A
  (where dom0 actually runs).  No forwarding needed.
- **IOAPIC/MSI interrupts**: these are routed by VT-d to the APIC ID of
  the target core.  Dom0's interrupts target core A (or whichever core
  dom0's IRTE points to).  They never reach core B.
- **Child's interrupts**: device interrupts destined for the child (via
  irqfd → `VMCALL_INJECT_INTERRUPT`) are delivered by dom0 on core A,
  which writes to the child's PIR and sends a notification IPI to core B.
  Core B checks PIR on VMRESUME and injects.

**Result**: the child core sees only its own exits and injected interrupts.
No dom0 interrupt forwarding overhead.

---

## 5. Meta Page / VpCommPage Protocol

The meta page (VpCommPage) is the **data plane** for async scheduling.
It carries VP register state and exit information between the capavisor
and the parent domain, without requiring hypercalls for each register
read/write.

### 5.1 Layout (per child VP, 4 KiB)

```
Offset    Size    Field
──────    ────    ─────
0x000     64B     Control area: dirty_mask, allowed_mask, status flags
0x040     448B    Register storage: GPRs, segment regs, control regs, MSRs
0x200     256B    Intercept message: exit_reason, exit_qual, guest_rip,
                  port/MMIO info, instruction bytes
0x300     256B    Inject area: pending interrupt vector, posted-interrupt
                  descriptor shadow, event injection request
0x400     768B    Reserved / XSAVE area pointer
```

### 5.2 Flow

**On child exit (capavisor, core B):**
1. Save child VP's register state into VpCommPage register storage area.
2. Write intercept message at offset 0x200 (exit reason, qualification, RIP,
   instruction bytes for emulation).
3. Set `status = EXITED` in control area.
4. Write message to DomainComm RX ring (lightweight: just `VP_EXIT` + VP index).
5. Send doorbell IPI (vector 0xF0) to parent's core.
6. Enter `async_park_loop`: spin on `resume_cmd`.

**On parent decision (dom0 driver / CHV):**
1. Read intercept message from VpCommPage (mmap'd into userspace).
2. Emulate the exit (I/O port write, MMIO, CPUID, etc.).
3. Write any register updates to VpCommPage register storage.
4. Set `dirty_mask` bits for modified registers.
5. Call `THHV_RUN_VP` → driver calls `VMCALL_RESUME_VP`.

**On resume (capavisor, core B):**
1. Read `dirty_mask`, apply register updates from VpCommPage to child VMCS.
2. Clear `dirty_mask`.
3. Check flush-pending flag → INVEPT if needed.
4. Check PIR for pending interrupts → inject.
5. VMRESUME child.

### 5.3 Advantages Over Hypercall-Based Register Access

| Aspect | Hypercall path | Meta page |
|--------|---------------|-----------|
| Read 1 register | VMCALL + VMEXIT + VMRESUME | Memory load (ns) |
| Write 1 register | VMCALL + VMEXIT + VMRESUME | Memory store (ns) |
| Bulk register dump | N × VMCALL | Single memcpy |
| Userspace access | ioctl → kernel → VMCALL | mmap (zero-copy) |

The meta page eliminates **all register-access VMCALLs** in the hot path.
The only VMCALLs needed are `START_VP`, `RESUME_VP`, and `STOP_VP`.

---

## 6. New VMCALLs

| VMCALL | Opcode | Description |
|--------|--------|-------------|
| `START_VP` | TBD | Launch child VP on target core. Core B loads child VMCS and VMRESUMEs. |
| `RESUME_VP` | TBD | Signal core B to resume a parked child VP. Sets `resume_cmd`. |
| `STOP_VP` | TBD | Request VP stop at next exit (no resume possible). |
| `RECOVER_CORE` | TBD | Switch core B back to parent domain (teardown). |

All go through the capability engine for validation (A1).

---

## 7. Capavisor Per-Core Async State

```rust
pub enum AsyncCoreState {
    /// Core is available for scheduling.
    Idle,

    /// Core is running a child VP.
    RunningChild {
        domain_id: DomainId,
        vp_id: u32,
    },

    /// Child exited, core is parked waiting for parent decision.
    Parked {
        domain_id: DomainId,
        vp_id: u32,
        resume_cmd: AtomicU32,      // WAITING=0, RESUME=1, STOP=2
        flush_pending: AtomicBool,  // set by EPT update on another core
    },
}
```

The `async_park_loop` on core B:

```rust
fn async_park_loop(state: &Parked) {
    loop {
        // 1. Check capability engine barrier (INIT IPI for revocation).
        if ipi_pending[self_core].load(Acquire) {
            respond_to_barrier();
        }
        // 2. Check resume command from parent.
        match state.resume_cmd.load(Acquire) {
            RESUME => {
                if state.flush_pending.swap(false, AcqRel) {
                    invept_single(child_eptp);
                }
                apply_dirty_registers_from_meta_page();
                inject_pending_interrupts();
                vmresume_child();
                break;
            }
            STOP => {
                cleanup_and_return_to_idle();
                break;
            }
            WAITING => core::hint::spin_loop(),
        }
    }
}
```

---

## 8. Driver (thhv.ko) Changes

### 8.1 Async Run Path

```c
static long thhv_run_vp_async(struct thhv_vp *vp, void __user *uarg)
{
    if (!vp->running) {
        /* First run: launch VP on target core. */
        ret = thhv_vmcall_start_vp(part, vp->index, target_core);
        vp->running = true;
    } else {
        /* Resume: signal capavisor to resume the parked VP. */
        ret = thhv_vmcall_resume_vp(part, vp->index);
    }

    /* Sleep until capavisor signals exit via doorbell IPI. */
    ret = wait_event_interruptible(vp->exit_wq,
                                   atomic_read(&vp->exit_pending));
    if (ret == -ERESTARTSYS) {
        thhv_vmcall_stop_vp(part, vp->index);
        return -EINTR;
    }

    atomic_set(&vp->exit_pending, 0);

    /* Copy exit info from meta page to userspace. */
    if (copy_to_user(uarg, vp->meta_page + INTERCEPT_OFFSET,
                     INTERCEPT_MSG_SIZE))
        return -EFAULT;

    return 0;
}
```

### 8.2 Doorbell ISR

```c
static irqreturn_t thhv_doorbell_isr(int irq, void *data)
{
    /* Read DomainComm RX ring for VP_EXIT messages. */
    struct thhv_partition *part = data;
    while (domcomm_rx_pending(part)) {
        struct domcomm_msg msg;
        domcomm_rx_read(part, &msg);
        if (msg.type == MSG_VP_EXIT) {
            struct thhv_vp *vp = &part->vps[msg.vp_index];
            atomic_set(&vp->exit_pending, 1);
            wake_up(&vp->exit_wq);
        }
    }
    return IRQ_HANDLED;
}
```

### 8.3 VP Register Access (Meta Page)

With the meta page mmap'd into userspace, cloud-hypervisor can read/write
VP registers directly:

```c
/* In VP mmap handler: */
static int thhv_vp_mmap(struct file *file, struct vm_area_struct *vma)
{
    struct thhv_vp *vp = file->private_data;
    return remap_pfn_range(vma, vma->vm_start,
                           virt_to_phys(vp->meta_page) >> PAGE_SHIFT,
                           PAGE_SIZE, vma->vm_page_prot);
}
```

---

## 9. Cloud-Hypervisor Changes

The CH Themis backend (`hypervisor/src/themis/mod.rs`) needs minimal changes:

1. **`vcpu.run()`** — no change.  The ioctl is the same (`THHV_RUN_VP`);
   the driver handles sync/async internally.
2. **Register access** — if meta page is mmap'd, read/write registers via
   memory instead of `GET_VP_STATE`/`SET_VP_STATE` ioctls.  Falls back to
   ioctls if meta page is unavailable (sync mode without Phase 10).
3. **Scheduling policy** — set via `create_partition` ioctl.  Could be
   a CH config option (e.g., `--themis-scheduler async`).

---

## 10. Implementation Plan

### Phase G1: Capavisor async core state

**Scope**: Add `AsyncCoreState` to per-core platform state.  Implement
`async_park_loop` with barrier integration.  No new VMCALLs yet — just the
parking infrastructure.

**Files**: `capavisor/src/platform.rs`, `capavisor/src/arch/x86_64/`

**Depends on**: nothing (pure addition).

### Phase G2: New VMCALLs (START_VP, RESUME_VP, STOP_VP, RECOVER_CORE)

**Scope**: Implement the four async VMCALLs in the capavisor hypercall
handler.  Wire capability engine validation (A1).  `START_VP` loads child
VMCS on target core via cross-core IPI.  `RESUME_VP` sets `resume_cmd`.
`STOP_VP` sets stop flag.  `RECOVER_CORE` transitions core back to parent.

**Files**: `capavisor/src/hypercall.rs`, `capavisor/src/opcodes.rs`

**Depends on**: G1.

### Phase G3: VpCommPage / meta page write-on-exit

**Scope**: On child exit in async mode, save VP state to VpCommPage and
write `VP_EXIT` message to DomainComm RX ring.  Send doorbell IPI.

**Files**: `capavisor/src/hypercall.rs` (forward_child_exit path),
`capavisor/src/domcomm.rs`

**Depends on**: G2, existing DomainComm infrastructure.

### Phase G4: Deferred TLB flush (flush-pending flag)

**Scope**: On EPT update affecting a child running on a remote core, set
`flush_pending` instead of sending an immediate INIT IPI.  Flush is
executed on next VMRESUME.  Synchronous flush remains for REVOKE paths
where the child must be stopped.

**Files**: `capavisor/src/platform.rs` (`apply_update`), per-core state.

**Depends on**: G1.

### Phase G5: Driver async path (thhv.ko)

**Scope**: Add `thhv_run_vp_async`, doorbell ISR, waitqueue wakeup.
Meta page mmap for VP register access.  Wire `sched_policy` to select
sync/async in `thhv_run_vp`.

**Files**: `thhv/src/thhv_vp.c`, `thhv/src/thhv_part.c`, `thhv/include/`

**Depends on**: G2, G3.

### Phase G6: Cloud-hypervisor integration

**Scope**: Meta page mmap for register access in the Themis CH backend.
Optional `--themis-scheduler` config flag.

**Files**: `cloud-hypervisor/hypervisor/src/themis/mod.rs`

**Depends on**: G5.

### Phase G7: Testing

- Unit test: async park loop with simulated barrier.
- thhv test: `test_child_hlt` with `THHV_SCHED_ASYNC`.
- Integration: dom1 boot with async scheduler under `cargo themis`.
- Performance: measure exit-to-resume latency (sync vs async).
- Stress: concurrent EPT updates + child execution (TLB flush correctness).

**Depends on**: G6.

---

## 11. Relationship to Existing Mechanisms

| Mechanism | Sync mode | Async mode |
|-----------|-----------|------------|
| VP dispatch | VMCALL_SWITCH (same core) | VMCALL_START_VP (cross-core IPI) |
| Exit notification | VMCALL return registers | VpCommPage + DomainComm + doorbell IPI |
| Register access | VMCALL_GET/SET_REG | Meta page (mmap) |
| TLB flush | INIT IPI barrier (synchronous) | Deferred flush-pending flag |
| Interrupt injection | PIR + VMENTRY_INTR_INFO | PIR + notification IPI to child core |
| Dom0 interrupts | VMEXIT on child core → forward | Never reach child core |
| Overcommit | Not possible (1:1 pinning) | Multiple VPs time-share cores |

---

## 12. Security Considerations

- **A1 (capability validation)**: all four new VMCALLs go through `execute()`
  before any hardware change.  The capability engine validates that the caller
  owns the child domain and has appropriate rights.
- **A2 (dom0 not privileged)**: async scheduling uses the same capability
  interface.  Dom0 does not get special access to core B — only the capavisor
  controls VMCS loading.
- **A5 (META pool isolation)**: VpCommPage is allocated from META pool, mapped
  into the parent's EPT only.  The child cannot access its own meta page.
- **Barrier integration**: the `async_park_loop` respects INIT IPI barriers
  for the capability engine's cross-core protocol.  A parked core still
  participates in revocation barriers, preventing deadlock.
- **Flush correctness**: deferred flushes are only safe when the EPT update
  **adds** permissions (map) or modifies non-present entries (already faulting).
  For permission **removal** (revoke, unmap), the capavisor must either (a)
  stop the child first or (b) use the synchronous INIT IPI barrier.

---

## 13. References

- `docs/architecture/mshv-themis.md` §2.3 (root scheduler), §4 (ThemIC),
  §6.1–6.2 (sync/async scheduling), §15f (RUN_VP)
- `docs/architecture/interrupt-virtualization.md` Phase 3 (core-gapping),
  §Key Design Constraint (LAPIC timer)
- `docs/domain-comm.md` (DomainComm rings, message types)
- `docs/capability-engine/implementation.md` §barrier protocol
- Hyper-V TLFS: SynIC (Chapter 11), Root Scheduler (Chapter 14)
- vmxvmm/monitor/tyche: `monitor.rs` (CoreUpdate, CORE_REMAP),
  `calls.rs` (SWITCH, CONFIGURE_CORE)
