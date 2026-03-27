## Themis — Implementation Status & Plan

> **Archives**: Previous todo content archived to:
> - [`2026/docs/archived/09-03-2026/archived_todo.md`](2026/docs/archived/09-03-2026/archived_todo.md) — phases 0–15, BUG-1–15, dom0 bringup
> - [`themis/docs/archive/27_03_2026.md`](themis/docs/archive/27_03_2026.md) — full history through dom1 multi-core debugging

---

## Current State (2026-03-27, 12:10 UTC)

### What works

- **Dom0**: boots to login on 4 CPUs. Ubuntu Noble 6.8.0-101-generic. Stable.
- **Dom1 (1 CPU)**: boots to login prompt. Custom kernel 6.8.0-dirty under CHV on Themis.
  Serial console, virtio-blk root. Timer via timerfd/irqfd (vector 0xEC, one-shot armed on
  WRMSR 0x6E0 TSC_DEADLINE — fires ~1/sec during boot, NOT at 1kHz).
  LAPIC via Mode B (EPT-trap MMIO emulation with iced-x86 in CHV). CPUID filtered (no AVX-512).
  Boot takes ~10min due to serial I/O exit overhead.

### What doesn't work

- **Dom1 (2 CPUs)**: AP boots through real→protected→long mode but gets stuck.
  See "The Problem" below.

### Uncommitted changes (on top of commit 796c048)

Files modified (all uncommitted):
- `themis/capavisor/src/vmexit.rs` — AP deferral code + 1ms preemption timer (latest attempt)
- `themis/capavisor/src/hypercall.rs` — `yield_child_to_dom0`, `inject_via_pid` is_remote=false, timer reset removed from do_switch
- `themis/capavisor/src/platform.rs` — minor additions
- `themis/capavisor/src/vmcs.rs` — minor additions
- `thhv/inc/thhv.h` — `struct thhv_irqfd` added `vp_index` + `rsvd` fields
- `thhv/src/thhv_irqfd.c` — per-VP irqfd targeting using `entry->vp_index`
- `thhv/src/thhv_vp.c` — wait-for-SIPI, cond_resched in retry loop, domcomm drain
- `thhv/src/thhv_part.c` — minor additions
- `todo.md` — rewritten
- `themis/docs/archive/27_03_2026.md` — archived old todo

CHV submodule also has per-vCPU irqfd changes (not shown in diff).

---

## The Problem: Child VP Scheduling on Nested Virtualization

### Architecture reminder

```
QEMU+KVM (actual L0, physical host)
  └─ Capavisor (L0 logical, VMX root inside KVM guest)
       └─ Dom0 (L1, Ubuntu, 4 CPUs) → thhv.ko
            └─ CHV (userspace) → ioctls
                 └─ Dom1 (L2, custom Linux, 2 CPUs) → the child VM
```

**Critical**: We develop on QEMU+KVM. Our "L0" capavisor is actually an L1 guest in KVM.
Dom1 is L2 in KVM terms. On real hardware, the capavisor would be true L0.

### The scheduling loop

1. CHV calls `ioctl(RUN_VP)` → `thhv_run_vp()` in kernel
2. thhv calls `themis_switch()` VMCALL → capavisor
3. Capavisor: VMCLEAR dom0 VMCS, VMPTRLD child VMCS, VMRESUME child
4. Child runs until VM exit
5. On exit: capavisor handles exit, returns control to dom0 (ERR_RETRY) or CHV (intercept message)
6. thhv: if EAGAIN, `cond_resched()` then goto retry_switch

### What goes wrong — three approaches tried, all fail

**Approach A: Defer AP interrupts + preemption timer yield**
- Child external interrupt → ACK vector → store in DEFERRED_HOST_VECTOR → VMRESUME child immediately
- Preemption timer fires → yield to dom0, inject deferred vector
- **Result at 20ms quantum**: AP reaches cpuhp_ap_sync_alive, but dom0 starves → RCU stall at ~688s
- **Result at 1ms quantum**: Dom0 hung_task warnings, SSH unresponsive. Too much VMCLEAR/VMPTRLD overhead.
- **Why it fails**: dom0's timer interrupt is consumed by capavisor (ACK_INTERRUPT_ON_EXIT), never
  delivered to dom0's IDT → scheduler_tick() never runs → TIF_NEED_RESCHED never set → dom0 starves

**Approach B: Forward ALL child interrupts to dom0** (mirrors KVM's local_irq_enable)
- Child external interrupt → `forward_interrupt_to_handler` → switch to dom0 VMCS, inject vector
- Dom0 IDT handles the interrupt → scheduler runs naturally
- **Result**: Dom0 stays healthy (SSH alive!) but AP stuck at RIP=0x0 — never executes one instruction
- **Why it fails**: The interrupt is vector 0xEC = dom0's LAPIC timer (scheduler tick at ~250Hz).
  In nested virt, KVM always has dom0's LAPIC timer pending or about to fire. The VMCLEAR/VMPTRLD/
  VMRESUME sequence for the child takes so long in nested virt that dom0's timer deadline is already
  past by the time the child's VMRESUME completes → KVM immediately exits → AP executes 0 instructions.
  This is a **nested virtualization artifact** — on real hardware, VMRESUME is ~microseconds and
  the child would execute thousands of instructions between 250Hz ticks.

**Approach C: Deferred + 1ms preemption timer (hybrid)**
- Defer AP interrupts (like A) but with 1ms quantum (3M ticks at 3GHz, rate divisor 5)
- **Result**: Dom0 shows hung_task warnings. SSH intermittently responsive. Child may be making
  some progress but very slowly. The 1ms quantum may cause too much context-switch overhead.

### Key insight: this is a nested virtualization problem

On real hardware:
- VMRESUME is ~1μs, child runs ~4ms between 250Hz timer ticks = ~4000 instructions minimum
- With posted interrupts (PI), dom0's timer would NOT cause a child VM exit at all
- The "forward every interrupt" approach (B) would work perfectly

On QEMU+KVM (our dev env):
- Our VMRESUME is a nested VMRESUME → KVM overhead → ~100s of μs or more
- Dom0's LAPIC timer fires before the child executes ANY instruction
- Posted interrupts are not available (nested PI not supported by KVM)

### User's suggestion to explore

**"Flush writes to child, return to dom0, let dom0 drain interrupts, then do a pure switch"**

The idea: after SET_VP_STATE writes the child's registers, return to dom0. Dom0 handles its
pending LAPIC timer (scheduler tick fires, gets rearmed for next tick). THEN call SWITCH.
The child now has a full quantum until the next timer tick.

Current flow: SET_VP_STATE (ioctl) → RUN_VP (ioctl) → SWITCH vmcall → child runs
With this change: between RUN_VP and SWITCH, dom0 would drain pending interrupts first.

This could translate to: in `thhv_run_vp`, instead of `cond_resched()` on EAGAIN,
do `schedule_timeout(1)` (sleep 1 jiffy = 1-4ms) to guarantee dom0 gets a full timer
tick before retrying. Or: have the capavisor itself do `sti; nop; cli` in VMX root
before the child VMRESUME to drain pending LAPIC interrupts.

### Other observations

- The timerfd/irqfd path for dom1's timer is NOT the cause of the 0xEC flood.
  The flood is dom0's OWN scheduler tick (hrtimer → LAPIC), not the irqfd injection.
  Dom1's timerfd fires ~1/sec during boot (large TSC deltas).
- Dom1 uses TSC-deadline mode (WRMSR 0x6E0). CHV arms a timerfd. When it fires:
  timerfd → eventfd → thhv workqueue → INJECT_INTERRUPT vmcall → capavisor sets PIR bit.
  PIR is drained by do_switch step 7b on next VMRESUME (software fallback, not hardware PI).
- `inject_via_pid` changed to is_remote=false to avoid notification IPI causing immediate exit.

---

## Action Plan

### Immediate: fix the nested-virt scheduling problem

- [ ] **S1**: Try `schedule_timeout(1)` in thhv_run_vp EAGAIN loop instead of `cond_resched()`.
  This guarantees dom0 processes its timer tick before retrying SWITCH. The child then gets
  a full quantum (~4ms at 250Hz) before the next timer interrupt.
- [ ] **S2**: If S1 doesn't work, try capavisor-side drain: `sti; nop; cli` in VMX root
  before child VMRESUME. Requires capavisor IDT to handle the interrupt.
- [ ] **S3**: If neither works, try forwarding every interrupt (approach B) but with the
  schedule_timeout fix — the combination might work: forward interrupt to dom0 → dom0 handles
  it → schedule_timeout ensures timer is rearmed → retry SWITCH → child gets full quantum.
- [ ] **S4**: Remove AP deferral code in vmexit.rs (use approach B as the base).
- [ ] **S5**: Test 2-CPU dom1 boot end-to-end. Verify: AP completes hotplug, "Brought up 2 CPUs",
  dom0 stable (no RCU stall), `cat /proc/cpuinfo` shows 2 processors.

### Design principle

On real hardware with posted interrupts: dom0's timer does NOT exit the child. This problem
goes away. The fix we implement for nested-virt should degrade gracefully — it should be a
"give dom0 enough time" mechanism, not a fundamental architecture change.

### Future work

- [ ] Per-VP irqfd: struct updated, needs end-to-end test
- [ ] Posted interrupt support when available (eliminates the scheduling problem on real HW)
- [ ] Paravirt timer (PV MMIO hypercall, P16.6d3)
- [ ] Reduce serial I/O overhead
- [ ] CPUID policy in DomainPolicy (P16.6c)
- [ ] Stock cloud image kernel

---

## Reference

### Key files

| File | Role |
|------|------|
| `themis/capavisor/src/vmexit.rs` | VMEXIT dispatch, child interrupt handling, preemption timer |
| `themis/capavisor/src/hypercall.rs` | `do_switch`, `forward_interrupt_to_handler`, `yield_child_to_dom0`, `do_inject_interrupt` |
| `thhv/src/thhv_vp.c` | `thhv_run_vp` — the critical VP run loop with EAGAIN retry |
| `thhv/inc/thhv.h` | ioctl structs (irqfd, VP state), shared constants |
| `cloud-hypervisor/hypervisor/src/themis/mod.rs` | CHV Themis backend, timer emulation, irqfd, SIPI |
| `themis/scripts/run-dom1.sh` | CHV launch script (CHV_CPUS=2, serial, init=/bin/bash) |

### Key functions

| Function | File | What it does |
|----------|------|-------------|
| `thhv_run_vp` | thhv_vp.c:38 | Run loop: wait-for-SIPI → SWITCH → EAGAIN retry → intercept msg |
| `do_switch` | hypercall.rs:~643 | VMCALL handler: VMCLEAR dom0, VMPTRLD child, drain PIR (step 7b), VMRESUME |
| `forward_interrupt_to_handler` | hypercall.rs:~1400 | Full context switch child→dom0, inject vector via VMENTRY_INTR_INFO |
| `yield_child_to_dom0` | hypercall.rs:~1516 | Lightweight preemption timer yield, inject deferred vector |
| `forward_child_exit` | hypercall.rs:~1100 | Forward non-interrupt exits to dom0, inject deferred vector |
| `inject_via_pid` | hypercall.rs:~1314 | Set PIR bit + optional notification IPI |

### Build commands

```bash
# Capavisor
cd themis && cargo build --release && cargo themis   # build + pack ISO

# CHV (inside cloud-hypervisor/)
cargo build --release --features themis

# thhv.ko (inside VM, at /opt/thhv or /home/cloud/thhv)
make   # needs liblibthemis.a, kernel headers for 6.8.0-101-generic

# Pack bins.img
cd themis && cargo build-bins

# SCP files to VM
scp -P 2222 thhv/inc/thhv.h thhv/src/thhv_irqfd.c thhv/src/thhv_vp.c cloud@localhost:/home/cloud/thhv/tmp_upload/
# password: cloud123
```

### VM details

- QEMU port forwarding: host 2222 → guest 22 (SSH)
- Serial console: `-serial mon:stdio` in QEMU, `-serial tty=/dev/ttyS0` in CHV
- Dom1 kernel: custom 6.8.0-dirty at `/home/cloud/bzImage`
- Dom1 rootfs: `/home/cloud/rootfs.ext4`
- Dom1 launch: `sudo /home/cloud/run-dom1.sh` (loads thhv.ko + runs CHV)

### VMCS constants

| Name | Value | Notes |
|------|-------|-------|
| PREEMPTION_TIMER_TICKS | 3_000_000 (1ms) | Currently set; was 60M (20ms) before |
| Timer rate divisor | 5 | 1 tick ≈ 10.67ns at 3GHz |
| DEFERRED_HOST_VECTOR | per-core atomic u32[64] | Stores deferred interrupt vector |
| ACK_INTERRUPT_ON_EXIT | enabled | Vector in VMEXIT_INTERRUPTION_INFO |

### VM exit reasons (common)

| Code | Reason | Notes |
|------|--------|-------|
| 1 | EXTERNAL_INTERRUPT | Timer, IPI — the scheduling-critical exit |
| 10 | CPUID | Emulated by CHV |
| 12 | HLT | Blocked in thhv via halt_wq |
| 28 | CR_ACCESS | CR0/CR4 writes during boot |
| 30 | IO_INSTRUCTION | Serial port (dominant during boot) |
| 48 | EPT_VIOLATION | MMIO (IOAPIC, platform devices) |
| 52 | VMX_PREEMPTION_TIMER | Backup scheduling mechanism |
