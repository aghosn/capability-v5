# Agent Handoff — Themis Development State

> **Date**: 2026-03-31
> **Branch**: `v2026.1`
> **Last commit**: `a3aee5e` (docs: add quantum-sched design doc)
>
> Read this file first when resuming work on any machine.

## Mandatory Reading (before any code change)

1. **`CONTEXT.md`** — full architecture, axioms A1–A11, component map
2. **`todo.md`** — current status, what works/doesn't, action items
3. **`skills/agent-workflow.md`** — build commands, session hygiene
4. **`capa-engine/docs/design/interrupt-virtualization.md`** — interrupt model, nested-virt scheduling, quantum-sched design (if working on multi-core or interrupts)

## What Works Right Now

| Feature | Status | Key commits |
|---------|--------|-------------|
| Dom0 (4 CPUs) | ✅ Boots to login | — |
| Dom1 (1 CPU, QEMU) | ✅ Boots to /bin/bash | `50ae665`, `fcbc04f` |
| virtio-blk disk I/O | ✅ Partition read + ext4 mount | `fcbc04f` |
| Lean formal spec | ✅ 83 theorems, 0 sorry | `69727ab` et al. |
| TPM attested boot | ✅ Code complete, untested e2e | `b19ceb7`..`1931c23` |

## What Doesn't Work

| Issue | Root cause | Fix status |
|-------|-----------|------------|
| Dom1 2-CPU boot | AP gets ~10 instr/quantum in nested virt | Planned: `quantum-sched` |
| Dom1 stock kernel | Not attempted yet | Todo |
| Dom1 on real hardware | Not tested with interrupt fixes | Todo |

## Interrupt Delivery — Critical Background

Three bugs were fixed to get 1-CPU dom1 booting. An agent MUST understand
these to work on interrupt code:

### Bug 1: PIR ON bit (fixed in `289d746`)
`inject_via_pid(is_remote=false)` set PIR[vector] but not PID.ON.
Hardware only processes PIR→vIRR on VMENTRY when ON=1. Fix: always set ON.

### Bug 2: PIR drain scan order (fixed in `50ae665`)
Software PIR drain in `do_switch` step 7b scanned high→low (word 3→0).
Timer (vec=236, word 3) always found before device interrupts (word 0).
Only ONE vector injectable per VMENTRY. Device vectors permanently starved.
Fix: scan low→high. Snapshot-and-restore for un-injected vectors.

### Bug 3: IF=0 defer loop (fixed in `fcbc04f`)
PIR drain only runs at SWITCH time. Guest has IF=0 (inside timer handler)
on ~97% of drain attempts. Device interrupts deferred thousands of times.
Fix: interrupt-window exiting (PRIMARY_PROCBASED bit 2). Forces VMEXIT
when guest IF becomes 1. Handler drains PIR and injects immediately.

**Key code locations**:
- PIR drain: `hypercall.rs` step 7b in `do_switch` (~line 797)
- Interrupt-window handler: `drain_pir_on_interrupt_window()` in `hypercall.rs`
- Interrupt-window VMEXIT: `EXIT_REASON_INTERRUPT_WINDOW` (7) in `vmexit.rs`
- Interrupt forwarding: `forward_interrupt_to_handler()` in `hypercall.rs`

## Next Tasks (priority order)

### 1. Quantum Scheduling (`quantum-sched`) — multi-core dom1

**Design doc**: `capa-engine/docs/design/interrupt-virtualization.md` §Nested Virtualization Scheduling (READ THIS FIRST)

Defer parent-bound interrupts during child VP execution. Deliver on
preemption timer expiry (~20ms). Gives child AP a guaranteed quantum.

Implementation steps:
1. Add `quantum-sched = []` feature to `themis/capavisor/Cargo.toml`
2. Add `deferred_vector: AtomicU16` to `CoreContext` in `platform.rs`
3. In `vmexit.rs` `EXIT_REASON_EXTERNAL_INTERRUPT` (child): if handler
   is parent, store vector and re-enter child (don't lazy-unwind)
4. In `vmexit.rs` `EXIT_REASON_VMX_PREEMPTION_TIMER` (child): if
   deferred vector set, call `forward_interrupt_to_handler(deferred_vec)`
5. Handle case where deferred already set (flush old, store new)
6. Test: `cargo build-bins` with `--features quantum-sched`, `CHV_CPUS=2`

**Previous failed approach (Approach A)**: deferred ALL interrupts, never
delivered dom0's timer → scheduler starved. This design only defers
parent-bound vectors and guarantees delivery via lazy-unwind.

### 2. Stock Kernel Boot — dom1 with Ubuntu kernel

Currently dom1 uses a custom `bzImage` with `init=/bin/bash`.
Goal: boot with stock Ubuntu cloud image kernel.
May need CPUID policy adjustments or additional MMIO emulation.

### 3. Real Hardware Test

Test interrupt-window fix + PIR drain on machine with real VT-x
and posted interrupts. The `quantum-sched` feature should NOT be
enabled on real hardware.

## Build & Test Quick Reference

```bash
# After capavisor/thhv changes:
cd /path/to/capability-v5
PROFILE=release cargo build-bins    # builds capavisor + thhv.ko + ISO

# Boot QEMU:
cd themis && PROFILE=release cargo themis 2>&1 | tee /tmp/out.txt

# SSH into dom0:
ssh -p 2222 cloud@localhost          # password: cloud123

# Launch dom1 (inside dom0):
sudo CHV_CPUS=1 /opt/bins/cloud-hypervisor/run-dom1.sh

# Dom1 console is on CHV stdout (or serial in /tmp/out.txt)
# Dom1 output is NOT the same as dom0 serial — check CHV stdout:
cat /tmp/chv-stdout.log              # ← THIS is dom1's console

# Engine unit tests:
cd capa-engine && cargo test
```

## Common Pitfalls

1. **Dom0 serial ≠ dom1 console**: Dom0 output goes to QEMU serial
   (`/tmp/out.txt`). Dom1 output goes to CHV stdout (`/tmp/chv-stdout.log`
   inside dom0). Don't confuse them — dom0 shows its own `virtio_blk`
   lines during boot, dom1's are different (smaller disk, different timestamps).

2. **thhv.ko can't be reloaded**: After `rmmod thhv`, the capavisor's
   domcomm state is consumed. Must reboot (rebuild ISO with `cargo build-bins`).

3. **Serial output garbling**: Two VPs printing simultaneously garble
   output. Use `serial_rtdbg!` (runtime-gated) for debug traces, not
   `serial_println!` in hot paths.

4. **Feature flags**: `no-posted-interrupts` forces software PIR drain
   (needed in QEMU/KVM). `quantum-sched` is the new one for multi-core.

5. **Preemption timer**: 60M ticks, rate divisor 5, ~20ms at 3GHz.
   Constant: `PREEMPTION_TIMER_TICKS` in `vmexit.rs`.
