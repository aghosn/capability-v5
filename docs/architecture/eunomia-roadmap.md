# Eunomia Roadmap — CHV Boot, CoCo, Core-Gapping

This document plans the next phases for Eunomia beyond E1–E7 (covered in
`eunomia.md`).  Eunomia serves as the **test vehicle** for Themis's advanced
features: confidential VMs (CoCo) and core-gapping.  Its minimal footprint
(~1200 LOC today) makes it far easier to iterate on than a full Linux dom1.

## Overview

**Key rationale**: Eunomia is deliberately used as the first test vehicle for
core-gapping (and CoCo) to avoid conflating hypervisor debugging with Linux
kernel complexity.  Once the capavisor mechanics are validated against a
controlled ~1200 LOC guest, the same infrastructure supports full Linux dom1
with confidence that the plumbing is correct.

Three phases, sequentially building on each other:

```
Phase A: CHV Boot         — Eunomia as real dom1 under Themis + CHV
Phase B: CoCo Integration — VTOM, MAP_SELF, shared-memory protocol
Phase C: Core-Gapping     — dedicated core, Forward policy, VMX preemption timer
```

Each phase produces a new **workload** crate that exercises the feature end-to-end.

---

## Phase A: Boot Eunomia Under CHV (Real dom1)

### Goal

Boot Eunomia as dom1 inside the full Themis stack (capavisor + dom0 + CHV)
instead of bare QEMU.  This validates:
- PVH boot through CHV's `linux-loader`
- hvm_start_info struct is correctly populated
- Serial output through CHV's virtio-console or COM port
- Graceful exit (triple-fault or HLT → CHV sees guest shutdown)

### Current State

Eunomia boots under QEMU microvm via `qemu-system-x86_64 -machine microvm
-kernel <elf>`.  This uses the Linux boot protocol, not real PVH.  The
hvm_start_info pointer in EBX is garbage under QEMU.

Under CHV, PVH is the native boot path — CHV's `linux-loader` parses the
PVH ELF note (XEN_ELFNOTE_PHYS32_ENTRY) and enters at `_pvh_start` with a
valid hvm_start_info in EBX.

### Tasks

#### A1: CHV launch script for Eunomia

Create `eunomia/scripts/run-chv.sh` (or integrate into existing
`run-dom1.sh`).  CHV configuration for Eunomia is minimal:

```
cloud-hypervisor \
  --kernel eunomia-smoke.elf \
  --console off \
  --serial tty \
  --cpus boot=1 \
  --memory size=128M \
  --pvh
```

No disk, no network, no virtio.  Serial is the only I/O device.  Exit on
guest HLT or triple-fault.

**Variant**: also support running under Themis (capavisor + dom0 + CHV),
using the existing `run-dom1.sh` infrastructure with Eunomia as the kernel
instead of bzImage.

#### A2: Validate hvm_start_info parsing

With CHV, EBX points to a valid `hvm_start_info`.  Add a workload test that
reads the struct fields:
- `magic` (0x336ec578)
- `version`
- `memmap_paddr` → memory map entries
- `nr_modules`

This is the first test that should **fail** under QEMU but **pass** under CHV,
confirming real PVH boot.

#### A3: Serial exit protocol

CHV needs to detect when Eunomia is done.  Options:
1. **Triple-fault** (current) — works but CHV may log it as a crash.
2. **Port I/O exit code** (current: `out 0xf4, al`) — CHV may or may not
   handle ISA debug port.  Verify or switch to `out 0x604, ax` (QEMU
   shutdown port) or ACPI PM1a_CNT.
3. **VMCALL** to capavisor → capavisor tears down domain.  This is the
   correct path when running under Themis.

Implement option 3 as default when the hypervisor is detected (CPUID leaf),
with option 1 as fallback for bare QEMU.

#### A4: Smoke-test all existing workloads under CHV

Run all 5 workloads (smoke, timer, memory, sched, hypercall) under CHV.
The hypercall workload should now produce real results instead of stub no-ops.

### Deliverables

- `eunomia/scripts/run-chv.sh`
- Updated `boot.rs` exit path (VMCALL when under Themis)
- New workload: `workloads/pvh-info/` — validates hvm_start_info
- CI: all workloads pass under CHV (manual for now)

---

## Phase B: Confidential VM (CoCo) Integration

### Goal

Eunomia boots as a **confidential domain**: its private memory is inaccessible
to dom0/CHV after SEND.  Eunomia explicitly shares back a bounce buffer region
via the capability channel.  This validates the VTOM design documented in
`confidential-vm.md`.

### Prerequisites

- Phase A complete (Eunomia boots under CHV/Themis)
- MAP_SELF engine operation (✅ already implemented in capa-engine)
- MAP_SELF wired to capavisor hypercall handler (needs doing)
- Channel SEND/RECV wired in capavisor

### Design Recap (from confidential-vm.md)

```
GPA space with VTOM at bit 39 (0x80_0000_0000):

  [0x00_0000_0000 .. RAM_SIZE)        → PRIVATE (dom0 has NO access)
  [0x80_0000_0000 .. 0x80_0000_0000 + RAM_SIZE)  → SHARED window (alias)
```

The guest flips the VTOM bit in its GPA to access the shared alias.  For
Eunomia (no Linux CoCo framework), this is trivial — just use different
pointer addresses for private vs shared data.

### Tasks

#### B1: Wire MAP_SELF hypercall in capavisor

The engine operation exists (`execute(MapSelf, ...)`).  The capavisor needs:
- A new VMCALL handler for `HC_MAP_SELF`
- `apply_update()` case for the MapSelf update batch
- EPT mapping of the capability at the requested GPA in the calling domain's EPT

This is capavisor work, not Eunomia work, but is a prerequisite.

#### B2: Wire CHANNEL_SEND / CHANNEL_RECV in capavisor

If not already wired, the channel operations need capavisor hypercall handlers
so Eunomia can send the shared-memory alias back to dom0.

#### B3: Eunomia shared-memory module (`shared.rs`)

A small module that:
1. Discovers its own capabilities via `HC_ENUMERATE`
2. Finds its channel endpoint
3. Allocates a shared buffer region (e.g., 4 KiB page at a known offset)
4. Calls `HC_ALIAS` to create an alias capability
5. Calls `HC_MAP_SELF` to map the alias at GPA | VTOM
6. Calls `CHANNEL_SEND` to send a second alias to dom0

Eunomia then writes data to the shared region at the VTOM-offset GPA, and
dom0/CHV can read it.

#### B4: Shared-memory workload

A new workload `workloads/coco/` that:
1. Boots, detects Themis via CPUID
2. Performs the shared-memory setup (B3)
3. Writes a known pattern to the shared buffer
4. Signals dom0 (via channel or serial)
5. Dom0 reads the shared buffer and verifies the pattern
6. Eunomia verifies that dom0 **cannot** read its private memory (optional:
   needs capavisor to report EPT violations)

This is the end-to-end CoCo validation without needing a Linux kernel patch.

#### B5: CPUID leaf for Themis detection

Define `CPUID 0x4000_0100` (or chosen leaf) so Eunomia can detect it's running
under Themis with CoCo support.  The capavisor must:
- Trap CPUID (already done via policy)
- Return Themis signature + VTOM address in registers

### Deliverables

- Capavisor: MAP_SELF + CHANNEL hypercall handlers
- `eunomia/src/shared.rs` — shared memory setup module
- Workload: `workloads/coco/`
- CPUID leaf definition (documented + implemented in capavisor)

---

## Phase C: Core-Gapping

### Goal

Eunomia runs on a **dedicated core** (core 1) with events forwarded to dom0
on core 0 via shared pages + IPI.  This validates the core-gapping design
in `core-gapping.md` and the VMX preemption timer approach for virtualized
timers.

### Prerequisites

- Phase A complete
- Forward policy variant in capa-engine (`InterruptPolicy::Forward`)
- VMX preemption timer support in capavisor

### Design Recap (from core-gapping.md)

```
Core 0 (dom0)                    Core 1 (child = Eunomia)
─────────────                    ────────────────────────
dom0 runs normally               Eunomia runs exclusively
  │                                │
  │  ← IPI ─────────────────────   │ child exits → Forward(core0, sync)
  │                                │   writes event to shared page
  │  read event, emulate           │   polls response variable
  │  write response ────────────→  │   reads response, VMRESUME
```

### Tasks

#### C1: Forward policy variant in capa-engine

Add `Forward { target_core: CoreId, synchronous: bool }` to the policy enum.
This is a capa-engine change with unit tests.

#### C2: Capavisor Forward handler

When a child exit matches a `Forward` policy:
1. Write exit info to the meta page (VpCommPage)
2. Send hardware IPI to target core
3. If synchronous: poll response variable until set
4. Read response, apply register updates, VMRESUME

#### C3: Dom0-side doorbell handler (thhv.ko)

Register an ISR on core 0 for the doorbell IPI vector.  On interrupt:
1. Read event from shared page
2. Wake CHV event loop
3. CHV processes event, writes response
4. Set response_ready flag

#### C4: VMX preemption timer for virtualized timer

When a child writes WRMSR 0x6E0 (TSC-deadline) and the policy is Forward:
1. Convert TSC deadline to VMX preemption timer value
2. Set preemption timer in VMCS
3. VMRESUME without forwarding to dom0
4. On preemption timer expiry: read guest's LVT timer vector, set PIR bit,
   VMRESUME (VID delivers interrupt)

Zero dom0 involvement per timer tick.

#### C5: Core-gapping workload

A new workload `workloads/core-gap/` that:
1. Boots on core 1 (dom0 has taken core 1 offline, pinned switch thread)
2. Runs a compute-bound loop with periodic timer ticks
3. Verifies timer interrupts arrive (VMX preemption timer path)
4. Performs I/O that triggers a Forward to dom0 (serial write or port I/O)
5. Verifies the response comes back correctly
6. Measures cycle counts to demonstrate no cross-core switches

#### C6: Core isolation in dom0

Dom0 preparation via thhv.ko or scripts:
1. `echo 0 > /sys/devices/system/cpu/cpu1/online` — take core offline
2. Disable NMI watchdog on core 1
3. Pin switch thread to core 1
4. After domain teardown: bring core 1 back online

### Deliverables

- capa-engine: `Forward` policy variant + tests
- Capavisor: Forward handler + VMX preemption timer
- thhv.ko: doorbell ISR
- Workload: `workloads/core-gap/`
- dom0 scripts/module support for core isolation

---

## Phase Dependencies

```
Phase A: CHV Boot
    │
    ├──→ Phase B: CoCo Integration
    │        │
    │        └──→ (can combine B + C for confidential core-gapped domain)
    │
    └──→ Phase C: Core-Gapping
```

Phase B and C are independent of each other (both depend on A).  Eventually
they combine: a confidential domain running on a gapped core is the full
Themis security story.

---

## Code Complexity Estimates

| Phase | Eunomia LOC | Capavisor LOC | thhv LOC | capa-engine LOC |
|-------|-------------|---------------|----------|-----------------|
| A: CHV Boot | ~50 (script + exit path) | ~0 | ~0 | ~0 |
| B: CoCo | ~150 (shared.rs + workload) | ~200 (MAP_SELF + CHANNEL handlers) | ~50 (channel ioctl) | ~0 (already done) |
| C: Core-Gap | ~100 (workload) | ~300 (Forward handler + preemption timer) | ~150 (doorbell ISR + core offline) | ~50 (Forward policy) |

**Total new code**: ~1050 LOC across all components.  Eunomia stays well
under 2000 LOC total.

---

## Milestones

1. **Eunomia boots under CHV** — smoke workload prints via serial, exits cleanly
2. **Eunomia boots under Themis** — hypercall workload returns real results
3. **Shared memory works** — Eunomia writes to shared buffer, dom0 reads it
4. **Private memory enforced** — dom0 cannot access Eunomia's private pages
5. **Core-gapped execution** — Eunomia runs on core 1, I/O forwarded to core 0
6. **Zero-dom0 timer** — timer ticks delivered via VMX preemption timer, no IPI
7. **Full integration** — confidential Eunomia on a gapped core

---

## Relation to Other Design Docs

- **`eunomia.md`** — kernel internals (E1–E7), boot sequence, workload model
- **`confidential-vm.md`** — CoCo architecture, VTOM, MAP_SELF, capability flow
- **`core-gapping.md`** — Forward policy, shared notification area, timer
  virtualization, security properties
- **`platform-modularization.md`** — trait-based capavisor arch (Phase B/C
  changes must work with the platform traits)
