## Themis — Implementation Status & Plan

> **Archives**: Previous todo content archived to:
> - [`docs/archive/todos/archived_todo_09_03_2026.md`](docs/archive/todos/archived_todo_09_03_2026.md) — phases 0–15, BUG-1–15, dom0 bringup
> - [`docs/archive/session-notes/27_03_2026.md`](docs/archive/session-notes/27_03_2026.md) — full history through dom1 multi-core debugging
> - [`docs/archive/session-notes/07_04_2026.md`](docs/archive/session-notes/07_04_2026.md) — differential testing, VITAL cascade fix, TPM, code review

---

## Current State (2026-05-18)

### What works

- **Dom0**: boots to login on 4 CPUs. Ubuntu Noble 6.8.0-107-generic. Stable.
- **Dom1 Linux (1 CPU)**: full systemd boot under Themis (emergency.target on local
  QEMU due to missing fstab — known, not a regression).
- **Dom1 Linux (2 CPUs)**: full systemd boot to login prompt. Verified 2026-04-14.
- **Eunomia as dom1**: ✅ boots under full Themis stack (capavisor + dom0 + CHV).
  All 33/33 tests pass (incl. timer via TSC-deadline, CPUID). 7 workloads.
  `cargo build-bins` now rebuilds Eunomia workloads before packaging.
- **Platform modularization**: complete. Opaque ArchDomainState/ArchPlatformState,
  aarch64 cross-check 0 errors. Generic monitor loop with SemanticExit dispatch.
- **AArch64 M1–M5c**: boot → memory → EL2 → GICv3 → guest → PSCI → Linux initramfs.
  M6 partial (full Ubuntu boot blocked by QEMU TCG overhead, needs real ARM HW).
- **Capability engine**: MAP_SELF implemented (refcounted projections, 33 tests).
  83 Lean theorems, 0 sorry. lean-exec 21/21 differential tests passing.
- **TPM attested boot**: Ed25519 + SHA-256 + TPM PCR extend. CRB/TIS auto-select.
- **CoCo guest kernel**: CC_VENDOR_THEMIS patch in `../linux`.  Minimal config
  (245 modules), virtio/ext4/9p built-in.
- **MAP_SELF hypercall**: wired across themis-abi (0x1f), capavisor handler, thhv.
- **CARVE+SEND**: fully working — dom0 loses EPT access when SENDing to child.
- **CPUID/MSR interposition policy**: ✅ fully policy-driven. All CPUID leaves
  (including hypervisor range) go through PolicyDriven path. No ArchHandled special
  case. CHV pushes Native/Emulate overrides for dom1. CoCo leaf (0x40000100)
  returns dynamic VTOM bit = MAXPHYADDR-1.
  `cargo diff-test` (from capa-cli/) runs automated Rust-vs-Lean differential
  testing on all 16 tutorials.
- **Dom1 CoCo detection**: ✅ kernel detects CC_VENDOR_THEMIS, reads VTOM bit 38.
- **MMIO VTOM stripping**: ✅ IO-APIC reads correctly (`version 17, GSI 0-23`)
  after stripping VTOM bit in CHV's handle_mmio_exit and emulator translate_gva.

### What doesn't work / known issues

- **Dom1 CoCo: ACPI table access crash**: CoCo kernel reads ACPI tables with VTOM
  bit set → GPA `0x40_000A12B3` not in EPT → emulation failure on unsupported
  instruction. Fix: double-map ACPI/firmware region at VTOM-offset GPA.
- **Dom1 emergency mode on QEMU**: fstab references missing partitions.
- **Unguarded interrupt injection**: 2 fallback paths without RFLAGS.IF check.
- **Posted interrupts**: hardware PI disabled (software PIR drain instead).
- **Dom1 on real hardware**: not yet tested.
- **KVM nested dom1**: CHV FailEntry under nested QEMU — only Themis backend works.
- **CoCo share-back**: MAP_SELF wired but not yet tested end-to-end. Channels
  not wired in capavisor. No dom1-initiated sharing yet.

### Recent commits

- `e642a14` — **policy-driven CPUID for all leaves (capavisor, eunomia, QEMU config)**
- CHV `1fa1e19` — **Native/Emulate CPUID policy for hypervisor leaves + CoCo VTOM bit**
- `ce15689` — **capa-cli, lean-exec: interposition policy support and differential testing**
- `836359b` — **capa-engine: generic CPUID/MSR interposition policy framework**
- `c15e246` — **fix(eunomia): emit CR+LF on serial output**
- `04edb1b` — **feat: build-bins rebuilds eunomia workloads before packaging**

### Uncommitted changes

- **CHV** (`cloud-hypervisor/hypervisor/src/themis/mod.rs`):
  - `vm_state.vtom_bit` field + VTOM mask stripping in `handle_mmio_exit`
  - `vtom_mask` passed to emulator context
- **CHV** (`cloud-hypervisor/hypervisor/src/themis/emulator.rs`):
  - `vtom_mask` field in `ThemisEmulatorContext`
  - Strip VTOM from GPAs in `translate_gva` (all 3 page-size return paths)

---

## Active Work Streams

### 1. Eunomia — minimal micro-kernel guest ✅ Phase A complete

Design docs: [`docs/architecture/eunomia.md`](docs/architecture/eunomia.md),
[`docs/architecture/eunomia-roadmap.md`](docs/architecture/eunomia-roadmap.md)

Eunomia is the test vehicle for core-gapping and CoCo before tackling Linux dom1
complexity.  ~1200 LOC, boots in <50ms, 6 workloads / 24 tests.

**Completed (E1–E7, Phase A)**:
- Boot (PVH 32→64, GDT/TSS, IDT, LAPIC timer, bump allocator, scheduler)
- HypervisorInterface trait (ThemisBackend VMCALL, StubBackend)
- Workload model (independent crates, `app_main` entry point)
- CHV PVH boot + ACPI shutdown exit path
- `cargo run-chv` alias, `run-eunomia.sh` for dom0
- pvh-info workload (validates hvm_start_info, memmap, RSDP)
- ✅ Timer: TSC-deadline mode, vector 0xEC (matches CHV's irqfd injection)
- ✅ All 24/24 tests pass under QEMU, CHV, and full Themis stack
- ✅ `cargo build-bins` rebuilds Eunomia workloads before packaging
- ✅ Clean serial output (CR+LF)

**Next**:
- [ ] Phase B: CoCo integration (shared.rs, MAP_SELF, CHANNEL_SEND workload)
- [ ] Phase C: Core-gapping workload (Forward policy, VMX preemption timer)

### 2. Core-gapping (design complete, implementation pending)

Design doc: [`docs/architecture/core-gapping.md`](docs/architecture/core-gapping.md)

Run child domain on dedicated core, events forwarded to dom0 on separate core
via shared pages + IPI.  Eliminates cache side channels and single-stepping.

**Design decisions (settled)**:
- `Forward { target_core, synchronous }` policy variant
- VMX preemption timer for local timer delivery (2 exits/tick, zero IPIs)
- Shared notification area = existing VpCommPage / meta page
- Policy-driven: core-gapping emerges from per-event Forward policies

**Implementation plan**:
- [ ] `InterruptPolicy::Forward` variant in capa-engine + tests
- [ ] Capavisor Forward handler (write event → IPI → poll response → VMRESUME)
- [ ] thhv.ko doorbell ISR on core 0
- [ ] VMX preemption timer for TSC-deadline → local timer delivery
- [ ] Core isolation in dom0 (cpu offline, watchdog disable, pin switch thread)
- [ ] Eunomia core-gap workload for end-to-end validation

### 3. Confidential VMs — CoCo (active)

Design doc: [`docs/architecture/confidential-vm.md`](docs/architecture/confidential-vm.md)

Dom1 memory private by default.  VTOM address-space split for explicit sharing.
No hardware encryption needed — EPT isolation provides equivalent protection.

**What already works**:
- CARVE+SEND removes pages from sender (dom0) EPT → dom1 memory is exclusive ✅
- MAP_SELF engine operation implemented (refcounted projections, 33 tests) ✅
- MAP_SELF hypercall wired: themis-abi (0x1f), capavisor handler, thhv ✅
- CC_VENDOR_THEMIS kernel patch exists in `../linux` (CPUID detection, cc_mkenc/cc_mkdec, VTOM) ✅
- CoCo guest kernel config (245 modules, virtio/ext4/9p built-in) ✅
- CPUID/MSR interposition policy framework in capa-engine ✅
  - Generic ProcFeature trait, ProcFeatureConfig<T>, Cpuid/Msr types
  - DomainPolicy extended with CpuidPolicy + MsrPolicy
  - Attestation includes CPUID/MSR policies
  - capa-cli: set-policy parsing for all interposition variants
  - lean-exec: DefaultAction/ProcFeatureConfig types, setPolicy/getPolicy support
  - Design doc: `docs/architecture/cpuid-policy.md`

**What needs implementation (interposition wiring)**: ✅ DONE
- [x] themis-abi: policy_kind constants for CPUID/MSR PolicyIdentifier variants
- [x] Capavisor: all CPUID leaves through PolicyDriven path
- [x] CHV: push Native/Emulate CPUID policy during domain setup
- [x] VTOM bit stripping in handle_mmio_exit + emulator translate_gva

**What needs implementation (ACPI firmware double-map — NEXT)**:
- [ ] CHV: separate ACPI/firmware region (`0xA0000–0xFFFFF`) into its own memory
      slot instead of being part of the main RAM blob. Register it twice:
      once at base GPA and once at `GPA | (1 << vtom_bit)`.
      The EBDA region is in the e820 gap (kernel marks it nosave, never recycles).
- [ ] Verify dom1 CoCo kernel boots past ACPI table parsing after double-map.

**What needs implementation (CoCo end-to-end)**:
- [ ] CHV: distinguish shared (MMIO) vs exclusive (guest RAM) memory at setup time.
      Currently `create_user_memory_region` uses `THHV_MEM_F_ALIAS` for everything.
      For CoCo: guest RAM should use CARVE (flags=0), MMIO regions stay ALIAS.
- [ ] CHV: receive shared regions back from dom1 (accept alias via channel or
      new ioctl after dom1 shares bounce buffers back)
- [ ] Capavisor: wire CHANNEL_SEND / CHANNEL_RECV hypercalls
- [ ] Dom1 kernel: early init share-back — create aliases of swiotlb pool,
      MAP_SELF at VTOM GPA, CHANNEL_SEND the other to dom0
- [ ] Eunomia CoCo workload: minimal test that verifies dom0 cannot read dom1
      private memory after SEND
- [ ] End-to-end: Linux dom1 boots with CC_VENDOR_THEMIS, swiotlb active,
      virtio works through shared bounce buffers

**Open questions**:
- Channel revocation semantics (does revoking endpoint cascade to sent caps?)
  → Resolved: yes, CDT cascades naturally (see design doc §9.8)

### 4. Contiguous physical memory for VMs (research needed)

**Problem**: VMs need physically contiguous memory regions for efficient EPT
mapping (2M/1G pages) and DMA.  Currently CHV allocates guest memory via
mmap which gives scattered 4K pages.  This matters for:
- EPT performance (fewer page table entries with large pages)
- IOMMU mapping (IOVA=GPA requires contiguous backing, axiom A4)
- Core-gapping shared notification area (meta pages)

**Questions to investigate**:
- [ ] Can CHV use hugetlbfs (2M/1G hugepages) for guest memory?
- [ ] Does the Themis CARVE+SEND flow preserve contiguity?
- [ ] Do we need a capavisor-side contiguous allocator for meta/notification pages?
- [ ] Impact on memory fragmentation under multiple domains

### 5. Inter-domain shared memory / ivshmem equivalent (research needed)

**Problem**: Domains need private shared memory for communication (not through
dom0).  Use cases:
- Core-gapped child ↔ dom0 event queue (currently meta page, but needs scaling)
- Domain-to-domain direct communication (e.g., crypto enclave ↔ app domain)
- High-bandwidth data plane without dom0 intermediary

**Questions to investigate**:
- [ ] Does CHV support ivshmem or similar shared memory device?
- [ ] Can ALIAS capabilities serve as the shared memory primitive?
  (A creates ALIAS, sends to B via CHANNEL → both map same HPAs)
- [ ] How does this interact with VTOM / CoCo? (shared window must be at
  GPA|VTOM in both domains)
- [ ] Performance: polling vs doorbell interrupt for notification
- [ ] Could Eunomia-to-Eunomia communication be the first test case?

### 6. AArch64 backend (blocked on hardware)

Design doc: [`docs/architecture/arm-porting.md`](docs/architecture/arm-porting.md)

M1–M5c complete.  M6 (full Ubuntu boot) blocked by QEMU TCG Stage-2 overhead.
Needs real ARM hardware with KVM to validate.

### 7. Posted interrupts / hardware PI (deferred)

Requires `intel_iommu=on` and IOMMU intremap support.  Currently using software
PIR drain.  Not blocking any active work stream.

### ~~TODO: Platform modularization~~ ✅ Complete
### ~~TODO: Implement VITAL cascade in Lean~~ ✅ Complete
### ~~TODO: Full TPM attestation~~ ✅ Complete

---

## Reference

### Design documents

| Document | Path | Content |
|----------|------|---------|
| **Interrupt Virtualization** | `docs/architecture/interrupt-virtualization.md` | Single source of truth: goals, HW background, routing model, gap analysis, nested-virt scheduling, quantum-sched, Directvisor reference, 3 delivery bugs |
| **Attestation** | `docs/architecture/attestation.md` | Two-layer TPM + Ed25519 model |
| **Address Translation** | `docs/architecture/address-translation.md` | EPT/IOMMU design |
| **ARM Porting** | `docs/architecture/arm-porting.md` | ARM GICv4 as PI equivalent |

### Key files

| File | Role |
|------|------|
| `themis/capavisor/src/vmexit.rs` | VMEXIT dispatch, child interrupt handling, preemption timer |
| `themis/capavisor/src/hypercall.rs` | `do_switch`, `forward_interrupt_to_handler`, `do_inject_interrupt` |
| `thhv/src/thhv_vp.c` | `thhv_run_vp` — the critical VP run loop with EAGAIN retry |
| `thhv/inc/thhv.h` | ioctl structs (irqfd, VP state), shared constants |
| `cloud-hypervisor/hypervisor/src/themis/mod.rs` | CHV Themis backend, timer emulation, irqfd, SIPI |
| `themis/scripts/run-dom1.sh` | CHV launch script (CHV_CPUS=2, serial, init=/bin/bash) |

### Key functions

| Function | File | What it does |
|----------|------|-------------|
| `thhv_run_vp` | thhv_vp.c:38 | Run loop: wait-for-SIPI → SWITCH → EAGAIN retry → intercept msg |
| `do_switch` | hypercall.rs:~643 | VMCALL handler: VMCLEAR dom0, VMPTRLD child, drain PIR (step 7b), VMRESUME |
| `forward_interrupt_to_handler` | hypercall.rs:~1400 | Uses route_interrupt() to find handler, context switch child→handler, inject vector |
| `forward_child_exit` | hypercall.rs:~1070 | Forward non-interrupt exits to dom0 |
| `inject_via_pid` | hypercall.rs:~1314 | Set PIR bit + optional notification IPI |
| `route_interrupt` | platform.rs:~979 | Delegates to SwitchManager::route_interrupt() for policy-based routing |

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
| PREEMPTION_TIMER_TICKS | 60_000_000 (~20ms) | Restored from 3M after cleanup |
| Timer rate divisor | 5 | 1 tick ≈ 10.67ns at 3GHz |
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
