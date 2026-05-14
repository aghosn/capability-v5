## Themis — Implementation Status & Plan

> **Archives**: Previous todo content archived to:
> - [`docs/archive/todos/archived_todo_09_03_2026.md`](docs/archive/todos/archived_todo_09_03_2026.md) — phases 0–15, BUG-1–15, dom0 bringup
> - [`docs/archive/session-notes/27_03_2026.md`](docs/archive/session-notes/27_03_2026.md) — full history through dom1 multi-core debugging
> - [`docs/archive/session-notes/07_04_2026.md`](docs/archive/session-notes/07_04_2026.md) — differential testing, VITAL cascade fix, TPM, code review

---

## Current State (2026-05-14)

### What works

- **Dom0**: boots to login on 4 CPUs. Ubuntu Noble 6.8.0-107-generic. Stable.
- **Dom1 Linux (1 CPU)**: full systemd boot under Themis (emergency.target on local
  QEMU due to missing fstab — known, not a regression).
- **Dom1 Linux (2 CPUs)**: full systemd boot to login prompt. Verified 2026-04-14.
- **Eunomia as dom1**: ✅ boots under full Themis stack (capavisor + dom0 + CHV).
  23/24 tests pass. Timer fails (LAPIC one-shot not yet supported for child domains).
  Also boots standalone under CHV and QEMU. 6 workloads, 24 tests total.
- **Platform modularization**: complete. Opaque ArchDomainState/ArchPlatformState,
  aarch64 cross-check 0 errors. Generic monitor loop with SemanticExit dispatch.
- **AArch64 M1–M5c**: boot → memory → EL2 → GICv3 → guest → PSCI → Linux initramfs.
  M6 partial (full Ubuntu boot blocked by QEMU TCG overhead, needs real ARM HW).
- **Capability engine**: MAP_SELF implemented. 83 Lean theorems, 0 sorry.
  lean-exec 21/21 differential tests passing.
- **TPM attested boot**: Ed25519 + SHA-256 + TPM PCR extend. CRB/TIS auto-select.
- **CoCo guest kernel**: minimal config (245 modules), virtio/ext4/9p built-in.

### What doesn't work / known issues

- **Dom1 timer under Themis**: LAPIC one-shot timer for child domains not delivered.
  Eunomia timer workload fails. Likely needs capavisor to handle LVT/ICR writes
  and arm timerfd for child domain (not just dom0's timer path).
- **Dom1 emergency mode on QEMU**: fstab references missing partitions.
- **Unguarded interrupt injection**: 2 fallback paths without RFLAGS.IF check.
- **Posted interrupts**: hardware PI disabled (software PIR drain instead).
- **Dom1 on real hardware**: not yet tested.
- **KVM nested dom1**: CHV FailEntry under nested QEMU — only Themis backend works.

### Recent commits

- `866132c` — **fix: --kvm flag now rmmod's thhv to force KVM backend**
- `48ecad0` — **docs: add comprehensive dom0 README and update deploy docs**
- `e41e2c8` — **feat: revamp run-dom1.sh for CoCo-ready dom1 boot**
- `b3908a8` — **feat: auto-detect CoCo kernel for dom1 boot**
- `d9feb47` — **feat(thhv): add 'make tidy' target**
- `d9d8d25` — **fix: set MODULE_SIG_KEY path in minimal kernel config**
- `d2d6ea1` — **feat: add minimal CoCo guest kernel config (1750 → 245 modules)**
- `0100975` — **docs: update loom runtime estimates from actual measurements**
- `5b063da` — **refactor: merge cargo loom-all into cargo loom**
- `d810b15` — **feat(aarch64): M6 — ICC_SRE_EL2 fix, Stage-2 1G pages, full RAM mapping**
- `2613117` — **feat(aarch64): M5c — full initramfs boot with boot descriptor system**
- `f067053` — **feat(aarch64): cargo fetch-aarch64-kernel + auto-discover Linux Image**
- `f7e0e19` — **feat(aarch64): M5b — boot Linux kernel to rootfs panic**
- `81703b9` — **docs: update arm-porting-design.md with M4+M5a completion**
- `2f044b2` — **feat(aarch64): M5a — guest entry at EL1 with HVC trap loop**
- `ae9234c` — **feat(aarch64): M4 — GICv3 distributor, redistributor, CPU interface, ICH**
- `cab9626` — **feat(aarch64): M3b — EL2 MMU, exception vectors, sysregs, Stage-2**
- `011ed77` — **feat(aarch64): M3a — EL2 direct-boot with FDT parsing**
- `e20f2d2` — **feat(aarch64): M2 — memory partitioning + ThemisPlatform init**
- `d0fe7c4` — **feat: add cargo aarch64-themis / aarch64-iso xtask aliases**
- `9823d73` — **feat(aarch64): M1 — boot capavisor on QEMU aarch64 via Limine**
- `3ffc8b5` — **docs: add Multi-ISA build section to README**
- `0b03cfd` — **cfg-gate x86 code in platform.rs, main.rs, attestation.rs for multi-ISA**
- `5f1a188` — **cfg-gate x86-specific code in hypercall.rs for multi-ISA support**
- `b9da854` — **refactor: extract ArchDomainState and ArchPlatformState opaque types**
- `6f81c14` — **feat: ARM AArch64 skeleton + arch-neutral trait fixes**
- `0d03948` — **chore: update cloud-hypervisor submodule (unified SET_POLICY)**
- `097f59d` — **cleanup: remove old per-type policy opcodes, unified SET_POLICY only (-245 lines)**
- `5e5acdb` — **feat: THHV ioctl + CHV support for unified SET_POLICY**
- `fd1964d` — **feat: unified THEMIS_SET_POLICY hypercall (0x22)**
- `45285a7` — **fix: copy registers via InterruptPolicy.read_set on interrupt forward**
- `1114535` — **refactor: wire generic monitor loop, remove old dispatch (-405 lines)**
- `5f5f9d2` — **feat: generic monitor_loop with SemanticExit dispatch**
- `4c028a1` — **feat: SemanticExit types + ArchVpOps::run/handle_local**
- `a41ca13` — **fix: register_access_check branches on interrupt vs non-interrupt exit**
- `730756c` — **feat: store exit reason in VP metadata for policy lookup**

### Uncommitted changes

(none — all prior MAP_SELF work has been committed)

---

## Active Work Streams

### 1. Eunomia — minimal micro-kernel guest (active)

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
- ✅ Tested under full Themis stack: 23/24 tests pass

**Next**:
- [ ] Fix timer workload under Themis (LAPIC one-shot for child domains)
- [ ] Phase B: CoCo integration (shared.rs, MAP_SELF, CHANNEL_SEND workload)
- [ ] Phase C: Core-gapping workload (Forward policy, VMX preemption timer)

Commits: `19bff01` (timer fix), `6037171` (allocator), `b097b9f` (restructure),
`737828c` (scheduler), `9dc4cf6` (hv interface), `14340c6` (CHV boot),
`59dd2d6` (dom0 packaging).

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

### 3. Confidential VMs — CoCo (design complete, implementation pending)

Design doc: [`docs/architecture/confidential-vm.md`](docs/architecture/confidential-vm.md)

Dom1 memory private by default.  VTOM address-space split for explicit sharing.
No hardware encryption needed — EPT isolation provides equivalent protection.

**Design decisions (settled)**:
- VTOM (address-range split, not per-page C-bit)
- Guest-initiated sharing via ALIAS + MAP_SELF + CHANNEL_SEND
- MAP_SELF engine operation ✅ implemented (refcounted projections, 33 tests)

**Implementation plan**:
- [ ] Wire MAP_SELF hypercall in capavisor (apply_update for MapSelf batch)
- [ ] Wire CHANNEL_SEND / CHANNEL_RECV hypercalls in capavisor
- [ ] CPUID leaf 0x4000_0100 for Themis CoCo detection
- [ ] Capavisor EPT enforcement: remove HPAs from dom0 EPT after SEND
- [ ] Eunomia CoCo workload (shared.rs, shared buffer, dom0 read verification)
- [ ] Linux CoCo kernel patch: CC_VENDOR_THEMIS (~50 lines in arch/x86/coco/)
- [ ] swiotlb bounce buffer integration with VTOM

**Open questions**:
- VTOM bit position (bit 39 proposed, needs finalization)
- CPUID leaf number (0x4000_0100 proposed)
- Channel revocation semantics (does revoking endpoint cascade to sent caps?)

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
