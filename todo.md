## Themis — Implementation Status & Plan

> **Archives**: Previous todo content archived to:
> - [`docs/archive/todos/archived_todo_09_03_2026.md`](docs/archive/todos/archived_todo_09_03_2026.md) — phases 0–15, BUG-1–15, dom0 bringup
> - [`docs/archive/session-notes/27_03_2026.md`](docs/archive/session-notes/27_03_2026.md) — full history through dom1 multi-core debugging
> - [`docs/archive/session-notes/07_04_2026.md`](docs/archive/session-notes/07_04_2026.md) — differential testing, VITAL cascade fix, TPM, code review

---

## Current State (2026-05-26)

### What works

- **Dom0**: boots to login on 4 CPUs. Ubuntu Noble 6.8.0-107-generic. Stable.
- **Dom1 Linux (1 CPU)**: full systemd boot under Themis (emergency.target on local
  QEMU due to missing fstab — known, not a regression).
- **Dom1 Linux (2 CPUs)**: full systemd boot to login prompt. Verified 2026-04-14.
- **Eunomia as dom1**: ✅ boots under full Themis stack (capavisor + dom0 + CHV).
  All 33/33 tests pass (incl. timer via TSC-deadline, CPUID). 7 workloads.
  `cargo build-bins` now rebuilds Eunomia workloads before packaging.
- **ivshmem doorbell pipeline**: ✅ **end-to-end working (2026-05-26)**. CHV
  ivshmem multi-device, CPUID discovery, deferred IOEVENTFD (with fd-clone
  fix), shmem ALIAS mapping, RING_DOORBELL VMCALL → synthetic exit →
  DomainComm notify → thhv RX drain → CHV listener. All 5 eunomia
  doorbell rings delivered, clean ACPI shutdown.
- **Platform modularization**: complete. Opaque ArchDomainState/ArchPlatformState,
  aarch64 cross-check 0 errors. Generic monitor loop with SemanticExit dispatch.
- **AArch64 M1–M5c**: boot → memory → EL2 → GICv3 → guest → PSCI → Linux initramfs.
  M6 partial (full Ubuntu boot blocked by QEMU TCG overhead, needs real ARM HW).
- **Capability engine**: MAP_SELF implemented (refcounted projections, 33 tests).
  83 Lean theorems, 0 sorry. lean-exec 21/21 differential tests passing.
  GPA-aware view_diff with lazy dirty-flag caching.
- **TPM attested boot**: Ed25519 + SHA-256 + TPM PCR extend. CRB/TIS auto-select.
- **CoCo guest kernel**: CC_VENDOR_THEMIS patch in `../linux`.  Minimal config
  (245 modules), virtio/ext4/9p built-in.
- **MAP_SELF hypercall**: wired across themis-abi (0x1f), capavisor handler, thhv.
- **COMM-as-SEND + DomainComm**: ✅ COMM pages provisioned via CARVE+SEND (commit
  `1d9867d8d`). CHV slot splitting for confidential memory (commit `235ed4c81`).
  `domcomm_discover` and `attest_dequeue` Eunomia tests pass.
- **Compound allocation batching** (uncommitted): thhv uses `alloc_pages(order)` for
  META and COMM pages. Contiguous runs merged into single CARVE+SEND. Reduces
  attestation cap count from ~128 to ~24.
- **CPUID/MSR interposition policy**: ✅ fully policy-driven. All CPUID leaves
  (including hypervisor range) go through PolicyDriven path. No ArchHandled special
  case. CHV pushes Native/Emulate overrides for dom1. CoCo leaf (0x40000100)
  returns dynamic VTOM bit = MAXPHYADDR-1.
  `cargo diff-test` (from capa-cli/) runs automated Rust-vs-Lean differential
  testing on all 16 tutorials.
- **Dom1 CoCo detection**: ✅ kernel detects CC_VENDOR_THEMIS, reads VTOM bit 38.
- **MMIO VTOM stripping**: ✅ IO-APIC reads correctly (`version 17, GSI 0-23`)
  after stripping VTOM bit in CHV's handle_mmio_exit and emulator translate_gva.
- **VTOM EBDA double-map**: ✅ CHV double-maps ACPI/EBDA region at VTOM-offset GPA
  so CoCo kernel can access firmware tables with VTOM bit set.
- **GPA-native view computation**: ✅ ViewRegion carries both GPA (`access.start`)
  and HPA (`physical_start`). `ensure_view_fresh()` translates HPA→GPA via
  address_map entries (identity fallback when uncovered). `view_diff` produces
  {GPA, HPA} ChangeRights directly. Same-HPA-at-two-GPAs (VTOM double-map)
  naturally produces two view regions. Tutorial 17 validates. Removed
  `snapshot_view`, `translate_view_to_gpa`, `fixup_domain_addresses` from
  carve/send/accept (kept in revoke for tree-walk updates).
- **Lazy view caching**: ✅ `Domain.view_dirty` flag — mutations mark dirty,
  `ensure_view_fresh()` recomputes only when read. Eliminates redundant
  double-recomputation. No loom gate — full correctness under loom.
- **Cross-domain revoke cleanup**: ✅ `remove_memory_capability_by_ref()` eagerly
  removes capability from child domain's table using `Weak::ptr_eq` (can't use
  prune since Arc is still alive on revoke_child's stack).

### What doesn't work / known issues

- **Dom1 virtio-blk rootfs failure**: kernel boots fully (ACPI, PCI, 2 CPUs) but
  panics at VFS mount — `/dev/vda1` shows as `unknown-block(0,0)` error -6.
  Virtio-blk not registering; likely transport negotiation or IOMMU/DMA issue.
  **Must fix before CoCo e2e.**
- **Unguarded interrupt injection**: 2 fallback paths without RFLAGS.IF check.
- **Posted interrupts**: hardware PI disabled (software PIR drain instead).
- **Dom1 on real hardware**: not yet tested.
- **KVM nested dom1**: CHV FailEntry under nested QEMU — only Themis backend works.
- **CoCo share-back**: MAP_SELF wired, channels wired (GET/SEND/ACCEPT).
  Not yet tested end-to-end. Need Eunomia workload first.

### Recent commits

- `985c1bf83` — **Slim intercept message: ExitPolicy.read_set enforcement**:
  InterceptMessage 120B→64B (exit metadata only), thhv assembles full msg
  from slim + COMM page regs. Registers gated by read_set. Dom1 boots OK.
- `9c13207af` — **Structured attestation API and CoCo workload fixes**:
  `build_structured_attestation()` in engine as single source of truth,
  `to_bytes()` binary serialization, capavisor `do_attest_self` rewritten
  to use engine API, eunomia CoCo tests all 4 pass
- `1d9867d8d` — **COMM-as-SEND redesign**: DomainComm pages provisioned via
  CARVE+SEND, domcomm finalization on first hypercall, CHV confidential cleanup
- `235ed4c81` — **CHV: confidential memory slot splitting** (cloud-hypervisor submodule)
- `HEAD` — **CHV: gate CoCo features on confidential mode**
  (vtom_bit=0 when !confidential, EBDA/CoCo-CPUID/VTOM-stripping gated)
- `8d3dd56f` — **CHV: confidential mode — CARVE guest RAM instead of ALIAS**
  (`--platform confidential=on`, MMIO classification, run-dom1.sh flag)
- `7ec460f` — **Wire channel hypercalls: GET_CHAN, SEND_CHAN, ACCEPT_CHAN**
  (capavisor handlers, thhv wrappers, auto-provision parent-back-channel)
- `e962a89` — **capa-engine: GPA-native view computation redesign**
  (ViewRegion carries {GPA, HPA}, ensure_view_fresh translates via address_map,
  removed snapshot_view/translate_view_to_gpa, cleaned fixup from carve/send/accept)

---

---

### ~~BUG-16: vtom_double_map~~ ✅ Fixed

Fixed in commit `9c13207af`. Root causes: (1) attestation reported HPA in both
GPA and HPA fields — fixed by using `mapped_gpas` via structured attestation API;
(2) unnecessary `map_4k` call on identity-mapped addresses — removed;
(3) `send_chan` vs `send` confusion in bounce_buffer_send — corrected.

---

## Tech Debt (must address)

- **capavisor/src/hypercall.rs cleanup**: `forward_child_exit`, `do_switch`,
  and `forward_interrupt_to_handler` have grown into multi-hundred-line
  functions mixing capa-engine calls, COMM-page marshaling, I/O-qual decoding,
  VMCS swap, and ad-hoc debug instrumentation. Extract helpers (COMM-page
  marshal, IO exit-qual decode, VMCS swap) and rip out the DB-* trace
  scaffolding once the doorbell bug is fixed. Quality is not acceptable as-is.

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

**What needs implementation (ACPI firmware double-map)**:
- [x] CHV: double-map EBDA (0xA0000–0xFFFFF) at VTOM-offset GPA during
      initialization (committed CHV `bc2ccfe`)
- [x] Engine: GPA-aware view_diff handles same-HPA-at-two-GPAs correctly
      (committed `2b34aad`, `84bfaed`, `53d7b1e`)
- [ ] **NEXT**: Boot dom0 + CoCo dom1, verify kernel gets past ACPI table parsing

**What needs implementation (CoCo end-to-end)**:
- [x] CHV: `--platform confidential=on` flag. Guest RAM → CARVE, MMIO → ALIAS.
- [x] Capavisor: wire CHANNEL GET/SEND/ACCEPT hypercalls (0x1e, 0x20, 0x21)
- [x] thhv: auto-provision parent-back-channel at domain creation
- [x] CHV: gate VTOM/EBDA/CoCo-CPUID on confidential mode (vtom_bit=0 when off)
- [ ] Eunomia CoCo workload: domcomm+attest+vtom_double_map+bounce_send all pass ✅
      Structured attestation API in engine (single source of truth).
- [ ] thhv: receive pending capability from child (wait for event, ACCEPT_CHAN)
- [ ] CHV: receive shared regions back from dom1 (accept alias via channel)
- [ ] Dom1 kernel: early init share-back — create aliases of swiotlb pool,
      MAP_SELF at VTOM GPA, CHANNEL_SEND the other to dom0
- [ ] End-to-end: Linux dom1 boots with CC_VENDOR_THEMIS, swiotlb active,
      virtio works through shared bounce buffers

**Open questions**:
- Channel revocation semantics (does revoking endpoint cascade to sent caps?)
  → Resolved: yes, CDT cascades naturally (see design doc §9.8)
- [x] **Intercept message register leak fix** (commit `985c1bf83`):
  Slim `InterceptMessage` (120B → 64B, exit metadata only). thhv assembles
  full message from slim + COMM page registers. `ExitPolicy.read_set` is now
  the single gate for register exposure. Dom1 Linux boots successfully.
- [x] **ExitPolicy in attestation** (uncommitted):
  Added Exit Policy section to attestation reports (both Rust engine and Lean
  executable model). Shows default action + per-reason overrides with trap/read_set/
  write_set bitmaps. Lean `setPolicy`/`getPolicy` supports `exit-default-trap`.
  Differential test passes (15/17 tutorials — 2 pre-existing view failures).
  Rust CLI `parse_policy_id` supports `exit-default-trap`, `exit-reason-trap:<N>`,
  `exit-read:<reason>:<word>`, `exit-write:<reason>:<word>`.
- **Refine per-exit-reason policies for confidential mode**: The default
  ExitPolicy uses `RegBitmap::ALL` (read & write) for child domains.
  When booting dom1 Linux in confidential mode, the child (or its
  creation policy) should restrict read_set/write_set per exit reason
  so the parent can only see/modify the registers actually needed
  (e.g., IO exits → RAX only; CPUID → RAX/RCX; MSR → RCX/RAX/RDX).
  Infrastructure is fully wired (`set_policy` hypercall, `ExitReasonRegReadSet`,
  `ExitReasonRegWriteSet`); only needs concrete policy definitions.
- **Future optimization**: mmap COMM page to CHV userspace so CHV reads
  registers directly without ioctl round-trips. Would eliminate thhv
  register-assembly step entirely.

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

### 5. Inter-domain shared memory / ivshmem doorbell (active)

**Design doc**: [`docs/architecture/ivshmem-doorbell.md`](docs/architecture/ivshmem-doorbell.md)

**What works**:
- [x] CHV ivshmem multi-device support + capability-backed shmem (ALIAS)
- [x] Shmem registration folded into SET_GUEST_MEMORY (shmem_mode flag)
- [x] thhv REGISTER_DOORBELL VMCALL + DomainComm notification pipeline
- [x] CPUID leaf 0x40000004 for ivshmem device discovery (BAR0/BAR2 GPAs)
- [x] Eunomia ivshmem module: discover devices, read BAR0/BAR2
- [x] Deferred IOEVENTFD registration (after domain creation, before seal)
- [x] CHV doorbell eventfd listener thread
- [x] Doorbell registration reaches capavisor (doorbells matched correctly)
- [x] CHV squashed to 2 logical commits (CoCo gating + doorbell pipeline)
- [x] RING_DOORBELL VMCALL → synthetic exit → context switch to parent
- [x] **End-to-end doorbell pipeline working (2026-05-26)**:
      eunomia rings → capavisor exits to dom0 → thhv drains DomainComm RX →
      signals matching eventfd → CHV listener fires → all 5 rings (0x42..0x46)
      delivered. All 5 eunomia tests pass, clean ACPI shutdown.

**Root cause of the multi-week shutdown bug (fixed 2026-05-26)**:
In `cloud-hypervisor/hypervisor/src/themis/mod.rs::register_ioevent` deferred
path, `ThhvIoeventfd.fd` stored the *original* caller-supplied raw fd. The
caller (e.g. `add_ivshmem_device`) dropped its `EventFd` immediately on
return, closing that fd number. During the ~600 ms window before
`ensure_initialized()` flushed pending ioeventfds, the closed fd number got
reassigned to a clone of `exit_evt`. At flush time, `THHV_IOEVENTFD` ioctl
did `eventfd_ctx_fdget(stale_fd)` and registered the doorbell against
`exit_evt`'s `eventfd_ctx`. First doorbell ring → `eventfd_signal()` on
`exit_evt` → `EpollDispatch::Exit` → `Vm::shutdown` → vcpu killed.

**Fix**: store `fd_clone.as_raw_fd()` in `ioevent.fd` for the deferred path.
The clone is kept alive in `pending_ioeventfds._owner` until flush, so its
fd number remains valid. Diagnosed via strace timing (600 ms gap between
defer and flush) + thhv-side `ctx` pointer logging.

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
