## Themis — Implementation Status & Plan

> **Archives**: Previous todo content archived to:
> - [`capa-engine/docs/archived/09-03-2026/archived_todo.md`](capa-engine/docs/archived/09-03-2026/archived_todo.md) — phases 0–15, BUG-1–15, dom0 bringup
> - [`themis/docs/archive/27_03_2026.md`](themis/docs/archive/27_03_2026.md) — full history through dom1 multi-core debugging
> - [`themis/docs/archive/07_04_2026.md`](themis/docs/archive/07_04_2026.md) — differential testing, VITAL cascade fix, TPM, code review

---

## Current State (2026-06)

### What works

- **Dom0**: boots to login on 4 CPUs. Ubuntu Noble 6.8.0-107-generic. Stable.
- **Dom1 (1 CPU)**: full systemd boot (reaches emergency.target on local QEMU due
  to missing fstab partitions — known issue, not a regression).
- **Dom1 (2 CPUs)**: **full systemd boot to login prompt** (`multi-user.target`,
  `graphical.target`). Verified 2026-04-14 after full modularization.
- **Platform modularization complete**: Phase A7 done. Opaque ArchDomainState/
  ArchPlatformState types, aarch64 cross-check passes with 0 errors.
  See `themis/docs/platform-modularization.md`.
- **AArch64 M1 complete**: Limine UEFI boot, PL011 UART, memory map dump.
- **AArch64 M2 complete**: Memory partitioning, MetaAllocator, ThemisPlatform init.
- **AArch64 M3 complete**: EL2 direct-boot, MMU enabled (identity-mapped),
  exception vectors installed, EL2 sysregs (HCR/CPTR/timers), Stage-2 page
  tables (VTCR, Stage2Map, VTTBR). `cargo aarch64-direct`.
- **AArch64 M4 complete**: GICv3 distributor, redistributor, CPU interface (ICC),
  virtual interface (ICH) all initialized. Dynamic GICD/GICR addresses from FDT.
- **AArch64 M5a complete**: Guest entry at EL1, PL011 UART write from guest,
  HVC trap → EL2 handler → ERET back to guest. Full EL2→EL1→EL2 cycle verified.
  Vector table rewrite (trampoline pattern), Stage-2 walk fix (SL0=1), T0SZ fix.
- **AArch64 M5b complete**: Linux kernel boots fully on QEMU aarch64. PSCI v1.0
  (VERSION/CPU_ON/SYSTEM_OFF/SYSTEM_RESET/FEATURES/MIGRATE_INFO_TYPE/CPU_OFF/
  CPU_SUSPEND/AFFINITY_INFO). SMCCC v1.1 (VERSION/ARCH_FEATURES/TRNG_VERSION).
  Stage-2 device memory mapping (GIC, UART, virtio, PCIe ECAM, PCIe MMIO).
  T0SZ=24 (40-bit IPA) with concatenated root tables (8K, 1024 L1 entries).
  Linux boots to rootfs panic (expected — no initrd). GICv3 + timer + PCI all OK.
- **AArch64 M5c complete**: Full initramfs boot with boot descriptor system.
  QEMU launch script dynamically computes memory layout from ELF `__image_end`.
  Boot descriptor (TDBS) format provides module discovery (kernel, initrd) —
  no hardcoded addresses in Rust. FDT patcher adds initrd properties to /chosen.
  Linux unpacks initramfs, runs /init. x86 boot verified (no regression).
- **AArch64 M6 in progress**: Full Ubuntu distro boot on QEMU aarch64 (TCG).
  ICC_SRE_EL2 fix enables GIC interrupt delivery. Stage-2 uses 1G pages.
  Kernel boots, systemd starts ("Hostname set"), but full boot blocked by
  QEMU TCG Stage-2 overhead (~25x slower). Confirmed only 1 EL2 trap (SMC)
  occurs — overhead is purely software page walks, not trap storms. Needs
  ARM hardware with KVM to validate.
- **VITAL memory revocation** cascades domain cleanup correctly (fix: 5830fdacf).
- **Interrupt injection** guards against IF=0 and STI/MOV-SS blocking (fix: afca23206).
- **lean-exec differential testing**: 21/21 tests passing.
- **Lean formal spec**: 83 proved theorems, zero `sorry`.
- **TPM attested boot (P20)**: Ed25519 + SHA-256 + TPM PCR extend. CRB/TIS auto-select.

### What doesn't work / known issues

- **Dom1 emergency mode on local QEMU machine**: fstab references missing /boot,
  /boot/efi partitions → systemd enters emergency mode. Confirmed on both 1-CPU
  and 2-CPU dom1 (2026-04-14). Networking not configured in dom1 image.
- **Unguarded interrupt injection paths**: `forward_interrupt_to_handler` has 2
  fallback paths (Deliver + route-error) that write VMENTRY_INTERRUPTION_INFO
  without checking RFLAGS.IF. Saw transient exit-33 crash on 2-CPU run (did not
  reproduce on retry). Should add IF guard to all injection paths.
- **Posted interrupts**: hardware PI is disabled (software PIR drain used instead).
- **Dom1 on real hardware**: not yet tested.
- **thhv kernel headers**: must match dom0 kernel exactly. After image upgrade:
  `rm -rf themis/target/kheaders && bash themis/scripts/fetch-kheaders.sh`
  then clean rebuild `rm thhv/*.o thhv/*.ko thhv/src/*.o && cargo build-bins`.

### Recent commits

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

- `capa-engine/src/translation.rs` — Refcounted projection model: `RightsRefCount`,
  `SegmentMeta`, `add_contribution`/`remove_contribution`, all legacy methods
  updated to maintain `segment_meta`.
- `capa-engine/src/capability.rs` — `add_footprint`/`remove_footprint` helpers,
  `map_self` rewrite using contribution model, `mapped_gpas` tracking on accept paths.
  Removed `restore_snapshot` (no longer needed).
- `capa-engine/src/domain.rs` — Added `mapped_gpas: BTreeMap<LocalHandle, u64>`
  field to Domain (behind `address_translation` feature).
- `capa-engine/tests/unit/translation.rs` — 21 new refcounted projection unit tests.
- `capa-engine/tests/integration/translation.rs` — 12 new MAP_SELF integration tests.
- `capa-engine/docs/design/address_translation/address_translation.md` — §13 Refcounted
  Projection Model design doc.
- `capa-engine/docs/design/confidential-vm/confidential-vm.md` — Phase B step 1 marked done.

---

## Active Work

### ~~TODO: Implement VITAL cascade in Lean~~ ✅ Done (2f2df4af6)

### ~~TODO: Platform modularization (multi-ISA support)~~ ✅ Phases A-C, E, F Done

Design doc: [`themis/docs/platform-modularization.md`](themis/docs/platform-modularization.md)

**Completed**:
- Phases A1-A6: Trait seams (ArchVpOps, ArchGuestPhysMap, ArchCoreSignaling, ArchIommu, ArchBoot) + X86Platform impls
- Phases B1-B2: ArchExit translation, unified dom0/child dispatch via ExitPolicy
- Phases C1-C4: File reorganization (9 x86-specific files to `arch/x86_64/`)
- Phases E1-E6: Policy enforcement fixes + unified SET_POLICY (0x22) across full stack
- Phases F1-F3: Generic monitor loop with SemanticExit dispatch (-405 lines)
- Cleanup: Removed all old per-type policy paths (-245 lines)
- Phase A7: Full platform generification — opaque ArchDomainState/ArchPlatformState types,
  cfg-gated x86 code across platform.rs, hypercall.rs, main.rs, attestation.rs.
  **aarch64 cross-check: 0 errors.** x86 build clean.
- Phase D: ARM skeleton — aarch64 arch module with stub types (arch_state.rs)

**Remaining**:
- [x] Implement aarch64 serial console (PL011 UART) — M1 done
- [x] QEMU aarch64 testbed setup — M1 done (`cargo aarch64-themis`)
- [x] Implement aarch64 boot sequence (EL2, GICv3, Stage-2 tables) — M2-M4 done
- [x] Implement aarch64 VP lifecycle (EL2 entry/exit, SPSR/ELR) — M5a done
- [x] PSCI handling + Linux kernel loading — M5b done
- [x] Linux dom0 boot with initramfs — M5c done
- [ ] Full distro boot (blocked on QEMU TCG Stage-2 overhead) — M6 partial

### TODO: AArch64 backend (active)

Design doc: [`themis/docs/arm-porting-design.md`](themis/docs/arm-porting-design.md)

**M1–M5c complete**: boot, memory, EL2, MMU, vectors, Stage-2, GICv3, guest entry,
PSCI, Linux kernel boot, initramfs boot with boot descriptor system.

**M6 in progress**: Full Ubuntu distro boot. ICC_SRE_EL2 + ICH_HCR_EL2 configured
for direct-assign interrupt mode. Stage-2 uses 1G pages. Kernel boots, systemd
starts, but full boot blocked by QEMU TCG Stage-2 translation overhead (~25x).
Only 1 EL2 trap occurs (SMC/PSCI) — no trap storms. Needs ARM hardware with KVM.

Commits: `9823d73` (M1), `d0fe7c4` (aliases), `e20f2d2` (M2), `011ed77` (M3a),
`cab9626` (M3b), `ae9234c` (M4), `2f044b2` (M5a), `f7e0e19` (M5b),
`2613117` (M5c), `d810b15` (M6 partial).

**Next for ARM**: test on real ARM hardware with KVM to validate Stage-2 performance.

### TODO: Confidential dom1 design (CC_VENDOR_THEMIS + VTOM)

New item — design phase. Goal: dom1 runs with most memory exclusive to it
(dom0/CHV cannot read/write). Uses VTOM (Virtual Top of Memory) address-space
split:

- Below VTOM: private memory (CARVE+SEND, removed from dom0 EPT)
- Above VTOM: shared memory (ALIAS, dom0 retains access for virtio I/O)
- Guest kernel detects Themis CoCo via CPUID leaf → enables swiotlb bounce buffers
- ~50 line kernel patch to add CC_VENDOR_THEMIS to arch/x86/coco/core.c
- Same kernel binary for dom0 (no CoCo) and dom1 (CoCo enabled via CPUID)
- Key design decisions pending: VTOM bit position, CPUID leaf number, capavisor
  EPT enforcement

**MAP_SELF engine operation**: ✅ **Implemented.** Refcounted projection model
(`add_footprint`/`remove_footprint`), per-cap GPA tracking (`mapped_gpas`),
snapshot-diff → UpdateBatch. 12 integration tests + 21 unit tests pass.
Files: `translation.rs`, `capability.rs`, `domain.rs`.
Next: wire MAP_SELF to capavisor hypercall (Phase B step 2).

### ~~Phase 3: VMEXIT dispatch unification~~ ✅ Subsumed by modularization (Phases B+F)

Merged dom0/child dispatch into unified ExitPolicy-based dispatch (Phase B2),
then restructured into generic monitor loop with SemanticExit (Phase F1-F3).
No more `domain_id != 0` special-casing.

### Phase 4: Posted interrupts (hardware PI)

**Goal**: Enable hardware posted interrupts for child VMs.

**Prerequisites** (from `testing-posted.md`):
- [ ] Add `intel_iommu=on` to host kernel cmdline (requires reboot)
- [ ] QEMU: `intel-iommu,intremap=on,caching-mode=on,device-iotlb=on,aw-bits=48`
- [ ] QEMU: `-cpu host,host-phys-bits=on`
- [ ] QEMU: virtio devices with `iommu_platform=on,ats=on`
- [ ] Re-enable PI bit 7 in vmcs.rs child pin-based controls
- [ ] Remove software PIR drain guard (or keep as fallback)
- [ ] Test 1-vCPU and 2-vCPU dom1 boot with hardware PI

### Phase 5: Stabilization + real hardware

- [ ] Test with 4 CPUs
- [ ] Test on real hardware (not nested KVM)
- [ ] Dom1 networking (ping 192.168.100.2 from dom0)
- [ ] Document what works on nested vs real hardware
- [ ] Update `HANDOFF.md`

### Future work

- [ ] Per-VP irqfd: struct updated, needs end-to-end test
- [ ] Paravirt timer (PV MMIO hypercall, P16.6d3)
- [ ] Reduce serial I/O overhead
- [ ] CPUID policy in DomainPolicy (P16.6c)
- [ ] Stock cloud image kernel

### ~~Full TPM attestation with user binding (P20j)~~ ✅ Done

Design doc: [`capa-engine/docs/design/attestation/attestation.md §14`](capa-engine/docs/design/attestation/attestation.md)

Two-layer attestation model complete: TPM2_Quote (platform) + Ed25519-signed
domain reports (capavisor) with user public key binding. All 7 sub-tasks done.
Graceful degradation: no TPM → Ed25519-only.

---

## Reference

### Design documents

| Document | Path | Content |
|----------|------|---------|
| **Interrupt Virtualization** | `capa-engine/docs/design/interrupt-virtualization.md` | Single source of truth: goals, HW background, routing model, gap analysis, nested-virt scheduling, quantum-sched, Directvisor reference, 3 delivery bugs |
| **Attestation** | `capa-engine/docs/design/attestation/attestation.md` | Two-layer TPM + Ed25519 model |
| **Address Translation** | `capa-engine/docs/design/address_translation/address_translation.md` | EPT/IOMMU design |
| **ARM Porting** | `themis/docs/arm-porting-design.md` | ARM GICv4 as PI equivalent |

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
