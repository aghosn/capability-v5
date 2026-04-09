## Themis — Implementation Status & Plan

> **Archives**: Previous todo content archived to:
> - [`capa-engine/docs/archived/09-03-2026/archived_todo.md`](capa-engine/docs/archived/09-03-2026/archived_todo.md) — phases 0–15, BUG-1–15, dom0 bringup
> - [`themis/docs/archive/27_03_2026.md`](themis/docs/archive/27_03_2026.md) — full history through dom1 multi-core debugging
> - [`themis/docs/archive/07_04_2026.md`](themis/docs/archive/07_04_2026.md) — differential testing, VITAL cascade fix, TPM, code review

---

## Current State (2026-04-07)

### What works

- **Dom0**: boots to login on 4 CPUs. Ubuntu Noble 6.8.0-107-generic. Stable.
- **Dom1 (1 CPU, bare-metal Linux/KVM)**: **full systemd boot to login prompt**.
  Stock Ubuntu 6.8.0-107-generic kernel + initramfs. virtio-blk, virtio-net,
  ext4 mount, systemd services all complete.
- **Dom1 (2 CPUs, bare-metal Linux/KVM)**: **full systemd boot to login prompt**.
  Both CPUs activated (12000 BogoMIPS), SMP bringup succeeds via SIPI through
  APIC_ACCESS exit interception and IPI routing.
  *Note*: emergency mode on local QEMU machine (fstab references missing /boot,
  /boot/efi partitions) — needs verification on remote.
- **VITAL memory revocation** cascades domain cleanup correctly (fix: 5830fdacf).
- **Interrupt injection** guards against IF=0 and STI/MOV-SS blocking (fix: afca23206).
- **lean-exec differential testing**: 21/21 tests passing.
- **Lean formal spec**: 83 proved theorems, zero `sorry`. Covers CDT preservation,
  N-level isolation, execute protocol, global system invariant, deep revocation cascade.
- **TPM attested boot (P20)**: Ed25519 keygen + SHA-256 measurement + TPM PCR extend
  at capavisor _start(). Signed attestation hypercall (ATTEST_SELF with nonce).
  On-demand domain config via ATTEST_SELF(nonce=0). TPM driver supports both
  **CRB** (default) and **TIS** transports, auto-selected via ACPI StartMethod.
  QEMU swtpm integration (CRB default, `QEMU_TIS=1` for TIS). thhv ioctls for
  ATTEST_SELF + READ_PCR. Full crypto verification test (Ed25519 + TPM RSA-2048
  via OpenSSL EVP).
  **Verified end-to-end**: boot + ATTEST_SELF → 52 mem_caps + 1 dom_cap +
  50 PA map entries loaded by thhv driver with zero errors.

### What doesn't work / known issues

- **Dom1 emergency mode on local QEMU machine**: fstab references missing /boot,
  /boot/efi partitions → systemd enters emergency mode. Needs investigation on
  remote machine.
- **Dom1 2-vCPU hangs after virtio_blk on local machine**: needs investigation on
  remote.
- **Posted interrupts**: hardware PI is disabled (software PIR drain used instead).
  The host advertises PI support but L2 delivery is unreliable under nested KVM.
  Requires `intel_iommu=on` on host kernel cmdline + QEMU IOMMU flags. See
  `testing-posted.md` for details.
- **Dom1 on real hardware**: not yet tested.

### Recent commits

- `2f2df4a` — **fix: Lean VITAL cascade fully revokes domain memory caps and cleans parent tree**
- `a268a40` — **docs: thhv function documentation, stale TODOs, sentinel constant**
- `9a3f056` — **Bumping cloud hypervisor**
- `d07600a` — **chore: remove nested bzImage override from run-dom1.sh**
- `afca232` — **fix: guard interrupt injection against IF=0 and STI/MOV-SS blocking**
- `5830fda` — **fix: VITAL memory revocation now cascades domain cleanup**
- `4b95cf9` — **docs: TODO — implement VITAL cascade in Lean, revert workarounds**
- `9967ee1` — **docs: update todo.md — 21/21 differential tests passing**
- `302f38d` — **fix: Lean META revoke, GPA mapping, overlap check — 21/21 tests pass**
- `5fc31fe` — **feat: dom1 full systemd boot with stock kernel**
- `dc48a67` — **fix: lost-wakeup race in thhv HLT + irqfd VP routing**
- `4968b9a` — **fix: 2-vCPU dom1 boot — APIC emulation, EOI, IPI routing**
- `440bafe` — **fix: Lean channel attest, forwarding, accept-removes-sender (19/21)**

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

### Phase 3: VMEXIT dispatch unification

**Goal**: Merge the two `match basic_reason` blocks in `handle_vmexit` (child
vs dom0) into a single dispatch table per `skills/code-review.md`.

**Approach** (incremental, avoid the all-at-once rewrite that broke dom0):
1. Extract dom0-specific local handlers into named functions (`handle_rdmsr_local`,
   `handle_cr_access_local`, `handle_ept_violation_dom0`, etc.)
2. Test each extracted function independently (dom0 must still boot)
3. Add `has_parent` flag and merge the dispatch, calling shared handlers from
   both paths
4. Remove the old child block once all handlers are merged

**Key pitfall** (discovered 2026-04-03): dom0 EPT violation handler has IOAPIC
MMIO emulation logic. Calling `forward_child_exit` for dom0 deadlocks because
dom0 has no parent. Must handle locally.

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
- [ ] Attestation: test with real TPM (bare metal or working swtpm probe)

### Full TPM attestation with user binding (P20j)

Design doc: [`capa-engine/docs/design/attestation/attestation.md §14`](capa-engine/docs/design/attestation/attestation.md)

**Goal**: Complete the two-layer attestation model — TPM2_Quote (platform proof)
bundled with Ed25519-signed domain reports (capavisor proof), with user public key
binding to prevent cross-user attestation replay.

**Two-layer model**:
- **Layer 1 (Platform)**: TPM2_Quote(AK, nonce, PCR[11]) — TPM signs PCR values
  with an RSA-2048 Attestation Key. Proves the capavisor binary + pub_key are
  running on genuine hardware.
- **Layer 2 (Domain)**: Ed25519 sign SHA-256(report ‖ nonce ‖ user_pub_key) — the
  capavisor signs the domain configuration for a specific verifier.

**Key design decisions**:
- `ATTEST_SELF` nonce=0 path unchanged (unsigned PA map for thhv init)
- Signed path uses DomainComm TX ring to pass `{nonce, user_pub_key}` (64 bytes)
- VMCALL `arg0=1, arg1=sequence` — flag + TX ring sequence number
- Defense in depth: thhv mutex (cooperative) + capavisor sequence verification (A2)
- RSA-2048 AK under Owner hierarchy
- Graceful degradation: no TPM → Ed25519-only (tpm_quote_size=0)

**Todos**: All complete.
- [x] P20j-1: TPM driver — `TPM2_CreatePrimary` (RSA-2048) + `TPM2_Quote` commands
- [x] P20j-2: Capavisor — AK creation at boot after PCR_Extend in `try_tpm()`
- [x] P20j-3: ABI — extend `SignedAttestReport` with user_pub_key + TPM quote fields
- [x] P20j-4: Hypercall — `do_attest_self` reads `AttestRequest` from TX ring, sequence verify
- [x] P20j-5: thhv — mutex + TX enqueue + RX dequeue for signed attestation ioctl
- [x] P20j-6: Userspace test — Ed25519 + RSA-2048 crypto verification (test_attestation.c)
- [x] P20j-7: Documentation — attestation.md + todo.md updated

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
