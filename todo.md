## Themis — Implementation Status & Plan

> **Archives**: Previous todo content archived to:
> - [`docs/archive/todos/archived_todo_09_03_2026.md`](docs/archive/todos/archived_todo_09_03_2026.md) — phases 0–15, BUG-1–15, dom0 bringup
> - [`docs/archive/session-notes/27_03_2026.md`](docs/archive/session-notes/27_03_2026.md) — full history through dom1 multi-core debugging
> - [`docs/archive/session-notes/07_04_2026.md`](docs/archive/session-notes/07_04_2026.md) — differential testing, VITAL cascade fix, TPM, code review

## Current Status

- **2026-07-17 — capa-engine domain API test migration** ✅ DONE. Updated default-feature tests for the platform-first `Capability::<Domain>` API and tuple-return signatures; `cd capa-engine && cargo test --no-run` now succeeds.

  Files modified this session:
  - `capa-engine/tests/concurrency/platform.rs` — passed `TestPlatform` into domain API calls under default features.
  - `capa-engine/tests/integration/api.rs` — migrated create/seal/carve/alias/send/revoke/revoke_domain calls and tuple destructuring.
  - `capa-engine/tests/integration/comm.rs` — migrated register_comm/carve/alias/create/seal/revoke/send calls and tuple destructuring.
  - `capa-engine/tests/integration/end_to_end.rs` — migrated create/seal/carve/alias/switch calls and tuple destructuring.
  - `capa-engine/tests/integration/interrupt.rs` — migrated create/seal call sites to the platform-first API.
  - `capa-engine/tests/integration/meta.rs` — migrated send/carve/alias/accept/revoke call sites and tuple destructuring.
  - `capa-engine/tests/integration/overlap.rs` — migrated carve/alias call sites and 3-tuple destructuring.
  - `capa-engine/tests/integration/revoke.rs` — migrated create/send/seal/carve/alias/revoke call sites and tuple destructuring.
  - `capa-engine/tests/integration/send_bugs.rs` — migrated create/seal/carve/send call sites.
  - `capa-engine/tests/integration/send_pending.rs` — finished remaining platform-first send/accept/reject/carve/revoke calls.
  - `capa-engine/tests/integration/translation.rs` — migrated translation tests to the platform-first domain API and updated tuple destructuring.
  - `capa-engine/tests/integration/vital_cascade.rs` — migrated create/seal/carve/send/revoke call sites.
  - `capa-engine/tests/integration/vital_revoke.rs` — migrated create/carve/alias/send/seal/revoke call sites.
  - `capa-engine/tests/unit/attest.rs` — added shared test platform usage for create/seal call sites.
  - `capa-engine/tests/unit/channel.rs` — migrated get_chan/attest/send_channel/accept_channel/switch and related tuple destructuring.
  - `capa-engine/tests/unit/domain.rs` — migrated create/seal/revoke_domain/set_policy/get_policy call sites.
  - `capa-engine/tests/unit/set_get.rs` — migrated helper/test set_policy/get_policy/set_register/get_register usage.
  - `capa-engine/tests/unit/switch.rs` — migrated switch/deliver_interrupt_vp call order and helper create/seal usage.

---

## RESUME NEXT: port + build dom1 (CoCo guest kernel) on this machine (2026-06-23)

Status on this machine: eunomia + attestation work. dom1 **root disk** and
**firmware** auto-fetch, but the **CoCo guest kernel is NOT built yet**:
`../linux` fork absent, `themis/guest/kernel/bzImage` absent, `/nested` empty in
`bins.img`. dom1 boots from `/opt/bins/nested/bzImage` (built-in virtio/ext4/9p,
no initramfs) + `/opt/bins/dom1/dom1.raw`.

Steps to run when resuming:

1. **Clone the kernel fork** next to the repo (default `LINUX_DIR=../linux`):
   ```bash
   cd ~/Documents/Programs/MSR        # parent of capability-v5
   git clone https://github.com/aghosn/linux.git
   cd linux && git checkout v6.19.14-themis
   ```
2. **Install kernel build deps** (host is jammy 22.04; gcc-11/12 builds 6.19 fine):
   ```bash
   sudo apt install -y build-essential flex bison libssl-dev libelf-dev bc dwarves
   ```
3. **Build the bzImage** from repo root → installs to `themis/guest/kernel/bzImage`:
   ```bash
   cd ~/Documents/Programs/MSR/capability-v5
   cargo build-kernel                 # KERNEL_PROFILE=minimal (default)
   # add modules if dom1 needs them:  TARGETS=all cargo build-kernel
   ```
4. **Pack into bins.img** — `update-bins.sh` auto-detects `guest/kernel/bzImage`
   and copies it to `/nested/bzImage`:
   ```bash
   cargo build-bins-docker            # repacks bins.img (includes nested kernel)
   # or just: NESTED_KERNEL=themis/guest/kernel/bzImage bash themis/scripts/update-bins.sh
   ```
5. **Reboot the stack** (`cargo themis`), then **inside dom0**:
   ```bash
   sudo /opt/bins/cloud-hypervisor/run-dom1.sh           # --themis auto if /dev/thhv
   ```
   Auto-picks `/opt/bins/nested/bzImage` + `dom1.raw`. Use `--kvm` to isolate
   kernel vs Themis if it panics.

Refs: `themis/scripts/build-kernel.sh`, `themis/scripts/README.md:183-251`,
`docs/building.md:144`. Fork branch `v6.19.14-themis` has `CONFIG_THEMIS_COCO=y`.
This is also where x2APIC fast-path boot validation gets exercised (per-child,
when dom1 boots — watch capavisor `CPU features:` + `FEATURE_X2APIC_VIRT`, no
`VIRTUALIZE_X2APIC_MODE`/`VID not supported` WARN).

---

## x2APIC fast-path — bare-metal prerequisites CONFIRMED (2026-06-23)

Context: commit `24c29d37e` added the child x2APIC fast path (children boot in
x2APIC mode so self-IPI `WRMSR(0x83F)` is hardware-handled under VID, zero
exits). It was **dormant on the WSL2/Hyper-V dev box** because nested L0 there
does not expose the APICv VMX bits. Gating lives in
`capavisor/src/arch/x86_64/vmcs/controls.rs:109-112` (`x2apic_virt_hw` =
`IA32_VMX_PROCBASED_CTLS2` allowed-1 bits **4** `VIRT_X2APIC_MODE`, **8**
`APIC_REGISTER_VIRT`, **9** `VID`) and `crates/vmx/src/features.rs`
(`has_x2apic_virt()`); `vmexit/cpuid.rs:83` advertises `FEATURE_X2APIC_VIRT`
to dom0/CHV only when all three are present.

On **this bare-metal machine** (asmodai), all prerequisites are GREEN:
* No `hypervisor` CPUID flag (true bare metal); host has `vmx` + `x2apic`.
* `IA32_VMX_PROCBASED_CTLS2` (0x48B) allowed-1 = `0x0f5d7fff` → bits 4, 8, 9
  (and 0) all **SET**.
* KVM: `kvm_intel` `nested=Y`, `enable_apicv=Y`, `ept=Y` — so KVM should pass
  APICv through to capavisor (L1) under `cargo themis` (`-enable-kvm -cpu host`).

Probe script saved at `/tmp/check-x2apic-bits.sh` (reads + decodes the cap MSR;
exit 0 = fast path will activate).

**Next step (deferred):** boot `cd themis && cargo themis 2>&1 | tee /tmp/out.txt`
and confirm in the capavisor serial: (a) `CPU features:` shows x2APIC virt,
(b) NO `[WARN] VIRTUALIZE_X2APIC_MODE not supported` / `VID not supported`
(controls.rs:138-148), (c) `FEATURE_X2APIC_VIRT` advertised. Fast path is
per-**child**, so it's exercised when **dom1** boots.

---

## Build-env fix (2026-06-23) — `cargo build-bins-docker` resilience

After syncing missing commits, `build-bins-docker` failed in four independent
spots; all fixed (uncommitted). Modified files:

* **`themis/scripts/build-bins-docker.sh`** — a host-side header **prefetch**
  was tried and **reverted**. The container is `ubuntu:24.04` (noble), the same
  distro as dom0, so it is the *authoritative* source for the noble headers that
  must match dom0's noble kernel. Prefetching on the host (asmodai = jammy 22.04)
  pulled **jammy-HWE** headers (`~22.04.1`) → distro mismatch. The fix was simply
  to rebuild the `themis-build:latest` image so its apt index is fresh enough to
  see `6.8.0-124`; the container then fetches **noble** headers itself.
* **`themis/scripts/fetch-kheaders.sh`** — now also fetches the **common**
  headers package, discovered from the `-generic` package's `Depends`
  (noble GA: `linux-headers-<abi>`). Both are extracted side-by-side under
  `usr/src/` so the relative symlinks (e.g. `scripts/Makefile.ubsan`) resolve;
  added a check that verifies this. Confirmed pulling noble `6.8.0-124.124` from
  `noble-updates/main` (not jammy).
* **`Dockerfile.build`** — added `gcc-12` (harmless; noble `6.8.0-124` is
  actually built with **gcc-13**, which the image already ships, so the compiler
  now matches the kernel — no vermagic/ABI issue).
* **`themis/scripts/update-bins.sh`** — auto `e2fsck -fp` on `guest/bins.img`
  before the fuse2fs mount; interrupted builds left it unclean and fuse2fs
  refused to mount it.

Result: full `cargo build-bins-docker` is green — `thhv.ko` (2.1 MB, vermagic
`6.8.0-124-generic`, noble) builds and `guest/bins.img` repacks. Verified the
`.ko` packed into `themis/guest/bins.img` is byte-identical to the build output.

### thhv/dom0 kernel reconciliation (2026-06-23)
dom0 ran noble `6.8.0-107-generic`; thhv built/pinned at `6.8.0-124-generic` →
`insmod` failed (modversions CRC mismatch, no `/dev/thhv`). Chose **option B**:
upgraded dom0. Installed `linux-image/linux-modules-extra-6.8.0-124-generic` in
dom0, `update-grub` (124 = top entry, `GRUB_DEFAULT=0`). Pin stays `6.8.0-124`.
**Next:** reboot the stack so dom0 boots 124, then
`sudo insmod /opt/bins/thhv/thhv.ko`, confirm `/dev/thhv`, run eunomia.

---

## Current State (2026-06-04)

### Just-completed CHV-themis cleanup arc (committed)

The cloud-hypervisor Themis backend is fully refactored and deduped:

* **File split** (Phases 1–8): `cloud-hypervisor/hypervisor/src/themis/` is now
  10 focused files (`mod.rs` 52 LOC façade, `vcpu.rs` 1362, `vm_impl.rs` 509,
  `hypervisor_impl.rs` 175, `vm_state.rs` 375, `consts.rs` 145, `abi.rs` 278,
  `helpers.rs` 117, `mmap.rs` 53, `emulator.rs` 218).
* **Dedup vs `themis-abi`**: VpRegister, REALMODE access-rights,
  THEMIC_MSG_*, `vmx_exit_reasons` (SDM basic exit reasons), and synthetic
  exits all flow from `themis-abi` — the CHV backend re-exports rather than
  redefines.
* **Inline magic named**: LAPIC_MMIO_{BASE,SIZE,END,OFFSET_MASK},
  CPUID_LEAF_TSC_FREQ/PROC_FREQ, THEMIS_MAX_VCPUS.
* **TSC kHz from CPUID**: `handle_wrmsr_exit` no longer hardcodes 3 GHz; reads
  the same OnceLock-cached CPUID-derived value as `Vcpu::tsc_khz()` (with a
  warned fallback only if both leaves return nothing).  Also fixed a
  pre-existing rounding bug (integer-divide through GHz → exact u128 ns math).
* Build with `themis,kvm,ivshmem`: 0 warnings, 0 errors.

Latest committed: CHV `7891cba82`, outer `d6fac441b`.

### In progress — thhv refactor + magic-number dedup (UNCOMMITTED)

Mirrors the CHV cleanup on the kernel-module side.  See
`~/.copilot/session-state/2d26c842-6034-4eb0-8eed-042885dd1a1a/plan.md` for
the full inventory; summary:

* `thhv_part.c` (1308 LOC) split into `thhv_part.c` (733, lifecycle + ioctl
  dispatch) + `thhv_part_mem.c` (597, rb-tree + SET_GUEST_MEMORY +
  send_meta_pages).
* `inc/thhv.h` (1418 LOC) split: kernel-only block extracted to private
  `src/thhv_internal.h` (375); `inc/thhv.h` is now 1071 LOC of pure UAPI.
  All 10 `src/*.c` files now `#include "thhv_internal.h"`.
* Magic numbers named: `THHV_MAX_VPS_PER_DOMAIN` (256), `THHV_MAX_GSI` (255),
  `THHV_PA_MAP_MAX_ENTRIES` (4096).  The 256 vCPU cap is now a single
  source-of-truth via `themis_abi::MAX_VPS_PER_DOMAIN`; CHV `THEMIS_MAX_VCPUS`
  re-exports from there, and `THHV_MAX_VPS_PER_DOMAIN` carries a comment
  cross-link.
* All three components build clean (`thhv.ko`, CHV themis+kvm+ivshmem,
  capavisor).  **No boot test yet** — that's tomorrow's first step before
  committing in 3 logical pieces.

### Next session resume order
1. Deploy + boot-test the uncommitted thhv work
   (`cd themis && cargo themis 2>&1 | tee /tmp/out.txt`).
2. Commit in 3 logical commits (split, header split, magic dedup) — see
   session plan.md for exact file lists.
3. Investigate the pre-existing `dom1-not-reaching-login` issue (deferred
   throughout the refactor so debug effort wasn't wasted on code about to
   be moved).

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

- **Coco isolation test — host access attempt after CARVE+SEND**:
  add a eunomia test (or extend `eunomia/workloads/coco/`) where dom0
  deliberately tries to read/write the guest RAM after CARVE+SEND has
  transferred ownership to the confidential child.  The original mmap
  pointers in CHV/dom0 are still valid VAs, but the underlying physical
  pages must no longer be reachable from dom0's EPT (that's the whole
  point of CARVE — see `docs/architecture/confidential-vm.md`).
  Expected outcome: dom0 access faults / EPT violation, child memory
  contents remain confidential.  Without this test we have no automated
  proof that CARVE actually revokes dom0 access end-to-end (capa-engine
  `send_region` → capavisor `apply_update` → EPT unmap → IOMMU mirror
  update).  Should also verify: (a) reads return zero/fault, not stale
  data; (b) writes don't leak into child; (c) IOMMU side is updated so
  a dom0-controlled device can't DMA into the carved region either.

- **APIC virtualization regression to design intent (child VMs)**:
  the intended design (`docs/architecture/interrupt-virtualization.md`
  §Child Domains) is `APIC_REGISTER_VIRT=1` + `VID=1`, leaving the
  hardware to handle most LAPIC accesses and shipping only ICR-IPI
  policy to CHV.  Commit `d21dc8241` ("fix: child APIC virtualization
  for multi-vCPU dom1", 2026-04-03) disabled both bits as a workaround
  because *"CHV doesn't yet provide VAPIC page state synchronisation"*
  and added a child-side software LAPIC emulator in capavisor.  This
  emulator (`arch/x86_64/vmexit.rs::handle_apic_access_exit` plus
  `decode_apic_write_value`) requires capavisor to decode the guest's
  MOV instruction at RIP every time the child touches the LAPIC, plus
  maintain a full software VAPIC mirror (read/write/EOI ISR walk).
  Decoding guest instructions in capavisor violates the design
  principle that decoding belongs in CHV (host-side `iced-x86`).

  **What needs to be done**, in order:
    1. Re-enable `APIC_REGISTER_VIRT` (sec bit 8) and `VID` (sec bit 9)
       for child VMs in `arch/x86_64/vmcs.rs`.
    2. Implement VAPIC-page state synchronisation on the
       capavisor↔CHV boundary — initial state at child VP create, and
       any state CHV needs at SWITCH-in / SWITCH-out.  The page lives
       in HHDM on the capavisor side and is already mapped into dom0
       via thhv, so this is cheap.
    3. For ICR writes that still need exit-based policy: ship the
       raw instruction bytes + access offset to CHV (same path as the
       EPT-MMIO forward today), let CHV decode using iced-x86 and
       forward the IPI request back through the normal hypercall ABI.
    4. Delete from capavisor: `handle_apic_access_exit`,
       `decode_apic_write_value`, and the `gpr_by_index` CR-decode
       helper in `arch/x86_64/vmexit.rs`; the page-walk helpers
       (`ept_gpa_to_hpa`, `guest_gva_to_gpa`) and instruction-byte
       fetch in `hypercall.rs` *stay* — they support the
       EPT-violation forward path, which is honest forwarding (CHV
       does the decode).
    5. Verify dom1 multi-vCPU boot (the workload that motivated
       `d21dc8241` in the first place) still works after the change.

  **Security and performance considerations** (raised when this debt
  was identified, 2026-05-28):
    - *Security*: CHV already maps the guest's physical memory via
      thhv (the EPT-MMIO forward path reads `instruction_bytes` and
      ships them to CHV today), so giving CHV the few bytes needed to
      decode an ICR write is no new authority.
    - *Performance*: with bits 8 + 9 enabled, most LAPIC accesses
      (reads, EOI, TPR writes) take **no exit at all** instead of one
      capavisor round-trip per access.  Only ICR / unhandled-offset
      writes still exit, and those go to CHV — fewer L0↔L1
      ping-pongs than today, not more.

  Doc updated 2026-05-28: see warning callout in
  `docs/architecture/interrupt-virtualization.md` §Child Domains.

- **capavisor/src/hypercall.rs cleanup**: `forward_child_exit`, `do_switch`,
  and `forward_interrupt_to_handler` have grown into multi-hundred-line
  functions mixing capa-engine calls, COMM-page marshaling, I/O-qual decoding,
  VMCS swap, and ad-hoc debug instrumentation. Extract helpers (COMM-page
  marshal, IO exit-qual decode, VMCS swap) and rip out the DB-* trace
  scaffolding once the doorbell bug is fixed. Quality is not acceptable as-is.

- **Dom1 cross-core IPI delivery slowdown after VcpuSwap refactor**
  (Phase 4 of capavisor cleanup): after extracting `swap_active_vp` and
  unifying the three swap sites in `themis/capavisor/src/hypercall.rs`,
  dom1 boot reaches PCI BAR 0 enumeration and then progresses extremely
  slowly. Symptom seen via SSH into dom0, tail of `/tmp/chv-stdout.log`
  (guest printk) vs `/tmp/chv-stderr.log` (CHV diags):
    * Guest stdout frozen for many minutes mid-PCI-probe.
    * CHV stderr keeps spinning: `[LAPIC-IPI] vp=1 ... vector=0xfd ...
      dest_apic=0` (Linux RESCHEDULE_VECTOR), `[THEMIS-MSR] WRMSR
      msr=0x6e0` (TSC_DEADLINE) at same RIP repeatedly, many
      `[THEMIS-TIMER] delta_tsc=0` (deadlines already past).
    * CHV process at 99% CPU; counters keep incrementing (#11000 →
      #14800 over ~8 min) so it's slow, not deadlocked.
  Hypothesis: cross-core notification IPI / PIR-drain latency increased
  for resched IPI delivery to vp0 (the BSP doing PCI probe), so vp0
  doesn't wake from idle promptly and vp1 spins reprogramming the
  TSC-deadline. Smoke tests and Eunomia got FASTER; only dom1's
  long-running cross-core workload exposes this. Code review of the
  refactor diff shows: `pid_set_ndst` still called on every swap (3 sites
  → helper), `sync_irte_ndst` unchanged (still only in `do_switch`), PIR
  drain logic byte-identical, register dispatch identical. The only
  ordering change is that `swap_active_vp` does `take(dst)` BEFORE
  `VMCLEAR src` (vs OLD which did `VMCLEAR src` → `put(src)` →
  `take(dst)`); intuitively this should not affect IPI latency but is
  worth checking under instrumentation. Investigation plan: defer until
  the rest of the refactor (phases 5–10) is in, then add timing probes
  around `inject_via_pid`, the PIR drain block, and `swap_active_vp`
  step boundaries; compare against pre-refactor commit `f95148ece`.
  See also session checkpoint `011-designing-vcpuswap-helper-api`.

- **Cleanup / teardown invariants need real tests**: after the capavisor
  refactor (VcpuSwap helper, RIP invariant, etc.), we observed that
  re-running dom1 after Eunomia in the same boot causes unexpected CHV
  exits; a fresh reboot fixes it. This strongly suggests leftover state on
  domain destroy — candidates: IRTE entries not torn down, PID/PIR words
  retaining bits, shmem pages still mapped in dom0, thhv refcounts, child
  VcpuSlot not emptied, EPT pages not reclaimed. We need tests that
  exercise create→destroy→create cycles on the same boot for each domain
  type (smoke child, Eunomia, dom1 with CHV) and assert all per-domain
  resources are released. Without these, refactor regressions in the
  cleanup path will keep surfacing as flaky integration runs.

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
