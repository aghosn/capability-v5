## Real platform implementation and integration

> **Archived content**: Resolved design decisions (Q1, Q2), completed phases (0, 0.5, 1, 2 partial),
> the dom0 boot bringup plan (R1–R7 refactoring), and all fixed bugs (BUG-1 through BUG-15) have
> been moved to [`2026/docs/archived/09-03-2026/archived_todo.md`](2026/docs/archived/09-03-2026/archived_todo.md).

**Goal**

Implement Themis (the capavisor) as described in the paper.
Themis uses the capability engine to maintain a state machine for domains that run on top of it and that Themis isolates using virtualization extensions (e.g., Intel VT-x).
It starts the initial domain, dom0 that acts as the root on the machine, i.e., the first domain owning the initial memory capabilities.

Themis should run (and boot) on bare-metal.
If we can, it'd ideally enable to target different platform (e.g., Intel and AMD to begin with).

## Current Status

**✅ MILESTONE: dom0 boots to login prompt on 4 CPUs.**

- Phases 0, 0.5, 1, 2 (partial) completed — workspace, Limine integration, memory/ACPI/PCI, VT-x foundation.
- Phase 7 (partial) completed — capability engine init, dom0 EPT, e820, ACPI passthrough, DMAR stripping, VMLAUNCH, SMP.
- Post-boot refactor (R1–R7) completed — ActiveVcpu/InactiveVcpu, per-core monitor loop, host stack cleanup, VMXON global, Domain consolidation, VMX crate extraction, clippy cleanup.
- 15 bugs fixed (BUG-1 through BUG-15).
- #U6 (XSAVES/XRSTORS) enabled.
- P2-platform completed — ThemisPlatform, MetaAllocator redesign, engine gaps (CreateDomain/GiveMetaMem updates), apply_update handlers, bootstrap helpers.
- #U7 completed — CoreContext, hypercall.rs dispatch, themis_abi register convention docs, VMCALL wiring in vmexit.rs.

---

## Open Implementation Phases

### Phase 0.5 — Remaining

- [ ] **P0.5e** — *(Future)* Switch to virtio-blk for dom0 disk once Themis's virtio-blk
  backend is implemented (Phase 12+). At that point, the disk can be passed as
  `-drive ...,if=virtio` in QEMU and Limine access becomes irrelevant (Themis will load
  the kernel from memory, not Limine). Kernel command line root= will switch to
  `root=/dev/vda1`.

### Phase 2 — Remaining

- [x] **P2-platform**: ✅ DONE.  ThemisPlatform fully implements the `Platform` trait.
  Engine gaps fixed (CreateDomain/GiveMetaMem updates emitted by capability engine).
  MetaAllocator redesigned (non-contiguous free_stack).  apply_update handles
  CreateDomain, GiveMetaMem, ChangeRights (lazy EPT), RevokeDomain, FlushTLB.
  Bootstrap helpers (`bootstrap_register_domain`, `bootstrap_give_meta`) in place.
  IOMMU integration deferred to Phase 4.  VMCS/VP allocation deferred to P2d placeholder.

### Phase 3 — Platform Trait Implementation

- [ ] **P3a**: `TychePlatform` with all `Platform` methods:
  - `acquire_shared_lock` / `acquire_exclusive_lock`: `spin::RwLock<()>`.
  - `apply_update`: EPT + IOMMU map/unmap/zero/flush as described above.
  - `register_domain`: allocate EPT root + IOMMU domain PT; insert into `domains` map.
  - `on_domain_revoked`: redirect cores, free EPT + IOMMU structures, release devices.
  - `set_core_domain` / `clear_core_domain` / `domain_core`.
  - `send_ipi` (x2APIC), `sync_barrier` (two AtomicUsize counters per barrier phase).
  - `try_acquire_update_lock` / `release_update_lock` / `poll_and_respond_cross_core`.
- [ ] **P3b**: IPI handler (IDT vector): set per-core `ipi_pending` flag;
  `poll_and_respond_cross_core` checks flag and participates in barrier.
- [ ] **P3c**: TLB shootdown: `INVEPT` (single-context) after each EPT update;
  `IOTLB` invalidation after each IOMMU update.

### Phase 4 — VT-d IOMMU Initialization

- [ ] **P4a**: Parse raw DMAR bytes: locate DRHD units (hardware units) + RMRR regions.
- [ ] **P4b**: For each DRHD unit: allocate root table + context tables from `FrameAllocator`;
  program root table address register; set passthrough mode (all DMA allowed) initially.
- [ ] **P4c**: Enable VT-d translation: `iommu.enable_translation()` on all units.
- [ ] **P4d**: RMRR handling: pre-map RMRR physical ranges as identity in the dom0 IOMMU domain
  PT (these regions must remain accessible to legacy devices regardless of domain assignment).
- [ ] **P4e**: `IommuManager::update_domain_pt(domain, hpa, size, rights)`:
  walk DMA PT (same format as EPT), set/clear entries, call IOTLB invalidation.
- [ ] **P4f**: `IommuManager::assign_device(pci_addr, domain)`:
  reprogram context entry for device BDF → domain's DMA page table.

### Phase 5 — APICv and Virtual APIC

- [ ] **P5-ept-verify**: Replace `crates/ept/` vmxvmm port with the formally-verified
  EPT from `asterinas/hyperenclave` (ASPLOS'24, Rust MIR → Coq proofs, Apache-2.0).
  Steps: clone hyperenclave, locate `src/memory/ept.rs` (or equivalent), strip
  TEE/enclave policy, adapt to our `FrameAllocator` trait and local address types,
  run unit tests under `x86_64-unknown-linux-gnu`.  This restores the original P0c plan.

- [ ] **P5a**: Per-VP allocation: VAPIC page (4 KB from `FrameAllocator`) and
  posted-interrupt descriptor (64 B, 64 B-aligned from `FrameAllocator`).
  Note: once Phase 10 (META VP-state regions) is implemented, the PI descriptor is
  colocated inside the `VpStateMeta` page, eliminating the separate allocation;
  `VpHw.pi_desc_phys` becomes an offset into the META page.
- [ ] **P5b**: APIC access page: one 4 KB page per domain at APIC MMIO address (0xFEE00000);
  used by `APIC_ACCESS_ADDR` VMCS field for xAPIC mode.
- [ ] **P5c**: VMCS secondary execution controls (when `CpuFeatures::apicv`):
  `VIRTUALIZE_X2APIC | APIC_REG_VIRT | VIRT_INTR_DELIVERY`.
  Pin-based controls: `PROCESS_POSTED_INTERRUPTS`.
  VMCS fields: `VIRTUAL_APIC_PAGE_ADDR`, `POSTED_INTR_DESC_ADDR`, `POSTED_INTR_NV`,
  `APIC_ACCESS_ADDR`, EOI-exit bitmap (zeroed initially).
- [ ] **P5d**: `vapic::inject_virtual_interrupt(vapic_page, vector)`:
  set bit in VIRR (offset 0x200 + vector/8 in VAPIC page); update RVI (requesting
  virtual interrupt = highest VIRR bit that exceeds PPR).
- [ ] **P5e**: `vapic::post_interrupt(pi_desc, vector)`:
  set `PIR[vector]` bit atomically; set `ON` (outstanding notification) bit;
  send posted-interrupt notification IPI (NV) to target LAPIC if domain VP is running.
- [ ] **P5f**: Fallback path: if `!CpuFeatures::apicv`, disable all APICv VMCS bits;
  emulate APIC register access via VMEXIT.

### Phase 6 — IRQ Router and Interrupt Policy

- [ ] **P6a**: `IrqRouter` initialization at boot: all vectors assigned to dom0 with
  `PostedInterrupt` delivery (APICv) or `VmExit` fallback.
- [ ] **P6b**: I/O APIC programming (`x2apic::IoApic`): set redirection table entries
  for all PCI legacy IRQs targeting dom0 initially.
- [ ] **P6c**: MSI-X programming: write MSI-X table entries for PCI devices targeting
  dom0's notification vector (LAPIC ID = dom0 VP[0] physical LAPIC).
- [ ] **P6d**: `IrqRouter::configure_domain_policy(domain, policy, hw)`:
  called by `VMCALL_SEAL` handler; programs EOI-exit bitmap and posted interrupt config.
- [ ] **P6e**: VMEXIT `EXTERNAL_INTERRUPT` handler:
  1. **Immediately** write physical LAPIC EOI: `wrmsr(IA32_X2APIC_EOI, 0)` (x2APIC) or
     MMIO write to LAPIC base + 0xB0 (xAPIC). This clears the physical ISR bit and
     de-asserts level-triggered IRQ lines. Must happen before any other action, and is
     independent of virtual APIC state (see Physical LAPIC EOI section in Q2).
  2. Read `VM_EXIT_INTR_INFO` to obtain the physical vector V.
  3. Look up `IrqRouter::route(V)` → (domain D, delivery mode).
  4. If delivery is `DELIVER` with `PostedInterrupt` or `VirtualInject`:
     call `deliver_interrupt_vp`; inject V into handler VP's VIRR (VAPIC page bit set);
     VMRESUME into handler domain VP on same core.
  5. If domain D is confidential and policy is `DEFER_TO_PARENT` or `REPORT`:
     **cross-core routing path** (see archived Q2 Cross-Core Interrupt Routing):
     a. Write interrupt info (vector, source, IRQ state) into VP META page.
     b. Set `PENDING_IRQ` bit in VP META page header atomically.
     c. Post virtual interrupt to dom0 VP's PI descriptor (`PIR[tyche_irq_notification_vector]`);
        send NV IPI to dom0 core's LAPIC → APICv delivers to dom0 with zero VMEXIT.
     d. Park core X with `CLI` — spin poll loop on RESUME_WITH_IRQ / RESUME_NO_IRQ bits
        in VP META page, calling `poll_and_respond_cross_core()` each iteration for barrier
        participation.
     e. On `RESUME_WITH_IRQ`: PI descriptor `PIR[V]` already set by dom0 core;
        hardware merges PIR → VIRR on VMRESUME; VMRESUME.
     f. On `RESUME_NO_IRQ`: VMRESUME with no pending interrupt (interrupt was for dom0).
- [ ] **P6f**: VMEXIT `EOI_INDUCED` handler: capability engine resume-after-interrupt
  for REPORT-visibility vectors; notify parent chain.
- [ ] **P6g**: Timer interrupt: LAPIC timer → DELIVER to dom0 by default; APICv posts
  it without VMEXIT. Monitor can intercept via EOI-exit bitmap if timer-based preemption
  of child domains is needed.
- [ ] **P6h**: NMI: always VMEXIT (cannot be posted); route to Themis for watchdog/panic.

### Phase 7 — Remaining Items

#### dom0 / Linux visibility policy

The following three invariants govern what dom0 sees and can access:

1. **Capavisor is invisible.**  All capavisor-internal physical memory
   (binary, heap, page tables, META pool) must appear as `TYPE_RESERVED` in
   the e820 and must NOT be mapped in dom0's EPT.

2. **IOMMU is invisible.**  The VT-d IOMMU is retained exclusively by Themis
   for DMA isolation.  The DMAR ACPI table is stripped before boot_params
   is handed to Linux.

3. **Devices are passed through.**  Themis implements no device emulation.
   Linux sees the real ACPI tables (minus DMAR) and gets direct EPT access to
   device MMIO regions.

#### Open items

- [ ] **P7d**: Set dom0 interrupt policy: all vectors DELIVER (dom0 is the default handler).

- [ ] **P7f-alt**: *(Future / optional)* **64-bit direct entry** for dom0 instead of the
  32-bit decompressor path.  Trade-offs:
  - **Benefits**: skips the decompressor (faster boot, less untrusted code runs before
    the kernel is in steady state); removes the `UNRESTRICTED_GUEST` dependency;
    enables measured boot (hash the kernel image before decompression).
  - **Costs**: requires an uncompressed kernel (`vmlinux`) or implementing the EFI
    handover / 64-bit boot stub protocol — a stock bzImage cannot be used as-is.
  - **Prerequisite**: decide on kernel format policy (bzImage vs vmlinux vs EFI stub)
    before implementing.

- [ ] **P7g-vmxon-global**: Extract per-core VMXON regions into a global static array.

  VMXON is a per-physical-core resource — it is executed before any domain is active
  and has no domain affiliation.  There is exactly one VMXON region per core for the
  lifetime of the hypervisor; it is allocated during boot and never freed.

  Implementation:
  - Add `static VMXON_PHYS: [AtomicU64; MAX_CORES]` in `main.rs` (or `vmx.rs`).
  - During `boot::vmcs()` (BSP), write physical address into `VMXON_PHYS[cpu_id]`.
  - Remove VMXON tracking from `VmxState` / domain structures.
  - In `ap_entry()`: read `VMXON_PHYS[cpu_id]`, call `enable_vmx_on_core(phys)`.

- [ ] **P7g-platform-locking**: Refactor `ThemisPlatformInner` from a single
  `Mutex<ThemisPlatformInner>` into a three-tier locking structure that allows cores
  to operate concurrently on independent domains or their own per-core state.

  **Tier 1 — per-core scheduling state** (`[CoreContext; MAX_CORES]`):
  - See `CoreContext` definition in #U7.  Each core owns its cell; reads by
    other cores happen only under the `execute()` barrier protocol or via the
    cached `domain_id` atomic (observational, lock-free).

  **Tier 2 — per-domain state** (`BTreeMap<DomainId, Mutex<PlatformDomain>>`):
  - `PlatformDomain` (EPT, meta allocator, `vps: Vec<VpHardware>`) moves behind its own `Mutex`.
  - `VpHardware { vmcs_phys: u64, vmxon_phys: u64 }` replaces the `Vec<()>` placeholder.

  **Tier 3 — global routing maps** (`RwLock<RoutingMaps>`):
  - `RoutingMaps { core_to_domain, domain_to_core, lapic_ids }` behind a single `RwLock`.

- [ ] **P7g-update-barriers**: Audit and document the interaction between multi-core
  capability operations (UpdateBatch) and the new fine-grained platform locking.
  Verify lock ordering, Tier 1 consistency, and INVEPT scope.

- [ ] **P7h**: Per-core VP run loop. Each core runs a tight loop that owns a `VpContext`
  carrying everything needed to dispatch exits:

  ```
  per-core loop:
    vmlaunch / vmresume
      → VMEXIT → trampoline saves GPRs
      → handle_vmexit(&mut VpContext, &mut GuestRegs)
           VpContext = { domain_id, vp_index, &platform, &vmx_state, ... }
      → dispatch: VMCALL  → capability_engine::execute(...)
                  EPT vio  → platform.remap(...)
                  HLT      → park/yield VP
      → loop
  ```

- [ ] **P7i — Post-boot cleanup and VP-setup factoring**:
  - **Code cleanup**: remove stale comments, dead code, resolved `TODO(P*)` markers.
  - **VP-setup factoring**: extract VP provisioning (VMXON, VMCS, VAPIC allocation +
    `setup_vmcs_for_vp`) into a single reusable `Platform::provision_vp()` path.
  - **Domain struct ownership review**: evaluate whether `domain::Domain` fields
    collapse into `PlatformDomain::vps: Vec<VpHardware>` exclusively.
  - **Module organisation**: split `platform.rs` if needed (~650 lines).
  - **VpContext definition**: pin in a stable location for P7h and Phase 8.

### Phase 8 — Hypercall Dispatch + Hypercall ABI

- [ ] **P8a**: `crates/themis-abi/`: opcode constants, `VpRegister` enum, error codes.
  Shared between capavisor and `libtyche` guest library.
- [ ] **P8b**: `hypercall.rs`: decode RAX, call `execute(||...)`, encode result.
- [ ] **P8c**: Implement all CapavisorAPI hypercall handlers listed in the Hypercall ABI table,
  including: `VMCALL_CARVE`, `VMCALL_ALIAS`, `VMCALL_SEND`, `VMCALL_ACCEPT`, `VMCALL_REJECT`,
  `VMCALL_CREATE_DOMAIN`, `VMCALL_SEAL`, `VMCALL_REVOKE_MEM`, `VMCALL_REVOKE_DOMAIN`,
  `VMCALL_SWITCH`, `VMCALL_GET_CHAN`, `VMCALL_ATTEST_SELF`, `VMCALL_ATTEST`,
  `VMCALL_GET_REG`, `VMCALL_SET_REG`, `VMCALL_SET_INTR_POLICY`, `VMCALL_SET_DEF_INTR_POLICY`.
  Stubs for `VMCALL_REGISTER_VP_META` and `VMCALL_REGISTER_DOORBELL` (implemented in
  Phases 10–11).
- [ ] **P8d**: `VMCALL_ASSIGN_DEVICE`: validate caller, reprogram IOMMU + I/O APIC.
- [ ] **P8e**: `libtyche` guest library (`crates/libtyche/`): `no_std` VMCALL wrappers.
  Usable from Linux kernel module (`std`) via FFI or from a bare-metal child domain.

### Phase 9 — Multi-Domain Support

- [ ] **P9a**: dom0 `VMCALL_CREATE_DOMAIN` → Themis allocates EPT root + IOMMU PT.
- [ ] **P9b**: dom0 carves memory + sends to child → `apply_update` updates child EPT + IOMMU.
- [ ] **P9c**: dom0 seals child → Themis allocates child VMCS + VAPIC + PI descriptors;
  calls `IrqRouter::configure_domain_policy` for child.
- [ ] **P9d**: `VMCALL_SWITCH` → `switch_domain`, VMPTRLD child VMCS, VMRESUME.
- [ ] **P9e**: `VMCALL_REVOKE_DOMAIN` → capability engine subtree revoke; `on_domain_revoked`
  frees EPT + IOMMU + VMCS + VAPIC structures; reassigns devices to parent.
- [ ] **P9f**: Cross-domain interrupt delivery (REPORT): EOI-exit VMEXIT → capability engine
  `deliver_interrupt_vp` → VMCS switch to handler domain → VMRESUME.

### Phase 10 — META VP-State Regions

Implements the EVMCS-inspired `VpStateMeta` pages for zero-hypercall VP register access,
PI descriptor colocation, and the cross-core interrupt routing channel. Depends on Phase 9.

- [ ] **P10a**: Define `VpStateMeta` struct in `crates/themis-abi/` (shared layout between
  capavisor and driver/userspace). Fields: GPRs, RIP/RSP/RFLAGS, CR0/CR3/CR4/EFER,
  exit_reason, exit_qualification, `dirty` atomic bitmask, interrupt routing fields,
  `pi_desc: PostedInterruptDescriptor` (64 B, 64 B-aligned).
- [ ] **P10b**: `VMCALL_REGISTER_VP_META(domain_handle, vp_id, meta_cap_handle)`:
  validate, map META page into Themis root-mode, store in `VpHw.meta_virt/meta_phys`,
  update VMCS `POSTED_INTR_DESC_ADDR`.
- [ ] **P10c**: On every VMEXIT from a VP with META page, write VP mirror (GPRs, CRs, exit info).
- [ ] **P10d**: On every VMENTRY, check `dirty` field and reload VMCS guest-state from META page.
- [ ] **P10e**: Update `THEMIS_GET_VP_REGS` ioctl path: if META mapped, read directly — no hypercall.
- [ ] **P10f**: Update cross-core interrupt routing (P6e step 5) to use META page fields.
- [ ] **P10g**: Resolve write-back timing: generation counter + benchmark overhead.

### Phase 11 — TychIC: Doorbell and Event Flag Pages

Implements the SynIC-inspired cross-domain notification protocol. Depends on Phase 10.

- [ ] **P11a**: Define event flag page layout in `crates/themis-abi/`: 4 KB page, each bit = notification slot.
- [ ] **P11b**: `VMCALL_REGISTER_EVENT_FLAGS(domain_handle, vp_id, meta_cap_handle)`:
  register event flag page, map into root mode + child EPT.
- [ ] **P11c**: `VMCALL_REGISTER_DOORBELL(domain_handle, vp_id, gpa, slot, vector)`:
  register doorbell — EPT violation on write sets event flag + posts interrupt to target VP.
- [ ] **P11d**: EPT_VIOLATION handler: check faulting GPA against registered doorbells.
- [ ] **P11e**: Interrupt channel registration: `VMCALL_REGISTER_INTR_CHANNEL(child, vp_id, slot, vector)`.
- [ ] **P11f**: TychIC vs raw APIC exposure: decide whether doorbell/event-flag is invisible to Linux.

### Phase 12 — `themis-vmm.ko` Linux Kernel Driver

Thin Linux kernel module that exposes `/dev/themis` to userspace. Depends on Phase 8.

- [ ] **P12a**: CPUID hypervisor leaf: return custom vendor string on leaf `0x40000000`.
- [ ] **P12b**: Character device `/dev/themis`: `file_operations` with `open`, `release`,
  `unlocked_ioctl`, `mmap`.
- [ ] **P12c**: Implement ioctl handlers (all translate to `VMCALL` via inline asm):
  `THEMIS_CREATE_DOMAIN`, `THEMIS_MAP_MEMORY`, `THEMIS_SET_VP_REGS`, `THEMIS_GET_VP_REGS`,
  `THEMIS_INIT_DOMAIN`, `THEMIS_DELETE_DOMAIN`, `THEMIS_RUN_VP`, `THEMIS_IRQFD`,
  `THEMIS_IOEVENTFD`.
- [ ] **P12d**: Intercept message page: Themis writes exit reason + faulting address to
  VP's `VpStateMeta` page; `THEMIS_RUN_VP` returns pointer to mmap'd META page.
- [ ] **P12e**: `mmap` implementation: userspace maps VP META page (read-only intercept info,
  read-write register dirty flags).
- [ ] **P12f**: `THEMIS_IRQFD`: `eventfd_ctx` + workqueue; on eventfd signal, write PIR + send NV IPI.
- [ ] **P12g**: `THEMIS_IOEVENTFD`: EPT-violation or I/O-bitmap intercept → signal eventfd.
- [ ] **P12h**: Driver recursion: any domain with child-creation capabilities can load `themis-vmm.ko`.

### Phase 13 — AMD SVM Support

Parallel to Intel VT-x; gated behind runtime CPU feature flag. Depends on Phase 2.

- [ ] **P13a**: CPUID check for AMD-V + SVM version + AVIC support. Record in `CpuFeatures`.
- [ ] **P13b**: Hand-roll `Vmcb` struct from AMD APM Vol.2 §15 (control area + state save area).
- [ ] **P13c**: VMRUN / VMSAVE / VMLOAD wrappers; enable SVM globally; per-core host save area.
- [ ] **P13d**: VMCB control area setup: intercept VMCALL, CPUID, CR writes, physical interrupts, NMI.
- [ ] **P13e**: Nested Page Tables (NPT): reuse `crates/ept/` (identical 4-level structure).
- [ ] **P13f**: Physical interrupt on VMEXIT: physical LAPIC EOI + cross-core routing.
- [ ] **P13g**: AVIC (AMD Virtual Interrupt Controller): equivalent of Intel APICv.
- [ ] **P13h**: `arch/x86_64/svm.rs`: implement `Arch` trait for SVM path.

### Phase 14 — Custom dom0 Image

Replace stock minimal Linux with purpose-built dom0 image. Deferred until Phase 12 is functional.

- [ ] **P14a** — Kernel configuration: `defconfig` + `kvm_guest.config` baseline, strip unnecessary
  drivers, enable virtio-blk/net/9p, serial console. Ship `guest/dom0/kernel.config`.
- [ ] **P14b** — `themis-vmm.ko` integration: build module against kernel source tree, pack into initrd.
- [ ] **P14c** — Minimal rootfs: Alpine mini rootfs or BusyBox static; auto-load `themis-vmm.ko`.
- [ ] **P14d** — Build script `scripts/build-dom0.sh`: fetch kernel, apply config, build, assemble initrd.
- [ ] **P14e** — Validation: boot under QEMU, verify driver loads, run child-domain smoke test.

---

## Platform API / Unimplemented Features

- [ ] **#U1** `UpdateBatch::snapshots` — rollback not implemented. _Deferred — future work._
- [ ] **#U2** `CapavisorAPI::ENUMERATE` / `enumerate_pending` — semantics TBD. _Deferred._
- [ ] **#U3** Cache coloring — see `./2026/docs/design/address_translation.md`. _Phase 4–6 of address translation design._
- [ ] **#U5** vAPIC for all domains (incl. dom0) — replace LAPIC/IOAPIC EPT passthrough with "Virtualize APIC accesses" (secondary bit 0), APIC-access page, virtual-APIC page, and TPR shadow.  Remove direct LAPIC EPT mapping from boot.rs.  See BUG-6 note. _Post-clean-boot refactor._
- [x] **#U6** Enable XSAVES/XRSTORS — ✅ DONE.  Set secondary exec control bit 20 (ENABLE_XSAVES_XRSTORS), write XSS-exiting bitmap = 0 (all XSAVES/XRSTORS execute natively), removed CPUID 0xD:1 bit 3 mask.  IA32_XSS (0xDA0) passes through via zeroed MSR bitmap.  Tested: dom0 boots to login prompt.
- [x] **#U7** Capability API plumbing (themis_abi ↔ capability engine) — ✅ DONE.
  CoreContext replaces PerCoreCell (domain_id, vp_id, domain_cap).  Boot init
  seeds dom0_cap and all per-core contexts before AP launch.  Register convention
  documented in themis_abi.  hypercall.rs dispatches 10 opcodes (CARVE, ALIAS,
  SEND, ACCEPT, REJECT, CREATE_DOMAIN, SEAL, REVOKE_MEM, REVOKE_DOMAIN,
  ATTEST_SELF) with 14 stubs.  VMCALL handler wired in vmexit.rs.  Builds clean.

  _(Design notes for U7a–U7f archived — implementation matches spec.)_
