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
- P7g completed — VMXON global array, three-tier platform locking, update barrier protocol.
- P7h completed — monitor_loop on all cores, VMCALL dispatch, EPT violation policy documented.
- Phase 3 (P3a, P3b, P3c) completed — all Platform trait methods, INVEPT, INIT-based cross-core preemption.

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

- [x] **P3a**: ✅ DONE.  All 9 Platform trait methods implemented: acquire_shared/exclusive_lock
  (spin::RwLock), apply_update (6 variants), register_domain, on_domain_revoked,
  send_ipi (x2APIC INIT assert), sync_barrier (two-phase AtomicUsize),
  try_acquire_update_lock / release_update_lock, poll_and_respond_cross_core.
  Helper methods: set_core_context, clear_core_domain, domain_core.
- [x] **P3b**: Cross-core preemption via INIT signal.

  **Design (revised):**  The original plan used a fixed-vector IPI (0xF2) with an IDT
  handler.  This is wrong: `EXTERNAL_INTERRUPT_EXITING = 0` in the dom0 VMCS means
  a fixed IPI is delivered to the *guest* IDT, not to Themis.  Even if we set
  `EXTERNAL_INTERRUPT_EXITING = 1`, an IDT handler in VMX root would risk preempting
  capavisor code while interrupts are disabled or locks are held.

  The correct approach (matching vmxvmm) uses **INIT assert**: the INIT signal always
  causes `VMEXIT(EXIT_REASON_INIT_SIGNAL = 3)` from non-root mode, regardless of
  pin-based controls.  If the target core is already in VMX root mode, INIT is latched
  and triggers an immediate VMEXIT on the next VMRESUME.  No IDT handler required.

  **Concurrency story:**

  Two paths cause a core to respond to a cross-core update request:

  1. *Core is in non-root mode (running a domain):*
     Initiating core sets `ipi_pending[target] = true`, then sends INIT assert.
     Target takes VMEXIT(INIT_SIGNAL) → `handle_vmexit` dispatches to the INIT_SIGNAL
     handler → calls `poll_and_respond_cross_core()` → barrier 0 (signal stopped) →
     INVEPT → barrier 1 (signal flushed) → VMRESUME.

  2. *Core is in VMX root mode (spinning on `update_lock`):*
     The spin loop already calls `poll_and_respond_cross_core()` on every iteration
     (`2026/src/platform.rs:372-373`).  It sees `ipi_pending[self] = true` (set by the
     initiating core before sending INIT), clears it, and enters the barrier dance.
     The latched INIT fires harmlessly on the next VMRESUME (handler sees
     `ipi_pending = false`, returns immediately).

  In both cases, `ipi_pending` is the *signaling* mechanism; INIT is the *preemption*
  mechanism that kicks a core out of guest mode.  The barrier protocol is unchanged.

  **Per-core update queue design:**

  In vmxvmm, the per-core `CoreUpdate` queue handles three operations that *must*
  execute on the affected core itself (the VMCS is per-physical-CPU):

  1. `TlbShootdown` — core reloads EPTP and flushes local EPT TLB.
  2. `Switch` — cross-core domain switch: target core loads new domain VMCS/context.
  3. `DomainRevocation` — core running a revoked domain must VMPTRLD the fallback
     domain's VMCS, switch register context, update `current_domain`.

  Themis adopts the same pattern, adapted for our heap-backed environment:

  ```rust
  /// Per-core update command, pushed by initiating core, consumed by target.
  #[derive(Debug, Clone)]
  pub enum CoreUpdate {
      /// Flush EPT TLB for the domain currently loaded on this core.
      TlbShootdown,
      /// Switch this core to a different domain/VP.
      Switch {
          domain_cap: CapabilityRef<Domain>,
          vp_id: u32,
      },
      /// Domain was revoked; switch to fallback domain.
      Revoke {
          revoked: DomainId,
          fallback_cap: CapabilityRef<Domain>,
          fallback_vp: u32,
      },
  }
  ```

  `Switch` and `Revoke` carry a **`CapabilityRef<Domain>`** (= `Arc<RwLock<…>>`,
  Clone+Send+Sync) for the new/fallback domain.  The responding core needs this to
  call `set_core_context(core_id, &cap_ref, vp_id)` and update its `CoreContext`
  with the correct capability reference — matching how the engine's own
  `switch_domain_forward` / `switch_domain_return` pass the cap ref.

  **Storage:** `Mutex<VecDeque<CoreUpdate>>` per core, inside `ThemisPlatform`:

  ```rust
  pub struct ThemisPlatform {
      // ... existing fields ...
      core_updates: [Mutex<VecDeque<CoreUpdate>>; MAX_CORES],
  }
  ```

  `Mutex<VecDeque>` is simple and correct.  Contention is minimal — only the
  initiating core writes (under `update_lock`), only the local core reads
  (in `poll_and_respond_cross_core` or the monitor loop).  The VecDeque grows
  dynamically via the heap, unlike vmxvmm's fixed 128-entry ring buffer.

  **Who pushes CoreUpdates:**  Currently the capability engine calls only
  `platform.send_ipi(core_id)` — it doesn't tell the platform *what kind*
  of per-core action is needed (the platform hardcodes INVEPT).

  For P3b, the platform's `send_ipi()` unconditionally pushes `TlbShootdown`.
  For P9, the platform (or a new Platform trait method like
  `preempt_core(core_id, update)`) will push `Revoke` or `Switch` with the
  CapabilityRef.  The engine already has the cap ref at revocation time —
  it can pass it via the update batch or a dedicated platform call.

  **Protocol (revised with queue):**

  ```
  Initiating core:                     Responding core:
    acquire update_lock
    determine affected cores
    for each target:
      push CoreUpdate to                (written before INIT)
        core_updates[target]
      set ipi_pending[target]
      send INIT assert
                                         VMEXIT(INIT_SIGNAL) or poll loop
                                         clear ipi_pending[self]
    sync_barrier(0, n+1) ─────────────── barriers[0].wait(0)
    │                                    │
    │ apply_update (EPT changes)         │ drain core_updates[self]:
    │                                    │   TlbShootdown → INVEPT
    │                                    │   Switch → deactivate old VMCS,
    │                                    │     activate new from VcpuSlot,
    │                                    │     set_core_context(cap_ref, vp)
    │                                    │   Revoke → same + mark interrupted
    │                                    │
    sync_barrier(1, n+1) ─────────────── barriers[1].wait(0)
    on_domain_revoked (cleanup)
    release update_lock                  resume (possibly different domain)
  ```

  **Ordering constraint for revocation:**  Between barriers 0 and 1, the
  initiating core's `apply_update(RevokeDomain)` frees the old domain's EPT.
  The responding core must VMCLEAR its old VMCS (releasing the EPT reference)
  *before* the EPT is freed.  This is safe in the concurrent phase because:
  (a) VMCLEAR is a local CPU operation that completes immediately, and
  (b) the responding core drains its CoreUpdate queue *before* calling
  `barriers[1].wait(0)`, so the VMCS switch completes before the initiator
  can proceed past barrier 1 to `on_domain_revoked`.  If tighter ordering
  proves necessary, a third barrier can be inserted (switch → barrier_1a →
  free EPT → barrier_1b → resume).

  Between barriers 0 and 1, the initiating core modifies EPT structures while
  responding cores apply their per-core updates.  This is safe because:
  - `TlbShootdown`: INVEPT invalidates TLB cache only, no page-table walk race.
  - `Switch/Revoke`: responding core deactivates its old VMCS (VMCLEAR) and
    activates the new domain's VMCS (VMPTRLD) — different VMCS from what the
    initiator touches.  The new domain's EPT is already set up (it's an existing
    domain).

  **monitor_loop refactor (needed for Switch/Revoke):**

  Currently `monitor_loop(vcpu: &mut ActiveVcpu) -> !` holds a single
  `ActiveVcpu` forever.  For domain switching, it must manage VCPU lifetime:

  ```rust
  pub fn monitor_loop(initial_vcpu: ActiveVcpu, platform: &ThemisPlatform) -> ! {
      let mut vcpu = initial_vcpu;
      loop {
          let exit_reason = vcpu.run();
          handle_vmexit(&mut vcpu, exit_reason, platform);
          // Drain per-core updates — may replace `vcpu` with a different domain's
          if let Some(new_vcpu) = platform.drain_core_updates(&mut vcpu) {
              vcpu = new_vcpu;
          }
      }
  }
  ```

  `drain_core_updates` returns `Some(new_vcpu)` when a Switch or Revoke
  deactivated the old VMCS and activated a new one.  The old `ActiveVcpu`
  is converted back to `InactiveVcpu` and stored in the old domain's `VcpuSlot`.

  **Implementation checklist:**

  - [x] **P3b-1**: Defined `CoreUpdate` enum (`TlbShootdown`, `Switch{..}`, `Revoke{..}`)
    and added `core_updates: [Mutex<VecDeque<CoreUpdate>>; MAX_CORES]` to `ThemisPlatform`.
    Added `push_core_update()` and `apply_local_core_updates()` methods.
  - [x] **P3b-2**: `send_ipi()` now pushes `TlbShootdown` + sets `ipi_pending` +
    sends INIT assert (delivery mode `0x5`, level assert).  Removed `CAPA_IPI_VECTOR`.
  - [x] **P3b-3**: Added `EXIT_REASON_INIT_SIGNAL = 3` handler in `vmexit.rs`.
    Uses `PLATFORM_PTR` global to access `ThemisPlatform` and call
    `poll_and_respond_cross_core()`.
  - [x] **P3b-4**: `poll_and_respond_cross_core()` now drains `core_updates[self]`
    between barriers via `apply_local_core_updates()`.  `Switch` and `Revoke` are
    `todo!("P9")` stubs.
  - [x] **P3b-5**: INIT handler uses `PLATFORM_PTR` global directly.  Full VCPU-swap
    `monitor_loop` refactor deferred to P9 (needs `ActiveVcpu` ownership transfer).
  - [x] **P3b-6**: No stale 0xF2/IDT references found; `CAPA_IPI_VECTOR` removed.
  - [x] **P3b-7**: Release build succeeds, no test regressions.  QEMU boot test
    pending manual validation.
- [x] **P3c**: ✅ DONE (EPT side).  `invept_for_domain()` calls INVEPT single-context
  after EPT updates and in `poll_and_respond_cross_core`.  IOTLB invalidation
  deferred to Phase 4 (VT-d).

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

- [x] **P7g-vmxon-global**: ✅ DONE.  Global `VMXON_PHYS: [AtomicU64; MAX_CORES]` in
  main.rs.  Allocated in boot.rs, stored per core.  No VMXON fields in VmxState/Domain.
  APs load from the global array after AP_LAUNCH_READY.

- [x] **P7g-platform-locking**: ✅ DONE.  Three-tier locking in ThemisPlatform:
  Tier 1 CoreContext (lock-free atomics), Tier 2 per-domain `Arc<Mutex<PlatformDomain>>`
  inside `RwLock<BTreeMap>`, Tier 3 `RwLock<RoutingMaps>`.  No single-Mutex wrapper.

- [x] **P7g-update-barriers**: ✅ DONE.  Two-phase barrier protocol documented and
  implemented in platform.rs (lines 1–67).  Lock ordering, deadlock prevention,
  per-core INVEPT on responding cores, INVEPT scope optimization noted.

- [x] **P7h**: ✅ DONE (core loop functional).  `monitor_loop` runs on all cores (BSP + APs).
  VMCALL dispatches to capability engine via `hypercall::handle_vmcall`.  HLT advances RIP.
  CoreContext + ActiveVcpu carry per-core state (no formal `VpContext` struct — not needed).

  **EPT violation policy**: EPT violations should not occur under normal operation —
  all memory accessible to a domain is pre-mapped via capability `ChangeRights` updates.
  An EPT violation indicates either a capability engine bug (missing mapping) or a guest
  accessing memory it does not own.  The current handler halts (`halt_forever()`).

  **TODO (semantics TBD)**: EPT violations need to be surfaced as a reportable event
  to the parent domain rather than halting the hypervisor.  Open questions:
  1. Should the violation be reported via the META VP-state page (Phase 10) as an
     exit reason the parent can inspect?
  2. Should it trigger an automatic domain kill / revocation, or should the parent
     decide the policy?
  3. How does this integrate with capabilities — is there a `Fault` update type, or
     does the parent's VMCALL_RUN_VP simply return with an error code?
  4. For dom0 (no parent), the violation is a fatal error — halt is correct.
  Design to be resolved when Phase 9 (multi-domain) is implemented.

- [x] **P7i — Post-boot cleanup and VP-setup factoring**:
  - **Code cleanup**: remove stale comments, dead code, resolved `TODO(P*)` markers.
  - **VP-setup factoring**: extract VP provisioning (VMXON, VMCS, VAPIC allocation +
    `setup_vmcs_for_vp`) into a single reusable `Platform::provision_vp()` path.
  - **Domain struct ownership review**: evaluate whether `domain::Domain` fields
    collapse into `PlatformDomain::vps: Vec<VpHardware>` exclusively.
  - **Module organisation**: split `platform.rs` if needed (~650 lines).
  - **VpContext definition**: pin in a stable location for P7h and Phase 8.

### Phase 8 — Hypercall Dispatch + Hypercall ABI

- [ ] **P8a**: `crates/themis-abi/`: opcode constants, `VpRegister` enum, error codes.
  Shared between capavisor and `libthemis` guest library.
- [ ] **P8b**: `hypercall.rs`: decode RAX, call `execute(||...)`, encode result.
- [ ] **P8c**: Implement all CapavisorAPI hypercall handlers listed in the Hypercall ABI table,
  including: `VMCALL_CARVE`, `VMCALL_ALIAS`, `VMCALL_SEND`, `VMCALL_ACCEPT`, `VMCALL_REJECT`,
  `VMCALL_CREATE_DOMAIN`, `VMCALL_SEAL`, `VMCALL_REVOKE_MEM`, `VMCALL_REVOKE_DOMAIN`,
  `VMCALL_SWITCH`, `VMCALL_GET_CHAN`, `VMCALL_ATTEST_SELF`, `VMCALL_ATTEST`,
  `VMCALL_GET_REG`, `VMCALL_SET_REG`, `VMCALL_SET_INTR_POLICY`, `VMCALL_SET_DEF_INTR_POLICY`.
  Stubs for `VMCALL_REGISTER_VP_META` and `VMCALL_REGISTER_DOORBELL` (implemented in
  Phases 10–11).
- [ ] **P8d**: `VMCALL_ASSIGN_DEVICE`: validate caller, reprogram IOMMU + I/O APIC.
- [x] **P8e**: `libthemis` guest library (`crates/libthemis/`): `no_std` VMCALL wrappers.
  Covers all 23 opcodes from `themis-abi`. Usable from Linux kernel module via FFI
  or from a bare-metal child domain.

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

### Phase 11 — ThemIC: Doorbell and Event Flag Pages

> **Renamed from TychIC.**  Redesigned to use generalized COMM capabilities
> (see COMM redesign below) instead of META pages.  See
> `2026/docs/design/mshv_themis/mshv_themis.md` §4 for the full ThemIC design.

Implements the SynIC-inspired cross-domain notification protocol.  ThemIC pages
are parent-owned COMM capabilities bound to child VPs.  Depends on COMM redesign.

**COMM Redesign** (capability engine change, prerequisite for ThemIC):

- [x] **P11-comm-a**: ✅ DONE.  Drop VITAL from COMM — `canonicalize()` now sets
  `COMM | CLEAN` (not VITAL).  Revoking a COMM page zeros memory but does not
  kill the owning domain.
- [x] **P11-comm-b**: ✅ DONE.  Allow multiple COMM per domain — `Domain` now has
  `comm_bindings: Vec<CapabilityWeak<MemoryRegion>>` (child-side list of parent
  COMM caps bound to this domain).
- [x] **P11-comm-c**: ✅ DONE.  `register_comm(caller, handle, child_domain_handle, vp_id)`
  implemented.  `MemoryRegion` carries `comm_binding: Option<CommBinding>` where
  `CommBinding = { target_domain_id, vp_id }`.  Weak ref pushed into child's
  `comm_bindings`.  `CommRegion` update includes target domain and VP ID.
- [x] **P11-comm-d**: ✅ DONE.  Auto-release on child revocation — revocation path
  iterates child's `comm_bindings`; clears COMM attribute + binding, emits
  `UncommRegion`.
- [x] **P11-comm-e**: ✅ DONE.  13 integration tests in `2026/tests/integration/comm.rs`:
  basic registration, carve/alias/send rejection, re-register rejection, multiple
  COMM per domain, VP ID validation, revocation emits UncommRegion, no domain
  revocation (no VITAL), zeroes memory (CLEAN), child revocation releases bindings.
- [x] **P11-comm-f**: ✅ DONE.  CLI-2026 updated for new `register_comm` signature:
  `cmd_register_comm()` accepts 3 args (`<mem> <child_domain> <vp_id>`),
  `Command::RegisterComm` has `child_domain` and `vp_id` fields.

**ThemIC protocol** (capavisor + driver, after COMM redesign):

- [ ] **P11a**: Define ThemIC message/event-flag/doorbell structs in `crates/themis-abi/`:
  `themic_message_page` (16 channels × 256 B), `themic_event_flag_page`,
  `themic_doorbell_entry`, `themic_intercept_message`, `themic_doorbell_message`.
- [ ] **P11b**: `VMCALL_REGISTER_DOORBELL(child_domain_handle, vp_id, gpa, size, datamatch, flags)`
  → doorbell_id.  Capavisor stores doorbell table per child domain.
- [ ] **P11c**: `VMCALL_UNREGISTER_DOORBELL(child_domain_handle, vp_id, doorbell_id)`.
- [ ] **P11d**: EPT_VIOLATION handler: check faulting GPA against registered doorbells.
  Match → write `themic_doorbell_message` to COMM page, set event flag, send doorbell
  IPI to parent core, advance child RIP, VMRESUME child (fast-path, child not stopped).
- [ ] **P11e**: `VMCALL_SET_THEMIC_VECTOR(vector)`: configure which IDT vector the
  capavisor uses for doorbell IPIs to dom0.  Default 0xF0.
- [ ] **P11f**: Intercept notification path (async mode): on child VP exit, write
  `themic_intercept_message` to COMM page channel 0, set event flag, send doorbell
  IPI to parent core.  Park child core waiting for resume/recover decision.

### Phase 12 — `themis-vmm.ko` Linux Kernel Driver *(superseded by Phase 15)*

> **Note**: Phase 15 (`mshv-themis`) replaces this phase with an mshv-compatible
> driver that reuses the well-known `/dev/mshv` ioctl ABI, enabling cloud-hypervisor
> integration.  The items below are retained for reference but should not be
> implemented independently.

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

### Phase 14.5 — Dom0 Image Upgrade (Jammy → Noble)

Upgraded the stock dom0 cloud image from Ubuntu Jammy 22.04 (kernel 5.15) to
Ubuntu Noble 24.04 (kernel 6.8) for better hardware support, Rust toolchain
availability, and newer kernel APIs.

- [x] **P14.5a** — ✅ DONE.  Image upgrade: updated `IMAGE_NAME` across 8 scripts
  (`fetch-dom0.sh`, `run-dom0.sh`, `run-qemu.sh`, `themis-debug.sh`, `build-iso.sh`,
  `mount-guest.sh`, `resize-disk.sh`, `README.md`) from `jammy-server-cloudimg-amd64.img`
  to `ubuntu-24.04-server-cloudimg-amd64.img`.
- [x] **P14.5b** — ✅ DONE.  Limine boot path fix: Noble splits `/boot` into a
  separate partition (`LABEL=BOOT`).  Changed Limine `module_path` from
  `fslabel(cloudimg-rootfs):/boot/vmlinuz` to `fslabel(BOOT):/vmlinuz`.
- [x] **P14.5c** — ✅ DONE.  AP triple-fault fix: Noble's 6.8 kernel trampoline
  writes `CR0_STATE & ~PG` (includes ET|NE) instead of just `PE`, causing extra
  CR_ACCESS VMEXITs during the 32-bit→64-bit transition.  Fixed
  `sync_ia32e_mode_guest()` in `vmexit.rs`: removed incorrect CS.L forcing
  that corrupted guest state when a VMEXIT hit the brief compatibility-mode
  window (LMA=1, CS.L=0) between enabling paging and the far jump.
- [x] **P14.5d** — ✅ DONE.  Improved VMEXIT diagnostics: added serial-lock
  guards to TRIPLE_FAULT, EPT_VIOLATION, EPT_MISCONFIG, and
  VMENTRY_INVALID_GUEST handlers to prevent garbled multi-core output.
  Added VP id, CS/SS state, IDTR, entry controls to dumps.
- [x] **P14.5e** — ✅ DONE.  Multi-version support: `scripts/dom0-versions.conf`
  registry with per-version image name, URL, and Limine boot paths.
  `scripts/dom0-lib.sh` provides `dom0_select` / `dom0_detect_from_guest_dir`.
  All scripts auto-detect which image is present and generate the correct
  Limine config.  Select explicitly via `DOM0_VERSION=jammy cargo themis`.

### Phase 15 — `mshv-themis` Linux Kernel Driver (mshv-compatible)

Capability-aware `/dev/mshv` replacement.  Exposes Themis's capability operations
through an ioctl interface modelled on Microsoft's `mshv` (Hyper-V) kernel driver,
so that existing VMM userspace (cloud-hypervisor) can target Themis with a thin
backend swap.  Replaces Phase 12's custom `/dev/themis` driver with a well-known
ABI.  Can be started at any time — missing capavisor features (e.g., SWITCH,
  SET_REG) will surface as stubs; the driver and cloud-hypervisor work can
  progress in parallel with the capavisor roadmap.

**Design principles**:
1. The driver is a **thin translation layer** — every ioctl maps to one or more
   Themis VMCALLs (capability operations).  No policy lives in the driver.
2. The ioctl surface mirrors `mshv`'s partition/VP model: create partition
   (= `CREATE_DOMAIN` + `SEAL`), map GPA (= `CARVE` + `SEND` + `ChangeRights`),
   set/get VP registers, run VP (= `SWITCH`).
3. Memory mapping uses capability transfer: userspace `mmap`s guest memory,
   driver issues `CARVE` to split the region and `SEND` to grant it to the child
   domain.  The capability engine enforces all access-control invariants.
4. Where `mshv` semantics diverge from capabilities (e.g., `mshv` assumes a flat
   GPA space; Themis uses explicit capability grants), the driver provides the
   adaptation glue.

- [x] **P15a** — ✅ DONE.  CPUID hypervisor leaves implemented in `vmexit.rs`:
  leaf `0x40000000` returns "ThemisCapa" vendor string + max leaf `0x40000003`;
  leaf `0x40000001` returns feature flags (bit 0: sync scheduling);
  leaf `0x40000003` returns capacity limits (256 VPs, 1024 partitions, 4096 mem regions).
  `THEMIS_REGISTER_COMM` opcode (0x18) wired in `hypercall.rs`.
  VP register profile (`VpGpRegs`, `VpSregs`, `SegmentReg`, `DescriptorTableReg`,
  `VpCommPage`) defined in `themis-abi/src/regs.rs`.
- [x] **P15b** — ✅ DONE.  `hvthemis/` kernel module skeleton:
  `hvthemis.h` (ioctl numbers magic 0xB8, uapi structs, internal driver structs),
  `hvthemis_main.c` (module init, CPUID "ThemisCapa" detection, misc_register `/dev/mshv`,
  device-level ioctl dispatch), `hvthemis_part.c` (partition fd via `anon_inode_getfile`,
  full lifecycle with kref, partition-level ioctl stubs), `hvthemis_vp.c` (VP fd lifecycle,
  RUN_VP/GET/SET_VP_STATE/mmap stubs), `hvthemis_hvcall.c` (VMCALL inline asm wrapper
  with Themis error→errno translation), `Makefile` + `Kbuild` (out-of-tree build).
  All ioctls return `-ENOSYS`; data structures fully wired.
- [x] **P15c** — ✅ DONE.  Partition ioctls wired to capavisor:
  `THHV_CREATE_PARTITION` → `themis_create_domain(cores_mask, api_flags, num_vps)`;
  `THHV_INITIALIZE_PARTITION` → pins shared META pages (MSR bitmap + IO bitmaps,
  3 pages from userspace) + `themis_seal(handle)`;
  partition destroy → `themis_revoke_domain(handle)` + unpin pages.
  Renamed entire driver from `hvthemis`/`MSHV` to `thhv`/`THHV` (`/dev/thhv`).
  Added `THHV_QUERY` ioctl with `META_PAGES_PER_VP` and `META_PAGES_SHARED` types.
- [x] **P15d** — ✅ DONE.  VP ioctls:
  `THHV_CREATE_VP` accepts `meta_uaddr` (2 per-VP META pages for VMCS + VAPIC) +
  `comm_uaddr` (1 COMM page for register state).  All pages pinned from userspace
  via `pin_user_pages_fast`, unpinned on VP release.
  `THHV_GET_VP_STATE` / `THHV_SET_VP_STATE` wired to per-register
  `themis_get_reg`/`themis_set_reg` as slow-path fallback.
  COMM page (`VpCommPage`) will be the fast path once REGISTER_COMM + SWITCH are wired.
  Capavisor GET_REG/SET_REG handlers still return ERR_UNIMPL — needs P15e first.
- [x] **P15e** — ✅ DONE (driver side).  Memory mapping via `THHV_SET_GUEST_MEMORY`:
  userspace provides child GPA (`guest_pfn`), host VA, size + flags, rights, attrs.
  Driver: pins pages → translates dom0 GPA→HPA via `thhv_translate_pages()` →
  CARVE/ALIAS per HPA segment → `themis_send_at(cap, child, attrs, child_gpa)` to
  place each segment at the correct child GPA offset.
  Multi-segment support for non-contiguous GPA→HPA mappings.
  PA map: driver-internal, populated from attestation at init (currently identity
  passthrough until attestation mechanism is designed — see P15-translate below).
  COMM page: CARVE + REGISTER_COMM wired at CREATE_VP time.
  META pages: CARVE + SEND deferred until capavisor EPT allocation from META pool.
- [x] **P15f** — ✅ DONE (driver side).  `THHV_RUN_VP` with sync and async paths:
  Sync: `themis_switch(domain, vp)` blocks until VM-exit, reads COMM page exit
  info area (offset 512+), formats `thhv_exit_msg` for userspace.
  Async: parks thread on `exit_wq` (TODO: actual async kick + doorbell/eventfd
  notification mechanism).
  Exit types (PROVISIONAL): HLT, IO, MMIO, CPUID, MSR, SHUTDOWN, INTR,
  MEMORY_FAULT, EXCEPTION, HYPERCALL.  Exit type taxonomy needs design review —
  depends on which exits the capavisor handles internally vs forwards to parent.
  VMX reason mapper uses `<asm/vmx.h>` constants but the capavisor may translate
  exit reasons via its platform abstraction before the driver sees them.
  Capavisor SWITCH handler still stubbed (ERR_UNIMPL) — needs implementation.

#### P15-translate — GPA→HPA Translation & DomainComm

  The driver maintains a GPA→HPA translation map (`thhv_translate.c`) so that
  `SET_GUEST_MEMORY` can translate pinned pages' dom0 GPAs to real HPAs before
  issuing CARVE/ALIAS capability operations.

  **Memory mapping flow** (userspace perspective):
  1. Userspace `mmap()`s a region, gets a VA
  2. Userspace calls `THHV_SET_GUEST_MEMORY(va, child_gpa, size, flags, rights, attrs)`
  3. Driver: pins pages (VA → struct page → dom0 GPA via `page_to_pfn`)
  4. Driver: translates dom0 GPA → HPA via the PA map (from attestation)
  5. Driver: `themis_carve(0, HPA, size, rights)` → capability on real physical memory
  6. Driver: `themis_send_at(cap, child, attrs, child_gpa)` → maps at correct child GPA

  **PA map population** — Derived from binary attestation report:
  The PA map is part of the binary attestation (DOMCOMM_MSG_ATTEST) delivered
  via the DomainComm RX ring at boot.  The driver parses the attestation to
  populate the `thhv_translate.c` rb-tree, learn capability handles, and
  configure domain policies.  See `thhv/docs/domain-comm-v0.2.md` for the full
  DomainComm design.

  **DomainComm bootstrap (dom0)**:
  - Capavisor pre-allocates DomainComm pages during dom0 creation
  - Pages marked as e820 type 2 (reserved); GPA reported via CPUID leaf 0x40000002
  - RX ring pre-populated with binary attestation (capability handles, PA map entries)
  - Driver reads CPUID → `memremap()` → dequeue attestation → bootstrapped

  **Capability engine stays clean**: REGISTER_COMM is unchanged (no COMM subtypes).
  The platform layer distinguishes DomainComm (self-ref: target == owner) from
  VP-level COMM (target != owner) based on the CommBinding.  Rings are growable
  via CARVE + GROW messages after bootstrap.  Recursive design: same API for
  dom0, children, grandchildren.

  **send_at ABI extension**:
  `themis_send_at(cap, receiver, attrs, child_gpa)` added to libthemis FFI.
  Uses VMCALL arg3 (RCX) for the child GPA hint.  The capavisor's `do_send`
  handler needs updating to pass this 4th argument to `Capability::send_at()`.
  Currently the capavisor ignores RCX in SEND — TODO.

- [ ] **P15g** — Interrupt injection: `THHV_ASSERT_INTERRUPT` → `VMCALL` or posted
  interrupt path.  `THHV_IRQFD` → eventfd + workqueue → PI descriptor write.
- [ ] **P15h** — `mmap` for VP state: userspace maps COMM page for
  zero-copy register access and exit reason inspection.
- [ ] **P15i** — Device assignment: `THHV_ASSIGN_DEVICE` → `VMCALL_ASSIGN_DEVICE`
  (Phase 4 IOMMU required).

#### P15-domcomm — DomainComm Implementation (see `thhv/docs/domain-comm-v0.2.md` §16)

  Incremental implementation with validation at each milestone:

- [x] **P15-dc-m0** — Binary attestation format: Define `domcomm_*` structs in
  `thhv.h` (C) and capavisor (Rust).  DomainComm header, message header,
  attestation report with mem_cap/dom_cap/pa_map entries.
- [x] **P15-dc-m1** — Capavisor pre-allocation: Allocate 4 DomainComm pages for
  dom0 at domain creation, e820 reserved, CPUID leaf 0x40000002, write header +
  binary attestation to RX ring.  **Test**: `cargo themis` boots normally.
- [x] **P15-dc-m2** — Driver discovery + parsing: CPUID discovery, `memremap()`,
  header validation, page-aware RX dequeue, parse attestation → PA map rb-tree +
  capability handles.  **Test**: `thhv-test-attest` userspace tool queries
  parsed info via ioctl.
- [ ] **P15-dc-m3** — Capability table + PA map validation: Implement the driver-side
  capability table (§17 of domain-comm-v0.2.md): global cap table (rb-tree by
  local_handle), per-partition sent-caps list, parent handle lookup by HPA.
  Replace ad-hoc `attest_caps[]` and `thhv_mem_cap` tracking.  Fix REVOKE to
  use `(parent_handle, sub)`.  **Test**: `insmod` loads attestation caps into
  the cap table; CARVE inserts, SEND removes + appends to sent_caps.
- [ ] **P15-dc-m4** — Ring growth: TX enqueue in driver, GROW_RX/TX messages,
  capavisor growth handler, platform CommBinding self-ref detection.
  **Test**: `thhv-test-grow` triggers growth, verifies expanded ring.
- [ ] **P15-dc-m5** — Async VP exit delivery: Capavisor writes VP_EXIT to
  parent's RX ring, driver dispatches to VP waitqueue.  **Test**:
  `thhv-test-vpexit` creates child VP, triggers exit, verifies DomainComm path.
- [ ] **P15-dc-m6** — Capability enumeration: ENUM_CAP request/response via
  TX/RX rings.

### Phase 16 — Cloud-Hypervisor Themis Backend

Add a Themis/mshv-themis hypervisor backend to cloud-hypervisor, enabling it to
create and run VMs on top of Themis via capability operations.  Can be started
in parallel with Phase 15 (stub missing ioctls); both phases progress alongside
the capavisor roadmap.

**Approach**: cloud-hypervisor already supports KVM and MSHV backends via the
`hypervisor` crate abstraction.  The Themis backend plugs into the same trait
hierarchy (`Hypervisor`, `Vm`, `Vcpu`) using `/dev/mshv` ioctls from Phase 15.

- [ ] **P16a** — Fork/branch cloud-hypervisor; add `hypervisor/src/themis/` module
  implementing the `Hypervisor` trait.  `Themis::new()` opens `/dev/mshv` and
  verifies the Themis CPUID vendor string.
- [ ] **P16b** — `ThemisVm` implementing the `Vm` trait: wraps a partition fd.
  `create_vm()` → `MSHV_CREATE_PARTITION`.  `set_memory_region()` →
  `MSHV_MAP_GUEST_MEMORY`.  `create_irq_chip()` / `set_irq_routing()` → Themis
  interrupt policy VMCALLs.
- [ ] **P16c** — `ThemisVcpu` implementing the `Vcpu` trait: wraps a VP fd.
  `run()` → `MSHV_RUN_VP`, decode exit reason, return `VcpuExit` enum.
  `set_regs()` / `get_regs()` → `MSHV_SET_VP_REGISTERS` / `MSHV_GET_VP_REGISTERS`.
- [ ] **P16d** — Memory management: adapt `GuestMemoryMmap` regions to
  `MSHV_MAP_GUEST_MEMORY` calls.  Handle capability-specific constraints
  (alignment, region splitting).
- [ ] **P16e** — Device passthrough: PCI device assignment via `MSHV_ASSIGN_DEVICE`.
  VFIO integration if needed for userspace device access.
- [ ] **P16f** — virtio device backends: verify virtio-blk, virtio-net, virtio-console
  work over the Themis backend (they should — virtio is guest-kernel ↔ VMM
  userspace, independent of hypervisor backend).
- [ ] **P16g** — Boot integration: kernel + initrd loading, boot parameter setup.
  Adapt cloud-hypervisor's direct kernel boot or firmware boot paths to use
  Themis VP register setup.
- [ ] **P16h** — End-to-end validation: boot a Linux guest under cloud-hypervisor
  running on Themis.  Test: serial console, virtio-blk root disk, SSH.

### Phase 17 — Dom0 Networking

Enable network connectivity for the dom0 Linux guest.  Can be started at any
time — the dom0 kernel already boots to a login prompt; this phase adds the
kernel config and QEMU/bare-metal setup needed for a working NIC.

- [ ] **P17a** — **QEMU networking (without Themis)**: Validate dom0 kernel has
  network driver support (e1000/virtio-net).  Run dom0 under QEMU with
  `-netdev user,id=n0 -device virtio-net-pci,netdev=n0` (or e1000).
  Verify `ip link` shows the interface, DHCP works, `ping` succeeds.
  Document the working QEMU command line.
- [ ] **P17b** — **Kernel config for networking**: Ensure dom0 kernel config
  includes `CONFIG_VIRTIO_NET=y`, `CONFIG_E1000=y` (or `=m`), TCP/IP stack,
  DHCP client support.  If using a minimal initrd, include `dhclient` or
  `udhcpc`.
- [ ] **P17c** — **Networking under Themis**: Boot dom0 under Themis with
  QEMU NIC passthrough.  Verify the NIC's MMIO BAR is EPT-mapped (should
  happen automatically via PCI BAR enumeration in boot.rs).  Verify
  interrupts are delivered (MSI/MSI-X or INTx via IOAPIC passthrough).
  Debug any missing EPT mappings or interrupt delivery issues.
- [ ] **P17d** — **Bare-metal networking**: On real hardware, identify the
  physical NIC, verify its MMIO BARs and MSI-X vectors are EPT-mapped.
  If the NIC requires IOMMU (VT-d) for DMA, this depends on Phase 4.
- [ ] **P17e** — **Validation**: SSH into dom0, `curl` an external URL,
  `apt`/`apk` package install over the network.

### Phase 18 — Monitor-Provided Hypercall Library (Exploratory)

Explore having the capavisor provide a pre-compiled hypercall stub library
(libthemis) to the parent domain at runtime, eliminating the need for the
kernel driver to maintain its own VMCALL wrappers and ensuring ABI version
match with the running capavisor.  See `2026/docs/design/mshv_themis/mshv_themis.md`
§18 for full design discussion.

- [ ] **P18a** — Evaluate approach: COMM-injected PIC binary vs Hyper-V-style
  hypercall page vs Rust kernel module vs FFI static library.  Select approach.
- [ ] **P18b** — If COMM/hypercall-page approach chosen: compile libthemis as
  flat PIC binary with function table header.  Validate size fits in 1–2 pages.
- [ ] **P18c** — Capavisor-side: populate COMM page (or map hypercall page) with
  compiled stubs at domain boot or on first `VMCALL_MAP_HYPERCALL_PAGE`.
- [ ] **P18d** — Driver-side: discover and map the stub page, call into it
  instead of issuing inline VMCALL assembly.
- [ ] **P18e** — Validation: verify round-trip for all capability operations
  through the injected stubs.

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
