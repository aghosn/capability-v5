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
**🚧 IN PROGRESS: dom1 (nested Ubuntu Noble) boot under CHV on Themis.**

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
- Phase 15.5 Phase 1 completed (intr-p1-vmcs/routing-table/forward/switch-ctx) — VAPIC+VID, interrupt policy routing, forward_interrupt_to_handler, SwitchContext interrupt_return.
- Phase 15.5 Phase 2 complete (intr-p2-pid/notify-vec/inject/test) — PID allocation, VMCS fields, inject_via_pid with cross-core IPI, test_intr_loop validated (748 interrupts forwarded, dom0 stable).
- **dom1 boot unblocked (2026-03-20)**:
  - Fixed `do_send` GPA-0 sentinel bug (`0` → `u64::MAX` for identity-map; `0` is now a valid explicit GPA).
  - Fixed `thhv_hvcall.c::themis_send` META pages used wrong sentinel → `RegionOverlap`.
  - Fixed VMCS guest-state validity: CR0 FIXED0, CR4 VMXE, LDTR_AR unusable enforcement.
  - Fixed `dom0-kernel-version.txt` pointing to wrong kernel (106 vs 101); thhv.ko now matches dom0.
  - Fixed `thhv.h` missing `#include <linux/poll.h>` (pre-existing build error).
  - Implemented CPUID exit emulation in CHV Themis backend (`handle_cpuid_exit`).
  - Implemented `set_cpuid2` to store CHV's filtered CPUID policy per-VP.
  - Dom1 now executes past GPA 0x100000 into the `hypervisor-fw` firmware region.

- **dom1 Linux kernel boot debugging (2026-03-23)** — using `themis_trace()` VMCALL
  instrumentation (see `skills/debugging-dom-boot.md` for full trace code registry and
  procedure). Current state of `../linux` (relative to repo root): instrumented bzImage
  is built and packed into `themis/guest/bins.img` as `nested/bzImage` (kernel #18).
  Run `cargo themis` then `sudo /opt/bins/cloud-hypervisor/run-dom1.sh` inside dom0
  and check `grep '\[DBG\]' /tmp/out.txt` for traces.

  Bugs fixed during this session:
  - **nopv**: added `nopv` to dom1 kernel cmdline in `themis/scripts/run-dom1.sh`.
    Without it, dom1 hangs in `pvclock_read_flags()` spinning on an odd version because
    CHV never initialises the pvclock struct after `MSR_KVM_SYSTEM_TIME_NEW` write.
    See P16.6b2 for long-term fix.
  - **CPUID 0x40000000 for child domains**: added `EXIT_REASON_CPUID` to child domain
    dispatch in `capavisor/src/vmexit.rs` — returns "ThemisCapa" for hypervisor leaves
    (0x40000000–0x4FFFFFFF), forwards all other leaves to CHV. Without this, dom1 saw
    "KVMKVMKVM" and `ms_hyperv_platform()` hung (ms_hyperv has `ignore_nopv=true`).
  - **APIC_ACCESS for child domains (IN PROGRESS as of 2026-03-23)**: root cause and
    design fully understood. Summary:

    Root cause: dom1's EPT has NO mapping for GPA `0xFEE00000`. Guest LAPIC MMIO
    accesses cause `EXIT_REASON_EPT_VIOLATION` (forwarded to CHV). CHV's
    `handle_mmio_exit` calls `advance_rip(rip, instruction_length=0)` — EPT violations
    do NOT populate `VMEXIT_INSTRUCTION_LEN` in hardware, so RIP never advances →
    infinite loop / hang.

    Fix: `VIRTUALIZE_APIC_ACCESSES` is already set in child VMCS (bit 0, secondary
    controls) when `apic_access_phys != 0`. `APIC_ACCESS_ADDR = apic_access_phys` is
    already written. What is missing is the EPT mapping `GPA 0xFEE00000 →
    apic_access_phys` in the child domain's EPT. Once this mapping exists, hardware
    fires `EXIT_REASON_APIC_ACCESS` (44) instead of EPT violations, instruction_length
    is populated, and `handle_apic_access_exit` handles it correctly.

    Design decisions confirmed (cross-checked against KVM `vmx.c`):
    - `VIRTUAL_APIC_PAGE` (vapic_phys) is **per-vCPU**: holds APIC register state.
    - `APIC_ACCESS_ADDR` (apic_access_phys) is **per-partition** (shared across vCPUs):
      just a sentinel HPA. EPT is per-partition (one mapping for all vCPUs), so
      APIC_ACCESS_ADDR must be the same for all vCPUs of a partition — it CANNOT be the
      same page as vapic_phys. KVM uses the same split (per-VM apic_access page vs
      per-vCPU virtual APIC page). Contents of apic_access_phys are never read/written
      by anyone — it is purely a unique HPA sentinel.
    - For any APIC operation requiring parent (dom0) involvement, the COMM channel
      handles the notification path. No APIC exits need to reach dom0 directly.

    **Next step**: ~~In `do_add_vp` (first VP of a child partition), after allocating
    `apic_access_phys`, call `platform.apply_update(&Update::ChangeRights { ... })` to
    add EPT mapping `GPA 0xFEE00000 → apic_access_phys` for the child domain.~~ **DONE
    via capability system (2026-03-23)**:
    - `struct thhv_initialize_partition` extended with `apic_access_uaddr` + `apic_access_size`
    - `THHV_SEND_SHARED_META` handler pins CHV-provided page, CARVEs from dom0, SEND_AT
      to child at GPA `0xFEE00000` → `ChangeRights` → EPT mapping (fully capability-mediated)
    - `thhv_set_guest_memory` guards against any overlap with `[0xFEE00000, 0xFEEFFFFF]`
    - capavisor `apply_update → ChangeRights` detects `address == 0xFEE00000` on child
      domain and stores `physical` as `apic_access_phys` (architectural constant, not magic)
    - `do_add_vp` no longer allocates `apic_access_phys` from META (removed); reads it
      from `pd.apic_access_phys` set by ChangeRights; first-VP META pages reduced 5→4
    - CHV allocates `apic_access` mmap (1 page), passes to `ThhvInitializePartition`,
      keeps it alive in `ThemisVmState::_apic_access`
    - **Next**: build + deploy and check trace advances past `0x2A4`

    **Build/deploy bugs found and fixed (2026-03-23)**:
    - `thhv.ko` was stale (Mar 20) despite `cargo build-bins` — Makefile only checks
      `liblibthemis.a` freshness. Fix: `touch src/thhv_part.c` before `make` to force
      rebuild when headers change.
    - Compile error: `sc->cap_handle` doesn't exist in `struct thhv_sent_cap`; correct
      field is `sub_handle`. Fixed in `thhv_part.c`.
    - `EEXIST` from `THHV_CREATE_VP`: after `themis_send_at` for APIC access page
      succeeds, `cap_handle` was left in the cap table. Capa engine reuses the same slot
      number for the next `CARVE` (COMM page in `THHV_CREATE_VP`). `thhv_cap_table_insert`
      returns `EEXIST`. Fix: call `thhv_cap_table_remove(cap_handle)` after successful
      `themis_send_at`, matching the pattern in `thhv_send_meta_pages`.
    - **Next**: re-run dom1 boot and check trace advances past `0x2A4`

  Last known trace sequence (kernel #18, as of 2026-03-23):
  ```
  0x293 (early_acpi_boot_init: after blacklist check)
  0x2A0 (apic_set_fixmap entry)
  0x2A1 (set_fixmap_nocache done)
  0x2A3 (apic_read_boot_cpu_id entry)
  → HANG at 0x2A4 (read_apic_id() MMIO read at 0xFEE00020) — EPT violation, RIP stuck
  ```

- **dom1 MMIO emulation fixes (2026-03-24)** — three critical bugs fixed:

  1. **MSR save/restore on VMCS switch** (`crates/vmx/src/vcpu.rs`):
     STAR, LSTAR, CSTAR, FMASK, KERNEL_GS_BASE were not saved/restored when
     switching between dom0 and dom1 VMCS. Dom1's `swapgs` corrupted dom0's
     KERNEL_GS_BASE → next interrupt in dom0 used wrong per-CPU base → double fault.
     Fix: manual RDMSR in `deactivate()`, WRMSR in `activate()`.

  2. **Instruction length for EPT violations** (`capavisor/src/hypercall.rs`):
     `VMEXIT_INSTRUCTION_LEN` is undefined for EPT violations (Intel SDM §27.2.1).
     Hardware returned 3 for a 4-byte `mov [rax+0x10], r13d` → RIP landed mid-instruction
     → page fault. Fix: decode full instruction length from ModR/M (SIB, disp8/disp32)
     in `decode_mmio_insn()`. Capavisor uses decoded length for EPT violations, falling
     back to `next_instruction()` for other exit types.

  3. **Per-exit EPT logging** (`capavisor/src/hypercall.rs`):
     Added `[EPT]` and `[EPT-DEC]` serial_println! lines for every EPT exit: GPA, RIP,
     qualification, decoded register, THHV constant, is_write, value, length.

  Results after fixes:
  - Dom0 double fault eliminated (MSR fix)
  - 202 EPT exits processed correctly (instruction length fix)
  - IOAPIC redirect table fully read and restored (registers 0x10-0x3F)
  - Dom1 reached trace 0x347 (past `enable_IR_x2apic` completely)
  - Dom1 reached 0x313/0x314 (past `x86_late_time_init` → `setup_boot_APIC_clock`)
  - Dom1 reached 0x301, 0x7 (further into boot)

  Current trace sequence (kernel #24):
  ```
  0x0–0x4f  (early boot) ✅
  0x210–0x2bb (setup_arch) ✅
  0x200–0x209 (start_kernel) ✅
  0x340–0x347 (enable_IR_x2apic — IOAPIC save/restore) ✅
  0x310–0x314 (x86_late_time_init — setup_boot_APIC_clock) ✅
  0x301, 0x7
  → HANG: soft lockup at themis_switch — dom1 stuck in timer calibration loop
  ```

  **Current blocker**: dom1 hangs in APIC timer calibration (`calibrate_APIC_clock`
  or `calibrate_delay`) waiting for a timer interrupt that never arrives. No periodic
  timer source exists to inject interrupts into dom1. See P16.6a for fix.

  **Architecture note — PV IOAPIC (future)**: long-term, IOAPIC will be paravirtualized
  (inspired by MSHV SynIC) to eliminate MMIO emulation, instruction decode, and RIP
  length issues. The current MMIO plumbing is the bootstrap path for stock kernels.
  See P16.6d3 for details.

- **Timer injection + ACPI platform debugging (2026-03-24 session 2)** —

  **Progress**:
  1. ✅ Timer injection via timerfd + IRQFd (1kHz at vector 0xEC) — working
  2. ✅ irqfd wakeup crash: `thhv_irqfd_wakeup` dereferenced key as pointer;
     key is `poll_to_key()` value. Fixed: `(__poll_t)(unsigned long)key`.
  3. ✅ VM-entry failure (exit reason 33): PIR→VMENTRY injection without checking
     RFLAGS.IF and interruptibility state. Fixed: check before inject, put PIR
     bit back if guest can't accept.
  4. ✅ Serial flooding: removed `pr_info` from `thhv_irqfd_inject` and
     `serial_println!` from `do_inject_interrupt` (both on 1kHz hot path).
  5. ✅ `lapic_timer_frequency=1000000000` kernel param skips APIC timer calibration.
  6. ✅ `max_phys_bits=34` — resolves CHV AddressAllocator crash (64-bit MMIO
     region needs >4GB alignment). phys_bits=32/33 had MMIO64 range < 4GB.
  7. Dom1 now reaches 117 traces, 204 EPT exits, gets to ACPI init.

  **Current blocker — ACPI platform MMIO decode failure**:
  CHV places platform devices (GED, CPU manager) at ~16GB (GPA 0x3FFEF0000
  with phys_bits=34). Guest ioremap works (EPT violations fire correctly at
  MMIO GPAs). But capavisor's `decode_mmio_insn()` fails on `MOVZX r32,r/m8`
  (`0F B6 00`) — only handles MOV (0x89/0x8B). When decode fails:
  - RIP advanced using UNDEFINED `VMEXIT_INSTRUCTION_LEN` (corrupts guest state)
  - MMIO register/size info not extracted → result not injected properly
  - Guest crashes with `#PF at 0x3FFFEE00C` (ACPI `_STA` evaluation path)

  **Root cause**: instruction decode in capavisor is fundamentally fragile.
  Each new instruction variant (MOVZX, MOVSX, byte MOV, etc.) requires more
  decode logic. This is a bottomless pit.

  **Solution — MSHV-style MMIO emulation (P16.6i)**:
  Move instruction decode out of capavisor into CHV using CHV's existing
  x86 emulator infrastructure (iced-x86 + `arch/x86/emulator/`), matching
  the MSHV backend's architecture. See P16.6i below.

  Platform MMIO EPT exit flow:
  ```
  [EPT violation] GPA=0x3fffee004 (MOVZX eax, byte [rax])
    → dom1 EPT violation → capavisor
    → reads instruction bytes from guest memory (already works)
    → fills intercept message: instruction_bytes, GPA, exit_qual
    → does NOT advance RIP, does NOT decode operands
    → forwards to dom0 (thhv.ko → CHV)
    → CHV Themis backend: iced-x86 decodes instruction_bytes
    → emulator: reads byte from device (mmio_read), zero-extends to EAX
    → emulator: advances RIP by 3 (instruction length)
    → CHV sets new registers via set_reg_values (RAX + RIP)
    → dom0 SWITCH back → capavisor applies new state → dom1 resumes
  ```

- **P16.6i implemented — MSHV-style MMIO emulation (2026-03-24 session 3)** —

  ✅ Moved instruction decode from capavisor to CHV's iced-x86 emulator.
  Handles MOV, MOVZX, CMP, MOVS, STOS, OR + all variants out of the box.
  - `hypervisor/Cargo.toml`: `themis = ["mshv_emulator"]`
  - `hypervisor/src/themis/emulator.rs` (NEW): ThemisEmulatorContext with
    x86-64 page-table walker (CR3→PML4→PDPT→PD→PT), GVA→GPA→RAM/MMIO routing
  - `hypervisor/src/themis/mod.rs`: `handle_mmio_exit` → `emulate_first_insn()`
  - `capavisor/src/hypercall.rs`: removed decode_mmio_insn, MmioInsn,
    x86_reg_to_gpr, x86_reg_to_thhv; no RIP advance for EPT violations

  Test result: 200+ IOAPIC MMIO R/W at 0xFEC00000 — all emulated correctly.
  Previously-crashing MOVZX pattern would now be handled by iced-x86.

  ✅ XSETBV (exit reason 55) — refactored `handle_xsetbv()` into a shared
  helper in vmexit.rs, called from both dom0 and child domain exit paths.
  Was previously only handled for dom0; child exits went through catch-all
  forward-to-parent → CHV ignored → guest stuck in loop.

  **Remaining milestones for dom1 boot**:
  - [ ] Enable multi-core for dom1 (CHV_CPUS>1) — SMP bringup
  - [ ] Switch from instrumented debug kernel back to stock cloud image kernel

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
  send_ipi (xAPIC MMIO INIT assert — see #U5 note), sync_barrier (two-phase AtomicUsize),
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

**Page allocation strategy** (mirrors IRT approach from Phase 3):
IOMMU table pages (root tables + context tables) come from the META pool — the same
capavisor-private pool that holds VMXON/VMCS/VAPIC/IRT pages.  META pages are excluded
from all EPT mappings so no guest can ever touch them.

To get the *exact* count before `partition()` runs, we extend the early ACPI pre-pass
(already done for DMAR in `platform()`) to also read the MCFG table (ACPI RAM, safe
early).  MCFG gives us the ECAM bus ranges per PCI segment.  Combined with the DRHD
count from DMAR we compute:

  root_pages        = n_drhd_units                            (1 page per DRHD)
  context_pages     = Σ (end_bus − start_bus + 1) per DRHD   (1 page per bus in segment)

For QEMU q35 (1 DRHD, segment 0, buses 0–255): 1 + 256 = 257 pages ≈ 1 MiB.
On real hardware with fewer buses the count is proportionally smaller.

Scope rule: for the initial implementation we handle only `INCLUDE_PCI_ALL` DRHDs
(covers all buses in the segment's ECAM range).  Scoped DRHDs are a future hardening item.

Dom0 uses **passthrough translation type** (context entry bits[1:0] = `10b`) so no
DMA page table is needed for dom0.  The IOMMU passes dom0 device DMA addresses straight
through to physical.  DMA PTs are introduced in P4e/P4f for child-domain isolation.

**RMRR note**: RMRR regions are reported by ACPI for legacy devices (USB, graphics)
that DMA to fixed physical ranges.  With passthrough mode for dom0 these regions are
implicitly covered — no extra mapping needed until we move to a real dom0 DMA PT in P4d.
P4d is therefore deferred until we have child-domain DMA isolation (P4e).

- [x] **P4a**: ✅ DONE (Phase 3).  DRHD units parsed from DMAR in `acpi.rs`; stored in
  `AcpiInfo.drhd_units` and `ThemisPlatform.drhd_units`.

- [x] **P4b**: ✅ DONE. Early ACPI pre-pass: extend to also parse MCFG → collect
  `EcamRegion { segment, start_bus, end_bus, base_phys }` into `AcpiInfo`.
  Compute exact META reservation: `iommu_root_pages = n_drhd`,
  `iommu_ctx_pages = Σ bus_count_per_drhd_segment`.  Add both fields to
  `MetaBreakdown` in `inventory.rs` so `partition()` reserves them correctly.
  In `init_themis()` for each DRHD:
    - alloc 1 META page → root table (zero it)
    - for each bus in segment: alloc 1 META page → context table (zero it)
    - fill root table entry N → present, context table phys
    - fill all 256 context entries per table → passthrough (`tt=10b`, `did=1` for dom0)
    - write `RTADDR_REG = root_phys | 0` (legacy translation mode), issue `GCMD.SRTP`,
      poll `GSTS.RTPS`
  Store `root_phys` and `Vec<(bus, ctx_phys)>` back into `DhrdUnit` (or a new
  `IommuUnit` struct in `platform.rs`).
  Bugs fixed: CTX_LOW 0x5→0x9 (TT bits[3:2] not bits[2:1]), CCMD CIRG bit[61] not
  bit[60], AW read from CAP.SAGAW at runtime (QEMU only supports AW=1/39-bit).

- [x] **P4c**: ✅ DONE. Enable VT-d DMA translation per DRHD.
  Sequence: `GCMD.TE = 1` → poll `GSTS.TES`.  WARN on timeout (same pattern as
  intr-p3c).  Log "DMA translation enabled on DRHD 0x…".
  After this point every PCIe DMA goes through the IOMMU; dom0 sees passthrough.

- [ ] **P4d** ⏸ DEFERRED: RMRR identity mapping in dom0 DMA PT.  Not needed while
  dom0 uses passthrough translation type.  Revisit when dom0 gets a real DMA PT.

- [x] **P4e**: ✅ DONE. IOMMU second-level page table (SLPT) per child domain.
  Reuses `EptMapper` (VT-d SLPT format is bit-compatible with EPT: same R/W/X
  bits, same phys addr layout).  Added `alloc_root_at_level(level)` + `root_phys()`
  to EptMapper.  Added `aw: u64` to `DhrdUnit` (stored from CAP.SAGAW in P4b).
  Added `iommu_pt: Option<EptMapper>` to `PlatformDomain` + `ensure_iommu_pt(level)`.
  `ThemisPlatform::iommu_pt_level()` derives `Level::L3`/`L4` from min SAGAW AW.
  `apply_update` mirrors EPT changes into SLPT: `ChangeRights(rights≠0)` maps,
  `ChangeRights(rights=0)` unmaps, `RevokeDomain` frees the SLPT tree.

- [x] **P4f**: ✅ DONE. Device assignment hypercalls.
  `ThemisPlatform::assign_device(bdf, domain_id)`: looks up context table for bus,
  writes TT=00/SLPTPTR context entry + flushes context-cache (device-selective) and
  IOTLB (global).  `release_device(bdf)`: restores dom0 passthrough entry.
  Added `THEMIS_ASSIGN_DEVICE` (0x12) + `THEMIS_RELEASE_DEVICE` (0x1a) hypercalls
  in hypercall.rs.  dom0 passes domain_handle + BDF to assign; BDF alone to release.

### Phase 5 — APICv and Virtual APIC

- [ ] **P5-ept-verify**: DEFERRED — Replace `crates/ept/` vmxvmm port with the formally-verified
  EPT from `asterinas/hyperenclave` (ASPLOS'24, Rust MIR → Coq proofs, Apache-2.0).
  Steps: clone hyperenclave, locate `src/memory/ept.rs` (or equivalent), strip
  TEE/enclave policy, adapt to our `FrameAllocator` trait and local address types,
  run unit tests under `x86_64-unknown-linux-gnu`.  This restores the original P0c plan.

- [x] **P5a**: Per-VP allocation: VAPIC page (4 KB from `FrameAllocator`) and
  posted-interrupt descriptor (64 B, 64 B-aligned from `FrameAllocator`).
  ✅ DONE: VAPIC in domain.rs, PID in VcpuSlot.pid_phys; both written to VMCS.
- [x] **P5b**: APIC access page: one 4 KB page per domain at APIC MMIO address (0xFEE00000);
  used by `APIC_ACCESS_ADDR` VMCS field for xAPIC mode.
  ✅ DONE (cdb85c0): per-domain apic_access_phys from META; VIRTUALIZE_APIC_ACCESSES
  (bit 0) enabled for child VPs; EXIT_REASON_APIC_ACCESS (44) handler in vmexit.rs.
- [x] **P5c**: VMCS secondary execution controls (when `CpuFeatures::apicv`):
  `VIRTUALIZE_X2APIC | APIC_REG_VIRT | VIRT_INTR_DELIVERY`.
  Pin-based controls: `PROCESS_POSTED_INTERRUPTS`.
  VMCS fields: `VIRTUAL_APIC_PAGE_ADDR`, `POSTED_INTR_DESC_ADDR`, `POSTED_INTR_NV`,
  `APIC_ACCESS_ADDR`, EOI-exit bitmap (zeroed initially).
  ✅ DONE: all bits set in vmcs.rs; VIRTUALIZE_X2APIC (bit 4) added in e6ebc30.
- [x] **P5d**: `vapic::inject_virtual_interrupt(vapic_page, vector)`:
  set bit in VIRR (offset 0x200 + vector/8 in VAPIC page); update RVI (requesting
  virtual interrupt = highest VIRR bit that exceeds PPR).
  ✅ DONE (26eecc2): `inject_virtual_interrupt` in vmexit.rs.
- [x] **P5e**: `vapic::post_interrupt(pi_desc, vector)`:
  set `PIR[vector]` bit atomically; set `ON` (outstanding notification) bit;
  send posted-interrupt notification IPI (NV) to target LAPIC if domain VP is running.
  ✅ DONE: `inject_via_pid` + `forward_interrupt_to_handler` in hypercall.rs.
- [x] **P5f**: Fallback path: if `!CpuFeatures::apicv`, disable all APICv VMCS bits;
  emulate APIC register access via VMEXIT.
  ✅ DONE: VMENTRY_INTERRUPTION_INFO_FIELD fallback in forward_interrupt_to_handler.

### Phase 6 — IRQ Router and Interrupt Policy

- [x] **P6a**: `IrqRouter` initialization at boot: all vectors assigned to dom0.
  ✅ DONE (pre-existing): `InterruptPolicy` / `InterruptVisibility` in capability engine
  + `program_domain_irtes()` at SEAL time + dom0 default policy = Deliver all vectors.
- [ ] **P6b**: I/O APIC programming (`x2apic::IoApic`): set redirection table entries
  for all PCI legacy IRQs targeting dom0 initially.
  *(DEFERRED: dom0 programs I/O APIC natively via EPT passthrough)*
- [ ] **P6c**: MSI-X programming: write MSI-X table entries for PCI devices targeting
  dom0's notification vector (LAPIC ID = dom0 VP[0] physical LAPIC).
  *(DEFERRED: dom0 programs MSI-X natively via EPT passthrough)*
- [x] **P6d**: `IrqRouter::configure_domain_policy(domain, policy, hw)`:
  called by `VMCALL_SEAL` handler; programs EOI-exit bitmap and posted interrupt config.
  ✅ DONE (pre-existing): `program_domain_irtes()` called from do_seal.
- [x] **P6e**: VMEXIT `EXTERNAL_INTERRUPT` handler: ✅ FULLY DONE.
  Same-core path: `forward_interrupt_to_handler` lazy-unwinds via `deliver_interrupt_vp`
  which walks the VP `caller` chain — **always same-core by construction** (SWITCH always
  parks the parent VP on the same core before running the child).
  Cross-core path: handled by Phase 2 Posted Interrupts (`inject_via_pid` + notification
  IPI) for Deliver VPs that are Available or running on a different core.
  No further work needed. P10f is closed.
- [x] **P6f**: VMEXIT `EOI_INDUCED` handler: stub present (`EXIT_REASON_EOI_INDUCED=45`).
  ✅ DONE (18e4c01): handler exists. **No further work needed**: in the lazy-unwind model
  the physical EOI is issued by dom0's interrupt handler (step 2 of the unwind chain).
  REPORT domains are notified via the COMM page `InterceptMessage`, not via virtual EOI.
  EOI-exit bitmap programming is not required for correctness; stub is sufficient.
- [x] **P6g**: Timer interrupt: LAPIC timer → DELIVER to dom0 by default.
  ✅ DONE (pre-existing): dom0 handles timer natively; child timer interrupts forward
  via `forward_interrupt_to_handler` → dom0.
- [x] **P6h**: NMI: always VMEXIT (cannot be posted); route to Themis for watchdog/panic.
  ✅ DONE (18e4c01): `NMI_EXITING` (pin bit 3) for child VPs; NMI forwarded to dom0
  via `forward_interrupt_to_handler(vcpu, 2)`. Dom0 NMIs handled natively.

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

- [x] **P7d**: ✅ DONE (pre-existing). Dom0's `DomainPolicy::new_root()` in the capability
  engine sets `default_deliver` for all vectors — dom0 is the default interrupt handler.

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

- [x] **P8a**: ✅ DONE. Opcodes, `VpRegister` enum, and error codes all present in
  `themis-abi/src/lib.rs` (opcodes/errors) and `themis-abi/src/regs.rs` (VpRegister).
- [x] **P8b**: ✅ DONE. Full dispatch in `hypercall.rs`: decodes RAX/RDI/RSI/RDX/RCX,
  routes via match, wraps each handler in `execute(||...)`, encodes `HypercallResult`.
- [x] **P8c**: ✅ DONE (core handlers). All major handlers implemented: CARVE, ALIAS, SEND,
  ACCEPT, REJECT, CREATE_DOMAIN, SEAL, REVOKE_MEM, REVOKE_DOMAIN, SWITCH, ATTEST_SELF,
  GET_REG, SET_REG, SET_INTR_POLICY, SET_DEF_INTR_POLICY, ADD_VP, REGISTER_COMM,
  DOMCOMM_NOTIFY. Still stubbed (ERR_UNIMPL): GET_CHAN, ATTEST, ENUMERATE,
  REGISTER_DOORBELL, REGISTER_EVENT_FLAGS, REGISTER_INTR_CHAN.
- [x] **P8d**: ✅ DONE. `do_assign_device` / `do_release_device` validate caller via
  capability handle and reprogram VT-d context entries to child SLPT.
- [x] **P8e**: `libthemis` guest library (`crates/libthemis/`): `no_std` VMCALL wrappers.
  Covers all 23 opcodes from `themis-abi`. Usable from Linux kernel module via FFI
  or from a bare-metal child domain.

### Phase 9 — Multi-Domain Support

- [x] **P9a**: ✅ DONE. `do_create_domain` → `Capability::create()` → `apply_update`
  allocates EPT root (`ensure_ept`) and IOMMU SLPT (`ensure_iommu_pt`) on first memory mapping.
- [x] **P9b**: ✅ DONE. CARVE/SEND handlers trigger `UpdateBatch`; `apply_update::ChangeRights`
  maps GPA→HPA in both child EPT and IOMMU SLPT.
- [x] **P9c**: ✅ DONE. `do_seal` programs child IRTEs. `do_add_vp` allocates VMCS + VAPIC +
  PID + MSR bitmap + APIC access page from META, then calls `vmcs::setup_child_vmcs`.
- [x] **P9d**: ✅ DONE. `do_switch` performs full domain context switch: validates COMM dirty
  registers, VMCLEAR parent, VMPTRLD child (`activate()`), VMRESUME via monitor loop.
- [x] **P9e**: ✅ DONE. `do_revoke_domain` calls `Capability::revoke_domain()`; `apply_update::
  RevokeDomain` tears down EPT + IOMMU SLPT; `invalidate_domain_irtes` clears all IRTEs.
- [x] **P9f**: ✅ NOT NEEDED. EOI-exit bitmap stays all-zeros by design. Report policy is
  implemented via the SWITCH return mechanism (RDI=vector on early return), not via EOI exits.
  Physical EOI is handled transparently by dom0's interrupt handler. Resolved.

### Phase 10 — META VP-State Regions *(SUPERSEDED by VpCommPage)*

> **STALE — design replaced.** The `VpStateMeta` concept (EVMCS-inspired shared page per VP)
> was implemented as `VpCommPage` (`themis-abi/src/regs.rs`), which covers all originally
> planned functionality: per-VP register storage with dirty bitmask, written on every VMEXIT
> (`forward_child_exit`), applied on every VMENTRY (`do_switch`), and used directly by
> GET_REG/SET_REG hypercalls via `platform.get_vp_register`/`set_vp_register`.
>
> Items P10a–P10e are already covered. Only P10f (cross-core routing) remains genuinely open.

- [x] **P10a**: ✅ DONE — `VpCommPage` in `themis-abi/src/regs.rs`. Full register storage,
  dirty/allowed bitmasks, `read_reg`/`write_reg`/`mark_dirty` helpers.
- [x] **P10b**: ✅ DONE — `THEMIS_REGISTER_COMM` (`do_register_comm`) maps the COMM page
  and stores `comm_hpa` in `PlatformDomain.comm_hpas[vp_id]`.
- [x] **P10c**: ✅ DONE — `forward_child_exit` writes all registers in `read_set` to the
  COMM page on every VP exit.
- [x] **P10d**: ✅ DONE — `do_switch` reads COMM dirty mask and applies to VMCS/regfile on
  every VP entry.
- [x] **P10e**: ✅ DONE — GET_REG/SET_REG read/write COMM page directly (no VMCS switching).
- [x] **P10f**: ✅ NOT NEEDED — Cross-core interrupt routing is handled by construction.
  `deliver_interrupt_vp` walks the VP `caller` chain which is always same-core (SWITCH
  parks the parent on the same core before running the child). The Posted Interrupts
  mechanism (Phase 2) handles the remaining case (Deliver VP running on a different core).
- [x] **P10g**: ✅ NOT NEEDED — EOI-exit bitmap programming is not required. In the
  lazy-unwind model the physical EOI is issued by dom0's interrupt handler. REPORT domains
  are notified via the COMM page `InterceptMessage`. No virtual EOI exit is needed.

### Phase 11 — ThemIC: Doorbell and Event Flag Pages

> **Renamed from TychIC.**  Redesigned to use generalized COMM capabilities
> (see COMM redesign below) instead of META pages.  See
> `2026/docs/design/mshv_themis/mshv_themis.md` §4 for the full ThemIC design.

Implements the SynIC-inspired cross-domain notification protocol.  Doorbell
notifications flow through the existing per-domain DomainComm RX ring; no new
per-VP shared pages are needed.  COMM redesign prerequisites are already done.

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

- [x] **P11a**: ✅ DONE. `msg_types::DOORBELL_NOTIFY = 0x0007` and `DoorbellNotify` struct
  added to `themis-abi/src/domcomm.rs`.
- [x] **P11b**: ✅ DONE. `VMCALL_REGISTER_DOORBELL(child_domain_handle, gpa, size, datamatch, flags)`
  → doorbell_id.  Capavisor stores `Vec<DoorbellEntry>` + `next_doorbell_id` per child domain in
  `PlatformDomain`.  Validates child domain cap ownership; enforces 128-entry limit.
- [x] **P11c**: ✅ DONE. `VMCALL_UNREGISTER_DOORBELL(child_domain_handle, doorbell_id)`.
- [x] **P11d**: ✅ DONE. EPT_VIOLATION handler replaced (`handle_ept_doorbell` in `vmexit.rs`).
  Match → write `DoorbellNotify` to parent's DomainComm RX ring, advance child RIP, VMRESUME
  child (fast-path, child not stopped).  No match → `forward_child_exit`.
  Note: IPI deferred (async mode future work; commented stub in handler).
- [x] **P11e**: ✅ DONE. `VMCALL_SET_THEMIC_VECTOR(vector)`: writes into caller's DomainComm
  header `notify_vector` field via `set_notify_vector()`.  Opcode 0x17 = `THEMIS_SET_THEMIC_VECTOR`.

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

- [x] **P15-ioeventfd** — ✅ DONE. `THHV_IOEVENTFD` ioctl fully implemented:
  `thhv_ioeventfd.c` (assign/deassign/drain), capavisor REGISTER_DOORBELL (0x15) wired,
  EPT violation → doorbell fast-path → `DOORBELL_NOTIFY` on DomainComm RX ring,
  `thhv_drain_domcomm_rx()` called after each `themis_switch()` return.

- [x] **P15g** — ✅ DONE. Interrupt injection implemented as `THEMIS_INJECT_INTERRUPT` (0x1b)
  VMCALL + `THHV_IRQFD` ioctl: eventfd + poll waitqueue + workqueue → `themis_inject_interrupt`
  → `do_inject_interrupt` → `inject_via_pid` → PI descriptor write.
- [x] **P15h** — ✅ NOT NEEDED / ALREADY DONE. COMM page is userspace-allocated: caller
  allocates a normal page, passes VA via `THHV_INIT_VP` ioctl, driver pins it with
  `pin_user_pages_fast`. Userspace already owns and can read/write the page directly.
  No `remap_pfn_range` needed.
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
- [x] **P15-dc-m3** — ✅ DONE.  Capability table + PA map validation: driver-side
  cap table (rb-tree by local_handle), per-partition sent_caps, parent handle
  lookup by HPA.  REVOKE uses `(parent_handle, sub)`.  55 caps loaded from
  attestation.
- [x] **P15-dc-m4** — ✅ DONE.  Ring growth: `domcomm_tx_enqueue()` (page-aware SPSC
  producer), `ring_write()` helper, dom_cap attestation parsing (self-domain handle=56),
  `VMCALL_DOMCOMM_NOTIFY` (opcode 0x19), `domcomm_request_grow()` (CARVE→REGISTER_COMM
  self-ref→GROW msg→ACK→extend local ring).  Capavisor: `DomainCommState` refactored
  with per-ring page tracking, `domcomm_tx_dequeue()`, CommRegion self-ref no-op,
  GROW handler (cap lookup→extend ring pages→update header→ACK).
  **Bugs fixed during bring-up**:
  - Head/tail wrapping mismatch (driver monotonic vs capavisor `% capacity`) — unified to monotonic.
  - TOCTOU: capavisor now copies msg headers before inspection (pattern for all future msgs).
  - `get_current_core()` deadlock: `lapic_ids` changed from `spin::RwLock` → `UnsafeCell`
    (write-once at boot, read-only after).
  - `rdmsr(IA32_X2APIC_APICID)` #GP: x2APIC never enabled; replaced with CPUID leaf 1.
  **Test infrastructure**: `thhv/test/thhv_test.c` userspace tool + `THHV_TEST` ioctl
  (build with `KCFLAGS=-DCONFIG_THHV_TEST`).
  **Tested**: `grow_rx 1` (RX 2→3 pages, 12288 bytes) and `grow_tx 1` (TX 1→2 pages, 8192 bytes)
  both pass end-to-end.
- [ ] **P15-dc-m5** — Async VP exit delivery: Capavisor writes VP_EXIT to
  parent's RX ring, driver dispatches to VP waitqueue.  **Test**:
  `thhv-test-vpexit` creates child VP, triggers exit, verifies DomainComm path.
- [ ] **P15-dc-m6** — Capability enumeration: ENUM_CAP request/response via
  TX/RX rings.

### C7 — End-to-End Child Domain HLT Test

Validates the full child domain lifecycle: CREATE_DOMAIN → CARVE/SEND memory →
ADD_VP → SET_VP_STATE → SEAL → SWITCH → verify HLT exit.
Test binary: `thhv/test/test_child_hlt.c`.

**Completed**:
- [x] **C7a** — Test skeleton: CREATE_PARTITION, SET_GUEST_MEMORY, CREATE_VP,
  SET_VP_STATE, INITIALIZE_PARTITION, RUN_VP, cleanup.
- [x] **C7b** — Fix CREATE_DOMAIN MonotonicityViolation: `cores_mask` must be
  a subset of parent's cores; now uses `sysconf(_SC_NPROCESSORS_ONLN)`.
- [x] **C7c** — EPT META page allocation: child domain needs META pages for EPT
  intermediate tables (PML4/PDPT/PD/PT).  Added `thhv_ept_meta_needed()` helper
  and EPT META allocation block in `thhv_set_guest_memory` (before guest CARVE).
  Key: `THHV_META_KEY_EPT = 0xFFFFFFFFFFFF2000`.
- [x] **C7d** — Fix SET_VP_STATE EFAULT: uninitialized `ret` variable in
  `thhv_vp_set_state()` fell through with stack garbage (-14 = EFAULT).
  Fix: `ret = 0` after successful path.
- [x] **C7e** — Fix RevokeDomain ordering panic and redundant updates:
  Root cause: META pages canonicalize to `META|CLEAN|VITAL`, so each META
  page's `revoke_subtree` emits a VITAL-triggered `RevokeDomain(child)` plus
  `ChangeRights` unmaps for the child domain being destroyed.
  Fix (in `2026/src/capability.rs`):
  (a) Mark domain as revoked early in `revoke_domain_subtree` (call
  `domain.data.revoke()` before dropping the lock), emit the single
  authoritative `RevokeDomain` update at the top.
  (b) In `revoke_subtree`, check `is_revoked()` on child_owner and
  parent_owner domains — skip `ChangeRights` and VITAL `RevokeDomain` for
  already-revoked domains.  This eliminates all redundant updates at the
  source.  `execute()` (`2026/src/platform.rs`) reverted to a clean
  single-pass apply — no mangling or dedup needed.

**Current blocker**:
- [x] **C7f** — ✅ DONE (validated). EPT violations on dom0 cores during CARVE/SEND:
  Fix implemented (domain_to_cores BTreeSet, all-cores stop before EPT modifications).
  Confirmed working: test_intr_loop ran 748 interrupt forwards on 4 CPUs with no
  EPT violation / halt_forever.

**Known non-blocking issues**:
- `REVOKE_MEM parent=N sub=M failed (-2)` warnings during cleanup: the driver's
  `sent_caps` list tries to individually revoke caps that `revoke_domain` already
  cleaned up.  Harmless but noisy.  Fix: skip `sent_caps` cleanup after a
  successful `revoke_domain`, or clear the list before the loop.

**Remaining after C7f**:
- [x] **C7f** — ✅ DONE (validated). EPT violation fix (domain_to_cores BTreeSet,
  all-cores stop before EPT modifications) confirmed working: test_intr_loop ran
  748 interrupt forwards on 4 CPUs with no EPT violation / halt_forever.

- [x] **C7g** — ✅ DONE. test_intr_loop creates child that exits via HLT; driver
  reads InterceptMessage from COMM page. test_child_hlt also present and working.

- [x] **C7h** — ✅ DONE. Removed debug prints:
  - `[CARVE]` entry/ok/error logging in `hypercall.rs`
  - `[CREATE_DOMAIN]` verbose logging in `hypercall.rs`
  - `[ChangeRights]` per-mapping log in `platform.rs`
  - `[apply] CommRegion` / `[apply] UncommRegion` logs in `platform.rs`
  - Simplified EPT violation handler (removed `domain_str` pattern, kept the
    core/domain info in the fatal log).

---

### Phase 15.5 — Interrupt Virtualization (VAPIC + VID + Posted Interrupts)

Design document: `2026/docs/design/interrupt-virtualization.md`

This phase implements correct interrupt routing between domains. It is the
current active work item. The lost-timer-interrupt regression (RCU stall after
C7 test) is a symptom of the missing Phase 1 implementation.

#### Phase 1 — VAPIC + VID + Core Interrupt Forwarding

- [x] **intr-p1-vmcs** — ✅ DONE. VAPIC page allocated per VP from META pool
  (`hypercall.rs:429`). APIC_REGISTER_VIRT (bit 8) + VID (bit 9) enabled in
  `write_control_fields` (`vmcs.rs:189-190`). `VIRT_APIC_ADDR`, `EOI_EXIT_BITMAP`=0,
  `TPR_THRESHOLD`=0 set (`vmcs.rs:277-290`). `EXTERNAL_INTERRUPT_EXITING`=0 for dom0,
  =1 for children (`vmcs.rs:148`).

- [x] **intr-p1-routing-table** — ✅ DONE. `InterruptPolicy` struct with
  Deliver/Report/NotReport in `domain.rs:230-237`. `THEMIS_HC_SET_INTR_POLICY` and
  `THEMIS_HC_SET_DEF_INTR_POLICY` handlers in `hypercall.rs:840-896`.
  `route_interrupt` walks caller chain to find first `Deliver` ancestor.

- [x] **intr-p1-forward** — ✅ DONE. `forward_interrupt_to_handler` in `hypercall.rs:979-1084`.
  Deliver path: `pid_set_pir()` with `VMENTRY_INTR_INFO` fallback.
  Route-upward path: `deliver_interrupt_vp()` lazy-unwind, VMCLEAR child, VMPTRLD
  handler, VMENTRY injection.

- [x] **intr-p1-switch-ctx** — ✅ DONE. `interrupt_return: Option<u8>` in
  `SwitchContext` (`2026/src/switch.rs:74`). `switch_domain_forward` populates it
  for `Suspended { vector }` VPs. `do_switch` (`hypercall.rs:673-681`) sets
  `RDI=V`, `RAX=SUCCESS`, advances RIP when `interrupt_return == Some(V)`.

- [x] **intr-p1-test** — ✅ DONE. test_intr_loop validated Phase 1: 748 interrupts
  forwarded to dom0 while child ran on 4 CPUs, no RCU stall, dom0 fully responsive.
  test_child_hlt also confirmed working (HLT exit via InterceptMessage).

#### Phase 2 — Posted Interrupts

- [x] **intr-p2-pid** — ✅ DONE. 4 KB PID page allocated per VP in `do_add_vp`
  (`hypercall.rs:413-442`), zeroed before use. `POSTED_INTR_DESCRIPTOR_ADDR` and
  `POSTED_INTR_NOTIFICATION_VECTOR` written to VMCS (`vmcs.rs:332-336`).
  `PROCESS_POSTED_INTERRUPTS` (pin bit 7) enabled for child VPs (`vmcs.rs:149`).
  `pid_phys` field added to `InactiveVcpu`/`ActiveVcpu`.

- [x] **intr-p2-notify-vec** — ✅ DONE. Vector `0xF2` reserved as
  `POSTED_INTR_NOTIFICATION_VECTOR` constant in `vmcs.rs:36`.

- [x] **intr-p2-inject** — ✅ DONE. Added `inject_via_pid(pid_phys, hhdm, vector, is_remote)`,
  `send_notification_ipi(ndst, vector, hhdm)`, `pid_set_ndst(pid_phys, hhdm, lapic_id)`,
  and `current_lapic_id()` helpers in `hypercall.rs`. Same-core Deliver path in
  `forward_interrupt_to_handler` now calls `inject_via_pid(..., is_remote=false)`.
  `pid_set_ndst` called after every `activate()` (do_switch child, parent exit,
  forward_interrupt handler) so PID.NDST always reflects the running core's LAPIC ID.
  Cross-core path (Case C): `inject_via_pid(..., is_remote=true)` sets PIR[V],
  conditionally sets ON=1, and sends Fixed IPI (vector 0xF2) to PID.NDST.

- [x] **intr-p2-test** — ✅ DONE. `thhv/test/test_intr_loop.c`: child loops ~1M
  iterations then HLTs. Run on QEMU (4 CPUs): 748 interrupts (vectors 0xEC/0xFD)
  forwarded via INTR_FWD while child ran; dom0 remained responsive; full partition
  teardown completed cleanly. PROCESS_POSTED_INTERRUPTS absent on QEMU → fallback
  VMENTRY injection path validated. PID/cross-core IPI path (is_remote=true)
  requires hardware with posted-interrupt support or `-cpu host` QEMU flag.

#### Phase 3 — VT-d Interrupt Remapping  *(required for device passthrough)*

Zero-exit physical device interrupt delivery to child domains requires VT-d
interrupt remapping.  Without it every physical interrupt causes an
`EXIT_REASON_EXTERNAL_INTERRUPT` VMEXIT even for `Deliver` vectors; the
capavisor re-injects them but the exit overhead is unavoidable.

**Dependency**: intr-p3a shares infrastructure with Phase 4 P4a (DMAR DRHD
enumeration).  Do intr-p3a first and have P4a reuse the same `DmarInfo`
structures.  VT-d DMA translation (P4b–P4f) and interrupt remapping (intr-p3b+)
are independent capabilities on the same DRHD units.

**QEMU support**: `-device intel-iommu,intremap=on` enables emulated VT-d IR.
Add this flag to `run-qemu.sh` before intr-p3i.

- [x] **intr-p3-plan** — ✅ DONE (this breakdown).

- [x] **intr-p3a** — DMAR parse for interrupt remapping. ✅ DONE
  `acpi.rs`: added `DhrdUnit { register_base, segment, flags, ir_supported }`,
  `parse_dmar()` helper walks DMAR table bytes, enumerates all DRHD structures,
  reads `CAP` (offset 0x08, bit 16) and `ECAP` (offset 0x10, bit 3) on each unit.
  `AcpiInfo` now carries `drhd_units: Vec<DhrdUnit>` (shared with P4a).
  Print logged at boot: `ACPI DMAR: DRHD seg=N base=0x... ir=true/false`

- [x] **intr-p3b** — IRT allocation. ✅ DONE
  `mem/inventory.rs`: added `MAX_DRHD_UNITS = 4` constant, `irt_pages` field to
  `MetaBreakdown`, included in META pool sizing (4 pages reserved at partition time).
  `acpi.rs`: added `irt_phys: u64` field to `DhrdUnit` (0 until allocated).
  `platform.rs`: added `drhd_units: Vec<DhrdUnit>` to `ThemisPlatform`.
  `boot.rs` (`init_themis`): for each IR-capable DRHD unit, allocates one page from
  dom0's MetaAllocator (META pool, excluded from EPT), writes `IRTA_REG` (base | size=0
  for 256 IRTEs), stores populated `DhrdUnit` list on `ThemisPlatform`.
  Pages are machine-global / capavisor-private — no capability records needed.

- [x] **intr-p3c** — Enable VT-d interrupt remapping. ✅ DONE
  `boot.rs` (`init_themis`): for each IR-capable DRHD unit with an allocated IRT:
  1. GCMD.SIRTP → poll GSTS.IRTPS (hardware latches IRTA_REG)
  2. GCMD.CFI=1 → poll GSTS.CFIS (compat-format interrupts pass through)
  3. GCMD.IRE → poll GSTS.IRES (interrupt remapping active)
  **Design decision**: CFI=1 (Compatibility Format Interrupt passthrough enabled).
  Dom0's I/O APIC RTEs stay in compatibility format — Linux programs them
  normally and they pass straight through the IOMMU.  All IRTEs start with
  P=0, so no remapped interrupt is active until intr-p3g programs one for a
  child domain.  This avoids the need for intr-p3d at this stage.

- [ ] **intr-p3d** — I/O APIC RTE reprogramming for remapped format. ⏸ DEFERRED
  Not needed while CFI=1 (compat interrupts pass through for dom0).
  Required only if we later set CFI=0 for full isolation.  Defer to device
  passthrough hardening (post-P16).  Original spec: reprogram each active RTE
  to remapped format (bit[11]=1, handle in bits[63:49]+[0], trigger/polarity
  preserved); write matching IRTE with P=1, DST=dom0_lapic, vector=V.

- [ ] **intr-p3e** — MSI/MSI-X reprogramming for remapped format.
  Walk PCI devices; rewrite MSI/MSI-X address/data fields to remapped format.
  Same IRTE handle scheme as intr-p3d.  Can be deferred until device passthrough
  (P16e) if no devices are currently assigned to children.
  Files: `pci.rs`, `boot.rs`.

- [x] **intr-p3f** — IRTE management API. ✅ DONE
  New file `iommu_ir.rs`:
  - `irte_program_remapped(irt_phys, hhdm, index, lapic_id, vector)`:
    remapped IRTE — fixed delivery, edge trigger, physical dest mode.
  - `irte_program_posted(irt_phys, hhdm, index, pid_phys, ndst)`:
    posted IRTE — IM=1, NV=0xF2, NDST=lapic_id, PDA=pid_phys>>6.
  - `irte_update_ndst(irt_phys, hhdm, index, ndst)`: patch NDST in-place
    when VP migrates to a different core.
  - `irte_invalidate(irt_phys, hhdm, index)`: zero both words (P=0).
    Note: real hardware needs IEC invalidation queue — deferred.
  All writes follow the VT-d 3-step update protocol (P=0 → high → low+P).

- [x] **intr-p3g** — Hook into `VMCALL_SEAL` / `SET_INTR_POLICY`.
  When a child domain VP is sealed with `Deliver` vectors:
    - call `irte_program_posted(index=vector, pid_phys=vp.pid_phys, ndst=0)`
      (NDST filled in at first `activate()`; IPI not needed if VP is not yet
      running).
  When `SET_INTR_POLICY` changes a vector back to `Report`/`NotReport`:
    - call `irte_program_remapped(index=vector, ...)` to route back through
      the capavisor notification path.
  On `VMCALL_REVOKE_DOMAIN`: `irte_program_remapped` all child's vectors back
  to dom0.  Files: `hypercall.rs`, `iommu_ir.rs`.

- [x] **intr-p3h** — QEMU validation.
  Add `-device intel-iommu,intremap=on` to `scripts/run-qemu.sh`.
  Run `test_intr_loop` and verify: (1) boot succeeds, (2) no EPT violations
  during CARVE/SEND, (3) child domain still receives interrupts correctly,
  (4) capavisor boot log shows "IR enabled" on each DRHD unit.

---

### Phase 16 — Cloud-Hypervisor Themis Backend

Add a Themis/mshv-themis hypervisor backend to cloud-hypervisor, enabling it to
create and run VMs on top of Themis via capability operations.  Can be started
in parallel with Phase 15 (stub missing ioctls); both phases progress alongside
the capavisor roadmap.

**Approach**: cloud-hypervisor already supports KVM and MSHV backends via the
`hypervisor` crate abstraction.  The Themis backend plugs into the same trait
hierarchy (`Hypervisor`, `Vm`, `Vcpu`) using `/dev/mshv` ioctls from Phase 15.

- [x] **P16a** — ✅ DONE. `hypervisor/src/themis/mod.rs` added with `ThemisHypervisor`
  implementing the `Hypervisor` trait. Opens `/dev/thhv`, detection via path check.
  Wired into `lib.rs` `new()` dispatch + `HypervisorType::Themis` variant.
- [x] **P16b** — ✅ DONE. `ThemisVm` implementing the `Vm` trait. `create_vm()` →
  `THHV_CREATE_PARTITION` + `THHV_INITIALIZE_PARTITION`. `create_user_memory_region()` →
  `THHV_SET_GUEST_MEMORY`. `register_irqfd/ioeventfd` → `THHV_IRQFD/IOEVENTFD`.
- [x] **P16c** — ✅ DONE. `ThemisVcpu` implementing the `Vcpu` trait. `run()` →
  `THHV_RUN_VP`, decodes `themic_intercept_message`, maps exits to `VmExit`.
  `get_regs()`/`set_regs()` via `THHV_GET/SET_VP_STATE`. `get_sregs()`/`set_sregs()`
  via segment/control register names. Builds clean with `--features themis`.
- [x] **P16d** — ✅ DONE. `create_user_memory_region()` in `ThemisVm` calls
  `THHV_SET_GUEST_MEMORY`; `GuestMemoryMmap` regions flow through the existing
  cloud-hypervisor memory manager unchanged.
- [ ] **P16e** — Device passthrough: PCI device assignment via `THHV_ASSIGN_DEVICE`.
  VFIO integration if needed for userspace device access. Requires P15i.
- [ ] **P16f** — virtio device backends: verify virtio-blk, virtio-net, virtio-console
  work over the Themis backend (they should — virtio is guest-kernel ↔ VMM
  userspace, independent of hypervisor backend).
- [x] **P16g** — ✅ DONE. Boot integration wired:
  - `set_fpu()` / `set_lapic()` made no-ops (Themis manages via APICv/VMCS).
  - `vmm/src/vm.rs`: `is_themis` detection + `init_themis()` path (skips mshv
    irqchip init; calls `create_interrupt_controller` + `create_devices`).
  - `vmm/src/seccomp_filters.rs`: Themis ioctl allowlist added.
  - `vmm/Cargo.toml` + `cloud-hypervisor/Cargo.toml`: `themis` feature passthrough.
  - Both `--features themis` and `--features kvm` build clean.
- [x] **P16h** — 🚧 IN PROGRESS. End-to-end validation: boot a Linux guest under
  cloud-hypervisor running on Themis. Dom1 executes past GPA 0x100000 into
  hypervisor-fw. Firmware CPUID and HLT exits handled. Next: firmware completes
  init, Linux kernel boots, serial console, login prompt.
  Blockers resolved: EPT GPA-0 mapping, LDTR_AR, CPUID emulation.
  Current blocker: firmware HLT exit handling / timer interrupt.

---

### Phase 16.6 — Dom1 Boot Completion & CPUID Policy

Follow-on work needed to complete dom1 boot and properly integrate CPUID
virtualization into the capability/domain-policy model.

- [x] **P16.6a** — **HLT exit + timer interrupt for dom1**: ✅ PARTIALLY DONE.
  HLT handled (CHV returns `VmExit::Ignore`). Timer interrupt injection is the
  remaining piece — dom1 hangs in `calibrate_APIC_clock` waiting for a timer tick.

  **Timer injection plan (timerfd + IRQFd, Option 1)**:
  The interrupt injection infrastructure already exists end-to-end:
  - Capavisor: `THEMIS_INJECT_INTERRUPT` hypercall, Posted Interrupt Descriptors,
    `inject_via_pid()`, PIR→VMENTRY drain fallback — all working.
  - thhv.ko: `THHV_IRQFD` ioctl, EventFd→workqueue→`themis_inject_interrupt` — working.
  - CHV: `register_irqfd(fd, gsi)` calls `THHV_IRQFD` — working.

  What's missing: a **periodic timer source** to trigger the EventFd.

  Implementation (in CHV VMM layer):
  1. Create a `timerfd` (CLOCK_MONOTONIC) firing at ~1 kHz (1 ms period).
  2. Register it via `register_irqfd(timerfd, APIC_TIMER_VECTOR)` where
     APIC_TIMER_VECTOR = 0x30 or whatever the guest's LVTT is configured to.
  3. On each timerfd expiry, kernel fires the EventFd → thhv.ko injects the
     interrupt → capavisor sets PIR bit → dom1 receives timer tick on VMENTRY.
  4. This unblocks `calibrate_APIC_clock` and provides jiffies/scheduling ticks.

  ~30 lines of code in CHV. Uses existing infrastructure, no capavisor changes.

- [ ] **P16.6b** — **MSR exit emulation**: RDMSR/WRMSR are currently silently
  ignored (`VmExit::Ignore`). Firmware and Linux kernel use several MSRs
  (IA32_MISC_ENABLE, IA32_EFER, IA32_PAT, IA32_TSC_DEADLINE, x2APIC MSRs).
  Implement basic MSR emulation: passthrough safe read-only MSRs, handle
  EFER/PAT writes, inject #GP for unsupported MSRs.

- [ ] **P16.6b2** — **Paravirtualization (nopv workaround)**: Dom1 currently
  boots with `nopv` in its kernel cmdline (same as dom0), disabling kvmclock
  and all KVM paravirt features. The hang without `nopv` is in
  `pvclock_read_flags()` spinning on an odd version in `hv_clock_boot[0].pvti`
  — CHV forwards the `MSR_KVM_SYSTEM_TIME_NEW` write (via capavisor passthrough)
  but never initialises the pvclock struct in guest memory. Long-term, either:
  (a) implement pvclock struct initialisation in capavisor / thhv when the MSR
  is written; or (b) have CHV handle it as it does under native KVM.
  Low priority while getting dom1 to a login prompt; revisit when clock accuracy
  and steal-time accounting matter.

- [ ] **P16.6c** — **CPUID policy in DomainPolicy (capavisor)**:
  Currently CHV handles CPUID exits in dom0 userspace (correct short-term
  design). Long-term: integrate CPUID policy into `DomainPolicy` in
  `themis/capavisor/src/capability.rs`. Add a `CpuIdPolicy` struct
  (allowed leaves, masked bits, topology overrides). CHV sends the policy via
  a new `THHV_SET_CPUID_POLICY` ioctl / `THEMIS_OP_SET_CPUID` hypercall before
  `INITIALIZE_PARTITION`. Capavisor handles CPUID exits entirely in VMX root
  mode without a round-trip to dom0. Benefits:
  - No VMX exit cost to dom0 userspace on every CPUID
  - Policy enforced at L0 (can't be bypassed by dom0 compromise)
  - Consistent with capability model: domain creation specifies full policy

- [ ] **P16.6d** — **EXCEPTION/NMI exit handling**: exit reason 0 is currently
  silently ignored. Dom1 exceptions (#GP, #PF, #UD) need to be either injected
  back into the guest or reported as errors.

- [ ] **P16.6d2** — **APIC virtualization for child domains (capavisor-owned)**:
  Currently `EXIT_REASON_APIC_ACCESS` from child domains is forwarded to the
  parent (CHV/dom0) via `forward_child_exit`. This is architecturally wrong and
  unscalable: at recursion depth N the round-trip cost is O(N) wake-ups.

  **Design principle**: the LAPIC is per-vCPU state. It does not cross domain
  boundaries at runtime. Capavisor (L0) should handle LAPIC virtualization for
  ALL domains, never involving the parent, except at vCPU creation time.

  | Operation | Handler | Rationale |
  |-----------|---------|-----------|
  | Routine LAPIC reads/writes | Capavisor, via vapic page | Per-vCPU state, O(1) at any depth |
  | APIC timer | Capavisor, via VMX preemption timer | Already done for dom0 |
  | Intra-domain IPI (same domain) | Capavisor directly | Domain-internal, no boundary |
  | Cross-domain IPI | Capavisor + capability check | IS a security boundary |
  | Initial APIC ID / topology | Parent sets at vCPU creation | Policy decision, not runtime |

  **Implementation**:
  1. Add `EXIT_REASON_APIC_ACCESS` to the child domain dispatch in `vmexit.rs`,
     routing it to `handle_apic_access_exit` (already implemented for dom0).
  2. The vapic page per child vCPU is already managed in VMCS setup — just needs
     to be populated at creation time with the APIC ID supplied by the parent.
  3. Add `EXIT_REASON_APIC_WRITE` handling for write-trapping (ICR writes for IPI
     delivery need the cross-domain capability check).
  4. Cross-domain IPI: capavisor checks whether the source domain has a capability
     allowing interrupt delivery to the target vCPU/domain; if yes, inject directly.

  This applies to dom1, dom2, dom3 etc. uniformly — no special-casing per depth.

- [ ] **P16.6d3** — **PV IOAPIC + PV APIC timer + PV MMIO (long-term, MSHV SynIC-inspired)**:
  Replace MMIO-emulated IOAPIC and APIC timer with paravirtualized interfaces.
  Inspired by Hyper-V SynIC (Synthetic Interrupt Controller) and MSHV Linux support.

  **Motivation**: current MMIO path requires per-access EPT exit → instruction
  decode (iced-x86 in CHV, P16.6i) → CHV userspace round-trip → response. Each
  MMIO access costs thousands of cycles. The emulator path (P16.6i) is a correct
  stepping stone for stock kernels but ultimately unnecessary for enlightened guests.

  **Design sketch**:
  - Guest kernel detects Themis hypervisor via CPUID 0x40000000 ("ThemisCapa")
  - **PV MMIO**: guest does `VMCALL(MMIO_WRITE, gpa, val, size)` or
    `VMCALL(MMIO_READ, gpa, size)` → capavisor forwards structured request to
    parent → parent dispatches to device → result returned via VMCALL return value.
    No EPT violation, no instruction bytes, no emulator. Guest provides register,
    size, direction, value explicitly in hypercall arguments.
  - PV IOAPIC: guest writes redirect table entries via VMCALL instead
    of MMIO. Capavisor updates internal routing table directly.
  - PV timer: guest programs timer via VMCALL or MSR write. Capavisor uses VMX
    preemption timer to deliver timer interrupts. No MMIO, no APIC timer emulation.
  - PV EOI: guest signals EOI via synthetic MSR write (like Hyper-V `HV_X64_MSR_EOI`).
  - Fallback: stock kernels without Themis PV support continue using MMIO + emulator
    path (P16.6i).

  **Layering**: P16.6i (iced-x86 emulator) handles stock kernels. P16.6d3 (PV MMIO)
  is the fast path for enlightened kernels. Both coexist — PV path is opt-in via
  CPUID feature detection.

  **Prerequisite**: dom1 must boot to login prompt first (P16.6g) using the current
  MMIO emulation path. PV interfaces layer on top as performance optimizations.

- [ ] **P16.6e** — **Dom1 serial console output**: verify dom1 kernel output
  appears on dom0's console (CHV serial → dom0 stdout → QEMU serial).

- [ ] **P16.6f** — **Dom1 virtio-blk root mount**: verify dom1 can mount its
  root disk (virtio-blk backed by `dom1.raw`).

- [ ] **P16.6g** — **Dom1 login prompt**: end-to-end: dom1 boots Ubuntu Noble
  to a login prompt with `cloud`/`cloud123`.

- [ ] **P16.6h** — **META page batching optimization** (`thhv/src/thhv_part.c::thhv_send_meta_pages`):
  Currently sends each 4KB EPT page-table node as a separate CARVE+SEND (518 sends for 1GB).
  Optimization: scan for runs of physically contiguous pages sharing the same parent capability
  handle → one CARVE (for `run_len × PAGE_SIZE`) + one SEND per contiguous run.
  Condition per run: `hpa[i+1] == hpa[i] + PAGE_SIZE` AND same `parent_handle`.
  The `thhv_sent_cap` tracking must be updated to store one entry per run instead of per page.
  Expected result: reduces ~518 capability metadata entries to O(10) for typical allocations.

- [ ] **P16.6i** — **MSHV-style MMIO emulation (move instruction decode to CHV)**:
  Replace fragile capavisor instruction decode with CHV's existing x86 emulator
  (iced-x86 + `hypervisor/src/arch/x86/emulator/`), matching the MSHV backend's
  architecture. This is the current dom1 boot blocker.

  **Background**: MSHV's `hv_x64_memory_intercept_message` provides raw
  `instruction_bytes[16]` + `instruction_length` from the hypervisor. The VMM
  (CHV) decodes operands using iced-x86 and emulates. CHV already has this code
  in `hypervisor/src/mshv/x86_64/emulator.rs` (MshvEmulatorContext) and
  `hypervisor/src/arch/x86/emulator/` (MOV, MOVZX, CMP, MOVS, STOS, OR handlers).
  The `mshv_emulator` feature flag enables iced-x86 independently of MSHV.

  **What changes where**:

  | Component | Change | Why |
  |-----------|--------|-----|
  | `hypervisor/Cargo.toml` | Add `mshv_emulator` to `themis` feature deps | Enable iced-x86 + emulator for Themis builds |
  | `hypervisor/src/themis/x86_64/emulator.rs` | NEW: ThemisEmulatorContext | Implements `PlatformEmulator` for Themis vCPU; adapts get/set_regs, mmio_read/write |
  | `hypervisor/src/themis/mod.rs` | Wire emulator into EPT violation handler | Replace current reactive MMIO dispatch with `emulate_insn_stream()` |
  | `capavisor/src/hypercall.rs` | Remove `decode_mmio_insn()` + all operand decode | Capavisor only reads instruction bytes into message, does NOT decode or advance RIP |
  | `capavisor/src/hypercall.rs` | Stop advancing RIP for EPT violations | Emulator handles RIP advancement; CHV sets new RIP via `set_reg_values` |

  **Capavisor changes (simplification)**:
  - Keep: reading instruction bytes from guest memory via EPT+page-table walk
  - Keep: filling `msg.instruction_bytes` and computing `instruction_byte_count`
  - Remove: `decode_mmio_insn()`, `x86_reg_to_gpr()`, `x86_reg_to_thhv()`, `MmioInsn` struct
  - Remove: RIP advancement for EPT violations (emulator does it)
  - Remove: register fixup (`msg.rax = vcpu.reg(gpr)`, `msg._reserved = ...`)

  **CHV Themis backend changes**:
  - Create `ThemisEmulatorContext` implementing `PlatformEmulator`:
    - `read_memory` / `write_memory`: try guest RAM first, fall back to `vm_ops.mmio_read/write`
    - `cpu_state`: read all GP regs + special regs from vCPU via `get_reg_values`
    - `set_cpu_state`: write changed regs back via `set_reg_values`
    - `fetch`: use instruction_bytes from intercept message (already provided by capavisor)
  - In EPT violation handler: create emulator, call `emulate_insn_stream(&old_state, &insn_bytes, Some(1))`
  - Apply new state (registers + RIP) via `update_cpu_state`

  **RIP advancement model (matches MSHV)**:
  - Capavisor does NOT advance RIP for EPT violations
  - iced-x86 decoder determines instruction length
  - Emulator's `emulate_insn_stream` returns new CpuState with RIP advanced
  - CHV writes new RIP via `set_reg_values` → thhv.ko → VP comm page → capavisor applies

  **Security note**: parent (dom0) already created child (dom1) and provided its
  kernel code. Allowing parent to set child RIP during MMIO emulation does not
  add new attack surface. Long-term, capavisor could validate RIP = old_RIP +
  instruction_length if needed.

  **Implementation order**:
  1. ✅ P16.6i-1: Enable `mshv_emulator` feature for Themis in Cargo.toml
  2. ✅ P16.6i-2: Create `ThemisEmulatorContext` in `hypervisor/src/themis/emulator.rs`
     - Implements `PlatformEmulator` with guest page-table walker (CR3→PML4→PDPT→PD→PT)
     - `read_memory`/`write_memory`: GVA→GPA translation, RAM→MMIO fallback
     - `fetch`: returns cached `instruction_bytes` from intercept message
     - `cpu_state`/`set_cpu_state`: delegates to ThemisVcpu get_regs/set_regs/get_sregs/set_sregs
  3. ✅ P16.6i-3: Rewrote `handle_mmio_exit` to use `Emulator::emulate_first_insn()`
     - Removed capavisor's `decode_mmio_insn()`, `MmioInsn`, `x86_reg_to_gpr()`, `x86_reg_to_thhv()`
     - Capavisor no longer advances RIP for EPT violations
     - Capavisor still reads instruction bytes into msg.instruction_bytes
  4. ✅ P16.6i-4: Test: IOAPIC MMIO works (200+ R/W at 0xfec00000), no crashes
  5. ✅ P16.6i-5: IOAPIC MMIO (0xFEC00000) works through emulator — MOV and REX-prefixed MOV both handled

  **New blocker (not MMIO related)**: exit reason 55 (XSETBV) — capavisor skips
  the instruction without executing it, XCR0 never gets set, kernel hangs.
  Needs proper XSETBV handling in capavisor (read ECX/EDX:EAX, execute XSETBV).


Replace the current manual sudo-heavy workflow with a fully automated, sudo-free build
and deployment pipeline.  Core idea: a separate **`bins.img`** ext2 disk image holds all
built artifacts (thhv.ko, tests, cloud-hypervisor binary, nested guest kernel).  dom0
mounts it read-only at `/opt/bins` via fstab.  The image is created and updated without
root using `fuse2fs`.  Kernel headers for thhv.ko are fetched from Ubuntu's package
archive (no VM mount needed).

**Decisions (resolved):**
- Image format: `fuse2fs` (ext2 raw image) — self-contained, no extra daemon
- Image size: 2 GB default, configurable via `BINS_SIZE`
- dom0 mount: read-only (`ro,nofail`); writable dev workflow via scp over SSH
- Kernel version: pinned in `themis/scripts/dom0-kernel-version.txt`
- Nested guest image: deferred to P16h (reuse dom0 kernel)

- [x] **P16.5a** — `bins.img` lifecycle: `themis/scripts/create-bins.sh` and
  `themis/scripts/update-bins.sh`.  `create-bins.sh` creates a sparse 2G ext2
  image with directory structure `thhv/`, `cloud-hypervisor/`, `nested/`, writes
  `version.txt`.  `update-bins.sh` mounts via `fuse2fs`, copies artifacts
  (thhv.ko, test bins, cloud-hypervisor binary), writes git rev + timestamp to
  `version.txt`, unmounts.  Both run with zero privileges.

- [x] **P16.5b** — QEMU integration: modify `themis/scripts/run-qemu.sh` and
  `themis/scripts/run-dom0.sh` to detect `guest/bins.img` and attach it as a
  second `virtio-blk-pci` drive (read-only).  If `bins.img` is absent, boot
  proceeds normally (no error).

- [x] **P16.5c** — Guest cloud-init auto-mount: modify `themis/scripts/fetch-dom0.sh`
  to add `mkdir -p /opt/bins` and an fstab entry
  `LABEL=bins /opt/bins ext2 ro,nofail,x-systemd.automount 0 0` to the
  cloud-init `user-data` `runcmd` section.  Also add a symlink
  `/home/cloud/bins -> /opt/bins` for convenience.

- [x] **P16.5d** — No-sudo kernel headers: `themis/scripts/fetch-kheaders.sh` reads
  `themis/scripts/dom0-kernel-version.txt` (pinned kernel version string, e.g.
  `6.8.0-51-generic`), downloads matching `.deb` packages from Ubuntu archive
  using `apt-get download` (no sudo), extracts into `themis/target/kheaders/`
  with `dpkg-deb --extract`.  Modify `thhv/build-guest.sh` to use
  `KHEADERS_DIR=themis/target/kheaders/...` when available; keep NBD-mount as
  fallback.  Add `dom0-kernel-version.txt` to repo with current pinned version.

- [x] **P16.5e** — Build orchestration: `themis/scripts/build-bins.sh` runs all
  component builds in order: (1) capavisor `cargo build`, (2) cloud-hypervisor
  `cargo build --release --features themis`, (3) 2026 workspace `cargo build
  --release`, (4) `make -C thhv` with headers from P16.5d, (5) `make -C thhv
  tests`, (6) `update-bins.sh`.  Flags: `BINS_TARGETS=thhv,chv,2026`,
  `PROFILE=release`.

- [x] **P16.5f** — xtask / cargo aliases: add `build-bins` and `dom0` as
  `cargo xtask` subcommands (or `.cargo/config.toml` aliases) so the full
  workflow is `cargo build-bins && cargo dom0`.

#### Docker build layer (containerized alternative)

The native path (P16.5a–f) and Docker path share the same scripts.  Docker
is a pure **build environment shim** — it provides a pinned, reproducible
toolchain without requiring the host machine to have the right Rust version,
LLVM, or kernel header tooling.  QEMU / boot always runs natively; the
container only produces `bins.img`.

Architecture:
```
[Docker container]                    [Host (always native)]
  workspace mounted at /workspace  →  run-qemu.sh / run-dom0.sh
  fetch-kheaders.sh                    boots QEMU with bins.img
  build-bins.sh
  → bins.img output at guest/bins.img
```

Key property: `build-bins.sh` is the same script in both paths.  The
container just wraps it with the right environment.  `fetch-kheaders.sh`
works inside Docker via `apt-get download` (no host kernel involved).

- [x] **P16.5g** — `Dockerfile.build`: builder image based on
  `ubuntu:24.04`.  Installs pinned Rust toolchain (via `rustup` with the
  same toolchain file as the workspace), LLVM/clang matching what capavisor
  needs, `build-essential`, `dpkg-dev`, `fuse2fs`, `e2fsprogs`, `curl`,
  `git`.  Does NOT install QEMU.  Copies nothing from the repo — workspace
  is bind-mounted at runtime.  Image is tagged `themis-build:latest`.
  Build with `docker build -f Dockerfile.build -t themis-build .` from
  the repo root.

- [x] **P16.5h** — `themis/scripts/build-bins-docker.sh`: thin wrapper
  that runs `build-bins.sh` inside the container:
  ```bash
  docker run --rm \
    -v "$(git rev-parse --show-toplevel)":/workspace \
    -w /workspace \
    --user "$(id -u):$(id -g)" \
    themis-build:latest \
    bash themis/scripts/build-bins.sh "$@"
  ```
  Passes through `BINS_TARGETS`, `PROFILE`, and other env vars.
  The `--user` flag ensures output files are owned by the host user.
  Expose as `cargo build-bins-docker` alias alongside `cargo build-bins`.

- [x] **P16.5i** — Document the two-path workflow in
  `themis/scripts/README.md`: native path (requires recent host kernel +
  toolchain), Docker path (requires only Docker; kernel compatibility
  handled inside container).  Include a troubleshooting section for the
  "older kernel host" case (the motivation for the Docker path).

- [ ] **P16.5j** — **Dom1 guest image**: `themis/scripts/fetch-dom1.sh`
  downloads a fresh Ubuntu Noble cloud image for dom1 (separate copy from
  dom0), creates a cloud-init seed (`guest/dom1-seed.img`) that provisions
  user `cloud`/`cloud123` with sudo.  No bins mount needed for dom1.
  `build-bins.sh` auto-fetches dom1 if `guest/dom1.img` is absent (same
  pattern as dom0 auto-fetch).

- [ ] **P16.5k** — **Dom1 disk attachment**: update `run-qemu.sh` and
  `run-dom0.sh` to attach `guest/dom1.img` as `vdc` (read-write) when
  present.  `SEED_DOM1=1` attaches `guest/dom1-seed.img` as a cdrom for
  first-boot cloud-init provisioning.

- [ ] **P16.5l** — **`run-dom1.sh` in bins**: package
  `themis/scripts/run-dom1.sh` into `bins.img` at
  `/opt/bins/run-dom1.sh`.  The script:
  1. Tries `sudo insmod /opt/bins/thhv/thhv.ko` if `/dev/thhv` absent.
  2. Calls `cloud-hypervisor` with UEFI firmware, `--disk path=/dev/vdc`,
     `--cpus boot=2`, `--memory size=1G`, `--console tty`, `--serial tty`.
  3. Auto-detects backend: if `/dev/thhv` present → Themis, else → KVM.
  Works identically under `cargo dom0` (KVM) and `cargo themis` (Themis).



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

### Phase 20 — Attested Boot

Bind the capavisor binary to the physical platform via a TPM root of trust, and
have the capavisor sign domain attestation reports with an Ed25519 key measured
into the TPM at boot.  Design: `2026/docs/design/attestation/attestation.md`.

**Dependency order**: P20a → P20b → P20c → P20d → P20e (signed reports).
P20f (swtpm QEMU) is independent of P20b–e.  P20g requires P20e + P20f.

- [ ] **P20a** — **Struct definitions in `themis-abi`**:
  - Add `BootAttestation` (128 bytes): magic, pub_key[32], priv_key[32],
    measurement[32], pcr_index:u32, reserved[20].  This is the boot handoff struct.
  - Add `SignedAttestReport` (168 bytes): wraps `AttestReport` + signature[64]
    + pub_key[32] + nonce[32].  This is what `do_attest_self` will deliver.
  - Add `ed25519-dalek` (no_std) + `sha2` + `zeroize` to `themis-abi/Cargo.toml`.

- [ ] **P20b** — **Pre-boot keygen + PCR extend** (Limine module or pre-capavisor binary):
  - Implement `BootAttestModule`: runs before capavisor entry.
  - Generate Ed25519 key pair seeded from RDRAND/RDSEED.
  - Compute `SHA-256(capavisor_binary ‖ boot_info_bytes ‖ pub_key)`.
  - Issue `TPM2_PCR_Extend(PCR=11, SHA-256, digest)` over TIS MMIO (0xFED40000).
  - Write `BootAttestation` struct to a Limine-tagged memory region for capavisor.
  - Minimal no_std TIS driver (send/recv TPM2 command/response bytes).

- [ ] **P20c** — **Capavisor boot handoff** (`capavisor/src/boot.rs`):
  - Scan Limine module list for `BOOT_ATTEST_MAGIC` tag.
  - Copy `BootAttestation` from the module region.
  - Zero the source region immediately after copying (key hygiene).
  - Store `pub_key` and `priv_key` in a static `AttestedKey` inside META
    (never mapped into any domain's EPT).
  - Verify `measurement` field matches expected PCR value (optional sanity check).

- [ ] **P20d** — **Attestation key management** (`capavisor/src/attest.rs` or new module):
  - `static ATTEST_KEY: Once<AttestKey>` — holds Ed25519 signing key.
  - `fn init_attest_key(priv_key: &[u8; 32])` — called from boot, zeroes input after init.
  - `fn sign_report(report: &AttestReport, nonce: &[u8; 32]) -> [u8; 64]` — Ed25519 sign.
  - `fn get_pub_key() -> [u8; 32]` — returns public key for inclusion in reports.

- [ ] **P20e** — **Signed report delivery** (`capavisor/src/hypercall.rs`):
  - Update `do_attest_self`: accept nonce from hypercall args (RDI–RDX = 4×u64 = 32 bytes).
  - Call `attest_domain` to build `AttestReport`.
  - Call `sign_report(report, nonce)` → signature.
  - Build `SignedAttestReport { report, signature, pub_key, nonce }`.
  - Write into DomainComm RX ring (same path as existing boot attestation write).
  - Return `HypercallResult::success_1(report.domain_id)` (unchanged ABI).

- [ ] **P20f** — **QEMU swtpm integration** (`themis/scripts/run-qemu.sh` + `run-dom0.sh`):
  - Add `start_swtpm()` helper: creates `/tmp/swtpm-state`, starts swtpm socket daemon.
  - Pass `-chardev socket,id=chrtpm,...  -tpmdev emulator,...  -device tpm-tis,...` to QEMU.
  - Stop swtpm on exit (`trap`).
  - Ensure `swtpm` and `tpm2-tools` are listed as host prerequisites in scripts/README.md.

- [ ] **P20g** — **Dom0 attestation verifier tool** (`2026/` workspace or `themis/tools/`):
  - Reads `SignedAttestReport` from DomainComm (via ioctl or /dev/thhv read).
  - Reads TPM PCR 11 via `tpm2_pcrread sha256:11` or direct TPM2 command.
  - Reconstructs `expected_measurement = SHA-256(expected_binary ‖ expected_boot_info ‖ pub_key)`.
  - Checks `PCR[11] == expected_measurement`.
  - Verifies Ed25519 signature on the `AttestReport` bytes using `pub_key` from report.
  - Prints pass/fail with details.

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
- [ ] **#U5** vAPIC for all domains (incl. dom0) — replace LAPIC/IOAPIC EPT passthrough with "Virtualize APIC accesses" (secondary bit 0), APIC-access page, virtual-APIC page, and TPR shadow.  Remove direct LAPIC EPT mapping from boot.rs.  See BUG-6 note.  _Post-clean-boot refactor._
  **NOTE (x2APIC)**: the capavisor never enables x2APIC mode; the APIC runs
  in xAPIC (MMIO) mode.  `get_current_core()` uses CPUID leaf 1 (always works).
  `send_ipi()` uses xAPIC MMIO writes (0xFEE0_0300/0x310 via HHDM).  We cannot
  enable x2APIC until dom0's APIC access is virtualised (otherwise dom0 Linux
  may regress the mode by writing IA32_APIC_BASE directly).  Once #U5 is done
  and IA32_APIC_BASE writes are intercepted, enable x2APIC for the capavisor
  and switch send_ipi back to `wrmsr(IA32_X2APIC_ICR)`.
- [x] **#U6** Enable XSAVES/XRSTORS — ✅ DONE.  Set secondary exec control bit 20 (ENABLE_XSAVES_XRSTORS), write XSS-exiting bitmap = 0 (all XSAVES/XRSTORS execute natively), removed CPUID 0xD:1 bit 3 mask.  IA32_XSS (0xDA0) passes through via zeroed MSR bitmap.  Tested: dom0 boots to login prompt.
- [x] **#U7** Capability API plumbing (themis_abi ↔ capability engine) — ✅ DONE.
  CoreContext replaces PerCoreCell (domain_id, vp_id, domain_cap).  Boot init
  seeds dom0_cap and all per-core contexts before AP launch.  Register convention
  documented in themis_abi.  hypercall.rs dispatches 10 opcodes (CARVE, ALIAS,
  SEND, ACCEPT, REJECT, CREATE_DOMAIN, SEAL, REVOKE_MEM, REVOKE_DOMAIN,
  ATTEST_SELF) with 14 stubs.  VMCALL handler wired in vmexit.rs.  Builds clean.

  _(Design notes for U7a–U7f archived — implementation matches spec.)_
