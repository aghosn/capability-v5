//! `ThemisPlatform` — the capability engine's [`Platform`] implementation.
//!
//! Phase P3a: full `Platform` implementation with a real RW spinlock, an
//! update-application serialisation lock, a two-phase IPI barrier, and x2APIC
//! IPI delivery.
//!
//! IOMMU integration points are marked `TODO(P4)` and left as no-ops until
//! Phase 4 (VT-d).
//!
//! ## Lock hierarchy (always acquire in this order to prevent deadlock)
//!
//! 1. `op_lock`     — RW spinlock for capability-tree operation serialisation.
//! 2. `update_lock` — TAS atomic for the IPI / barrier / apply sequence.
//! 3. per-domain `Mutex<PlatformDomain>` for EPT / domain state.
//!
//! ## Cross-core protocol (§5.2)
//!
//! ```text
//! initiating core:
//!   acquire op_lock (shared or exclusive)
//!   run capability mutation → UpdateBatch
//!   spin on update_lock (poll_and_respond_cross_core while waiting)
//!   for each affected core: send IPI (sets ipi_pending[core])
//!   sync.switched.wait(n+1)      — wait for all affected cores to stop
//!   apply_update for each entry   — EPT/memory changes
//!   sync.applied.wait(n+1)       — release cores to flush local state
//!   release update_lock
//!   release op_lock
//!
//! responding core (via poll_and_respond_cross_core / P3b IDT handler):
//!   clear ipi_pending[self]
//!   capability_engine::domain_api::apply_core_updates(platform, core) —
//!     drains this core's own engine-owned queue (VMCLEAR/VMPTRLD for
//!     Switch, INVEPT for TlbShootdown, …) and rendezvous on the same
//!     transaction's barriers (found embedded in the queue entries it
//!     just drained) — this is where the responder actually switches off
//!     the doomed domain:
//!   sync.switched.wait(0)    — signal "I have switched off the doomed domain"
//!   sync.applied.wait(0)     — wait for initiator's apply_update to finish
//! ```
//!
//! ## Update barrier and locking invariants
//!
//! 1. **No deadlock between apply_update and barrier**: `apply_update` acquires
//!    per-domain `Mutex<PlatformDomain>` AFTER barrier 0 (all affected cores have
//!    stopped).  Responding cores (in `poll_and_respond_cross_core`) do NOT hold
//!    domain locks when they call `sync.switched.wait(0)`.  Therefore there is no
//!    deadlock.
//!
//! 2. **Domain lock ordering**: `apply_update` must NOT acquire two domain locks
//!    simultaneously (no such case today).  When this becomes necessary, locks must
//!    be acquired in ascending DomainId order to prevent deadlock.
//!
//! 3. **Single source of truth for "who is running what"**: which domain/VP
//!    is scheduled on each core lives exclusively in the capability engine's
//!    `SwitchManager`/`CoreContext` (`capability_engine::switch`) — this
//!    platform has no shadow copy (Tier 1 atomics/Tier 3 routing maps were
//!    removed once the engine took ownership). `get_core_cap`/
//!    `core_domain_id` read the engine's binding directly.
//!
//! 4. **Domain switch race with UpdateBatch**: A core performing a domain switch
//!    must complete its engine-side `set_binding` + VMPTRLD of the new VMCS
//!    BEFORE handling any VMEXIT that could trigger a new UpdateBatch for the
//!    new domain. This is guaranteed because the switch is atomic from the
//!    perspective of the barrier: the core is either "stopped at barrier" or
//!    "running in a domain". A core cannot be simultaneously doing a switch
//!    and responding to a barrier.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use spin::{Mutex, RwLock};

use capability_engine::{CapabilityRef, CoreId, Domain, DomainId, OpLockGuard, Platform, Result, SwitchManager, Update};

use crate::arch::{ArchDomainState, ArchPlatformState};
#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::msr_bitmap;
use crate::arch_traits::{ArchDomain, ArchPlatform, ChangeRightsCtx};

use crate::mem::{PhysRegion, UncacheableRanges};

/// Cross-arch alias for the per-VP inactive state owned by an
/// [`ArchDomainState`].  On x86 this resolves to
/// [`crate::vcpu::InactiveVcpu`]; on AArch64 it resolves to the stub
/// associated type.  Used by the platform's VP-slot wrappers so callers
/// never have to spell out the trait projection.
pub type InactiveVp = <ArchDomainState as ArchDomain>::InactiveVp;

// ── Submodules ────────────────────────────────────────────────────────────── //

mod domain;
mod maps;
mod sync;
pub(crate) mod vcpu_slot;

pub use domain::{DoorbellEntry, PlatformDomain, THEMIC_DOORBELL_FLAG_ANY_SIZE,
    THEMIC_DOORBELL_FLAG_ANY_VALUE, THEMIC_MAX_DOORBELLS,
};
pub use vcpu_slot::CoreContext;

use maps::DomainTable;
use sync::{ExclusiveGuard, SharedGuard};

// ── Constants ─────────────────────────────────────────────────────────────── //

/// Maximum number of physical cores supported.
/// Used only for compile-time statics (GDT/TSS) that cannot be
/// heap-allocated.  ThemisPlatform sizes its per-core arrays dynamically.
pub const MAX_CORES: usize = 256;

// ── ThemisPlatform ────────────────────────────────────────────────────────── //

/// Domain ID reserved for the root (dom0) domain.
/// IOMMU page-table frames (SLPT root + intermediate pages) are allocated
/// from this domain's META pool — not from child domains — so that child
/// META budgets are not consumed by hypervisor-internal structures.
pub const ROOT_DOMAIN_ID: DomainId = 0;

/// The Themis `Platform` implementation.
pub struct ThemisPlatform {
    // Hot path: no lock needed
    op_lock: RwLock<()>,
    update_lock: AtomicBool,
    pub ipi_pending: Box<[AtomicBool]>,
    // Immutable after bootstrap
    num_cores: usize,
    hhdm_offset: AtomicU64,
    uc_ranges: alloc::sync::Arc<UncacheableRanges>,
    // Hardware-only per-core state (pinned ActiveVcpu pointer, deferred
    // vector). "Which domain/VP is running here" is NOT tracked here — see
    // `switch_mgr` below.
    cores: Box<[CoreContext]>,
    // Tier 2: per-domain hardware state
    domains: DomainTable,
    // Tree root anchor — keeps dom0's capability tree alive.
    dom0_cap: Mutex<Option<CapabilityRef<Domain>>>,
    /// Architecture-specific platform state (VMXON, DRHD, LAPIC IDs on x86;
    /// GIC, MPIDRs on ARM). Cross-arch operations on this state go through
    /// the [`ArchPlatform`] trait; arch-specific accessors are inherent
    /// methods on the concrete `ArchPlatformState`.
    pub arch: ArchPlatformState,
    /// The single authoritative source for "which domain/VP is running on
    /// each core", the per-core cross-core update queue, and each core's
    /// live call chain. See [`capability_engine::switch::SwitchManager`].
    switch_mgr: SwitchManager,
}

// SAFETY: All fields are Sync (atomics, spin locks, ArchPlatformState which
// owns its own UnsafeCell-protected boot-time data).
unsafe impl Sync for ThemisPlatform {}

impl ThemisPlatform {
    /// Create a new platform with no domains registered.
    ///
    /// `num_cores` is the physical core count discovered at boot (from Limine MP).
    pub fn new(uc_ranges: alloc::sync::Arc<UncacheableRanges>, num_cores: usize) -> Self {
        let ipi_pending: Box<[AtomicBool]> = (0..num_cores)
            .map(|_| AtomicBool::new(false))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let cores: Box<[CoreContext]> = (0..num_cores)
            .map(|_| CoreContext::new())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        ThemisPlatform {
            op_lock: RwLock::new(()),
            update_lock: AtomicBool::new(false),
            ipi_pending,
            num_cores,
            hhdm_offset: AtomicU64::new(0),
            uc_ranges,
            cores,
            domains: DomainTable::new(),
            dom0_cap: Mutex::new(None),
            arch: ArchPlatformState::new(),
            switch_mgr: SwitchManager::new(num_cores),
        }
    }

    /// Number of physical cores (set at boot from Limine MP response).
    pub fn num_cores(&self) -> usize {
        self.num_cores
    }

    /// Reprogram a PCI device's IOMMU context entry to use `domain_id`'s
    /// second-level page table (SLPT), replacing the dom0 passthrough entry.
    ///
    /// Architecture-neutral wrapper: x86 implementation lives in
    /// `arch/x86_64/iommu_dev` (VT-d).  No-op on non-x86 (will be replaced
    /// with an SMMU implementation).
    ///
    /// `bdf` is the 16-bit source ID: `bus[15:8] | device[7:3] | function[2:0]`.
    pub fn assign_device(&self, bdf: u16, domain_id: DomainId) {
        crate::arch::assign_device(self, bdf, domain_id);
    }

    /// Restore the passthrough context entry for a PCI device, returning it to
    /// dom0 (DID=1, TT=10b pass-through).  Called on child-domain revocation.
    pub fn release_device(&self, bdf: u16) {
        crate::arch::release_device(self, bdf);
    }

    pub fn bootstrap_give_meta(&self, domain_id: DomainId, region: PhysRegion) {
        self.domains
            .get(domain_id)
            .unwrap_or_else(|| panic!("bootstrap_give_meta: domain {} not registered", domain_id))
            .lock()
            .meta
            .add_range(region);
    }

    /// Allocate and initialize the DomainComm region for a domain.
    ///
    /// For dom0 this is called during boot before the domain starts.
    /// Allocates `nr_pages` from the domain's META pool, writes the header
    /// and optionally pre-populates the RX ring with an attestation message.
    ///
    /// For dom0 the base HPA equals the GPA (identity mapping).  For child
    /// domains the caller provides HPAs from CARVEd pages.
    ///
    /// Returns `(gpa, nr_pages)` — the domain's e820/CPUID should be updated
    /// to reflect this reserved region.
    pub fn bootstrap_init_domcomm(
        &self,
        domain_id: DomainId,
        base_hpa: u64,
        gpa: u64,
        nr_pages: u32,
    ) -> (u64, u32) {
        let arc = self
            .domains
            .get(domain_id)
            .unwrap_or_else(|| panic!("bootstrap_init_domcomm: domain not registered"));
        let mut d = arc.lock();
        // Build contiguous HPA list from base.
        let hpas: Vec<u64> = (0..nr_pages as u64).map(|i| base_hpa + i * 0x1000).collect();
        d.init_domcomm(&hpas);
        (gpa, nr_pages)
    }

    /// Finalize DomainComm for a child domain at seal time.
    ///
    /// Consumes `pending_domcomm_hpas` accumulated during `REGISTER_COMM`
    /// calls and initialises the DomainComm header + rings.  Returns the
    /// header HPA (for CPUID discovery) or `None` if no pages were registered.
    pub fn finalize_domcomm(&self, domain_id: DomainId) -> Option<u64> {
        let arc = self.domains.get(domain_id)?;
        let mut pd = arc.lock();
        if pd.pending_domcomm_hpas.is_empty() {
            return None;
        }
        let hpas: Vec<u64> = core::mem::take(&mut pd.pending_domcomm_hpas);
        let state = pd.init_domcomm(&hpas);
        Some(state.header_hpa)
    }

    /// Write a binary attestation message to a domain's DomainComm RX ring.
    ///
    /// The attestation payload is a `domcomm::AttestReport` header followed by
    /// packed arrays of mem_cap, dom_cap, and pa_map entries.
    ///
    /// Must be called after `bootstrap_init_domcomm`.

    pub fn bootstrap_register_domain(
        &self,
        domain_id: DomainId,
        parent_id: Option<DomainId>,
        hhdm_offset: u64,
    ) {
        self.hhdm_offset.store(hhdm_offset, Ordering::Relaxed);
        if !self.domains.contains(domain_id) {
            self.domains
                .insert(domain_id, PlatformDomain::new(hhdm_offset, parent_id));
        }
    }

    /// Snapshot of the per-LP translation-cache handle (the SLAT context
    /// identifier) for `domain_id` — x86: the EPTP, ARM: a VMID-derived
    /// value.  Returns `None` when the domain is unknown or has no
    /// second-stage tables yet.
    pub fn slat(&self, domain_id: DomainId) -> Option<u64> {
        self.domains.get(domain_id)?.lock().arch.slat()
    }

    /// Get a cloned Arc reference to a PlatformDomain (for use outside apply_update).
    pub fn domain_arc(
        &self,
        domain_id: DomainId,
    ) -> Option<alloc::sync::Arc<Mutex<PlatformDomain>>> {
        self.domains.get(domain_id)
    }

    /// Get the HHDM offset (physical → virtual address translation).
    pub fn hhdm_offset(&self) -> u64 {
        self.hhdm_offset.load(Ordering::Relaxed)
    }

    /// Program the IOMMU's IRTEs for a sealed child domain.
    ///
    /// Architecture-neutral wrapper: the actual implementation lives under
    /// `arch/x86_64/iommu_ir` (VT-d Interrupt Remapping). On non-x86 builds
    /// this is a no-op (will be replaced with an SMMU implementation).
    pub fn program_domain_irtes(&self, child: &capability_engine::CapabilityRef<capability_engine::Domain>) {
        crate::arch::program_domain_irtes(self, child);
    }

    /// Invalidate all IRTEs that were programmed for a (now-revoked) domain.
    pub fn invalidate_domain_irtes(&self, domain_id: DomainId) {
        crate::arch::invalidate_domain_irtes(self, domain_id);
    }

    /// Allocate the next globally unique VPID (1, 2, 3, ...).
    /// VPID 0 is reserved (means "current VPID" in INVVPID).
    pub fn next_vpid(&self) -> u16 {
        static VPID_COUNTER: AtomicU16 = AtomicU16::new(1);
        let id = VPID_COUNTER.fetch_add(1, Ordering::Relaxed);
        assert!(id != 0, "VPID counter wrapped to 0");
        id
    }

    pub fn alloc_meta_frame(&self, domain_id: DomainId) -> u64 {
        self.domains
            .get(domain_id)
            .unwrap_or_else(|| panic!("alloc_meta_frame: domain not registered"))
            .lock()
            .meta
            .alloc_frame()
    }

    /// Store an InactiveVcpu in a domain's VP slot during bootstrap.
    ///
    /// Insert an inactive VP into a domain's per-VP slot vector, growing
    /// the vector as needed.
    ///
    /// `vp_id` is the domain-local VP index (0, 1, 2, ...).
    pub fn bootstrap_store_vcpu(&self, domain_id: DomainId, vp_id: usize, vcpu: InactiveVp) {
        let arc = self
            .domains
            .get(domain_id)
            .unwrap_or_else(|| panic!("bootstrap_store_vcpu: domain not registered"));
        let mut d = arc.lock();
        d.arch.store_inactive_vp(vp_id, vcpu);
    }

    /// Atomically take an inactive VP from a domain's slot.
    ///
    /// Returns `None` if the VP is already active on another core (slot
    /// empty) or the domain/VP id is unknown.
    pub fn take_vcpu(&self, domain_id: DomainId, vp_id: usize) -> Option<InactiveVp> {
        let arc = self.domains.get(domain_id)?;
        let d = arc.lock();
        d.arch.take_inactive_vp(vp_id)
    }

    /// Return an inactive VP to a domain's slot after deactivation.
    pub fn return_vcpu(&self, domain_id: DomainId, vp_id: usize, vcpu: InactiveVp) {
        let arc = self
            .domains
            .get(domain_id)
            .unwrap_or_else(|| panic!("return_vcpu: domain not registered"));
        let mut d = arc.lock();
        d.arch.return_inactive_vp(vp_id, vcpu);
    }

    /// Flush this domain's per-LP translation cache on the *current* CPU.
    /// Cross-arch wrapper around [`ArchDomain::flush_tlb`] that also
    /// clears the cache-presence bit so subsequent shootdowns do not
    /// redundantly target this LP.
    pub(crate) fn flush_local(&self, domain_id: DomainId) {
        if let Some(arc) = self.domains.get(domain_id) {
            let pd = arc.lock();
            pd.arch.flush_tlb();
            if let Some(core) = self.get_current_core() {
                if let Ok(core_ctx) = self.switch_mgr.get_core(core) {
                    core_ctx.clear_cached(domain_id);
                }
            }
        }
    }

    // ── CoreContext access ─────────────────────────────────────────────── //

    /// Pin the calling core's `ActiveVcpu` pointer.
    ///
    /// Called once from `monitor_loop` before entering the exit-handling
    /// loop.  The pointer lives at a fixed stack address for the entire
    /// (divergent) lifetime of `monitor_loop`, so it is never cleared.
    ///
    /// SAFETY: `ptr` must point to a valid `ActiveVcpu` on this core's
    /// monitor-loop stack that will remain live and unmoved for the rest
    /// of the core's execution.  Only the owning core will dereference it,
    /// and only between VMEXITs.
    ///
    /// Does not overlap with `VcpuSlot::take`/`put`: this pointer identifies
    /// *which stack slot* `monitor_loop` currently reads/writes into on this
    /// core (fixed for the core's whole lifetime, never cleared), whereas
    /// `VcpuSlot` tracks *which VP's* `InactiveVcpu` is checked in/out of a
    /// per-VP slot (changes on every cross-domain switch). `swap_active_vp`
    /// uses both: it `take`/`put`s VP-level slots while VMCLEAR/VMPTRLD-ing
    /// the contents pointed to by this same pinned `active_vcpu` pointer.
    pub fn pin_active_vcpu(&self, core_id: CoreId, ptr: *mut u8) {
        self.cores[core_id as usize]
            .active_vcpu
            .store(ptr, Ordering::Release);
    }

    /// Read the calling core's pinned `ActiveVcpu` pointer, if any.
    ///
    /// Returns `null` before `pin_active_vcpu` has been called on this
    /// core (early boot only).  Callers cast to the arch-specific
    /// `ActiveVcpu` type.
    pub fn active_vcpu_ptr(&self, core_id: CoreId) -> *mut u8 {
        self.cores[core_id as usize]
            .active_vcpu
            .load(Ordering::Acquire)
    }

    /// Store the dom0 `CapabilityRef<Domain>` as the tree root anchor.
    ///
    /// Must be called exactly once during boot.  Keeps the entire capability
    /// tree alive for the lifetime of the capavisor.
    pub fn set_dom0_cap(&self, cap: CapabilityRef<Domain>) {
        *self.dom0_cap.lock() = Some(cap);
    }

    /// Get the dom0 `CapabilityRef<Domain>` (tree root anchor).
    #[allow(dead_code)]
    pub fn dom0_cap(&self) -> CapabilityRef<Domain> {
        self.dom0_cap
            .lock()
            .as_ref()
            .expect("dom0_cap not yet initialised")
            .clone()
    }

    /// Get the `CapabilityRef<Domain>` for the domain running on `core_id`.
    ///
    /// Reads the capability engine's `SwitchManager` — the single
    /// authoritative source for "which domain/VP is running where".
    /// Returns `None` during early boot before the core is bound.
    pub fn get_core_cap(&self, core_id: usize) -> Option<CapabilityRef<Domain>> {
        self.switch_mgr
            .get_core(core_id as CoreId)
            .ok()
            .and_then(|c| c.current_binding())
            .map(|b| b.domain)
    }

    /// Read the domain ID currently scheduled on `core_id`.
    pub fn core_domain_id(&self, core_id: usize) -> u64 {
        self.switch_mgr
            .get_core(core_id as CoreId)
            .ok()
            .and_then(|c| c.current_domain())
            .unwrap_or(u64::MAX)
    }

    /// Get the VP index currently running on `core_id`.
    #[allow(dead_code)]
    pub fn get_core_vp(&self, core_id: usize) -> u32 {
        self.switch_mgr
            .get_core(core_id as CoreId)
            .ok()
            .and_then(|c| c.current_vp())
            .unwrap_or(u32::MAX as u64) as u32
    }

    // ── quantum-sched deferred vector helpers ────────────────────────── //

    /// Store a parent-bound vector to be flushed later (quantum-sched).
    ///
    /// The deferred vector is flushed to the parent domain on the next
    /// preemption timer expiry or before the next SWITCH to a child.
    #[cfg(feature = "quantum-sched")]
    pub fn set_deferred(&self, core_id: usize, vector: u8) {
        self.cores[core_id]
            .deferred_vector
            .store(vector as u16, Ordering::Release);
    }

    /// Atomically take the deferred vector for the given core (quantum-sched).
    /// Returns `Some(vector)` if one was stored, `None` if empty (0).
    #[cfg(feature = "quantum-sched")]
    pub fn take_deferred(&self, core_id: usize) -> Option<u8> {
        let val = self.cores[core_id]
            .deferred_vector
            .swap(0, Ordering::AcqRel);
        if val == 0 {
            None
        } else {
            Some(val as u8)
        }
    }
}

impl ThemisPlatform {
    /// Public wrapper around the Platform trait's get_current_core for
    /// crate-internal use (e.g., by x86_platform.rs).
    pub(crate) fn current_core_id(&self) -> Option<capability_engine::CoreId> {
        self.get_current_core()
    }

    /// Apply a `PolicyChange` delta to per-domain hardware state.
    ///
    /// Today only MSR variants project to hardware (the per-domain VMX
    /// MSR bitmap, x86-only). The other variants are no-ops with
    /// explicit TODO markers — kept as match arms so any future
    /// engine-side addition causes a compile-time miss here.
    fn apply_policy_change(
        &self,
        domain: DomainId,
        change: &capability_engine::PolicyChange,
    ) {
        use capability_engine::PolicyChange as PC;

        match change {
            #[cfg(target_arch = "x86_64")]
            PC::MsrDefault(action) => {
                if let Some(phys) = self.msr_bitmap_phys(domain) {
                    // SAFETY: bitmap_phys is the domain's MSR bitmap
                    // page; hardware re-reads the bitmap on every MSR
                    // access so partial updates between set_default and
                    // the subsequent range/override re-emits are safe.
                    let hhdm = self.hhdm_offset.load(Ordering::Relaxed);
                    unsafe { msr_bitmap::set_default(phys, hhdm, *action); }
                }
            }
            #[cfg(target_arch = "x86_64")]
            PC::MsrRange { start, end, action } => {
                if let Some(phys) = self.msr_bitmap_phys(domain) {
                    let trap = matches!(action, capability_engine::DefaultAction::Trap);
                    let hhdm = self.hhdm_offset.load(Ordering::Relaxed);
                    unsafe { msr_bitmap::apply_range(phys, hhdm, *start, *end, trap); }
                }
            }
            #[cfg(target_arch = "x86_64")]
            PC::MsrEmulate { msr, .. } => {
                if let Some(phys) = self.msr_bitmap_phys(domain) {
                    // Emulate ⇒ trap (capavisor's emulator runs on exit).
                    let hhdm = self.hhdm_offset.load(Ordering::Relaxed);
                    unsafe { msr_bitmap::trap_msr(phys, hhdm, *msr, true); }
                }
            }

            // Non-x86 builds: MSR variants have no projection.
            #[cfg(not(target_arch = "x86_64"))]
            PC::MsrDefault(_) | PC::MsrRange { .. } | PC::MsrEmulate { .. } => {}

            // CPUID is always trapped via CPUID-exiting=1 and dispatched
            // at exit against the live engine policy; no derived bitmap.
            PC::CpuidDefault(_)
            | PC::CpuidRange { .. }
            | PC::CpuidEmulate { .. } => {}

            // Exit-routing → VMCS procbased/pin/exit/entry controls.
            // TODO: project to VMCS controls when policy.exits drives them.
            PC::DefaultExitTrap(_)
            | PC::ExitReason { .. }
            | PC::ExitReasonRegReadSet { .. }
            | PC::ExitReasonRegWriteSet { .. } => {}

            // Interrupt visibility / per-vector reg sets — consumed at
            // exit dispatch time; no derived hardware bitmap today.
            // TODO when A3 (lazy-unwind) relaxes and EOI-exit bitmap is used.
            PC::InterruptDefaultVisibility(_)
            | PC::VectorVisibility { .. }
            | PC::VectorRegReadSet { .. }
            | PC::VectorRegWriteSet { .. } => {}

            // Per-vector explicit-injection permission — consumed directly
            // by `do_inject_interrupt` at THEMIS_INJECT_INTERRUPT call time
            // (reads `policy.interrupts` live); no derived hardware state.
            PC::VectorInjectable { .. } => {}

            // Pure engine ACLs (no hardware effect).
            PC::Cores(_) | PC::ApiMonitor(_) => {}
        }

        let _ = domain;
    }

    /// Look up the per-domain MSR bitmap physical address, or `None` if
    /// the domain isn't registered yet or has no bitmap allocated (will
    /// be projected from policy by the next `do_add_vp`).
    #[cfg(target_arch = "x86_64")]
    fn msr_bitmap_phys(&self, domain: DomainId) -> Option<u64> {
        let d = self.domains.get(domain)?;
        let phys = d.lock().arch.msr_bitmap_phys();
        if phys == 0 { None } else { Some(phys) }
    }

    /// Re-project the sealed domain's full MsrPolicy onto its VMCS MSR
    /// bitmap. Called from `do_seal` so that seal is the authoritative
    /// synchronization point between the engine's policy state and the
    /// hardware bitmap — regardless of the order in which userspace
    /// issued `THHV_SET_POLICY` and `THHV_CREATE_VP` (which cannot be
    /// trusted per axiom A2).
    ///
    /// If the domain has no MSR bitmap yet (no VP was ever added,
    /// therefore the bitmap page was never allocated), this is a no-op:
    /// there is no hardware state to stale. Any future `do_add_vp` will
    /// project the current policy at that time.
    #[cfg(target_arch = "x86_64")]
    pub fn reproject_msr_policy(&self, child: &CapabilityRef<Domain>) {
        let domain_id = child.read().data.id;
        let Some(phys) = self.msr_bitmap_phys(domain_id) else {
            return;
        };
        let hhdm = self.hhdm_offset.load(Ordering::Relaxed);
        // SAFETY: `phys` is the domain's dedicated MSR bitmap page; the
        // domain is sealed but its VPs have not been dispatched to any
        // physical core yet (dispatch happens after seal on the userspace
        // side via THHV_RUN_VP). Rewriting the bitmap here races only
        // with subsequent SetPolicy calls which serialize through the
        // capa-engine op-lock via apply_update.
        unsafe {
            let guard = child.read();
            crate::arch::x86_64::msr_bitmap::populate_from_policy(
                phys,
                hhdm,
                &guard.data.policy.msrs,
            );
        }
    }

    /// Non-x86 stub for `reproject_msr_policy` — no MSR bitmap exists.
    #[cfg(not(target_arch = "x86_64"))]
    pub fn reproject_msr_policy(&self, _child: &CapabilityRef<Domain>) {}
}

impl Platform for ThemisPlatform {
    fn acquire_shared_lock(&self) -> Result<Box<dyn OpLockGuard>> {
        Ok(Box::new(SharedGuard::new(&self.op_lock, self)))
    }

    fn acquire_exclusive_lock(&self) -> Result<Box<dyn OpLockGuard>> {
        Ok(Box::new(ExclusiveGuard::new(&self.op_lock, self)))
    }

    fn send_ipi(&self, core_id: CoreId) {
        // NOTE: this only signals the target core to enter the cross-core
        // poll/barrier protocol.  Per-domain TLB-shootdown / revoke-switch
        // payloads are pushed onto the engine's own per-core queue (see
        // `Platform::execute`'s per-domain/per-switch push loops) so each
        // affected core has the correct entries queued before the IPI lands.

        // Set the flag so the target core (if polling) can respond.
        self.ipi_pending[core_id as usize].store(true, Ordering::Release);

        // Delegate the actual cross-core wake to the arch backend
        // (LAPIC ICR INIT on x86, GICv3 SGI on ARM).
        self.arch
            .send_ipi(core_id, self.hhdm_offset.load(Ordering::Relaxed));
    }

    fn new_semaphore(&self) -> Arc<dyn capability_engine::Semaphore> {
        Arc::new(sync::Semaphore::new())
    }

    fn try_acquire_update_lock(&self) -> bool {
        self.update_lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    fn release_update_lock(&self) {
        self.update_lock.store(false, Ordering::Release);
    }

    fn poll_and_respond_cross_core(&self) {
        let Some(core_id) = self.get_current_core() else {
            return;
        };
        if core_id as usize >= self.num_cores {
            return;
        }
        if self.ipi_pending[core_id as usize]
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        // Drain this core's own engine-owned update queue — this is where
        // Switch handlers do VMCLEAR/VMPTRLD, and where rendezvous on the
        // transaction's barriers happens (inside `apply_core_updates`,
        // so it fires exactly once regardless of which caller drains the
        // entry first).  Must precede the initiator's first rendezvous, so
        // the initiator can rely on "no affected core still points at the
        // doomed VMCS" before tearing anything down.
        let _ = capability_engine::domain_api::apply_core_updates(self, core_id);
    }

    fn apply_update(&self, update: &Update) {
        match update {
            Update::CreateDomain {
                domain_id,
                parent_id,
            } => {
                self.register_domain(*domain_id, *parent_id);
            }

            Update::GiveMetaMem {
                domain_id,
                start,
                size,
            } => {
                self.domains
                    .get(*domain_id)
                    .expect("GiveMetaMem: unknown domain")
                    .lock()
                    .meta
                    .add_range(PhysRegion {
                        base: *start,
                        length: *size,
                    });
                // META pages are hypervisor-internal (EPT tables, VMCS) and are
                // not DMA targets — no IOMMU PT mapping needed here.
            }

            Update::ChangeRights {
                domain,
                address,
                size,
                physical,
                rights,
                shootdown_required,
            } => {
                let is_child = *domain != ROOT_DOMAIN_ID;
                let arc = self
                    .domains
                    .get(*domain)
                    .expect("ChangeRights: unknown domain");

                // Lock root before child for IOMMU SLPT page allocations.
                // Skipped when target IS root (no SLPT) or there is no root yet
                // (boot-time root self-mapping, before dom0 is registered).
                let root_arc = if is_child {
                    Some(
                        self.domains
                            .get(ROOT_DOMAIN_ID)
                            .expect("ChangeRights on child requires root domain"),
                    )
                } else {
                    None
                };
                let mut root_guard = root_arc.as_ref().map(|a| a.lock());
                let mut d = arc.lock();
                // Split MutexGuard's DerefMut so meta and arch can be borrowed
                // disjointly (they are separate fields of PlatformDomain).
                let pd: &mut PlatformDomain = &mut d;
                let mut ctx = ChangeRightsCtx {
                    meta: &mut pd.meta,
                    root_meta: root_guard.as_mut().map(|g| &mut g.meta),
                    uc_ranges: &self.uc_ranges,
                    hhdm_offset: self.hhdm_offset.load(Ordering::Relaxed),
                    is_child,
                };
                pd.arch
                    .change_rights(&self.arch, *address, *physical, *size as usize, rights, &mut ctx);
                // Local flush when this is a permission-reduction or unmap
                // (the engine pushes shootdowns to remote cores directly
                // via `execute()`'s per-domain push loop; the initiator
                // flushes itself here so the next VMENTER on this LP sees
                // the new EPT).
                if *shootdown_required {
                    pd.arch.flush_tlb();
                    if let Some(core) = self.get_current_core() {
                        if let Ok(core_ctx) = self.switch_mgr.get_core(core) {
                            core_ctx.clear_cached(*domain);
                        }
                    }
                }
            }

            Update::RevokeDomain { domain, .. } => {
                if let Some(mut d) = self.domains.remove(*domain) {
                    let is_child = *domain != ROOT_DOMAIN_ID;
                    let root_arc = if is_child {
                        self.domains.get(ROOT_DOMAIN_ID)
                    } else {
                        None
                    };
                    let mut root_guard = root_arc.as_ref().map(|a| a.lock());
                    // Local flush BEFORE tearing down EPT structures —
                    // otherwise the next VMENTER on this LP could TLB-hit
                    // a freed EPT entry.  Remote-core flushes were queued
                    // earlier by `execute()` with a snapshot of the EPTP,
                    // so `destroy` freeing the EPT here is safe.
                    d.arch.flush_tlb();
                    d.arch.destroy(
                        &mut d.meta,
                        root_guard.as_mut().map(|g| &mut g.meta),
                    );
                }
            }

            Update::ZeroMemory { address, size } => {
                let hhdm = self.hhdm_offset.load(Ordering::Relaxed);
                let virt = (address + hhdm) as *mut u8;
                unsafe { core::ptr::write_bytes(virt, 0, *size as usize) };
            }

            Update::FlushTLB { domain } => {
                self.flush_local(*domain);
            }

            Update::CommRegion {
                domain_id,
                target_domain_id,
                vp_id,
                phys,
                size,
            } => {
                if *domain_id != *target_domain_id {
                    if let Some(arc) = self.domains.get(*target_domain_id) {
                        let mut pd = arc.lock();
                        if *vp_id == u32::MAX {
                            // Domain-level COMM (from SEND with COMM attr):
                            // accumulate pages for init_domcomm at seal time.
                            let nr = (*size as usize + 0xFFF) / 0x1000;
                            for i in 0..nr {
                                pd.pending_domcomm_hpas.push(*phys + i as u64 * 0x1000);
                            }
                        } else {
                            // VP-level COMM: store HPA for child VP.
                            let vp = *vp_id as usize;
                            if vp >= pd.comm_hpas.len() {
                                pd.comm_hpas.resize(vp + 1, 0);
                            }
                            pd.comm_hpas[vp] = *phys;
                        }
                    }
                }
                let _ = (domain_id, phys, size);
            }
            Update::UncommRegion {
                domain_id,
                target_domain_id,
                vp_id,
                phys,
                size,
            } => {
                let _ = (domain_id, target_domain_id, vp_id, phys, size);
                // TODO(P7): unmap COMM page.
            }

            /// Domain-wide policy mutation. The platform re-projects any
            // per-domain hardware state it derives from policy. Today
            // only MSR has a derived projection (the VMX MSR bitmap);
            // the rest are no-ops with TODOs for when we wire them up.
            Update::PolicyChanged { domain, change } => {
                self.apply_policy_change(*domain, change);
            }

            // Already actioned before the barrier via the per-core
            // `CoreUpdate::Switch` push in `Platform::execute` (drained by
            // `apply_core_updates` strictly before `apply_update` runs) —
            // no separate hardware projection here.
            Update::Switch(_) => {}
        }
    }

    fn register_domain(&self, domain_id: DomainId, parent_id: Option<DomainId>) {
        if !self.domains.contains(domain_id) {
            let hhdm = self.hhdm_offset.load(Ordering::Relaxed);
            self.domains
                .insert(domain_id, PlatformDomain::new(hhdm, parent_id));
        }
    }

    fn on_domain_revoked(&self, _domain_id: DomainId, _fallback: Option<DomainId>) {
        // Redirecting cores off the doomed domain is now handled entirely
        // by the `CoreUpdate::Switch` mechanism: the engine pushes a
        // per-core switch order (drained by `apply_core_updates`, which
        // calls `Capability::switch_after_callee_revoked` to resolve the
        // resume target and commits the new binding on
        // `SwitchManager`/`CoreContext`) strictly before this callback
        // runs. There is no capavisor-side routing state left to clean up:
        // "which domain/VP is running where" lives solely in the engine's
        // `SwitchManager`, and Tier-2 domain unregistration is handled by
        // `apply_update(RevokeDomain)`'s `self.domains.remove(*domain)`.
    }

    fn tlb_flush_handle(&self, domain_id: DomainId) -> u64 {
        self.domains
            .get(domain_id)
            .and_then(|arc| arc.lock().arch.slat())
            .unwrap_or(0)
    }

    fn flush_tlb(&self, _domain_id: DomainId, handle: u64, _core_id: CoreId) {
        crate::arch::flush_tlb_handle(handle);
    }

    fn complete_revoke_switch(&self, core_id: CoreId, src: (DomainId, u64), dst: (DomainId, u64)) {
        // SAFETY: called by `capability_engine::domain_api::apply_core_updates`
        // strictly on the affected core itself (this platform never invokes
        // it cross-core), after the engine has already resolved and
        // committed the new `SwitchManager` binding — matching
        // `complete_revoke_switch`'s (arch) documented precondition. The
        // pinned `active_vcpu` pointer for `core_id` is valid because we are
        // running on `core_id`.
        unsafe {
            crate::arch::complete_revoke_switch(
                self,
                core_id,
                (src.0, src.1 as usize),
                (dst.0, dst.1 as usize),
            );
        }
    }

    // ── Register access (validation-only; actual VMCS writes batched by handler) ──

    fn register_count(&self) -> u64 {
        // VpRegister discriminants range 0x00..=0xB2 (179 values).
        // Round up to 192 (3 × 64) to match the dirty_mask word layout.
        192
    }

    fn set_vp_register(
        &self,
        domain_id: DomainId,
        vp_id: u64,
        reg_id: u64,
        value: u64,
    ) -> capability_engine::error::Result<()> {
        use capability_engine::error::CapaError;
        use themis_abi::regs::{VpCommPage, VpRegister};

        let reg = VpRegister::from_discriminant(reg_id)
            .ok_or_else(|| CapaError::InvalidOperation("unknown reg_id".into()))?;

        let arc = self
            .domain_arc(domain_id)
            .ok_or_else(|| CapaError::InvalidOperation("domain not found".into()))?;
        let comm_hpa = arc
            .lock()
            .comm_hpas
            .get(vp_id as usize)
            .copied()
            .unwrap_or(0);

        if comm_hpa == 0 {
            return Err(CapaError::InvalidOperation("VP has no COMM page".into()));
        }

        let hhdm = self.hhdm_offset();
        let comm = unsafe { &mut *((comm_hpa + hhdm) as *mut VpCommPage) };
        comm.write_reg(reg, value);
        comm.mark_dirty(reg);
        Ok(())
    }

    fn get_vp_register(
        &self,
        domain_id: DomainId,
        vp_id: u64,
        reg_id: u64,
    ) -> capability_engine::error::Result<u64> {
        use capability_engine::error::CapaError;
        use themis_abi::regs::{VpCommPage, VpRegister};

        let reg = VpRegister::from_discriminant(reg_id)
            .ok_or_else(|| CapaError::InvalidOperation("unknown reg_id".into()))?;

        let arc = self
            .domain_arc(domain_id)
            .ok_or_else(|| CapaError::InvalidOperation("domain not found".into()))?;
        let comm_hpa = arc
            .lock()
            .comm_hpas
            .get(vp_id as usize)
            .copied()
            .unwrap_or(0);

        if comm_hpa == 0 {
            return Err(CapaError::InvalidOperation("VP has no COMM page".into()));
        }

        let hhdm = self.hhdm_offset();
        let comm = unsafe { &*((comm_hpa + hhdm) as *const VpCommPage) };
        Ok(comm.read_reg(reg))
    }

    fn get_current_core(&self) -> Option<CoreId> {
        self.arch.current_core_id()
    }

    fn switch_manager(&self) -> &SwitchManager {
        &self.switch_mgr
    }
}
