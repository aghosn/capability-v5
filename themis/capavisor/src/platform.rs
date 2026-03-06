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
//! 3. `inner`       — `Mutex<ThemisPlatformInner>` for EPT / domain state.
//!
//! ## Cross-core protocol (§5.2)
//!
//! ```text
//! initiating core:
//!   acquire op_lock (shared or exclusive)
//!   run capability mutation → UpdateBatch
//!   spin on update_lock (poll_and_respond_cross_core while waiting)
//!   for each affected core: send IPI (sets ipi_pending[core])
//!   sync_barrier(0, n+1)          — wait for all affected cores to stop
//!   apply_update for each entry   — EPT/memory changes
//!   sync_barrier(1, n+1)          — release cores to flush local state
//!   release update_lock
//!   release op_lock
//!
//! responding core (via poll_and_respond_cross_core / P3b IDT handler):
//!   clear ipi_pending[self]
//!   sync_barrier(0, 0)    — signal "I have stopped"
//!   TODO(P3c): INVEPT     — flush stale TLB entries
//!   sync_barrier(1, 0)    — signal "local flush done"
//! ```

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::{Mutex, RwLock};

use capability_engine::{CoreId, DomainId, OpLockGuard, Platform, Result, Update};
use ept::{EptEntryFlags, EptMapper, EptMemoryType};

use crate::mem::{MetaAllocator, PhysRegion, UncacheableRanges};

// ── Constants ─────────────────────────────────────────────────────────────── //

/// Maximum number of physical cores supported.
pub const MAX_CORES: usize = 256;

/// x86 interrupt vector reserved for capability-engine cross-core IPIs.
/// Must match the IDT entry installed in Phase P3b.
pub const CAPA_IPI_VECTOR: u8 = 0xF2;

// ── Two-phase synchronisation barrier ─────────────────────────────────────── //

/// Reusable two-phase barrier for the cross-core IPI protocol.
///
/// The initiating core calls `wait(participants)` which stores the expected
/// count.  Responding cores call `wait(0)` to read the stored count and wait.
struct Barrier {
    /// Total participants expected; written by the initiating core (participants > 0)
    /// before it begins spinning.  Responding cores use the stored value (pass 0).
    expected:   AtomicUsize,
    /// How many cores have arrived so far in the current generation.
    arrived:    AtomicUsize,
    /// Incremented when all participants arrive, allowing barrier reuse.
    generation: AtomicUsize,
}

impl Barrier {
    const fn new() -> Self {
        Barrier {
            expected:   AtomicUsize::new(0),
            arrived:    AtomicUsize::new(0),
            generation: AtomicUsize::new(0),
        }
    }

    /// Arrive and wait until all expected participants have arrived.
    ///
    /// * `participants > 0` — store as new expected count (initiating core).
    /// * `participants == 0` — use the previously stored count (responding core).
    fn wait(&self, participants: usize) {
        if participants > 0 {
            self.expected.store(participants, Ordering::Release);
        }
        // Spin until the initiating core has stored a non-zero expected count.
        let expected = loop {
            let e = self.expected.load(Ordering::Acquire);
            if e > 0 { break e; }
            core::hint::spin_loop();
        };
        let gen = self.generation.load(Ordering::Acquire);
        let n   = self.arrived.fetch_add(1, Ordering::AcqRel) + 1;
        if n >= expected {
            // Last to arrive: reset for the next use, then advance generation.
            self.arrived.store(0, Ordering::Release);
            self.expected.store(0, Ordering::Release);
            self.generation.fetch_add(1, Ordering::Release);
        } else {
            while self.generation.load(Ordering::Acquire) == gen {
                core::hint::spin_loop();
            }
        }
    }
}

// ── RW-spinlock guards ─────────────────────────────────────────────────────── //
//
// `spin::RwLock` guards carry a lifetime tied to the lock reference.  Since
// `ThemisPlatform` is effectively `'static` (created in `_start` and never
// dropped), we transmute the guard lifetime to `'static` so the guards can be
// boxed as `Box<dyn OpLockGuard + Send>`.
//
// `ManuallyDrop` is used so we can implement `Drop` ourselves; the inner guard's
// destructor releases the spinlock when we manually drop it.

/// Guard for a shared (read) capability-tree lock.
struct SharedGuard(ManuallyDrop<spin::RwLockReadGuard<'static, ()>>);

impl SharedGuard {
    fn new(lock: &RwLock<()>) -> Self {
        // SAFETY: `lock` lives as long as `ThemisPlatform` which outlives
        // any guard it produces ('static in practice).
        let guard: spin::RwLockReadGuard<'static, ()> =
            unsafe { core::mem::transmute(lock.read()) };
        SharedGuard(ManuallyDrop::new(guard))
    }
}
impl Drop for SharedGuard {
    fn drop(&mut self) { unsafe { ManuallyDrop::drop(&mut self.0) }; }
}
impl OpLockGuard for SharedGuard {}
// SAFETY: tied to a 'static platform; moving a guard across logical "threads"
// (monitor entries) on the same physical core is intentional.
unsafe impl Send for SharedGuard {}

/// Guard for an exclusive (write) capability-tree lock.
struct ExclusiveGuard(ManuallyDrop<spin::RwLockWriteGuard<'static, ()>>);

impl ExclusiveGuard {
    fn new(lock: &RwLock<()>) -> Self {
        let guard: spin::RwLockWriteGuard<'static, ()> =
            unsafe { core::mem::transmute(lock.write()) };
        ExclusiveGuard(ManuallyDrop::new(guard))
    }
}
impl Drop for ExclusiveGuard {
    fn drop(&mut self) { unsafe { ManuallyDrop::drop(&mut self.0) }; }
}
impl OpLockGuard for ExclusiveGuard {}
unsafe impl Send for ExclusiveGuard {}

// ── Per-domain hardware state ─────────────────────────────────────────────── //

/// Hardware state owned by a single domain.
pub struct PlatformDomain {
    /// EPT root mapper, allocated lazily on first `ChangeRights` or `GiveMetaMem`.
    pub ept: Option<EptMapper>,
    /// META page allocator — populated via `GiveMetaMem` updates.
    pub meta: MetaAllocator,
    /// Parent domain ID, stored for vital-memory revocation fallback.
    pub parent: Option<DomainId>,
    /// HHDM offset, cached here so EPT root allocation can use it.
    hhdm_offset: u64,
    /// Per-VP hardware structures — placeholder until P2d.
    pub vps: Vec<()>,
}

impl PlatformDomain {
    fn new(hhdm_offset: u64, parent: Option<DomainId>) -> Self {
        PlatformDomain {
            ept: None,
            meta: MetaAllocator::new(hhdm_offset),
            parent,
            hhdm_offset,
            vps: Vec::new(),
        }
    }

    /// Ensure an EPT root page exists, allocating from `self.meta` if needed.
    ///
    /// # Panics
    ///
    /// Panics if the META pool is empty (no `GiveMetaMem` update received yet).
    fn ensure_ept(&mut self) {
        if self.ept.is_none() {
            self.ept = Some(EptMapper::alloc_root(&mut self.meta, self.hhdm_offset));
        }
    }
}

// ── UC-aware EPT range mapping helper ─────────────────────────────────────── //

/// Map `[gpa, gpa+size)` → `[hpa, hpa+size)` into `ept`, splitting the range at
/// UC boundaries so that MMIO sub-ranges use [`EptMemoryType::UC`] and all other
/// sub-ranges use [`EptMemoryType::WB`].
///
/// The split is O(k log n) where k is the number of UC sub-ranges that intersect
/// the mapping and n is the total number of registered UC regions — typically a
/// handful of iterations for any real `ChangeRights` update.
fn map_range_typed(
    ept:       &mut EptMapper,
    meta:      &mut crate::mem::MetaAllocator,
    gpa:       u64,
    hpa:       u64,
    size:      usize,
    flags:     EptEntryFlags,
    uc_ranges: &UncacheableRanges,
) {
    let mut cur_gpa  = gpa;
    let mut cur_hpa  = hpa;
    let mut remaining = size;

    while remaining > 0 {
        match uc_ranges.first_overlap(cur_hpa, remaining as u64) {
            None => {
                // Remainder is entirely cacheable.
                ept.map_range(meta, cur_gpa, cur_hpa, remaining, flags, EptMemoryType::WB);
                return;
            }
            Some((ov_start, ov_end)) => {
                // Map any WB prefix before the UC overlap.
                if ov_start > cur_hpa {
                    let wb_size = (ov_start - cur_hpa) as usize;
                    ept.map_range(meta, cur_gpa, cur_hpa, wb_size, flags, EptMemoryType::WB);
                    cur_gpa   += wb_size as u64;
                    cur_hpa   += wb_size as u64;
                    remaining -= wb_size;
                }
                // Map the UC segment.
                let uc_size = ((ov_end - cur_hpa) as usize).min(remaining);
                ept.map_range(meta, cur_gpa, cur_hpa, uc_size, flags, EptMemoryType::UC);
                cur_gpa   += uc_size as u64;
                cur_hpa   += uc_size as u64;
                remaining -= uc_size;
            }
        }
    }
}

// ── ThemisPlatformInner (everything behind the single Mutex) ─────────────── //

struct ThemisPlatformInner {
    domains:        BTreeMap<DomainId, PlatformDomain>,
    core_to_domain: BTreeMap<CoreId, DomainId>,
    domain_to_core: BTreeMap<DomainId, CoreId>,
    /// LAPIC IDs indexed by CoreId — populated by `bootstrap_set_lapic_ids`.
    lapic_ids:      Vec<u32>,
    /// Cached HHDM offset from the first registered domain.
    hhdm_offset:    u64,
    /// MMIO physical ranges that must be mapped UC in the EPT.
    /// Read-only after boot; shared via Arc with PlatformInfo.
    uc_ranges:      alloc::sync::Arc<UncacheableRanges>,
}

impl ThemisPlatformInner {
    fn new(uc_ranges: alloc::sync::Arc<UncacheableRanges>) -> Self {
        ThemisPlatformInner {
            domains:        BTreeMap::new(),
            core_to_domain: BTreeMap::new(),
            domain_to_core: BTreeMap::new(),
            lapic_ids:      Vec::new(),
            hhdm_offset:    0,
            uc_ranges,
        }
    }
}

// ── ThemisPlatform ────────────────────────────────────────────────────────── //

/// The Themis `Platform` implementation.
///
/// Fields outside `inner` are accessed on hot paths (IPI, barrier, lock) and
/// must not require holding `inner` to prevent lock inversion.
pub struct ThemisPlatform {
    /// Capability-tree operation lock: shared for carve/alias/send, exclusive
    /// for revoke.  Held for the entire duration of the capability operation.
    op_lock:     RwLock<()>,
    /// Update-application serialisation lock.  Only one core at a time may run
    /// the IPI / barrier / `apply_update` sequence.
    update_lock: AtomicBool,
    /// Two-phase synchronisation barriers (index 0 = pre-update, 1 = post-update).
    barriers:    [Barrier; 2],
    /// Per-core IPI-pending flags.  The IPI handler (P3b) sets the flag for the
    /// interrupted core; `poll_and_respond_cross_core` clears it and participates
    /// in the barrier protocol.
    pub ipi_pending: [AtomicBool; MAX_CORES],
    /// All mutable domain / EPT / core-tracking state.
    inner:       Mutex<ThemisPlatformInner>,
}

impl ThemisPlatform {
    /// Create a new platform with no domains registered.
    ///
    /// `uc_ranges` is the table of MMIO physical ranges (built from the Limine
    /// memory map during `boot::platform()`) that must be mapped UC in the EPT.
    pub fn new(uc_ranges: alloc::sync::Arc<UncacheableRanges>) -> Self {
        ThemisPlatform {
            op_lock:     RwLock::new(()),
            update_lock: AtomicBool::new(false),
            barriers:    [Barrier::new(), Barrier::new()],
            ipi_pending: unsafe { core::mem::zeroed() },
            inner:       Mutex::new(ThemisPlatformInner::new(uc_ranges)),
        }
    }

    /// Register the LAPIC IDs for all physical cores.
    ///
    /// `ids[core_id]` is the x2APIC LAPIC ID for that core.  Must be called
    /// during bootstrap (before any AP is released) so that `send_ipi` and
    /// `get_current_core` work correctly.
    pub fn bootstrap_set_lapic_ids(&self, ids: Vec<u32>) {
        self.inner.lock().lapic_ids = ids;
    }

    /// Give a domain its initial META region directly, bypassing the update
    /// protocol.  Used during dom0 bootstrap before `execute()` is called.
    pub fn bootstrap_give_meta(&self, domain_id: DomainId, region: PhysRegion) {
        let mut g = self.inner.lock();
        if let Some(d) = g.domains.get_mut(&domain_id) {
            d.meta.add_range(region);
        } else {
            panic!("bootstrap_give_meta: domain {} not registered", domain_id);
        }
    }

    /// Register a domain directly (bypasses the update protocol).
    /// Use during bootstrap before `execute()` is called.
    pub fn bootstrap_register_domain(
        &self,
        domain_id: DomainId,
        parent_id: Option<DomainId>,
        hhdm_offset: u64,
    ) {
        let mut g = self.inner.lock();
        g.hhdm_offset = hhdm_offset;
        g.domains
            .insert(domain_id, PlatformDomain::new(hhdm_offset, parent_id));
    }

    /// Return the EPTP value for `domain_id`, or `None` if no EPT root exists yet.
    pub fn eptp(&self, domain_id: DomainId) -> Option<u64> {
        let g = self.inner.lock();
        g.domains.get(&domain_id)?.ept.as_ref().map(|e| e.eptp())
    }

    /// Allocate one META page (4 KiB, zeroed) from `domain_id`'s pool.
    ///
    /// Used by `domain::Domain` allocation helpers for VMXON, VMCS, VAPIC pages.
    /// Panics if the domain is not registered or its pool is exhausted.
    pub fn alloc_meta_frame(&self, domain_id: DomainId) -> u64 {
        let mut g = self.inner.lock();
        let d = g
            .domains
            .get_mut(&domain_id)
            .expect("alloc_meta_frame: domain not registered");
        d.meta.alloc_frame()
    }
}

// ── Platform trait ────────────────────────────────────────────────────────── //

impl Platform for ThemisPlatform {
    // ── Capability-tree operation lock ─────────────────────────────────── //

    fn acquire_shared_lock(&self) -> Result<Box<dyn OpLockGuard>> {
        Ok(Box::new(SharedGuard::new(&self.op_lock)))
    }

    fn acquire_exclusive_lock(&self) -> Result<Box<dyn OpLockGuard>> {
        Ok(Box::new(ExclusiveGuard::new(&self.op_lock)))
    }

    // ── Cross-core synchronisation ────────────────────────────────────── //

    /// Send a capability-engine sync IPI to `core_id` via x2APIC.
    ///
    /// Looks up the target LAPIC ID in the bootstrap-populated table and writes
    /// the ICR MSR.  The receiving core's IPI handler (P3b) sets
    /// `ipi_pending[core_id]` so `poll_and_respond_cross_core` can react.
    fn send_ipi(&self, core_id: CoreId) {
        let lapic_id = {
            let g = self.inner.lock();
            *g.lapic_ids
                .get(core_id as usize)
                .unwrap_or_else(|| panic!("send_ipi: unknown core {}", core_id))
        };
        // x2APIC ICR (MSR 0x830): bits[63:32]=dest, bit[14]=level(assert),
        // bits[10:8]=delivery(000=fixed), bits[7:0]=vector.
        let icr: u64 = ((lapic_id as u64) << 32)
            | (1u64 << 14)              // level = assert
            | (CAPA_IPI_VECTOR as u64); // fixed delivery, no shorthand
        unsafe { x86::msr::wrmsr(x86::msr::IA32_X2APIC_ICR, icr) };
    }

    /// Two-phase synchronisation barrier.
    ///
    /// All participants (initiating core + IPI-responding cores) call this with
    /// the same `id`.  The initiating core passes `participants` > 0; responding
    /// cores pass 0 (the stored value is used instead).
    fn sync_barrier(&self, id: u8, participants: usize) {
        self.barriers[id as usize].wait(participants);
    }

    // ── Update-application serialisation lock ─────────────────────────── //

    fn try_acquire_update_lock(&self) -> bool {
        self.update_lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    fn release_update_lock(&self) {
        self.update_lock.store(false, Ordering::Release);
    }

    /// Poll for a pending cross-core IPI and participate in the barrier if one
    /// is waiting.
    ///
    /// Called while spinning on `try_acquire_update_lock`.  If another core has
    /// sent us a capability-engine IPI (set `ipi_pending[our_core]`), we
    /// participate in its barrier so it can proceed.
    ///
    /// TODO(P3b): The IPI handler (IDT vector CAPA_IPI_VECTOR) must set
    /// `ipi_pending[current_core]`.  Until P3b, IPIs may be missed if delivered
    /// while the core is executing in the monitor with interrupts disabled.
    fn poll_and_respond_cross_core(&self) {
        let Some(core_id) = self.get_current_core() else { return };
        if core_id as usize >= MAX_CORES { return; }
        if self.ipi_pending[core_id as usize]
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        // An initiating core sent us an IPI waiting at barrier 0.
        // Signal "I have stopped" so it can proceed with hardware updates.
        self.barriers[0].wait(0);
        // TODO(P3c): INVEPT(single-context) here for TLB shootdown.
        // Signal "local flush done" so the initiating core can release op_lock.
        self.barriers[1].wait(0);
    }

    // ── Hardware state (apply_update) ─────────────────────────────────── //

    fn apply_update(&self, update: &Update) {
        match update {
            Update::CreateDomain { domain_id, parent_id } => {
                self.register_domain(*domain_id, *parent_id);
            }

            Update::GiveMetaMem { domain_id, start, size } => {
                let mut g = self.inner.lock();
                let d = g
                    .domains
                    .get_mut(domain_id)
                    .expect("GiveMetaMem: unknown domain");
                d.meta.add_range(PhysRegion { base: *start, length: *size });
                // TODO(P4): update IOMMU domain page table for this META region.
            }

            Update::ChangeRights { domain, address, size, physical, rights, .. } => {
                let mut g = self.inner.lock();
                // Clone the Arc before the mutable domain borrow to avoid
                // simultaneous mutable + immutable borrow of `g`.
                let uc_ranges = alloc::sync::Arc::clone(&g.uc_ranges);
                let d = g
                    .domains
                    .get_mut(domain)
                    .expect("ChangeRights: unknown domain");

                if rights.bits() == 0 {
                    if let Some(ept) = d.ept.as_mut() {
                        ept.unmap_range(&mut d.meta, *address, *size as usize);
                    }
                    // TODO(P4): remove mapping from IOMMU domain page table.
                } else {
                    d.ensure_ept();
                    let flags = rights_to_ept_flags(rights);
                    let ept   = d.ept.as_mut().unwrap();
                    // Map the range, splitting at UC boundaries so that MMIO
                    // regions get EptMemoryType::UC and RAM regions get WB.
                    map_range_typed(
                        ept, &mut d.meta,
                        *address, *physical, *size as usize,
                        flags, &uc_ranges,
                    );
                    // TODO(P4): update IOMMU domain page table with same mapping.
                }
            }

            Update::RevokeDomain { domain, .. } => {
                // Free EPT structures while affected cores are paused (between
                // the two barriers).  `on_domain_revoked` handles core redirect.
                let mut g = self.inner.lock();
                if let Some(mut d) = g.domains.remove(domain) {
                    if let Some(ept) = d.ept.take() {
                        ept.free_all(&mut d.meta);
                    }
                    // TODO(P4): free IOMMU domain page table.
                    // META pages themselves belong to the parent's allocator and
                    // are returned when the memory capability is revoked.
                }
            }

            Update::ZeroMemory { address, size } => {
                let g = self.inner.lock();
                let hhdm = g.hhdm_offset;
                drop(g);
                let virt = (address + hhdm) as *mut u8;
                unsafe { core::ptr::write_bytes(virt, 0, *size as usize) };
            }

            Update::FlushTLB { .. } => {
                // TODO(P3c): INVEPT(single-context) for the affected domain.
                // For now, cores do a full INVEPT on VMRESUME via the barrier
                // protocol once P3b/P3c are implemented.
            }
        }
    }

    // ── Domain lifecycle ─────────────────────────────────────────────── //

    fn register_domain(&self, domain_id: DomainId, parent_id: Option<DomainId>) {
        let mut g = self.inner.lock();
        if g.domains.contains_key(&domain_id) {
            return; // Idempotent: bootstrap_register_domain already called.
        }
        let hhdm = g.hhdm_offset;
        g.domains.insert(domain_id, PlatformDomain::new(hhdm, parent_id));
        // TODO(P4): allocate IOMMU domain page table for domain_id.
    }

    fn on_domain_revoked(&self, domain_id: DomainId, fallback: Option<DomainId>) {
        // EPT structures were freed in apply_update(RevokeDomain).
        // Redirect any core running this domain to the fallback.
        let mut g = self.inner.lock();
        if let Some(&core_id) = g.domain_to_core.get(&domain_id) {
            g.domain_to_core.remove(&domain_id);
            g.core_to_domain.remove(&core_id);
            if let Some(fb) = fallback {
                g.core_to_domain.insert(core_id, fb);
                g.domain_to_core.insert(fb, core_id);
            }
            // TODO(P4): reassign devices belonging to domain_id to fallback/parent.
        }
        // TODO(multi-VP): a domain can run on multiple cores; this only handles
        // the single-VP (one core per domain) case.
    }

    // ── Core tracking ─────────────────────────────────────────────────── //

    fn set_core_domain(&self, core_id: CoreId, domain_id: DomainId) {
        let mut g = self.inner.lock();
        if let Some(old_domain) = g.core_to_domain.remove(&core_id) {
            g.domain_to_core.remove(&old_domain);
        }
        g.core_to_domain.insert(core_id, domain_id);
        g.domain_to_core.insert(domain_id, core_id);
    }

    fn clear_core_domain(&self, core_id: CoreId) {
        let mut g = self.inner.lock();
        if let Some(domain_id) = g.core_to_domain.remove(&core_id) {
            g.domain_to_core.remove(&domain_id);
        }
    }

    fn domain_core(&self, domain_id: DomainId) -> Option<CoreId> {
        self.inner.lock().domain_to_core.get(&domain_id).copied()
    }

    /// Return the CoreId of the calling physical core by reading the x2APIC ID
    /// and looking it up in the bootstrap-populated LAPIC ID table.
    fn get_current_core(&self) -> Option<CoreId> {
        let lapic_id = unsafe { x86::msr::rdmsr(x86::msr::IA32_X2APIC_APICID) as u32 };
        let g = self.inner.lock();
        g.lapic_ids
            .iter()
            .position(|&id| id == lapic_id)
            .map(|i| i as CoreId)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────── //

/// Convert capability-engine `Rights` to EPT entry permission flags.
///
/// Execute permission is split into `SUPERVISOR_EXECUTE | USER_EXECUTE` so
/// that guest ring-3 code can execute — Intel SDM Vol 3C §29.3.2.
fn rights_to_ept_flags(rights: &capability_engine::Rights) -> EptEntryFlags {
    let mut flags = EptEntryFlags::empty();
    if rights.read() {
        flags |= EptEntryFlags::READ;
    }
    if rights.write() {
        flags |= EptEntryFlags::WRITE;
    }
    if rights.execute() {
        flags |= EptEntryFlags::SUPERVISOR_EXECUTE | EptEntryFlags::USER_EXECUTE;
    }
    flags
}
