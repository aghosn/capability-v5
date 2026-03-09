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
//!
//! ## Update barrier and locking invariants
//!
//! 1. **No deadlock between apply_update and barrier**: `apply_update` acquires
//!    per-domain `Mutex<PlatformDomain>` AFTER barrier 0 (all affected cores have
//!    stopped).  Responding cores (in `poll_and_respond_cross_core`) do NOT hold
//!    domain locks when they call `sync_barrier(0, 0)`.  Therefore there is no
//!    deadlock.
//!
//! 2. **Domain lock ordering**: `apply_update` must NOT acquire two domain locks
//!    simultaneously (no such case today).  When this becomes necessary, locks must
//!    be acquired in ascending DomainId order to prevent deadlock.
//!
//! 3. **Tier 1/3 consistency**: `set_core_domain` writes both
//!    `cores[core_id].current_domain` (Tier 1, Release) and `routing.write()`
//!    (Tier 3).  Readers of domain-for-core should prefer Tier 1 (lock-free) for
//!    hot-path decisions (e.g., INVEPT targeting).  Tier 3 is authoritative for
//!    reverse lookup (domain → core, needed for IPI targeting on domain switch).
//!
//! 4. **INVEPT scope optimization**: After barrier 0, before INVEPT (currently
//!    TODO(P3c)), the initiating core can check
//!    `cores[c].current_domain.load(Relaxed) == affected_domain` for each c to
//!    send INVEPT only to affected cores, avoiding unnecessary shootdowns.  This
//!    is safe because Tier 1 cells are written only by their owning core (under
//!    the barrier protocol, all affected cores are stopped).
//!
//! 5. **Domain switch race with UpdateBatch**: A core performing a domain switch
//!    must complete (Tier 1 + Tier 3 update + VMPTRLD of new VMCS) BEFORE
//!    handling any VMEXIT that could trigger a new UpdateBatch for the new domain.
//!    This is guaranteed because the switch is atomic from the perspective of the
//!    barrier: the core is either "stopped at barrier" or "running in a domain".
//!    A core cannot be simultaneously doing a switch and responding to a barrier.

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering};
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

const IDLE_DOMAIN: u64 = u64::MAX;
const IDLE_VP:     u32 = u32::MAX;

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

// ── Per-VP slot (atomic take/return for exclusive access) ──────────────────── //

use crate::vcpu::InactiveVcpu;

/// A slot holding an `InactiveVcpu` that can be atomically taken by one core
/// at a time.  When a core wants to run a VP, it `take()`s the InactiveVcpu
/// (leaving the slot empty), activates it, and runs.  When done, it
/// deactivates and `return()`s the InactiveVcpu back to the slot.
///
/// An empty slot (null pointer) means the VP is currently active on some core.
pub struct VcpuSlot {
    ptr: AtomicPtr<InactiveVcpu>,
}

impl VcpuSlot {
    /// Create an empty slot (no VP stored).
    pub const fn empty() -> Self {
        VcpuSlot {
            ptr: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// Create a slot holding an InactiveVcpu.
    #[allow(dead_code)]
    pub fn with_vcpu(vcpu: InactiveVcpu) -> Self {
        VcpuSlot {
            ptr: AtomicPtr::new(Box::into_raw(Box::new(vcpu))),
        }
    }

    /// Atomically take the InactiveVcpu from this slot.
    /// Returns `Some(InactiveVcpu)` if the VP was available, `None` if already
    /// taken by another core.
    pub fn take(&self) -> Option<InactiveVcpu> {
        let ptr = self.ptr.swap(core::ptr::null_mut(), Ordering::Acquire);
        if ptr.is_null() {
            None
        } else {
            Some(*unsafe { Box::from_raw(ptr) })
        }
    }

    /// Return an InactiveVcpu to this slot after deactivation.
    ///
    /// # Panics
    /// Panics if the slot is not empty (double-return bug).
    pub fn put(&self, vcpu: InactiveVcpu) {
        let old = self.ptr.swap(Box::into_raw(Box::new(vcpu)), Ordering::Release);
        assert!(old.is_null(), "VcpuSlot::put: slot was not empty (double-return bug)");
    }

    /// Check if the VP is currently available (not taken by any core).
    #[allow(dead_code)]
    pub fn is_available(&self) -> bool {
        !self.ptr.load(Ordering::Relaxed).is_null()
    }
}

// ── Per-core cell (Tier 1) ────────────────────────────────────────────────── //

pub struct PerCoreCell {
    pub current_domain: AtomicU64,
    #[allow(dead_code)]
    pub current_vp:     AtomicU32,
}

impl PerCoreCell {
    const fn new() -> Self {
        PerCoreCell {
            current_domain: AtomicU64::new(IDLE_DOMAIN),
            current_vp:     AtomicU32::new(IDLE_VP),
        }
    }
}

// ── Per-domain hardware state ─────────────────────────────────────────────── //

/// Hardware state owned by a single domain.
pub struct PlatformDomain {
    /// EPT root mapper, allocated lazily on first `ChangeRights` or `GiveMetaMem`.
    pub ept: Option<EptMapper>,
    /// META page allocator — populated via `GiveMetaMem` updates.
    pub meta: MetaAllocator,
    /// Parent domain ID, stored for vital-memory revocation fallback.
    #[allow(dead_code)]
    pub parent: Option<DomainId>,
    /// HHDM offset, cached here so EPT root allocation can use it.
    hhdm_offset: u64,
    /// Per-VP slots.  Index = domain-local VP ID (0, 1, 2, ...).
    /// Each slot holds an InactiveVcpu when the VP is not running.
    pub vps: Vec<VcpuSlot>,
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
                ept.map_range(meta, cur_gpa, cur_hpa, remaining, flags, EptMemoryType::WB);
                return;
            }
            Some((ov_start, ov_end)) => {
                if ov_start > cur_hpa {
                    let wb_size = (ov_start - cur_hpa) as usize;
                    ept.map_range(meta, cur_gpa, cur_hpa, wb_size, flags, EptMemoryType::WB);
                    cur_gpa   += wb_size as u64;
                    cur_hpa   += wb_size as u64;
                    remaining -= wb_size;
                }
                let uc_size = ((ov_end - cur_hpa) as usize).min(remaining);
                ept.map_range(meta, cur_gpa, cur_hpa, uc_size, flags, EptMemoryType::UC);
                cur_gpa   += uc_size as u64;
                cur_hpa   += uc_size as u64;
                remaining -= uc_size;
            }
        }
    }
}

// ── Domain table (Tier 2) ─────────────────────────────────────────────────── //

struct DomainTable {
    map: RwLock<BTreeMap<DomainId, alloc::sync::Arc<Mutex<PlatformDomain>>>>,
}

impl DomainTable {
    fn new() -> Self { DomainTable { map: RwLock::new(BTreeMap::new()) } }

    fn get(&self, id: DomainId) -> Option<alloc::sync::Arc<Mutex<PlatformDomain>>> {
        self.map.read().get(&id).cloned()
    }

    fn insert(&self, id: DomainId, domain: PlatformDomain) {
        self.map.write().insert(id, alloc::sync::Arc::new(Mutex::new(domain)));
    }

    fn remove(&self, id: DomainId) -> Option<PlatformDomain> {
        self.map.write().remove(&id)
            .and_then(|arc| alloc::sync::Arc::try_unwrap(arc).ok())
            .map(|m| m.into_inner())
    }

    fn contains(&self, id: DomainId) -> bool {
        self.map.read().contains_key(&id)
    }
}

// ── Routing maps (Tier 3) ─────────────────────────────────────────────────── //

struct RoutingMaps {
    core_to_domain: BTreeMap<CoreId, DomainId>,
    domain_to_core: BTreeMap<DomainId, CoreId>,
}

impl RoutingMaps {
    fn new() -> Self {
        RoutingMaps {
            core_to_domain: BTreeMap::new(),
            domain_to_core: BTreeMap::new(),
        }
    }
}

// ── ThemisPlatform ────────────────────────────────────────────────────────── //

/// The Themis `Platform` implementation.
pub struct ThemisPlatform {
    // Hot path: no lock needed
    op_lock:         RwLock<()>,
    update_lock:     AtomicBool,
    barriers:        [Barrier; 2],
    pub ipi_pending: [AtomicBool; MAX_CORES],
    // Immutable after bootstrap
    hhdm_offset:     AtomicU64,
    uc_ranges:       alloc::sync::Arc<UncacheableRanges>,
    // Tier 1: per-core current state
    cores:           [PerCoreCell; MAX_CORES],
    // Tier 2: per-domain hardware state
    domains:         DomainTable,
    // Tier 3: global routing
    routing:         RwLock<RoutingMaps>,
    // LAPIC IDs: immutable after bootstrap
    lapic_ids:       RwLock<Vec<u32>>,
}

impl ThemisPlatform {
    /// Create a new platform with no domains registered.
    pub fn new(uc_ranges: alloc::sync::Arc<UncacheableRanges>) -> Self {
        const C: PerCoreCell = PerCoreCell::new();
        ThemisPlatform {
            op_lock:     RwLock::new(()),
            update_lock: AtomicBool::new(false),
            barriers:    [Barrier::new(), Barrier::new()],
            ipi_pending: unsafe { core::mem::zeroed() },
            hhdm_offset: AtomicU64::new(0),
            uc_ranges,
            cores:       [C; MAX_CORES],
            domains:     DomainTable::new(),
            routing:     RwLock::new(RoutingMaps::new()),
            lapic_ids:   RwLock::new(Vec::new()),
        }
    }

    pub fn bootstrap_set_lapic_ids(&self, ids: Vec<u32>) {
        *self.lapic_ids.write() = ids;
    }

    pub fn bootstrap_give_meta(&self, domain_id: DomainId, region: PhysRegion) {
        self.domains
            .get(domain_id)
            .unwrap_or_else(|| panic!("bootstrap_give_meta: domain {} not registered", domain_id))
            .lock()
            .meta
            .add_range(region);
    }

    pub fn bootstrap_register_domain(
        &self,
        domain_id: DomainId,
        parent_id: Option<DomainId>,
        hhdm_offset: u64,
    ) {
        self.hhdm_offset.store(hhdm_offset, Ordering::Relaxed);
        if !self.domains.contains(domain_id) {
            self.domains.insert(domain_id, PlatformDomain::new(hhdm_offset, parent_id));
        }
    }

    pub fn eptp(&self, domain_id: DomainId) -> Option<u64> {
        self.domains.get(domain_id)?.lock().ept.as_ref().map(|e| e.eptp())
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
    /// `vp_id` is the domain-local VP index (0, 1, 2, ...).
    /// Extends the VP vector if needed.
    pub fn bootstrap_store_vcpu(&self, domain_id: DomainId, vp_id: usize, vcpu: InactiveVcpu) {
        let arc = self.domains
            .get(domain_id)
            .unwrap_or_else(|| panic!("bootstrap_store_vcpu: domain not registered"));
        let mut d = arc.lock();
        if d.vps.len() <= vp_id {
            d.vps.resize_with(vp_id + 1, VcpuSlot::empty);
        }
        d.vps[vp_id].put(vcpu);
    }

    /// Atomically take an InactiveVcpu from a domain's VP slot.
    ///
    /// Returns `None` if the VP is already active on another core.
    pub fn take_vcpu(&self, domain_id: DomainId, vp_id: usize) -> Option<InactiveVcpu> {
        let arc = self.domains.get(domain_id)?;
        let d = arc.lock();
        d.vps.get(vp_id).and_then(|slot| slot.take())
    }

    /// Return an InactiveVcpu to a domain's VP slot after deactivation.
    #[allow(dead_code)]
    pub fn return_vcpu(&self, domain_id: DomainId, vp_id: usize, vcpu: InactiveVcpu) {
        let arc = self.domains
            .get(domain_id)
            .unwrap_or_else(|| panic!("return_vcpu: domain not registered"));
        let d = arc.lock();
        assert!(vp_id < d.vps.len(), "return_vcpu: vp_id out of range");
        d.vps[vp_id].put(vcpu);
    }
}

// ── Platform trait ────────────────────────────────────────────────────────── //

impl Platform for ThemisPlatform {
    fn acquire_shared_lock(&self) -> Result<Box<dyn OpLockGuard>> {
        Ok(Box::new(SharedGuard::new(&self.op_lock)))
    }

    fn acquire_exclusive_lock(&self) -> Result<Box<dyn OpLockGuard>> {
        Ok(Box::new(ExclusiveGuard::new(&self.op_lock)))
    }

    fn send_ipi(&self, core_id: CoreId) {
        let lapic_id = *self.lapic_ids
            .read()
            .get(core_id as usize)
            .unwrap_or_else(|| panic!("send_ipi: unknown core {}", core_id));
        let icr: u64 = ((lapic_id as u64) << 32)
            | (1u64 << 14)
            | (CAPA_IPI_VECTOR as u64);
        unsafe { x86::msr::wrmsr(x86::msr::IA32_X2APIC_ICR, icr) };
    }

    fn sync_barrier(&self, id: u8, participants: usize) {
        self.barriers[id as usize].wait(participants);
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
        let Some(core_id) = self.get_current_core() else { return };
        if core_id as usize >= MAX_CORES { return; }
        if self.ipi_pending[core_id as usize]
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        self.barriers[0].wait(0);
        // TODO(P3c): INVEPT(single-context) here for TLB shootdown.
        self.barriers[1].wait(0);
    }

    fn apply_update(&self, update: &Update) {
        match update {
            Update::CreateDomain { domain_id, parent_id } => {
                self.register_domain(*domain_id, *parent_id);
            }

            Update::GiveMetaMem { domain_id, start, size } => {
                self.domains
                    .get(*domain_id)
                    .expect("GiveMetaMem: unknown domain")
                    .lock()
                    .meta
                    .add_range(PhysRegion { base: *start, length: *size });
                // TODO(P4): update IOMMU domain page table for this META region.
            }

            Update::ChangeRights { domain, address, size, physical, rights, .. } => {
                let uc_ranges = alloc::sync::Arc::clone(&self.uc_ranges);
                let arc = self.domains
                    .get(*domain)
                    .expect("ChangeRights: unknown domain");
                let mut d = arc.lock();
                // Split the MutexGuard borrow into disjoint field pointers so the
                // borrow checker accepts simultaneous &mut ept and &mut meta.
                let meta_ptr: *mut MetaAllocator = &mut d.meta;

                if rights.bits() == 0 {
                    if let Some(ept) = d.ept.as_mut() {
                        // SAFETY: `ept` and `meta` are disjoint fields of PlatformDomain.
                        ept.unmap_range(unsafe { &mut *meta_ptr }, *address, *size as usize);
                    }
                    // TODO(P4): remove mapping from IOMMU domain page table.
                } else {
                    d.ensure_ept();
                    let flags = rights_to_ept_flags(rights);
                    let ept   = d.ept.as_mut().unwrap();
                    map_range_typed(
                        // SAFETY: `ept` and `meta` are disjoint fields of PlatformDomain.
                        ept, unsafe { &mut *meta_ptr },
                        *address, *physical, *size as usize,
                        flags, &uc_ranges,
                    );
                    // TODO(P4): update IOMMU domain page table with same mapping.
                }
            }

            Update::RevokeDomain { domain, .. } => {
                if let Some(mut d) = self.domains.remove(*domain) {
                    if let Some(ept) = d.ept.take() {
                        ept.free_all(&mut d.meta);
                    }
                    // TODO(P4): free IOMMU domain page table.
                }
            }

            Update::ZeroMemory { address, size } => {
                let hhdm = self.hhdm_offset.load(Ordering::Relaxed);
                let virt = (address + hhdm) as *mut u8;
                unsafe { core::ptr::write_bytes(virt, 0, *size as usize) };
            }

            Update::FlushTLB { .. } => {
                // TODO(P3c): INVEPT(single-context) for the affected domain.
            }
        }
    }

    fn register_domain(&self, domain_id: DomainId, parent_id: Option<DomainId>) {
        if !self.domains.contains(domain_id) {
            let hhdm = self.hhdm_offset.load(Ordering::Relaxed);
            self.domains.insert(domain_id, PlatformDomain::new(hhdm, parent_id));
        }
    }

    fn on_domain_revoked(&self, domain_id: DomainId, fallback: Option<DomainId>) {
        let mut routing = self.routing.write();
        if let Some(core_id) = routing.domain_to_core.remove(&domain_id) {
            routing.core_to_domain.remove(&core_id);
            self.cores[core_id as usize].current_domain.store(
                fallback.unwrap_or(IDLE_DOMAIN),
                Ordering::Release,
            );
            if let Some(fb) = fallback {
                routing.core_to_domain.insert(core_id, fb);
                routing.domain_to_core.insert(fb, core_id);
            }
        }
    }

    fn set_core_domain(&self, core_id: CoreId, domain_id: DomainId) {
        self.cores[core_id as usize].current_domain.store(domain_id, Ordering::Release);
        let mut routing = self.routing.write();
        if let Some(old_domain) = routing.core_to_domain.remove(&core_id) {
            routing.domain_to_core.remove(&old_domain);
        }
        routing.core_to_domain.insert(core_id, domain_id);
        routing.domain_to_core.insert(domain_id, core_id);
    }

    fn clear_core_domain(&self, core_id: CoreId) {
        self.cores[core_id as usize].current_domain.store(IDLE_DOMAIN, Ordering::Release);
        let mut routing = self.routing.write();
        if let Some(domain_id) = routing.core_to_domain.remove(&core_id) {
            routing.domain_to_core.remove(&domain_id);
        }
    }

    fn domain_core(&self, domain_id: DomainId) -> Option<CoreId> {
        self.routing.read().domain_to_core.get(&domain_id).copied()
    }

    fn get_current_core(&self) -> Option<CoreId> {
        let lapic_id = unsafe { x86::msr::rdmsr(x86::msr::IA32_X2APIC_APICID) as u32 };
        self.lapic_ids
            .read()
            .iter()
            .position(|&id| id == lapic_id)
            .map(|i| i as CoreId)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────── //

/// Convert capability-engine `Rights` to EPT entry permission flags.
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
