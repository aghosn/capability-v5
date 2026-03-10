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
//!   INVEPT(single-context) — flush stale EPT TLB entries for current domain
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
//! 3. **Tier 1/3 consistency**: `set_core_context` writes both
//!    `cores[core_id].domain_id` (Tier 1, Release) and `routing.write()`
//!    (Tier 3).  Readers of domain-for-core should prefer Tier 1 (lock-free) for
//!    hot-path decisions (e.g., INVEPT targeting).  Tier 3 is authoritative for
//!    reverse lookup (domain → core, needed for IPI targeting on domain switch).
//!
//! 4. **INVEPT scope optimization**: After barrier 0, before INVEPT (currently
//!    TODO(P3c)), the initiating core can check
//!    `cores[c].domain_id.load(Relaxed) == affected_domain` for each c to
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
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use spin::{Mutex, RwLock};

use capability_engine::{
    CapabilityRef, CoreId, Domain, DomainId, OpLockGuard, Platform, Result, Update,
};
use ept::{EptEntryFlags, EptMapper, EptMemoryType};

use crate::mem::{MetaAllocator, PhysRegion, UncacheableRanges};

// ── Constants ─────────────────────────────────────────────────────────────── //

/// Maximum number of physical cores supported.
/// Used only for compile-time statics (GDT/TSS) that cannot be
/// heap-allocated.  ThemisPlatform sizes its per-core arrays dynamically.
pub const MAX_CORES: usize = 256;

const IDLE_DOMAIN: u64 = u64::MAX;
const IDLE_VP:     u32 = u32::MAX;

// ── Per-core update command ───────────────────────────────────────────────── //

/// Command pushed by the initiating core into a target core's update queue,
/// consumed by that core between barriers 0 and 1 in `poll_and_respond_cross_core`.
///
/// `TlbShootdown` is the only variant used today.  `Switch` and `Revoke` are
/// stubs for Phase 9 (domain switching / revocation).
#[derive(Clone)]
pub enum CoreUpdate {
    /// Flush EPT TLB (INVEPT single-context) for the domain on this core.
    TlbShootdown,
    /// Switch this core to a different domain/VP (Phase 9).
    Switch {
        domain_cap: CapabilityRef<Domain>,
        vp_id: u32,
    },
    /// Domain was revoked; switch to fallback (Phase 9).
    Revoke {
        revoked: DomainId,
        fallback_cap: CapabilityRef<Domain>,
        fallback_vp: u32,
    },
}

impl core::fmt::Debug for CoreUpdate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CoreUpdate::TlbShootdown => write!(f, "TlbShootdown"),
            CoreUpdate::Switch { vp_id, .. } => {
                write!(f, "Switch {{ vp_id: {} }}", vp_id)
            }
            CoreUpdate::Revoke { revoked, fallback_vp, .. } => {
                write!(f, "Revoke {{ revoked: {:?}, fallback_vp: {} }}", revoked, fallback_vp)
            }
        }
    }
}

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

// ── Per-core scheduling state (Tier 1) ────────────────────────────────────── //

/// Per-core scheduling state: identifies what domain and VP are currently
/// executing on this physical core.
///
/// **Invariants**:
/// - A core only writes to its own `CoreContext`.
/// - Cross-core reads happen under the `execute()` barrier protocol
///   (IPI + sync_barrier), so the `domain_cap` Mutex is never truly contended.
/// - `domain_id` is a cached copy of the domain ID for fast lock-free
///   observational reads (e.g., `domain_core()` routing lookups).
pub struct CoreContext {
    /// Cached domain ID — lock-free observational reads by other cores.
    pub domain_id: AtomicU64,
    /// Current VP index within the domain (dom0: VP i = core i, fixed).
    pub vp_id: AtomicU32,
    /// Capability reference to the currently-scheduled domain.
    /// The VMCALL handler's entry point into the capability tree.
    /// `None` only during early boot before dom0 is initialised.
    pub domain_cap: Mutex<Option<CapabilityRef<Domain>>>,
}

impl CoreContext {
    const fn new() -> Self {
        CoreContext {
            domain_id: AtomicU64::new(IDLE_DOMAIN),
            vp_id: AtomicU32::new(IDLE_VP),
            domain_cap: Mutex::new(None),
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
    pub ipi_pending: Box<[AtomicBool]>,
    // Per-core update queue: written by initiating core (under update_lock),
    // drained by the local core in poll_and_respond_cross_core.
    core_updates:    Box<[Mutex<VecDeque<CoreUpdate>>]>,
    // Immutable after bootstrap
    num_cores:       usize,
    hhdm_offset:     AtomicU64,
    uc_ranges:       alloc::sync::Arc<UncacheableRanges>,
    // Tier 1: per-core scheduling state
    cores:           Box<[CoreContext]>,
    // Tier 2: per-domain hardware state
    domains:         DomainTable,
    // Tier 3: global routing
    routing:         RwLock<RoutingMaps>,
    // LAPIC IDs: immutable after bootstrap
    lapic_ids:       RwLock<Vec<u32>>,
    // Tree root anchor — keeps dom0's capability tree alive.
    dom0_cap:        Mutex<Option<CapabilityRef<Domain>>>,
    // Per-core VMXON physical addresses; written once by BSP, read by each AP.
    vmxon_phys:      Vec<u64>,
}

impl ThemisPlatform {
    /// Create a new platform with no domains registered.
    ///
    /// `num_cores` is the physical core count discovered at boot (from Limine MP).
    pub fn new(uc_ranges: alloc::sync::Arc<UncacheableRanges>, num_cores: usize) -> Self {
        let ipi_pending: Box<[AtomicBool]> = (0..num_cores)
            .map(|_| AtomicBool::new(false))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let core_updates: Box<[Mutex<VecDeque<CoreUpdate>>]> = (0..num_cores)
            .map(|_| Mutex::new(VecDeque::new()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let cores: Box<[CoreContext]> = (0..num_cores)
            .map(|_| CoreContext::new())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        ThemisPlatform {
            op_lock:      RwLock::new(()),
            update_lock:  AtomicBool::new(false),
            barriers:     [Barrier::new(), Barrier::new()],
            ipi_pending,
            core_updates,
            num_cores,
            hhdm_offset:  AtomicU64::new(0),
            uc_ranges,
            cores,
            domains:      DomainTable::new(),
            routing:      RwLock::new(RoutingMaps::new()),
            lapic_ids:    RwLock::new(Vec::new()),
            dom0_cap:     Mutex::new(None),
            vmxon_phys:   Vec::new(),
        }
    }

    /// Number of physical cores (set at boot from Limine MP response).
    pub fn num_cores(&self) -> usize {
        self.num_cores
    }

    /// Store per-core VMXON physical addresses (called once by BSP before
    /// AP_LAUNCH_READY).
    pub fn bootstrap_set_vmxon_phys(&mut self, phys: Vec<u64>) {
        self.vmxon_phys = phys;
    }

    /// Get VMXON physical address for a core (called by APs after Acquire
    /// on AP_LAUNCH_READY).
    pub fn vmxon_phys(&self, core_index: usize) -> u64 {
        self.vmxon_phys[core_index]
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

    /// Execute INVEPT(single-context) for the given domain's EPTP on the
    /// current core.  If the domain has no EPT (not yet mapped), this is a
    /// no-op since there can be no cached translations.
    fn invept_for_domain(&self, domain_id: DomainId) {
        if let Some(arc) = self.domains.get(domain_id) {
            let d = arc.lock();
            if let Some(ept) = d.ept.as_ref() {
                unsafe {
                    crate::vmx::invept(crate::vmx::INVEPT_SINGLE_CONTEXT, ept.eptp());
                }
            }
        }
    }

    // ── CoreContext access ─────────────────────────────────────────────── //

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

    /// Set the per-core scheduling state: domain capability ref and VP index.
    ///
    /// Called during bootstrap (BSP and AP init) and on domain switch.
    pub fn set_core_context(&self, core_id: usize, cap: CapabilityRef<Domain>, vp_id: u32) {
        let dom_id = cap.read().data.id;
        self.cores[core_id].domain_id.store(dom_id, Ordering::Release);
        self.cores[core_id].vp_id.store(vp_id, Ordering::Release);
        *self.cores[core_id].domain_cap.lock() = Some(cap);
    }

    /// Get the `CapabilityRef<Domain>` for the domain running on `core_id`.
    ///
    /// Returns `None` during early boot before the core is initialised.
    pub fn get_core_cap(&self, core_id: usize) -> Option<CapabilityRef<Domain>> {
        self.cores[core_id].domain_cap.lock().clone()
    }

    /// Get the VP index currently running on `core_id`.
    #[allow(dead_code)]
    pub fn get_core_vp(&self, core_id: usize) -> u32 {
        self.cores[core_id].vp_id.load(Ordering::Acquire)
    }

    // ── Per-core update queue ─────────────────────────────────────────── //

    /// Push a `CoreUpdate` to a target core's queue.
    ///
    /// Called by the initiating core (under `update_lock`) before sending
    /// the INIT assert.
    pub fn push_core_update(&self, core_id: CoreId, update: CoreUpdate) {
        self.core_updates[core_id as usize].lock().push_back(update);
    }

    /// Drain and apply all pending `CoreUpdate`s for the current core.
    ///
    /// Called between barriers 0 and 1 in `poll_and_respond_cross_core`.
    /// Returns `true` if any update was processed.
    fn apply_local_core_updates(&self, core_id: CoreId) {
        let mut queue = self.core_updates[core_id as usize].lock();
        while let Some(update) = queue.pop_front() {
            match update {
                CoreUpdate::TlbShootdown => {
                    let dom = self.cores[core_id as usize]
                        .domain_id
                        .load(Ordering::Relaxed);
                    if dom != IDLE_DOMAIN {
                        self.invept_for_domain(dom);
                    }
                }
                CoreUpdate::Switch { .. } => {
                    todo!("P9: cross-core domain switch");
                }
                CoreUpdate::Revoke { .. } => {
                    todo!("P9: cross-core domain revocation");
                }
            }
        }
    }
} //

impl Platform for ThemisPlatform {
    fn acquire_shared_lock(&self) -> Result<Box<dyn OpLockGuard>> {
        Ok(Box::new(SharedGuard::new(&self.op_lock)))
    }

    fn acquire_exclusive_lock(&self) -> Result<Box<dyn OpLockGuard>> {
        Ok(Box::new(ExclusiveGuard::new(&self.op_lock)))
    }

    fn send_ipi(&self, core_id: CoreId) {
        // Push TlbShootdown to target's queue before signaling.
        self.push_core_update(core_id, CoreUpdate::TlbShootdown);

        // Set the flag so the target core (if polling) can respond.
        self.ipi_pending[core_id as usize].store(true, Ordering::Release);

        // Send INIT assert: delivery mode 0x5, level assert (bit 14), edge.
        // INIT always causes VMEXIT(EXIT_REASON_INIT_SIGNAL = 3) from
        // non-root mode, regardless of pin-based controls.
        let lapic_id = *self.lapic_ids
            .read()
            .get(core_id as usize)
            .unwrap_or_else(|| panic!("send_ipi: unknown core {}", core_id));
        let icr: u64 = ((lapic_id as u64) << 32)
            | (1u64 << 14)   // level = assert
            | (0x5u64 << 8); // delivery mode = INIT
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
        if core_id as usize >= self.num_cores { return; }
        if self.ipi_pending[core_id as usize]
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        // Barrier 0: rendezvous with initiator.
        self.barriers[0].wait(0);
        // Drain per-core update queue between the two barriers.
        self.apply_local_core_updates(core_id);
        // Barrier 1: signal completion.
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

            Update::FlushTLB { domain } => {
                self.invept_for_domain(*domain);
            }

            Update::CommRegion { .. } | Update::UncommRegion { .. } => {
                // TODO(P7): shared-memory regions.
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
            self.cores[core_id as usize].domain_id.store(
                fallback.unwrap_or(IDLE_DOMAIN),
                Ordering::Release,
            );
            // TODO(Phase 9): also update CoreContext.domain_cap to the fallback's
            // CapabilityRef once on_domain_revoked carries it (switch-based unification).
            if let Some(fb) = fallback {
                routing.core_to_domain.insert(core_id, fb);
                routing.domain_to_core.insert(fb, core_id);
            }
        }
    }

    fn set_core_context(
        &self,
        core_id: CoreId,
        domain_cap: &CapabilityRef<Domain>,
        vp_id: u64,
    ) {
        let domain_id = domain_cap.read().data.id;
        self.cores[core_id as usize].domain_id.store(domain_id, Ordering::Release);
        self.cores[core_id as usize].vp_id.store(vp_id as u32, Ordering::Release);
        *self.cores[core_id as usize].domain_cap.lock() = Some(domain_cap.clone());
        let mut routing = self.routing.write();
        if let Some(old_domain) = routing.core_to_domain.remove(&core_id) {
            routing.domain_to_core.remove(&old_domain);
        }
        routing.core_to_domain.insert(core_id, domain_id);
        routing.domain_to_core.insert(domain_id, core_id);
    }

    fn clear_core_domain(&self, core_id: CoreId) {
        self.cores[core_id as usize].domain_id.store(IDLE_DOMAIN, Ordering::Release);
        self.cores[core_id as usize].vp_id.store(IDLE_VP, Ordering::Release);
        *self.cores[core_id as usize].domain_cap.lock() = None;
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
