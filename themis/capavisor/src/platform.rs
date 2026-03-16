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
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use spin::{Mutex, RwLock};

use capability_engine::{
    CapabilityRef, CoreId, Domain, DomainId, OpLockGuard, Platform, Result, Update,
};

use crate::serial_println;
use ept::{EptEntryFlags, EptMapper, EptMemoryType, Level};

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
    /// Physical address of this VP's Posted Interrupt Descriptor.
    /// Set by `put()` from the InactiveVcpu and never changes afterwards.
    /// Readable without taking the VP — safe because pid_phys is immutable
    /// after the first `put()`.  0 for dom0 VPs (no PID).
    pid_phys: AtomicU64,
}

impl VcpuSlot {
    /// Create an empty slot (no VP stored).
    pub const fn empty() -> Self {
        VcpuSlot {
            ptr: AtomicPtr::new(core::ptr::null_mut()),
            pid_phys: AtomicU64::new(0),
        }
    }

    /// Create a slot holding an InactiveVcpu.
    #[allow(dead_code)]
    pub fn with_vcpu(vcpu: InactiveVcpu) -> Self {
        let pid = vcpu.pid_phys();
        VcpuSlot {
            ptr: AtomicPtr::new(Box::into_raw(Box::new(vcpu))),
            pid_phys: AtomicU64::new(pid),
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
        let pid = vcpu.pid_phys();
        let old = self.ptr.swap(Box::into_raw(Box::new(vcpu)), Ordering::Release);
        assert!(old.is_null(), "VcpuSlot::put: slot was not empty (double-return bug)");
        // Cache pid_phys so callers can read it without taking the VP.
        self.pid_phys.store(pid, Ordering::Relaxed);
    }

    /// Read the cached pid_phys without taking the VP.
    ///
    /// Returns 0 if the VP has no PID (dom0) or the slot was never populated.
    /// Safe to call concurrently with `take()` / `put()` because pid_phys
    /// is immutable after the first `put()`.
    pub fn peek_pid_phys(&self) -> u64 {
        self.pid_phys.load(Ordering::Relaxed)
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
///   observational reads (e.g., `domain_cores()` routing lookups).
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
    /// IOMMU second-level page table (SLPT), mirrors EPT for DMA isolation.
    /// Allocated lazily on the first `ChangeRights` mapping for this domain.
    /// Uses the same EptMapper type (VT-d SLPT format is bit-compatible with EPT).
    pub iommu_pt: Option<EptMapper>,
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
    /// Per-VP COMM page physical addresses.  Index = VP ID.
    /// Set when CommRegion update is applied (or during do_add_vp).
    pub comm_hpas: Vec<u64>,
    /// Physical address of the MSR bitmap page for this domain's VPs.
    /// Allocated from META pool at seal time; 0 until then.
    pub msr_bitmap_phys: u64,

    /// Physical address of the APIC access page (one per domain, 4 KB).
    /// Used with VIRTUALIZE_APIC_ACCESSES (secondary proc-based bit 0) for
    /// child VPs — xAPIC MMIO accesses to 0xFEE00000 fault to this page
    /// instead of an EPT violation.  Allocated from META on first ADD_VP.
    /// 0 until then.
    pub apic_access_phys: u64,

    /// DomainComm region: per-domain message ring with the capavisor.
    /// `None` until `init_domcomm()` allocates it.
    pub domcomm: Option<DomainCommState>,
}

/// Per-ring page tracking for DomainComm growth.
pub struct DomainCommRing {
    /// Physical addresses of the ring's backing pages (growable).
    pub page_hpas: Vec<u64>,
}

impl DomainCommRing {
    fn new() -> Self {
        DomainCommRing { page_hpas: Vec::new() }
    }

    fn capacity(&self) -> usize {
        self.page_hpas.len() * 0x1000
    }
}

/// Per-domain DomainComm region state (capavisor-side bookkeeping).
pub struct DomainCommState {
    /// Physical address of the header page (page 0).
    pub header_hpa: u64,
    /// RX ring pages (capavisor→domain, capavisor is producer).
    pub rx: DomainCommRing,
    /// TX ring pages (domain→capavisor, capavisor is consumer).
    pub tx: DomainCommRing,
    /// GPA at which this region is visible to the domain.
    pub gpa: u64,
    /// HHDM offset, cached for ring access.
    pub hhdm_offset: u64,
}

impl PlatformDomain {
    fn new(hhdm_offset: u64, parent: Option<DomainId>) -> Self {
        PlatformDomain {
            ept: None,
            iommu_pt: None,
            meta: MetaAllocator::new(hhdm_offset),
            parent,
            hhdm_offset,
            vps: Vec::new(),
            comm_hpas: Vec::new(),
            msr_bitmap_phys: 0,
            apic_access_phys: 0,
            domcomm: None,
        }
    }

    /// Initialize DomainComm pages for this domain.
    ///
    /// For dom0 the pages live at a fixed GPA inside the identity-mapped RAM
    /// region (marked TYPE_RESERVED in e820 so Linux won't use them).  The
    /// caller passes the contiguous base HPA and page count; no META allocation
    /// is needed because the pages are ordinary DRAM already EPT-mapped.
    ///
    /// For child domains the caller will CARVE pages and pass their HPAs.
    fn init_domcomm(&mut self, base_hpa: u64, nr_pages: u32, gpa: u64) -> &DomainCommState {
        use themis_abi::domcomm;

        assert!(nr_pages >= 2, "DomainComm needs at least 2 pages (header + 1 ring)");

        let header_hpa = base_hpa;

        // Write header to page 0 via HHDM.
        let hdr_virt = (header_hpa + self.hhdm_offset) as *mut domcomm::Header;
        let rx_page_count = (nr_pages - 1).saturating_sub(1).max(1);
        let tx_page_count = nr_pages - 1 - rx_page_count;

        // Build per-ring page HPA lists.
        let mut rx_ring = DomainCommRing::new();
        for i in 0..rx_page_count {
            rx_ring.page_hpas.push(base_hpa + (1 + i as u64) * 0x1000);
        }
        let mut tx_ring = DomainCommRing::new();
        for i in 0..tx_page_count {
            tx_ring.page_hpas.push(base_hpa + (1 + rx_page_count as u64 + i as u64) * 0x1000);
        }

        unsafe {
            let hdr = &mut *hdr_virt;
            hdr.magic = domcomm::DOMCOMM_MAGIC;
            hdr.version_major = domcomm::DOMCOMM_VERSION_MAJOR;
            hdr.version_minor = domcomm::DOMCOMM_VERSION_MINOR;
            hdr.total_pages = nr_pages;
            hdr.flags = 0;

            hdr.rx = domcomm::RingMeta {
                head: 0,
                tail: 0,
                page_offset: 1,
                page_count: rx_page_count,
            };

            hdr.tx = domcomm::RingMeta {
                head: 0,
                tail: 0,
                page_offset: 1 + rx_page_count,
                page_count: tx_page_count,
            };

            hdr.notify_vector = 0;
            hdr.notify_flags = 0;
        }

        self.domcomm = Some(DomainCommState {
            header_hpa,
            rx: rx_ring,
            tx: tx_ring,
            gpa,
            hhdm_offset: self.hhdm_offset,
        });
        self.domcomm.as_ref().unwrap()
    }

    /// Write a message to the RX ring of this domain's DomainComm.
    ///
    /// The capavisor is the sole producer of the RX ring.
    /// Head/tail are monotonic (wrap only for page lookup).
    /// Returns the number of bytes written (including header), or 0 if ring full.
    pub fn domcomm_rx_enqueue(&mut self, msg_type: u32, payload: &[u8]) -> usize {
        use themis_abi::domcomm;

        let dc = self.domcomm.as_ref().expect("DomainComm not initialized");
        let hdr_virt = (dc.header_hpa + dc.hhdm_offset) as *mut domcomm::Header;

        let msg_hdr_size = core::mem::size_of::<domcomm::MsgHeader>();
        let total_size = ((msg_hdr_size + payload.len() + 7) / 8) * 8; // 8-byte align

        let capacity = dc.rx.capacity();
        let nr_pages = dc.rx.page_hpas.len();

        unsafe {
            let hdr = &mut *hdr_virt;
            let rx = &mut hdr.rx;
            let head = rx.head as usize;

            // Read tail (consumer = domain, monotonic) with acquire.
            let tail = core::ptr::read_volatile(&rx.tail) as usize;
            core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);

            // Check space using monotonic subtraction.
            let used = head.wrapping_sub(tail);
            if used > capacity || capacity - used < total_size {
                return 0; // Ring full
            }

            // Wrap head for page lookup.
            let wrapped_head = head % capacity;
            let ring_page_idx = wrapped_head / 4096;
            let page_off = wrapped_head % 4096;

            // Check if message fits in current page.
            if page_off + total_size > 4096 {
                // Write padding message to fill rest of page.
                let pad_size = 4096 - page_off;
                if ring_page_idx >= nr_pages {
                    serial_println!("[domcomm] RX enqueue: page_idx {} OOB", ring_page_idx);
                    return 0;
                }
                let pad_page_hpa = dc.rx.page_hpas[ring_page_idx];
                let pad_virt = (pad_page_hpa + dc.hhdm_offset) as *mut u8;
                let pad_hdr = pad_virt.add(page_off) as *mut domcomm::MsgHeader;
                (*pad_hdr).message_type = domcomm::msg_types::NONE;
                (*pad_hdr).total_size = pad_size as u32;
                (*pad_hdr).sequence = 0;

                // Advance head monotonically (no wrapping).
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                rx.head = (head + pad_size) as u32;

                // Recurse with the new head position.
                return self.domcomm_rx_enqueue(msg_type, payload);
            }

            if ring_page_idx >= nr_pages {
                serial_println!("[domcomm] RX enqueue: page_idx {} OOB", ring_page_idx);
                return 0;
            }

            // Write message within current page.
            let ring_page_hpa = dc.rx.page_hpas[ring_page_idx];
            let ring_page_virt = (ring_page_hpa + dc.hhdm_offset) as *mut u8;
            let msg_ptr = ring_page_virt.add(page_off);

            // Write payload first, then header (producer protocol).
            if !payload.is_empty() {
                core::ptr::copy_nonoverlapping(
                    payload.as_ptr(),
                    msg_ptr.add(msg_hdr_size),
                    payload.len(),
                );
            }

            // Write header.
            let msg_hdr_ptr = msg_ptr as *mut domcomm::MsgHeader;
            (*msg_hdr_ptr).message_type = msg_type;
            (*msg_hdr_ptr).total_size = total_size as u32;
            (*msg_hdr_ptr).sequence = 0; // TODO: monotonic counter per ring

            // Memory barrier + advance head monotonically.
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            rx.head = (head + total_size) as u32;
        }

        total_size
    }

    /// Read one message from the TX ring (domain→capavisor, we are consumer).
    ///
    /// Returns `Some((msg_type, payload_size))` on success, `None` if ring is empty.
    /// Handles padding messages transparently.
    ///
    /// Security: bounds-checks all domain-supplied values. Copies the message
    /// header before inspecting it to avoid TOCTOU on shared memory.
    pub fn domcomm_tx_dequeue(&mut self, buf: &mut [u8]) -> Option<(u32, usize)> {
        use themis_abi::domcomm;

        let dc = self.domcomm.as_ref().expect("DomainComm not initialized");
        let hdr_virt = (dc.header_hpa + dc.hhdm_offset) as *mut domcomm::Header;

        let msg_hdr_size = core::mem::size_of::<domcomm::MsgHeader>();

        let capacity = dc.tx.capacity();
        if capacity == 0 {
            return None;
        }
        let nr_pages = dc.tx.page_hpas.len();

        unsafe {
            let hdr = &mut *hdr_virt;
            let tx = &mut hdr.tx;

            // Read head (producer = domain) with acquire fence.
            // Head/tail are monotonic (never wrapped by the domain).
            let head = core::ptr::read_volatile(&tx.head) as usize;
            core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
            let tail = tx.tail as usize;

            if head == tail {
                return None;
            }

            // Sanity: available data.
            let avail = head.wrapping_sub(tail);
            if avail > capacity {
                serial_println!("[domcomm] TX dequeue: corrupt ring (head={}, tail={}, cap={})",
                    head, tail, capacity);
                return None;
            }

            // Wrap tail for page lookup.
            let wrapped_tail = tail % capacity;
            let ring_page_idx = wrapped_tail / 4096;
            let page_off = wrapped_tail % 4096;

            if ring_page_idx >= nr_pages {
                serial_println!("[domcomm] TX dequeue: page_idx {} out of range (nr_pages={})",
                    ring_page_idx, nr_pages);
                return None;
            }

            let page_hpa = dc.tx.page_hpas[ring_page_idx];
            let page_virt = (page_hpa + dc.hhdm_offset) as *const u8;

            // Copy the message header to a local variable (TOCTOU defense).
            let mut msg_hdr: domcomm::MsgHeader = core::mem::zeroed();
            core::ptr::copy_nonoverlapping(
                page_virt.add(page_off) as *const u8,
                &mut msg_hdr as *mut domcomm::MsgHeader as *mut u8,
                msg_hdr_size,
            );

            // Skip padding — use monotonic tail (no wrapping).
            if msg_hdr.message_type == domcomm::msg_types::NONE {
                let pad_size = msg_hdr.total_size as usize;
                if pad_size == 0 || pad_size > 4096 {
                    serial_println!("[domcomm] TX dequeue: invalid padding size {}", pad_size);
                    return None;
                }
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                tx.tail = (tail + pad_size) as u32;
                return self.domcomm_tx_dequeue(buf);
            }

            // Bounds-check total_size.
            let total_size = msg_hdr.total_size as usize;
            if total_size < msg_hdr_size || total_size > avail || total_size > 4096 {
                serial_println!("[domcomm] TX dequeue: invalid total_size {} (avail={}, hdr={})",
                    total_size, avail, msg_hdr_size);
                return None;
            }

            let payload_size = total_size - msg_hdr_size;
            if payload_size > buf.len() {
                serial_println!("[domcomm] TX message too large ({} > {})", payload_size, buf.len());
                return None;
            }

            // Copy payload (skip header).
            if payload_size > 0 {
                let payload_src = page_virt.add(page_off + msg_hdr_size);
                core::ptr::copy_nonoverlapping(payload_src, buf.as_mut_ptr(), payload_size);
            }

            // Advance tail monotonically (match driver protocol).
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            tx.tail = (tail + total_size) as u32;

            Some((msg_hdr.message_type, payload_size))
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

    /// Ensure an IOMMU second-level page table (SLPT) root exists for this domain.
    ///
    /// `alloc` should be backed by the **root domain's** META pool so that child
    /// domain META budgets are not consumed by hypervisor page-table pages.
    fn ensure_iommu_pt(&mut self, level: Level, alloc: &mut impl ept::FrameAllocator) {
        if self.iommu_pt.is_none() {
            self.iommu_pt = Some(EptMapper::alloc_root_at_level(
                alloc,
                self.hhdm_offset,
                level,
            ));
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
    domain_to_cores: BTreeMap<DomainId, BTreeSet<CoreId>>,
}

impl RoutingMaps {
    fn new() -> Self {
        RoutingMaps {
            core_to_domain: BTreeMap::new(),
            domain_to_cores: BTreeMap::new(),
        }
    }
}

// ── ThemisPlatform ────────────────────────────────────────────────────────── //

/// Domain ID reserved for the root (dom0) domain.
/// IOMMU page-table frames (SLPT root + intermediate pages) are allocated
/// from this domain's META pool — not from child domains — so that child
/// META budgets are not consumed by hypervisor-internal structures.
pub const ROOT_DOMAIN_ID: DomainId = 0;

/// A frame allocator that routes alloc/free to the **root domain**'s META pool.
///
/// Used by IOMMU SLPT operations in `apply_update` so that child domains'
/// META budgets are not consumed by hypervisor page-table pages.
struct RootMetaProxy<'a>(&'a ThemisPlatform);

impl ept::FrameAllocator for RootMetaProxy<'_> {
    fn allocate_frame(&mut self) -> Option<u64> {
        let arc = self.0.domains.get(ROOT_DOMAIN_ID)?;
        let mut d = arc.lock();
        let phys = d.meta.alloc_frame();
        Some(phys)
    }

    fn free_frame(&mut self, phys: u64) {
        if let Some(arc) = self.0.domains.get(ROOT_DOMAIN_ID) {
            arc.lock().meta.free_frame(phys);
        }
    }
}

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
    // LAPIC IDs: written once at boot, immutable after — no lock needed.
    lapic_ids:       UnsafeCell<Vec<u32>>,
    // Tree root anchor — keeps dom0's capability tree alive.
    dom0_cap:        Mutex<Option<CapabilityRef<Domain>>>,
    // Per-core VMXON physical addresses; written once by BSP, read by each AP.
    vmxon_phys:      Vec<u64>,
    /// VT-d DRHD units with allocated IRT pages; written once at boot by
    /// `init_themis`, immutable afterwards (entries updated via `program_irte`).
    pub drhd_units:  Vec<crate::acpi::DhrdUnit>,
}

// SAFETY: `lapic_ids` uses `UnsafeCell` but is only written once during
// single-threaded boot (bootstrap_set_lapic_ids) and read-only after.
// All other fields are already Sync (atomics, spin locks, etc.).
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
            lapic_ids:    UnsafeCell::new(Vec::new()),
            dom0_cap:     Mutex::new(None),
            vmxon_phys:   Vec::new(),
            drhd_units:   Vec::new(),
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
        unsafe { *self.lapic_ids.get() = ids; }
    }

    /// Physical LAPIC ID of the BSP (core 0).
    /// Used as the remapped-IRTE destination for Report/NotReport vectors.
    pub fn bsp_lapic_id(&self) -> u32 {
        unsafe { &*self.lapic_ids.get() }
            .first()
            .copied()
            .unwrap_or(0)
    }

    /// Return the `Level` to use for IOMMU second-level page tables.
    ///
    /// Derived from the minimum AW (adjusted guest-address width) across all
    /// DRHD units: AW=1 → `Level::L3` (39-bit), AW=2 → `Level::L4` (48-bit).
    /// Falls back to `Level::L3` if no DRHD units are present.
    pub fn iommu_pt_level(&self) -> Level {
        let min_aw = self.drhd_units.iter()
            .filter(|u| u.aw > 0)
            .map(|u| u.aw)
            .min()
            .unwrap_or(1);
        if min_aw >= 2 { Level::L4 } else { Level::L3 }
    }

    /// Reprogram a PCI device's IOMMU context entry to use `domain_id`'s
    /// second-level page table (SLPT), replacing the dom0 passthrough entry.
    ///
    /// `bdf` is the 16-bit source ID: `bus[15:8] | device[7:3] | function[2:0]`.
    ///
    /// # Panics
    /// Panics if `domain_id` has no IOMMU PT yet (no memory has been mapped for
    /// it), or if no DRHD unit covers the bus encoded in `bdf`.
    pub fn assign_device(&self, bdf: u16, domain_id: DomainId) {
        let hhdm = self.hhdm_offset.load(Ordering::Relaxed);
        let bus   = (bdf >> 8) as u8;
        let devfn = (bdf & 0xFF) as usize;

        let slptptr = self.domains
            .get(domain_id)
            .unwrap_or_else(|| panic!("assign_device: unknown domain {}", domain_id))
            .lock()
            .iommu_pt
            .as_ref()
            .unwrap_or_else(|| panic!("assign_device: domain {} has no IOMMU PT", domain_id))
            .root_phys();

        for unit in &self.drhd_units {
            if let Some(&(_, ctx_phys)) = unit.ctx_tables.iter().find(|(b, _)| *b == bus) {
                let ctx_virt = (ctx_phys + hhdm) as *mut u64;
                let entry    = unsafe { ctx_virt.add(devfn * 2) };
                // Write high word first (DID, AW), then low word with P=1 last.
                // TT=00 (multi-level second-level translation).
                let ctx_hi = (domain_id << 8) | unit.aw;
                let ctx_lo = slptptr | 0x1; // P=1, TT=00, SLPTPTR
                unsafe {
                    entry.add(1).write_volatile(ctx_hi);
                    entry.write_volatile(ctx_lo);
                }
                self.flush_ctx_and_iotlb(unit, bdf, hhdm);
                serial_println!(
                    "  IOMMU: BDF {:#06x} assigned to domain {} (slptptr={:#x})",
                    bdf, domain_id, slptptr
                );
                return;
            }
        }
        panic!("assign_device: no DRHD covers bus {} for BDF {:#06x}", bus, bdf);
    }

    /// Restore the passthrough context entry for a PCI device, returning it to
    /// dom0 (DID=1, TT=10b pass-through).  Called on child-domain revocation.
    ///
    /// No-ops silently if no DRHD covers the bus.
    pub fn release_device(&self, bdf: u16) {
        let hhdm  = self.hhdm_offset.load(Ordering::Relaxed);
        let bus   = (bdf >> 8) as u8;
        let devfn = (bdf & 0xFF) as usize;

        for unit in &self.drhd_units {
            if let Some(&(_, ctx_phys)) = unit.ctx_tables.iter().find(|(b, _)| *b == bus) {
                let ctx_virt = (ctx_phys + hhdm) as *mut u64;
                let entry    = unsafe { ctx_virt.add(devfn * 2) };
                // Restore dom0 passthrough: high=(DID=1<<8)|AW, low=0x9 (P=1, TT=10b).
                let ctx_hi = (1u64 << 8) | unit.aw;
                let ctx_lo = 0x9u64;
                unsafe {
                    entry.add(1).write_volatile(ctx_hi);
                    entry.write_volatile(ctx_lo);
                }
                self.flush_ctx_and_iotlb(unit, bdf, hhdm);
                serial_println!("  IOMMU: BDF {:#06x} released to dom0 passthrough", bdf);
                return;
            }
        }
    }

    /// Flush context-cache (device-selective) and IOTLB (global) for a DRHD unit.
    fn flush_ctx_and_iotlb(&self, unit: &crate::acpi::DhrdUnit, bdf: u16, hhdm: u64) {
        const CCMD_OFFSET:  u64 = 0x28;
        const ECAP_OFFSET:  u64 = 0x10;
        const POLL_LIMIT: usize = 100_000;

        let base = unit.register_base + hhdm;
        let ccmd = (base + CCMD_OFFSET) as *mut u64;

        // Context-cache invalidation: device-selective (CIRG=11b=bits[62:61]),
        // SID=bdf in bits[47:32], ICC=bit[63].
        let ccmd_val = (1u64 << 63)          // ICC
            | (3u64 << 61)                   // CIRG = device-selective
            | ((bdf as u64) << 32);          // SID
        unsafe { ccmd.write_volatile(ccmd_val) };
        for _ in 0..POLL_LIMIT {
            core::hint::spin_loop();
            if unsafe { ccmd.read_volatile() } & (1u64 << 63) == 0 { break; }
        }

        // IOTLB global invalidation.
        let ecap = unsafe { ((base + ECAP_OFFSET) as *const u64).read_volatile() };
        let iro  = ((ecap >> 8) & 0x3f) as u64;
        let iotlb_reg = (base + iro * 16 + 8) as *mut u64;
        unsafe { iotlb_reg.write_volatile((1u64 << 63) | (1u64 << 60)) };
        for _ in 0..POLL_LIMIT {
            core::hint::spin_loop();
            if unsafe { iotlb_reg.read_volatile() } & (1u64 << 63) == 0 { break; }
        }
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
        let arc = self.domains
            .get(domain_id)
            .unwrap_or_else(|| panic!("bootstrap_init_domcomm: domain not registered"));
        let mut d = arc.lock();
        d.init_domcomm(base_hpa, nr_pages, gpa);
        (gpa, nr_pages)
    }

    /// Write a binary attestation message to a domain's DomainComm RX ring.
    ///
    /// The attestation payload is a `domcomm::AttestReport` header followed by
    /// packed arrays of mem_cap, dom_cap, and pa_map entries.
    ///
    /// Must be called after `bootstrap_init_domcomm`.
    pub fn bootstrap_write_attestation(
        &self,
        domain_id: DomainId,
        payload: &[u8],
    ) {
        use themis_abi::domcomm;
        let arc = self.domains
            .get(domain_id)
            .unwrap_or_else(|| panic!("bootstrap_write_attestation: domain not registered"));
        let mut d = arc.lock();
        let wrote = d.domcomm_rx_enqueue(domcomm::msg_types::ATTEST, payload);
        assert!(wrote > 0, "bootstrap_write_attestation: RX ring full or too small");
    }

    /// Get the DomainComm GPA and page count for a domain (for CPUID / e820).
    pub fn domcomm_info(&self, domain_id: DomainId) -> Option<(u64, u32)> {
        let arc = self.domains.get(domain_id)?;
        let d = arc.lock();
        d.domcomm.as_ref().map(|dc| {
            let total = 1 + dc.rx.page_hpas.len() as u32 + dc.tx.page_hpas.len() as u32;
            (dc.gpa, total)
        })
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

    /// Get a cloned Arc reference to a PlatformDomain (for use outside apply_update).
    pub fn domain_arc(&self, domain_id: DomainId) -> Option<alloc::sync::Arc<Mutex<PlatformDomain>>> {
        self.domains.get(domain_id)
    }

    /// Get the HHDM offset (physical → virtual address translation).
    pub fn hhdm_offset(&self) -> u64 {
        self.hhdm_offset.load(Ordering::Relaxed)
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
        // Also keep the routing maps consistent so that execute() sends IPIs
        // to ALL cores running this domain during EPT updates.
        let mut routing = self.routing.write();
        if let Some(old_domain) = routing.core_to_domain.remove(&(core_id as CoreId)) {
            if let Some(set) = routing.domain_to_cores.get_mut(&old_domain) {
                set.remove(&(core_id as CoreId));
                if set.is_empty() {
                    routing.domain_to_cores.remove(&old_domain);
                }
            }
        }
        routing.core_to_domain.insert(core_id as CoreId, dom_id);
        routing.domain_to_cores.entry(dom_id).or_default().insert(core_id as CoreId);
    }

    /// Get the `CapabilityRef<Domain>` for the domain running on `core_id`.
    ///
    /// Returns `None` during early boot before the core is initialised.
    pub fn get_core_cap(&self, core_id: usize) -> Option<CapabilityRef<Domain>> {
        self.cores[core_id].domain_cap.lock().clone()
    }

    /// Lock-free read of the domain ID currently scheduled on `core_id`.
    pub fn core_domain_id(&self, core_id: usize) -> u64 {
        self.cores[core_id].domain_id.load(Ordering::Acquire)
    }

    /// Get the `PlatformDomain` for a given domain ID.
    pub fn get_platform_domain(&self, id: DomainId)
        -> Option<alloc::sync::Arc<Mutex<PlatformDomain>>>
    {
        self.domains.get(id)
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
        //
        // Use xAPIC MMIO (0xFEE0_0000) because the capavisor never enables
        // x2APIC mode and dom0 could regress it.  When we properly
        // virtualise dom0's APIC access, we can switch to x2APIC MSRs.
        let lapic_id = unsafe {
            let ids = &*self.lapic_ids.get();
            *ids.get(core_id as usize)
                .unwrap_or_else(|| panic!("send_ipi: unknown core {}", core_id))
        };
        let hhdm = self.hhdm_offset.load(Ordering::Relaxed);
        let apic_base = hhdm + 0xFEE0_0000u64;
        unsafe {
            // ICR high: destination APIC ID in bits 24-31
            let icr_hi = (apic_base + 0x310) as *mut u32;
            core::ptr::write_volatile(icr_hi, lapic_id << 24);
            // ICR low: delivery=INIT (0x5<<8), level=assert (1<<14)
            let icr_lo = (apic_base + 0x300) as *mut u32;
            core::ptr::write_volatile(icr_lo, (1u32 << 14) | (0x5u32 << 8));
        }
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
                // META pages are hypervisor-internal (EPT tables, VMCS) and are
                // not DMA targets — no IOMMU PT mapping needed here.
            }

            Update::ChangeRights { domain, address, size, physical, rights, .. } => {
                let uc_ranges = alloc::sync::Arc::clone(&self.uc_ranges);
                let iommu_level = self.iommu_pt_level();
                // Only child domains (domain != ROOT_DOMAIN_ID) get a SLPT.
                // dom0 uses passthrough context entries and needs no IOMMU PT.
                let is_child = *domain != ROOT_DOMAIN_ID;
                let arc = self.domains
                    .get(*domain)
                    .expect("ChangeRights: unknown domain");
                let mut d = arc.lock();
                // Split the MutexGuard borrow into a disjoint field pointer so the
                // borrow checker accepts simultaneous &mut ept and &mut meta.
                let meta_ptr: *mut MetaAllocator = &mut d.meta;

                if rights.bits() == 0 {
                    if let Some(ept) = d.ept.as_mut() {
                        // SAFETY: `ept` and `meta` are disjoint fields of PlatformDomain.
                        ept.unmap_range(unsafe { &mut *meta_ptr }, *address, *size as usize);
                    }
                    if is_child {
                        if let Some(slpt) = d.iommu_pt.as_mut() {
                            // SLPT pages are owned by root's META; use RootMetaProxy.
                            slpt.unmap_range(&mut RootMetaProxy(self), *address, *size as usize);
                        }
                    }
                } else {
                    d.ensure_ept();
                    if is_child {
                        // SAFETY: child domain lock held; root domain lock acquired
                        // inside RootMetaProxy. update_lock serialises all apply_update
                        // calls so no other thread can hold the root domain lock here.
                        d.ensure_iommu_pt(iommu_level, &mut RootMetaProxy(self));
                    }
                    let flags = rights_to_ept_flags(rights);
                    // SAFETY: ept and meta are disjoint fields of PlatformDomain.
                    let ept = d.ept.as_mut().unwrap();
                    map_range_typed(ept, unsafe { &mut *meta_ptr },
                        *address, *physical, *size as usize, flags, &uc_ranges);
                    if is_child {
                        if let Some(slpt) = d.iommu_pt.as_mut() {
                            // VT-d SLPT: same GPA→HPA mapping; no memory-type bits needed.
                            slpt.map_range(&mut RootMetaProxy(self),
                                *address, *physical, *size as usize,
                                flags, ept::EptMemoryType::WB);
                        }
                    }
                }
            }

            Update::RevokeDomain { domain, .. } => {
                if let Some(mut d) = self.domains.remove(*domain) {
                    if let Some(ept) = d.ept.take() {
                        ept.free_all(&mut d.meta);
                    }
                    if let Some(slpt) = d.iommu_pt.take() {
                        // SLPT pages were allocated from root's META; return them there.
                        slpt.free_all(&mut RootMetaProxy(self));
                    }
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

            Update::CommRegion { domain_id, target_domain_id, vp_id, phys, size } => {
                if *domain_id != *target_domain_id {
                    // VP-level COMM: store HPA for child VP.
                    if let Some(arc) = self.domains.get(*target_domain_id) {
                        let mut pd = arc.lock();
                        let vp = *vp_id as usize;
                        if vp >= pd.comm_hpas.len() {
                            pd.comm_hpas.resize(vp + 1, 0);
                        }
                        pd.comm_hpas[vp] = *phys;
                    }
                }
                let _ = (domain_id, phys, size);
            }
            Update::UncommRegion { domain_id, target_domain_id, vp_id, phys, size } => {
                let _ = (domain_id, target_domain_id, vp_id, phys, size);
                // TODO(P7): unmap COMM page.
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
        if let Some(cores) = routing.domain_to_cores.remove(&domain_id) {
            for core_id in cores {
                routing.core_to_domain.remove(&core_id);
                self.cores[core_id as usize].domain_id.store(
                    fallback.unwrap_or(IDLE_DOMAIN),
                    Ordering::Release,
                );
                // TODO(Phase 9): also update CoreContext.domain_cap to the fallback's
                // CapabilityRef once on_domain_revoked carries it (switch-based unification).
                if let Some(fb) = fallback {
                    routing.core_to_domain.insert(core_id, fb);
                    routing.domain_to_cores.entry(fb).or_default().insert(core_id);
                }
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
            if let Some(set) = routing.domain_to_cores.get_mut(&old_domain) {
                set.remove(&core_id);
                if set.is_empty() {
                    routing.domain_to_cores.remove(&old_domain);
                }
            }
        }
        routing.core_to_domain.insert(core_id, domain_id);
        routing.domain_to_cores.entry(domain_id).or_default().insert(core_id);
    }

    fn clear_core_domain(&self, core_id: CoreId) {
        self.cores[core_id as usize].domain_id.store(IDLE_DOMAIN, Ordering::Release);
        self.cores[core_id as usize].vp_id.store(IDLE_VP, Ordering::Release);
        *self.cores[core_id as usize].domain_cap.lock() = None;
        let mut routing = self.routing.write();
        if let Some(domain_id) = routing.core_to_domain.remove(&core_id) {
            if let Some(set) = routing.domain_to_cores.get_mut(&domain_id) {
                set.remove(&core_id);
                if set.is_empty() {
                    routing.domain_to_cores.remove(&domain_id);
                }
            }
        }
    }

    fn domain_cores(&self, domain_id: DomainId) -> alloc::vec::Vec<CoreId> {
        self.routing.read().domain_to_cores
            .get(&domain_id)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
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
        use themis_abi::regs::VpRegister;

        let reg = VpRegister::from_discriminant(reg_id)
            .ok_or_else(|| CapaError::InvalidOperation("unknown reg_id".into()))?;

        let mut vcpu = self.take_vcpu(domain_id, vp_id as usize)
            .ok_or_else(|| CapaError::InvalidOperation("VP not available".into()))?;

        if let Some(gpr) = crate::hypercall::vp_reg_to_gpr(reg) {
            vcpu.set_reg(gpr, value);
            self.return_vcpu(domain_id, vp_id as usize, vcpu);
        } else if let Some(field) = crate::hypercall::vp_reg_to_vmcs_field(reg) {
            let vmcs_phys = vcpu.vmcs_phys();
            self.return_vcpu(domain_id, vp_id as usize, vcpu);
            unsafe {
                use x86::bits64::vmx as vmx_ops;
                let caller_vmcs = vmx_ops::vmptrst()
                    .map_err(|_| CapaError::InvalidOperation("vmptrst failed".into()))?;
                vmx_ops::vmptrld(vmcs_phys)
                    .map_err(|_| CapaError::InvalidOperation("vmptrld failed".into()))?;
                let write_result = x86::bits64::vmx::vmwrite(field, value)
                    .map_err(|_| CapaError::InvalidOperation("vmwrite failed".into()));
                // Always restore caller VMCS even on write failure.
                vmx_ops::vmclear(vmcs_phys)
                    .map_err(|_| CapaError::InvalidOperation("vmclear failed".into()))?;
                vmx_ops::vmptrld(caller_vmcs)
                    .map_err(|_| CapaError::InvalidOperation("vmptrld restore failed".into()))?;
                write_result?;
            }
        } else {
            self.return_vcpu(domain_id, vp_id as usize, vcpu);
            return Err(CapaError::InvalidOperation("reg has no VMCS mapping".into()));
        }
        Ok(())
    }

    fn get_vp_register(
        &self,
        domain_id: DomainId,
        vp_id: u64,
        reg_id: u64,
    ) -> capability_engine::error::Result<u64> {
        use capability_engine::error::CapaError;
        use themis_abi::regs::VpRegister;

        let reg = VpRegister::from_discriminant(reg_id)
            .ok_or_else(|| CapaError::InvalidOperation("unknown reg_id".into()))?;

        let vcpu = self.take_vcpu(domain_id, vp_id as usize)
            .ok_or_else(|| CapaError::InvalidOperation("VP not available".into()))?;

        if let Some(gpr) = crate::hypercall::vp_reg_to_gpr(reg) {
            let val = vcpu.reg(gpr);
            self.return_vcpu(domain_id, vp_id as usize, vcpu);
            Ok(val)
        } else if let Some(field) = crate::hypercall::vp_reg_to_vmcs_field(reg) {
            let vmcs_phys = vcpu.vmcs_phys();
            self.return_vcpu(domain_id, vp_id as usize, vcpu);
            let val = unsafe {
                use x86::bits64::vmx as vmx_ops;
                let caller_vmcs = vmx_ops::vmptrst()
                    .map_err(|_| CapaError::InvalidOperation("vmptrst failed".into()))?;
                vmx_ops::vmptrld(vmcs_phys)
                    .map_err(|_| CapaError::InvalidOperation("vmptrld failed".into()))?;
                let read_result = x86::bits64::vmx::vmread(field)
                    .map_err(|_| CapaError::InvalidOperation("vmread failed".into()));
                vmx_ops::vmclear(vmcs_phys)
                    .map_err(|_| CapaError::InvalidOperation("vmclear failed".into()))?;
                vmx_ops::vmptrld(caller_vmcs)
                    .map_err(|_| CapaError::InvalidOperation("vmptrld restore failed".into()))?;
                read_result?
            };
            Ok(val)
        } else {
            self.return_vcpu(domain_id, vp_id as usize, vcpu);
            Err(CapaError::InvalidOperation("reg has no VMCS mapping".into()))
        }
    }

    fn get_current_core(&self) -> Option<CoreId> {
        // Use CPUID leaf 1 (initial APIC ID in EBX[31:24]).
        // Works regardless of xAPIC vs x2APIC mode.
        let cpuid = core::arch::x86_64::__cpuid(1);
        let lapic_id = (cpuid.ebx >> 24) as u32;
        let ids = unsafe { &*self.lapic_ids.get() };
        ids.iter()
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
