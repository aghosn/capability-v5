//! `ThemisPlatform` — the capability engine's [`Platform`] implementation.
//!
//! This is the bootstrap implementation (Phase P2-platform).  It wires the
//! capability engine's update protocol to real EPT manipulations and a
//! per-domain META frame allocator.
//!
//! ## Bootstrap constraints
//!
//! * **Single-threaded during init** — APs are parked until after capability
//!   engine initialisation, so no cross-core IPI/barrier is needed yet.
//!   `send_ipi`, `sync_barrier`, and the update-lock methods are no-ops that
//!   return `true` / do nothing.  A proper spinlock-based IPI protocol will
//!   replace them in Phase P3.
//!
//! * **No `SwitchManager`** — core ↔ domain tracking is a simple
//!   `BTreeMap<CoreId, DomainId>`.  The VP layer (P2d) will extend this.

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;

use capability_engine::{CoreId, DomainId, OpLockGuard, Platform, Result, Update};
use ept::{EptEntryFlags, EptMapper, EptMemoryType};

use crate::mem::{MetaAllocator, PhysRegion};

// ── Lock guards (bootstrap: no actual contention, guards are trivial tokens) //

/// Guard token returned by `acquire_shared_lock`.
struct SharedGuard;
impl OpLockGuard for SharedGuard {}
// SAFETY: `SharedGuard` carries no data; Send is vacuously correct.
unsafe impl Send for SharedGuard {}

/// Guard token returned by `acquire_exclusive_lock`.
struct ExclusiveGuard;
impl OpLockGuard for ExclusiveGuard {}
// SAFETY: same as above.
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

// ── ThemisPlatformInner (everything behind the single Mutex) ─────────────── //

struct ThemisPlatformInner {
    domains: BTreeMap<DomainId, PlatformDomain>,
    core_to_domain: BTreeMap<CoreId, DomainId>,
    domain_to_core: BTreeMap<DomainId, CoreId>,
}

impl ThemisPlatformInner {
    fn new() -> Self {
        ThemisPlatformInner {
            domains: BTreeMap::new(),
            core_to_domain: BTreeMap::new(),
            domain_to_core: BTreeMap::new(),
        }
    }
}

// ── ThemisPlatform ────────────────────────────────────────────────────────── //

/// The Themis `Platform` implementation.
///
/// Wraps all mutable hardware state in a single `spin::Mutex` to satisfy the
/// `Sync` bound required by the capability engine.
pub struct ThemisPlatform {
    inner: Mutex<ThemisPlatformInner>,
}

impl ThemisPlatform {
    /// Create a new platform with no domains registered.
    ///
    /// `hhdm_offset` is forwarded to every `PlatformDomain` created by later
    /// `CreateDomain` updates.
    pub fn new() -> Self {
        ThemisPlatform {
            inner: Mutex::new(ThemisPlatformInner::new()),
        }
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
    // ── Locking (bootstrap: trivial no-op guards) ─────────────────────── //

    fn acquire_shared_lock(&self) -> Result<Box<dyn OpLockGuard>> {
        Ok(Box::new(SharedGuard))
    }

    fn acquire_exclusive_lock(&self) -> Result<Box<dyn OpLockGuard>> {
        Ok(Box::new(ExclusiveGuard))
    }

    // ── Cross-core sync (bootstrap: no-op) ───────────────────────────── //

    fn send_ipi(&self, _core_id: CoreId) {}

    fn sync_barrier(&self, _id: u8, _participants: usize) {}

    // ── Update application ────────────────────────────────────────────── //

    fn apply_update(&self, update: &Update) {
        match update {
            Update::CreateDomain { domain_id, parent_id } => {
                // Handled by register_domain — also called via apply_update path.
                self.register_domain(*domain_id, *parent_id);
            }

            Update::GiveMetaMem { domain_id, start, size } => {
                let mut g = self.inner.lock();
                let d = g
                    .domains
                    .get_mut(domain_id)
                    .expect("GiveMetaMem: unknown domain");
                d.meta.add_range(PhysRegion {
                    base: *start,
                    length: *size,
                });
            }

            Update::ChangeRights {
                domain,
                address,
                size,
                physical,
                rights,
                ..
            } => {
                let mut g = self.inner.lock();
                let d = g
                    .domains
                    .get_mut(domain)
                    .expect("ChangeRights: unknown domain");

                if rights.bits() == 0 {
                    // Unmap
                    if let Some(ept) = d.ept.as_mut() {
                        ept.unmap_range(&mut d.meta, *address, *size as usize);
                    }
                    // If there's no EPT yet, there's nothing to unmap.
                } else {
                    // Map (or rights update on existing entry)
                    d.ensure_ept();
                    let flags = rights_to_ept_flags(rights);
                    // All normal RAM is WB; MMIO regions will use UC once
                    // device enumeration is in place (Phase 4).
                    let ept = d.ept.as_mut().unwrap();
                    ept.map_range(
                        &mut d.meta,
                        *address,
                        *physical,
                        *size as usize,
                        flags,
                        EptMemoryType::WB,
                    );
                }
            }

            Update::RevokeDomain { domain, .. } => {
                // Revoked domains are cleaned up in on_domain_revoked.
                // apply_update is responsible for freeing EPT structures while
                // affected cores are paused (between the two barriers).
                let mut g = self.inner.lock();
                if let Some(mut d) = g.domains.remove(domain) {
                    if let Some(ept) = d.ept.take() {
                        ept.free_all(&mut d.meta);
                    }
                    // META pages themselves belong to the parent's allocator and
                    // will be returned when the memory capability is revoked.
                }
            }

            Update::ZeroMemory { address, size } => {
                // Zero the range via HHDM — works for pages physically present.
                // We need hhdm_offset; grab it from any registered domain.
                let g = self.inner.lock();
                if let Some(d) = g.domains.values().next() {
                    let virt = (address + d.hhdm_offset) as *mut u8;
                    unsafe {
                        core::ptr::write_bytes(virt, 0, *size as usize);
                    }
                }
            }

            Update::FlushTLB { .. } => {
                // Single-core bootstrap: no TLB shootdown needed.
                // APs are not running any domain yet.
            }
        }
    }

    // ── Domain lifecycle ─────────────────────────────────────────────── //

    fn on_domain_revoked(&self, domain_id: DomainId, fallback: Option<DomainId>) {
        // EPT structures were freed in apply_update(RevokeDomain).
        // Here we redirect any core running this domain to `fallback`.
        let mut g = self.inner.lock();
        if let Some(&core_id) = g.domain_to_core.get(&domain_id) {
            g.domain_to_core.remove(&domain_id);
            g.core_to_domain.remove(&core_id);
            if let Some(fb) = fallback {
                g.core_to_domain.insert(core_id, fb);
                g.domain_to_core.insert(fb, core_id);
            }
        }
    }

    fn register_domain(&self, domain_id: DomainId, parent_id: Option<DomainId>) {
        let mut g = self.inner.lock();
        // Avoid overwriting an entry created via bootstrap_register_domain.
        if g.domains.contains_key(&domain_id) {
            return;
        }
        // We need hhdm_offset — borrow it from an existing domain if available.
        // If the platform is completely empty (root domain registration during
        // bootstrap), the caller must use bootstrap_register_domain instead.
        let hhdm_offset = g
            .domains
            .values()
            .next()
            .map(|d| d.hhdm_offset)
            .unwrap_or(0);
        g.domains
            .insert(domain_id, PlatformDomain::new(hhdm_offset, parent_id));
    }

    // ── Core tracking ─────────────────────────────────────────────────── //

    fn set_core_domain(&self, core_id: CoreId, domain_id: DomainId) {
        let mut g = self.inner.lock();
        // Remove any previous assignment for this core.
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
