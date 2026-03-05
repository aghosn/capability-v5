//! Domain representation.
//!
//! A domain is the unit of isolation in Themis.  Every domain — including dom0 —
//! owns a META pool from which hardware VP structures are allocated, and a set of
//! memory capabilities describing the physical memory it controls.
//!
//! dom0 is bootstrapped by the capavisor at boot (no parent to grant META).
//! Child domains receive their META pool via capability operations from their parent.

extern crate alloc;
use alloc::vec::Vec;

use crate::mem::{MetaAllocator, PhysRegion};

/// Opaque domain identifier.
pub type DomainId = u64;

/// A domain managed by the capavisor.
pub struct Domain {
    /// Unique identifier (0 = dom0).
    pub id: DomainId,

    /// Per-domain META frame allocator.
    pub meta: MetaAllocator,

    /// Physical addresses of VMXON regions allocated from `meta`, one per core
    /// assigned to this domain.
    pub vmxon_regions: Vec<u64>,
}

impl Domain {
    /// Create a new domain with the given META pool.
    ///
    /// # Arguments
    /// * `id` — domain identifier (0 for dom0)
    /// * `meta_pool` — contiguous physical region for the domain's META
    /// * `hhdm_offset` — HHDM offset for phys→virt translation
    pub fn new(id: DomainId, meta_pool: PhysRegion, hhdm_offset: u64) -> Self {
        Self {
            id,
            meta: MetaAllocator::new(meta_pool, hhdm_offset),
            vmxon_regions: Vec::new(),
        }
    }

    /// Allocate VMXON regions for `num_cores` cores from the META pool.
    ///
    /// Each VMXON region is a single 4 KiB page, zeroed, with the VMCS revision
    /// ID written at offset 0.
    pub fn alloc_vmxon_regions(&mut self, num_cores: usize, vmcs_revision_id: u32) {
        self.vmxon_regions.reserve(num_cores);
        for _ in 0..num_cores {
            let phys = self.meta.alloc_frame();
            // Write VMCS revision ID at offset 0 (bits 30:0, bit 31 cleared).
            let virt = self.meta.phys_to_virt(phys) as *mut u32;
            unsafe {
                virt.write_volatile(vmcs_revision_id & 0x7FFF_FFFF);
            }
            self.vmxon_regions.push(phys);
        }
    }

    /// Get the VMXON region physical address for a given core index.
    pub fn vmxon_phys(&self, core_index: usize) -> u64 {
        self.vmxon_regions[core_index]
    }
}
