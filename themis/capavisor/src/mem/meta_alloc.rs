//! Per-domain META frame allocator.
//!
//! Each domain owns a contiguous physical META pool from which it allocates
//! 4 KiB-aligned pages for hardware VP structures (VMXON, VMCS, VAPIC, EPT).
//!
//! The allocator is a simple bump allocator — META pages are long-lived and
//! not freed during normal operation.  A future bitmap extension can add free
//! support if needed.

use super::PhysRegion;

const PAGE_SIZE: u64 = 4096;

/// A bump allocator over a contiguous physical memory region.
///
/// Hands out 4 KiB-aligned physical frames.  Thread-safety is the caller's
/// responsibility (domains are currently single-writer during setup).
pub struct MetaAllocator {
    /// Physical base of the META pool.
    base: u64,
    /// Total size of the pool in bytes.
    size: u64,
    /// Byte offset of the next free page (relative to `base`).
    next: u64,
    /// HHDM offset for phys→virt conversion.
    hhdm_offset: u64,
}

impl MetaAllocator {
    /// Create a new allocator over the given physical region.
    pub fn new(region: PhysRegion, hhdm_offset: u64) -> Self {
        assert!(region.base % PAGE_SIZE == 0, "META pool not page-aligned");
        assert!(region.length % PAGE_SIZE == 0, "META pool size not page-aligned");
        Self {
            base: region.base,
            size: region.length,
            next: 0,
            hhdm_offset,
        }
    }

    /// Allocate a single 4 KiB page, returning its physical address.
    ///
    /// The page is zeroed before being returned.
    ///
    /// # Panics
    /// Panics if the META pool is exhausted.
    pub fn alloc_frame(&mut self) -> u64 {
        assert!(
            self.next + PAGE_SIZE <= self.size,
            "META pool exhausted ({} / {} bytes used)",
            self.next,
            self.size
        );
        let phys = self.base + self.next;
        self.next += PAGE_SIZE;

        // Zero the page via HHDM.
        let virt = (phys + self.hhdm_offset) as *mut u8;
        unsafe {
            core::ptr::write_bytes(virt, 0, PAGE_SIZE as usize);
        }

        phys
    }

    /// Return the virtual (HHDM) address corresponding to a physical address
    /// within this pool.
    pub fn phys_to_virt(&self, phys: u64) -> *mut u8 {
        debug_assert!(phys >= self.base && phys < self.base + self.size);
        (phys + self.hhdm_offset) as *mut u8
    }

    /// Number of pages allocated so far.
    pub fn allocated_pages(&self) -> u64 {
        self.next / PAGE_SIZE
    }

    /// Number of free pages remaining.
    pub fn free_pages(&self) -> u64 {
        (self.size - self.next) / PAGE_SIZE
    }

    /// Total capacity in pages.
    pub fn total_pages(&self) -> u64 {
        self.size / PAGE_SIZE
    }

    /// Physical base address of the pool.
    pub fn base(&self) -> u64 {
        self.base
    }
}
