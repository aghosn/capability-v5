//! Per-domain META frame allocator.
//!
//! Each domain owns a pool of physical META pages from which it allocates
//! 4 KiB-aligned pages for hardware VP structures (VMXON, VMCS, VAPIC, EPT).
//!
//! The allocator starts empty; call `add_range` to populate it.
//! Freed pages are pushed onto a `Vec`-backed free stack and reused.

extern crate alloc;
use alloc::vec::Vec;

use super::PhysRegion;
use ept::FrameAllocator;

const PAGE_SIZE: u64 = 4096;

/// Free-stack allocator over a (potentially non-contiguous) set of physical pages.
///
/// Allocation order: pop from `free_stack`.  Freed pages are pushed back
/// onto `free_stack` for reuse.
///
/// Thread-safety is the caller's responsibility.
pub struct MetaAllocator {
    /// HHDM offset for phys→virt conversion.
    hhdm_offset: u64,
    /// Stack of free physical page addresses available for allocation.
    free_stack: Vec<u64>,
    /// Total number of pages ever added via `add_range`.
    total: u64,
    /// Number of pages currently allocated (total - free_stack.len()).
    allocated: u64,
}

impl MetaAllocator {
    /// Create a new empty allocator.
    pub fn new(hhdm_offset: u64) -> Self {
        Self {
            hhdm_offset,
            free_stack: Vec::new(),
            total: 0,
            allocated: 0,
        }
    }

    /// Add all 4 KiB-aligned pages of `[region.base, region.base + region.length)` to the pool.
    pub fn add_range(&mut self, region: PhysRegion) {
        assert!(region.base % PAGE_SIZE == 0, "META pool not page-aligned");
        assert!(region.length % PAGE_SIZE == 0, "META pool size not page-aligned");
        let pages = region.length / PAGE_SIZE;
        for i in 0..pages {
            self.free_stack.push(region.base + i * PAGE_SIZE);
        }
        self.total += pages;
    }

    /// Zero a page and return its physical address.
    fn zero_and_return(&self, phys: u64) -> u64 {
        let virt = (phys + self.hhdm_offset) as *mut u8;
        unsafe { core::ptr::write_bytes(virt, 0, PAGE_SIZE as usize) };
        phys
    }

    /// Allocate a single 4 KiB page, returning its physical address.
    ///
    /// The page is zeroed before being returned.
    ///
    /// # Panics
    /// Panics if the META pool is exhausted.
    pub fn alloc_frame(&mut self) -> u64 {
        let phys = self.free_stack.pop().expect("META pool exhausted");
        self.allocated += 1;
        self.zero_and_return(phys)
    }

    /// Return a previously-allocated page back to the pool.
    pub fn free_frame(&mut self, phys: u64) {
        self.free_stack.push(phys);
        self.allocated -= 1;
    }

    /// Return the virtual (HHDM) address corresponding to a physical address.
    #[allow(dead_code)]
    pub fn phys_to_virt(&self, phys: u64) -> *mut u8 {
        (phys + self.hhdm_offset) as *mut u8
    }

    /// Number of pages currently allocated.
    #[allow(dead_code)]
    pub fn allocated_pages(&self) -> u64 {
        self.allocated
    }

    /// Number of free pages remaining.
    #[allow(dead_code)]
    pub fn free_pages(&self) -> u64 {
        self.free_stack.len() as u64
    }

    /// Total capacity in pages.
    #[allow(dead_code)]
    pub fn total_pages(&self) -> u64 {
        self.total
    }
}

impl FrameAllocator for MetaAllocator {
    fn allocate_frame(&mut self) -> Option<u64> {
        if self.free_stack.is_empty() {
            return None;
        }
        Some(self.alloc_frame())
    }

    fn free_frame(&mut self, phys: u64) {
        self.free_frame(phys);
    }
}
