//! Per-domain META frame allocator.
//!
//! Each domain owns a contiguous physical META pool from which it allocates
//! 4 KiB-aligned pages for hardware VP structures (VMXON, VMCS, VAPIC, EPT).
//!
//! Fresh pages come from a bump pointer.  Freed pages are pushed onto a
//! `Vec`-backed free stack and reused before bumping further.

extern crate alloc;
use alloc::vec::Vec;

use super::PhysRegion;
use ept::FrameAllocator;

const PAGE_SIZE: u64 = 4096;

/// Bump allocator with a free stack over a contiguous physical memory region.
///
/// Allocation order: pop from `free_stack` first; if empty, advance the bump
/// pointer.  Freed pages are pushed onto `free_stack` for reuse.
///
/// Thread-safety is the caller's responsibility.
pub struct MetaAllocator {
    /// Physical base of the META pool.
    base: u64,
    /// Total size of the pool in bytes.
    size: u64,
    /// Byte offset of the next *never-used* page (relative to `base`).
    next: u64,
    /// HHDM offset for phys→virt conversion.
    hhdm_offset: u64,
    /// Stack of freed physical page addresses available for reuse.
    free_stack: Vec<u64>,
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
            free_stack: Vec::new(),
        }
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
        if let Some(phys) = self.free_stack.pop() {
            return self.zero_and_return(phys);
        }
        assert!(
            self.next + PAGE_SIZE <= self.size,
            "META pool exhausted ({} / {} bytes used)",
            self.next,
            self.size
        );
        let phys = self.base + self.next;
        self.next += PAGE_SIZE;
        self.zero_and_return(phys)
    }

    /// Return a previously-allocated page back to the pool.
    pub fn free_frame(&mut self, phys: u64) {
        debug_assert!(
            phys >= self.base && phys < self.base + self.size && phys % PAGE_SIZE == 0,
            "free_frame: address 0x{:x} not in META pool",
            phys
        );
        self.free_stack.push(phys);
    }

    /// Return the virtual (HHDM) address corresponding to a physical address
    /// within this pool.
    pub fn phys_to_virt(&self, phys: u64) -> *mut u8 {
        debug_assert!(phys >= self.base && phys < self.base + self.size);
        (phys + self.hhdm_offset) as *mut u8
    }

    /// Number of pages currently in use (bumped minus freed).
    pub fn allocated_pages(&self) -> u64 {
        self.next / PAGE_SIZE - self.free_stack.len() as u64
    }

    /// Number of free pages remaining (virgin bump pages + free stack).
    pub fn free_pages(&self) -> u64 {
        (self.size - self.next) / PAGE_SIZE + self.free_stack.len() as u64
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

impl FrameAllocator for MetaAllocator {
    fn allocate_frame(&mut self) -> Option<u64> {
        if self.free_stack.is_empty() && self.next + PAGE_SIZE > self.size {
            return None;
        }
        Some(self.alloc_frame())
    }

    fn free_frame(&mut self, phys: u64) {
        self.free_frame(phys);
    }
}
