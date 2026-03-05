//! Physical memory inventory built from the Limine memory map.

use limine::memory_map::{Entry, EntryType};

/// Desired heap size (64 MiB).
const HEAP_SIZE: u64 = 64 * 1024 * 1024;

/// A contiguous physical memory region.
#[derive(Debug, Clone, Copy)]
pub struct PhysRegion {
    /// Physical base address (page-aligned).
    pub base: u64,
    /// Length in bytes.
    pub length: u64,
}

/// Physical memory inventory parsed from Limine's memory map.
///
/// After [`PhysicalInventory::from_limine`], the heap is initialized and the
/// remaining usable regions are available for Phase 1b partitioning.
pub struct PhysicalInventory {
    /// Usable regions *excluding* the heap.  Sorted by base address.
    /// Stored inline to avoid heap allocation before the heap is ready.
    regions: [PhysRegion; Self::MAX_REGIONS],
    /// Number of valid entries in `regions`.
    count: usize,
    /// Total usable RAM discovered (including heap).
    pub total_usable: u64,
    /// Heap physical base address.
    pub heap_phys: u64,
    /// Heap size in bytes.
    pub heap_size: u64,
}

impl PhysicalInventory {
    /// Maximum number of usable regions we track (generous for any real system).
    const MAX_REGIONS: usize = 128;

    /// Parse the Limine memory map, carve out a heap, and initialize the global
    /// allocator.
    ///
    /// # Arguments
    /// * `entries` — memory map entries from `MemoryMapResponse::entries()`
    /// * `hhdm_offset` — Higher-Half Direct Map offset from `HhdmResponse::offset()`
    ///
    /// # Panics
    /// Panics if no usable region is large enough for the heap.
    pub fn from_limine(entries: &[&Entry], hhdm_offset: u64) -> Self {
        let mut total_usable: u64 = 0;
        let mut regions = [PhysRegion { base: 0, length: 0 }; Self::MAX_REGIONS];
        let mut count = 0;

        // First pass: tally total usable memory and collect regions.
        for entry in entries {
            if entry.entry_type == EntryType::USABLE {
                total_usable += entry.length;
            }
        }

        // Find the largest usable region for the heap.
        let mut heap_region_idx: Option<usize> = None;
        let mut heap_region_base: u64 = 0;
        let mut heap_region_len: u64 = 0;

        for (i, entry) in entries.iter().enumerate() {
            if entry.entry_type == EntryType::USABLE && entry.length >= HEAP_SIZE {
                if heap_region_idx.is_none() || entry.length > heap_region_len {
                    heap_region_idx = Some(i);
                    heap_region_base = entry.base;
                    heap_region_len = entry.length;
                }
            }
        }

        let heap_idx = heap_region_idx.expect("no usable region large enough for 64 MiB heap");
        let heap_phys = heap_region_base;

        // Collect all usable regions, splitting the heap region as needed.
        for (i, entry) in entries.iter().enumerate() {
            if entry.entry_type != EntryType::USABLE {
                continue;
            }

            if i == heap_idx {
                // The heap is carved from the start of this region.
                // If there's space left after the heap, record the remainder.
                let remainder_base = entry.base + HEAP_SIZE;
                let remainder_len = entry.length - HEAP_SIZE;
                if remainder_len > 0 {
                    assert!(count < Self::MAX_REGIONS, "too many usable memory regions");
                    regions[count] = PhysRegion {
                        base: remainder_base,
                        length: remainder_len,
                    };
                    count += 1;
                }
            } else {
                assert!(count < Self::MAX_REGIONS, "too many usable memory regions");
                regions[count] = PhysRegion {
                    base: entry.base,
                    length: entry.length,
                };
                count += 1;
            }
        }

        // Initialize the global heap allocator.
        let heap_virt = (heap_phys + hhdm_offset) as usize;
        unsafe {
            super::super::ALLOCATOR.lock().init(heap_virt as *mut u8, HEAP_SIZE as usize);
        }

        Self {
            regions,
            count,
            total_usable,
            heap_phys,
            heap_size: HEAP_SIZE,
        }
    }

    /// Iterator over usable regions (excluding the heap).
    pub fn usable_regions(&self) -> &[PhysRegion] {
        &self.regions[..self.count]
    }

    /// Total usable memory excluding the heap.
    pub fn available_bytes(&self) -> u64 {
        self.usable_regions().iter().map(|r| r.length).sum()
    }
}
