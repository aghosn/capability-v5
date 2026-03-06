//! Physical memory inventory built from the Limine memory map.

use limine::memory_map::{Entry, EntryType};

/// Desired heap size (64 MiB).  Compile-time configurable.
const HEAP_SIZE: u64 = 64 * 1024 * 1024;

const PAGE_SIZE: u64 = 4096;
/// Entries per EPT page table level (512 for 4K pages in a 4-level structure).
const EPT_ENTRIES_PER_TABLE: u64 = 512;

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

/// Result of Phase 1b memory partitioning.
pub struct MemoryPartition {
    /// Regions given to dom0 as normal capabilities.
    pub dom0_owned: [PhysRegion; PhysicalInventory::MAX_REGIONS],
    /// Number of valid dom0_owned entries.
    pub dom0_owned_count: usize,
    /// META pool for dom0's hardware VP structures (VMXON, VMCS, VAPIC, EPT).
    pub meta_pool: PhysRegion,
    /// Breakdown of META pool usage.
    pub meta_breakdown: MetaBreakdown,
}

/// Breakdown of how the META pool is sized.
#[derive(Debug, Clone, Copy)]
pub struct MetaBreakdown {
    /// VMXON region pages (1 per physical core).
    pub vmxon_pages: u64,
    /// VMCS pages (1 per VP).
    pub vmcs_pages: u64,
    /// VAPIC pages (1 per VP).
    pub vapic_pages: u64,
    /// EPT page table pages (4K-only mapping).
    pub ept_pages: u64,
    /// Total META pages.
    pub total_pages: u64,
}

impl PhysicalInventory {
    /// Maximum number of usable regions we track (generous for any real system).
    pub const MAX_REGIONS: usize = 128;

    /// Parse the Limine memory map, carve out a heap, and initialize the global
    /// allocator.
    ///
    /// The heap is taken from the **top** of the USABLE entry with the highest
    /// physical end address that is large enough to hold the full heap.  This
    /// places the heap as high in physical memory as possible, well above the
    /// range where the Linux kernel and initrd are copied before VMLAUNCH
    /// (typically < 128 MiB).  The approach is robust across different machine
    /// sizes without requiring any hardcoded thresholds.
    ///
    /// The portion of the selected entry below the heap window is returned to
    /// dom0 as normal RAM.  The heap itself is emitted as a TYPE_RESERVED hole
    /// in the e820 table passed to Linux.
    ///
    /// # Arguments
    /// * `entries` — memory map entries from `MemoryMapResponse::entries()`
    /// * `hhdm_offset` — Higher-Half Direct Map offset from `HhdmResponse::offset()`
    ///
    /// # Panics
    /// Panics if no single usable region is large enough for the heap.
    pub fn from_limine(entries: &[&Entry], hhdm_offset: u64) -> Self {
        let mut total_usable: u64 = 0;
        let mut regions = [PhysRegion { base: 0, length: 0 }; Self::MAX_REGIONS];
        let mut count = 0;

        // First pass: tally total usable memory.
        for entry in entries {
            if entry.entry_type == EntryType::USABLE {
                total_usable += entry.length;
            }
        }

        // Find the USABLE entry with the highest physical end address that is
        // at least HEAP_SIZE bytes.  Taking the heap from the top of that entry
        // ensures it sits as high in RAM as possible.
        let mut heap_region_idx: Option<usize> = None;
        let mut heap_region_end: u64 = 0;

        for (i, entry) in entries.iter().enumerate() {
            if entry.entry_type == EntryType::USABLE && entry.length >= HEAP_SIZE {
                let end = entry.base + entry.length;
                if heap_region_idx.is_none() || end > heap_region_end {
                    heap_region_idx = Some(i);
                    heap_region_end = end;
                }
            }
        }

        let heap_idx = heap_region_idx.expect("no usable region large enough for 64 MiB heap");
        // Carve the heap window from the TOP of the selected region.
        let heap_phys = entries[heap_idx].base + entries[heap_idx].length - HEAP_SIZE;

        // Collect all usable regions, splitting the heap region as needed.
        // The heap window itself is excluded from dom0_owned; only the portion
        // below the window (if any) is kept as dom0 RAM.
        for (i, entry) in entries.iter().enumerate() {
            if entry.entry_type != EntryType::USABLE {
                continue;
            }

            if i == heap_idx {
                // Lower portion [entry.base..heap_phys) goes to dom0 as RAM.
                if heap_phys > entry.base {
                    assert!(count < Self::MAX_REGIONS, "too many usable memory regions");
                    regions[count] = PhysRegion {
                        base: entry.base,
                        length: heap_phys - entry.base,
                    };
                    count += 1;
                }
                // [heap_phys..entry.base+entry.length) is the heap — excluded.
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

    /// Usable regions (excluding the heap).
    pub fn usable_regions(&self) -> &[PhysRegion] {
        &self.regions[..self.count]
    }

    /// Total usable memory excluding the heap.
    pub fn available_bytes(&self) -> u64 {
        self.usable_regions().iter().map(|r| r.length).sum()
    }

    /// Partition usable memory into dom0-owned regions and a META pool.
    ///
    /// The META pool is sized minimally for dom0's own hardware VP structures:
    /// - VMXON: 1 page per physical core
    /// - VMCS: 1 page per VP (= per core for dom0)
    /// - VAPIC: 1 page per VP
    /// - EPT: enough 4K-granularity page table pages to map `dom0_mem_bytes`
    ///
    /// The equation: we need `x` META pages to map `(available - x*4K)` bytes
    /// of dom0 memory.  We solve iteratively (converges in 1–2 steps).
    ///
    /// # Arguments
    /// * `num_cores` — number of physical cores (from Limine MP response)
    pub fn partition(&self, num_cores: u64) -> MemoryPartition {
        let num_vps = num_cores; // dom0 gets one VP per core

        // Fixed per-VP/core overhead.
        let vmxon_pages = num_cores;
        let vmcs_pages = num_vps;
        let vapic_pages = num_vps;
        let fixed_pages = vmxon_pages + vmcs_pages + vapic_pages;

        // Solve for EPT pages: we need enough page table pages to map
        // (total_available - meta_pool_size) at 4K granularity.
        //
        // EPT structure (4-level, 4K pages only):
        //   L4: 1 page (PML4)
        //   L3: ceil(mapped_pages / 512³) pages (PDPT) — always 1 for < 512 GiB
        //   L2: ceil(mapped_pages / 512²) pages (PD)
        //   L1: ceil(mapped_pages / 512) pages (PT)
        let available = self.available_bytes();
        let mut meta_pages = fixed_pages;

        // Iterate: compute EPT pages needed for (available - meta*4K).
        // Converges in 1–2 iterations since EPT overhead is tiny.
        for _ in 0..3 {
            let dom0_bytes = available - meta_pages * PAGE_SIZE;
            let dom0_pages = dom0_bytes / PAGE_SIZE;

            let l1 = div_ceil(dom0_pages, EPT_ENTRIES_PER_TABLE);
            let l2 = div_ceil(dom0_pages, EPT_ENTRIES_PER_TABLE * EPT_ENTRIES_PER_TABLE);
            let l3 = div_ceil(
                dom0_pages,
                EPT_ENTRIES_PER_TABLE * EPT_ENTRIES_PER_TABLE * EPT_ENTRIES_PER_TABLE,
            );
            let l4 = 1;
            let ept_pages = l1 + l2 + l3 + l4;

            meta_pages = fixed_pages + ept_pages;
        }

        let ept_pages = meta_pages - fixed_pages;
        let meta_size = meta_pages * PAGE_SIZE;

        // Carve the META pool from the end of the largest region.
        let mut dom0_owned = self.regions;
        let mut dom0_owned_count = self.count;
        let mut meta_pool = PhysRegion { base: 0, length: 0 };

        // Find the largest region and carve META from its end.
        let mut largest_idx = 0;
        let mut largest_len: u64 = 0;
        for (i, r) in self.usable_regions().iter().enumerate() {
            if r.length > largest_len {
                largest_idx = i;
                largest_len = r.length;
            }
        }

        assert!(
            largest_len >= meta_size,
            "largest usable region ({} KiB) too small for META pool ({} KiB)",
            largest_len / 1024,
            meta_size / 1024,
        );

        // Shrink the region and place META at the end.
        let region = &mut dom0_owned[largest_idx];
        region.length -= meta_size;
        meta_pool = PhysRegion {
            base: region.base + region.length,
            length: meta_size,
        };

        MemoryPartition {
            dom0_owned,
            dom0_owned_count,
            meta_pool,
            meta_breakdown: MetaBreakdown {
                vmxon_pages,
                vmcs_pages,
                vapic_pages,
                ept_pages,
                total_pages: meta_pages,
            },
        }
    }
}

/// Integer ceiling division.
fn div_ceil(a: u64, b: u64) -> u64 {
    (a + b - 1) / b
}
