//! Physical memory inventory built from the Limine memory map.

use limine::memory_map::{Entry, EntryType};

const PAGE_SIZE: u64 = 4096;
/// Entries per EPT page table level (512 for 4K pages in a 4-level structure).
const EPT_ENTRIES_PER_TABLE: u64 = 512;
/// Maximum number of META physical regions (spanning multiple disjoint e820 entries).
pub const MAX_META_REGIONS: usize = 16;

/// A contiguous physical memory region.
#[derive(Debug, Clone, Copy)]
pub struct PhysRegion {
    pub base: u64,
    pub length: u64,
}

/// Physical memory inventory parsed from Limine's memory map.
///
/// After [`PhysicalInventory::from_limine`], all usable regions are available
/// for partitioning.  The heap is NOT carved here — it lives in the capavisor
/// BSS (see `crate::HEAP`) and is handled by the bootloader.
pub struct PhysicalInventory {
    /// All usable regions from Limine, sorted by base address.
    regions: [PhysRegion; Self::MAX_REGIONS],
    count: usize,
    /// Total usable RAM discovered.
    pub total_usable: u64,
}

/// Result of Phase 1b memory partitioning.
pub struct MemoryPartition {
    /// Regions given to dom0 as normal RAM capabilities.
    pub dom0_owned: [PhysRegion; PhysicalInventory::MAX_REGIONS],
    pub dom0_owned_count: usize,
    /// META physical regions (one per disjoint usable entry fragment), sorted
    /// by base address, taken from the TOP of usable physical memory.
    pub meta_regions: [PhysRegion; MAX_META_REGIONS],
    pub meta_count: usize,
    /// Breakdown of META pool usage.
    pub meta_breakdown: MetaBreakdown,
}

/// Breakdown of how the META pool is sized.
#[derive(Debug, Clone, Copy)]
pub struct MetaBreakdown {
    pub vmxon_pages: u64,
    pub vmcs_pages: u64,
    pub vapic_pages: u64,
    pub ept_pages: u64,
    pub total_pages: u64,
}

impl MetaBreakdown {
    pub fn total_bytes(&self) -> u64 { self.total_pages * PAGE_SIZE }
}

impl PhysicalInventory {
    pub const MAX_REGIONS: usize = 128;

    /// Parse the Limine memory map and collect all usable regions.
    ///
    /// The heap is NOT carved here — it is backed by the static `crate::HEAP`
    /// BSS array, which Limine places and maps as part of the kernel binary.
    ///
    /// # Arguments
    /// * `entries` — memory map entries from `MemoryMapResponse::entries()`
    pub fn from_limine(entries: &[&Entry]) -> Self {
        let mut total_usable: u64 = 0;
        let mut regions = [PhysRegion { base: 0, length: 0 }; Self::MAX_REGIONS];
        let mut count = 0usize;

        for entry in entries {
            if entry.entry_type == EntryType::USABLE {
                total_usable += entry.length;
                assert!(count < Self::MAX_REGIONS, "too many usable memory regions");
                regions[count] = PhysRegion { base: entry.base, length: entry.length };
                count += 1;
            }
        }

        Self { regions, count, total_usable }
    }

    /// Usable regions (all of them, pre-META partitioning).
    pub fn usable_regions(&self) -> &[PhysRegion] {
        &self.regions[..self.count]
    }

    /// Total usable memory.
    pub fn available_bytes(&self) -> u64 {
        self.total_usable
    }

    /// Partition usable memory into dom0-owned regions and a META pool.
    ///
    /// META is collected from the **top of physical memory** (highest physical
    /// addresses first) to keep it as far as possible from the low-memory
    /// kernel+initrd copy range.  It may span multiple disjoint usable entries.
    ///
    /// The iterative EPT-page calculation is the same as before (converges in
    /// 1–2 steps).
    ///
    /// # Arguments
    /// * `num_cores` — number of physical cores (from Limine MP response)
    pub fn partition(&self, num_cores: u64) -> MemoryPartition {
        let num_vps = num_cores;

        let vmxon_pages = num_cores;
        let vmcs_pages  = num_vps;
        let vapic_pages = num_vps;
        let fixed_pages = vmxon_pages + vmcs_pages + vapic_pages;

        // Iteratively solve for EPT pages.
        let available = self.available_bytes();
        let mut meta_pages = fixed_pages;
        for _ in 0..3 {
            let dom0_bytes = available.saturating_sub(meta_pages * PAGE_SIZE);
            let dom0_pages = dom0_bytes / PAGE_SIZE;
            let l1 = div_ceil(dom0_pages, EPT_ENTRIES_PER_TABLE);
            let l2 = div_ceil(dom0_pages, EPT_ENTRIES_PER_TABLE * EPT_ENTRIES_PER_TABLE);
            let l3 = div_ceil(dom0_pages,
                EPT_ENTRIES_PER_TABLE * EPT_ENTRIES_PER_TABLE * EPT_ENTRIES_PER_TABLE);
            let l4 = 1u64;
            meta_pages = fixed_pages + l1 + l2 + l3 + l4;
        }
        let ept_pages  = meta_pages - fixed_pages;
        let meta_size  = meta_pages * PAGE_SIZE;

        // Collect META from the TOP of usable physical memory.
        // Work through self.regions in reverse (highest base last after Limine sort).
        let mut meta_regions  = [PhysRegion { base: 0, length: 0 }; MAX_META_REGIONS];
        let mut meta_count    = 0usize;
        let mut meta_needed   = meta_size;

        // dom0_owned starts as a copy of all regions; we'll trim/remove entries
        // consumed by META.
        let mut dom0_owned       = self.regions;
        let mut dom0_owned_count = self.count;

        // Walk from the highest-address region backwards.
        let mut ri = self.count; // index into self.regions (will be decremented)
        while meta_needed > 0 && ri > 0 {
            ri -= 1;
            let region = self.regions[ri];
            if region.length == 0 { continue; }

            let take = region.length.min(meta_needed);
            let meta_base = region.base + region.length - take;

            // Record this META fragment (prepend to keep ascending order).
            // Shift existing entries up to insert at front.
            if meta_count < MAX_META_REGIONS {
                // Shift entries [0..meta_count) one position right.
                let mut i = meta_count;
                while i > 0 { meta_regions[i] = meta_regions[i-1]; i -= 1; }
                meta_regions[0] = PhysRegion { base: meta_base, length: take };
                meta_count += 1;
            }
            meta_needed -= take;

            // Update dom0_owned: find this region's entry (by base) and shrink/remove it.
            for d in 0..dom0_owned_count {
                if dom0_owned[d].base == region.base {
                    if take == region.length {
                        // Entire entry consumed — remove it by shifting down.
                        let mut j = d;
                        while j + 1 < dom0_owned_count {
                            dom0_owned[j] = dom0_owned[j+1];
                            j += 1;
                        }
                        dom0_owned_count -= 1;
                    } else {
                        // Partial: shrink the entry (take from the top).
                        dom0_owned[d].length -= take;
                    }
                    break;
                }
            }
        }

        assert!(meta_needed == 0,
            "not enough usable memory for META pool ({} KiB needed)",
            meta_size / 1024);

        MemoryPartition {
            dom0_owned,
            dom0_owned_count,
            meta_regions,
            meta_count,
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

fn div_ceil(a: u64, b: u64) -> u64 {
    (a + b - 1) / b
}
