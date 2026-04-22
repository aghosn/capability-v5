//! AArch64 Stage-2 page tables (guest physical → host physical).
//!
//! ARM's Stage-2 translation is the equivalent of Intel EPT. Each domain
//! gets its own Stage-2 page table tree, selected via VTTBR_EL2.
//!
//! Page table format: 4KB granule, up to 4 levels (L0→L3).
//! We support 4KB pages, 2MB blocks (L2), and 1GB blocks (L1).
//!
//! VTCR_EL2 controls Stage-2 translation parameters; it is configured
//! once at boot time.

extern crate alloc;

use alloc::vec::Vec;
use core::ptr;

use crate::arch_traits::types::{MapPermissions, PageSize};
use crate::serial_println;

// ── Stage-2 descriptor bits ──────────────────────────────────────────────── //

/// Valid bit.
const S2_VALID: u64 = 1 << 0;
/// Table descriptor (L0/L1/L2 pointing to next-level table).
const S2_TABLE: u64 = 1 << 1;
/// Page descriptor at L3 (bit[1] = 1 for L3 page, 0 for block at L1/L2).
const S2_PAGE: u64 = 1 << 1;
/// Access flag — must be set.
const S2_AF: u64 = 1 << 10;
/// Inner Shareable.
const S2_SH_INNER: u64 = 0b11 << 8;

// Stage-2 memory attributes (MemAttr[3:2] in bits[5:4], MemAttr[1:0] in bits[3:2])
// For Stage-2, the memory type encoding is different from Stage-1 (no MAIR).
// Bits[5:4] = MemAttr[3:2], bits[3:2] = MemAttr[1:0].

/// Normal memory, Inner/Outer Write-Back (MemAttr = 0b1111).
const S2_MEM_NORMAL_WB: u64 = 0b1111 << 2;
/// Device-nGnRnE (MemAttr = 0b0000).
const S2_MEM_DEVICE: u64 = 0b0000 << 2;

// Stage-2 access permissions (S2AP bits[7:6]).
/// Read-only.
const S2_AP_RO: u64 = 0b01 << 6;
/// Write-only.
const S2_AP_WO: u64 = 0b10 << 6;
/// Read-write.
const S2_AP_RW: u64 = 0b11 << 6;

// Stage-2 execute permissions.
// XN[1:0] bits[54:53] for Stage-2 (different from Stage-1).
/// Execute-never for EL1 (XN[0]).
const S2_XN_EL1: u64 = 1 << 53;
/// Execute-never for EL0 (XN[1]).
const S2_XN_EL0: u64 = 1 << 54;
/// Both EL0 and EL1 execute-never.
const S2_XN_ALL: u64 = S2_XN_EL1 | S2_XN_EL0;

// ── Page sizes ───────────────────────────────────────────────────────────── //

const PAGE_SIZE_4K: u64 = 0x1000;
const PAGE_SIZE_2M: u64 = 0x20_0000;
const PAGE_SIZE_1G: u64 = 0x4000_0000;

/// Number of entries per table (512 for 4KB granule).
const ENTRIES_PER_TABLE: usize = 512;

// ── Stage-2 map handle ───────────────────────────────────────────────────── //

/// Per-domain Stage-2 translation state.
///
/// Owns the root page table and tracks allocated table pages for cleanup.
pub struct Stage2Map {
    /// Physical address of the L0 root table (goes into VTTBR_EL2).
    root_phys: u64,
    /// Virtual pointer to the root table (identity-mapped, so == root_phys).
    root_ptr: *mut u64,
    /// All allocated table pages (for cleanup on destroy).
    allocated_tables: Vec<*mut u64>,
}

impl Stage2Map {
    /// Create a new empty Stage-2 map.
    pub fn new() -> Self {
        // Allocate root table (must be page-aligned).
        let root = alloc_page_table();
        let root_phys = root as u64; // Identity-mapped.
        Stage2Map {
            root_phys,
            root_ptr: root,
            allocated_tables: alloc::vec![root],
        }
    }

    /// Physical address of the root table (for VTTBR_EL2).
    pub fn root_phys(&self) -> u64 {
        self.root_phys
    }

    /// Map a guest physical address (IPA) to a host physical address.
    ///
    /// With VTCR_EL2.SL0=1, the page table walk starts at L1 (root = L1).
    pub fn map(&mut self, ipa: u64, hpa: u64, size: PageSize, perms: &MapPermissions) {
        let desc = build_descriptor(hpa, size, perms);
        match size {
            PageSize::Page1G => {
                // L1 block descriptor (root table entry).
                let l1_idx = ((ipa >> 30) & 0x1FF) as usize;
                unsafe { self.root_ptr.add(l1_idx).write_volatile(desc) };
            }
            PageSize::Page2M => {
                // L1 → L2 block descriptor.
                let l1_idx = ((ipa >> 30) & 0x1FF) as usize;
                let l2 = self.ensure_table(self.root_ptr, l1_idx);
                let l2_idx = ((ipa >> 21) & 0x1FF) as usize;
                unsafe { l2.add(l2_idx).write_volatile(desc) };
            }
            PageSize::Page4K => {
                // L1 → L2 → L3 page descriptor.
                let l1_idx = ((ipa >> 30) & 0x1FF) as usize;
                let l2 = self.ensure_table(self.root_ptr, l1_idx);
                let l2_idx = ((ipa >> 21) & 0x1FF) as usize;
                let l3 = self.ensure_table(l2, l2_idx);
                let l3_idx = ((ipa >> 12) & 0x1FF) as usize;
                unsafe { l3.add(l3_idx).write_volatile(desc) };
            }
        }
    }

    /// Unmap a guest physical page/block.
    pub fn unmap(&mut self, ipa: u64, size: PageSize) {
        match size {
            PageSize::Page1G => {
                let l1_idx = ((ipa >> 30) & 0x1FF) as usize;
                unsafe { self.root_ptr.add(l1_idx).write_volatile(0) };
            }
            PageSize::Page2M => {
                let l1_idx = ((ipa >> 30) & 0x1FF) as usize;
                if let Some(l2) = self.get_table(self.root_ptr, l1_idx) {
                    let l2_idx = ((ipa >> 21) & 0x1FF) as usize;
                    unsafe { l2.add(l2_idx).write_volatile(0) };
                }
            }
            PageSize::Page4K => {
                let l1_idx = ((ipa >> 30) & 0x1FF) as usize;
                if let Some(l2) = self.get_table(self.root_ptr, l1_idx) {
                    let l2_idx = ((ipa >> 21) & 0x1FF) as usize;
                    if let Some(l3) = self.get_table(l2, l2_idx) {
                        let l3_idx = ((ipa >> 12) & 0x1FF) as usize;
                        unsafe { l3.add(l3_idx).write_volatile(0) };
                    }
                }
            }
        }
    }

    /// Flush Stage-2 TLB for this address space.
    ///
    /// Uses VMID-based invalidation when available, otherwise invalidates all.
    pub fn flush(&self) {
        unsafe {
            // TLBI VMALLS12E1IS — invalidate all Stage-1 and Stage-2 TLB
            // entries for the current VMID (set in VTTBR_EL2).
            core::arch::asm!(
                "dsb ishst",
                "tlbi vmalls12e1is",
                "dsb ish",
                "isb",
                options(nostack),
            );
        }
    }

    /// Ensure a table entry at `table[idx]` points to a next-level table.
    /// If the entry is empty, allocate a new table and install it.
    /// Returns a pointer to the next-level table.
    fn ensure_table(&mut self, table: *mut u64, idx: usize) -> *mut u64 {
        let entry = unsafe { table.add(idx).read_volatile() };
        if entry & S2_VALID != 0 && entry & S2_TABLE != 0 {
            // Already a table descriptor — extract the address.
            let next_phys = entry & 0x0000_FFFF_FFFF_F000;
            next_phys as *mut u64
        } else {
            // Allocate a new table.
            let new_table = alloc_page_table();
            self.allocated_tables.push(new_table);
            let new_phys = new_table as u64;
            let desc = S2_VALID | S2_TABLE | (new_phys & 0x0000_FFFF_FFFF_F000);
            unsafe { table.add(idx).write_volatile(desc) };
            new_table
        }
    }

    /// Get next-level table from an existing entry, or None.
    fn get_table(&self, table: *mut u64, idx: usize) -> Option<*mut u64> {
        let entry = unsafe { table.add(idx).read_volatile() };
        if entry & S2_VALID != 0 && entry & S2_TABLE != 0 {
            let next_phys = entry & 0x0000_FFFF_FFFF_F000;
            Some(next_phys as *mut u64)
        } else {
            None
        }
    }
}

impl Drop for Stage2Map {
    fn drop(&mut self) {
        // Free all allocated table pages.
        for &table_ptr in &self.allocated_tables {
            let layout = core::alloc::Layout::from_size_align(PAGE_SIZE_4K as usize, PAGE_SIZE_4K as usize).unwrap();
            unsafe { alloc::alloc::dealloc(table_ptr as *mut u8, layout) };
        }
    }
}

// ── Descriptor builders ──────────────────────────────────────────────────── //

/// Build a Stage-2 block or page descriptor.
fn build_descriptor(hpa: u64, size: PageSize, perms: &MapPermissions) -> u64 {
    let mut desc = S2_VALID | S2_AF | S2_SH_INNER | S2_MEM_NORMAL_WB;

    // Output address.
    match size {
        PageSize::Page1G => {
            desc |= hpa & 0x0000_FFFF_C000_0000; // PA[47:30]
            // L1 block: bit[1] = 0
        }
        PageSize::Page2M => {
            desc |= hpa & 0x0000_FFFF_FFE0_0000; // PA[47:21]
            // L2 block: bit[1] = 0
        }
        PageSize::Page4K => {
            desc |= hpa & 0x0000_FFFF_FFFF_F000; // PA[47:12]
            desc |= S2_PAGE; // L3 page: bit[1] = 1
        }
    }

    // Access permissions.
    desc |= match (perms.read, perms.write) {
        (true, true) => S2_AP_RW,
        (true, false) => S2_AP_RO,
        (false, true) => S2_AP_WO,
        (false, false) => 0, // No access
    };

    // Execute permissions.
    if !perms.execute {
        desc |= S2_XN_ALL;
    }

    desc
}

// ── Page table allocation ────────────────────────────────────────────────── //

/// Allocate a zeroed, page-aligned 4KB page table.
fn alloc_page_table() -> *mut u64 {
    let layout = core::alloc::Layout::from_size_align(PAGE_SIZE_4K as usize, PAGE_SIZE_4K as usize).unwrap();
    let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
    assert!(!ptr.is_null(), "Stage-2: out of memory for page table");
    ptr as *mut u64
}

// ── VTCR_EL2 configuration ──────────────────────────────────────────────── //

/// Configure VTCR_EL2 (Virtualization Translation Control Register).
///
/// This is a one-time operation at boot. It sets the Stage-2 translation
/// parameters that apply to all domains.
///
/// # Safety
/// Must be called at EL2, once during boot.
pub unsafe fn configure_vtcr() {
    // Read PA size from ID_AA64MMFR0_EL1.
    let mmfr0: u64;
    core::arch::asm!("mrs {}, ID_AA64MMFR0_EL1", out(reg) mmfr0, options(nostack));
    let pa_range = mmfr0 & 0xF;

    let mut vtcr: u64 = 0;
    // T0SZ = 25 → 39-bit IPA (512 GiB guest address space)
    // With SL0=1 and 4KB granule, the L1 table has 512 entries (= one 4K page).
    // No concatenation needed.
    vtcr |= 25; // bits[5:0]
    // SL0 = 0b01 → start at L1 (for 40-bit IPA with 4KB granule)
    vtcr |= 0b01 << 6;
    // IRGN0 = 0b01 → Inner Write-Back, Write-Allocate (for table walks)
    vtcr |= 0b01 << 8;
    // ORGN0 = 0b01 → Outer Write-Back, Write-Allocate
    vtcr |= 0b01 << 10;
    // SH0 = 0b11 → Inner Shareable
    vtcr |= 0b11 << 12;
    // TG0 = 0b00 → 4KB granule
    // (bits[15:14] = 0b00, already zero)
    // PS = PA size from ID_AA64MMFR0_EL1
    vtcr |= (pa_range & 0x7) << 16;
    // RES1 bit 31
    vtcr |= 1 << 31;

    core::arch::asm!("msr VTCR_EL2, {}", in(reg) vtcr, options(nostack));
    core::arch::asm!("isb", options(nostack));

    serial_println!(
        "VTCR_EL2 configured: T0SZ=25, SL0=1, TG0=4K, PS={} (VTCR={:#x})",
        pa_range, vtcr
    );
}

/// Load a Stage-2 map into VTTBR_EL2 for the given VMID.
///
/// After this call, Stage-2 translations use the given page tables.
/// HCR_EL2.VM must be set to enable Stage-2 translation.
///
/// # Safety
/// Must be called at EL2.
pub unsafe fn load_vttbr(map: &Stage2Map, vmid: u16) {
    let vttbr = ((vmid as u64) << 48) | map.root_phys();
    core::arch::asm!(
        "msr VTTBR_EL2, {}",
        "isb",
        in(reg) vttbr,
        options(nostack),
    );
}
