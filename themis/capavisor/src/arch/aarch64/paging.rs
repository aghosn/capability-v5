//! Minimal page table manipulation for adding HHDM mappings on AArch64.
//!
//! Limine base revision 0 identity-maps the first 4 GiB, but META/COMM
//! regions are accessed through the HHDM (phys + hhdm_offset).  This module
//! walks the Limine-provided EL1 page tables (TTBR1_EL1) and adds 4 KiB
//! entries for physical ranges that may not be HHDM-mapped by the bootloader.
//!
//! Uses AArch64 4-level page tables (L0 → L1 → L2 → L3) with 4 KiB granule.

extern crate alloc;

use core::arch::asm;

const PAGE_SIZE: u64 = 4096;

// AArch64 descriptor bits (stage-1, 4 KiB granule).
const VALID: u64 = 1 << 0;
const TABLE: u64 = 1 << 1; // For L0–L2 table descriptors
const PAGE_DESC: u64 = 0b11; // L3 page descriptor (bits [1:0] = 0b11)
const AF: u64 = 1 << 10; // Access flag (must be set or fault)
const AP_RW_EL1: u64 = 0b00 << 6; // AP[2:1] = 00 → EL1 RW
const SH_INNER: u64 = 0b11 << 8; // Inner Shareable
const UXN: u64 = 1 << 54; // Unprivileged execute-never
const PXN: u64 = 1 << 53; // Privileged execute-never

// AttrIndx for normal memory (assumes MAIR index 0 = Normal WB, as Limine sets up).
const ATTR_NORMAL: u64 = 0 << 2;

/// Output address mask: bits [47:12] for 4 KiB granule.
const OA_MASK: u64 = 0x0000_FFFF_FFFF_F000;

/// Map a physical range into the HHDM virtual address space by
/// walking/creating 4-level AArch64 page table entries (TTBR1_EL1).
///
/// Pages are mapped as present + RW + NX (data, not code).
/// New page table pages are allocated from the global heap.
pub fn map_phys_range(phys_base: u64, length: u64, hhdm_offset: u64) {
    let start = phys_base & !(PAGE_SIZE - 1);
    let end = (phys_base + length + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let ttbr1 = read_ttbr1_el1() & OA_MASK;

    let mut addr = start;
    while addr < end {
        let virt = addr.wrapping_add(hhdm_offset);
        ensure_mapping(ttbr1, virt, addr, hhdm_offset);
        addr += PAGE_SIZE;
    }

    // TLB invalidate for the mapped range.
    let mut addr = start;
    while addr < end {
        let virt = addr.wrapping_add(hhdm_offset);
        unsafe {
            // TLBI VAE1IS — invalidate by VA, EL1, inner-shareable.
            // The VA is shifted right by 12 (page granule).
            let tlbi_val = virt >> 12;
            asm!("tlbi vae1is, {}", in(reg) tlbi_val, options(nostack));
        }
        addr += PAGE_SIZE;
    }
    // Ensure TLB invalidation is complete.
    unsafe {
        asm!("dsb ish", options(nostack));
        asm!("isb", options(nostack));
    }
}

fn read_ttbr1_el1() -> u64 {
    let val: u64;
    unsafe { asm!("mrs {}, ttbr1_el1", out(reg) val, options(nomem, nostack)) };
    val
}

/// Walk the 4-level page table (L0 → L1 → L2 → L3), creating intermediate
/// tables as needed, and insert a 4 KiB page descriptor mapping `virt` → `phys`.
fn ensure_mapping(l0_phys: u64, virt: u64, phys: u64, hhdm: u64) {
    let l0_idx = ((virt >> 39) & 0x1FF) as usize;
    let l1_idx = ((virt >> 30) & 0x1FF) as usize;
    let l2_idx = ((virt >> 21) & 0x1FF) as usize;
    let l3_idx = ((virt >> 12) & 0x1FF) as usize;

    let l0 = phys_to_virt(l0_phys, hhdm) as *mut u64;

    // L0 → L1 table
    let l1_entry = unsafe { l0.add(l0_idx).read_volatile() };
    if l1_entry & VALID != 0 && l1_entry & TABLE == 0 {
        return; // Block descriptor at L0 (512 GiB — unlikely but bail)
    }
    let l1_phys = ensure_table(l0, l0_idx, hhdm);
    let l1 = phys_to_virt(l1_phys, hhdm) as *mut u64;

    // L1: check for 1 GiB block descriptor
    let l1_entry = unsafe { l1.add(l1_idx).read_volatile() };
    if l1_entry & VALID != 0 && l1_entry & TABLE == 0 {
        return; // 1 GiB block covers this address
    }
    let l2_phys = ensure_table(l1, l1_idx, hhdm);
    let l2 = phys_to_virt(l2_phys, hhdm) as *mut u64;

    // L2: check for 2 MiB block descriptor
    let l2_entry = unsafe { l2.add(l2_idx).read_volatile() };
    if l2_entry & VALID != 0 && l2_entry & TABLE == 0 {
        return; // 2 MiB block covers this address
    }
    let l3_phys = ensure_table(l2, l2_idx, hhdm);
    let l3 = phys_to_virt(l3_phys, hhdm) as *mut u64;

    // L3: insert 4 KiB page descriptor if not already present.
    let pte = unsafe { l3.add(l3_idx).read_volatile() };
    if pte & VALID == 0 {
        let new_pte = phys | PAGE_DESC | AF | AP_RW_EL1 | SH_INNER | ATTR_NORMAL | UXN | PXN;
        unsafe { l3.add(l3_idx).write_volatile(new_pte) };
    }
}

/// Convert physical address to virtual via HHDM or identity map.
fn phys_to_virt(phys: u64, hhdm: u64) -> u64 {
    // Use wrapping_add to handle the higher-half offset without overflow panic.
    phys.wrapping_add(hhdm)
}

/// Ensure that `table[index]` points to a valid next-level table descriptor.
/// If the entry is not valid, allocate a zeroed 4 KiB page from the heap.
/// Returns the **physical** address of the next-level table.
fn ensure_table(table: *mut u64, index: usize, hhdm: u64) -> u64 {
    let entry = unsafe { table.add(index).read_volatile() };
    if entry & VALID != 0 {
        return entry & OA_MASK;
    }

    // Allocate a new page table page from the global heap.
    let layout = core::alloc::Layout::from_size_align(PAGE_SIZE as usize, PAGE_SIZE as usize)
        .expect("bad layout");
    let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
    assert!(!ptr.is_null(), "OOM allocating page table page");

    // Convert virtual address to physical.
    let virt_addr = ptr as u64;
    let kern_virt = crate::KERNEL_VIRT_BASE.load(core::sync::atomic::Ordering::Relaxed);
    let phys_addr = if kern_virt != 0 && virt_addr >= kern_virt {
        let kern_phys = crate::KERNEL_PHYS_BASE.load(core::sync::atomic::Ordering::Relaxed);
        virt_addr - kern_virt + kern_phys
    } else {
        virt_addr.wrapping_sub(hhdm)
    };

    // Table descriptor: OA | TABLE | VALID
    let new_entry = phys_addr | TABLE | VALID;
    unsafe { table.add(index).write_volatile(new_entry) };

    phys_addr
}
