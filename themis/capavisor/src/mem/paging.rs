//! Minimal page table manipulation for adding HHDM mappings.
//!
//! Limine base revision 3 only HHDM-maps usable/bootloader/kernel+modules/FB
//! regions.  ACPI reclaimable and NVS regions are **not** mapped.  This module
//! adds 4 KiB page table entries for those regions so the `acpi` crate can
//! read firmware tables through the HHDM.
//!
//! Uses x86-64 4-level paging (PML4 → PDP → PD → PT).

use core::arch::asm;

const PAGE_SIZE: u64 = 4096;
const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const NO_EXECUTE: u64 = 1 << 63;

/// Map a physical range into the HHDM virtual address space by
/// walking/creating 4-level page table entries.
///
/// Pages are mapped as present + writable + NX (data, not code).
/// New page table pages are allocated from the global heap.
pub fn map_phys_range(phys_base: u64, length: u64, hhdm_offset: u64) {
    let start = phys_base & !(PAGE_SIZE - 1);
    let end = (phys_base + length + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let pml4_phys = read_cr3() & !0xFFF;

    let mut addr = start;
    while addr < end {
        let virt = addr + hhdm_offset;
        ensure_mapping(pml4_phys, virt, addr, hhdm_offset);
        addr += PAGE_SIZE;
    }

    // Flush TLB for the mapped range.
    let mut addr = start;
    while addr < end {
        let virt = addr + hhdm_offset;
        unsafe { asm!("invlpg [{}]", in(reg) virt, options(nostack, preserves_flags)) };
        addr += PAGE_SIZE;
    }
}

fn read_cr3() -> u64 {
    let cr3: u64;
    unsafe { asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack)) };
    cr3
}

/// Walk the 4-level page table, creating intermediate tables as needed,
/// and insert a 4 KiB PTE mapping `virt` → `phys`.
fn ensure_mapping(pml4_phys: u64, virt: u64, phys: u64, hhdm: u64) {
    let pml4_idx = ((virt >> 39) & 0x1FF) as usize;
    let pdp_idx = ((virt >> 30) & 0x1FF) as usize;
    let pd_idx = ((virt >> 21) & 0x1FF) as usize;
    let pt_idx = ((virt >> 12) & 0x1FF) as usize;

    let pml4 = (pml4_phys + hhdm) as *mut u64;
    let pdp_phys = ensure_table(pml4, pml4_idx, hhdm);
    let pdp = (pdp_phys + hhdm) as *mut u64;

    // Check for 1 GiB huge page — if present, the region is already mapped.
    let pdp_entry = unsafe { pdp.add(pdp_idx).read_volatile() };
    if pdp_entry & PRESENT != 0 && pdp_entry & (1 << 7) != 0 {
        return; // 1 GiB page covers this address
    }

    let pd_phys = ensure_table(pdp, pdp_idx, hhdm);
    let pd = (pd_phys + hhdm) as *mut u64;

    // Check for 2 MiB huge page.
    let pd_entry = unsafe { pd.add(pd_idx).read_volatile() };
    if pd_entry & PRESENT != 0 && pd_entry & (1 << 7) != 0 {
        return; // 2 MiB page covers this address
    }

    let pt_phys = ensure_table(pd, pd_idx, hhdm);
    let pt = (pt_phys + hhdm) as *mut u64;

    // Set the PTE if not already present.
    let pte = unsafe { pt.add(pt_idx).read_volatile() };
    if pte & PRESENT == 0 {
        let new_pte = phys | PRESENT | WRITABLE | NO_EXECUTE;
        unsafe { pt.add(pt_idx).write_volatile(new_pte) };
    }
}

/// Ensure that `table[index]` points to a valid next-level page table.
/// If the entry is not present, allocate a zeroed 4 KiB page from the heap.
/// Returns the **physical** address of the next-level table.
fn ensure_table(table: *mut u64, index: usize, hhdm: u64) -> u64 {
    let entry = unsafe { table.add(index).read_volatile() };
    if entry & PRESENT != 0 {
        return entry & 0x000F_FFFF_FFFF_F000;
    }

    // Allocate a new page table page from the global heap.
    let layout = core::alloc::Layout::from_size_align(PAGE_SIZE as usize, PAGE_SIZE as usize)
        .expect("bad layout");
    let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
    assert!(!ptr.is_null(), "OOM allocating page table page");

    // Convert virtual heap address to physical.
    let virt_addr = ptr as u64;
    let phys_addr = virt_addr - hhdm;

    let new_entry = phys_addr | PRESENT | WRITABLE;
    unsafe { table.add(index).write_volatile(new_entry) };

    phys_addr
}
