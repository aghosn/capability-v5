//! x86 page-table walkers (Extended Page Tables (EPT) + 4-level guest paging).
//!
//! Used by the MMIO instruction decoder (`forward_interrupt_to_handler` in
//! `hypercall::switch`, plus the CR-access emulation in `vmexit`) to translate
//! a Guest Virtual Address (GVA) → Guest Physical Address (GPA) → Host
//! Physical Address (HPA) without taking VMEXITs.
//!
//! Layout assumptions:
//!   * 4-level paging (PML4 / PDPT / PD / PT), 9-bit indices, 4 KiB pages.
//!   * Large pages allowed at PDPT (level 2) and PD (level 1) via PS bit 7.
//!   * EPT entries use the same 52-bit physical-address mask
//!     (`0x000F_FFFF_FFFF_F000`).

/// Walk a 4-level EPT to translate `gpa` (Guest Physical Address) → HPA.
/// Returns `None` if the mapping doesn't exist.
pub(crate) fn ept_gpa_to_hpa(ept_root_phys: u64, hhdm: u64, gpa: u64) -> Option<u64> {
    let mut table_phys = ept_root_phys & !0xFFF;
    for level in (0u64..4).rev() {
        let shift = 12 + level * 9;
        let index = ((gpa >> shift) & 0x1FF) as usize;
        let entry_addr = table_phys + (index as u64) * 8;
        let entry: u64 = unsafe { core::ptr::read_volatile((entry_addr + hhdm) as *const u64) };
        if entry & 0x7 == 0 {
            return None;
        } // not present
          // Check for large page (bit 7) at levels 2 and 1
        if level > 0 && entry & (1 << 7) != 0 {
            let mask = (1u64 << shift) - 1;
            return Some((entry & !mask & 0x000F_FFFF_FFFF_F000) | (gpa & mask));
        }
        table_phys = entry & 0x000F_FFFF_FFFF_F000;
    }
    Some(table_phys | (gpa & 0xFFF))
}

/// Walk guest 4-level page tables (via EPT) to translate GVA → GPA.
pub(crate) fn guest_gva_to_gpa(
    ept_root_phys: u64,
    hhdm: u64,
    guest_cr3: u64,
    gva: u64,
) -> Option<u64> {
    let mut table_gpa = guest_cr3 & !0xFFF;
    for level in (0u64..4).rev() {
        let shift = 12 + level * 9;
        let index = ((gva >> shift) & 0x1FF) as usize;
        let entry_gpa = table_gpa + (index as u64) * 8;
        let entry_hpa = ept_gpa_to_hpa(ept_root_phys, hhdm, entry_gpa)?;
        let entry: u64 = unsafe { core::ptr::read_volatile((entry_hpa + hhdm) as *const u64) };
        if entry & 1 == 0 {
            return None;
        } // not present
          // Large page at PDPT (level 2) or PD (level 1)
        if level > 0 && entry & (1 << 7) != 0 {
            let mask = (1u64 << shift) - 1;
            return Some((entry & !mask & 0x000F_FFFF_FFFF_F000) | (gva & mask));
        }
        table_gpa = entry & 0x000F_FFFF_FFFF_F000;
    }
    Some(table_gpa | (gva & 0xFFF))
}
