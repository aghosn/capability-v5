//! Page table management for Eunomia.
//!
//! The boot assembly sets up a 4-level identity map using 2 MiB pages
//! covering 0–4 GiB.  This module allows mapping additional 4 KiB pages
//! at arbitrary virtual addresses (identity-mapped: VA == GPA).
//!
//! Used for:
//!   - Mapping DomainComm pages (GPA returned by CPUID, may be above 4 GiB)
//!   - vTOM shared-page PTE manipulation (setting the vTOM bit in PTE phys addr)

use core::sync::atomic::{AtomicUsize, Ordering};

// Page table entry flags.
const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITABLE: u64 = 1 << 1;
const _PTE_PAGE_SIZE: u64 = 1 << 7; // 2 MiB page (PD level)

const PAGE_SIZE: usize = 4096;

extern "C" {
    static page_tables: u8;
}

/// Get the PML4 base address (set up by boot assembly).
fn pml4_base() -> *mut u64 {
    &raw const page_tables as *mut u64
}

// ── Frame allocator ──────────────────────────────────────────────────
//
// A tiny bump allocator for page-table frames.  Allocates from a static
// pool (separate from the heap) to avoid circular dependency.

const PT_POOL_PAGES: usize = 32;

#[repr(C, align(4096))]
struct PagePool {
    data: core::cell::UnsafeCell<[u8; PT_POOL_PAGES * PAGE_SIZE]>,
}

unsafe impl Sync for PagePool {}

static PT_POOL: PagePool = PagePool {
    data: core::cell::UnsafeCell::new([0; PT_POOL_PAGES * PAGE_SIZE]),
};
static PT_POOL_NEXT: AtomicUsize = AtomicUsize::new(0);

/// Allocate a zeroed 4 KiB frame for page table use.
fn alloc_pt_frame() -> Option<u64> {
    let idx = PT_POOL_NEXT.fetch_add(1, Ordering::Relaxed);
    if idx >= PT_POOL_PAGES {
        PT_POOL_NEXT.fetch_sub(1, Ordering::Relaxed);
        return None;
    }
    let base = PT_POOL.data.get() as *mut u8;
    let addr = unsafe { base.add(idx * PAGE_SIZE) } as u64;
    unsafe {
        core::ptr::write_bytes(addr as *mut u8, 0, PAGE_SIZE);
    }
    Some(addr)
}

// ── Page table indices ───────────────────────────────────────────────

fn pml4_index(va: u64) -> usize {
    ((va >> 39) & 0x1FF) as usize
}
fn pdpt_index(va: u64) -> usize {
    ((va >> 30) & 0x1FF) as usize
}
fn pd_index(va: u64) -> usize {
    ((va >> 21) & 0x1FF) as usize
}
fn pt_index(va: u64) -> usize {
    ((va >> 12) & 0x1FF) as usize
}

/// Read a page table entry.
unsafe fn read_entry(table: *mut u64, index: usize) -> u64 {
    core::ptr::read_volatile(table.add(index))
}

/// Write a page table entry.
unsafe fn write_entry(table: *mut u64, index: usize, value: u64) {
    core::ptr::write_volatile(table.add(index), value);
}

/// Ensure an intermediate table entry exists; allocate if missing.
/// Returns the physical address of the next-level table.
unsafe fn ensure_table(table: *mut u64, index: usize) -> Option<u64> {
    let entry = read_entry(table, index);
    if entry & PTE_PRESENT != 0 {
        Some(entry & !0xFFF)
    } else {
        let frame = alloc_pt_frame()?;
        write_entry(table, index, frame | PTE_PRESENT | PTE_WRITABLE);
        Some(frame)
    }
}

// ── Public API ───────────────────────────────────────────────────────

/// Map a single 4 KiB page: VA → GPA (identity-mapped, so VA == GPA).
///
/// Walks the 4-level page table, allocating intermediate tables as needed.
/// If the VA falls within a 2 MiB page (from the boot identity map), that
/// large page is NOT split — the new 4 KiB mapping would conflict.  Only
/// use this for addresses outside the boot identity map (above 4 GiB or
/// in unmapped holes).
///
/// Returns `true` on success.
pub fn map_4k(va: u64, gpa: u64) -> bool {
    unsafe {
        let pml4 = pml4_base();
        let pdpt_phys = match ensure_table(pml4, pml4_index(va)) {
            Some(p) => p,
            None => return false,
        };

        let pdpt = pdpt_phys as *mut u64;
        let pd_phys = match ensure_table(pdpt, pdpt_index(va)) {
            Some(p) => p,
            None => return false,
        };

        let pd = pd_phys as *mut u64;
        let pd_entry = read_entry(pd, pd_index(va));

        if pd_entry & PTE_PRESENT != 0 && pd_entry & _PTE_PAGE_SIZE != 0 {
            // This VA is inside a 2 MiB large page — cannot add a 4 KiB
            // mapping without splitting the large page.  Caller should
            // only map addresses outside the boot identity map.
            return false;
        }

        let pt_phys = match ensure_table(pd, pd_index(va)) {
            Some(p) => p,
            None => return false,
        };

        let pt = pt_phys as *mut u64;
        write_entry(pt, pt_index(va), gpa | PTE_PRESENT | PTE_WRITABLE);

        // Flush TLB for this VA.
        core::arch::asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags));
        true
    }
}

/// Map a contiguous range of 4 KiB pages (identity-mapped: VA == GPA).
///
/// `base` and `size` must be page-aligned.  Returns `true` if all pages
/// were mapped successfully.
pub fn map_range(base: u64, size: u64) -> bool {
    assert!(base & 0xFFF == 0, "base must be page-aligned");
    assert!(size & 0xFFF == 0, "size must be page-aligned");

    let mut offset = 0u64;
    while offset < size {
        let addr = base + offset;
        if !map_4k(addr, addr) {
            return false;
        }
        offset += PAGE_SIZE as u64;
    }
    true
}

/// Modify an existing PTE to change the physical (GPA) address.
///
/// Used for vTOM: set the vTOM bit in the GPA field of a PTE while
/// keeping the same VA.  The VA must already be mapped.
///
/// Returns `true` on success, `false` if the VA is not mapped or uses
/// a 2 MiB large page.
pub fn remap_gpa(va: u64, new_gpa: u64) -> bool {
    unsafe {
        let pml4 = pml4_base();
        let pml4_entry = read_entry(pml4, pml4_index(va));
        if pml4_entry & PTE_PRESENT == 0 {
            return false;
        }

        let pdpt = (pml4_entry & !0xFFF) as *mut u64;
        let pdpt_entry = read_entry(pdpt, pdpt_index(va));
        if pdpt_entry & PTE_PRESENT == 0 {
            return false;
        }

        let pd = (pdpt_entry & !0xFFF) as *mut u64;
        let pd_entry = read_entry(pd, pd_index(va));
        if pd_entry & PTE_PRESENT == 0 {
            return false;
        }
        if pd_entry & _PTE_PAGE_SIZE != 0 {
            // 2 MiB large page — cannot modify individual 4 KiB PTE.
            return false;
        }

        let pt = (pd_entry & !0xFFF) as *mut u64;
        let pt_entry = read_entry(pt, pt_index(va));
        if pt_entry & PTE_PRESENT == 0 {
            return false;
        }

        // Preserve flags (low 12 bits), replace physical address.
        let flags = pt_entry & 0xFFF;
        write_entry(pt, pt_index(va), (new_gpa & !0xFFF) | flags);

        core::arch::asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags));
        true
    }
}
