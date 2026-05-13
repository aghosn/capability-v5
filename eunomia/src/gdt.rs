//! GDT with TSS for IST-based double-fault handling.
//!
//! Replaces the minimal boot GDT (assembly) with a full GDT that includes
//! a TSS entry.  The TSS provides an IST (Interrupt Stack Table) so that
//! double-faults get a known-good stack.

use core::mem;

// GDT selectors (byte offsets into the GDT).
pub const KERNEL_CS: u16 = 0x08;
pub const KERNEL_DS: u16 = 0x10;
const TSS_SEL: u16 = 0x18;

/// 64-bit TSS (Task State Segment).
#[repr(C, packed)]
struct Tss {
    _reserved0: u32,
    /// RSP values for privilege-level transitions (unused in ring-0-only kernel).
    rsp: [u64; 3],
    _reserved1: u64,
    /// Interrupt Stack Table — 7 entries.
    ist: [u64; 7],
    _reserved2: u64,
    _reserved3: u16,
    /// I/O permission bitmap offset (set past TSS limit to disable).
    iopb_offset: u16,
}

/// IST index used for #DF (double fault).  IST entries are 1-based.
pub const IST_DF: u8 = 1;

// Separate stack for double-fault handler (4 KiB).
#[repr(C, align(4096))]
struct DfStack([u8; 4096]);
static mut DF_STACK: DfStack = DfStack([0; 4096]);

static mut TSS: Tss = Tss {
    _reserved0: 0,
    rsp: [0; 3],
    _reserved1: 0,
    ist: [0; 7],
    _reserved2: 0,
    _reserved3: 0,
    iopb_offset: mem::size_of::<Tss>() as u16,
};

// 4 entries: NULL, Code64, Data64, TSS (16-byte descriptor = 2 slots).
// Total = 5 u64 slots.
static mut GDT: [u64; 5] = [0; 5];

#[repr(C, packed)]
struct GdtPtr {
    limit: u16,
    base: u64,
}

/// Initialise and load the GDT + TSS.
pub fn init() {
    unsafe {
        // Point IST1 at the top of the double-fault stack.
        let df_top = (&raw const DF_STACK.0 as u64) + 4096;
        (*(&raw mut TSS)).ist[0] = df_top;

        let tss_addr = &raw const TSS as u64;
        let tss_limit = (mem::size_of::<Tss>() - 1) as u64;

        // Build GDT entries.
        let gdt = &mut *(&raw mut GDT);
        gdt[0] = 0; // NULL
        gdt[1] = 0x00AF_9A00_0000_FFFF; // Code64
        gdt[2] = 0x00CF_9200_0000_FFFF; // Data64

        // TSS descriptor (system segment, 16 bytes across two GDT slots).
        let tss_low: u64 = (tss_limit & 0xFFFF)
            | ((tss_addr & 0xFFFF) << 16)
            | (((tss_addr >> 16) & 0xFF) << 32)
            | (0x89u64 << 40) // P=1, type=0x9
            | (((tss_limit >> 16) & 0xF) << 48)
            | (((tss_addr >> 24) & 0xFF) << 56);
        gdt[3] = tss_low;
        gdt[4] = tss_addr >> 32;

        let ptr = GdtPtr {
            limit: (mem::size_of::<[u64; 5]>() - 1) as u16,
            base: (&raw const GDT) as u64,
        };

        core::arch::asm!(
            "lgdt [{}]",
            // Reload CS via a far return.
            "push {cs}",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",
            // Reload data segments.
            "mov ds, {ds:x}",
            "mov es, {ds:x}",
            "mov fs, {ds:x}",
            "mov gs, {ds:x}",
            "mov ss, {ds:x}",
            // Load TSS.
            "ltr {tss:x}",
            in(reg) &ptr,
            cs = in(reg) KERNEL_CS as u64,
            ds = in(reg) KERNEL_DS as u64,
            tss = in(reg) TSS_SEL,
            tmp = lateout(reg) _,
        );
    }
}
