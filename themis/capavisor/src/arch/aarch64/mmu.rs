//! AArch64 EL2 MMU setup — identity-mapped page tables.
//!
//! Builds a minimal identity map for the hypervisor at EL2:
//!   L1[0] = 0x0000_0000..0x3FFF_FFFF — Device-nGnRnE (GIC, PL011, etc.)
//!   L1[1] = 0x4000_0000..0x7FFF_FFFF — Normal WB (RAM)
//!
//! Uses 1G block descriptors (no L2/L3) for initial bringup.
//! This gives the entire RAM region a single RWX policy, which is
//! acceptable for early bringup. A later pass should split with L2.
//!
//! Reference: ARMv8-A Architecture Reference Manual, Chapter D5.

use crate::serial_println;

// ── MAIR attribute indices ───────────────────────────────────────────────── //

/// MAIR_EL2 attribute index for Normal Write-Back cacheable memory.
const MAIR_IDX_NORMAL: u64 = 0;
/// MAIR_EL2 attribute index for Device-nGnRnE memory (strongly ordered).
const MAIR_IDX_DEVICE: u64 = 1;

/// MAIR_EL2 value:
///   Attr0 = 0xFF  (Normal, Inner/Outer Write-Back, Read/Write Allocate)
///   Attr1 = 0x00  (Device-nGnRnE)
const MAIR_VALUE: u64 = 0x00_FF;

// ── Page table descriptor bits ───────────────────────────────────────────── //

/// Valid bit — entry is active.
const DESC_VALID: u64 = 1 << 0;
/// Block/page bit: 0 = block (at L1/L2), 1 = table (at L0/L1/L2) or page (L3).
/// For L1 block entries, bit[1] = 0.
// const DESC_TABLE: u64 = 1 << 1;  // unused for block entries
/// Access Flag — must be set or hardware faults immediately.
const DESC_AF: u64 = 1 << 10;
/// Inner Shareable (for Normal memory, required for SMP coherency).
const DESC_SH_INNER: u64 = 0b11 << 8;
/// EL0 access disable (hypervisor-only).
const DESC_AP_EL0_NONE: u64 = 0b00 << 6;
/// Execute-never at EL2 (for device/data regions).
const DESC_XN: u64 = 1 << 54;
/// Privileged Execute-Never (UXN in some terminology).
const DESC_PXN: u64 = 1 << 53;

/// Build a L1 block descriptor for 1G region.
///
/// `phys_base` must be 1G-aligned. `attr_idx` selects MAIR attribute.
const fn l1_block(phys_base: u64, attr_idx: u64, executable: bool) -> u64 {
    let mut desc = DESC_VALID | DESC_AF;
    // bit[1] = 0 for block descriptor (not table)
    desc |= phys_base & 0x0000_FFFF_C000_0000; // PA[47:30]
    desc |= (attr_idx & 0x7) << 2; // AttrIndx[2:0]
    desc |= DESC_AP_EL0_NONE;
    if attr_idx == MAIR_IDX_NORMAL {
        desc |= DESC_SH_INNER; // Inner Shareable for RAM
    }
    if !executable {
        desc |= DESC_XN | DESC_PXN;
    }
    desc
}

/// Build an L0 table descriptor pointing to an L1 table.
const fn l0_table(l1_phys: u64) -> u64 {
    DESC_VALID | (1 << 1) | (l1_phys & 0x0000_FFFF_FFFF_F000)
}

// ── Static page tables (BSS) ─────────────────────────────────────────────── //

/// L0 table: 512 entries, one for each 512G region. Only index 0 is used
/// (covers 0..512 GiB which includes all QEMU virt address space).
#[repr(C, align(4096))]
struct PageTable([u64; 512]);

static mut L0_TABLE: PageTable = PageTable([0; 512]);
static mut L1_TABLE: PageTable = PageTable([0; 512]);

// ── Public API ───────────────────────────────────────────────────────────── //

/// Initialize EL2 identity-mapped page tables and enable the MMU.
///
/// After this call, VA == PA for the first 2G (0x0000_0000..0x7FFF_FFFF),
/// with the first 1G as Device and the second 1G as Normal WB.
///
/// # Safety
/// Must be called exactly once, at EL2, with MMU off.
pub unsafe fn init_and_enable() {
    // ── Build page tables ────────────────────────────────────────────────── //

    let l1_ptr = core::ptr::addr_of_mut!(L1_TABLE) as *mut u64;
    let l0_ptr = core::ptr::addr_of_mut!(L0_TABLE) as *mut u64;

    // L1[0] = 0x0000_0000..0x3FFF_FFFF — Device (GIC, PL011, flash, etc.)
    // Not executable.
    l1_ptr.add(0).write_volatile(
        l1_block(0x0000_0000, MAIR_IDX_DEVICE, false),
    );

    // L1[1] = 0x4000_0000..0x7FFF_FFFF — Normal WB (RAM)
    // Executable (kernel code lives here).
    l1_ptr.add(1).write_volatile(
        l1_block(0x4000_0000, MAIR_IDX_NORMAL, true),
    );

    // Rest of L1 entries are zero (invalid) — faults on access.

    // L0[0] → L1 table (covers 0..512 GiB)
    let l1_phys = l1_ptr as u64;
    l0_ptr.add(0).write_volatile(l0_table(l1_phys));

    // ── Clean page tables from D-cache (caches are already on) ───────────── //
    // The translation table walker reads from memory, not D-cache, so we
    // must clean our writes to Point of Coherency.

    dc_civac_range(l0_ptr as usize, 4096);
    dc_civac_range(l1_ptr as usize, 4096);
    core::arch::asm!("dsb sy", options(nostack));

    // ── Configure EL2 translation regime ─────────────────────────────────── //

    // MAIR_EL2: memory attribute indirection register.
    core::arch::asm!("msr MAIR_EL2, {}", in(reg) MAIR_VALUE, options(nostack));

    // TCR_EL2: translation control register.
    let tcr = tcr_el2_value();
    core::arch::asm!("msr TCR_EL2, {}", in(reg) tcr, options(nostack));

    // TTBR0_EL2: translation table base register.
    let ttbr = l0_ptr as u64;
    core::arch::asm!("msr TTBR0_EL2, {}", in(reg) ttbr, options(nostack));

    // ── Invalidate TLBs and barrier ──────────────────────────────────────── //

    core::arch::asm!(
        "isb",
        "tlbi alle2",
        "dsb sy",
        "isb",
        options(nostack),
    );

    // ── Enable MMU ───────────────────────────────────────────────────────── //

    let sctlr = sctlr_el2_value();
    core::arch::asm!(
        "msr SCTLR_EL2, {}",
        "isb",
        in(reg) sctlr,
        options(nostack),
    );

    serial_println!("MMU enabled at EL2 (identity-mapped)");
}

/// Build TCR_EL2 value for 48-bit VA, 4K granule.
fn tcr_el2_value() -> u64 {
    // Read PA size from ID_AA64MMFR0_EL1.PARange.
    let mmfr0: u64;
    unsafe {
        core::arch::asm!("mrs {}, ID_AA64MMFR0_EL1", out(reg) mmfr0, options(nostack));
    }
    let pa_range = mmfr0 & 0xF; // bits[3:0]

    let mut tcr: u64 = 0;
    tcr |= 16; // T0SZ = 16 → 48-bit VA
    // TG0 = 0b00 → 4KB granule (bits[15:14])
    // IRGN0 = 0b01 → Inner Write-Back, Write-Allocate (bit[9:8])
    tcr |= 0b01 << 8;
    // ORGN0 = 0b01 → Outer Write-Back, Write-Allocate (bit[11:10])
    tcr |= 0b01 << 10;
    // SH0 = 0b11 → Inner Shareable (bit[13:12])
    tcr |= 0b11 << 12;
    // PS = PA size from ID_AA64MMFR0_EL1 (bit[18:16])
    tcr |= (pa_range & 0x7) << 16;

    tcr
}

/// Build SCTLR_EL2 value with MMU, caches, and required RES1 bits.
fn sctlr_el2_value() -> u64 {
    // Start from known state with architecturally required RES1 bits.
    // ARMv8.0: bits 29,28,23,22,18,16,11,5,4 are RES1 for SCTLR_EL2.
    let mut v: u64 = 0;
    // RES1 bits (ARMv8.0 SCTLR_EL2 — see D13.2.106)
    v |= (1 << 29) | (1 << 28) | (1 << 23) | (1 << 22);
    v |= (1 << 18) | (1 << 16) | (1 << 11) | (1 << 5) | (1 << 4);
    // Enable bits
    v |= 1 << 0;  // M  — MMU enable
    v |= 1 << 2;  // C  — Data cache enable
    v |= 1 << 12; // I  — Instruction cache enable
    v
}

/// Clean and invalidate D-cache by VA to Point of Coherency for a range.
unsafe fn dc_civac_range(start: usize, len: usize) {
    // Cache line size: assume 64 bytes (Cortex-A76 and most ARMv8 cores).
    const LINE_SIZE: usize = 64;
    let mut addr = start & !(LINE_SIZE - 1);
    let end = start + len;
    while addr < end {
        core::arch::asm!(
            "dc civac, {}",
            in(reg) addr,
            options(nostack),
        );
        addr += LINE_SIZE;
    }
}
