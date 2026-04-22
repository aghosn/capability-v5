//! GICv3 interrupt controller driver for AArch64 EL2.
//!
//! Initializes the GIC Distributor (GICD), Redistributors (GICR),
//! CPU Interface (ICC system registers), and Hypervisor Interface (ICH).
//!
//! All interrupts are configured as Non-secure Group 1 and routed to EL2
//! via HCR_EL2.IMO (set in el2_regs.rs).
//!
//! Reference: ARM GICv3 Architecture Specification (IHI 0069)

use crate::serial_println;

// ── GICD register offsets ────────────────────────────────────────────────── //

const GICD_CTLR: usize = 0x0000;
const GICD_TYPER: usize = 0x0004;
const GICD_IGROUPR: usize = 0x0080; // Group registers (32 INTs per reg)
const GICD_ISENABLER: usize = 0x0100; // Set-enable
const GICD_ICENABLER: usize = 0x0180; // Clear-enable
const GICD_IPRIORITYR: usize = 0x0400; // Priority (4 INTs per reg, byte-wide)
const GICD_ICFGR: usize = 0x0C00; // Configuration (edge/level)
const GICD_IROUTER: usize = 0x6100; // Affinity routing (64-bit, SPI 32+)

// GICD_CTLR bits
const GICD_CTLR_ENABLE_GRP1_NS: u32 = 1 << 1;
const GICD_CTLR_ARE_NS: u32 = 1 << 4;
const GICD_CTLR_RWP: u32 = 1 << 31;

// ── GICR register offsets ────────────────────────────────────────────────── //
// Each redistributor has two 64K frames: RD_base and SGI_base.

const GICR_CTLR: usize = 0x0000;
const GICR_WAKER: usize = 0x0014;
const GICR_CTLR_RWP: u32 = 1 << 3;
const GICR_WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;
const GICR_WAKER_CHILDREN_ASLEEP: u32 = 1 << 2;

// SGI_base offsets (at RD_base + 0x10000)
const GICR_SGI_BASE_OFF: usize = 0x10000;
const GICR_IGROUPR0: usize = GICR_SGI_BASE_OFF + 0x0080;
const GICR_ISENABLER0: usize = GICR_SGI_BASE_OFF + 0x0100;
const GICR_ICENABLER0: usize = GICR_SGI_BASE_OFF + 0x0180;
const GICR_IPRIORITYR: usize = GICR_SGI_BASE_OFF + 0x0400;

// ── Helper: MMIO read/write ──────────────────────────────────────────────── //

#[inline(always)]
unsafe fn mmio_write32(base: u64, offset: usize, val: u32) {
    let ptr = (base as usize + offset) as *mut u32;
    ptr.write_volatile(val);
}

#[inline(always)]
unsafe fn mmio_read32(base: u64, offset: usize) -> u32 {
    let ptr = (base as usize + offset) as *const u32;
    ptr.read_volatile()
}

#[inline(always)]
unsafe fn mmio_write64(base: u64, offset: usize, val: u64) {
    let ptr = (base as usize + offset) as *mut u64;
    ptr.write_volatile(val);
}

// ── GICD init ────────────────────────────────────────────────────────────── //

/// Initialize the GIC Distributor.
///
/// Configures all SPIs (32..max) as Group 1 NS, medium priority, disabled.
/// Enables ARE (affinity routing) and Group 1 NS delivery.
///
/// # Safety
/// Must be called once from the BSP at EL2 with GICD MMIO identity-mapped.
pub unsafe fn init_gicd(gicd_base: u64) -> u32 {
    // Disable distributor while configuring.
    mmio_write32(gicd_base, GICD_CTLR, 0);
    gicd_wait_rwp(gicd_base);

    // Read TYPER to get number of interrupt lines.
    let typer = mmio_read32(gicd_base, GICD_TYPER);
    let it_lines = (typer & 0x1F) as u32;
    let max_spi = core::cmp::min((it_lines + 1) * 32, 1020);

    serial_println!("GICD: ITLinesNumber={}, max SPI={}", it_lines, max_spi);

    // Configure SPIs (INTIDs 32..max_spi).
    // SGIs (0..15) and PPIs (16..31) are per-CPU, handled by GICR.
    let spi_start_reg = 1u32; // Register index 1 = INTIDs 32..63

    for reg_idx in spi_start_reg..((max_spi + 31) / 32) {
        let offset = reg_idx as usize;
        // Group 1 NS: set all bits to 1
        mmio_write32(gicd_base, GICD_IGROUPR + offset * 4, 0xFFFF_FFFF);
        // Disable all SPIs initially
        mmio_write32(gicd_base, GICD_ICENABLER + offset * 4, 0xFFFF_FFFF);
    }

    // Set SPI priorities to 0xA0 (byte-accessible).
    for intid in 32..max_spi {
        let reg_offset = GICD_IPRIORITYR + (intid as usize);
        let ptr = (gicd_base as usize + reg_offset) as *mut u8;
        ptr.write_volatile(0xA0);
    }

    // Route all SPIs to CPU 0 (affinity 0.0.0.0).
    for intid in 32..max_spi {
        let offset = GICD_IROUTER + ((intid - 32) as usize) * 8;
        mmio_write64(gicd_base, offset, 0); // Aff3.Aff2.Aff1.Aff0 = 0
    }

    // Enable distributor: ARE_NS + EnableGrp1NS.
    mmio_write32(gicd_base, GICD_CTLR, GICD_CTLR_ARE_NS | GICD_CTLR_ENABLE_GRP1_NS);
    gicd_wait_rwp(gicd_base);

    serial_println!("GICD: enabled (ARE_NS + Grp1NS)");
    max_spi
}

/// Wait for GICD register write pending to clear.
unsafe fn gicd_wait_rwp(gicd_base: u64) {
    while mmio_read32(gicd_base, GICD_CTLR) & GICD_CTLR_RWP != 0 {
        core::hint::spin_loop();
    }
}

// ── GICR init ────────────────────────────────────────────────────────────── //

/// Initialize a per-CPU GIC Redistributor.
///
/// Wakes the redistributor, configures SGIs (0..15) and PPIs (16..31)
/// as Group 1 NS, enables SGIs.
///
/// # Safety
/// Must be called on each CPU at EL2 with the correct `gicr_base` for that CPU.
pub unsafe fn init_gicr(gicr_base: u64) {
    // Wake the redistributor.
    let waker = mmio_read32(gicr_base, GICR_WAKER);
    mmio_write32(gicr_base, GICR_WAKER, waker & !GICR_WAKER_PROCESSOR_SLEEP);

    // Wait for ChildrenAsleep to clear.
    while mmio_read32(gicr_base, GICR_WAKER) & GICR_WAKER_CHILDREN_ASLEEP != 0 {
        core::hint::spin_loop();
    }

    // SGIs/PPIs (INTIDs 0..31): Group 1 NS.
    mmio_write32(gicr_base, GICR_IGROUPR0, 0xFFFF_FFFF);

    // Set SGI/PPI priorities to 0xA0.
    for i in 0..32u32 {
        let ptr = (gicr_base as usize + GICR_IPRIORITYR + i as usize) as *mut u8;
        ptr.write_volatile(0xA0);
    }

    // Enable SGIs (INTIDs 0..15).
    mmio_write32(gicr_base, GICR_ISENABLER0, 0x0000_FFFF);

    // Wait for writes to propagate.
    while mmio_read32(gicr_base, GICR_CTLR) & GICR_CTLR_RWP != 0 {
        core::hint::spin_loop();
    }

    serial_println!("GICR: CPU redistributor initialized (base={:#x})", gicr_base);
}

// ── CPU Interface (ICC system registers) ─────────────────────────────────── //

/// Initialize the GICv3 CPU interface via system registers.
///
/// Enables the system register interface (ICC_SRE_EL2), sets priority
/// mask, and enables Group 1 interrupt delivery.
///
/// # Safety
/// Must be called on each CPU at EL2.
pub unsafe fn init_cpu_interface() {
    // Enable system register interface at EL2.
    let mut sre: u64;
    core::arch::asm!("mrs {}, ICC_SRE_EL2", out(reg) sre, options(nostack));
    sre |= 1; // SRE = 1
    sre |= 1 << 3; // Enable = 1 (allow lower ELs to use SRE)
    core::arch::asm!("msr ICC_SRE_EL2, {}", in(reg) sre, options(nostack));
    core::arch::asm!("isb", options(nostack));

    // Set priority mask to accept all priorities.
    let pmr: u64 = 0xFF;
    core::arch::asm!("msr ICC_PMR_EL1, {}", in(reg) pmr, options(nostack));

    // Binary point = 0 (finest grouping).
    let bpr: u64 = 0;
    core::arch::asm!("msr ICC_BPR1_EL1, {}", in(reg) bpr, options(nostack));

    // EOI mode = 0 (combined priority drop + deactivation).
    let ctlr: u64 = 0;
    core::arch::asm!("msr ICC_CTLR_EL1, {}", in(reg) ctlr, options(nostack));

    // Enable Group 1 NS interrupts.
    let igrpen: u64 = 1;
    core::arch::asm!("msr ICC_IGRPEN1_EL1, {}", in(reg) igrpen, options(nostack));

    core::arch::asm!("isb", options(nostack));

    serial_println!("GIC CPU interface: SRE={:#x}, PMR=0xFF, Grp1 enabled", sre);
}

// ── ICH (Hypervisor virtual interface) ───────────────────────────────────── //

/// Number of List Registers discovered from ICH_VTR_EL2.
static mut NUM_LRS: u32 = 0;

/// Initialize the GICv3 hypervisor interface for virtual interrupt injection.
///
/// Reads ICH_VTR_EL2 to discover the number of List Registers, enables
/// the virtual CPU interface, and zeroes all LRs.
///
/// # Safety
/// Must be called on each CPU at EL2, after CPU interface init.
pub unsafe fn init_ich() {
    // Read ICH_VTR_EL2: bits[4:0] = ListRegs - 1.
    let vtr: u64;
    core::arch::asm!("mrs {}, ICH_VTR_EL2", out(reg) vtr, options(nostack));
    let num_lrs = ((vtr & 0x1F) + 1) as u32;
    NUM_LRS = num_lrs;

    // Enable virtual CPU interface.
    let hcr: u64 = 1; // En = 1
    core::arch::asm!("msr ICH_HCR_EL2, {}", in(reg) hcr, options(nostack));

    // Zero all List Registers.
    // We handle up to 16 LRs (architecturally max).
    let zero: u64 = 0;
    // ICH_LR<n>_EL2 must be accessed individually; use a match for known counts.
    if num_lrs >= 1 { core::arch::asm!("msr ICH_LR0_EL2, {}", in(reg) zero, options(nostack)); }
    if num_lrs >= 2 { core::arch::asm!("msr ICH_LR1_EL2, {}", in(reg) zero, options(nostack)); }
    if num_lrs >= 3 { core::arch::asm!("msr ICH_LR2_EL2, {}", in(reg) zero, options(nostack)); }
    if num_lrs >= 4 { core::arch::asm!("msr ICH_LR3_EL2, {}", in(reg) zero, options(nostack)); }
    if num_lrs >= 5 { core::arch::asm!("msr ICH_LR4_EL2, {}", in(reg) zero, options(nostack)); }
    if num_lrs >= 6 { core::arch::asm!("msr ICH_LR5_EL2, {}", in(reg) zero, options(nostack)); }
    if num_lrs >= 7 { core::arch::asm!("msr ICH_LR6_EL2, {}", in(reg) zero, options(nostack)); }
    if num_lrs >= 8 { core::arch::asm!("msr ICH_LR7_EL2, {}", in(reg) zero, options(nostack)); }
    if num_lrs >= 9 { core::arch::asm!("msr ICH_LR8_EL2, {}", in(reg) zero, options(nostack)); }
    if num_lrs >= 10 { core::arch::asm!("msr ICH_LR9_EL2, {}", in(reg) zero, options(nostack)); }
    if num_lrs >= 11 { core::arch::asm!("msr ICH_LR10_EL2, {}", in(reg) zero, options(nostack)); }
    if num_lrs >= 12 { core::arch::asm!("msr ICH_LR11_EL2, {}", in(reg) zero, options(nostack)); }
    if num_lrs >= 13 { core::arch::asm!("msr ICH_LR12_EL2, {}", in(reg) zero, options(nostack)); }
    if num_lrs >= 14 { core::arch::asm!("msr ICH_LR13_EL2, {}", in(reg) zero, options(nostack)); }
    if num_lrs >= 15 { core::arch::asm!("msr ICH_LR14_EL2, {}", in(reg) zero, options(nostack)); }
    if num_lrs >= 16 { core::arch::asm!("msr ICH_LR15_EL2, {}", in(reg) zero, options(nostack)); }

    core::arch::asm!("isb", options(nostack));

    let pri_bits = ((vtr >> 29) & 0x7) + 1;
    serial_println!(
        "ICH: {} list registers, {} priority bits, virtual interface enabled",
        num_lrs, pri_bits
    );
}

// ── Full GICv3 init (called from boot) ───────────────────────────────────── //

/// Initialize the full GICv3 subsystem.
///
/// Call order: ICC_SRE → GICR → GICD → ICC → ICH.
///
/// # Safety
/// Must be called once from the BSP at EL2, with GIC MMIO identity-mapped.
pub unsafe fn init_gicv3(gicd_base: u64, gicr_base: u64) {
    serial_println!();
    serial_println!("GICv3 init: GICD={:#x} GICR={:#x}", gicd_base, gicr_base);

    // 1. Enable system register interface first (before any ICC_* access).
    init_cpu_interface();

    // 2. Wake and configure BSP's redistributor.
    init_gicr(gicr_base);

    // 3. Configure distributor (SPIs).
    let max_spi = init_gicd(gicd_base);

    // 4. Initialize hypervisor virtual interface.
    init_ich();

    serial_println!(
        "GICv3 init complete: {} SPIs, {} LRs",
        max_spi - 32,
        NUM_LRS
    );
}
