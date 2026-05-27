//! Fixed guest-physical memory layout for x86-64.
//!
//! Constants in this module describe addresses and sizes that are dictated by
//! the x86 platform itself (the legacy ISA hole, the standard APIC/HPET MMIO
//! windows) and are therefore the same for every Themis x86 domain.
//!
//! These constants used to be inlined at their call sites in `boot.rs`,
//! `hypercall.rs`, and `platform.rs`.

// ── Page sizes ───────────────────────────────────────────────────────────── //

/// 4 KiB — the smallest x86-64 page size (also the standard MMIO register
/// region size for LAPIC / I/O APIC / HPET).
pub const PAGE_SIZE_4K: u64 = 0x1000;

// ── Legacy ISA hole (real-mode VGA / BIOS shadow) ─────────────────────────── //
//
// Firmware typically does not report this range in the memory map but the
// guest's identity-mapped page tables cover it.  The EPT must map it so
// page-table walks that touch GPA 0xC0000 (VGA BIOS shadow) do not fault.

/// Base GPA of the legacy ISA memory hole.
pub const ISA_HOLE_BASE: u64 = 0xA0000;
/// Inclusive end (exclusive upper bound) of the legacy ISA hole.
pub const ISA_HOLE_END: u64 = 0x100000;
/// Length of the legacy ISA hole (384 KiB).
pub const ISA_HOLE_LEN: u64 = ISA_HOLE_END - ISA_HOLE_BASE;

// ── Fixed-address MMIO regions ────────────────────────────────────────────── //
//
// Standard x86 platform MMIO windows.  Each is one 4 KiB page.

/// I/O APIC MMIO base (4 KiB).
pub const IOAPIC_MMIO_BASE: u64 = 0xFEC0_0000;
/// HPET MMIO base (4 KiB).
pub const HPET_MMIO_BASE: u64 = 0xFED0_0000;
/// Local APIC (xAPIC) MMIO base (4 KiB).  Used by the capavisor itself for
/// cross-core IPIs since the capavisor never enables x2APIC mode.
pub const LAPIC_MMIO_BASE: u64 = 0xFEE0_0000;
/// Size of each of the above MMIO windows.
pub const MMIO_PAGE_SIZE: u64 = PAGE_SIZE_4K;

// ── Local APIC register offsets (Intel SDM Vol 3A §10.4.1) ────────────────── //
//
// Used by the capavisor for cross-core notification IPIs through xAPIC MMIO.

/// Interrupt Command Register, low dword (write triggers IPI).
pub const APIC_REG_ICR_LOW: u64 = 0x300;
/// Interrupt Command Register, high dword (destination APIC ID).
pub const APIC_REG_ICR_HIGH: u64 = 0x310;
