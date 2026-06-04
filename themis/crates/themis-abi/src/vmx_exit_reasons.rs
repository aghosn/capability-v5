//! Intel VMX **basic exit reasons** (Intel SDM Vol 3C §27.2.1, Appendix C).
//!
//! These are pure hardware-ABI values defined by the Intel architecture — no
//! Themis customization.  They live in `themis-abi` so the bare-metal
//! capavisor and userspace VMM (cloud-hypervisor's Themis backend) read from a
//! single source of truth and cannot drift.
//!
//! Themis-specific *synthetic* exits (capavisor-injected, e.g. doorbell
//! notifications) live in [`crate::synthetic_exits`] with the high bit set
//! (`0x8000_0000+`) so they cannot collide with these hardware values.
//!
//! Only reasons currently consumed by capavisor or CHV are listed; add new
//! ones from SDM Appendix C as they are needed.

#![allow(dead_code)]

pub const EXCEPTION_NMI: u32 = 0;
pub const EXTERNAL_INTERRUPT: u32 = 1;
pub const TRIPLE_FAULT: u32 = 2;
pub const INIT_SIGNAL: u32 = 3;
pub const SIPI: u32 = 4;
pub const INTERRUPT_WINDOW: u32 = 7;
pub const CPUID: u32 = 10;
pub const HLT: u32 = 12;
pub const VMCALL: u32 = 18;
pub const CR_ACCESS: u32 = 28;
pub const IO_INSTRUCTION: u32 = 30;
pub const RDMSR: u32 = 31;
pub const WRMSR: u32 = 32;
pub const VMENTRY_INVALID_GUEST: u32 = 33;
/// APIC-access VM exit (SDM Vol 3C §29.4): guest accessed the APIC-access
/// page while VIRTUALIZE_APIC_ACCESSES (secondary bit 0) was set.
pub const APIC_ACCESS: u32 = 44;
/// EOI-induced VM exit (SDM Vol 3C §29.1.4): VID=1, guest wrote EOI, and the
/// delivered vector's bit was set in the EOI-exit bitmap.
pub const EOI_INDUCED: u32 = 45;
pub const EPT_VIOLATION: u32 = 48;
pub const EPT_MISCONFIG: u32 = 49;
pub const VMX_PREEMPTION_TIMER: u32 = 52;
pub const XSETBV: u32 = 55;
/// APIC-write VM exit (SDM Vol 3C §29.4.3.3): APIC_REGISTER_VIRT wrote to
/// VAPIC page, processor exits so VMM can process side-effects.
/// RIP is already past the faulting instruction.
pub const APIC_WRITE: u32 = 56;
