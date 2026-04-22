//! AArch64 EL2 exception vector table and context save/restore.
//!
//! The ARMv8-A exception model has 4 types × 4 source levels = 16 entries.
//! Each entry is 128 bytes (32 instructions). VBAR_EL2 must be 2048-byte aligned.
//!
//! For now, all vectors print the exception type and halt. Once Stage-2
//! page tables are in place, the "Lower EL using AArch64" synchronous
//! vector will route to the hypervisor trap handler.

use core::fmt;

/// Saved CPU context on EL2 exception entry.
///
/// The assembly stub pushes all general-purpose registers, ELR_EL2,
/// SPSR_EL2, and ESR_EL2 onto the EL2 stack. This struct matches
/// that layout exactly.
#[repr(C)]
pub struct ExceptionContext {
    /// General-purpose registers X0–X30.
    pub gpr: [u64; 31],
    /// Saved program counter (return address).
    pub elr_el2: u64,
    /// Saved processor state.
    pub spsr_el2: u64,
    /// Exception syndrome register (cause of exception).
    pub esr_el2: u64,
}

impl fmt::Display for ExceptionContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "  ELR_EL2:  {:#018x}", self.elr_el2)?;
        writeln!(f, "  SPSR_EL2: {:#018x}", self.spsr_el2)?;
        writeln!(f, "  ESR_EL2:  {:#018x}  (EC={:#x}, ISS={:#x})",
            self.esr_el2,
            (self.esr_el2 >> 26) & 0x3F,
            self.esr_el2 & 0x1FF_FFFF)?;
        for i in (0..31).step_by(4) {
            write!(f, "  X{:<2}={:#018x}", i, self.gpr[i])?;
            if i + 1 < 31 { write!(f, "  X{:<2}={:#018x}", i+1, self.gpr[i+1])?; }
            if i + 2 < 31 { write!(f, "  X{:<2}={:#018x}", i+2, self.gpr[i+2])?; }
            if i + 3 < 31 { write!(f, "  X{:<2}={:#018x}", i+3, self.gpr[i+3])?; }
            writeln!(f)?;
        }
        Ok(())
    }
}

/// Exception class codes from ESR_EL2.EC (bits[31:26]).
#[allow(dead_code)]
pub mod ec {
    pub const UNKNOWN: u64 = 0x00;
    pub const WFI_WFE: u64 = 0x01;
    pub const HVC64: u64 = 0x16;
    pub const SMC64: u64 = 0x17;
    pub const SYS_REG: u64 = 0x18;
    pub const INST_ABORT_LOWER: u64 = 0x20;
    pub const INST_ABORT_SAME: u64 = 0x21;
    pub const DATA_ABORT_LOWER: u64 = 0x24;
    pub const DATA_ABORT_SAME: u64 = 0x25;
    pub const SERROR: u64 = 0x2F;
}

// ── Exception vector table (assembly) ────────────────────────────────────── //
//
// The table must be 2048-byte (0x800) aligned. Each of the 16 entries is
// exactly 128 bytes (0x80). The layout is:
//
//   Offset  Source              Type
//   0x000   Current EL, SP0     Synchronous
//   0x080   Current EL, SP0     IRQ
//   0x100   Current EL, SP0     FIQ
//   0x180   Current EL, SP0     SError
//   0x200   Current EL, SPx     Synchronous
//   0x280   Current EL, SPx     IRQ
//   0x300   Current EL, SPx     FIQ
//   0x380   Current EL, SPx     SError
//   0x400   Lower EL, AArch64   Synchronous    ← guest traps land here
//   0x480   Lower EL, AArch64   IRQ
//   0x500   Lower EL, AArch64   FIQ
//   0x580   Lower EL, AArch64   SError
//   0x600   Lower EL, AArch32   Synchronous
//   0x680   Lower EL, AArch32   IRQ
//   0x700   Lower EL, AArch32   FIQ
//   0x780   Lower EL, AArch32   SError

core::arch::global_asm!(r#"
.section .text
.balign 2048
.global __vectors_el2
__vectors_el2:

// ── Macro: save context and call Rust handler ────────────────────────
.macro EXCEPTION_ENTRY handler
    // Make room for ExceptionContext on stack
    sub     sp, sp, #(34 * 8)       // 31 GPRs + ELR + SPSR + ESR

    // Save X0–X30
    stp     x0,  x1,  [sp, #(0  * 8)]
    stp     x2,  x3,  [sp, #(2  * 8)]
    stp     x4,  x5,  [sp, #(4  * 8)]
    stp     x6,  x7,  [sp, #(6  * 8)]
    stp     x8,  x9,  [sp, #(8  * 8)]
    stp     x10, x11, [sp, #(10 * 8)]
    stp     x12, x13, [sp, #(12 * 8)]
    stp     x14, x15, [sp, #(14 * 8)]
    stp     x16, x17, [sp, #(16 * 8)]
    stp     x18, x19, [sp, #(18 * 8)]
    stp     x20, x21, [sp, #(20 * 8)]
    stp     x22, x23, [sp, #(22 * 8)]
    stp     x24, x25, [sp, #(24 * 8)]
    stp     x26, x27, [sp, #(26 * 8)]
    stp     x28, x29, [sp, #(28 * 8)]
    str     x30,       [sp, #(30 * 8)]

    // Save ELR_EL2, SPSR_EL2, ESR_EL2
    mrs     x0, ELR_EL2
    mrs     x1, SPSR_EL2
    mrs     x2, ESR_EL2
    stp     x0, x1, [sp, #(31 * 8)]
    str     x2,     [sp, #(33 * 8)]

    // First argument = pointer to ExceptionContext
    mov     x0, sp
    bl      \handler

    // Restore ELR_EL2, SPSR_EL2
    ldp     x0, x1, [sp, #(31 * 8)]
    msr     ELR_EL2, x0
    msr     SPSR_EL2, x1

    // Restore X0–X30
    ldp     x0,  x1,  [sp, #(0  * 8)]
    ldp     x2,  x3,  [sp, #(2  * 8)]
    ldp     x4,  x5,  [sp, #(4  * 8)]
    ldp     x6,  x7,  [sp, #(6  * 8)]
    ldp     x8,  x9,  [sp, #(8  * 8)]
    ldp     x10, x11, [sp, #(10 * 8)]
    ldp     x12, x13, [sp, #(12 * 8)]
    ldp     x14, x15, [sp, #(14 * 8)]
    ldp     x16, x17, [sp, #(16 * 8)]
    ldp     x18, x19, [sp, #(18 * 8)]
    ldp     x20, x21, [sp, #(20 * 8)]
    ldp     x22, x23, [sp, #(22 * 8)]
    ldp     x24, x25, [sp, #(24 * 8)]
    ldp     x26, x27, [sp, #(26 * 8)]
    ldp     x28, x29, [sp, #(28 * 8)]
    ldr     x30,       [sp, #(30 * 8)]

    add     sp, sp, #(34 * 8)
    eret
.endm

// ── Vector entries ───────────────────────────────────────────────────
// Each entry must be exactly 128 bytes (0x80). We use the macro which
// branches to a Rust handler; the branch instruction fits in 128 bytes.

// Current EL with SP0 (shouldn't happen — we use SPx)
.balign 0x80
    EXCEPTION_ENTRY el2_sync_current_sp0
.balign 0x80
    EXCEPTION_ENTRY el2_irq_current_sp0
.balign 0x80
    EXCEPTION_ENTRY el2_fiq_current_sp0
.balign 0x80
    EXCEPTION_ENTRY el2_serror_current_sp0

// Current EL with SPx (EL2 exceptions while in EL2)
.balign 0x80
    EXCEPTION_ENTRY el2_sync_current_spx
.balign 0x80
    EXCEPTION_ENTRY el2_irq_current_spx
.balign 0x80
    EXCEPTION_ENTRY el2_fiq_current_spx
.balign 0x80
    EXCEPTION_ENTRY el2_serror_current_spx

// Lower EL using AArch64 (guest → hypervisor traps)
.balign 0x80
    EXCEPTION_ENTRY el2_sync_lower_a64
.balign 0x80
    EXCEPTION_ENTRY el2_irq_lower_a64
.balign 0x80
    EXCEPTION_ENTRY el2_fiq_lower_a64
.balign 0x80
    EXCEPTION_ENTRY el2_serror_lower_a64

// Lower EL using AArch32 (not supported — halt)
.balign 0x80
    EXCEPTION_ENTRY el2_sync_lower_a32
.balign 0x80
    EXCEPTION_ENTRY el2_irq_lower_a32
.balign 0x80
    EXCEPTION_ENTRY el2_fiq_lower_a32
.balign 0x80
    EXCEPTION_ENTRY el2_serror_lower_a32
"#);

// ── Rust exception handlers ──────────────────────────────────────────────── //
//
// For now, all handlers print diagnostic info and halt. Once Stage-2
// and guest execution are in place, the "lower EL sync" handler will
// decode ESR_EL2.EC and route to the hypervisor trap handler.

macro_rules! define_handler {
    ($name:ident, $label:expr) => {
        #[no_mangle]
        extern "C" fn $name(ctx: &ExceptionContext) {
            crate::serial_println!();
            crate::serial_println!("*** EL2 EXCEPTION: {} ***", $label);
            crate::serial_println!("{}", ctx);
            loop {
                unsafe { core::arch::asm!("wfi", options(nomem, nostack)) };
            }
        }
    };
}

// Current EL, SP0
define_handler!(el2_sync_current_sp0,   "Sync (Current EL, SP0)");
define_handler!(el2_irq_current_sp0,    "IRQ (Current EL, SP0)");
define_handler!(el2_fiq_current_sp0,    "FIQ (Current EL, SP0)");
define_handler!(el2_serror_current_sp0, "SError (Current EL, SP0)");

// Current EL, SPx
define_handler!(el2_sync_current_spx,   "Sync (Current EL, SPx)");
define_handler!(el2_irq_current_spx,    "IRQ (Current EL, SPx)");
define_handler!(el2_fiq_current_spx,    "FIQ (Current EL, SPx)");
define_handler!(el2_serror_current_spx, "SError (Current EL, SPx)");

// Lower EL, AArch64
define_handler!(el2_sync_lower_a64,   "Sync (Lower EL, AArch64)");
define_handler!(el2_irq_lower_a64,    "IRQ (Lower EL, AArch64)");
define_handler!(el2_fiq_lower_a64,    "FIQ (Lower EL, AArch64)");
define_handler!(el2_serror_lower_a64, "SError (Lower EL, AArch64)");

// Lower EL, AArch32
define_handler!(el2_sync_lower_a32,   "Sync (Lower EL, AArch32)");
define_handler!(el2_irq_lower_a32,    "IRQ (Lower EL, AArch32)");
define_handler!(el2_fiq_lower_a32,    "FIQ (Lower EL, AArch32)");
define_handler!(el2_serror_lower_a32, "SError (Lower EL, AArch32)");

// ── VBAR_EL2 installation ────────────────────────────────────────────────── //

/// Install the EL2 exception vector table.
///
/// Must be called after MMU is enabled (vectors are in .text which is
/// identity-mapped).
pub unsafe fn install_vectors() {
    extern "C" {
        static __vectors_el2: u8;
    }
    let vbar = &__vectors_el2 as *const u8 as u64;
    core::arch::asm!(
        "msr VBAR_EL2, {}",
        "isb",
        in(reg) vbar,
        options(nostack),
    );
    crate::serial_println!("VBAR_EL2 installed at {:#x}", vbar);
}
