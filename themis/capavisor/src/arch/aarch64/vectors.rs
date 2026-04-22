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

/// PSCI function IDs (SMCCC convention).
#[allow(dead_code)]
pub mod psci {
    pub const VERSION: u64 = 0x8400_0000;
    pub const CPU_SUSPEND_32: u64 = 0x8400_0001;
    pub const CPU_OFF: u64 = 0x8400_0002;
    pub const CPU_ON_64: u64 = 0xC400_0003;
    pub const CPU_ON_32: u64 = 0x8400_0003;
    pub const AFFINITY_INFO_64: u64 = 0xC400_0004;
    pub const MIGRATE_INFO_TYPE: u64 = 0x8400_0006;
    pub const SYSTEM_OFF: u64 = 0x8400_0008;
    pub const SYSTEM_RESET: u64 = 0x8400_0009;
    pub const FEATURES: u64 = 0x8400_000A;

    // SMCCC architecture calls
    pub const SMCCC_VERSION: u64 = 0x8000_0000;
    pub const SMCCC_ARCH_FEATURES: u64 = 0x8000_0001;
    pub const SMCCC_ARCH_SOC_ID: u64 = 0x8000_0002;
    pub const SMCCC_ARCH_WORKAROUND_1: u64 = 0x8000_8000;
    pub const SMCCC_ARCH_WORKAROUND_2: u64 = 0x8000_7FFF;
    pub const SMCCC_TRNG_VERSION: u64 = 0x8400_0050;

    /// Return values.
    pub const SUCCESS: u64 = 0;
    pub const NOT_SUPPORTED: u64 = (-1i64) as u64;
    pub const ALREADY_ON: u64 = (-6i64) as u64;
    /// PSCI 1.0
    pub const VERSION_1_0: u64 = 0x0001_0000;
    /// SMCCC 1.1
    pub const SMCCC_VERSION_1_1: u64 = 0x0001_0001;
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

// ── Shared trampoline: save context, call handler, restore, ERET ─────
// Each vector entry branches here via `b`. The handler address is in x0
// (set by the small per-entry stub).
//
// Convention: before branching here, the entry stub does:
//   stp  x0, x1, [sp, #-16]!    // save X0, X1 (need two scratch regs)
//   adr  x0, <handler_addr_var>  // load address of the Rust handler
//   ldr  x0, [x0]
//   b    __trampoline
//
// ...but that's still too many instructions for 128 bytes. Instead, we use
// a simpler scheme: each entry just branches to a per-handler trampoline
// that's placed OUTSIDE the vector table. The vector entries are just:
//   b  __tramp_<handler>
// which is 1 instruction = 4 bytes, well within 128 bytes.

// ── Per-handler trampolines (placed after the vector table) ──────────
.macro TRAMPOLINE handler
.balign 16
__tramp_\handler:
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

    // Restore ELR_EL2, SPSR_EL2 (handler may have modified them)
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

// ── Vector table ─────────────────────────────────────────────────────
// Each entry is exactly 128 bytes (0x80). We use a single `b` instruction
// (4 bytes) to jump to the trampoline code placed after the table.
// VBAR_EL2 must be 2048-byte (0x800) aligned.

.balign 2048
.global __vectors_el2
__vectors_el2:

// Current EL with SP0 (shouldn't happen — we use SPx)
.balign 0x80
    b   __tramp_el2_sync_current_sp0
.balign 0x80
    b   __tramp_el2_irq_current_sp0
.balign 0x80
    b   __tramp_el2_fiq_current_sp0
.balign 0x80
    b   __tramp_el2_serror_current_sp0

// Current EL with SPx (EL2 exceptions while in EL2)
.balign 0x80
    b   __tramp_el2_sync_current_spx
.balign 0x80
    b   __tramp_el2_irq_current_spx
.balign 0x80
    b   __tramp_el2_fiq_current_spx
.balign 0x80
    b   __tramp_el2_serror_current_spx

// Lower EL using AArch64 (guest → hypervisor traps)
.balign 0x80
    b   __tramp_el2_sync_lower_a64
.balign 0x80
    b   __tramp_el2_irq_lower_a64
.balign 0x80
    b   __tramp_el2_fiq_lower_a64
.balign 0x80
    b   __tramp_el2_serror_lower_a64

// Lower EL using AArch32 (not supported — halt)
.balign 0x80
    b   __tramp_el2_sync_lower_a32
.balign 0x80
    b   __tramp_el2_irq_lower_a32
.balign 0x80
    b   __tramp_el2_fiq_lower_a32
.balign 0x80
    b   __tramp_el2_serror_lower_a32

// ── Trampolines (outside the 2048-byte vector table) ─────────────────

TRAMPOLINE el2_sync_current_sp0
TRAMPOLINE el2_irq_current_sp0
TRAMPOLINE el2_fiq_current_sp0
TRAMPOLINE el2_serror_current_sp0

TRAMPOLINE el2_sync_current_spx
TRAMPOLINE el2_irq_current_spx
TRAMPOLINE el2_fiq_current_spx
TRAMPOLINE el2_serror_current_spx

TRAMPOLINE el2_sync_lower_a64
TRAMPOLINE el2_irq_lower_a64
TRAMPOLINE el2_fiq_lower_a64
TRAMPOLINE el2_serror_lower_a64

TRAMPOLINE el2_sync_lower_a32
TRAMPOLINE el2_irq_lower_a32
TRAMPOLINE el2_fiq_lower_a32
TRAMPOLINE el2_serror_lower_a32
"#);

// ── Rust exception handlers ──────────────────────────────────────────────── //

/// Default handler: print diagnostic info and halt.
/// Used for unexpected exceptions (current EL, AArch32 lower EL).
macro_rules! define_handler {
    ($name:ident, $label:expr) => {
        #[no_mangle]
        extern "C" fn $name(ctx: &mut ExceptionContext) {
            crate::serial_println!();
            crate::serial_println!("*** EL2 EXCEPTION: {} ***", $label);
            crate::serial_println!("{}", ctx);
            loop {
                unsafe { core::arch::asm!("wfi", options(nomem, nostack)) };
            }
        }
    };
}

/// Handler that prints and returns (ERETs back to source).
/// Used for interrupts from lower EL that we want to let pass.
macro_rules! define_return_handler {
    ($name:ident, $label:expr) => {
        #[no_mangle]
        extern "C" fn $name(_ctx: &mut ExceptionContext) {
            // Return to guest — the asm stub will restore context and ERET.
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

// ── Lower EL, AArch64: guest trap handlers ───────────────────────────────── //

/// Synchronous exception from guest (EL1/EL0).
/// Decodes ESR_EL2.EC and dispatches:
///  - HVC: print + advance ELR + return to guest
///  - Data/Inst Abort: print fault info + halt
///  - WFI/WFE: advance ELR + return to guest
///  - Others: print + halt
#[no_mangle]
extern "C" fn el2_sync_lower_a64(ctx: &mut ExceptionContext) {
    let ec = (ctx.esr_el2 >> 26) & 0x3F;
    let iss = ctx.esr_el2 & 0x1FF_FFFF;
    // IL bit (bit 25): 1 = 32-bit instruction, 0 = 16-bit
    let il = if (ctx.esr_el2 >> 25) & 1 == 1 { 4u64 } else { 2u64 };

    match ec {
        ec::HVC64 => {
            let func_id = ctx.gpr[0];
            handle_hvc(ctx, func_id, il);
        }

        ec::WFI_WFE => {
            // Guest executed WFI/WFE — just advance past it and return.
            // In a real hypervisor we might yield the vCPU here.
            ctx.elr_el2 += il;
        }

        ec::DATA_ABORT_LOWER => {
            // Read FAR_EL2 (faulting virtual address) and HPFAR_EL2 (IPA)
            let far: u64;
            let hpfar: u64;
            unsafe {
                core::arch::asm!("mrs {}, FAR_EL2", out(reg) far, options(nostack));
                core::arch::asm!("mrs {}, HPFAR_EL2", out(reg) hpfar, options(nostack));
            }
            let ipa = (hpfar & 0xFFFF_FFFF_F0) << 8; // HPFAR[43:4] → IPA[47:12]
            crate::serial_println!();
            crate::serial_println!(
                "*** EL2: Data Abort (Lower EL) ***\n  FAR={:#x}, IPA={:#x}, ISS={:#x}",
                far, ipa, iss
            );
            crate::serial_println!("{}", ctx);
            loop { unsafe { core::arch::asm!("wfi", options(nomem, nostack)) }; }
        }

        ec::INST_ABORT_LOWER => {
            let far: u64;
            let hpfar: u64;
            unsafe {
                core::arch::asm!("mrs {}, FAR_EL2", out(reg) far, options(nostack));
                core::arch::asm!("mrs {}, HPFAR_EL2", out(reg) hpfar, options(nostack));
            }
            let ipa = (hpfar & 0xFFFF_FFFF_F0) << 8;
            crate::serial_println!();
            crate::serial_println!(
                "*** EL2: Instruction Abort (Lower EL) ***\n  FAR={:#x}, IPA={:#x}, ISS={:#x}",
                far, ipa, iss
            );
            crate::serial_println!("{}", ctx);
            loop { unsafe { core::arch::asm!("wfi", options(nomem, nostack)) }; }
        }

        ec::SYS_REG => {
            // ISS encoding for sysreg traps: Op0[21:20], Op2[19:17],
            // Op1[16:14], CRn[13:10], CRm[4:1], Rt[9:5], Direction[0]
            let direction = if iss & 1 == 0 { "write" } else { "read" };
            let crn = (iss >> 10) & 0xF;
            let crm = (iss >> 1) & 0xF;
            let op1 = (iss >> 14) & 0x7;
            let op2 = (iss >> 17) & 0x7;
            let rt = (iss >> 5) & 0x1F;
            crate::serial_println!(
                "[EL2] SysReg trap: {} Op1={} CRn={} CRm={} Op2={} Rt=X{} ELR={:#x}",
                direction, op1, crn, crm, op2, rt, ctx.elr_el2
            );
            // Advance past the trapped instruction
            ctx.elr_el2 += il;
        }

        ec::SMC64 => {
            // SMC is used for PSCI on some firmware/DTB configurations.
            // Handle the same way as HVC.
            let func_id = ctx.gpr[0];
            handle_hvc(ctx, func_id, il);
        }

        _ => {
            crate::serial_println!();
            crate::serial_println!(
                "*** EL2: Unhandled Sync (Lower EL) EC={:#x} ISS={:#x} ***",
                ec, iss
            );
            crate::serial_println!("{}", ctx);
            loop { unsafe { core::arch::asm!("wfi", options(nomem, nostack)) }; }
        }
    }
}

/// IRQ from lower EL — return to guest (IRQ handled by guest's own GIC config
/// in direct-assignment mode, or needs vGIC injection in virtualized mode).
define_return_handler!(el2_irq_lower_a64, "IRQ (Lower EL, AArch64)");

// ── PSCI / HVC dispatch ─────────────────────────────────────────────────── //

/// Handle an HVC call from the guest. Decodes PSCI function IDs
/// and returns results in X0. Non-PSCI HVCs are logged.
fn handle_hvc(ctx: &mut ExceptionContext, func_id: u64, il: u64) {
    match func_id {
        // ── SMCCC architecture calls ──
        psci::SMCCC_VERSION => {
            ctx.gpr[0] = psci::SMCCC_VERSION_1_1;
        }
        psci::SMCCC_ARCH_FEATURES => {
            let requested = ctx.gpr[1];
            ctx.gpr[0] = match requested {
                psci::SMCCC_ARCH_WORKAROUND_1 | psci::SMCCC_ARCH_WORKAROUND_2 => {
                    psci::NOT_SUPPORTED
                }
                psci::SMCCC_VERSION | psci::SMCCC_ARCH_FEATURES => psci::SUCCESS,
                _ => psci::NOT_SUPPORTED,
            };
        }
        psci::SMCCC_ARCH_SOC_ID => {
            ctx.gpr[0] = psci::NOT_SUPPORTED;
        }
        psci::SMCCC_TRNG_VERSION => {
            ctx.gpr[0] = psci::NOT_SUPPORTED;
        }

        // ── PSCI calls ──
        psci::VERSION => {
            ctx.gpr[0] = psci::VERSION_1_0;
        }
        psci::FEATURES => {
            let requested = ctx.gpr[1];
            // Report which PSCI features we support.
            ctx.gpr[0] = match requested {
                psci::VERSION | psci::SYSTEM_OFF | psci::SYSTEM_RESET
                | psci::CPU_OFF | psci::MIGRATE_INFO_TYPE => psci::SUCCESS,
                _ => psci::NOT_SUPPORTED,
            };
        }
        psci::CPU_ON_64 | psci::CPU_ON_32 => {
            // Secondary CPU bringup — not supported yet (UP only).
            crate::serial_println!(
                "[EL2] PSCI CPU_ON: target={:#x}, entry={:#x} — NOT_SUPPORTED",
                ctx.gpr[1], ctx.gpr[2]
            );
            ctx.gpr[0] = psci::NOT_SUPPORTED;
        }
        psci::CPU_OFF => {
            crate::serial_println!("[EL2] PSCI CPU_OFF — halting vCPU");
            loop { unsafe { core::arch::asm!("wfi", options(nomem, nostack)) }; }
        }
        psci::CPU_SUSPEND_32 => {
            // Treat as WFI for now.
            ctx.gpr[0] = psci::SUCCESS;
        }
        psci::AFFINITY_INFO_64 => {
            // All CPUs OFF for now (single-CPU).
            ctx.gpr[0] = 1; // OFF
        }
        psci::MIGRATE_INFO_TYPE => {
            // 2 = TOS not present (no Trusted OS migration needed).
            ctx.gpr[0] = 2;
        }
        psci::SYSTEM_OFF => {
            crate::serial_println!("[EL2] PSCI SYSTEM_OFF — shutting down");
            loop { unsafe { core::arch::asm!("wfi", options(nomem, nostack)) }; }
        }
        psci::SYSTEM_RESET => {
            crate::serial_println!("[EL2] PSCI SYSTEM_RESET — halting (no reset impl)");
            loop { unsafe { core::arch::asm!("wfi", options(nomem, nostack)) }; }
        }
        _ => {
            // Non-PSCI HVC — log it.
            crate::serial_println!(
                "[EL2] HVC: func={:#x}, X1={:#x}, X2={:#x}, X3={:#x}",
                func_id, ctx.gpr[1], ctx.gpr[2], ctx.gpr[3]
            );
        }
    }
    // Advance past the HVC instruction.
    ctx.elr_el2 += il;
}

/// FIQ from lower EL — return to guest.
define_return_handler!(el2_fiq_lower_a64, "FIQ (Lower EL, AArch64)");

/// SError from lower EL — fatal, halt.
define_handler!(el2_serror_lower_a64, "SError (Lower EL, AArch64)");

// Lower EL, AArch32 (unsupported)
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
