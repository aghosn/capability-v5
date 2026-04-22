//! AArch64 vCPU entry and guest stub for M5a bringup.
//!
//! Provides:
//! - `enter_guest_initial()`: one-way ERET from EL2 into a guest at EL1
//! - `GUEST_STUB`: a tiny EL1 program that writes to PL011 and does HVC traps
//!
//! The guest stub is copied into guest RAM and executed via Stage-2 translation.

/// SPSR_EL2 value for EL1h with DAIF masked (all exceptions masked).
/// M[3:0]=0b0101 (EL1h), D=1, A=1, I=1, F=1 → bits[9:6]=0b1111.
pub const SPSR_EL1H_DAIF: u64 = 0x3C5;

/// Enter a guest for the first time (non-returning).
///
/// Sets ELR_EL2, SPSR_EL2, SP_EL1, guest X0, and ERETs to EL1.
/// All other guest GPRs are zeroed.
///
/// # Safety
/// - Stage-2 must be configured and VTTBR_EL2 loaded
/// - HCR_EL2.VM must be set
/// - `entry` must be a valid IPA mapped in Stage-2
#[inline(never)]
pub unsafe fn enter_guest_initial(entry: u64, sp_el1: u64, x0_dtb: u64) -> ! {
    core::arch::asm!(
        // Set return address and saved processor state
        "msr ELR_EL2, {entry}",
        "msr SPSR_EL2, {spsr}",
        // Set guest SP_EL1
        "msr SP_EL1, {sp}",
        // Set guest X0 (e.g., DTB pointer)
        "mov x0, {x0}",
        // Zero X1–X3 (ARM64 boot protocol)
        "mov x1, xzr",
        "mov x2, xzr",
        "mov x3, xzr",
        // Barrier before world switch
        "isb",
        // Enter guest — does not return to caller
        "eret",
        entry = in(reg) entry,
        spsr = in(reg) SPSR_EL1H_DAIF,
        sp = in(reg) sp_el1,
        x0 = in(reg) x0_dtb,
        options(noreturn),
    )
}

// ── Guest stub (tiny EL1 program) ────────────────────────────────────────── //
//
// This is assembled into .text and copied to guest RAM at runtime.
// It writes "Hello from EL1\n" to PL011 UART, then does two HVC traps,
// then enters a WFI loop.

core::arch::global_asm!(r#"
.section .text
.balign 16
.global __guest_stub_start
.global __guest_stub_end

__guest_stub_start:
    // ── Write "Hello from EL1\n" to PL011 UART at 0x09000000 ──
    mov     x1, #0x09000000

    mov     w2, #'H'
    strb    w2, [x1]
    mov     w2, #'e'
    strb    w2, [x1]
    mov     w2, #'l'
    strb    w2, [x1]
    mov     w2, #'l'
    strb    w2, [x1]
    mov     w2, #'o'
    strb    w2, [x1]
    mov     w2, #' '
    strb    w2, [x1]
    mov     w2, #'f'
    strb    w2, [x1]
    mov     w2, #'r'
    strb    w2, [x1]
    mov     w2, #'o'
    strb    w2, [x1]
    mov     w2, #'m'
    strb    w2, [x1]
    mov     w2, #' '
    strb    w2, [x1]
    mov     w2, #'E'
    strb    w2, [x1]
    mov     w2, #'L'
    strb    w2, [x1]
    mov     w2, #'1'
    strb    w2, [x1]
    mov     w2, #'\n'
    strb    w2, [x1]

    // ── HVC trap #1 ──
    mov     x0, #0xDEAD
    hvc     #0

    // ── HVC trap #2 ──
    movz    x0, #0xBEEF
    hvc     #0

    // ── WFI loop ──
1:  wfi
    b       1b

__guest_stub_end:
"#);

/// Returns the (start, end) virtual addresses of the guest stub binary.
///
/// The stub can be copied to guest RAM and executed at EL1.
pub fn guest_stub_range() -> (*const u8, *const u8) {
    extern "C" {
        static __guest_stub_start: u8;
        static __guest_stub_end: u8;
    }
    unsafe {
        (
            core::ptr::addr_of!(__guest_stub_start),
            core::ptr::addr_of!(__guest_stub_end),
        )
    }
}
