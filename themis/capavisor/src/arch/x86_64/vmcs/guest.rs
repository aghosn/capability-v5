//! Guest-state VMCS field setup (segments, control regs, EFER/PAT, RIP/RSP,
//! activity/interruptibility/link pointer, preemption timer, SYSENTER MSRs).
//!
//! Stub state: protected mode (PE only), no paging, all segments flat, RIP=0.
//! `ActiveVcpu::run()` overwrites RIP/RSP/CR3 at P7f for the actual guest entry.

use x86::bits64::vmx;
use x86::vmx::vmcs::guest;

use super::{vmcs_adjust_cr0, vmcs_adjust_cr4};

pub(super) unsafe fn write_guest_state() {
    // ── Segment selectors (all 0 — real or flat protected mode) ─────── //
    for sel_field in [
        guest::ES_SELECTOR,
        guest::CS_SELECTOR,
        guest::SS_SELECTOR,
        guest::DS_SELECTOR,
        guest::FS_SELECTOR,
        guest::GS_SELECTOR,
        guest::TR_SELECTOR,
        guest::LDTR_SELECTOR,
    ] {
        vmx::vmwrite(sel_field, 0).expect("vmwrite guest selector");
    }

    // ── Segment access rights (UNRESTRICTED_GUEST — protected mode) ─── //
    // CS: code, 32-bit, present, DPL=0 (type 0x1B = execute/read/accessed)
    vmx::vmwrite(guest::CS_ACCESS_RIGHTS, 0xC09B).expect("vmwrite guest CS AR");
    // DS/ES: data, 32-bit, present, DPL=0
    vmx::vmwrite(guest::DS_ACCESS_RIGHTS, 0xC093).expect("vmwrite guest DS AR");
    vmx::vmwrite(guest::ES_ACCESS_RIGHTS, 0xC093).expect("vmwrite guest ES AR");
    vmx::vmwrite(guest::SS_ACCESS_RIGHTS, 0xC093).expect("vmwrite guest SS AR");
    // FS/GS/LDTR: unusable
    vmx::vmwrite(guest::FS_ACCESS_RIGHTS, 0x10000).expect("vmwrite guest FS AR");
    vmx::vmwrite(guest::GS_ACCESS_RIGHTS, 0x10000).expect("vmwrite guest GS AR");
    vmx::vmwrite(guest::LDTR_ACCESS_RIGHTS, 0x10000).expect("vmwrite guest LDTR AR");
    // TR: busy TSS, present (type 0x8B = TSS32 busy)
    vmx::vmwrite(guest::TR_ACCESS_RIGHTS, 0x8B).expect("vmwrite guest TR AR");

    // ── Segment limits ────────────────────────────────────────────────── //
    for lim_field in [
        guest::ES_LIMIT,
        guest::CS_LIMIT,
        guest::SS_LIMIT,
        guest::DS_LIMIT,
        guest::FS_LIMIT,
        guest::GS_LIMIT,
        guest::LDTR_LIMIT,
    ] {
        vmx::vmwrite(lim_field, 0xFFFF_FFFF).expect("vmwrite guest seg limit");
    }
    vmx::vmwrite(guest::TR_LIMIT, 0xFF).expect("vmwrite guest TR limit");
    vmx::vmwrite(guest::GDTR_LIMIT, 0xFFFF).expect("vmwrite guest GDTR limit");
    vmx::vmwrite(guest::IDTR_LIMIT, 0xFFFF).expect("vmwrite guest IDTR limit");

    // ── Segment bases (all 0) ─────────────────────────────────────────── //
    for base_field in [
        guest::ES_BASE,
        guest::CS_BASE,
        guest::SS_BASE,
        guest::DS_BASE,
        guest::FS_BASE,
        guest::GS_BASE,
        guest::TR_BASE,
        guest::LDTR_BASE,
        guest::GDTR_BASE,
        guest::IDTR_BASE,
    ] {
        vmx::vmwrite(base_field, 0).expect("vmwrite guest seg base");
    }

    // ── Control registers ─────────────────────────────────────────────── //
    // CR0: PE (bit 0) + ET (bit 4) + NE (bit 5) = 0x31, plus any other
    // FIXED0-required bits from this CPU.  PG is NOT set — UNRESTRICTED_GUEST
    // allows no-paging protected mode.
    vmx::vmwrite(guest::CR0, vmcs_adjust_cr0(0x31)).expect("vmwrite guest CR0");
    vmx::vmwrite(guest::CR3, 0).expect("vmwrite guest CR3");
    // CR4: VMXE (bit 13) is required by IA32_VMX_CR4_FIXED0.
    vmx::vmwrite(guest::CR4, vmcs_adjust_cr4(0)).expect("vmwrite guest CR4");

    // ── EFER: 0 (no long mode in the stub; P7f sets LME+LMA for Linux) ── //
    vmx::vmwrite(guest::IA32_EFER_FULL, 0).expect("vmwrite guest EFER");
    // ── PAT: default value (same as vmxvmm) ─────────────────────────── //
    vmx::vmwrite(guest::IA32_PAT_FULL, 0x0007_0406_0007_0406u64).expect("vmwrite guest PAT");

    // ── General purpose / misc ────────────────────────────────────────── //
    vmx::vmwrite(guest::RIP, 0).expect("vmwrite guest RIP");
    vmx::vmwrite(guest::RSP, 0).expect("vmwrite guest RSP");
    vmx::vmwrite(guest::RFLAGS, 0x2).expect("vmwrite guest RFLAGS"); // reserved bit
    vmx::vmwrite(guest::DR7, 0x400).expect("vmwrite guest DR7");

    // ── State fields ──────────────────────────────────────────────────── //
    vmx::vmwrite(guest::ACTIVITY_STATE, 0).expect("vmwrite guest activity state");
    vmx::vmwrite(guest::INTERRUPTIBILITY_STATE, 0).expect("vmwrite guest interruptibility");
    vmx::vmwrite(guest::PENDING_DBG_EXCEPTIONS, 0).expect("vmwrite guest pending dbg");
    // VMCS link pointer: 0xFFFF…FFFF means no shadow VMCS.
    vmx::vmwrite(guest::LINK_PTR_FULL, u64::MAX).expect("vmwrite VMCS link ptr");
    // GUEST_INTERRUPT_STATUS (RVI | SVI): required when VID=1.
    // RVI=0: no pending virtual interrupt on entry.  SVI=0: no in-service virtual interrupt.
    // Written to 0 here; updated automatically by hardware when VID delivers vIRR bits.
    vmx::vmwrite(guest::INTERRUPT_STATUS, 0).expect("vmwrite GUEST_INTERRUPT_STATUS");
    // Preemption timer: initialise to a non-zero value so the first VMENTRY
    // does not fire an immediate timer exit (a timer value of 0 fires on the
    // first cycle).  The monitor loop resets it on every timer exit anyway.
    vmx::vmwrite(
        guest::VMX_PREEMPTION_TIMER_VALUE,
        crate::arch::vmexit::PREEMPTION_TIMER_TICKS,
    )
    .expect("vmwrite guest preemption timer");

    // ── SYSENTER MSRs ─────────────────────────────────────────────────── //
    vmx::vmwrite(guest::IA32_SYSENTER_CS, 0).expect("vmwrite guest SYSENTER_CS");
    vmx::vmwrite(guest::IA32_SYSENTER_ESP, 0).expect("vmwrite guest SYSENTER_ESP");
    vmx::vmwrite(guest::IA32_SYSENTER_EIP, 0).expect("vmwrite guest SYSENTER_EIP");
}
