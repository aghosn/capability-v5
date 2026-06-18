//! VMCS control-field setup (pin-based, proc-based, exit/entry, EPTP, VPID,
//! exception/EOI/IO/MSR bitmaps, posted-interrupt fields).

use x86::bits64::vmx;
use x86::msr;
use x86::vmx::vmcs::{control, guest};

use crate::serial_println;

use super::POSTED_INTR_NOTIFY_VEC;

/// Apply allowed-0 / allowed-1 mask from a VMX capability MSR to `desired`.
///
/// `low32` = bits that MUST be 1 (OR'd in).
/// `high32` = bits that MAY be 1 (AND'd in).
fn adjust(desired: u64, msr_value: u64) -> u64 {
    let must_be_1 = msr_value & 0xFFFF_FFFF; // allowed-0 → must be 1
    let may_be_1 = (msr_value >> 32) & 0xFFFF_FFFF; // allowed-1 → may be 1
    (desired | must_be_1) & may_be_1
}

/// Read a VMX capability MSR and return its 64-bit value.
///
/// Uses the TRUE variant when IA32_VMX_BASIC[55] = 1.
fn vmx_ctrl_msr(basic_msr: u32, true_msr: u32) -> u64 {
    let basic = unsafe { msr::rdmsr(msr::IA32_VMX_BASIC) };
    if (basic >> 55) & 1 == 1 {
        unsafe { msr::rdmsr(true_msr) }
    } else {
        unsafe { msr::rdmsr(basic_msr) }
    }
}

pub(super) unsafe fn write_control_fields(
    eptp: u64,
    vapic_phys: u64,
    msr_bitmap_phys: u64,
    pid_phys: u64,
    apic_access_phys: u64,
    io_bitmap_a_phys: u64,
    io_bitmap_b_phys: u64,
    vpid: u16,
    child: bool,
) {
    // ── Pin-based ──────────────────────────────────────────────────── //
    let mut pin_desired: u64 = 1 << 6; // ACTIVATE_VMX_PREEMPTION_TIMER
    if child {
        pin_desired |= 1 << 0; // EXTERNAL_INTERRUPT_EXITING
        pin_desired |= 1 << 3; // NMI_EXITING — NMIs from child VM always exit to capavisor
                               // PROCESS_POSTED_INTERRUPTS (bit 7) intentionally NOT set.
                               // Under nested virtualisation (QEMU/KVM) the host advertises PI
                               // support but L2 posted-interrupt delivery is unreliable.  We use
                               // the software PIR drain in do_switch() instead — it works on both
                               // nested and bare-metal.
    }
    let pin_msr = vmx_ctrl_msr(
        msr::IA32_VMX_PINBASED_CTLS,
        msr::IA32_VMX_TRUE_PINBASED_CTLS,
    );
    let pin_val = adjust(pin_desired, pin_msr);
    vmx::vmwrite(control::PINBASED_EXEC_CONTROLS, pin_val).expect("vmwrite pin-based");

    // ── Primary proc-based ────────────────────────────────────────────── //
    // USE_TPR_SHADOW (bit 21): required prerequisite for APIC_REGISTER_VIRT
    // and VID.  With TPR_THRESHOLD=0 it causes no threshold exits; CR8 writes
    // in the guest land in VAPIC.vTPR (benign for dom0 since TPR_THRESHOLD=0).
    let mut primary_desired: u64 = (1 << 21)  // USE_TPR_SHADOW
        | (1 << 28) // USE_MSR_BITMAPS
        | (1 << 31); // ACTIVATE_SECONDARY_CONTROLS
    if child {
        primary_desired |= 1 << 7; // HLT_EXITING
        primary_desired |= 1 << 24; // USE_IO_BITMAPS — selective I/O port trapping (serial UART etc.)
    }
    let primary_msr = vmx_ctrl_msr(
        msr::IA32_VMX_PROCBASED_CTLS,
        msr::IA32_VMX_TRUE_PROCBASED_CTLS,
    );
    let primary_val = adjust(primary_desired, primary_msr);
    vmx::vmwrite(control::PRIMARY_PROCBASED_EXEC_CONTROLS, primary_val)
        .expect("vmwrite primary proc-based");

    // ── Secondary proc-based ──────────────────────────────────────────── //
    // ENABLE_RDTSCP (bit 3), ENABLE_EPT (bit 1), ENABLE_VPID (bit 5),
    // UNRESTRICTED_GUEST (bit 7), ENABLE_XSAVES (bit 20).
    //
    // APIC virtualisation, two mutually-exclusive modes:
    //   • Dom0: VIRTUALIZE_APIC_ACCESSES (bit 0) when apic_access_phys != 0,
    //     plus APIC_REGISTER_VIRT (bit 8). Dom0 runs in xAPIC mode.
    //   • Child: VIRTUALIZE_X2APIC_MODE (bit 4) + APIC_REGISTER_VIRT (bit 8)
    //     + VID (bit 9). Children are pinned to x2APIC mode from boot
    //     (CHV pushes IA32_APIC_BASE = EN|EXTD via MSR_EMULATE policy, and a
    //     Native MSR bitmap range for 0x800..=0x83F except ICR 0x830 which
    //     stays Trap and forwards to CHV's deliver_ipi). The xAPIC MMIO
    //     decoder (vmexit/apic.rs::decode_apic_write_value) is therefore
    //     dead code for children — the first APIC write is WRMSR(0x830),
    //     never an xAPIC MOV.
    //
    // VIRT_X2APIC_MODE (bit 4) and VIRT_APIC_ACCESSES (bit 0) are mutually
    // exclusive per SDM Vol 3C §26.2.1.1 — children use bit 4 instead of
    // bit 0. Self-IPI WRMSR(0x83F) under VID=1 is fully hardware-handled
    // (zero exits) — this is the perf-win that motivates the switch.
    // Pre-read secondary cap MSR so we can gate the x2APIC virtualization
    // path on hardware support.  Nested KVM (L0) typically does not expose
    // VIRT_X2APIC_MODE / APIC_REGISTER_VIRT / VID — when any of bits 4, 8, 9
    // are missing from allowed-1, fall back to the xAPIC MMIO path for
    // children (EPT-violation forwarding via arch_state::change_rights),
    // and never advertise FEATURE_X2APIC_VIRT to dom0 userspace.  See
    // themis_abi::cpuid::feature_bits::FEATURE_X2APIC_VIRT.
    let secondary_msr = unsafe { msr::rdmsr(msr::IA32_VMX_PROCBASED_CTLS2) };
    let allowed1 = (secondary_msr >> 32) as u32;
    let x2apic_virt_hw =
        (allowed1 & (1 << 4)) != 0 && (allowed1 & (1 << 8)) != 0 && (allowed1 & (1 << 9)) != 0;

    let want_virt_x2apic_child = child && x2apic_virt_hw;
    let want_virt_apic_accesses_dom0 = !child && apic_access_phys != 0;
    let want_apic_reg_virt = true; // both dom0 and child (cleared by adjust() if unsupported)
    let want_vid_child = child && x2apic_virt_hw; // VID only useful alongside VIRT_X2APIC_MODE
    let secondary_desired: u64 = (1 << 1)   // ENABLE_EPT
        | (1 << 3) // ENABLE_RDTSCP
        | (1 << 5) // ENABLE_VPID
        | (1 << 7) // UNRESTRICTED_GUEST
        | (if want_apic_reg_virt { 1 << 8 } else { 0 }) // APIC_REGISTER_VIRT
        | (if want_vid_child { 1 << 9 } else { 0 })     // VID
        | (if want_virt_x2apic_child { 1 << 4 } else { 0 }) // VIRT_X2APIC_MODE (child)
        | (if want_virt_apic_accesses_dom0 { 1 << 0 } else { 0 }) // VIRT_APIC_ACCESSES (dom0)
        | (1 << 12) // ENABLE_INVPCID
        | (1 << 20); // ENABLE_XSAVES_XRSTORS
    let secondary_val = adjust(secondary_desired, secondary_msr);
    vmx::vmwrite(control::SECONDARY_PROCBASED_EXEC_CONTROLS, secondary_val)
        .expect("vmwrite secondary proc-based");

    if want_virt_apic_accesses_dom0 && (secondary_val & (1 << 0)) == 0 {
        serial_println!(
            "  [WARN] VIRTUALIZE_APIC_ACCESSES not supported by hardware — \
             LAPIC MMIO will use EPT violation fallback"
        );
    }
    if want_virt_x2apic_child && (secondary_val & (1 << 4)) == 0 {
        serial_println!(
            "  [WARN] VIRTUALIZE_X2APIC_MODE not supported by hardware — \
             child x2APIC MSRs will all trap to capavisor"
        );
    }
    if want_vid_child && (secondary_val & (1 << 9)) == 0 {
        serial_println!(
            "  [WARN] Virtual-Interrupt-Delivery (VID) not supported — \
             self-IPI WRMSR(0x83F) will exit instead of running natively"
        );
    }

    // XSS-exiting bitmap: only valid when ENABLE_XSAVES (bit 20) is active.
    if secondary_val & (1 << 20) != 0 {
        // 0 = no XSAVES/XRSTORS cause VM exits; all execute natively.
        vmx::vmwrite(control::XSS_EXITING_BITMAP_FULL, 0).expect("vmwrite XSS-exiting bitmap");
    }

    // ── VM-exit controls ──────────────────────────────────────────────── //
    // HOST_ADDRESS_SPACE_SIZE, SAVE/LOAD IA32_EFER and IA32_PAT,
    // SAVE_VMX_PREEMPTION_TIMER (bit 22) — preserve timer across exits.
    // ACKNOWLEDGE_INTERRUPT_ON_EXIT (bit 15): for child VMCSes with
    // EXTERNAL_INTERRUPT_EXITING=1, the hardware ACKs (sends EOI) the
    // interrupt on exit so it is consumed.  Without this, the LAPIC keeps
    // the interrupt pending and it fires again on every VMRESUME, causing an
    // infinite external-interrupt exit loop that prevents the child from ever
    // executing its first instruction.
    let exit_desired: u64 = (1 << 9)   // HOST_ADDRESS_SPACE_SIZE
        | (if child { 1 << 15 } else { 0 }) // ACKNOWLEDGE_INTERRUPT_ON_EXIT
        | (1 << 18) // SAVE_IA32_PAT
        | (1 << 19) // LOAD_IA32_PAT
        | (1 << 20) // SAVE_IA32_EFER
        | (1 << 21) // LOAD_IA32_EFER
        | (1 << 22); // SAVE_VMX_PREEMPTION_TIMER
    let exit_msr = vmx_ctrl_msr(msr::IA32_VMX_EXIT_CTLS, msr::IA32_VMX_TRUE_EXIT_CTLS);
    let exit_val = adjust(exit_desired, exit_msr);
    vmx::vmwrite(control::VMEXIT_CONTROLS, exit_val).expect("vmwrite vm-exit controls");

    // ── VM-entry controls ─────────────────────────────────────────────── //
    // No IA32E_MODE_GUEST (bit 9): guest starts in 32-bit protected mode.
    // LOAD_IA32_EFER (bit 15): load guest EFER from VMCS on each VM entry
    // so the guest doesn't inherit the host's EFER (which has LMA=1).
    // Without this, the guest runs in an architecturally undefined state
    // (LMA=1 + CR0.PG=0).
    let entry_desired: u64 = (1 << 14)  // LOAD_IA32_PAT
        | (1 << 15); // LOAD_IA32_EFER
    let entry_msr = vmx_ctrl_msr(msr::IA32_VMX_ENTRY_CTLS, msr::IA32_VMX_TRUE_ENTRY_CTLS);
    let entry_val = adjust(entry_desired, entry_msr);
    vmx::vmwrite(control::VMENTRY_CONTROLS, entry_val).expect("vmwrite vm-entry controls");

    // ── EPT pointer ───────────────────────────────────────────────────── //
    vmx::vmwrite(control::EPTP_FULL, eptp).expect("vmwrite EPTP");

    // ── VPID ──────────────────────────────────────────────────────────── //
    // VPID 0 is reserved for the VMX-root context. Caller provides the
    // final 1-based VPID value directly.
    assert!(vpid != 0, "VPID 0 is reserved for VMX-root");
    vmx::vmwrite(control::VPID as u32, vpid as u64).expect("vmwrite VPID");

    // ── Exception bitmap: do not intercept any exceptions ─────────────────── //
    // All exceptions are handled by the guest's own IDT.
    vmx::vmwrite(control::EXCEPTION_BITMAP, 0).expect("vmwrite exception bitmap");

    // ── CR0/CR4 guest-host masks ──────────────────────────────────────────── //
    // CR0: mask the FIXED0 bits (except PE/PG which UNRESTRICTED_GUEST exempts).
    // In VMX non-root, writing a CR0 value that violates IA32_VMX_CR0_FIXED0
    // causes #GP(0).  Linux startup_32 writes CR0 = 0x80000001 (PG+PE only),
    // dropping NE (bit 5) which FIXED0 requires.  By masking the FIXED0 bits
    // the host owns them (always forced to 1) while the shadow reads 0, so the
    // guest sees normal hardware behavior — no #GP, no VM exit.
    let cr0_fixed0 = unsafe { msr::rdmsr(msr::IA32_VMX_CR0_FIXED0) };
    let cr0_mask = cr0_fixed0 & !((1u64 << 0) | (1u64 << 31)); // remove PE, PG
    vmx::vmwrite(control::CR0_GUEST_HOST_MASK, cr0_mask).expect("vmwrite CR0 mask");
    vmx::vmwrite(control::CR0_READ_SHADOW, 0).expect("vmwrite CR0 shadow");
    // CR4: own VMXE (bit 13) only. The SDM mandates that in VMX non-root
    // operation, any guest attempt to clear CR4.VMXE causes #GP(0).
    // With mask bit 13 = 1 and shadow bit 13 = 1, a guest write that clears
    // VMXE instead causes a CR_ACCESS VM exit, which our handler resolves by
    // preserving VMXE=1 in the written value.
    // All other CR4 bits (PAE, PGE, etc.) are guest-controlled (mask=0).
    const CR4_VMXE: u64 = 1 << 13;
    vmx::vmwrite(control::CR4_GUEST_HOST_MASK, CR4_VMXE).expect("vmwrite CR4 mask");
    vmx::vmwrite(control::CR4_READ_SHADOW, 0).expect("vmwrite CR4 shadow");

    // ── VAPIC page ────────────────────────────────────────────────────── //
    vmx::vmwrite(control::VIRT_APIC_ADDR_FULL as u32, vapic_phys).expect("vmwrite VAPIC addr");

    // ── APIC access page (child VPs only) ─────────────────────────────── //
    // When VIRTUALIZE_APIC_ACCESSES (bit 0) is set in secondary controls,
    // xAPIC MMIO accesses by the guest to this physical page cause
    // EXIT_REASON_APIC_ACCESS (44) instead of an EPT violation.
    // dom0 uses EPT passthrough of 0xFEE00000 and has apic_access_phys=0.
    if apic_access_phys != 0 {
        vmx::vmwrite(control::APIC_ACCESS_ADDR_FULL as u32, apic_access_phys)
            .expect("vmwrite APIC access addr");
    }

    // ── TPR threshold ─────────────────────────────────────────────────── //
    // Required when USE_TPR_SHADOW=1.  0 = no TPR-threshold VM exits.
    vmx::vmwrite(control::TPR_THRESHOLD, 0).expect("vmwrite TPR threshold");

    // ── EOI-exit bitmap (256 bits = four 64-bit VMCS fields) ─────────── //
    // All 0: no EOI exits for any vector.  Report-domain notification uses
    // the SWITCH return mechanism, not EOI exits (see interrupt-virtualization.md).
    vmx::vmwrite(control::EOI_EXIT0_FULL, 0).expect("vmwrite EOI-exit bitmap 0");
    vmx::vmwrite(control::EOI_EXIT1_FULL, 0).expect("vmwrite EOI-exit bitmap 1");
    vmx::vmwrite(control::EOI_EXIT2_FULL, 0).expect("vmwrite EOI-exit bitmap 2");
    vmx::vmwrite(control::EOI_EXIT3_FULL, 0).expect("vmwrite EOI-exit bitmap 3");

    // ── MSR / I/O bitmap addresses ────────────────────────────────────── //
    // Explicitly write address 0 (physical page 0, 4KB-aligned, within
    // physical address space → valid per Intel SDM 26.2.1.1).
    // A zeroed page at phys 0 means no I/O intercepts and no MSR intercepts,
    // which is correct for a pass-through hypervisor at bootstrap time.
    // ── I/O / MSR bitmap addresses ──────────────────────────────────── //
    // When USE_IO_BITMAPS is set (child VMs), write the IO bitmap physical
    // addresses.  Each bitmap is 4KB: A covers ports 0x0000-0x7FFF, B covers
    // 0x8000-0xFFFF.  A set bit causes a VM exit on that port's IN/OUT.
    if child && io_bitmap_a_phys != 0 {
        vmx::vmwrite(control::IO_BITMAP_A_ADDR_FULL as u32, io_bitmap_a_phys)
            .expect("vmwrite IO bitmap A");
        vmx::vmwrite(control::IO_BITMAP_B_ADDR_FULL as u32, io_bitmap_b_phys)
            .expect("vmwrite IO bitmap B");
    } else {
        vmx::vmwrite(control::IO_BITMAP_A_ADDR_FULL as u32, 0).expect("vmwrite IO bitmap A");
        vmx::vmwrite(control::IO_BITMAP_B_ADDR_FULL as u32, 0).expect("vmwrite IO bitmap B");
    }
    // MSR bitmap: allocated from META pool, initialized to trap perf MSRs.
    vmx::vmwrite(control::MSR_BITMAPS_ADDR_FULL as u32, msr_bitmap_phys)
        .expect("vmwrite MSR bitmap");
    vmx::vmwrite(control::VMENTRY_MSR_LOAD_COUNT as u32, 0)
        .expect("vmwrite vmentry msr load count");
    vmx::vmwrite(control::VMEXIT_MSR_STORE_COUNT as u32, 0)
        .expect("vmwrite vmexit msr store count");
    vmx::vmwrite(control::VMEXIT_MSR_LOAD_COUNT as u32, 0).expect("vmwrite vmexit msr load count");

    // ── VMX preemption timer ──────────────────────────────────────────── //
    // Diagnostic heartbeat: fires every ~2s to sample guest RIP/RSP.
    vmx::vmwrite(
        guest::VMX_PREEMPTION_TIMER_VALUE,
        crate::arch::vmexit::PREEMPTION_TIMER_TICKS,
    )
    .expect("vmwrite preemption timer");

    // ── Debug: print MSR raw values and adjusted controls ─────────────── //
    serial_println!("  VMCS controls (VPID={}):", vpid);
    serial_println!("    pin_msr={:#018x}  pin={:#010x}", pin_msr, pin_val);
    serial_println!(
        "    primary_msr={:#018x}  primary={:#010x}",
        primary_msr,
        primary_val
    );
    serial_println!(
        "    secondary_msr={:#018x}  secondary={:#010x}",
        secondary_msr,
        secondary_val
    );
    serial_println!("    exit_msr={:#018x}  exit={:#010x}", exit_msr, exit_val);
    serial_println!(
        "    entry_msr={:#018x}  entry={:#010x}",
        entry_msr,
        entry_val
    );
    serial_println!("    EPTP={:#018x}  VPID={}", eptp, vpid);

    // ── Posted Interrupt fields (child VPs only) ─────────────────────── //
    // Only write these fields if PROCESS_POSTED_INTERRUPTS was actually set
    // after the hardware capability mask was applied (bit 7 of pin_val).
    // On hardware that doesn't support posted interrupts, these VMCS fields
    // are unsupported and vmwrite would return VM_FAIL_INVALID.
    if child && (pin_val & (1 << 7)) != 0 {
        // Notification vector: sent as IPI to the VP's core for cross-core injection.
        vmx::vmwrite(
            control::POSTED_INTERRUPT_NOTIFICATION_VECTOR,
            POSTED_INTR_NOTIFY_VEC as u64,
        )
        .expect("vmwrite posted-intr notification vector");
        // Physical address of the 64-byte aligned Posted-Interrupt Descriptor.
        vmx::vmwrite(control::POSTED_INTERRUPT_DESC_ADDR_FULL, pid_phys)
            .expect("vmwrite posted-intr descriptor addr");
    } else if child {
        serial_println!("  [INFO] Posted interrupts disabled — using software PIR drain fallback");
    }
}
