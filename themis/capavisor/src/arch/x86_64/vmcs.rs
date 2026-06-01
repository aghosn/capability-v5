//! VMCS allocation and setup — Phase P2d.
//!
//! One VMCS page is set up per VP (one per physical core for dom0).
//! After `setup_vmcs_for_vp` returns, the VMCS is loaded (VMPTRLD) and
//! all fields are written.  The caller can then execute VMLAUNCH.
//!
//! # Layout
//!
//! - Host state  : captured from the current CPU (CR0/CR3/CR4, segments, EFER,
//!                 GDTR/IDTR base, TR base).  Host RSP → per-VP stack top.
//!                 Host RIP → `host_rip_stub` (overwritten by `ActiveVcpu::run()`).
//! - Guest state : protected mode stub (UNRESTRICTED_GUEST, no paging, PE only).
//!                 RIP/RSP/CR3 left at 0; will be overwritten at P7f with Linux
//!                 boot parameters.
//! - Controls    : EPT + VPID + UNRESTRICTED_GUEST; intercept VMCALL (always),
//!                 CPUID (always), NMI, external interrupts, CR0/CR4 changes.

use x86::bits64::vmx;
use x86::msr;
use x86::vmx::vmcs::{control, guest, host};

// ── VMCS constraint helpers (public — used by hypercall.rs apply_vmcs_reg) ── //

/// Return the CR0 bits that must always be 1 in the guest VMCS field.
///
/// IA32_VMX_CR0_FIXED0 lists bits that VMX non-root operation requires.
/// UNRESTRICTED_GUEST exempts PE (bit 0) and PG (bit 31), so we exclude them.
/// The remaining mandatory bits (typically ET=4, NE=5) must be set in
/// guest::CR0 before VMLAUNCH or the VMCS consistency check fails (exit 33).
pub unsafe fn cr0_required_bits() -> u64 {
    let fixed0 = msr::rdmsr(msr::IA32_VMX_CR0_FIXED0);
    fixed0 & !((1u64 << 0) | (1u64 << 31)) // exclude PE and PG
}

/// Adjust a guest CR0 value so it satisfies IA32_VMX_CR0_FIXED0.
///
/// OR in the required bits (typically ET=bit4, NE=bit5); other bits are
/// left as requested.  PE/PG are exempted and not forced.
pub unsafe fn vmcs_adjust_cr0(val: u64) -> u64 {
    val | cr0_required_bits()
}

/// Adjust a guest CR4 value so it satisfies IA32_VMX_CR4_FIXED0.
///
/// CR4.VMXE (bit 13) is required on all Intel VMX-capable CPUs.
/// The CR4 guest/host mask owns this bit, so the guest never clears it,
/// but the VMCS field must have it set for the consistency check.
pub fn vmcs_adjust_cr4(val: u64) -> u64 {
    val | (1u64 << 13) // VMXE
}

use crate::arch::vmexit::host_rip_stub;
use crate::serial_println;

// ── Posted Interrupt constants ───────────────────────────────────────────── //

/// Notification vector used for Posted Interrupt IPIs.
///
/// When a VP running on another core has a posted interrupt delivered, the
/// capavisor sends an IPI with this vector. Hardware then moves PIR → vIRR on
/// the receiving core without a VM exit.
///
/// 0xF2 is chosen to avoid conflicts with Linux's per-CPU IPI vectors
/// (0xF0=RESCHEDULE, 0xF1=CALL_FUNCTION_SINGLE, 0xFF=LOCAL_TIMER in common
/// kernels). Validated at capavisor init against the running kernel's IDT.
pub const POSTED_INTR_NOTIFY_VEC: u8 = 0xF2;

// VMCS encodings for the Posted-Interrupt notification vector (16-bit) and
// descriptor address (64-bit full) come from `x86::vmx::vmcs::control`.

// ── MSR-capability–adjusted control helper ───────────────────────────────── //

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

// ── VMCS setup ────────────────────────────────────────────────────────────── //

/// Set up the VMCS for VP `vp_index` of dom0.
///
/// # Arguments
/// * `vmcs_phys`  — physical address of the (already-initialised) VMCS page
/// * `vapic_phys` — physical address of the VAPIC page for this VP
/// * `eptp`       — EPT pointer value from `EptMapper::eptp()`
/// * `vp_index`   — VP index (0-based; VPID written as vp_index + 1)
///
/// HOST_RSP is set to 0 here (placeholder).  `ActiveVcpu::run()` overwrites it
/// with the caller's RSP before every VMLAUNCH/VMRESUME.
///
/// # Safety
/// VMXON must already be active on this core.
pub unsafe fn setup_vmcs_for_vp(
    vmcs_phys: u64,
    vapic_phys: u64,
    msr_bitmap_phys: u64,
    eptp: u64,
    vp_index: usize,
) {
    vmx::vmclear(vmcs_phys).expect("vmclear failed");
    vmx::vmptrld(vmcs_phys).expect("vmptrld failed");

    // dom0 keeps its xAPIC MMIO EPT passthrough — no APIC access page.
    write_control_fields(
        eptp,
        vapic_phys,
        msr_bitmap_phys,
        0,
        0,
        0,
        0,
        (vp_index + 1) as u16,
        false,
    );
    write_host_state();
    write_guest_state();

    serial_println!(
        "  VMCS VP{}: phys={:#x} VAPIC={:#x} EPTP={:#x} VPID={}",
        vp_index,
        vmcs_phys,
        vapic_phys,
        eptp,
        vp_index + 1,
    );
}

/// Set up a child domain's VMCS with intercept-heavy controls.
///
/// Differs from dom0 VMCS setup:
/// - EXTERNAL_INTERRUPT_EXITING: external interrupts cause VMEXIT to parent
/// - HLT_EXITING: HLT causes VMEXIT to parent
/// - Guest state is left at zeroes (parent populates via COMM page)
///
/// # Safety
/// VMXON must already be active on this core. Clobbers current VMPTRLD.
pub unsafe fn setup_child_vmcs(
    vmcs_phys: u64,
    vapic_phys: u64,
    msr_bitmap_phys: u64,
    pid_phys: u64,
    apic_access_phys: u64,
    io_bitmap_a_phys: u64,
    io_bitmap_b_phys: u64,
    eptp: u64,
    vpid: u16,
) {
    vmx::vmclear(vmcs_phys).expect("child vmclear failed");
    vmx::vmptrld(vmcs_phys).expect("child vmptrld failed");

    write_control_fields(
        eptp,
        vapic_phys,
        msr_bitmap_phys,
        pid_phys,
        apic_access_phys,
        io_bitmap_a_phys,
        io_bitmap_b_phys,
        vpid,
        true,
    );
    write_host_state();
    write_guest_state();

    serial_println!(
        "  child VMCS: phys={:#x} VAPIC={:#x} PID={:#x} APIC_ACC={:#x} EPTP={:#x} VPID={}",
        vmcs_phys,
        vapic_phys,
        pid_phys,
        apic_access_phys,
        eptp,
        vpid,
    );
}

// ── Control fields ────────────────────────────────────────────────────────── //

unsafe fn write_control_fields(
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
    // APIC_REGISTER_VIRT (bit 8): virtualises APIC register reads to VAPIC page.
    //   Requires USE_TPR_SHADOW=1.  Harmless without "Virtualize APIC accesses"
    //   for xAPIC MMIO — it only affects x2APIC MSR reads.
    // VID (bit 9): Virtual Interrupt Delivery.  On VM entry with VID=1, the
    //   processor evaluates vIRR and delivers pending virtual interrupts without
    //   a VM exit.  Requires USE_TPR_SHADOW=1 AND EXTERNAL_INTERRUPT_EXITING=1
    //   (Intel SDM Vol 3C §26.2.1.1).  Only set for child VMs, which already
    //   have EXTERNAL_INTERRUPT_EXITING enabled.  For dom0, VID is omitted:
    //   dom0 handles interrupts natively and vIRR is always 0.
    let secondary_desired: u64 = (1 << 1)   // ENABLE_EPT
        | (1 << 3) // ENABLE_RDTSCP
        | (1 << 5) // ENABLE_VPID
        | (1 << 7) // UNRESTRICTED_GUEST
        | (if !child { 1 << 8 } else { 0 }) // APIC_REGISTER_VIRT — dom0 only
        // Child: bit 8 off because APIC_REGISTER_VIRT causes the processor to
        // execute the guest's LAPIC write instruction, hitting INT3 text_poke
        // sites in native_apic_mem_write.  Without bit 8, the exit happens
        // BEFORE instruction execution, avoiding the INT3.
        // VID (bit 9): dom0 doesn't have EXTERNAL_INTERRUPT_EXITING.
        // Child: off (requires bit 8 for EOI→ISR clearing).
        // EOI is emulated in software by handle_apic_access_exit.
        | (if apic_access_phys != 0 { 1 << 0 } else { 0 }) // VIRTUALIZE_APIC_ACCESSES
        | (1 << 12) // ENABLE_INVPCID
        | (1 << 20); // ENABLE_XSAVES_XRSTORS
    let secondary_msr = unsafe { msr::rdmsr(msr::IA32_VMX_PROCBASED_CTLS2) };
    let secondary_val = adjust(secondary_desired, secondary_msr);
    vmx::vmwrite(control::SECONDARY_PROCBASED_EXEC_CONTROLS, secondary_val)
        .expect("vmwrite secondary proc-based");

    if apic_access_phys != 0 && (secondary_val & 1) == 0 {
        serial_println!(
            "  [WARN] VIRTUALIZE_APIC_ACCESSES not supported by hardware — \
             LAPIC MMIO will use EPT violation fallback"
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

// ── Host state ────────────────────────────────────────────────────────────── //

unsafe fn write_host_state() {
    // Read current segment selectors (TI and RPL bits must be 0 in VMCS).
    let cs: u16;
    let ss: u16;
    let ds: u16;
    let es: u16;
    let fs: u16;
    let gs: u16;
    core::arch::asm!(
        "mov {:x}, cs", out(reg) cs,
        options(nomem, nostack, preserves_flags),
    );
    core::arch::asm!(
        "mov {:x}, ss", out(reg) ss,
        options(nomem, nostack, preserves_flags),
    );
    core::arch::asm!(
        "mov {:x}, ds", out(reg) ds,
        options(nomem, nostack, preserves_flags),
    );
    core::arch::asm!(
        "mov {:x}, es", out(reg) es,
        options(nomem, nostack, preserves_flags),
    );
    core::arch::asm!(
        "mov {:x}, fs", out(reg) fs,
        options(nomem, nostack, preserves_flags),
    );
    core::arch::asm!(
        "mov {:x}, gs", out(reg) gs,
        options(nomem, nostack, preserves_flags),
    );

    // Segment selectors (TI and RPL bits cleared — VMX requirement).
    // CS/SS/DS/ES/FS/GS come from the actual registers; TR uses the known
    // selector from the GDT we loaded with gdt::load_for_core() — never 0.
    let tr_sel = crate::arch::gdt::tss_selector(0); // BSP is always core 0
    vmx::vmwrite(host::CS_SELECTOR as u32, (cs & !7) as u64).expect("vmwrite host CS");
    vmx::vmwrite(host::SS_SELECTOR as u32, (ss & !7) as u64).expect("vmwrite host SS");
    vmx::vmwrite(host::DS_SELECTOR as u32, (ds & !7) as u64).expect("vmwrite host DS");
    vmx::vmwrite(host::ES_SELECTOR as u32, (es & !7) as u64).expect("vmwrite host ES");
    vmx::vmwrite(host::FS_SELECTOR as u32, (fs & !7) as u64).expect("vmwrite host FS");
    vmx::vmwrite(host::GS_SELECTOR as u32, (gs & !7) as u64).expect("vmwrite host GS");
    vmx::vmwrite(host::TR_SELECTOR as u32, tr_sel as u64).expect("vmwrite host TR");

    // Control registers.
    let cr0: u64;
    let cr3: u64;
    let mut cr4: u64;
    core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
    core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));

    // Enable OSXSAVE (bit 18) so the XSETBV/XGETBV handler can execute
    // in the host context after VM exit.  Without this, those instructions
    // #UD and crash Themis (no IDT handler → triple fault → KVM kills VM).
    let osxsave = 1u64 << 18;
    if cr4 & osxsave == 0 {
        cr4 |= osxsave;
        core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack, preserves_flags));
    }

    vmx::vmwrite(host::CR0, cr0).expect("vmwrite host CR0");
    vmx::vmwrite(host::CR3, cr3).expect("vmwrite host CR3");
    vmx::vmwrite(host::CR4, cr4).expect("vmwrite host CR4");

    // EFER.
    let efer = msr::rdmsr(msr::IA32_EFER);
    vmx::vmwrite(host::IA32_EFER_FULL as u32, efer).expect("vmwrite host EFER");
    // PAT.
    let pat = msr::rdmsr(0x277); // IA32_PAT
    vmx::vmwrite(host::IA32_PAT_FULL as u32, pat).expect("vmwrite host PAT");

    // GDTR base: use the GDT we loaded (authoritative, no sgdt ambiguity).
    // IDTR base: read from the processor (Limine set this up).
    let gdtr = crate::arch::gdt::gdtr_base();
    let idtr = read_descriptor_table_base("sidt");
    vmx::vmwrite(host::GDTR_BASE, gdtr).expect("vmwrite host GDTR base");
    vmx::vmwrite(host::IDTR_BASE, idtr).expect("vmwrite host IDTR base");

    // FS / GS base (MSR-based on x86_64).
    let fs_base = msr::rdmsr(0xC000_0100); // IA32_FS_BASE
    let gs_base = msr::rdmsr(0xC000_0101); // IA32_GS_BASE
    vmx::vmwrite(host::FS_BASE, fs_base).expect("vmwrite host FS base");
    vmx::vmwrite(host::GS_BASE, gs_base).expect("vmwrite host GS base");

    // TR base: taken directly from our known TSS for core 0 (BSP).
    // gdt_system_segment_base is kept as a fallback but we use the direct
    // address to avoid any GDT parse ambiguity.
    let tr_base = crate::arch::gdt::tss_base(0);
    vmx::vmwrite(host::TR_BASE, tr_base).expect("vmwrite host TR base");

    // SYSENTER CS/ESP/EIP (set to zero — Limine / our monitor does not use SYSENTER).
    vmx::vmwrite(host::IA32_SYSENTER_CS as u32, 0).expect("vmwrite host SYSENTER_CS");
    vmx::vmwrite(host::IA32_SYSENTER_ESP, 0).expect("vmwrite host SYSENTER_ESP");
    vmx::vmwrite(host::IA32_SYSENTER_EIP, 0).expect("vmwrite host SYSENTER_EIP");

    // Host RSP and RIP.
    // RSP is set to 0 here — ActiveVcpu::run() overwrites it with the caller's
    // RSP before every VMLAUNCH/VMRESUME via `vmwrite rsi, rsp`.
    vmx::vmwrite(host::RSP, 0).expect("vmwrite host RSP");
    vmx::vmwrite(host::RIP, host_rip_stub as *const () as u64).expect("vmwrite host RIP");
}

// ── Guest state ───────────────────────────────────────────────────────────── //

unsafe fn write_guest_state() {
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

// ── Descriptor-table helpers ──────────────────────────────────────────────── //

/// Read the base address of IDTR via `sidt`.
unsafe fn read_descriptor_table_base(insn: &str) -> u64 {
    // The pseudo-descriptor is 10 bytes: 2-byte limit + 8-byte base.
    let mut desc = [0u8; 10];
    match insn {
        "sidt" => core::arch::asm!("sidt [{0}]", in(reg) desc.as_mut_ptr(), options(nostack)),
        _ => unreachable!(),
    }
    // Base is at bytes [2..10], little-endian.
    u64::from_le_bytes(desc[2..10].try_into().unwrap())
}
