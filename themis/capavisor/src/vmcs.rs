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
//!                 Host RIP → `vmexit_trampoline`.
//! - Guest state : protected mode stub (UNRESTRICTED_GUEST, no paging, PE only).
//!                 RIP/RSP/CR3 left at 0; will be overwritten at P7f with Linux
//!                 boot parameters.
//! - Controls    : EPT + VPID + UNRESTRICTED_GUEST; intercept VMCALL (always),
//!                 CPUID (always), NMI, external interrupts, CR0/CR4 changes.

use x86::bits64::vmx;
use x86::msr;
use x86::vmx::vmcs::{control, guest, host, ro};

use crate::serial_println;
use crate::vmexit::vmexit_trampoline;

// ── MSR-capability–adjusted control helper ───────────────────────────────── //

/// Apply allowed-0 / allowed-1 mask from a VMX capability MSR to `desired`.
///
/// `low32` = bits that MUST be 1 (OR'd in).
/// `high32` = bits that MAY be 1 (AND'd in).
fn adjust(desired: u64, msr_value: u64) -> u64 {
    let must_be_1 = msr_value & 0xFFFF_FFFF;         // allowed-0 → must be 1
    let may_be_1  = (msr_value >> 32) & 0xFFFF_FFFF; // allowed-1 → may be 1
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
/// * `host_stack_top` — top of the per-VP host stack (highest address, stack
///   grows downward; must be 16-byte aligned)
/// * `eptp`       — EPT pointer value from `EptMapper::eptp()`
/// * `vp_index`   — VP index (used as VPID; 0 is reserved, so VPID = vp_index + 1)
///
/// # Safety
/// VMXON must already be active on this core.
pub unsafe fn setup_vmcs_for_vp(
    vmcs_phys: u64,
    vapic_phys: u64,
    host_stack_top: u64,
    eptp: u64,
    vp_index: usize,
) {
    // VMCLEAR initialises the VMCS region and clears any previous launch state.
    vmx::vmclear(vmcs_phys).expect("vmclear failed");
    // VMPTRLD makes this VMCS the current one for all subsequent vmread/vmwrite.
    vmx::vmptrld(vmcs_phys).expect("vmptrld failed");

    write_control_fields(eptp, vapic_phys, vp_index);
    write_host_state(host_stack_top);
    write_guest_state();

    serial_println!(
        "  VMCS VP{}: phys={:#x} VAPIC={:#x} EPTP={:#x} VPID={}",
        vp_index, vmcs_phys, vapic_phys, eptp, vp_index + 1,
    );
}

// ── Control fields ────────────────────────────────────────────────────────── //

unsafe fn write_control_fields(eptp: u64, vapic_phys: u64, vp_index: usize) {
    // ── Pin-based: external-interrupt exiting + NMI exiting ──────────── //
    let pin_desired: u64 =
        (1 << 0)  // EXTERNAL_INTERRUPT_EXITING
        | (1 << 3);  // NMI_EXITING
    let pin_msr = vmx_ctrl_msr(msr::IA32_VMX_PINBASED_CTLS, msr::IA32_VMX_TRUE_PINBASED_CTLS);
    vmx::vmwrite(control::PINBASED_EXEC_CONTROLS, adjust(pin_desired, pin_msr))
        .expect("vmwrite pin-based");

    // ── Primary proc-based ────────────────────────────────────────────── //
    // HLT_EXITING (bit 7), USE_IO_BITMAPS (bit 25), USE_MSR_BITMAPS (bit 28),
    // SECONDARY_CONTROLS (bit 31).
    let primary_desired: u64 =
        (1 << 7)   // HLT_EXITING
        | (1 << 25) // USE_IO_BITMAPS
        | (1 << 28) // USE_MSR_BITMAPS
        | (1 << 31); // ACTIVATE_SECONDARY_CONTROLS
    let primary_msr = vmx_ctrl_msr(msr::IA32_VMX_PROCBASED_CTLS, msr::IA32_VMX_TRUE_PROCBASED_CTLS);
    vmx::vmwrite(control::PRIMARY_PROCBASED_EXEC_CONTROLS, adjust(primary_desired, primary_msr))
        .expect("vmwrite primary proc-based");

    // ── Secondary proc-based ──────────────────────────────────────────── //
    // ENABLE_RDTSCP (bit 3), ENABLE_EPT (bit 1), ENABLE_VPID (bit 5),
    // UNRESTRICTED_GUEST (bit 7).
    let secondary_desired: u64 =
        (1 << 1)  // ENABLE_EPT
        | (1 << 3) // ENABLE_RDTSCP
        | (1 << 5) // ENABLE_VPID
        | (1 << 7); // UNRESTRICTED_GUEST
    let secondary_msr = unsafe { msr::rdmsr(msr::IA32_VMX_PROCBASED_CTLS2) };
    vmx::vmwrite(
        control::SECONDARY_PROCBASED_EXEC_CONTROLS,
        adjust(secondary_desired, secondary_msr),
    )
    .expect("vmwrite secondary proc-based");

    // ── VM-exit controls ──────────────────────────────────────────────── //
    // HOST_ADDRESS_SPACE_SIZE (bit 9), SAVE_IA32_EFER (bit 20),
    // LOAD_IA32_EFER (bit 21).
    let exit_desired: u64 =
        (1 << 9)   // HOST_ADDRESS_SPACE_SIZE
        | (1 << 20) // SAVE_IA32_EFER
        | (1 << 21); // LOAD_IA32_EFER
    let exit_msr = vmx_ctrl_msr(msr::IA32_VMX_EXIT_CTLS, msr::IA32_VMX_TRUE_EXIT_CTLS);
    vmx::vmwrite(control::VMEXIT_CONTROLS, adjust(exit_desired, exit_msr))
        .expect("vmwrite vm-exit controls");

    // ── VM-entry controls ─────────────────────────────────────────────── //
    // No IA32E_MODE_GUEST: guest starts in protected mode (no paging); P7f
    // will switch to long mode before VMLAUNCH.
    let entry_desired: u64 = 0;
    let entry_msr = vmx_ctrl_msr(msr::IA32_VMX_ENTRY_CTLS, msr::IA32_VMX_TRUE_ENTRY_CTLS);
    vmx::vmwrite(control::VMENTRY_CONTROLS, adjust(entry_desired, entry_msr))
        .expect("vmwrite vm-entry controls");

    // ── EPT pointer ───────────────────────────────────────────────────── //
    vmx::vmwrite(control::EPTP_FULL, eptp).expect("vmwrite EPTP");

    // ── VPID ──────────────────────────────────────────────────────────── //
    // VPID 0 is reserved for the VMX-root context; dom0 VPs get 1..=N.
    vmx::vmwrite(control::VPID as u32, (vp_index + 1) as u64).expect("vmwrite VPID");

    // ── Exception bitmap: intercept nothing (pass all exceptions to guest) //
    vmx::vmwrite(control::EXCEPTION_BITMAP, 0).expect("vmwrite exception bitmap");

    // ── CR0/CR4 guest-host masks: intercept VMXE (CR4[13]) ───────────── //
    // The guest sees VMXE = 1 in CR4 via the read shadow, but cannot clear it.
    vmx::vmwrite(control::CR0_GUEST_HOST_MASK, 0).expect("vmwrite CR0 mask");
    vmx::vmwrite(control::CR0_READ_SHADOW, 0x31).expect("vmwrite CR0 shadow");
    vmx::vmwrite(control::CR4_GUEST_HOST_MASK, 1u64 << 13).expect("vmwrite CR4 mask");
    vmx::vmwrite(control::CR4_READ_SHADOW, 1u64 << 13).expect("vmwrite CR4 shadow");

    // ── VAPIC page ────────────────────────────────────────────────────── //
    vmx::vmwrite(control::VIRT_APIC_ADDR_FULL as u32, vapic_phys)
        .expect("vmwrite VAPIC addr");

    // ── MSR / I/O bitmap addresses: all-zero = no interception ───────── //
    // We write 0 for counts; USE_MSR_BITMAPS and USE_IO_BITMAPS require valid
    // addresses — we disable them for the bootstrap stage if MSR/IO bitmaps are
    // not yet allocated.  (The adjust() call will keep USE_IO_BITMAPS only if
    // the CPU allows it; if not, the bit is stripped.)
    vmx::vmwrite(control::VMENTRY_MSR_LOAD_COUNT as u32, 0)
        .expect("vmwrite vmentry msr load count");
    vmx::vmwrite(control::VMEXIT_MSR_STORE_COUNT as u32, 0)
        .expect("vmwrite vmexit msr store count");
    vmx::vmwrite(control::VMEXIT_MSR_LOAD_COUNT as u32, 0)
        .expect("vmwrite vmexit msr load count");
}

// ── Host state ────────────────────────────────────────────────────────────── //

unsafe fn write_host_state(host_stack_top: u64) {
    // Read current segment selectors (TI and RPL bits must be 0 in VMCS).
    let cs: u16;
    let ss: u16;
    let ds: u16;
    let es: u16;
    let fs: u16;
    let gs: u16;
    let tr: u16;
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
    core::arch::asm!(
        "str {:x}", out(reg) tr,
        options(nomem, nostack, preserves_flags),
    );

    // Segment selectors (TI and RPL bits cleared — VMX requirement).
    vmx::vmwrite(host::CS_SELECTOR as u32, (cs & !7) as u64).expect("vmwrite host CS");
    vmx::vmwrite(host::SS_SELECTOR as u32, (ss & !7) as u64).expect("vmwrite host SS");
    vmx::vmwrite(host::DS_SELECTOR as u32, (ds & !7) as u64).expect("vmwrite host DS");
    vmx::vmwrite(host::ES_SELECTOR as u32, (es & !7) as u64).expect("vmwrite host ES");
    vmx::vmwrite(host::FS_SELECTOR as u32, (fs & !7) as u64).expect("vmwrite host FS");
    vmx::vmwrite(host::GS_SELECTOR as u32, (gs & !7) as u64).expect("vmwrite host GS");
    vmx::vmwrite(host::TR_SELECTOR as u32, (tr & !7) as u64).expect("vmwrite host TR");

    // Control registers.
    let cr0: u64;
    let cr3: u64;
    let cr4: u64;
    core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
    core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
    vmx::vmwrite(host::CR0, cr0).expect("vmwrite host CR0");
    vmx::vmwrite(host::CR3, cr3).expect("vmwrite host CR3");
    vmx::vmwrite(host::CR4, cr4).expect("vmwrite host CR4");

    // EFER.
    let efer = msr::rdmsr(msr::IA32_EFER);
    vmx::vmwrite(host::IA32_EFER_FULL as u32, efer).expect("vmwrite host EFER");

    // GDTR and IDTR base.
    let gdtr = read_descriptor_table_base("sgdt");
    let idtr = read_descriptor_table_base("sidt");
    vmx::vmwrite(host::GDTR_BASE, gdtr).expect("vmwrite host GDTR base");
    vmx::vmwrite(host::IDTR_BASE, idtr).expect("vmwrite host IDTR base");

    // FS / GS base (MSR-based on x86_64).
    let fs_base = msr::rdmsr(0xC000_0100); // IA32_FS_BASE
    let gs_base = msr::rdmsr(0xC000_0101); // IA32_GS_BASE
    vmx::vmwrite(host::FS_BASE, fs_base).expect("vmwrite host FS base");
    vmx::vmwrite(host::GS_BASE, gs_base).expect("vmwrite host GS base");

    // TR base: look up in the GDT.
    // The TR selector (bits[15:3]) gives the GDT index.  Each GDT entry is 8
    // bytes; a system segment (TSS) uses two consecutive 8-byte slots (16 bytes).
    let tr_base = gdt_system_segment_base(gdtr, tr);
    vmx::vmwrite(host::TR_BASE, tr_base).expect("vmwrite host TR base");

    // SYSENTER CS/ESP/EIP (set to zero — Limine / our monitor does not use SYSENTER).
    vmx::vmwrite(host::IA32_SYSENTER_CS as u32, 0).expect("vmwrite host SYSENTER_CS");
    vmx::vmwrite(host::IA32_SYSENTER_ESP, 0).expect("vmwrite host SYSENTER_ESP");
    vmx::vmwrite(host::IA32_SYSENTER_EIP, 0).expect("vmwrite host SYSENTER_EIP");

    // Host RSP and RIP.
    vmx::vmwrite(host::RSP, host_stack_top).expect("vmwrite host RSP");
    vmx::vmwrite(host::RIP, vmexit_trampoline as *const () as u64).expect("vmwrite host RIP");
}

// ── Guest state ───────────────────────────────────────────────────────────── //

unsafe fn write_guest_state() {
    // ── Segment selectors (all 0 — real or flat protected mode) ─────── //
    for sel_field in [
        guest::ES_SELECTOR, guest::CS_SELECTOR, guest::SS_SELECTOR,
        guest::DS_SELECTOR, guest::FS_SELECTOR, guest::GS_SELECTOR,
        guest::TR_SELECTOR, guest::LDTR_SELECTOR,
    ] {
        vmx::vmwrite(sel_field, 0).expect("vmwrite guest selector");
    }

    // ── Segment access rights (UNRESTRICTED_GUEST — protected mode) ─── //
    // CS: code, 32-bit, present, DPL=0 (type 0x1B = execute/read/accessed)
    vmx::vmwrite(guest::CS_ACCESS_RIGHTS,  0xC09B).expect("vmwrite guest CS AR");
    // DS/ES: data, 32-bit, present, DPL=0
    vmx::vmwrite(guest::DS_ACCESS_RIGHTS,  0xC093).expect("vmwrite guest DS AR");
    vmx::vmwrite(guest::ES_ACCESS_RIGHTS,  0xC093).expect("vmwrite guest ES AR");
    vmx::vmwrite(guest::SS_ACCESS_RIGHTS,  0xC093).expect("vmwrite guest SS AR");
    // FS/GS/LDTR: unusable
    vmx::vmwrite(guest::FS_ACCESS_RIGHTS,  0x10000).expect("vmwrite guest FS AR");
    vmx::vmwrite(guest::GS_ACCESS_RIGHTS,  0x10000).expect("vmwrite guest GS AR");
    vmx::vmwrite(guest::LDTR_ACCESS_RIGHTS,0x10000).expect("vmwrite guest LDTR AR");
    // TR: busy TSS, present (type 0x8B = TSS32 busy)
    vmx::vmwrite(guest::TR_ACCESS_RIGHTS,  0x8B).expect("vmwrite guest TR AR");

    // ── Segment limits ────────────────────────────────────────────────── //
    for lim_field in [
        guest::ES_LIMIT, guest::CS_LIMIT, guest::SS_LIMIT,
        guest::DS_LIMIT, guest::FS_LIMIT, guest::GS_LIMIT,
        guest::LDTR_LIMIT,
    ] {
        vmx::vmwrite(lim_field, 0xFFFF_FFFF).expect("vmwrite guest seg limit");
    }
    vmx::vmwrite(guest::TR_LIMIT, 0xFF).expect("vmwrite guest TR limit");
    vmx::vmwrite(guest::GDTR_LIMIT, 0xFFFF).expect("vmwrite guest GDTR limit");
    vmx::vmwrite(guest::IDTR_LIMIT, 0xFFFF).expect("vmwrite guest IDTR limit");

    // ── Segment bases (all 0) ─────────────────────────────────────────── //
    for base_field in [
        guest::ES_BASE,    guest::CS_BASE,    guest::SS_BASE,
        guest::DS_BASE,    guest::FS_BASE,    guest::GS_BASE,
        guest::TR_BASE,    guest::LDTR_BASE,
        guest::GDTR_BASE,  guest::IDTR_BASE,
    ] {
        vmx::vmwrite(base_field, 0).expect("vmwrite guest seg base");
    }

    // ── Control registers ─────────────────────────────────────────────── //
    // CR0: PE (bit 0) + ET (bit 4) + NE (bit 5) = 0x31
    // PG is NOT set — UNRESTRICTED_GUEST allows no-paging protected mode.
    // P7f will set PG + load CR3 before VMLAUNCH.
    vmx::vmwrite(guest::CR0, 0x31).expect("vmwrite guest CR0");
    vmx::vmwrite(guest::CR3, 0).expect("vmwrite guest CR3");
    // CR4: VMXE (bit 13) required in VMX non-root; PAE (bit 5) for future 64-bit.
    vmx::vmwrite(guest::CR4, 1u64 << 13).expect("vmwrite guest CR4");

    // ── EFER: 0 (no long mode in the stub; P7f sets LME+LMA for Linux) ── //
    vmx::vmwrite(guest::IA32_EFER_FULL, 0).expect("vmwrite guest EFER");

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

    // ── SYSENTER MSRs ─────────────────────────────────────────────────── //
    vmx::vmwrite(guest::IA32_SYSENTER_CS, 0).expect("vmwrite guest SYSENTER_CS");
    vmx::vmwrite(guest::IA32_SYSENTER_ESP, 0).expect("vmwrite guest SYSENTER_ESP");
    vmx::vmwrite(guest::IA32_SYSENTER_EIP, 0).expect("vmwrite guest SYSENTER_EIP");
}

// ── Descriptor-table helpers ──────────────────────────────────────────────── //

/// Read the base address of GDTR or IDTR via `sgdt` / `sidt`.
unsafe fn read_descriptor_table_base(insn: &str) -> u64 {
    // The pseudo-descriptor is 10 bytes: 2-byte limit + 8-byte base.
    let mut desc = [0u8; 10];
    match insn {
        "sgdt" => core::arch::asm!("sgdt [{0}]", in(reg) desc.as_mut_ptr(), options(nostack)),
        "sidt" => core::arch::asm!("sidt [{0}]", in(reg) desc.as_mut_ptr(), options(nostack)),
        _ => unreachable!(),
    }
    // Base is at bytes [2..10], little-endian.
    u64::from_le_bytes(desc[2..10].try_into().unwrap())
}

/// Extract the 64-bit base of a system segment (TSS/LDT) from the GDT.
///
/// A system segment occupies two consecutive 8-byte GDT slots (16 bytes total).
/// Bits encoding the base: [39:16] in qword 0, [63:32] in qword 1.
unsafe fn gdt_system_segment_base(gdtr_base: u64, selector: u16) -> u64 {
    // selector[15:3] = index, selector[2] = TI (ignored here — must be 0),
    // selector[1:0] = RPL (ignored).
    let idx = (selector >> 3) as u64;
    let entry_addr = (gdtr_base + idx * 8) as *const u64;

    let low = *entry_addr;
    let high = *entry_addr.add(1);

    // Base bits from qword 0: [39:32] = low[39:32], [23:16] = low[23:16].
    let base_lo = ((low >> 16) & 0xFF_FFFF) | (((low >> 32) & 0xFF) << 24);
    // Base bits from qword 1: [63:32] = high[31:0].
    let base_hi = high & 0xFFFF_FFFF;

    base_lo | (base_hi << 32)
}
