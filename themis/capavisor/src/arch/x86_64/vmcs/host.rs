//! Host-state VMCS field setup (segments, control regs, MSRs, GDTR/IDTR/TR
//! bases, host RIP/RSP).

use x86::bits64::vmx;
use x86::msr;
use x86::vmx::vmcs::host;

use crate::arch::vmexit::host_rip_stub;

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

pub(super) unsafe fn write_host_state() {
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
