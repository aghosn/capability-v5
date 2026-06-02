//! Fatal-exit dump helpers (VM-entry failure, triple fault, EPT misconfig).
//!
//! All three serialize on `crate::SERIAL_LOCK` and emit a wide register/VMCS
//! snapshot before the monitor loop returns `SemanticExit::Shutdown`.

use x86::vmx::vmcs;
use x86::vmx::vmcs::control;

use crate::serial_println;
use crate::vcpu::{ActiveVcpu, Reg};
use crate::arch::x86_64::vcpu_ext::ActiveVcpuExt;

pub(super) fn dump_vmentry_failure(
    vcpu: &ActiveVcpu,
    platform: Option<&crate::platform::ThemisPlatform>,
    core_id: usize,
) {
    while crate::SERIAL_LOCK.swap(true, core::sync::atomic::Ordering::Acquire) {
        core::hint::spin_loop();
    }
    let domain_id = platform
        .map(|p| p.core_domain_id(core_id))
        .unwrap_or(u64::MAX);
    let qual = vcpu.get(vmcs::ro::EXIT_QUALIFICATION);
    let cr0 = vcpu.get(vmcs::guest::CR0);
    let cr4 = vcpu.get(vmcs::guest::CR4);
    let cr3 = vcpu.get(vmcs::guest::CR3);
    let rip = vcpu.rip();
    let rsp = vcpu.rsp();
    let rflags = vcpu.rflags();
    let efer = vcpu.get(vmcs::guest::IA32_EFER_FULL);
    let cs_sel = vcpu.get(vmcs::guest::CS_SELECTOR);
    let cs_base = vcpu.get(vmcs::guest::CS_BASE);
    let cs_lim = vcpu.get(vmcs::guest::CS_LIMIT);
    let cs_ar = vcpu.get(vmcs::guest::CS_ACCESS_RIGHTS);
    let ss_sel = vcpu.get(vmcs::guest::SS_SELECTOR);
    let ss_ar = vcpu.get(vmcs::guest::SS_ACCESS_RIGHTS);
    let tr_ar = vcpu.get(vmcs::guest::TR_ACCESS_RIGHTS);
    let ldtr_ar = vcpu.get(vmcs::guest::LDTR_ACCESS_RIGHTS);
    let activity = vcpu.get(vmcs::guest::ACTIVITY_STATE);
    let interrupt = vcpu.get(vmcs::guest::INTERRUPTIBILITY_STATE);
    let link_ptr = vcpu.get(vmcs::guest::LINK_PTR_FULL);
    let vpid = vcpu.get(control::VPID);
    let entry_ctrl = vcpu.get(control::VMENTRY_CONTROLS);
    let pin_ctrl = vcpu.get(control::PINBASED_EXEC_CONTROLS);
    let proc2_ctrl = vcpu.get(control::SECONDARY_PROCBASED_EXEC_CONTROLS);
    let intr_info = vcpu.get(control::VMENTRY_INTERRUPTION_INFO_FIELD);
    let cr0_mask = vcpu.get(control::CR0_GUEST_HOST_MASK);
    let cr0_shadow = vcpu.get(control::CR0_READ_SHADOW);
    let cr4_mask = vcpu.get(control::CR4_GUEST_HOST_MASK);
    let cr4_shadow = vcpu.get(control::CR4_READ_SHADOW);
    serial_println!(
        "[FATAL] exit 33 dom={} core={} EXIT_QUAL={:#x} (check={})\n\
         CR0={:#x} CR4={:#x} CR3={:#x} EFER={:#x}\n\
         RIP={:#x} RSP={:#x} RFLAGS={:#x}\n\
         CS sel={:#x} base={:#x} lim={:#x} ar={:#x}\n\
         SS sel={:#x} ar={:#x} TR_AR={:#x} LDTR_AR={:#x}\n\
         activity={} interrupt={:#x} link_ptr={:#x} vpid={}\n\
         ENTRY_CTRL={:#x} PIN={:#x} PROC2={:#x}\n\
         INTR_INFO={:#x}\n\
         CR0_MASK={:#x} CR0_SHADOW={:#x} CR4_MASK={:#x} CR4_SHADOW={:#x}",
        domain_id,
        core_id,
        qual,
        qual & 0xf,
        cr0,
        cr4,
        cr3,
        efer,
        rip,
        rsp,
        rflags,
        cs_sel,
        cs_base,
        cs_lim,
        cs_ar,
        ss_sel,
        ss_ar,
        tr_ar,
        ldtr_ar,
        activity,
        interrupt,
        link_ptr,
        vpid,
        entry_ctrl,
        pin_ctrl,
        proc2_ctrl,
        intr_info,
        cr0_mask,
        cr0_shadow,
        cr4_mask,
        cr4_shadow,
    );
    serial_println!(
        "  RAX={:#018x}  RBX={:#018x}  RCX={:#018x}",
        vcpu.reg(Reg::Rax),
        vcpu.reg(Reg::Rbx),
        vcpu.reg(Reg::Rcx)
    );
    crate::SERIAL_LOCK.store(false, core::sync::atomic::Ordering::Release);
}

pub(super) fn dump_triple_fault(vcpu: &ActiveVcpu) {
    while crate::SERIAL_LOCK.swap(true, core::sync::atomic::Ordering::Acquire) {
        core::hint::spin_loop();
    }
    let rip = vcpu.rip();
    let rsp = vcpu.rsp();
    let cr0 = vcpu.get(vmcs::guest::CR0);
    let cr3 = vcpu.get(vmcs::guest::CR3);
    let cr4 = vcpu.get(vmcs::guest::CR4);
    let efer = vcpu.get(vmcs::guest::IA32_EFER_FULL);
    let rflags = vcpu.rflags();
    let cs_sel = vcpu.get(vmcs::guest::CS_SELECTOR);
    let cs_base = vcpu.get(vmcs::guest::CS_BASE);
    let cs_ar = vcpu.get(vmcs::guest::CS_ACCESS_RIGHTS);
    let ss_sel = vcpu.get(vmcs::guest::SS_SELECTOR);
    let ss_ar = vcpu.get(vmcs::guest::SS_ACCESS_RIGHTS);
    let entry_ctl = vcpu.get(control::VMENTRY_CONTROLS);
    let act = vcpu.get(vmcs::guest::ACTIVITY_STATE);
    let interruptibility = vcpu.get(vmcs::guest::INTERRUPTIBILITY_STATE);
    let idtr_base = vcpu.get(vmcs::guest::IDTR_BASE);
    let idtr_limit = vcpu.get(vmcs::guest::IDTR_LIMIT);
    serial_println!("===== TRIPLE FAULT (vpid={}) =====", vcpu.vpid());
    serial_println!(
        "  RIP={:#018x}  RSP={:#018x}  RFLAGS={:#010x}",
        rip,
        rsp,
        rflags
    );
    serial_println!(
        "  CR0={:#010x}  CR3={:#010x}  CR4={:#010x}  EFER={:#010x}",
        cr0,
        cr3,
        cr4,
        efer
    );
    serial_println!(
        "  CS: sel={:#06x} base={:#010x} ar={:#06x}  SS: sel={:#06x} ar={:#06x}",
        cs_sel,
        cs_base,
        cs_ar,
        ss_sel,
        ss_ar
    );
    serial_println!("  IDTR: base={:#018x} limit={:#06x}", idtr_base, idtr_limit);
    serial_println!(
        "  entry_ctl={:#010x}  activity={} interruptibility={:#x}",
        entry_ctl,
        act,
        interruptibility
    );
    serial_println!(
        "  RAX={:#018x}  RBX={:#018x}  RCX={:#018x}",
        vcpu.reg(Reg::Rax),
        vcpu.reg(Reg::Rbx),
        vcpu.reg(Reg::Rcx)
    );
    serial_println!(
        "  RDX={:#018x}  RSI={:#018x}  RDI={:#018x}",
        vcpu.reg(Reg::Rdx),
        vcpu.reg(Reg::Rsi),
        vcpu.reg(Reg::Rdi)
    );
    serial_println!(
        "  R8 ={:#018x}  R9 ={:#018x}  R10={:#018x}",
        vcpu.reg(Reg::R8),
        vcpu.reg(Reg::R9),
        vcpu.reg(Reg::R10)
    );
    serial_println!(
        "  RBP={:#018x}  R12={:#018x}  R13={:#018x}",
        vcpu.reg(Reg::Rbp),
        vcpu.reg(Reg::R12),
        vcpu.reg(Reg::R13)
    );
    serial_println!("=================================");
    crate::SERIAL_LOCK.store(false, core::sync::atomic::Ordering::Release);
}

pub(super) fn dump_ept_misconfig(vcpu: &ActiveVcpu) {
    while crate::SERIAL_LOCK.swap(true, core::sync::atomic::Ordering::Acquire) {
        core::hint::spin_loop();
    }
    let gpa = vcpu.get(vmcs::ro::GUEST_PHYSICAL_ADDR_FULL);
    let rip = vcpu.rip();
    serial_println!(
        "[VMEXIT] EPT misconfig vpid={} GPA={:#x} RIP={:#x}",
        vcpu.vpid(),
        gpa,
        rip
    );
    crate::SERIAL_LOCK.store(false, core::sync::atomic::Ordering::Release);
}
