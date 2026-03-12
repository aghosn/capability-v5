//! Hypercall dispatch — bridges `themis_abi` opcodes to the capability engine.
//!
//! The VMCALL handler in `vmexit.rs` delegates here.  The dispatch reads the
//! calling core's `CoreContext` to obtain the `CapabilityRef<Domain>`, then
//! routes each opcode to the appropriate `Capability::` method via `execute()`.

extern crate alloc;

use core::sync::atomic::Ordering;

use capability_engine::{
    execute, Access, Attributes, Capability, CapabilityRef, CapaError, Domain, DomainId,
    DomainPolicy, MonitorAPI, Platform, Rights, UpdateBatch,
};
use themis_abi::{errors, opcodes};

use crate::platform::ThemisPlatform;
use crate::serial_println;
use crate::vcpu::{ActiveVcpu, InactiveVcpu, Reg};

// ── Result encoding ──────────────────────────────────────────────────────── //

/// Return values written back to guest registers after a hypercall.
pub struct HypercallResult {
    pub rax: u64, // error code
    pub rdi: u64, // result0
    pub rsi: u64, // result1
    pub rdx: u64, // result2
}

impl HypercallResult {
    fn success() -> Self {
        HypercallResult { rax: errors::SUCCESS, rdi: 0, rsi: 0, rdx: 0 }
    }

    fn success_1(rdi: u64) -> Self {
        HypercallResult { rax: errors::SUCCESS, rdi, rsi: 0, rdx: 0 }
    }

    fn success_2(rdi: u64, rsi: u64) -> Self {
        HypercallResult { rax: errors::SUCCESS, rdi, rsi, rdx: 0 }
    }

    fn error(code: u64) -> Self {
        HypercallResult { rax: code, rdi: 0, rsi: 0, rdx: 0 }
    }

    fn unimpl() -> Self {
        Self::error(errors::ERR_UNIMPL)
    }
}

// ── CapaError → ABI error mapping ────────────────────────────────────────── //

fn map_error(e: &CapaError) -> u64 {
    match e {
        CapaError::InvalidAccess
        | CapaError::InvalidOperation(_)
        | CapaError::RegionOverlap
        | CapaError::InvalidRemapping
        | CapaError::AlreadyExists => errors::ERR_INVALID,

        CapaError::PermissionDenied
        | CapaError::CannotAliasCarved
        | CapaError::MonotonicityViolation
        | CapaError::TreeLocked
        | CapaError::RegisterAccessDenied => errors::ERR_NOPERM,

        CapaError::NotFound
        | CapaError::ParentRevoked
        | CapaError::DomainRevoked => errors::ERR_NOTFOUND,

        CapaError::DomainSealed
        | CapaError::DomainNotSealed
        | CapaError::ApiNotAllowed => errors::ERR_BADSTATE,

        CapaError::NotSupported
        | CapaError::RegisterOutOfRange => errors::ERR_UNIMPL,
    }
}

// ── Opcode dispatch ──────────────────────────────────────────────────────── //

/// Handle a VMCALL from the guest.
///
/// Reads the opcode and arguments from guest registers, dispatches to the
/// capability engine, and returns a `HypercallResult` to be written back.
pub fn handle_vmcall(vcpu: &mut ActiveVcpu) -> HypercallResult {
    let platform_ptr = crate::PLATFORM_PTR.load(Ordering::Relaxed);
    if platform_ptr.is_null() {
        serial_println!("[VMCALL] platform_ptr null!");
        return HypercallResult::error(errors::ERR_INVALID);
    }
    let platform = unsafe { &*platform_ptr };

    let Some(core_id) = platform.get_current_core() else {
        serial_println!("[VMCALL] get_current_core returned None");
        return HypercallResult::error(errors::ERR_INVALID);
    };

    let Some(caller) = platform.get_core_cap(core_id as usize) else {
        serial_println!("[VMCALL] get_core_cap({}) returned None", core_id);
        return HypercallResult::error(errors::ERR_INVALID);
    };

    let opcode = vcpu.reg(Reg::Rax);
    let arg0 = vcpu.reg(Reg::Rdi);
    let arg1 = vcpu.reg(Reg::Rsi);
    let arg2 = vcpu.reg(Reg::Rdx);
    let arg3 = vcpu.reg(Reg::Rcx);

    match opcode {
        opcodes::THEMIS_CARVE => do_carve(platform, &caller, arg0, arg1, arg2, arg3),
        opcodes::THEMIS_ALIAS => do_alias(platform, &caller, arg0, arg1, arg2, arg3),
        opcodes::THEMIS_SEND => do_send(platform, &caller, arg0, arg1, arg2, arg3),
        opcodes::THEMIS_ACCEPT => do_accept(platform, &caller, arg0),
        opcodes::THEMIS_REJECT => do_reject(platform, &caller, arg0),
        opcodes::THEMIS_CREATE_DOMAIN => do_create_domain(platform, &caller, arg0, arg1),
        opcodes::THEMIS_SEAL => do_seal(platform, &caller, arg0),
        opcodes::THEMIS_REVOKE_MEM => do_revoke_mem(platform, &caller, arg0, arg1),
        opcodes::THEMIS_REVOKE_DOMAIN => do_revoke_domain(platform, &caller, arg0),
        opcodes::THEMIS_ATTEST_SELF => do_attest_self(&caller),
        opcodes::THEMIS_REGISTER_COMM => do_register_comm(platform, &caller, arg0, arg1, arg2),
        opcodes::THEMIS_DOMCOMM_NOTIFY => do_domcomm_notify(platform, &caller),
        opcodes::THEMIS_ADD_VP => do_add_vp(platform, &caller, arg0, arg1, vcpu.vmcs_phys()),

        // Stubbed — return ERR_UNIMPL
        opcodes::THEMIS_SWITCH
        | opcodes::THEMIS_GET_CHAN
        | opcodes::THEMIS_ATTEST
        | opcodes::THEMIS_GET_REG
        | opcodes::THEMIS_SET_REG
        | opcodes::THEMIS_SET_INTR_POLICY
        | opcodes::THEMIS_SET_DEF_INTR_POLICY
        | opcodes::THEMIS_ASSIGN_DEVICE
        | opcodes::THEMIS_ENUMERATE
        | opcodes::THEMIS_REGISTER_DOORBELL
        | opcodes::THEMIS_REGISTER_EVENT_FLAGS
        | opcodes::THEMIS_REGISTER_INTR_CHAN => HypercallResult::unimpl(),

        _ => {
            serial_println!("[VMCALL] unknown opcode {:#x}", opcode);
            HypercallResult::error(errors::ERR_INVALID)
        }
    }
}

// ── Individual opcode handlers ───────────────────────────────────────────── //

/// CARVE (0x01): carve exclusive sub-region from parent memory capability.
fn do_carve(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    parent_handle: u64,
    start: u64,
    size: u64,
    rights_bits: u64,
) -> HypercallResult {
    serial_println!("[CARVE] parent={} start={:#x} size={:#x} rights={:#x}",
        parent_handle, start, size, rights_bits);
    let access = Access::new(start, size, Rights::from_bits(rights_bits as u8));
    let caller = caller.clone();
    match execute(platform, false, || {
        Capability::carve(&caller, parent_handle, access).map(|(h, s, batch)| ((h, s), batch))
    }) {
        Ok(((handle, sub), _)) => {
            serial_println!("[CARVE] ok: handle={} sub={}", handle, sub);
            HypercallResult::success_2(handle, sub)
        }
        Err(e) => {
            serial_println!("[CARVE] error: {:?}", e);
            HypercallResult::error(map_error(&e))
        }
    }
}

/// ALIAS (0x02): alias shared sub-region from parent memory capability.
fn do_alias(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    parent_handle: u64,
    start: u64,
    size: u64,
    rights_bits: u64,
) -> HypercallResult {
    let access = Access::new(start, size, Rights::from_bits(rights_bits as u8));
    let caller = caller.clone();
    match execute(platform, false, || {
        Capability::alias(&caller, parent_handle, access).map(|(h, s)| ((h, s), UpdateBatch::default()))
    }) {
        Ok(((handle, sub), _)) => HypercallResult::success_2(handle, sub),
        Err(e) => HypercallResult::error(map_error(&e)),
    }
}

/// SEND (0x03): send memory capability to a receiver domain.
/// arg3 (RCX) = child GPA hint; 0 means identity-map (GPA = HPA).
fn do_send(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    cap_handle: u64,
    receiver_handle: u64,
    attrs_bits: u64,
    child_gpa: u64,
) -> HypercallResult {
    let attrs = Attributes::from_bits(attrs_bits as u8);
    let gpa_hint = if child_gpa != 0 { Some(child_gpa) } else { None };
    let caller = caller.clone();
    match execute(platform, false, || {
        Capability::send_at(&caller, cap_handle, receiver_handle, attrs, gpa_hint)
            .map(|batch| ((), batch))
    }) {
        Ok(_) => HypercallResult::success(),
        Err(e) => HypercallResult::error(map_error(&e)),
    }
}

/// ACCEPT (0x04): accept a pending memory capability.
fn do_accept(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    pending_id: u64,
) -> HypercallResult {
    let caller = caller.clone();
    match execute(platform, false, || Capability::accept(&caller, pending_id)) {
        Ok((handle, _)) => HypercallResult::success_1(handle),
        Err(e) => HypercallResult::error(map_error(&e)),
    }
}

/// REJECT (0x05): reject a pending memory capability.
fn do_reject(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    pending_id: u64,
) -> HypercallResult {
    let caller = caller.clone();
    match execute(platform, false, || {
        Capability::reject(&caller, pending_id).map(|()| ((), Default::default()))
    }) {
        Ok(_) => HypercallResult::success(),
        Err(e) => HypercallResult::error(map_error(&e)),
    }
}

/// CREATE_DOMAIN (0x06): create a new child domain.
fn do_create_domain(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    cores_bitmask: u64,
    api_flags: u64,
) -> HypercallResult {
    let api = MonitorAPI::from_bits(api_flags as u16);
    let policy = DomainPolicy::new_restricted(cores_bitmask, api);
    let caller = caller.clone();
    match execute(platform, false, || Capability::create(&caller, policy.clone())) {
        Ok((handle, _)) => HypercallResult::success_1(handle),
        Err(e) => HypercallResult::error(map_error(&e)),
    }
}

/// SEAL (0x07): seal a domain (Unsealed → Sealed).
fn do_seal(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    domain_handle: u64,
) -> HypercallResult {
    let caller = caller.clone();
    match execute(platform, false, || {
        Capability::seal(&caller, domain_handle).map(|()| ((), Default::default()))
    }) {
        Ok(_) => HypercallResult::success(),
        Err(e) => HypercallResult::error(map_error(&e)),
    }
}

/// REVOKE_MEM (0x08): revoke a child of a memory capability.
fn do_revoke_mem(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    parent_handle: u64,
    child_sub: u64,
) -> HypercallResult {
    let caller = caller.clone();
    match execute(platform, true, || {
        Capability::revoke(&caller, parent_handle, child_sub).map(|batch| ((), batch))
    }) {
        Ok(_) => HypercallResult::success(),
        Err(e) => HypercallResult::error(map_error(&e)),
    }
}

/// REVOKE_DOMAIN (0x09): revoke an entire child domain.
fn do_revoke_domain(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    child_handle: u64,
) -> HypercallResult {
    let caller = caller.clone();
    match execute(platform, true, || {
        Capability::revoke_domain(&caller, child_handle).map(|batch| ((), batch))
    }) {
        Ok(_) => HypercallResult::success(),
        Err(e) => HypercallResult::error(map_error(&e)),
    }
}

/// ATTEST_SELF (0x0C): self-attestation of the calling domain.
fn do_attest_self(caller: &CapabilityRef<Domain>) -> HypercallResult {
    let report = capability_engine::attest::attest_domain(caller);
    // Return domain_id in RDI. The full report string is not easily
    // passed through registers — a future GET_REG-based approach will
    // allow retrieval of the full attestation blob.
    HypercallResult::success_1(report.domain_id)
}

/// REGISTER_COMM (0x18): register a COMM page bound to a child domain's VP.
///
/// IN:  RDI = mem_cap_handle, RSI = child_domain_handle, RDX = vp_id
fn do_register_comm(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    mem_cap_handle: u64,
    child_domain_handle: u64,
    vp_id: u64,
) -> HypercallResult {
    let caller = caller.clone();
    match execute(platform, false, || {
        Capability::register_comm(&caller, mem_cap_handle, child_domain_handle, vp_id as u32)
            .map(|batch| ((), batch))
    }) {
        Ok(_) => HypercallResult::success(),
        Err(e) => HypercallResult::error(map_error(&e)),
    }
}

/// ADD_VP (0x14): add a virtual processor to a child domain.
///
/// The caller must have already CARVE'd a COMM page and SENT VP META pages
/// to the child domain.  This operation:
///   1. Allocates VMCS + VAPIC (+ MSR bitmap on first VP) from META pool.
///   2. Calls `Capability::add_vp` in the capa engine (creates VProcessorState,
///      binds COMM page).
///   3. Sets up the VMCS and creates an InactiveVcpu.
///   4. On capa engine failure, returns allocated META pages to the pool.
///
/// IN:  RDI = child_domain_handle, RSI = comm_cap_handle, RDX = vp_index
/// OUT: RDI = vp_index on success
fn do_add_vp(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    child_domain_handle: u64,
    comm_cap_handle: u64,
    caller_vmcs_phys: u64,
) -> HypercallResult {
    use x86::bits64::vmx as vmx_ops;
    use x86::msr;

    // ── Step 0: resolve child domain_id from handle (read-only) ──
    let child_domain_id: DomainId = {
        let r = caller.read();
        let child_weak = match r.data.get_domain_capability(child_domain_handle) {
            Some(w) => w.clone(),
            None => return HypercallResult::error(errors::ERR_NOTFOUND),
        };
        drop(r);
        let child_ref = match child_weak.upgrade() {
            Some(c) => c,
            None => return HypercallResult::error(errors::ERR_NOTFOUND),
        };
        let id = child_ref.read().data.id;
        id
    };

    // ── Step 1: pre-allocate VMCS + VAPIC from child's META pool ──
    let arc = match platform.domain_arc(child_domain_id) {
        Some(a) => a,
        None => return HypercallResult::error(errors::ERR_NOTFOUND),
    };

    let (vmcs_phys, vapic_phys, msr_bitmap_phys, first_vp);
    {
        let mut pd = arc.lock();
        // Check if this is the first VP (need extra page for MSR bitmap).
        first_vp = pd.msr_bitmap_phys == 0;
        let pages_needed = if first_vp { 3 } else { 2 };
        if pd.meta.free_pages() < pages_needed as u64 {
            serial_println!(
                "[ADD_VP] not enough META pages: need {} have {}",
                pages_needed, pd.meta.free_pages()
            );
            return HypercallResult::error(errors::ERR_NOMEM);
        }
        vmcs_phys = pd.meta.alloc_frame();
        vapic_phys = pd.meta.alloc_frame();
        if first_vp {
            pd.msr_bitmap_phys = pd.meta.alloc_frame();
        }
        msr_bitmap_phys = pd.msr_bitmap_phys;
    }

    // ── Step 2: call into capa engine ──
    let caller = caller.clone();
    let result = execute(platform, false, || {
        Capability::add_vp(&caller, child_domain_handle, comm_cap_handle)
            .map(|(vp_id, batch)| (vp_id, batch))
    });

    match result {
        Err(e) => {
            // Rollback: return allocated pages to META pool.
            let mut pd = arc.lock();
            pd.meta.free_frame(vmcs_phys);
            pd.meta.free_frame(vapic_phys);
            if first_vp {
                pd.meta.free_frame(msr_bitmap_phys);
                pd.msr_bitmap_phys = 0;
            }
            serial_println!("[ADD_VP] capa engine error, META rolled back");
            HypercallResult::error(map_error(&e))
        }
        Ok((vp_id, _batch)) => {
            // ── Step 3: write VMCS revision ID, set up VMCS, create InactiveVcpu ──
            let hhdm = platform.hhdm_offset();
            let rev_id = (unsafe { msr::rdmsr(msr::IA32_VMX_BASIC) } & 0x7FFF_FFFF) as u32;

            // Write revision ID into the VMCS page header.
            let vmcs_virt = (vmcs_phys + hhdm) as *mut u32;
            unsafe { vmcs_virt.write_volatile(rev_id) };

            // Get child EPT pointer.
            let eptp = match platform.eptp(child_domain_id) {
                Some(e) => e,
                None => {
                    serial_println!("[ADD_VP] child domain has no EPT");
                    // Rollback META.
                    let mut pd = arc.lock();
                    pd.meta.free_frame(vmcs_phys);
                    pd.meta.free_frame(vapic_phys);
                    if first_vp {
                        pd.meta.free_frame(msr_bitmap_phys);
                        pd.msr_bitmap_phys = 0;
                    }
                    return HypercallResult::error(errors::ERR_INVALID);
                }
            };

            // Allocate a unique VPID.
            let vpid = platform.next_vpid();

            // Set up VMCS control/host/guest fields.
            // This does VMCLEAR + VMPTRLD internally, so it clobbers the current
            // (caller's) VMCS pointer — we restore it below.
            unsafe {
                crate::vmcs::setup_vmcs_for_vp(
                    vmcs_phys,
                    vapic_phys,
                    msr_bitmap_phys,
                    eptp,
                    vp_id as usize,
                );
                // Deactivate child VMCS (save state to memory).
                vmx_ops::vmclear(vmcs_phys).expect("ADD_VP: child vmclear failed");
                // Restore caller's VMCS.
                vmx_ops::vmptrld(caller_vmcs_phys).expect("ADD_VP: parent vmptrld restore failed");
            }

            // Create InactiveVcpu and store in the child's PlatformDomain.
            let vcpu = InactiveVcpu::new(vmcs_phys, vapic_phys, msr_bitmap_phys, vpid);
            platform.bootstrap_store_vcpu(child_domain_id, vp_id as usize, vcpu);

            serial_println!(
                "[ADD_VP] dom={} vp={} vmcs={:#x} vapic={:#x} msr_bm={:#x} vpid={}",
                child_domain_id, vp_id, vmcs_phys, vapic_phys, msr_bitmap_phys, vpid,
            );

            HypercallResult::success_1(vp_id as u64)
        }
    }
}

/// Map a `VpRegister` to the appropriate VMCS guest-state field or GPR slot
/// and write the value.
///
/// **Precondition**: the child VMCS is currently loaded (VMPTRLD done).
/// GPRs (RAX–R15) go to InactiveVcpu's register file; everything else
/// goes via VMWRITE to the corresponding VMCS guest-state encoding.
fn apply_reg_to_vcpu(reg: themis_abi::regs::VpRegister, val: u64, vcpu: &mut InactiveVcpu) {
    use themis_abi::regs::VpRegister;
    use x86::vmx::vmcs::guest;

    match reg {
        // GPRs → register save area (not in VMCS)
        VpRegister::Rax => vcpu.set_reg(Reg::Rax, val),
        VpRegister::Rbx => vcpu.set_reg(Reg::Rbx, val),
        VpRegister::Rcx => vcpu.set_reg(Reg::Rcx, val),
        VpRegister::Rdx => vcpu.set_reg(Reg::Rdx, val),
        VpRegister::Rsi => vcpu.set_reg(Reg::Rsi, val),
        VpRegister::Rdi => vcpu.set_reg(Reg::Rdi, val),
        VpRegister::Rbp => vcpu.set_reg(Reg::Rbp, val),
        VpRegister::R8  => vcpu.set_reg(Reg::R8, val),
        VpRegister::R9  => vcpu.set_reg(Reg::R9, val),
        VpRegister::R10 => vcpu.set_reg(Reg::R10, val),
        VpRegister::R11 => vcpu.set_reg(Reg::R11, val),
        VpRegister::R12 => vcpu.set_reg(Reg::R12, val),
        VpRegister::R13 => vcpu.set_reg(Reg::R13, val),
        VpRegister::R14 => vcpu.set_reg(Reg::R14, val),
        VpRegister::R15 => vcpu.set_reg(Reg::R15, val),

        // VMCS guest-state fields → VMWRITE
        VpRegister::Rsp    => vmwrite(guest::RSP, val),
        VpRegister::Rip    => vmwrite(guest::RIP, val),
        VpRegister::Rflags => vmwrite(guest::RFLAGS, val),

        VpRegister::Cr0  => vmwrite(guest::CR0, val),
        VpRegister::Cr3  => vmwrite(guest::CR3, val),
        VpRegister::Cr4  => vmwrite(guest::CR4, val),
        VpRegister::Efer => vmwrite(guest::IA32_EFER_FULL, val),
        VpRegister::Dr7  => vmwrite(guest::DR7, val),

        VpRegister::CsSelector   => vmwrite(guest::CS_SELECTOR, val),
        VpRegister::DsSelector   => vmwrite(guest::DS_SELECTOR, val),
        VpRegister::EsSelector   => vmwrite(guest::ES_SELECTOR, val),
        VpRegister::FsSelector   => vmwrite(guest::FS_SELECTOR, val),
        VpRegister::GsSelector   => vmwrite(guest::GS_SELECTOR, val),
        VpRegister::SsSelector   => vmwrite(guest::SS_SELECTOR, val),
        VpRegister::TrSelector   => vmwrite(guest::TR_SELECTOR, val),
        VpRegister::LdtrSelector => vmwrite(guest::LDTR_SELECTOR, val),

        VpRegister::CsBase   => vmwrite(guest::CS_BASE, val),
        VpRegister::DsBase   => vmwrite(guest::DS_BASE, val),
        VpRegister::EsBase   => vmwrite(guest::ES_BASE, val),
        VpRegister::FsBase   => vmwrite(guest::FS_BASE, val),
        VpRegister::GsBase   => vmwrite(guest::GS_BASE, val),
        VpRegister::SsBase   => vmwrite(guest::SS_BASE, val),
        VpRegister::TrBase   => vmwrite(guest::TR_BASE, val),
        VpRegister::LdtrBase => vmwrite(guest::LDTR_BASE, val),

        VpRegister::CsLimit   => vmwrite(guest::CS_LIMIT, val),
        VpRegister::DsLimit   => vmwrite(guest::DS_LIMIT, val),
        VpRegister::EsLimit   => vmwrite(guest::ES_LIMIT, val),
        VpRegister::FsLimit   => vmwrite(guest::FS_LIMIT, val),
        VpRegister::GsLimit   => vmwrite(guest::GS_LIMIT, val),
        VpRegister::SsLimit   => vmwrite(guest::SS_LIMIT, val),
        VpRegister::TrLimit   => vmwrite(guest::TR_LIMIT, val),
        VpRegister::LdtrLimit => vmwrite(guest::LDTR_LIMIT, val),

        VpRegister::CsAccessRights   => vmwrite(guest::CS_ACCESS_RIGHTS, val),
        VpRegister::DsAccessRights   => vmwrite(guest::DS_ACCESS_RIGHTS, val),
        VpRegister::EsAccessRights   => vmwrite(guest::ES_ACCESS_RIGHTS, val),
        VpRegister::FsAccessRights   => vmwrite(guest::FS_ACCESS_RIGHTS, val),
        VpRegister::GsAccessRights   => vmwrite(guest::GS_ACCESS_RIGHTS, val),
        VpRegister::SsAccessRights   => vmwrite(guest::SS_ACCESS_RIGHTS, val),
        VpRegister::TrAccessRights   => vmwrite(guest::TR_ACCESS_RIGHTS, val),
        VpRegister::LdtrAccessRights => vmwrite(guest::LDTR_ACCESS_RIGHTS, val),

        VpRegister::GdtrBase  => vmwrite(guest::GDTR_BASE, val),
        VpRegister::GdtrLimit => vmwrite(guest::GDTR_LIMIT, val),
        VpRegister::IdtrBase  => vmwrite(guest::IDTR_BASE, val),
        VpRegister::IdtrLimit => vmwrite(guest::IDTR_LIMIT, val),

        VpRegister::SysenterCs  => vmwrite(guest::IA32_SYSENTER_CS, val),
        VpRegister::SysenterEsp => vmwrite(guest::IA32_SYSENTER_ESP, val),
        VpRegister::SysenterEip => vmwrite(guest::IA32_SYSENTER_EIP, val),

        // FS/GS base MSRs map to the same VMCS fields as the segment bases.
        VpRegister::FsBaseMsr    => vmwrite(guest::FS_BASE, val),
        VpRegister::GsBaseMsr    => vmwrite(guest::GS_BASE, val),
        // KERNEL_GS_BASE: not a VMCS field — saved/restored via MSR load/store
        // lists.  For now, store it in the InactiveVcpu.
        VpRegister::KernelGsBase => { /* TODO: MSR load/store area */ }

        VpRegister::ApicBase => { /* IA32_APIC_BASE is a real MSR, skip for now */ }
        VpRegister::Tpr      => { /* read-only for parent, ignore writes */ }
        VpRegister::Ppr      => { /* read-only for parent, ignore writes */ }

        VpRegister::ActivityState         => vmwrite(guest::ACTIVITY_STATE, val),
        VpRegister::InterruptibilityState => vmwrite(guest::INTERRUPTIBILITY_STATE, val),
        VpRegister::Pat                   => vmwrite(guest::IA32_PAT_FULL, val),
    }
}

/// Helper: VMWRITE with panic on failure.
#[inline]
fn vmwrite(field: u32, val: u64) {
    unsafe {
        x86::bits64::vmx::vmwrite(field, val).expect("VMWRITE failed in apply_reg_to_vcpu");
    }
}

/// DOMCOMM_NOTIFY (0x19): process pending messages on the caller's TX ring.
///
/// The domain enqueues messages (GROW_RX, GROW_TX, ENUM_CAP, etc.) on its
/// TX ring and then does this VMCALL to trigger the capavisor to process them.
fn do_domcomm_notify(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
) -> HypercallResult {
    use themis_abi::domcomm;

    let domain_id = caller.read().data.id;

    let pd = match platform.get_platform_domain(domain_id) {
        Some(pd) => pd,
        None => return HypercallResult::error(errors::ERR_NOTFOUND),
    };

    let mut pd_locked = pd.lock();
    if pd_locked.domcomm.is_none() {
        return HypercallResult::error(errors::ERR_BADSTATE);
    }

    // Drain all pending TX messages.
    let mut buf = [0u8; 4096];

    loop {
        let result = pd_locked.domcomm_tx_dequeue(&mut buf);
        match result {
            None => break,
            Some((msg_type, payload_size)) => {
                match msg_type {
                    domcomm::msg_types::GROW_RX | domcomm::msg_types::GROW_TX => {
                        let is_rx = msg_type == domcomm::msg_types::GROW_RX;
                        handle_grow(platform, caller, &mut *pd_locked,
                                    is_rx, &buf[..payload_size]);
                    }
                    _ => {
                        serial_println!(
                            "[domcomm] unknown TX msg type {:#x} from domain {}",
                            msg_type, domain_id,
                        );
                    }
                }
            }
        }
    }

    HypercallResult::success()
}

/// Handle a GROW_RX or GROW_TX request from the domain.
///
/// The domain has CARVEd pages and REGISTER_COMM'd them (self-ref).
/// We look up the capability to find the HPAs, then extend the ring.
///
/// Security: the payload was already copied from shared memory by
/// domcomm_tx_dequeue (TOCTOU-safe). All domain-supplied values
/// (handle, nr_pages) are bounds-checked before use.
fn handle_grow(
    _platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    pd: &mut crate::platform::PlatformDomain,
    is_rx: bool,
    payload: &[u8],
) {
    use themis_abi::domcomm;

    let req_size = core::mem::size_of::<domcomm::GrowRequest>();
    if payload.len() < req_size {
        serial_println!("[domcomm] GROW payload too small ({})", payload.len());
        send_grow_ack(pd, 1);
        return;
    }

    // Copy to a local struct (payload is already a copy from domcomm_tx_dequeue,
    // but we do a typed copy for alignment safety).
    let mut req: domcomm::GrowRequest = unsafe { core::mem::zeroed() };
    unsafe {
        core::ptr::copy_nonoverlapping(
            payload.as_ptr(),
            &mut req as *mut domcomm::GrowRequest as *mut u8,
            req_size,
        );
    }

    serial_println!(
        "[domcomm] GROW_{}: cap_handle={} cap_sub={} nr_pages={}",
        if is_rx { "RX" } else { "TX" },
        req.cap_handle, req.cap_sub, req.nr_pages,
    );

    // Bounds-check nr_pages (prevent OOM from malicious domain).
    if req.nr_pages == 0 || req.nr_pages > 256 {
        serial_println!("[domcomm] GROW: invalid nr_pages {}", req.nr_pages);
        send_grow_ack(pd, 6);
        return;
    }

    // Look up the capability to find the HPAs.
    let hpa_start: u64;
    let cap_size: u64;
    {
        let dom = caller.read();
        let cap_weak = match dom.data.get_memory_capability(req.cap_handle) {
            Some(w) => w.clone(),
            None => {
                serial_println!("[domcomm] GROW: cap {} not found", req.cap_handle);
                send_grow_ack(pd, 2);
                return;
            }
        };
        drop(dom);

        let cap_ref = match cap_weak.upgrade() {
            Some(r) => r,
            None => {
                serial_println!("[domcomm] GROW: cap {} revoked", req.cap_handle);
                send_grow_ack(pd, 3);
                return;
            }
        };
        let c = cap_ref.read();
        hpa_start = c.data.access.start;
        cap_size = c.data.access.size;

        // Verify the cap has COMM attribute (was REGISTER_COMM'd).
        if !c.owned.attributes.comm() {
            serial_println!("[domcomm] GROW: cap {} not COMM-attributed", req.cap_handle);
            send_grow_ack(pd, 4);
            return;
        }
    }

    let expected_size = req.nr_pages as u64 * 0x1000;
    if cap_size < expected_size {
        serial_println!(
            "[domcomm] GROW: cap size {:#x} < expected {:#x}",
            cap_size, expected_size,
        );
        send_grow_ack(pd, 5);
        return;
    }

    // Extend the ring page list.
    let (new_page_count, new_capacity) = {
        let dc = pd.domcomm.as_mut().expect("DomainComm not init");
        let ring = if is_rx { &mut dc.rx } else { &mut dc.tx };
        for i in 0..req.nr_pages {
            ring.page_hpas.push(hpa_start + i as u64 * 0x1000);
        }

        // Update the header page's ring metadata.
        let hdr_virt = (dc.header_hpa + dc.hhdm_offset) as *mut domcomm::Header;
        unsafe {
            let hdr = &mut *hdr_virt;
            let ring_meta = if is_rx { &mut hdr.rx } else { &mut hdr.tx };
            ring_meta.page_count = ring.page_hpas.len() as u32;
        }

        (ring.page_hpas.len() as u32, ring.page_hpas.len() as u32 * 4096)
    };

    serial_println!(
        "[domcomm] GROW_{} done: {} pages, capacity {}",
        if is_rx { "RX" } else { "TX" },
        new_page_count, new_capacity,
    );

    // Send GROW_ACK on the RX ring.
    let ack = domcomm::GrowAck {
        new_page_count,
        new_capacity,
        status: 0,
        reserved: 0,
    };
    let ack_bytes = unsafe {
        core::slice::from_raw_parts(
            &ack as *const domcomm::GrowAck as *const u8,
            core::mem::size_of::<domcomm::GrowAck>(),
        )
    };
    pd.domcomm_rx_enqueue(domcomm::msg_types::GROW_ACK, ack_bytes);
}

/// Send a GROW_ACK with an error status.
fn send_grow_ack(pd: &mut crate::platform::PlatformDomain, status: u32) {
    use themis_abi::domcomm;

    let ack = domcomm::GrowAck {
        new_page_count: 0,
        new_capacity: 0,
        status,
        reserved: 0,
    };
    let ack_bytes = unsafe {
        core::slice::from_raw_parts(
            &ack as *const domcomm::GrowAck as *const u8,
            core::mem::size_of::<domcomm::GrowAck>(),
        )
    };
    pd.domcomm_rx_enqueue(domcomm::msg_types::GROW_ACK, ack_bytes);
}
