//! Hypercall dispatch — bridges `themis_abi` opcodes to the capability engine.
//!
//! The VMCALL handler in `vmexit.rs` delegates here.  The dispatch reads the
//! calling core's `CoreContext` to obtain the `CapabilityRef<Domain>`, then
//! routes each opcode to the appropriate `Capability::` method via `execute()`.

extern crate alloc;

use core::sync::atomic::Ordering;

use capability_engine::{
    execute, Access, Attributes, Capability, CapabilityRef, CapaError, Domain, DomainId,
    DomainPolicy, InterruptVisibility, MonitorAPI, Platform, PolicyIdentifier, Rights, UpdateBatch,
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
pub fn handle_vmcall(vcpu: &mut ActiveVcpu) -> Option<HypercallResult> {
    let platform_ptr = crate::PLATFORM_PTR.load(Ordering::Relaxed);
    if platform_ptr.is_null() {
        serial_println!("[VMCALL] platform_ptr null!");
        return Some(HypercallResult::error(errors::ERR_INVALID));
    }
    let platform = unsafe { &*platform_ptr };

    let Some(core_id) = platform.get_current_core() else {
        serial_println!("[VMCALL] get_current_core returned None");
        return Some(HypercallResult::error(errors::ERR_INVALID));
    };

    let Some(caller) = platform.get_core_cap(core_id as usize) else {
        serial_println!("[VMCALL] get_core_cap({}) returned None", core_id);
        return Some(HypercallResult::error(errors::ERR_INVALID));
    };

    let opcode = vcpu.reg(Reg::Rax);
    let arg0 = vcpu.reg(Reg::Rdi);
    let arg1 = vcpu.reg(Reg::Rsi);
    let arg2 = vcpu.reg(Reg::Rdx);
    let arg3 = vcpu.reg(Reg::Rcx);

    match opcode {
        opcodes::THEMIS_CARVE => Some(do_carve(platform, &caller, arg0, arg1, arg2, arg3)),
        opcodes::THEMIS_ALIAS => Some(do_alias(platform, &caller, arg0, arg1, arg2, arg3)),
        opcodes::THEMIS_SEND => Some(do_send(platform, &caller, arg0, arg1, arg2, arg3)),
        opcodes::THEMIS_ACCEPT => Some(do_accept(platform, &caller, arg0)),
        opcodes::THEMIS_REJECT => Some(do_reject(platform, &caller, arg0)),
        opcodes::THEMIS_CREATE_DOMAIN => Some(do_create_domain(platform, &caller, arg0, arg1)),
        opcodes::THEMIS_SEAL => Some(do_seal(platform, &caller, arg0)),
        opcodes::THEMIS_REVOKE_MEM => Some(do_revoke_mem(platform, &caller, arg0, arg1)),
        opcodes::THEMIS_REVOKE_DOMAIN => Some(do_revoke_domain(platform, &caller, arg0)),
        opcodes::THEMIS_ATTEST_SELF => Some(do_attest_self(&caller)),
        opcodes::THEMIS_REGISTER_COMM => Some(do_register_comm(platform, &caller, arg0, arg1, arg2)),
        opcodes::THEMIS_DOMCOMM_NOTIFY => Some(do_domcomm_notify(platform, &caller)),
        opcodes::THEMIS_ADD_VP => Some(do_add_vp(platform, &caller, arg0, arg1, vcpu.vmcs_phys())),
        opcodes::THEMIS_SWITCH => do_switch(platform, &caller, arg0, arg1, vcpu),
        opcodes::THEMIS_SET_INTR_POLICY =>
            Some(do_set_intr_policy(platform, &caller, arg0, arg1 as u8, arg2)),
        opcodes::THEMIS_SET_DEF_INTR_POLICY =>
            Some(do_set_def_intr_policy(platform, &caller, arg0, arg1)),

        // Stubbed — return ERR_UNIMPL
        opcodes::THEMIS_GET_CHAN
        | opcodes::THEMIS_ATTEST
        | opcodes::THEMIS_GET_REG
        | opcodes::THEMIS_SET_REG
        | opcodes::THEMIS_ASSIGN_DEVICE
        | opcodes::THEMIS_ENUMERATE
        | opcodes::THEMIS_REGISTER_DOORBELL
        | opcodes::THEMIS_REGISTER_EVENT_FLAGS
        | opcodes::THEMIS_REGISTER_INTR_CHAN => Some(HypercallResult::unimpl()),

        _ => {
            serial_println!("[VMCALL] unknown opcode {:#x}", opcode);
            Some(HypercallResult::error(errors::ERR_INVALID))
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
    let access = Access::new(start, size, Rights::from_bits(rights_bits as u8));
    let caller = caller.clone();
    match execute(platform, false, || {
        Capability::carve(&caller, parent_handle, access).map(|(h, s, batch)| ((h, s), batch))
    }) {
        Ok(((handle, sub), _)) => HypercallResult::success_2(handle, sub),
        Err(e) => HypercallResult::error(map_error(&e)),
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
    let result = execute(platform, false, || {
        Capability::seal(&caller, domain_handle).map(|()| ((), Default::default()))
    });
    match result {
        Ok(_) => {
            // intr-p3g: program IRTEs for the newly-sealed child domain.
            let child_cap = caller
                .read()
                .data
                .get_domain_capability(domain_handle)
                .and_then(|weak| weak.upgrade());
            if let Some(child) = child_cap {
                program_domain_irtes(platform, &child);
            }
            HypercallResult::success()
        }
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
    // intr-p3g: capture child domain_id BEFORE revocation (cap may be dropped after).
    let child_domain_id: Option<capability_engine::DomainId> = caller
        .read()
        .data
        .get_domain_capability(child_handle)
        .and_then(|weak| weak.upgrade())
        .map(|cap| cap.read().data.id);

    let caller = caller.clone();
    match execute(platform, true, || {
        Capability::revoke_domain(&caller, child_handle).map(|batch| ((), batch))
    }) {
        Ok(_) => {
            // intr-p3g: clear all IRTEs that were programmed for this domain.
            if let Some(id) = child_domain_id {
                invalidate_domain_irtes(platform, id);
            }
            HypercallResult::success()
        }
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

    // ── Step 1: pre-allocate VMCS + VAPIC + PID from child's META pool ──
    //
    // Per-VP META page layout (current):
    //   Page 0 (4 KB): VMCS — Intel requires a full 4 KB page.
    //   Page 1 (4 KB): VAPIC — Virtual-APIC page; hardware maps the xAPIC
    //     register space here.  xAPIC registers occupy offsets 0x000–0x3FF
    //     (1 KB); offsets 0x400–0xFFF (3 KB) are architecturally reserved
    //     and never accessed by hardware or the guest APIC emulation.
    //   Page 2 (4 KB): PID — Posted-Interrupt Descriptor; only 64 bytes are
    //     used (PIR bitmap + ON/SN/NV/NDST fields; Intel SDM Vol 3C §29.6).
    //
    // Optimization opportunity (TODO): sub-allocate the PID from the
    // VAPIC page at offset 0x400 (naturally 64-byte aligned, in the unused
    // upper 3 KB).  This would reduce per-VP META consumption from 3 pages
    // to 2 pages, matching the original THHV_META_PAGES_PER_VP=2 budget.
    // Requires computing pid_phys = vapic_phys + 0x400 instead of
    // allocating a separate frame, and reverting THHV_META_PAGES_PER_VP to 2.
    let arc = match platform.domain_arc(child_domain_id) {
        Some(a) => a,
        None => return HypercallResult::error(errors::ERR_NOTFOUND),
    };

    let (vmcs_phys, vapic_phys, pid_phys, msr_bitmap_phys, first_vp);
    {
        let mut pd = arc.lock();
        // Check if this is the first VP (need extra page for MSR bitmap).
        first_vp = pd.msr_bitmap_phys == 0;
        // Per VP: VMCS + VAPIC + PID (+ MSR bitmap if first VP).
        // See optimization note above for reducing this from 3 to 2 pages.
        let pages_needed = if first_vp { 4 } else { 3 };
        if pd.meta.free_pages() < pages_needed as u64 {
            serial_println!(
                "[ADD_VP] not enough META pages: need {} have {}",
                pages_needed, pd.meta.free_pages()
            );
            return HypercallResult::error(errors::ERR_NOMEM);
        }
        vmcs_phys = pd.meta.alloc_frame();
        vapic_phys = pd.meta.alloc_frame();
        pid_phys = pd.meta.alloc_frame();
        if first_vp {
            pd.msr_bitmap_phys = pd.meta.alloc_frame();
        }
        msr_bitmap_phys = pd.msr_bitmap_phys;
    }

    // Zero the PID (64 bytes at offset 0 of the PID page; must be clean before VMENTRY).
    // PIR[255:0] = 0, ON=0, SN=0 — no pending virtual interrupts, no IPI in flight.
    let hhdm = platform.hhdm_offset();
    unsafe {
        core::ptr::write_bytes((pid_phys + hhdm) as *mut u8, 0, 64);
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
            pd.meta.free_frame(pid_phys);
            if first_vp {
                pd.meta.free_frame(msr_bitmap_phys);
                pd.msr_bitmap_phys = 0;
            }
            serial_println!("[ADD_VP] capa engine error, META rolled back");
            HypercallResult::error(map_error(&e))
        }
        Ok((vp_id, _batch)) => {
            // ── Step 3: write VMCS revision ID, set up VMCS, create InactiveVcpu ──
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
                    pd.meta.free_frame(pid_phys);
                    if first_vp {
                        pd.meta.free_frame(msr_bitmap_phys);
                        pd.msr_bitmap_phys = 0;
                    }
                    return HypercallResult::error(errors::ERR_INVALID);
                }
            };

            // Allocate a unique VPID.
            let vpid = platform.next_vpid();

            // Set up child VMCS with intercept-heavy controls + Posted Interrupts.
            // Clobbers VMPTRLD — restored below.
            unsafe {
                crate::vmcs::setup_child_vmcs(
                    vmcs_phys,
                    vapic_phys,
                    msr_bitmap_phys,
                    pid_phys,
                    eptp,
                    vpid,
                );
                // Deactivate child VMCS (save state to memory).
                vmx_ops::vmclear(vmcs_phys).expect("ADD_VP: child vmclear failed");
                // Restore caller's VMCS.
                vmx_ops::vmptrld(caller_vmcs_phys).expect("ADD_VP: parent vmptrld restore failed");
            }

            // Create InactiveVcpu and store in the child's PlatformDomain.
            let vcpu = InactiveVcpu::new(vmcs_phys, vapic_phys, msr_bitmap_phys, pid_phys, vpid);
            platform.bootstrap_store_vcpu(child_domain_id, vp_id as usize, vcpu);

            serial_println!(
                "[ADD_VP] dom={} vp={} vmcs={:#x} vapic={:#x} pid={:#x} msr_bm={:#x} vpid={}",
                child_domain_id, vp_id, vmcs_phys, vapic_phys, pid_phys, msr_bitmap_phys, vpid,
            );

            HypercallResult::success_1(vp_id as u64)
        }
    }
}

// ── SWITCH (sync mode) ───────────────────────────────────────────────────── //

/// SWITCH (0x0A): swap the current ActiveVcpu for a child domain's VP.
///
/// The monitor loop's `vcpu` is replaced: the parent is deactivated and
/// stored in its VcpuSlot; the child is taken from its slot, activated,
/// and becomes the new `vcpu`.  The next `vcpu.run()` in the monitor loop
/// enters the child guest.
///
/// Returns `None` to tell the VMCALL handler to skip result-writeback
/// and RIP-advance (the vcpu is now the child's, not the parent's).
fn do_switch(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    child_domain_handle: u64,
    vp_id: u64,
    vcpu: &mut ActiveVcpu,
) -> Option<HypercallResult> {
    use themis_abi::regs::{VpCommPage, VpRegister, ALL_VP_REGISTERS};

    let vp_idx = vp_id as usize;

    // ── 1a. Resolve child domain ID + COMM HPA (before Capability::switch) ──
    // MUST happen before Capability::switch transitions the child VP to Running,
    // because set_register (used to validate the dirty COMM page registers)
    // rejects writes to a VP that is already in Running state.
    let (child_domain_id_pre, comm_hpa) = {
        let c = caller.read();
        let child_weak = match c.data.get_domain_capability(child_domain_handle) {
            Some(w) => w.clone(),
            None => return Some(HypercallResult::error(errors::ERR_NOTFOUND)),
        };
        drop(c);
        let child_ref = match child_weak.upgrade() {
            Some(r) => r,
            None => return Some(HypercallResult::error(errors::ERR_NOTFOUND)),
        };
        let child_id = child_ref.read().data.id;
        let hpa = platform.domain_arc(child_id)
            .map(|arc| arc.lock().comm_hpas.get(vp_idx).copied().unwrap_or(0))
            .unwrap_or(0);
        (child_id, hpa)
    };
    serial_println!("[SWITCH] comm_hpa={:#x} for dom={} vp={}", comm_hpa, child_domain_id_pre, vp_idx);

    // ── 1b. Snapshot COMM page dirty registers while child VP is Available ──
    let mut pending: alloc::vec::Vec<(VpRegister, u64)> = alloc::vec::Vec::new();

    if comm_hpa != 0 {
        let hhdm = platform.hhdm_offset();
        let comm = unsafe { &mut *((comm_hpa + hhdm) as *mut VpCommPage) };
        let dirty: [u64; 3] = [comm.dirty_mask[0], comm.dirty_mask[1], comm.dirty_mask[2]];
        serial_println!("[SWITCH] dirty_mask=[{:#x}, {:#x}, {:#x}]", dirty[0], dirty[1], dirty[2]);

        if !dirty.iter().all(|w| *w == 0) {
            // Clear dirty bits atomically before validation so we don't replay them.
            for i in 0..3 {
                comm.dirty_mask[i] &= !dirty[i];
            }
            for reg in ALL_VP_REGISTERS {
                let (w, b) = VpCommPage::mask_bit(*reg);
                if dirty[w] & (1 << b) == 0 {
                    continue;
                }
                let val = comm.read_reg(*reg);
                serial_println!("[SWITCH] dirty reg={:?} val={:#x}", reg, val);
                // Validate via capability engine while child VP is still Available.
                if Capability::set_register(
                    caller, child_domain_handle, vp_id, *reg as u64, val, platform,
                ).is_ok() {
                    pending.push((*reg, val));
                }
            }
        }
    }

    // ── 2. Capability engine: forward switch (run-state transitions) ──
    // Child VP transitions Available → Running here; must be after COMM read above.
    let switch_ctx = match Capability::switch(caller, child_domain_handle, vp_id, platform) {
        Ok(ctx) => ctx,
        Err(e) => {
            serial_println!("[SWITCH] validation failed: {:?}", e);
            return Some(HypercallResult::error(map_error(&e)));
        }
    };

    let child_domain_id: DomainId = switch_ctx.to_domain;
    let parent_domain_id: DomainId = switch_ctx.from_domain;
    let parent_vp_id = switch_ctx.from_vp_id.unwrap_or(0) as usize;

    // ── 3. Look up child PlatformDomain ──
    let child_arc = match platform.domain_arc(child_domain_id) {
        Some(a) => a,
        None => {
            let _ = Capability::switch(caller, 0, 0, platform);
            return Some(HypercallResult::error(errors::ERR_NOTFOUND));
        }
    };

    // ── 4. Take child InactiveVcpu from its slot ──
    let mut child_inactive = {
        let d = child_arc.lock();
        match d.vps.get(vp_idx).and_then(|s| s.take()) {
            Some(v) => v,
            None => {
                serial_println!("[SWITCH] VP slot empty dom={} vp={}", child_domain_id, vp_idx);
                let _ = Capability::switch(caller, 0, 0, platform);
                return Some(HypercallResult::error(errors::ERR_BUSY));
            }
        }
    };

    // ── 5. Apply GPRs to child InactiveVcpu (before VMPTRLD) ──
    let mut vmcs_pending: alloc::vec::Vec<(VpRegister, u64)> = alloc::vec::Vec::new();
    for (reg, val) in pending {
        if is_gpr(reg) {
            apply_reg_to_vcpu(reg, val, &mut child_inactive);
        } else {
            vmcs_pending.push((reg, val));
        }
    }

    // ── 6. Deactivate parent → InactiveVcpu → store in parent slot ──
    // SAFETY: we take ownership via ptr::read and will ptr::write the child
    // ActiveVcpu back before returning.  Between read and write, `vcpu`
    // is logically moved-from and must not be used.
    let parent_active = unsafe { core::ptr::read(vcpu as *const ActiveVcpu) };
    let parent_inactive = parent_active.deactivate()
        .expect("[SWITCH] parent deactivate (VMCLEAR) failed");

    let parent_arc = platform.domain_arc(parent_domain_id)
        .expect("[SWITCH] parent PlatformDomain not found");
    parent_arc.lock().vps[parent_vp_id].put(parent_inactive);

    // ── 7. Activate child (VMPTRLD) ──
    // activate() consumes child_inactive.  VMPTRLD failure is fatal since
    // the parent is already deactivated and stored.
    let mut child_active = child_inactive.activate()
        .expect("[SWITCH] child activate (VMPTRLD) failed — fatal");
    // Update PID.NDST so remote cores can send notification IPIs to this core.
    unsafe { pid_set_ndst(child_active.pid_phys(), platform.hhdm_offset(), current_lapic_id()) };

    // ── 8. Apply VMCS-field registers (child VMCS is now loaded) ──
    for (reg, val) in &vmcs_pending {
        apply_vmcs_reg(&mut child_active, *reg, *val);
    }

    // ── 8b. Interrupt return: if the target VP was Suspended (multi-hop interrupt
    // unwind), its RIP is sitting AT its own SWITCH VMCALL.  Deliver a synthetic
    // SWITCH return result so the domain sees "my callee was preempted by interrupt V".
    if let Some(vector) = switch_ctx.interrupt_return {
        child_active.set_reg(Reg::Rax, errors::SUCCESS);
        child_active.set_reg(Reg::Rdi, vector as u64);
        child_active.set_reg(Reg::Rsi, 0);
        child_active.set_reg(Reg::Rdx, 0);
        // Advance RIP past the SWITCH VMCALL (3 bytes).
        let rip = child_active.get(x86::vmx::vmcs::guest::RIP);
        child_active.set(x86::vmx::vmcs::guest::RIP, rip + 3);
    }

    serial_println!(
        "[SWITCH] swapped dom={}→{} vp={}→{} child_rip={:#x}",
        parent_domain_id, child_domain_id,
        parent_vp_id, vp_idx,
        child_active.get(x86::vmx::vmcs::guest::RIP),
    );

    // ── 9. Replace the monitor loop's ActiveVcpu ──
    unsafe { core::ptr::write(vcpu, child_active); }

    // Return None: skip result-writeback + RIP-advance.
    // The monitor loop will call vcpu.run() on the child next.
    None
}

// ── Child exit forwarding ────────────────────────────────────────────────── //

/// Called from `handle_vmexit` when the current domain is not dom0.
///
/// Reads the child's interrupt policy for this exit reason to determine
/// which registers to copy back to the child's COMM page (so the parent
/// can read them).  Then swaps back to the parent — to the parent this
/// looks like a normal return from the SWITCH VMCALL with the exit reason
/// in rdi.
pub fn forward_child_exit(
    vcpu: &mut ActiveVcpu,
    exit_reason: u32,
) {
    use themis_abi::regs::{
        VpCommPage, ALL_VP_REGISTERS,
        InterceptMessage, ThemicMessageHeader,
        VP_COMM_INTERCEPT_OFFSET, THEMIC_MSG_VP_INTERCEPT,
    };
    use x86::vmx::vmcs;

    let platform_ptr = crate::PLATFORM_PTR.load(Ordering::Relaxed);
    assert!(!platform_ptr.is_null());
    let platform = unsafe { &*platform_ptr };

    let core_id = platform.get_current_core()
        .expect("[CHILD_EXIT] get_current_core failed");

    // Get child's cap BEFORE the return switch (core is still assigned to child).
    let child_cap = platform.get_core_cap(core_id as usize)
        .expect("[CHILD_EXIT] get_core_cap failed");

    // Look up the interrupt policy for this exit reason.
    let read_set = {
        let c = child_cap.read();
        let policy = c.data.policy.interrupts.get_policy(exit_reason as u8);
        policy.read_set
    };

    serial_println!(
        "[CHILD_EXIT] reason={} read_set={:x}",
        exit_reason, read_set,
    );

    // ── Capa engine: return switch (child → parent) ──
    let return_ctx = Capability::switch(&child_cap, 0, 0, platform)
        .expect("[CHILD_EXIT] return switch failed");

    let child_domain_id = return_ctx.from_domain;
    let child_vp_id = return_ctx.from_vp_id.unwrap_or(0) as usize;
    let parent_domain_id = return_ctx.to_domain;
    let parent_vp_id = return_ctx.to_vp_id.unwrap_or(0) as usize;

    // ── Copy reported registers + intercept message to child's COMM page ──
    let child_arc = platform.domain_arc(child_domain_id)
        .expect("[CHILD_EXIT] child PlatformDomain not found");
    let comm_hpa = child_arc.lock().comm_hpas.get(child_vp_id).copied().unwrap_or(0);

    if comm_hpa != 0 {
        let hhdm = platform.hhdm_offset();
        let comm = unsafe { &mut *((comm_hpa + hhdm) as *mut VpCommPage) };

        // Copy register values into the COMM page register area.
        for reg in ALL_VP_REGISTERS {
            if !read_set.is_set(*reg as u64) {
                continue;
            }
            let val = if let Some(gpr) = vp_reg_to_gpr(*reg) {
                vcpu.reg(gpr)
            } else if let Some(field) = vp_reg_to_vmcs_field(*reg) {
                vcpu.try_get(field).unwrap_or(0)
            } else {
                continue;
            };
            comm.write_reg(*reg, val);
        }

        // Write the intercept message at offset 512 so the driver can read it.
        let exit_qual = vcpu.try_get(vmcs::ro::EXIT_QUALIFICATION).unwrap_or(0);
        let guest_rip = vcpu.get(vmcs::guest::RIP);
        let guest_rflags = vcpu.get(vmcs::guest::RFLAGS);
        let instr_len = vcpu.try_get(vmcs::ro::VMEXIT_INSTRUCTION_LEN).unwrap_or(0) as u32;
        let guest_phys = vcpu.try_get(vmcs::ro::GUEST_PHYSICAL_ADDR_FULL).unwrap_or(0);

        let msg = InterceptMessage {
            header: ThemicMessageHeader {
                message_type: THEMIC_MSG_VP_INTERCEPT,
                payload_size: (core::mem::size_of::<InterceptMessage>() - core::mem::size_of::<ThemicMessageHeader>()) as u32,
                sequence: 0,
            },
            exit_reason,
            instruction_length: instr_len,
            exit_qualification: exit_qual,
            guest_physical_address: guest_phys,
            guest_rip,
            guest_rflags,
            rax: vcpu.reg(Reg::Rax),
            ..InterceptMessage::default()
        };

        let msg_ptr = (comm_hpa + hhdm + VP_COMM_INTERCEPT_OFFSET as u64) as *mut InterceptMessage;
        unsafe { core::ptr::write_volatile(msg_ptr, msg); }
    }

    // ── Deactivate child → store in child's VcpuSlot ──
    let child_active = unsafe { core::ptr::read(vcpu as *const ActiveVcpu) };
    let child_inactive = child_active.deactivate()
        .expect("[CHILD_EXIT] child deactivate failed");
    child_arc.lock().vps[child_vp_id].put(child_inactive);

    // ── Take parent → activate → replace vcpu ──
    let parent_arc = platform.domain_arc(parent_domain_id)
        .expect("[CHILD_EXIT] parent PlatformDomain not found");
    let parent_inactive = parent_arc.lock().vps[parent_vp_id].take()
        .expect("[CHILD_EXIT] parent VcpuSlot empty");
    let mut parent_active = parent_inactive.activate()
        .expect("[CHILD_EXIT] parent activate failed");
    // Update PID.NDST so remote cores can send notification IPIs to this core.
    unsafe { pid_set_ndst(parent_active.pid_phys(), platform.hhdm_offset(), current_lapic_id()) };

    // To the parent, this is a return from SWITCH VMCALL.
    // RAX = SUCCESS, RDI = exit_reason.
    parent_active.set_reg(Reg::Rax, errors::SUCCESS);
    parent_active.set_reg(Reg::Rdi, exit_reason as u64);
    parent_active.set_reg(Reg::Rsi, 0);
    parent_active.set_reg(Reg::Rdx, 0);

    // Advance parent RIP past the SWITCH VMCALL instruction.
    let parent_rip = parent_active.get(vmcs::guest::RIP);
    let parent_instr_len = parent_active.try_get(vmcs::ro::VMEXIT_INSTRUCTION_LEN)
        .unwrap_or(3); // VMCALL is 3 bytes
    parent_active.set(vmcs::guest::RIP, parent_rip + parent_instr_len);

    serial_println!(
        "[CHILD_EXIT] swapped back dom={}→{} vp={}→{}",
        child_domain_id, parent_domain_id,
        child_vp_id, parent_vp_id,
    );

    // Replace the monitor loop's ActiveVcpu with the parent's.
    unsafe { core::ptr::write(vcpu, parent_active); }
}

// ── Interrupt policy VMCALLs ─────────────────────────────────────────────── //

/// SET_INTR_POLICY (0x10): set per-vector interrupt visibility on a child domain.
///
/// arg0 = child_domain_handle, arg1 = vector (0–254), arg2 = visibility
/// (0=Deliver, 1=Report, 2=NotReport).
fn do_set_intr_policy(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    child_handle: u64,
    vector: u8,
    visibility: u64,
) -> HypercallResult {
    serial_println!(
        "[SET_INTR_POLICY] child={} vec={} vis={}",
        child_handle, vector, visibility
    );
    let caller = caller.clone();
    match execute(platform, false, || {
        Capability::set_policy(
            &caller,
            child_handle,
            PolicyIdentifier::VectorVisibility(vector),
            visibility,
        )
        .map(|()| ((), UpdateBatch::new()))
    }) {
        Ok(_) => HypercallResult::success(),
        Err(e) => HypercallResult::error(map_error(&e)),
    }
}

/// SET_DEF_INTR_POLICY (0x11): set the default interrupt visibility for a child domain.
///
/// arg0 = child_domain_handle, arg1 = visibility (0=Deliver, 1=Report, 2=NotReport).
fn do_set_def_intr_policy(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    child_handle: u64,
    visibility: u64,
) -> HypercallResult {
    serial_println!(
        "[SET_DEF_INTR_POLICY] child={} vis={}",
        child_handle, visibility
    );
    let caller = caller.clone();
    match execute(platform, false, || {
        Capability::set_policy(
            &caller,
            child_handle,
            PolicyIdentifier::DefaultInterruptVisibility,
            visibility,
        )
        .map(|()| ((), UpdateBatch::new()))
    }) {
        Ok(_) => HypercallResult::success(),
        Err(e) => HypercallResult::error(map_error(&e)),
    }
}

// ── Posted Interrupt Descriptor helpers ──────────────────────────────────── //
//
// The Posted-Interrupt Descriptor (PID) is a 64-byte, 64-byte-aligned
// hardware structure defined in Intel SDM Vol 3C §29.6.  Its layout:
//
//   Bytes  0–31  (256 bits): PIR — Posted-Interrupt Requests.
//                            One bit per interrupt vector (vectors 0–255).
//                            The hypervisor sets bits here to post virtual
//                            interrupts to the vCPU.  On the next VM entry
//                            with PROCESS_POSTED_INTERRUPTS=1, hardware
//                            atomically moves all set PIR bits into the
//                            vIRR (VAPIC page bytes 0x200–0x21F) and
//                            delivers the highest-priority pending interrupt
//                            without a VM exit.
//   Byte  32 bit 0:          ON — Outstanding Notification.
//                            Set by the poster before sending a notification
//                            IPI (if the vCPU is not currently running).
//                            Cleared by hardware after processing PIR.
//   Byte  32 bit 1:          SN — Suppress Notification.
//                            When set, hardware suppresses the notification
//                            IPI (used when vCPU is being scheduled off).
//   Byte  33 (bits 15:8):    NV — Notification Vector.
//                            Vector of the IPI sent to wake a sleeping vCPU
//                            (configured in VMCS field 0x0002; we use 0xF2).
//   Bytes 40–43:             NDST — Notification Destination.
//                            APIC ID of the physical CPU currently running
//                            this vCPU; used for cross-core IPI targeting.
//
// The PID is referenced by the child VMCS via VMCS field 0x2016.

/// Set bit `vector` in the Posted-Interrupt Requests (PIR) bitmap of the
/// descriptor at physical address `pid_phys`.
///
/// The PIR is 256 bits = 4 × u64 starting at byte 0 of the PID page.
/// Uses an atomic OR to avoid races with concurrent setters.
///
/// # Safety
/// `pid_phys` must be a valid physical address of a zeroed 64-byte aligned
/// PID page accessible via the HHDM.
unsafe fn pid_set_pir(pid_phys: u64, hhdm: u64, vector: u8) {
    use core::sync::atomic::{AtomicU64, Ordering};
    let word = (vector / 64) as usize;
    let bit = vector % 64;
    let pir_virt = (pid_phys + hhdm) as *const AtomicU64;
    unsafe { (*pir_virt.add(word)).fetch_or(1u64 << bit, Ordering::Release) };
}

/// Atomically set the Outstanding Notification (ON) bit (byte 32, bit 0) of
/// the PID.  Returns `true` if ON was already set (another sender beat us),
/// `false` if we were the first setter (we must send the notification IPI).
unsafe fn pid_test_and_set_on(pid_phys: u64, hhdm: u64) -> bool {
    use core::sync::atomic::{AtomicU32, Ordering};
    let on_ptr = ((pid_phys + hhdm) + 32) as *const AtomicU32;
    let prev = unsafe { (*on_ptr).fetch_or(1, Ordering::AcqRel) };
    prev & 1 != 0
}

/// Write the NDST (Notification Destination, bytes 40–43) field of the PID
/// to `lapic_id`.  Called whenever a VP is activated on a core so remote
/// senders know which LAPIC to address the notification IPI to.
///
/// No-op when `pid_phys == 0` (dom0 has no PID page).
///
/// # Safety
/// `pid_phys` must be a valid physical PID page address accessible via HHDM,
/// or 0 to skip (dom0).
unsafe fn pid_set_ndst(pid_phys: u64, hhdm: u64, lapic_id: u32) {
    if pid_phys == 0 {
        return;
    }
    let ndst_ptr = ((pid_phys + hhdm) + 40) as *mut u32;
    unsafe { core::ptr::write_volatile(ndst_ptr, lapic_id) };
}

/// Send a Fixed-delivery IPI with `vector` to the physical LAPIC identified
/// by `ndst_lapic_id`, using xAPIC MMIO at `hhdm + 0xFEE0_0000`.
///
/// Used to notify a remote core that a VP's PID has pending PIR bits (ON=1).
///
/// # Safety
/// Must be called from VMX root mode; caller must have set `PID.ON = 1` before
/// calling so the target core correctly processes the PID on VMENTRY.
unsafe fn send_notification_ipi(ndst_lapic_id: u32, vector: u8, hhdm: u64) {
    let apic_base = hhdm + 0xFEE0_0000u64;
    unsafe {
        let icr_hi = (apic_base + 0x310) as *mut u32;
        let icr_lo = (apic_base + 0x300) as *mut u32;
        core::ptr::write_volatile(icr_hi, ndst_lapic_id << 24);
        // Fixed delivery mode (0), level assert (bit 14), edge trigger.
        core::ptr::write_volatile(icr_lo, (1u32 << 14) | (vector as u32));
    }
}

/// Return the physical LAPIC ID of the calling CPU via CPUID leaf 1.
fn current_lapic_id() -> u32 {
    let cpuid = unsafe { core::arch::x86_64::__cpuid(1) };
    (cpuid.ebx >> 24) as u32
}

/// Inject interrupt `vector` into the VP whose PID is at `pid_phys`.
///
/// - `is_remote = false` (Case A/B): VP is on this core or not running.
///   Set PIR[V] only; the processor moves PIR → vIRR on VMENTRY automatically.
/// - `is_remote = true` (Case C): VP is Running on a different core.
///   Set PIR[V], then conditionally set ON=1 and send a notification IPI to
///   that core so it processes the PID without a VM exit.
///
/// # Safety
/// `pid_phys` must be a valid 64-byte aligned PID page accessible via HHDM.
unsafe fn inject_via_pid(pid_phys: u64, hhdm: u64, vector: u8, is_remote: bool) {
    unsafe { pid_set_pir(pid_phys, hhdm, vector) };
    if is_remote {
        let on_already_set = unsafe { pid_test_and_set_on(pid_phys, hhdm) };
        if !on_already_set {
            // We set ON=1 first — send the notification IPI to wake the remote core.
            let ndst = unsafe {
                core::ptr::read_volatile(((pid_phys + hhdm) + 40) as *const u32)
            };
            let notify_vec = crate::vmcs::POSTED_INTR_NOTIFY_VEC;
            unsafe { send_notification_ipi(ndst, notify_vec, hhdm) };
        }
    }
}

// ── Interrupt forwarding ─────────────────────────────────────────────────── //

/// Called from `handle_vmexit` when a physical external interrupt fires while a
/// child domain VP is running on this core.
///
/// Routes the interrupt to the handler (Deliver-policy ancestor, which in Phase 1
/// is always dom0) using the lazy-unwind model:
///
/// 1. `deliver_interrupt_vp`: transitions child VP → Available, dom0 VP → Running.
/// 2. VMCLEAR child → store InactiveVcpu in child's VcpuSlot.
/// 3. Take dom0's InactiveVcpu from dom0's VcpuSlot → VMPTRLD dom0.
/// 4. Set `VMENTRY_INTERRUPTION_INFO_FIELD` = external interrupt V (type=0, valid).
/// 5. Dom0 RIP is left unchanged (stays AT the SWITCH VMCALL, since `do_switch`
///    does not advance RIP before storing dom0 to its slot).  After the interrupt
///    fires and `iret` returns, dom0 re-executes SWITCH → finds child VP Available
///    → VMLAUNCH resumes child from its saved VMCS state.
///
/// Routing uses `InterruptPolicy`: if the running child domain has `Deliver`
/// visibility for this vector, the interrupt is injected directly into the child
/// (it owns the vector).  Otherwise (Report/NotReport) the interrupt is forwarded
/// to dom0 via lazy-unwind.
pub fn forward_interrupt_to_handler(vcpu: &mut ActiveVcpu, vector: u8) {
    use x86::vmx::vmcs;

    let platform_ptr = crate::PLATFORM_PTR.load(Ordering::Relaxed);
    assert!(!platform_ptr.is_null());
    let platform = unsafe { &*platform_ptr };

    let core_id = platform.get_current_core()
        .expect("[INTR_FWD] get_current_core failed") as u64;

    // Currently-running domain cap (the child that was interrupted).
    let child_cap = platform.get_core_cap(core_id as usize)
        .expect("[INTR_FWD] get_core_cap failed");

    // Consult the child's interrupt policy for this vector.
    let child_visibility = child_cap.read().data.policy.interrupts.get_policy(vector).visibility;
    if child_visibility == InterruptVisibility::Deliver {
        // Check whether PROCESS_POSTED_INTERRUPTS was actually enabled on the
        // child's VMCS (hardware may have cleared it if unsupported).
        use x86::vmx::vmcs::control::PINBASED_EXEC_CONTROLS;
        let pin_val = vcpu.get(PINBASED_EXEC_CONTROLS);
        if pin_val & (1 << 7) != 0 {
            // Hardware supports posted interrupts — inject via PID (Case A: same core).
            serial_println!("[INTR_FWD] v={} Deliver: posting via PID (same-core)", vector);
            let pid_phys = vcpu.pid_phys();
            let hhdm = platform.hhdm_offset();
            unsafe { inject_via_pid(pid_phys, hhdm, vector, false) };
            // VP is on this core; VMRESUME moves PIR → vIRR automatically.
            return;
        } else {
            // PID not supported — fall back to VMENTRY_INTR_INFO injection.
            serial_println!("[INTR_FWD] v={} Deliver: fallback VMENTRY injection (no PID)", vector);
            let intr_info = (1u64 << 31) | (vector as u64);
            vcpu.set(x86::vmx::vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD, intr_info);
            return;
        }
    }

    // Report or NotReport: forward to dom0 (the root Deliver domain).
    let dom0_cap = platform.dom0_cap();
    let dom0_domain_id = dom0_cap.read().data.id;

    // Lazy-unwind: child VP → Available (n==2), dom0 VP → Running.
    let intr_ctx = match Capability::deliver_interrupt_vp(
        &child_cap,
        dom0_domain_id,
        core_id,
        vector,
        platform,
    ) {
        Ok(ctx) => ctx,
        Err(e) => {
            serial_println!("[INTR_FWD] deliver_interrupt_vp failed: {:?} — re-entering child", e);
            // Fallback: re-inject into child via VMENTRY injection so the interrupt
            // is not lost.  This can happen if the call chain is unexpected.
            let intr_info = (1u64 << 31) | (vector as u64);
            vcpu.set(vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD, intr_info);
            return;
        }
    };

    serial_println!(
        "[INTR_FWD] v={} child_dom={}:{} → handler_dom={}:{}",
        vector,
        intr_ctx.interrupted_domain_id, intr_ctx.interrupted_vp_id,
        intr_ctx.handler_domain_id, intr_ctx.handler_vp_id,
    );

    // Deactivate child (VMCLEAR) → store InactiveVcpu in child's VcpuSlot.
    let child_arc = platform.domain_arc(intr_ctx.interrupted_domain_id)
        .expect("[INTR_FWD] child domain not found");
    let child_active = unsafe { core::ptr::read(vcpu as *const ActiveVcpu) };
    let child_inactive = child_active.deactivate()
        .expect("[INTR_FWD] child deactivate failed");
    child_arc.lock().vps[intr_ctx.interrupted_vp_id as usize].put(child_inactive);

    // Activate dom0 (VMPTRLD) from dom0's VcpuSlot.
    let handler_arc = platform.domain_arc(intr_ctx.handler_domain_id)
        .expect("[INTR_FWD] handler domain not found");
    let handler_inactive = handler_arc.lock().vps[intr_ctx.handler_vp_id as usize].take()
        .expect("[INTR_FWD] handler VcpuSlot empty");
    let mut handler_active = handler_inactive.activate()
        .expect("[INTR_FWD] handler activate (VMPTRLD) failed");
    // Update PID.NDST so remote cores can address notification IPIs to this core.
    unsafe { pid_set_ndst(handler_active.pid_phys(), platform.hhdm_offset(), current_lapic_id()) };

    // Inject the interrupt via VM-entry event injection.
    // Format: bit 31=valid, bits [10:8]=type (0=external interrupt), bits [7:0]=vector.
    // VMENTRY injection bypasses VID and does not update vISR — safe for dom0's
    // xAPIC MMIO EOI path.  The processor clears bit 31 automatically after delivery.
    let intr_info = (1u64 << 31) | (vector as u64);
    handler_active.set(vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD, intr_info);

    // Advance dom0's RIP past the SWITCH VMCALL (3 bytes) and return ERR_RETRY.
    // This allows the Linux kernel driver to return from themis_switch(-EAGAIN),
    // check signal_pending(), and either retry or propagate -EINTR to user space.
    // Without this, the SWITCH vmcall would re-execute after every interrupt and
    // the driver thread could never receive signals.
    let rip = handler_active.get(x86::vmx::vmcs::guest::RIP);
    handler_active.set(x86::vmx::vmcs::guest::RIP, rip + 3);
    handler_active.set_reg(Reg::Rax, errors::ERR_RETRY);
    handler_active.set_reg(Reg::Rdi, 0);
    handler_active.set_reg(Reg::Rsi, 0);
    handler_active.set_reg(Reg::Rdx, 0);

    // Replace the monitor loop's ActiveVcpu with the handler's.
    unsafe { core::ptr::write(vcpu, handler_active); }
}

// ── VpRegister ↔ VMCS / GPR mapping (reusable) ──────────────────────────── //

/// Map a `VpRegister` to its VMCS guest-state field encoding.
/// Returns `None` for GPRs (stored in the register file, not in VMCS)
/// and for registers without a direct VMCS mapping.
fn vp_reg_to_vmcs_field(reg: themis_abi::regs::VpRegister) -> Option<u32> {
    use themis_abi::regs::VpRegister;
    use x86::vmx::vmcs::guest;

    Some(match reg {
        VpRegister::Rsp    => guest::RSP,
        VpRegister::Rip    => guest::RIP,
        VpRegister::Rflags => guest::RFLAGS,
        VpRegister::Cr0    => guest::CR0,
        VpRegister::Cr3    => guest::CR3,
        VpRegister::Cr4    => guest::CR4,
        VpRegister::Efer   => guest::IA32_EFER_FULL,
        VpRegister::Dr7    => guest::DR7,
        VpRegister::CsSelector   => guest::CS_SELECTOR,
        VpRegister::DsSelector   => guest::DS_SELECTOR,
        VpRegister::EsSelector   => guest::ES_SELECTOR,
        VpRegister::FsSelector   => guest::FS_SELECTOR,
        VpRegister::GsSelector   => guest::GS_SELECTOR,
        VpRegister::SsSelector   => guest::SS_SELECTOR,
        VpRegister::TrSelector   => guest::TR_SELECTOR,
        VpRegister::LdtrSelector => guest::LDTR_SELECTOR,
        VpRegister::CsBase   => guest::CS_BASE,
        VpRegister::DsBase   => guest::DS_BASE,
        VpRegister::EsBase   => guest::ES_BASE,
        VpRegister::FsBase   => guest::FS_BASE,
        VpRegister::GsBase   => guest::GS_BASE,
        VpRegister::SsBase   => guest::SS_BASE,
        VpRegister::TrBase   => guest::TR_BASE,
        VpRegister::LdtrBase => guest::LDTR_BASE,
        VpRegister::CsLimit   => guest::CS_LIMIT,
        VpRegister::DsLimit   => guest::DS_LIMIT,
        VpRegister::EsLimit   => guest::ES_LIMIT,
        VpRegister::FsLimit   => guest::FS_LIMIT,
        VpRegister::GsLimit   => guest::GS_LIMIT,
        VpRegister::SsLimit   => guest::SS_LIMIT,
        VpRegister::TrLimit   => guest::TR_LIMIT,
        VpRegister::LdtrLimit => guest::LDTR_LIMIT,
        VpRegister::CsAccessRights   => guest::CS_ACCESS_RIGHTS,
        VpRegister::DsAccessRights   => guest::DS_ACCESS_RIGHTS,
        VpRegister::EsAccessRights   => guest::ES_ACCESS_RIGHTS,
        VpRegister::FsAccessRights   => guest::FS_ACCESS_RIGHTS,
        VpRegister::GsAccessRights   => guest::GS_ACCESS_RIGHTS,
        VpRegister::SsAccessRights   => guest::SS_ACCESS_RIGHTS,
        VpRegister::TrAccessRights   => guest::TR_ACCESS_RIGHTS,
        VpRegister::LdtrAccessRights => guest::LDTR_ACCESS_RIGHTS,
        VpRegister::GdtrBase  => guest::GDTR_BASE,
        VpRegister::GdtrLimit => guest::GDTR_LIMIT,
        VpRegister::IdtrBase  => guest::IDTR_BASE,
        VpRegister::IdtrLimit => guest::IDTR_LIMIT,
        VpRegister::SysenterCs  => guest::IA32_SYSENTER_CS,
        VpRegister::SysenterEsp => guest::IA32_SYSENTER_ESP,
        VpRegister::SysenterEip => guest::IA32_SYSENTER_EIP,
        VpRegister::FsBaseMsr   => guest::FS_BASE,
        VpRegister::GsBaseMsr   => guest::GS_BASE,
        VpRegister::ActivityState         => guest::ACTIVITY_STATE,
        VpRegister::InterruptibilityState => guest::INTERRUPTIBILITY_STATE,
        VpRegister::Pat                   => guest::IA32_PAT_FULL,
        // No VMCS mapping.
        _ => return None,
    })
}

/// Map a `VpRegister` to a GPR index (`Reg`).
/// Returns `None` for non-GPR registers.
fn vp_reg_to_gpr(reg: themis_abi::regs::VpRegister) -> Option<Reg> {
    use themis_abi::regs::VpRegister;
    Some(match reg {
        VpRegister::Rax => Reg::Rax,
        VpRegister::Rbx => Reg::Rbx,
        VpRegister::Rcx => Reg::Rcx,
        VpRegister::Rdx => Reg::Rdx,
        VpRegister::Rsi => Reg::Rsi,
        VpRegister::Rdi => Reg::Rdi,
        VpRegister::Rbp => Reg::Rbp,
        VpRegister::R8  => Reg::R8,
        VpRegister::R9  => Reg::R9,
        VpRegister::R10 => Reg::R10,
        VpRegister::R11 => Reg::R11,
        VpRegister::R12 => Reg::R12,
        VpRegister::R13 => Reg::R13,
        VpRegister::R14 => Reg::R14,
        VpRegister::R15 => Reg::R15,
        _ => return None,
    })
}

/// Apply a VMCS-field register to an active VCPU via `ActiveVcpu::set()`.
fn apply_vmcs_reg(vcpu: &mut ActiveVcpu, reg: themis_abi::regs::VpRegister, val: u64) {
    if let Some(field) = vp_reg_to_vmcs_field(reg) {
        vcpu.set(field, val);
    }
}

/// Apply a register value to an InactiveVcpu.
/// GPRs go to the register file; VMCS fields require the VMCS to be loaded.
fn apply_reg_to_vcpu(reg: themis_abi::regs::VpRegister, val: u64, vcpu: &mut InactiveVcpu) {
    if let Some(gpr) = vp_reg_to_gpr(reg) {
        vcpu.set_reg(gpr, val);
    } else if let Some(field) = vp_reg_to_vmcs_field(reg) {
        vmwrite(field, val);
    }
}

/// Returns true if the register is a GPR (stored in register file, not VMCS).
fn is_gpr(reg: themis_abi::regs::VpRegister) -> bool {
    vp_reg_to_gpr(reg).is_some()
}

/// Helper: VMWRITE with panic on failure.
#[inline]
fn vmwrite(field: u32, val: u64) {
    unsafe {
        x86::bits64::vmx::vmwrite(field, val).expect("VMWRITE failed");
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

// ── intr-p3g: IRTE lifecycle helpers ────────────────────────────────────── //

/// Program IRTEs for every vector in a newly-sealed child domain.
///
/// For each IR-capable DRHD unit:
/// - Deliver vectors with a valid PID → posted-interrupt IRTE pointing to VP[0]
/// - Report / NotReport vectors → remapped IRTE delivered to BSP LAPIC
///
/// Called from `do_seal` after the capability engine completes sealing.
fn program_domain_irtes(
    platform: &ThemisPlatform,
    child_cap: &CapabilityRef<Domain>,
) {
    if platform.drhd_units.is_empty() {
        return;
    }

    let hhdm = platform.hhdm_offset();
    let bsp_lapic = platform.bsp_lapic_id();

    let (child_id, intr_policy) = {
        let r = child_cap.read();
        (r.data.id, r.data.policy.interrupts.clone())
    };

    // Peek at VP[0]'s pid_phys without taking the VP.
    let primary_pid_phys: u64 = platform
        .domain_arc(child_id)
        .map(|arc| arc.lock().vps.first().map_or(0, |s| s.peek_pid_phys()))
        .unwrap_or(0);

    for unit in platform.drhd_units.iter() {
        if unit.irt_phys == 0 {
            continue;
        }
        for vector in 0u8..=254 {
            let vis = intr_policy.get_policy(vector).visibility;
            match vis {
                InterruptVisibility::Deliver if primary_pid_phys != 0 => unsafe {
                    crate::iommu_ir::irte_program_posted(
                        unit.irt_phys,
                        hhdm,
                        vector,
                        primary_pid_phys,
                        0,
                    );
                },
                _ => unsafe {
                    crate::iommu_ir::irte_program_remapped(
                        unit.irt_phys,
                        hhdm,
                        vector,
                        bsp_lapic,
                        vector,
                    );
                },
            }
        }
    }
}

/// Invalidate all IRTE slots for a domain that is being revoked.
///
/// Called from `do_revoke_domain` after the capability engine removes the
/// domain.  Clears all 256 entries for every IR-capable DRHD unit.
fn invalidate_domain_irtes(platform: &ThemisPlatform, _child_id: DomainId) {
    if platform.drhd_units.is_empty() {
        return;
    }
    let hhdm = platform.hhdm_offset();
    for unit in platform.drhd_units.iter() {
        if unit.irt_phys == 0 {
            continue;
        }
        for vector in 0u8..=255 {
            unsafe {
                crate::iommu_ir::irte_invalidate(unit.irt_phys, hhdm, vector);
            }
        }
    }
}
