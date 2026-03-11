//! Hypercall dispatch — bridges `themis_abi` opcodes to the capability engine.
//!
//! The VMCALL handler in `vmexit.rs` delegates here.  The dispatch reads the
//! calling core's `CoreContext` to obtain the `CapabilityRef<Domain>`, then
//! routes each opcode to the appropriate `Capability::` method via `execute()`.

extern crate alloc;

use core::sync::atomic::Ordering;

use capability_engine::{
    execute, Access, Attributes, Capability, CapabilityRef, CapaError, Domain, DomainPolicy,
    MonitorAPI, Platform, Rights, UpdateBatch,
};
use themis_abi::{errors, opcodes};

use crate::platform::ThemisPlatform;
use crate::serial_println;
use crate::vcpu::{ActiveVcpu, Reg};

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
        opcodes::THEMIS_SEND => do_send(platform, &caller, arg0, arg1, arg2),
        opcodes::THEMIS_ACCEPT => do_accept(platform, &caller, arg0),
        opcodes::THEMIS_REJECT => do_reject(platform, &caller, arg0),
        opcodes::THEMIS_CREATE_DOMAIN => do_create_domain(platform, &caller, arg0, arg1),
        opcodes::THEMIS_SEAL => do_seal(platform, &caller, arg0),
        opcodes::THEMIS_REVOKE_MEM => do_revoke_mem(platform, &caller, arg0, arg1),
        opcodes::THEMIS_REVOKE_DOMAIN => do_revoke_domain(platform, &caller, arg0),
        opcodes::THEMIS_ATTEST_SELF => do_attest_self(&caller),
        opcodes::THEMIS_REGISTER_COMM => do_register_comm(platform, &caller, arg0, arg1, arg2),
        opcodes::THEMIS_DOMCOMM_NOTIFY => do_domcomm_notify(platform, &caller),

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
        | opcodes::THEMIS_REGISTER_VP_META
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
fn do_send(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    cap_handle: u64,
    receiver_handle: u64,
    attrs_bits: u64,
) -> HypercallResult {
    let attrs = Attributes::from_bits(attrs_bits as u8);
    let caller = caller.clone();
    match execute(platform, false, || {
        Capability::send(&caller, cap_handle, receiver_handle, attrs).map(|batch| ((), batch))
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

// ── DomainComm TX ring processing ────────────────────────────────────────── //

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
