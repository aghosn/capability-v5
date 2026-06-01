//! Hypercall dispatch — bridges `themis_abi` opcodes to the capability engine.
//!
//! The VMCALL handler in `vmexit.rs` delegates here.  The dispatch reads the
//! calling core's `CoreContext` to obtain the `CapabilityRef<Domain>`, then
//! routes each opcode to the appropriate `Capability::` method via `execute()`.

extern crate alloc;

mod attest;
mod capa;
mod domcomm;
mod doorbell;
mod switch;
mod vp;

pub(crate) use switch::{
    drain_pir_on_interrupt_window, forward_child_exit, forward_interrupt_to_handler,
};

// Re-export the x86-locked per-opcode handlers so the arch impl of
// `ArchHypercall` (under `arch/x86_64/hypercall.rs`) can reach them
// without poking into the private submodules.
#[cfg(target_arch = "x86_64")]
pub(crate) use doorbell::do_ring_doorbell;
#[cfg(target_arch = "x86_64")]
pub(crate) use switch::do_switch;
#[cfg(target_arch = "x86_64")]
pub(crate) use vp::do_add_vp;

use core::sync::atomic::Ordering;

use capability_engine::{CapabilityRef, Domain, CapaError, Platform};
use themis_abi::{errors, opcodes};

use crate::arch_traits::traits::ArchVpOps;
use crate::platform::ThemisPlatform;
#[cfg(target_arch = "x86_64")]
use crate::vcpu::{ActiveVcpu, Reg};
use crate::{serial_debug, serial_println};

// ── Hypercall flow-control helpers ───────────────────────────────────────── //

/// Look up a `PlatformDomain` by `DomainId` from the calling handler.
///
/// Returns the `Arc<Mutex<PlatformDomain>>` on hit; on miss, performs an
/// early `return` from the enclosing function with `ERR_NOTFOUND`.
///
/// Variants:
///   `try_domain!(platform, id)` — for `fn -> HypercallResult`; on miss
///   returns `HypercallResult::error(ERR_NOTFOUND)` from the enclosing fn.
macro_rules! try_domain {
    ($platform:expr, $id:expr) => {
        match $platform.domain_arc($id) {
            Some(a) => a,
            None => return HypercallResult::error(themis_abi::errors::ERR_NOTFOUND),
        }
    };
}
pub(super) use try_domain;

/// Wrap a `capability_engine::execute()` call: on `Ok(v)` evaluate to `v`;
/// on `Err(e)` perform an early `return HypercallResult::error(map_error(&e))`
/// from the enclosing function.
///
/// Eliminates the boilerplate `match execute(...) { Ok(_) => …, Err(e) => … }`
/// that appears at every capability-engine handler site.  The two-argument
/// form defaults the `sealed` flag to `false`; pass it explicitly for the
/// signed-only handlers.
macro_rules! execute_or_return {
    ($platform:expr, $body:expr) => {
        execute_or_return!($platform, false, $body)
    };
    ($platform:expr, $sealed:expr, $body:expr) => {
        match execute($platform, $sealed, $body) {
            Ok(v) => v,
            Err(e) => return HypercallResult::error(map_error(&e)),
        }
    };
}
pub(super) use execute_or_return;

// ── Result encoding ──────────────────────────────────────────────────────── //

// Re-export the architecture-neutral hypercall result type from the arch_traits
// boundary. Per-opcode handlers in the submodules return this; `handle_vmcall`
// writes it back via the arch-trait `set_hypercall_result`.
pub(super) use crate::arch_traits::types::HypercallResult;

/// Write a hypercall result back to the caller's x86 guest registers.
///
/// Does NOT advance RIP — callers must invoke `vcpu.next_rip()` separately.
/// Used by swap-handler early-error paths in `switch.rs` / `doorbell.rs`
/// which are inherently x86-locked and operate directly on `ActiveVcpu`
/// (rather than going through the `ArchVpOps` trait).
#[cfg(target_arch = "x86_64")]
pub(super) fn write_reply(vcpu: &mut ActiveVcpu, r: HypercallResult) {
    vcpu.set_reg(Reg::Rax, r.status);
    vcpu.set_reg(Reg::Rdi, r.val0);
    vcpu.set_reg(Reg::Rsi, r.val1);
    vcpu.set_reg(Reg::Rdx, r.val2);
}

// ── CapaError → ABI error mapping ────────────────────────────────────────── //

pub(super) fn map_error(e: &CapaError) -> u64 {
    match e {
        CapaError::InvalidAccess
        | CapaError::InvalidOperation(_)
        | CapaError::RegionOverlap
        | CapaError::InvalidRemapping
        | CapaError::AlreadyExists
        | CapaError::InvalidValue => errors::ERR_INVALID,

        CapaError::PermissionDenied
        | CapaError::CannotAliasCarved
        | CapaError::MonotonicityViolation
        | CapaError::TreeLocked
        | CapaError::RegisterAccessDenied => errors::ERR_NOPERM,

        CapaError::NotFound | CapaError::ParentRevoked | CapaError::DomainRevoked => {
            errors::ERR_NOTFOUND
        }

        CapaError::DomainSealed | CapaError::DomainNotSealed | CapaError::ApiNotAllowed => {
            errors::ERR_BADSTATE
        }

        CapaError::NotSupported | CapaError::RegisterOutOfRange => errors::ERR_UNIMPL,

        CapaError::NoMemory => errors::ERR_NOMEM,
    }
}

// ── Arch-locked hypercall extension ──────────────────────────────────────── //

/// Hypercall operations that need direct access to the VP's hardware state
/// (raw VMCS reads, swap mechanics) and so cannot be expressed against the
/// neutral `ArchVpOps` interface alone.
///
/// `ArchHypercall` lives here (in the `hypercall/` module) rather than in
/// `arch_traits/` because its method signatures reference `ThemisPlatform`
/// and `CapabilityRef<Domain>` — capavisor-internal types that the arch
/// boundary deliberately stays free of. The trait is implemented per-arch
/// in `hypercall/<arch>_arch.rs`.
pub(crate) trait ArchHypercall: ArchVpOps {
    /// `THEMIS_ADD_VP` opcode — allocates VMCS/VAPIC/PID for a new child VP.
    /// Returns a `HypercallResult`; the generic dispatcher writes it back.
    fn h_add_vp(
        &mut self,
        vp: &mut Self::VpHandle,
        platform: &ThemisPlatform,
        caller: &CapabilityRef<Domain>,
        child_domain_handle: u64,
        comm_cap_handle: u64,
    ) -> HypercallResult;

    /// `THEMIS_SWITCH` opcode — swaps the active VP to a different domain.
    /// On success the active VP is replaced underneath us, so the handler
    /// owns the full reply protocol (no generic writeback follows).
    fn h_switch(
        &mut self,
        vp: &mut Self::VpHandle,
        platform: &ThemisPlatform,
        caller: &CapabilityRef<Domain>,
        to_domain_handle: u64,
        vp_id: u64,
    );

    /// `THEMIS_RING_DOORBELL` opcode — signals a parent / sibling domain.
    /// Like `h_switch`, may swap the active VP, so the handler owns reply.
    fn h_ring_doorbell(
        &mut self,
        vp: &mut Self::VpHandle,
        platform: &ThemisPlatform,
        caller: &CapabilityRef<Domain>,
        gpa: u64,
        value: u64,
    );
}

// ── Opcode dispatch ──────────────────────────────────────────────────────── //

/// Handle a hypercall from the guest, architecture-neutral.
///
/// Reads opcode + args via the `ArchVpOps` accessors, dispatches each opcode
/// to either a generic handler (capa/vp/attest/domcomm/simple doorbell) or
/// an architecture-locked handler (`ArchHypercall::h_add_vp` / `h_switch` /
/// `h_ring_doorbell`), then writes the reply and advances the IP.
///
/// The two swap opcodes (`THEMIS_SWITCH` and `THEMIS_RING_DOORBELL`) may
/// swap the active VP underneath us. They own their own reply protocol:
/// on success they've swapped, on early error they've written the reply
/// themselves.  This function returns early without touching the (possibly
/// new) VP's registers in those cases.
pub fn handle_vmcall<A: ArchHypercall>(arch: &mut A, vp: &mut A::VpHandle) {
    let platform_ptr = crate::PLATFORM_PTR.load(Ordering::Relaxed);
    if platform_ptr.is_null() {
        serial_println!("[VMCALL] platform_ptr null!");
        arch.set_hypercall_result(vp, HypercallResult::error(errors::ERR_INVALID));
        arch.next_rip(vp);
        return;
    }
    let platform = unsafe { &*platform_ptr };

    let Some(core_id) = platform.get_current_core() else {
        serial_println!("[VMCALL] get_current_core returned None");
        arch.set_hypercall_result(vp, HypercallResult::error(errors::ERR_INVALID));
        arch.next_rip(vp);
        return;
    };

    let Some(caller) = platform.get_core_cap(core_id as usize) else {
        serial_println!("[VMCALL] get_core_cap({}) returned None", core_id);
        arch.set_hypercall_result(vp, HypercallResult::error(errors::ERR_INVALID));
        arch.next_rip(vp);
        return;
    };

    let args = arch.get_hypercall_args(vp);
    let (arg0, arg1, arg2, arg3, arg4) = (args.arg0, args.arg1, args.arg2, args.arg3, args.arg4);

    let result = match args.opcode {
        opcodes::THEMIS_CARVE => capa::do_carve(platform, &caller, arg0, arg1, arg2, arg3),
        opcodes::THEMIS_ALIAS => capa::do_alias(platform, &caller, arg0, arg1, arg2, arg3),
        opcodes::THEMIS_SEND => capa::do_send(platform, &caller, arg0, arg1, arg2, arg3),
        opcodes::THEMIS_ACCEPT => capa::do_accept(platform, &caller, arg0),
        opcodes::THEMIS_REJECT => capa::do_reject(platform, &caller, arg0),
        opcodes::THEMIS_CREATE_DOMAIN => capa::do_create_domain(platform, &caller, arg0, arg1),
        opcodes::THEMIS_SEAL => capa::do_seal(platform, &caller, arg0),
        opcodes::THEMIS_REVOKE_MEM => capa::do_revoke_mem(platform, &caller, arg0, arg1),
        opcodes::THEMIS_REVOKE_DOMAIN => capa::do_revoke_domain(platform, &caller, arg0),
        opcodes::THEMIS_ATTEST_SELF => {
            attest::do_attest_self(platform, &caller, arg0, arg1, arg2, arg3)
        }
        opcodes::THEMIS_REGISTER_COMM => vp::do_register_comm(platform, &caller, arg0, arg1, arg2),
        opcodes::THEMIS_DOMCOMM_NOTIFY => domcomm::do_domcomm_notify(platform, &caller),

        // Arch-locked opcode: needs raw VP state (VMCS PA on x86).
        opcodes::THEMIS_ADD_VP => arch.h_add_vp(vp, platform, &caller, arg0, arg1),

        // Swap handlers: own their writeback (success → swapped, early error → wrote reply).
        opcodes::THEMIS_SWITCH => {
            arch.h_switch(vp, platform, &caller, arg0, arg1);
            return;
        }
        opcodes::THEMIS_RING_DOORBELL => {
            arch.h_ring_doorbell(vp, platform, &caller, arg0, arg1);
            return;
        }

        opcodes::THEMIS_SET_POLICY => {
            capa::do_set_policy(platform, &caller, arg0, arg1, arg2, arg3, arg4)
        }

        opcodes::THEMIS_ASSIGN_DEVICE => capa::do_assign_device(platform, &caller, arg0, arg1),
        opcodes::THEMIS_RELEASE_DEVICE => capa::do_release_device(platform, arg0),

        opcodes::THEMIS_GET_REG => vp::do_get_reg(platform, &caller, arg0, arg1, arg2),
        opcodes::THEMIS_SET_REG => vp::do_set_reg(platform, &caller, arg0, arg1, arg2, arg3),

        opcodes::THEMIS_REGISTER_DOORBELL => doorbell::do_register_doorbell(
            platform,
            &caller,
            arg0,
            arg1,
            arg2 as u32,
            arg3,
            arg4 as u32,
        ),
        opcodes::THEMIS_UNREGISTER_DOORBELL => {
            doorbell::do_unregister_doorbell(platform, &caller, arg0, arg1 as u32)
        }
        opcodes::THEMIS_SET_THEMIC_VECTOR => {
            doorbell::do_set_themic_vector(platform, &caller, arg0)
        }
        opcodes::THEMIS_INJECT_INTERRUPT => {
            doorbell::do_inject_interrupt(platform, &caller, arg0, arg1 as u32, arg2 as u8)
        }

        opcodes::THEMIS_DBG_PRINT => {
            // Silenced — each DBG_PRINT is a VMCALL + serial write,
            // flooding serial during virtio-pci probe.  Re-enable for debugging.
            // let dom_id = caller.read().data.id;
            // serial_println!("[DBG] dom={} val={:#x}", dom_id, arg0);
            HypercallResult::success()
        }

        opcodes::THEMIS_TOGGLE_DEBUG => {
            let enable = arg0 != 0;
            crate::RUNTIME_DEBUG.store(enable, core::sync::atomic::Ordering::Relaxed);
            serial_println!(
                "[RTDBG] runtime debug {}",
                if enable { "ENABLED" } else { "DISABLED" }
            );
            HypercallResult::success()
        }

        opcodes::THEMIS_READ_PCR => attest::do_read_pcr(arg0 as u32),

        opcodes::THEMIS_MAP_SELF => capa::do_map_self(platform, &caller, arg0, arg1),

        opcodes::THEMIS_GET_CHAN => capa::do_get_chan(&caller, arg0),
        opcodes::THEMIS_SEND_CHAN => capa::do_send_chan(&caller, arg0, arg1, arg2),
        opcodes::THEMIS_ACCEPT_CHAN => capa::do_accept_chan(&caller, arg0),

        // Stubbed — return ERR_UNIMPL
        opcodes::THEMIS_ATTEST | opcodes::THEMIS_ENUMERATE => HypercallResult::unimpl(),

        _unknown_opcode => {
            serial_debug!("[VMCALL] unknown opcode {:#x}", _unknown_opcode);
            HypercallResult::error(errors::ERR_INVALID)
        }
    };

    arch.set_hypercall_result(vp, result);
    arch.next_rip(vp);
}
