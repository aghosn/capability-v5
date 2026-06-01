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

use core::sync::atomic::Ordering;

use capability_engine::{CapaError, Platform};
use themis_abi::{errors, opcodes};

#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::vcpu_ext::ActiveVcpuExt;
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
// writes it back to the caller's registers via `write_reply`.
pub(super) use crate::arch_traits::types::HypercallResult;

/// Write a hypercall result back to the caller's guest registers.
///
/// Does NOT advance RIP — callers must invoke `vcpu.next_rip()` separately
/// after this when they want to step past the `VMCALL` instruction. Keeping
/// the two operations distinct lets swap-handler error paths reuse this
/// helper without taking an implicit IP-advance contract.
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

// ── Opcode dispatch ──────────────────────────────────────────────────────── //

#[cfg(target_arch = "x86_64")]
/// Handle a VMCALL from the guest.
///
/// Reads the opcode and arguments from guest registers, dispatches to the
/// per-opcode handler, and writes the reply back to the caller's registers
/// (plus advancing RIP past the VMCALL instruction). The two swap opcodes
/// (`THEMIS_SWITCH` and the synthesized `THEMIS_RING_DOORBELL` path) take
/// `vcpu` directly and perform their own bookkeeping — on success they have
/// swapped the active VP underneath us, on early error they write the error
/// reply themselves before returning.
pub fn handle_vmcall(vcpu: &mut ActiveVcpu) {
    let platform_ptr = crate::PLATFORM_PTR.load(Ordering::Relaxed);
    if platform_ptr.is_null() {
        serial_println!("[VMCALL] platform_ptr null!");
        write_reply(vcpu, HypercallResult::error(errors::ERR_INVALID));
        vcpu.next_rip();
        return;
    }
    let platform = unsafe { &*platform_ptr };

    let Some(core_id) = platform.get_current_core() else {
        serial_println!("[VMCALL] get_current_core returned None");
        write_reply(vcpu, HypercallResult::error(errors::ERR_INVALID));
        vcpu.next_rip();
        return;
    };

    let Some(caller) = platform.get_core_cap(core_id as usize) else {
        serial_println!("[VMCALL] get_core_cap({}) returned None", core_id);
        write_reply(vcpu, HypercallResult::error(errors::ERR_INVALID));
        vcpu.next_rip();
        return;
    };

    let opcode = vcpu.reg(Reg::Rax);
    let arg0 = vcpu.reg(Reg::Rdi);
    let arg1 = vcpu.reg(Reg::Rsi);
    let arg2 = vcpu.reg(Reg::Rdx);
    let arg3 = vcpu.reg(Reg::Rcx);
    let arg4 = vcpu.reg(Reg::R8);

    let result = match opcode {
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
        opcodes::THEMIS_ADD_VP => vp::do_add_vp(platform, &caller, arg0, arg1, vcpu.vmcs_phys()),

        // Swap handlers: own their writeback (success → swapped, early error → wrote reply).
        opcodes::THEMIS_SWITCH => {
            switch::do_switch(platform, &caller, arg0, arg1, vcpu);
            return;
        }
        opcodes::THEMIS_RING_DOORBELL => {
            doorbell::do_ring_doorbell(platform, &caller, arg0, arg1, vcpu);
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

        _ => {
            serial_debug!("[VMCALL] unknown opcode {:#x}", opcode);
            HypercallResult::error(errors::ERR_INVALID)
        }
    };

    write_reply(vcpu, result);
    vcpu.next_rip();
}

