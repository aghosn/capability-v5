//! Hypercall dispatch — bridges `themis_abi` opcodes to the capability engine.
//!
//! The VMCALL handler in `vmexit.rs` delegates here.  The dispatch reads the
//! calling core's `CoreContext` to obtain the `CapabilityRef<Domain>`, then
//! routes each opcode to the appropriate `Capability::` method via `execute()`.
//!
//! All code in this module is architecture-neutral. Opcodes that require
//! raw hardware-VP access (VMCS reads, posted-interrupt mechanics, swap
//! mechanics) are routed through the `ArchHypercall` trait whose impls
//! live under `crate::arch::<isa>::hypercall::`.

extern crate alloc;

mod attest;
mod capa;
mod domcomm;
mod doorbell;
mod vp;

use core::sync::atomic::Ordering;

use capability_engine::{CapaError, CapabilityRef, Domain, Platform};
use themis_abi::{errors, opcodes};

use crate::arch_traits::traits::ArchVpOps;
use crate::platform::ThemisPlatform;
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

// ── Result encoding ──────────────────────────────────────────────────────── //

// Re-export the architecture-neutral hypercall result type from the arch_traits
// boundary. Per-opcode handlers in the submodules return this; `handle_vmcall`
// writes it back via the arch-trait `set_hypercall_result`.
pub(super) use crate::arch_traits::types::HypercallResult;

// ── Arch-locked hypercall extension ──────────────────────────────────────── //

/// Hypercall operations that need direct access to the VP's hardware state
/// (raw VMCS reads, swap mechanics, posted-interrupt mechanics) and so cannot
/// be expressed against the neutral `ArchVpOps` interface alone.
///
/// `ArchHypercall` lives here (in the `hypercall/` module) rather than in
/// `arch_traits/` because its method signatures reference `ThemisPlatform`
/// and `CapabilityRef<Domain>` — capavisor-internal types that the arch
/// boundary deliberately stays free of. The trait is implemented per-arch
/// under `crate::arch::<isa>::hypercall::`.
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

    /// `THEMIS_INJECT_INTERRUPT` opcode — post a vector into a (typically
    /// stopped) target VP. On x86 this writes the VP's Posted-Interrupt
    /// Descriptor; on ARM it would push into the LR/ICH state. Does NOT
    /// touch the calling VP (the `vp` handle is supplied only for symmetry
    /// and so the impl can advance RIP itself if it wishes).
    fn h_inject_interrupt(
        &mut self,
        vp: &mut Self::VpHandle,
        platform: &ThemisPlatform,
        caller: &CapabilityRef<Domain>,
        child_domain_handle: u64,
        vp_id: u32,
        vector: u8,
    ) -> HypercallResult;
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

    let result: Result<HypercallResult, CapaError> = match args.opcode {
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
            Ok(attest::do_attest_self(platform, &caller, arg0, arg1, arg2, arg3))
        }
        opcodes::THEMIS_REGISTER_COMM => vp::do_register_comm(platform, &caller, arg0, arg1, arg2),
        opcodes::THEMIS_DOMCOMM_NOTIFY => Ok(domcomm::do_domcomm_notify(platform, &caller)),

        // Arch-locked opcode: needs raw VP state (VMCS PA on x86).
        opcodes::THEMIS_ADD_VP => Ok(arch.h_add_vp(vp, platform, &caller, arg0, arg1)),

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

        opcodes::THEMIS_REGISTER_DOORBELL => Ok(doorbell::do_register_doorbell(
            platform,
            &caller,
            arg0,
            arg1,
            arg2 as u32,
            arg3,
            arg4 as u32,
        )),
        opcodes::THEMIS_UNREGISTER_DOORBELL => {
            Ok(doorbell::do_unregister_doorbell(platform, &caller, arg0, arg1 as u32))
        }
        opcodes::THEMIS_SET_THEMIC_VECTOR => {
            Ok(doorbell::do_set_themic_vector(platform, &caller, arg0))
        }
        opcodes::THEMIS_INJECT_INTERRUPT => {
            Ok(arch.h_inject_interrupt(vp, platform, &caller, arg0, arg1 as u32, arg2 as u8))
        }

        opcodes::THEMIS_DBG_PRINT => {
            // Silenced — each DBG_PRINT is a VMCALL + serial write,
            // flooding serial during virtio-pci probe.  Re-enable for debugging.
            // let dom_id = caller.read().data.id;
            // serial_println!("[DBG] dom={} val={:#x}", dom_id, arg0);
            Ok(HypercallResult::success())
        }

        opcodes::THEMIS_TOGGLE_DEBUG => {
            let enable = arg0 != 0;
            crate::RUNTIME_DEBUG.store(enable, core::sync::atomic::Ordering::Relaxed);
            serial_println!(
                "[RTDBG] runtime debug {}",
                if enable { "ENABLED" } else { "DISABLED" }
            );
            Ok(HypercallResult::success())
        }

        opcodes::THEMIS_READ_PCR => Ok(attest::do_read_pcr(arg0 as u32)),

        opcodes::THEMIS_MAP_SELF => capa::do_map_self(platform, &caller, arg0, arg1),

        opcodes::THEMIS_GET_CHAN => capa::do_get_chan(platform, &caller, arg0),
        opcodes::THEMIS_SEND_CHAN => capa::do_send_chan(platform, &caller, arg0, arg1, arg2),
        opcodes::THEMIS_ACCEPT_CHAN => capa::do_accept_chan(platform, &caller, arg0),

        // Stubbed — return ERR_UNIMPL
        opcodes::THEMIS_ATTEST | opcodes::THEMIS_ENUMERATE => Ok(HypercallResult::unimpl()),

        _unknown_opcode => {
            serial_debug!("[VMCALL] unknown opcode {:#x}", _unknown_opcode);
            Ok(HypercallResult::error(errors::ERR_INVALID))
        }
    };
    let result = result.unwrap_or_else(HypercallResult::from);

    arch.set_hypercall_result(vp, result);
    arch.next_rip(vp);
}
