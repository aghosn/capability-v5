//! VP (Virtual-Processor) hypercalls.
//!
//! - REGISTER_COMM (0x18): bind a memory capability as a child VP's COMM page.
//! - ADD_VP (0x14): allocate VMCS/VAPIC/PID for a new child VP.
//! - GET_REG / SET_REG (0x0E / 0x0F): read/write a single VP register via the
//!   capability engine + `ThemisPlatform::{get,set}_vp_register`.
//!
//! All four operate on a child domain's VPs; register access is mediated by the
//! engine's read-/write-bitmaps and `MonitorAPI::{GET,SET}` checks.

use capability_engine::{Capability, CapabilityRef, Domain};

use super::{map_error, try_capa, HypercallResult};
use crate::platform::ThemisPlatform;

/// REGISTER_COMM (0x18): register a COMM page bound to a child domain's VP.
///
/// IN:  RDI = mem_cap_handle, RSI = child_domain_handle, RDX = vp_id
pub(super) fn do_register_comm(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    mem_cap_handle: u64,
    child_domain_handle: u64,
    vp_id: u64,
) -> HypercallResult {
    let _batch = try_capa!(Capability::register_comm(
        platform,
        caller,
        mem_cap_handle,
        child_domain_handle,
        vp_id as u32,
    ));
    HypercallResult::success()
}


// ── GET_REG / SET_REG ────────────────────────────────────────────────────── //

/// GET_REG (0x0E): read a single VP register from a child domain VP.
///
/// All permission and state checks are performed by the capability engine:
/// - Caller must hold `MonitorAPI::GET`.
/// - `reg_id` must be within `platform.register_count()`.
/// - The register bit must be set in the effective read-bitmap for the VP.
/// - The VP must not be in Running state.
///
/// The actual hardware read is delegated to `ThemisPlatform::get_vp_register`.
pub(super) fn do_get_reg(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    domain_handle: u64,
    vp_id: u64,
    reg_id: u64,
) -> HypercallResult {
    let (value, _batch) = try_capa!(Capability::get_register(
        platform,
        caller,
        domain_handle,
        vp_id,
        reg_id,
    ));
    HypercallResult::success_1(value)
}

/// SET_REG (0x0F): write a single VP register on a child domain VP.
///
/// All permission and state checks are performed by the capability engine
/// (symmetric to GET_REG, requires `MonitorAPI::SET` and write-bitmap access).
///
/// The actual hardware write is delegated to `ThemisPlatform::set_vp_register`.
pub(super) fn do_set_reg(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    domain_handle: u64,
    vp_id: u64,
    reg_id: u64,
    value: u64,
) -> HypercallResult {
    let _batch = try_capa!(Capability::set_register(
        platform,
        caller,
        domain_handle,
        vp_id,
        reg_id,
        value,
    ));
    HypercallResult::success()
}
