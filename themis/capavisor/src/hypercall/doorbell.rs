//! ThemIC doorbell hypercalls (arch-neutral).
//!
//! - REGISTER_DOORBELL   / UNREGISTER_DOORBELL (0x15 / 0x16)
//! - SET_THEMIC_VECTOR   (0x18)
//!
//! The arch-locked half lives in `arch/<isa>/hypercall/doorbell.rs`:
//!   - RING_DOORBELL    (0x17) — context-switches via `forward_child_exit`
//!   - INJECT_INTERRUPT (0x1B) — writes target VP's PIR on x86

use capability_engine::{Capability, CapabilityRef, CapaError, Domain};
use themis_abi::errors;

use super::{try_domain, HypercallResult};
use crate::platform::ThemisPlatform;

// ── ThemIC VMCALLs ───────────────────────────────────────────────────────── //

/// REGISTER_DOORBELL (0x15): register a doorbell entry for a child domain.
///
/// arg0 = child_domain_handle, arg1 = gpa, arg2 = size (1/2/4/8),
/// arg3 = datamatch, arg4 = flags (THEMIC_DOORBELL_FLAG_*)
/// Returns doorbell_id in arg0 on success.
pub(super) fn do_register_doorbell(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    child_handle: u64,
    gpa: u64,
    size: u32,
    datamatch: u64,
    flags: u32,
) -> HypercallResult {
    use crate::platform::{DoorbellEntry, THEMIC_MAX_DOORBELLS};

    let any_size = flags & crate::platform::THEMIC_DOORBELL_FLAG_ANY_SIZE != 0;
    if !any_size && size != 1 && size != 2 && size != 4 && size != 8 {
        return HypercallResult::error(errors::ERR_INVALID);
    }

    let result = Capability::platform_action_on_child(
        platform,
        caller,
        child_handle,
        |_platform, child_ref| {
            let child_domain_id = child_ref.read().data.id;
            let child_arc = platform
                .domain_arc(child_domain_id)
                .ok_or(CapaError::NotFound)?;
            let mut pd = child_arc.lock();

            if pd.doorbells.len() >= THEMIC_MAX_DOORBELLS {
                return Err(CapaError::NoMemory);
            }

            let doorbell_id = pd.next_doorbell_id;
            pd.next_doorbell_id = pd.next_doorbell_id.wrapping_add(1);
            pd.doorbells.push(DoorbellEntry {
                doorbell_id,
                gpa,
                datamatch,
                size,
                flags,
            });
            Ok(doorbell_id)
        },
    );

    match result {
        Ok(doorbell_id) => {
            serial_rtdbg!(
                "[REG_DB] id={} gpa={:#x} sz={} flags={:#x}",
                doorbell_id,
                gpa,
                size,
                flags
            );
            HypercallResult::success_1(doorbell_id as u64)
        }
        Err(e) => HypercallResult::from(e),
    }
}

/// UNREGISTER_DOORBELL (0x16): remove a previously registered doorbell entry.
///
/// arg0 = child_domain_handle, arg1 = doorbell_id
pub(super) fn do_unregister_doorbell(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    child_handle: u64,
    doorbell_id: u32,
) -> HypercallResult {
    let result = Capability::platform_action_on_child(
        platform,
        caller,
        child_handle,
        |_platform, child_ref| {
            let child_domain_id = child_ref.read().data.id;
            let child_arc = platform
                .domain_arc(child_domain_id)
                .ok_or(CapaError::NotFound)?;
            let mut pd = child_arc.lock();

            let before = pd.doorbells.len();
            pd.doorbells.retain(|e| e.doorbell_id != doorbell_id);
            if pd.doorbells.len() == before {
                return Err(CapaError::NotFound);
            }
            Ok(())
        },
    );

    match result {
        Ok(()) => HypercallResult::success(),
        Err(e) => HypercallResult::from(e),
    }
}

/// SET_THEMIC_VECTOR (0x17): configure the notify_vector in the caller's
/// DomainComm header.  dom0's driver registers the IDT handler for this vector;
/// the capavisor sends an IPI at this vector to notify dom0 of pending
/// DomainComm RX ring messages (doorbells, VP exits in async mode).
///
/// arg0 = vector (u8, 1–255)
pub(super) fn do_set_themic_vector(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    vector: u64,
) -> HypercallResult {
    if vector == 0 || vector > 255 {
        return HypercallResult::error(errors::ERR_INVALID);
    }
    let caller_id = caller.read().data.id;
    let arc = try_domain!(platform, caller_id);
    arc.lock().set_notify_vector(vector as u32);
    HypercallResult::success()
}

