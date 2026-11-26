//! Immutable notification capability creation.

use capability_engine::{CapaError, Capability, CapabilityRef, Domain, DoorbellKind, SELF_CAPABILITY};

use super::HypercallResult;
use crate::platform::ThemisPlatform;

pub(super) fn do_create_doorbell(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    child: u64,
    vector: u64,
    kind: u64,
    vp: u64,
) -> Result<HypercallResult, CapaError> {
    let vector = u8::try_from(vector).map_err(|_| CapaError::InvalidValue)?;
    let kind = match (kind, vp) {
        (0, 0) => DoorbellKind::Sync,
        (1, vp_id) => DoorbellKind::Async { vp_id },
        _ => return Err(CapaError::InvalidValue),
    };
    let child = if child == SELF_CAPABILITY { None } else { Some(child) };
    let (handle, port) = Capability::create_doorbell(platform, caller, child, vector, kind)?;
    Ok(HypercallResult::success_2(handle, port))
}
