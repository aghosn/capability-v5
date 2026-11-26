//! Capability-engine hypercalls.
//!
//! Tree-shape operations:        CARVE / ALIAS / SEND / ACCEPT / REJECT / REVOKE
//! Channel creation:             GET_CHAN
//! Domain lifecycle:             CREATE / SEAL
//! Self-mapping:                 MAP_SELF
//! Policy:                       SET_POLICY (all PolicyIdentifier variants)
//! Device assignment:            ASSIGN_DEVICE / RELEASE_DEVICE
//!
//! Most handlers are thin wrappers around `capability_engine::Capability::*`
//! via engine-managed transactions. Only `do_assign_device`
//! and `do_release_device` touch arch-specific state (IOMMU IRTEs / device
//! assignment) through `crate::arch::x86_64::iommu_ir`.

use capability_engine::{
    Access, Attributes, Capability, CapaError, CapabilityRef, Domain, DomainPolicy, MonitorAPI,
    PolicyIdentifier, ResourceKind, Rights,
};
use themis_abi::errors;

use super::{HypercallResult};
use crate::platform::ThemisPlatform;

// ── Individual opcode handlers ───────────────────────────────────────────── //

/// CARVE (0x01): carve exclusive sub-region from parent memory capability.
pub(super) fn do_carve(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    parent_handle: u64,
    start: u64,
    size: u64,
    rights_bits: u64,
) -> Result<HypercallResult, CapaError> {
    let access = Access::new(start, size, Rights::from_bits(rights_bits as u8));
    let (handle, sub, _batch) = Capability::carve(platform, caller, parent_handle, access)?;
    Ok(HypercallResult::success_2(handle, sub))
}

/// ALIAS (0x02): alias shared sub-region from parent memory capability.
pub(super) fn do_alias(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    parent_handle: u64,
    start: u64,
    size: u64,
    rights_bits: u64,
) -> Result<HypercallResult, CapaError> {
    let access = Access::new(start, size, Rights::from_bits(rights_bits as u8));
    let (handle, sub, _batch) = Capability::alias(platform, caller, parent_handle, access)?;
    Ok(HypercallResult::success_2(handle, sub))
}

/// SEND (0x03): send a capability to a receiver domain or channel.
/// arg3 (RCX) = child GPA; u64::MAX means identity-map (GPA = HPA).
/// 0 is a valid explicit GPA (maps memory at the bottom of the child's
/// address space), so the sentinel must not be 0.
pub(super) fn do_send(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    cap_handle: u64,
    receiver_handle: u64,
    attrs_bits: u64,
    child_gpa: u64,
) -> Result<HypercallResult, CapaError> {
    let attrs = Attributes::from_bits(attrs_bits as u8);
    let gpa_hint = if child_gpa != u64::MAX {
        Some(child_gpa)
    } else {
        None
    };
    let _batch = Capability::send_at(
        platform,
        caller,
        cap_handle,
        receiver_handle,
        attrs,
        gpa_hint
    )?;
    Ok(HypercallResult::success())
}

/// ACCEPT (0x04): accept a pending capability.
pub(super) fn do_accept(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    pending_id: u64,
) -> Result<HypercallResult, CapaError> {
    let (handle, _batch) = Capability::accept(platform, caller, pending_id)?;
    Ok(HypercallResult::success_1(handle))
}

/// REJECT (0x05): reject a pending capability.
pub(super) fn do_reject(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    pending_id: u64,
) -> Result<HypercallResult, CapaError> {
    let _batch = Capability::reject(platform, caller, pending_id)?;
    Ok(HypercallResult::success())
}

// ── Channel (domain capability transfer) handlers ────────────────────────── //

/// GET_CHAN (0x0B): get a channel capability to a child domain.
/// If domain_handle == 0, creates a self-channel (for receiving from children).
pub(super) fn do_get_chan(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    domain_handle: u64,
) -> Result<HypercallResult, CapaError> {
    let (handle, _batch) = if domain_handle == 0 {
        Capability::get_chan_self(platform, caller)?
    } else {
        Capability::get_chan(platform, caller, domain_handle)?
    };
    Ok(HypercallResult::success_1(handle))
}

/// CREATE_DOMAIN (0x06): create a new child domain.
pub(super) fn do_create_domain(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    cores_bitmask: u64,
    api_flags: u64,
) -> Result<HypercallResult, CapaError> {
    let parent_cores = caller.read().data.policy.cores;
    let parent_api = caller.read().data.policy.api;
    let api = MonitorAPI::from_bits(api_flags as u16 & parent_api.bits());
    let policy = DomainPolicy::new_restricted(cores_bitmask & parent_cores, api);
    let (handle, _batch) = Capability::create(platform, caller, policy)?;
    Ok(HypercallResult::success_1(handle))
}

/// SEAL (0x07): seal a domain (Unsealed → Sealed).
pub(super) fn do_seal(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    domain_handle: u64,
) -> Result<HypercallResult, CapaError> {
    // DomainComm finalization, MSR bitmap re-projection, and IRTE
    // programming for the newly-sealed child are all handled by
    // `ThemisPlatform::on_domain_sealed`, which the engine calls under its
    // own op-lock as part of `seal`'s `execute()` -- no need to re-resolve
    // the child handle again here (that would be an unsynchronized read of
    // tree state after the lock has already been released).
    let _batch = Capability::seal(platform, caller, domain_handle)?;
    Ok(HypercallResult::success())
}

/// REVOKE (0x08): revoke a tree child, or an owned domain when child_sub is zero.
pub(super) fn do_revoke(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    parent_handle: u64,
    child_sub: u64,
) -> Result<HypercallResult, CapaError> {
    let _batch = Capability::revoke(platform, caller, parent_handle, child_sub)?;
    Ok(HypercallResult::success())
}

/// MAP_SELF (0x1f): remap a memory capability at a new GPA within the caller's space.
///
/// IN:  RDI = cap_handle, RSI = new_gpa
pub(super) fn do_map_self(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    cap_handle: u64,
    new_gpa: u64,
) -> Result<HypercallResult, CapaError> {
    let _batch = Capability::map_self(platform, caller, cap_handle, new_gpa)?;
    Ok(HypercallResult::success())
}


// ── Interrupt policy VMCALLs ─────────────────────────────────────────────── //

/// THEMIS_SET_POLICY (0x22): unified policy-setting hypercall.
///
/// Maps directly to `Capability::set_policy(&caller, child_handle, id, value)`.
///
/// arg0 = child_handle, arg1 = policy_kind, arg2 = key, arg3 = sub_key, arg4 = value.
pub(super) fn do_set_policy(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    child_handle: u64,
    kind: u64,
    key: u64,
    sub_key: u64,
    value: u64,
) -> Result<HypercallResult, CapaError> {
    use themis_abi::policy_kind;

    let (kind, vp, emulate_word) = policy_kind::decode(kind).ok_or(CapaError::InvalidValue)?;
    let scope = vp.map_or(capability_engine::PolicyScope::Domain, |id| {
        capability_engine::PolicyScope::Vp(u64::from(id))
    });
    match kind {
        policy_kind::CORES
        | policy_kind::API_MONITOR
        | policy_kind::DEFAULT_INTR_VISIBILITY
        | policy_kind::DEFAULT_EXIT_TRAP
        | policy_kind::CPUID_DEFAULT
        | policy_kind::MSR_DEFAULT
        | policy_kind::DEFAULT_VECTOR_INJECTABLE
            if key != 0 || sub_key != 0 =>
        {
            return Err(CapaError::InvalidValue);
        }
        policy_kind::VECTOR_VISIBILITY
        | policy_kind::VECTOR_INJECTABLE
        | policy_kind::EXIT_REASON_TRAP
            if sub_key != 0 =>
        {
            return Err(CapaError::InvalidValue);
        }
        policy_kind::DEFAULT_INTR_REG_READ_SET
        | policy_kind::DEFAULT_INTR_REG_WRITE_SET
        | policy_kind::DEFAULT_EXIT_REG_READ_SET
        | policy_kind::DEFAULT_EXIT_REG_WRITE_SET
            if key != 0 =>
        {
            return Err(CapaError::InvalidValue);
        }
        _ => {}
    }
    let id = match kind {
        policy_kind::CORES => PolicyIdentifier::Cores,
        policy_kind::API_MONITOR => PolicyIdentifier::ApiMonitor,
        policy_kind::DEFAULT_INTR_VISIBILITY => PolicyIdentifier::DefaultInterruptVisibility,
        policy_kind::DEFAULT_INTR_REG_READ_SET => PolicyIdentifier::DefaultInterruptRegReadSet(u8::try_from(sub_key).map_err(|_| CapaError::InvalidValue)?),
        policy_kind::DEFAULT_INTR_REG_WRITE_SET => PolicyIdentifier::DefaultInterruptRegWriteSet(u8::try_from(sub_key).map_err(|_| CapaError::InvalidValue)?),
        policy_kind::DEFAULT_VECTOR_INJECTABLE => PolicyIdentifier::DefaultVectorInjectable,
        policy_kind::VECTOR_VISIBILITY => PolicyIdentifier::VectorVisibility(u8::try_from(key).map_err(|_| CapaError::InvalidValue)?),
        policy_kind::VECTOR_REG_READ_SET => {
            PolicyIdentifier::VectorRegReadSet(u8::try_from(key).map_err(|_| CapaError::InvalidValue)?, u8::try_from(sub_key).map_err(|_| CapaError::InvalidValue)?)
        }
        policy_kind::VECTOR_REG_WRITE_SET => {
            PolicyIdentifier::VectorRegWriteSet(u8::try_from(key).map_err(|_| CapaError::InvalidValue)?, u8::try_from(sub_key).map_err(|_| CapaError::InvalidValue)?)
        }
        policy_kind::VECTOR_INJECTABLE => PolicyIdentifier::VectorInjectable(u8::try_from(key).map_err(|_| CapaError::InvalidValue)?),
        policy_kind::DEFAULT_EXIT_TRAP => PolicyIdentifier::DefaultExitTrap,
        policy_kind::DEFAULT_EXIT_REG_READ_SET => PolicyIdentifier::DefaultExitRegReadSet(u8::try_from(sub_key).map_err(|_| CapaError::InvalidValue)?),
        policy_kind::DEFAULT_EXIT_REG_WRITE_SET => PolicyIdentifier::DefaultExitRegWriteSet(u8::try_from(sub_key).map_err(|_| CapaError::InvalidValue)?),
        policy_kind::EXIT_REASON_TRAP => PolicyIdentifier::ExitReasonTrap(u32::try_from(key).map_err(|_| CapaError::InvalidValue)?),
        policy_kind::EXIT_REASON_REG_READ_SET => {
            PolicyIdentifier::ExitReasonRegReadSet(u32::try_from(key).map_err(|_| CapaError::InvalidValue)?, u8::try_from(sub_key).map_err(|_| CapaError::InvalidValue)?)
        }
        policy_kind::EXIT_REASON_REG_WRITE_SET => {
            PolicyIdentifier::ExitReasonRegWriteSet(u32::try_from(key).map_err(|_| CapaError::InvalidValue)?, u8::try_from(sub_key).map_err(|_| CapaError::InvalidValue)?)
        }
        policy_kind::CPUID_DEFAULT => {
            PolicyIdentifier::ProcFeatureDefault(ResourceKind::Cpuid)
        }
        policy_kind::CPUID_RANGE => {
            let start_leaf = (key >> 32) as u32;
            let start_sub = key as u32;
            let end_leaf = (sub_key >> 32) as u32;
            let end_sub = sub_key as u32;
            PolicyIdentifier::ProcFeatureRange(
                ResourceKind::Cpuid, start_leaf, start_sub, end_leaf, end_sub,
            )
        }
        policy_kind::CPUID_EMULATE => {
            let leaf = (key >> 32) as u32;
            let subleaf = key as u32;
            PolicyIdentifier::ProcFeatureEmulate(
                ResourceKind::Cpuid, leaf, subleaf, u8::try_from(sub_key).map_err(|_| CapaError::InvalidValue)?,
            )
        }
        policy_kind::CPUID_EMULATE_RANGE => PolicyIdentifier::ProcFeatureEmulateRange(
            ResourceKind::Cpuid,
            (key >> 32) as u32,
            key as u32,
            (sub_key >> 32) as u32,
            sub_key as u32,
            emulate_word,
        ),
        policy_kind::MSR_EMULATE_RANGE => PolicyIdentifier::ProcFeatureEmulateRange(
            ResourceKind::Msr,
            u32::try_from(key).map_err(|_| CapaError::InvalidValue)?,
            0,
            u32::try_from(sub_key).map_err(|_| CapaError::InvalidValue)?,
            0,
            emulate_word,
        ),
        policy_kind::MSR_DEFAULT => {
            PolicyIdentifier::ProcFeatureDefault(ResourceKind::Msr)
        }
        policy_kind::MSR_RANGE => {
            PolicyIdentifier::ProcFeatureRange(ResourceKind::Msr, u32::try_from(key).map_err(|_| CapaError::InvalidValue)?, 0, u32::try_from(sub_key).map_err(|_| CapaError::InvalidValue)?, 0)
        }
        policy_kind::MSR_EMULATE => {
            PolicyIdentifier::ProcFeatureEmulate(ResourceKind::Msr, u32::try_from(key).map_err(|_| CapaError::InvalidValue)?, 0, u8::try_from(sub_key).map_err(|_| CapaError::InvalidValue)?)
        }
        _ => return Ok(HypercallResult::error(errors::ERR_INVALID)),
    };

    if value == policy_kind::INHERIT
        && matches!(
            id,
            PolicyIdentifier::ProcFeatureDefault(_)
                | PolicyIdentifier::DefaultExitTrap
                | PolicyIdentifier::DefaultInterruptVisibility
        )
    {
        let capability_engine::PolicyScope::Vp(vp) = scope else {
            return Err(CapaError::InvalidValue);
        };
        Capability::clear_vp_policy(
            platform,
            caller,
            child_handle,
            vp,
            id.execution_kind().ok_or(CapaError::InvalidValue)?,
        )?;
    } else {
        Capability::set_policy_scoped(platform, caller, child_handle, scope, id, value)?;
    }
    Ok(HypercallResult::success())
}



// ── P4f: Device assignment hypercall handlers ────────────────────────────── //

/// ASSIGN_DEVICE (0x12): assign a PCI device to a child domain's IOMMU context.
///
/// After this call the device's DMA is isolated to `domain_handle`'s SLPT;
/// addresses the child maps via CARVE/ALIAS appear in the IOMMU page table.
///
/// IN:  RDI = domain_handle (u64)
///      RSI = pci_bdf (u16 — bus[15:8] | device[7:3] | function[2:0])
pub(super) fn do_assign_device(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    domain_handle: u64,
    bdf_arg: u64,
) -> Result<HypercallResult, CapaError> {
    let bdf = bdf_arg as u16;
    Capability::platform_action_on_child(
        platform,
        caller,
        domain_handle,
        |_platform, child_ref| {
            let child_domain_id = child_ref.read().data.id;
            platform.assign_device(bdf, child_domain_id);
            Ok(())
        },
    )?;
    Ok(HypercallResult::success())
}

/// RELEASE_DEVICE (0x1a): return a PCI device to dom0 passthrough.
///
/// IN:  RDI = pci_bdf (u16)
pub(super) fn do_release_device(platform: &ThemisPlatform, bdf_arg: u64) -> Result<HypercallResult, CapaError> {
    let bdf = bdf_arg as u16;
    platform.release_device(bdf);
    Ok(HypercallResult::success())
}
