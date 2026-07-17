//! Capability-engine hypercalls.
//!
//! Tree-shape operations:        CARVE / ALIAS / SEND / ACCEPT / REJECT
//! Channel transfer:             GET_CHAN / SEND_CHAN / ACCEPT_CHAN
//! Domain lifecycle:             CREATE / SEAL / REVOKE_MEM / REVOKE_DOMAIN
//! Self-mapping:                 MAP_SELF
//! Policy:                       SET_POLICY (all PolicyIdentifier variants)
//! Device assignment:            ASSIGN_DEVICE / RELEASE_DEVICE
//!
//! Most handlers are thin wrappers around `capability_engine::Capability::*`
//! via the `execute_or_return!` macro. Only `do_revoke_domain`, `do_assign_device`
//! and `do_release_device` touch arch-specific state (IOMMU IRTEs / device
//! assignment) through `crate::arch::x86_64::iommu_ir`.

use capability_engine::{
    Access, Attributes, Capability, CapabilityRef, Domain, DomainPolicy, MonitorAPI,
    PolicyIdentifier, ResourceKind, Rights,
};
use themis_abi::errors;

use super::{map_error, try_capa, HypercallResult};
use crate::platform::ThemisPlatform;
use crate::serial_println;

// ── Individual opcode handlers ───────────────────────────────────────────── //

/// CARVE (0x01): carve exclusive sub-region from parent memory capability.
pub(super) fn do_carve(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    parent_handle: u64,
    start: u64,
    size: u64,
    rights_bits: u64,
) -> HypercallResult {
    let access = Access::new(start, size, Rights::from_bits(rights_bits as u8));
    let (handle, sub, _batch) = try_capa!(Capability::carve(platform, caller, parent_handle, access));
    HypercallResult::success_2(handle, sub)
}

/// ALIAS (0x02): alias shared sub-region from parent memory capability.
pub(super) fn do_alias(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    parent_handle: u64,
    start: u64,
    size: u64,
    rights_bits: u64,
) -> HypercallResult {
    let access = Access::new(start, size, Rights::from_bits(rights_bits as u8));
    let (handle, sub, _batch) = try_capa!(Capability::alias(platform, caller, parent_handle, access));
    HypercallResult::success_2(handle, sub)
}

/// SEND (0x03): send memory capability to a receiver domain.
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
) -> HypercallResult {
    let attrs = Attributes::from_bits(attrs_bits as u8);
    let gpa_hint = if child_gpa != u64::MAX {
        Some(child_gpa)
    } else {
        None
    };
    let _batch = try_capa!(Capability::send_at(
        platform,
        caller,
        cap_handle,
        receiver_handle,
        attrs,
        gpa_hint
    ));
    HypercallResult::success()
}

/// ACCEPT (0x04): accept a pending memory capability.
pub(super) fn do_accept(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    pending_id: u64,
) -> HypercallResult {
    let (handle, _batch) = try_capa!(Capability::accept(platform, caller, pending_id));
    HypercallResult::success_1(handle)
}

/// REJECT (0x05): reject a pending memory capability.
pub(super) fn do_reject(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    pending_id: u64,
) -> HypercallResult {
    let _batch = try_capa!(Capability::reject(platform, caller, pending_id));
    HypercallResult::success()
}

// ── Channel (domain capability transfer) handlers ────────────────────────── //

/// GET_CHAN (0x0B): get a channel capability to a child domain.
/// If domain_handle == 0, creates a self-channel (for receiving from children).
pub(super) fn do_get_chan(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    domain_handle: u64,
) -> HypercallResult {
    let (handle, _batch) = if domain_handle == 0 {
        try_capa!(Capability::get_chan_self(platform, caller))
    } else {
        try_capa!(Capability::get_chan(platform, caller, domain_handle))
    };
    HypercallResult::success_1(handle)
}

/// SEND_CHAN (0x20): send a channel capability to a receiver domain.
pub(super) fn do_send_chan(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    chan_handle: u64,
    receiver_handle: u64,
    attrs: u64,
) -> HypercallResult {
    let _batch = try_capa!(Capability::send_channel(
        platform,
        caller,
        chan_handle,
        receiver_handle,
        Attributes::from_bits(attrs as u8),
    ));
    HypercallResult::success()
}

/// ACCEPT_CHAN (0x21): accept a pending channel capability.
pub(super) fn do_accept_chan(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    pending_id: u64,
) -> HypercallResult {
    let (handle, _batch) = try_capa!(Capability::accept_channel(platform, caller, pending_id));
    HypercallResult::success_1(handle)
}

/// CREATE_DOMAIN (0x06): create a new child domain.
pub(super) fn do_create_domain(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    cores_bitmask: u64,
    api_flags: u64,
) -> HypercallResult {
    // Intersect the requested cores/api with what the caller actually has,
    // so that !0 ("give me everything") works correctly.
    let parent_cores = caller.read().data.policy.cores;
    let parent_api = caller.read().data.policy.api;
    let api = MonitorAPI::from_bits(api_flags as u16 & parent_api.bits());
    let policy = DomainPolicy::new_restricted(cores_bitmask & parent_cores, api);
    let (handle, _batch) = try_capa!(Capability::create(platform, caller, policy));
    HypercallResult::success_1(handle)
}

/// SEAL (0x07): seal a domain (Unsealed → Sealed).
pub(super) fn do_seal(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    domain_handle: u64,
) -> HypercallResult {
    let _batch = try_capa!(Capability::seal(platform, caller, domain_handle));

    // Resolve the child domain for post-seal setup.
    let child_cap = caller
        .read()
        .data
        .get_domain_capability(domain_handle)
        .and_then(|weak| weak.upgrade());

    if let Some(child) = &child_cap {
        // Finalize DomainComm if pages were registered pre-seal.
        let child_id = child.read().data.id;
        if let Some(header_hpa) = platform.finalize_domcomm(child_id) {
            serial_println!(
                "[seal] DomainComm initialized for domain {:?} (header @ {:#x})",
                child_id,
                header_hpa,
            );
        }
    }

    // intr-p3g: program IRTEs for the newly-sealed child domain.
    if let Some(child) = &child_cap {
        platform.program_domain_irtes(child);
    }
    HypercallResult::success()
}

/// REVOKE_MEM (0x08): revoke a child of a memory capability.
pub(super) fn do_revoke_mem(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    parent_handle: u64,
    child_sub: u64,
) -> HypercallResult {
    let _batch = try_capa!(Capability::revoke(platform, caller, parent_handle, child_sub));
    HypercallResult::success()
}

/// REVOKE_DOMAIN (0x09): revoke an entire child domain.
pub(super) fn do_revoke_domain(
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

    let _batch = try_capa!(Capability::revoke_domain(platform, caller, child_handle));
    // intr-p3g: clear all IRTEs that were programmed for this domain.
    if let Some(id) = child_domain_id {
        platform.invalidate_domain_irtes(id);
    }
    HypercallResult::success()
}


/// MAP_SELF (0x1f): remap a memory capability at a new GPA within the caller's space.
///
/// IN:  RDI = cap_handle, RSI = new_gpa
pub(super) fn do_map_self(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    cap_handle: u64,
    new_gpa: u64,
) -> HypercallResult {
    let _batch = try_capa!(Capability::map_self(platform, caller, cap_handle, new_gpa));
    HypercallResult::success()
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
) -> HypercallResult {
    use themis_abi::policy_kind;

    let id = match kind {
        policy_kind::CORES => PolicyIdentifier::Cores,
        policy_kind::API_MONITOR => PolicyIdentifier::ApiMonitor,
        policy_kind::DEFAULT_INTR_VISIBILITY => PolicyIdentifier::DefaultInterruptVisibility,
        policy_kind::VECTOR_VISIBILITY => PolicyIdentifier::VectorVisibility(key as u8),
        policy_kind::VECTOR_REG_READ_SET => {
            PolicyIdentifier::VectorRegReadSet(key as u8, sub_key as u8)
        }
        policy_kind::VECTOR_REG_WRITE_SET => {
            PolicyIdentifier::VectorRegWriteSet(key as u8, sub_key as u8)
        }
        policy_kind::DEFAULT_EXIT_TRAP => PolicyIdentifier::DefaultExitTrap,
        policy_kind::EXIT_REASON_TRAP => PolicyIdentifier::ExitReasonTrap(key as u32),
        policy_kind::EXIT_REASON_REG_READ_SET => {
            PolicyIdentifier::ExitReasonRegReadSet(key as u32, sub_key as u8)
        }
        policy_kind::EXIT_REASON_REG_WRITE_SET => {
            PolicyIdentifier::ExitReasonRegWriteSet(key as u32, sub_key as u8)
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
                ResourceKind::Cpuid, leaf, subleaf, sub_key as u8,
            )
        }
        policy_kind::MSR_DEFAULT => {
            PolicyIdentifier::ProcFeatureDefault(ResourceKind::Msr)
        }
        policy_kind::MSR_RANGE => {
            PolicyIdentifier::ProcFeatureRange(ResourceKind::Msr, key as u32, 0, sub_key as u32, 0)
        }
        policy_kind::MSR_EMULATE => {
            PolicyIdentifier::ProcFeatureEmulate(ResourceKind::Msr, key as u32, 0, sub_key as u8)
        }
        _ => return HypercallResult::error(errors::ERR_INVALID),
    };

    let _batch = try_capa!(Capability::set_policy(platform, caller, child_handle, id, value));
    HypercallResult::success()
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
) -> HypercallResult {
    let bdf = bdf_arg as u16;
    // Resolve domain_handle → domain_id via the caller's capability tree.
    let child_domain_id = {
        let cap = caller.read();
        let child_weak = cap.data.get_domain_capability(domain_handle);
        match child_weak.and_then(|w| w.upgrade()) {
            Some(child) => child.read().data.id,
            None => return HypercallResult::error(errors::ERR_INVALID),
        }
    };
    platform.assign_device(bdf, child_domain_id);
    HypercallResult::success()
}

/// RELEASE_DEVICE (0x1a): return a PCI device to dom0 passthrough.
///
/// IN:  RDI = pci_bdf (u16)
pub(super) fn do_release_device(platform: &ThemisPlatform, bdf_arg: u64) -> HypercallResult {
    let bdf = bdf_arg as u16;
    platform.release_device(bdf);
    HypercallResult::success()
}

