//! ThemIC doorbell + interrupt-injection hypercalls.
//!
//! - REGISTER_DOORBELL / UNREGISTER_DOORBELL (0x15 / 0x16)
//! - RING_DOORBELL (0x17, may synthesize a doorbell EXIT)
//! - SET_THEMIC_VECTOR (0x18)
//! - INJECT_INTERRUPT (0x1B): posts a vector into a child VP's Posted-
//!   Interrupt Descriptor (PID) via `arch::pid::inject_via_pid`.

use capability_engine::{CapabilityRef, Domain, DomainId};
use themis_abi::errors;

use super::{try_domain, write_reply, HypercallResult};
use crate::arch::x86_64::pid::inject_via_pid;
use crate::arch::x86_64::vcpu_ext::ActiveVcpuExt;
use crate::platform::ThemisPlatform;
use crate::vcpu::ActiveVcpu;

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

    let child_domain_id: DomainId = {
        let r = caller.read();
        let child_weak = match r.data.get_domain_capability(child_handle) {
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

    let child_arc = try_domain!(platform, child_domain_id);
    let mut pd = child_arc.lock();

    if pd.doorbells.len() >= THEMIC_MAX_DOORBELLS {
        return HypercallResult::error(errors::ERR_NOMEM);
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

    serial_rtdbg!(
        "[REG_DB] id={} gpa={:#x} sz={} flags={:#x}",
        doorbell_id,
        gpa,
        size,
        flags
    );

    HypercallResult::success_1(doorbell_id as u64)
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
    let child_domain_id: DomainId = {
        let r = caller.read();
        let child_weak = match r.data.get_domain_capability(child_handle) {
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

    let child_arc = try_domain!(platform, child_domain_id);
    let mut pd = child_arc.lock();

    let before = pd.doorbells.len();
    pd.doorbells.retain(|e| e.doorbell_id != doorbell_id);
    if pd.doorbells.len() == before {
        return HypercallResult::error(errors::ERR_NOTFOUND);
    }

    HypercallResult::success()
}

/// RING_DOORBELL (0x23): called by a child domain to ring a doorbell.
/// The capavisor matches the GPA against the caller's doorbell list,
/// enqueues a notification to the parent domain's DomainComm RX ring,
/// then context-switches back to the parent so thhv can drain the ring
/// and signal the matching ioeventfd.
///
/// RING_DOORBELL (0x17): synthesize a doorbell exit back to the parent.
///
/// The capavisor matches the GPA against the caller's doorbell list,
/// enqueues a notification to the parent domain's DomainComm RX ring,
/// then context-switches back to the parent so thhv can drain the ring
/// and signal the matching ioeventfd.
///
/// arg0 = doorbell GPA, arg1 = value
///
/// On success the active VP has been swapped to the parent; `handle_vmcall`
/// must NOT write a reply or advance the (now-parent) VP's RIP. On early
/// error this function writes the error reply to the caller (still active)
/// and advances its RIP itself.
pub(super) fn do_ring_doorbell(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    gpa: u64,
    value: u64,
    vcpu: &mut ActiveVcpu,
) {
    use crate::platform::THEMIC_DOORBELL_FLAG_ANY_VALUE;
    use themis_abi::domcomm;
    use themis_abi::synthetic_exits::THEMIS_EXIT_DOORBELL;

    let caller_id = caller.read().data.id;
    let Some(caller_arc) = platform.domain_arc(caller_id) else {
        write_reply(vcpu, HypercallResult::error(errors::ERR_NOTFOUND));
        vcpu.next_rip();
        return;
    };

    let (doorbell_id, parent_id) = {
        let pd = caller_arc.lock();
        let entry = pd.doorbells.iter().find(|e| {
            if e.gpa != gpa {
                return false;
            }
            let any_value = e.flags & THEMIC_DOORBELL_FLAG_ANY_VALUE != 0;
            any_value || e.datamatch == value
        });
        let db_id = match entry {
            Some(e) => e.doorbell_id,
            None => {
                drop(pd);
                write_reply(vcpu, HypercallResult::error(errors::ERR_NOTFOUND));
                vcpu.next_rip();
                return;
            }
        };
        let parent = match pd.parent {
            Some(p) => p,
            None => {
                drop(pd);
                write_reply(vcpu, HypercallResult::error(errors::ERR_NOTFOUND));
                vcpu.next_rip();
                return;
            }
        };
        (db_id, parent)
    };

    let Some(parent_arc) = platform.domain_arc(parent_id) else {
        write_reply(vcpu, HypercallResult::error(errors::ERR_NOTFOUND));
        vcpu.next_rip();
        return;
    };
    let mut parent_pd = parent_arc.lock();

    let notify = domcomm::DoorbellNotify {
        doorbell_id,
        reserved: 0,
        gpa,
        value,
        size: 0,
        reserved2: 0,
    };
    parent_pd.enqueue_rx(&notify);
    drop(parent_pd);

    // Context-switch back to parent so thhv can drain the DomainComm RX ring.
    // forward_child_exit advances child RIP (non-EPT path) and swaps VMCS.
    super::switch::forward_child_exit(vcpu, THEMIS_EXIT_DOORBELL);
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

/// INJECT_INTERRUPT (0x1B): inject a virtual interrupt into a stopped child VP.
///
/// The caller (parent domain) specifies the child domain, VP index, and
/// interrupt vector.  The capavisor writes to the VP's Posted Interrupt
/// Descriptor (PIR) so the interrupt is delivered on the next VMRESUME.
///
/// The VP must not currently be running (i.e. the caller is not inside
/// a SWITCH for this VP).  Injecting into a running VP is a no-op today
/// (future work: posted-interrupt VMCALL while VP is live on a remote core).
///
/// IN:  arg0 = child_domain_handle, arg1 = vp_id, arg2 = vector (0–255)
#[cfg(target_arch = "x86_64")]
pub(super) fn do_inject_interrupt(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    child_domain_handle: u64,
    vp_id: u32,
    vector: u8,
) -> HypercallResult {
    serial_rtdbg!(
        "[INJECT] vec={} vp={} handle={:#x}",
        vector,
        vp_id,
        child_domain_handle
    );
    if vector == 0 {
        return HypercallResult::error(errors::ERR_INVALID);
    }

    // Validate that the caller owns the child domain capability.
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

    let child_arc = try_domain!(platform, child_domain_id);

    let pid_phys = {
        let pd = child_arc.lock();
        if vp_id as usize >= pd.arch.vps().len() {
            return HypercallResult::error(errors::ERR_INVALID);
        }
        pd.arch.vps()[vp_id as usize].peek_pid_phys()
    };

    if pid_phys == 0 {
        // VP has no PID yet (never run, or async mode not initialised).
        return HypercallResult::error(errors::ERR_NOTFOUND);
    }

    let hhdm = platform.hhdm_offset();

    // Write the vector into the VP's Posted-Interrupt Descriptor (PIR).
    // Use is_remote=false: the PIR bit is picked up by do_switch's PIR
    // drain on the next VMRESUME.  Sending a notification IPI here is
    // counter-productive — the IPI is a physical interrupt that causes
    // an immediate EXIT_REASON_EXTERNAL_INTERRUPT on VMRESUME, preventing
    // the child from executing even a single instruction.  The thhv retry
    // loop already calls themis_switch() in a tight loop, so the PIR bit
    // is consumed promptly without an IPI.
    unsafe { inject_via_pid(pid_phys, hhdm, vector, false) };

    HypercallResult::success()
}
