//! x86-64 implementations of `THEMIS_RING_DOORBELL` and `THEMIS_INJECT_INTERRUPT`.
//!
//! - `do_ring_doorbell` enqueues a doorbell notification into the parent's
//!   DomainComm RX ring, then context-switches back to the parent via
//!   `super::switch::forward_child_exit` (lazy-unwind).
//! - `do_inject_interrupt` writes a vector into a target VP's Posted Interrupt
//!   Descriptor (PIR) using `arch::pid::inject_via_pid`.

use capability_engine::{CapabilityRef, Domain, DomainId};
use themis_abi::errors;

use crate::arch::x86_64::pid::inject_via_pid;
use crate::arch::x86_64::vcpu_ext::ActiveVcpuExt;
use crate::hypercall::{try_domain, HypercallResult};
use crate::platform::ThemisPlatform;
use crate::vcpu::ActiveVcpu;

use super::write_reply;

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
        let child_r = child_ref.read();
        let id = child_r.data.id;
        // `InterruptVisibility` only governs the automatic real-hardware
        // routing decision; explicit parent-initiated injection is gated by
        // the separate `injectable` bit so a parent can, e.g., mark a vector
        // NotReport (isolate the child from real hardware timing for it)
        // while still retaining sole, explicit control over delivering it.
        if !child_r.data.policy.interrupts.get_policy(vector).injectable {
            return HypercallResult::error(errors::ERR_NOPERM);
        }
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
