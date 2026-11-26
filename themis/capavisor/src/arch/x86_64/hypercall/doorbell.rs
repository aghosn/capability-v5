//! x86-64 interrupt injection through a target VP's Posted Interrupt Descriptor.

use capability_engine::{Capability, CapabilityRef, CapaError, Domain, Platform};
use themis_abi::errors;

use crate::arch::x86_64::pid::inject_via_pid;
use crate::hypercall::HypercallResult;
use crate::platform::ThemisPlatform;

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

    let hhdm = platform.hhdm_offset();
    let result = Capability::platform_action_on_child(
        platform,
        caller,
        child_domain_handle,
        |_platform, child_ref| {
            let child_r = child_ref.read();
            // `InterruptVisibility` only governs the automatic real-hardware
            // routing decision; explicit parent-initiated injection is gated
            // by the separate `injectable` bit so a parent can, e.g., mark a
            // vector NotReport (isolate the child from real hardware timing
            // for it) while still retaining sole, explicit control over
            // delivering it.
            if !child_r.data.policy.interrupts.get_policy(vector).injectable {
                return Err(CapaError::PermissionDenied);
            }
            let child_domain_id = child_r.data.id;
            drop(child_r);

            let child_arc = platform
                .domain_arc(child_domain_id)
                .ok_or(CapaError::NotFound)?;
            let pid_phys = {
                let pd = child_arc.lock();
                if vp_id as usize >= pd.arch.vps().len() {
                    return Err(CapaError::InvalidOperation("vp_id out of range".into()));
                }
                pd.arch.vps()[vp_id as usize].peek_pid_phys()
            };
            if pid_phys == 0 {
                // VP has no PID yet (never run, or async mode not initialised).
                return Err(CapaError::NotFound);
            }

            // Write the vector into the VP's Posted-Interrupt Descriptor
            // (PIR), still under the engine's lock so a concurrent revoke
            // of this domain can't free/repurpose the PID's physical page
            // between resolving it and writing it. Use is_remote=false:
            // the PIR bit is picked up by do_switch's PIR drain on the
            // next VMRESUME. Sending a notification IPI here is
            // counter-productive — the IPI is a physical interrupt that
            // causes an immediate EXIT_REASON_EXTERNAL_INTERRUPT on
            // VMRESUME, preventing the child from executing even a single
            // instruction. The thhv retry loop already calls
            // themis_switch() in a tight loop, so the PIR bit is consumed
            // promptly without an IPI.
            unsafe { inject_via_pid(pid_phys, hhdm, vector, false) };
            Ok(())
        },
    );

    match result {
        Ok(()) => HypercallResult::success(),
        Err(e) => HypercallResult::from(e),
    }
}
