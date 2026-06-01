//! VMX-level active-VP swap primitive.
//!
//! Wraps the VMCLEAR-then-VMPTRLD dance that capavisor performs whenever
//! the monitor loop has to change which virtual processor (VP) is
//! "current" on this core (cross-domain SWITCH hypercall, interrupt
//! forwarding, child-exit forwarding).
//!
//! Pure arch: the capability engine has already validated the transition
//! by the time this is called.  All Run-state book-keeping is the
//! caller's responsibility — this helper only moves bytes.

use capability_engine::DomainId;

use crate::arch::x86_64::apic::current_lapic_id;
use crate::arch::x86_64::pid::PidPage;
use crate::platform::ThemisPlatform;
use crate::vcpu::ActiveVcpu;

/// Switch the monitor loop's `*vcpu` from a src VP to a dst VP.
///
/// Performs, in order:
///   1. `take(dst)` — fetch the dst InactiveVcpu from its slot.
///   2. VMCLEAR src → `put(src)` — deactivate the currently-active src VP
///      and return it to its slot.
///   3. VMPTRLD dst → `ptr::write(vcpu, dst_active)` — install dst as the
///      monitor loop's active VP in place.
///   4. Update `PID.NDST` (Posted-Interrupt Descriptor, Notification
///      Destination field) to this core so cross-core notification
///      Inter-Processor Interrupts (IPIs) target us.
///
/// Caller obligations:
///  - The capability engine must have already transitioned dst → `Running`
///    and src → a non-`Running` state.  This helper does not touch
///    cap-engine state.
///  - All pre-work on the src VP (RIP advance, COMM-page marshalling, …)
///    must be done before calling.  Post-work on the dst VP runs on
///    `*vcpu` directly after this call returns.
///  - For VPs that are posted-interrupt targets, caller must additionally
///    invoke `sync_irte_ndst` after this returns (handles Interrupt
///    Remapping Table Entry (IRTE) routing).
///
/// # Panics
/// Panics if dst's `PlatformDomain` is missing or its `VcpuSlot` is empty:
/// these are bug-equivalent invariant violations after the cap-engine has
/// validated the transition.  VMCLEAR/VMPTRLD failures also panic.
///
/// # Safety
/// `vcpu` must point to a valid, owned, currently-VMPTRLD'd `ActiveVcpu`.
/// On return, `*vcpu` is the dst VP.
pub(crate) unsafe fn swap_active_vp(
    vcpu: &mut ActiveVcpu,
    platform: &ThemisPlatform,
    src: (DomainId, usize),
    dst: (DomainId, usize),
    tag: &'static str,
) {
    let (src_dom, src_vp) = src;
    let (dst_dom, dst_vp) = dst;

    // 1. Take dst from its slot.  Cap-engine guarantees it is populated.
    let dst_inactive = platform.take_vcpu(dst_dom, dst_vp).unwrap_or_else(|| {
        panic!(
            "[{}] dst VcpuSlot empty dom={} vp={} (cap-engine/platform out of sync)",
            tag, dst_dom, dst_vp
        )
    });

    // 2. VMCLEAR src → return to its slot.
    // SAFETY: caller guarantees `vcpu` is a valid owned ActiveVcpu.  We
    // immediately move it out via deactivate(); the matching ptr::write
    // below restores the &mut to a valid VP before returning.
    let src_active = unsafe { core::ptr::read(vcpu as *const ActiveVcpu) };
    let src_inactive = src_active
        .deactivate()
        .unwrap_or_else(|_| panic!("[{}] src deactivate (VMCLEAR) failed", tag));
    platform.return_vcpu(src_dom, src_vp, src_inactive);

    // 3. VMPTRLD dst → install as new *vcpu.
    let dst_active = dst_inactive
        .activate()
        .unwrap_or_else(|_| panic!("[{}] dst activate (VMPTRLD) failed", tag));
    // SAFETY: matching write for the ptr::read above.
    unsafe { core::ptr::write(vcpu, dst_active) };

    // 4. Update PID.NDST so notifications target this core.
    unsafe {
        PidPage::new(vcpu.pid_phys(), platform.hhdm_offset()).set_ndst(current_lapic_id());
    }
}
