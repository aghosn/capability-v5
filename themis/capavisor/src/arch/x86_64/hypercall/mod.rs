//! x86-64 implementation of `ArchHypercall`.
//!
//! Bridges the generic `handle_vmcall` dispatcher (in `hypercall/mod.rs`) to
//! the x86-locked per-opcode handlers re-exported from `hypercall` (`do_add_vp`,
//! `do_switch`, `do_ring_doorbell`), which operate directly on `ActiveVcpu`
//! and use raw VMX intrinsics.

use capability_engine::{CapabilityRef, Domain};

use crate::arch::x86_64::x86_platform::X86Platform;
use crate::hypercall::{self, ArchHypercall, HypercallResult};
use crate::platform::ThemisPlatform;
use crate::vcpu::ActiveVcpu;

impl ArchHypercall for X86Platform {
    fn h_add_vp(
        &mut self,
        vcpu: &mut ActiveVcpu,
        platform: &ThemisPlatform,
        caller: &CapabilityRef<Domain>,
        child_domain_handle: u64,
        comm_cap_handle: u64,
    ) -> HypercallResult {
        hypercall::do_add_vp(
            platform,
            caller,
            child_domain_handle,
            comm_cap_handle,
            vcpu.vmcs_phys(),
        )
    }

    fn h_switch(
        &mut self,
        vcpu: &mut ActiveVcpu,
        platform: &ThemisPlatform,
        caller: &CapabilityRef<Domain>,
        to_domain_handle: u64,
        vp_id: u64,
    ) {
        hypercall::do_switch(platform, caller, to_domain_handle, vp_id, vcpu);
    }

    fn h_ring_doorbell(
        &mut self,
        vcpu: &mut ActiveVcpu,
        platform: &ThemisPlatform,
        caller: &CapabilityRef<Domain>,
        gpa: u64,
        value: u64,
    ) {
        hypercall::do_ring_doorbell(platform, caller, gpa, value, vcpu);
    }
}
