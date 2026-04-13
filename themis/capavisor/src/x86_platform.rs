//! x86-64 (Intel VT-x) implementation of the arch-backend traits.
//!
//! `X86Platform` wraps the existing capavisor code (`ThemisPlatform`, `vmcs.rs`,
//! `vmexit.rs`, etc.) behind the arch-backend trait interface.  This file is
//! the seam between platform-agnostic policy code and x86-specific mechanism.
//!
//! Phase A: trait impls are defined and compile but are not yet wired into the
//! main code path.  The existing `monitor_loop` / `handle_vmexit` / `handle_vmcall`
//! continue to drive execution.  Phase A7 will genericize `ThemisPlatform` to
//! call through these traits.

extern crate alloc;

use capability_engine::CapaError;
use x86::vmx::vmcs;

use crate::arch_traits::traits::{
    ArchBoot, ArchCoreSignaling, ArchGuestPhysMap, ArchIommu, ArchVpOps,
};
use crate::arch_traits::types::{
    ArchExit, DeviceId, HypercallArgs, HypercallResult, MapPermissions, PageSize,
};
use crate::platform::ThemisPlatform;
use crate::vcpu::{ActiveVcpu, Reg};
use crate::vmexit;

// ── X86Platform ──────────────────────────────────────────────────────────── //

/// x86-64 arch backend.  Holds a pointer to the global `ThemisPlatform`
/// for access to domain state, META allocator, EPT, IOMMU, and IPI.
///
/// # Safety
/// The `platform` pointer must remain valid for the lifetime of X86Platform.
/// This is guaranteed because ThemisPlatform is a heap-allocated singleton
/// that lives for the entire hypervisor lifetime.
pub struct X86Platform {
    platform: *const ThemisPlatform,
}

impl X86Platform {
    /// Wrap an existing ThemisPlatform.
    ///
    /// # Safety
    /// Caller must ensure `platform` outlives the returned X86Platform.
    pub unsafe fn new(platform: *const ThemisPlatform) -> Self {
        Self { platform }
    }

    fn platform(&self) -> &ThemisPlatform {
        unsafe { &*self.platform }
    }
}

// SAFETY: X86Platform is a thin wrapper around a shared reference.
// ThemisPlatform is already Sync (all fields use atomics/locks).
unsafe impl Send for X86Platform {}
unsafe impl Sync for X86Platform {}

// ── ArchVpOps ────────────────────────────────────────────────────────────── //

/// On x86, the VP handle is the `ActiveVcpu` — the VMCS is loaded on the
/// current core and ready for vmread/vmwrite/run().
impl ArchVpOps for X86Platform {
    type VpHandle = ActiveVcpu;

    fn create_vp(&mut self, _domain_id: u64, _cpu: u32) -> Result<Self::VpHandle, CapaError> {
        // VP creation involves META allocation (VMCS, VAPIC, PID pages),
        // VMCS field setup (vmcs::setup_vmcs_for_vp), and VMPTRLD.
        // Currently done across domain.rs + vmcs.rs + boot.rs.
        // Will be consolidated here in Phase A7.
        unimplemented!("create_vp: wire up in Phase A7")
    }

    fn destroy_vp(&mut self, _vp: &mut Self::VpHandle) {
        // Deactivate (VMCLEAR) and free META pages.
        // Currently handled by PlatformDomain cleanup in RevokeDomain.
        unimplemented!("destroy_vp: wire up in Phase A7")
    }

    fn enter_guest(&mut self, vp: &mut Self::VpHandle) -> ArchExit {
        let exit_reason = unsafe { vp.run() };
        match exit_reason {
            Ok(reason) => vmexit::classify_exit(reason, vp),
            Err(_) => ArchExit::Shutdown,
        }
    }

    fn advance_ip(&mut self, vp: &mut Self::VpHandle, _len: u32) {
        // Use the hardware-reported instruction length from the VMCS,
        // which is more reliable than the caller-provided len.
        let len = vp.get(vmcs::ro::VMEXIT_INSTRUCTION_LEN);
        let rip = vp.get(vmcs::guest::RIP);
        vp.set(vmcs::guest::RIP, rip + len);
    }

    fn get_hypercall_args(&self, vp: &Self::VpHandle) -> HypercallArgs {
        HypercallArgs {
            opcode: vp.reg(Reg::Rax),
            arg0: vp.reg(Reg::Rdi),
            arg1: vp.reg(Reg::Rsi),
            arg2: vp.reg(Reg::Rdx),
            arg3: vp.reg(Reg::Rcx),
            arg4: vp.reg(Reg::R8),
        }
    }

    fn set_hypercall_result(&mut self, vp: &mut Self::VpHandle, result: HypercallResult) {
        vp.set_reg(Reg::Rax, result.status);
        vp.set_reg(Reg::Rdi, result.val0);
        vp.set_reg(Reg::Rsi, result.val1);
        vp.set_reg(Reg::Rdx, result.val2);
    }

    fn inject_interrupt(&mut self, vp: &mut Self::VpHandle, vector: u32) -> Result<(), CapaError> {
        // Use the VMENTRY_INTERRUPTION_INFO_FIELD for direct injection
        // when the VP is about to be resumed.
        // Type = 0 (external interrupt), valid bit = 1<<31.
        let info = (vector as u64) | (1u64 << 31);
        vp.set(vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD, info);
        Ok(())
    }
}

// ── ArchGuestPhysMap ─────────────────────────────────────────────────────── //

/// On x86, the map handle is a domain ID.  EPT state is stored in
/// `PlatformDomain` and looked up via `ThemisPlatform::domains`.
impl ArchGuestPhysMap for X86Platform {
    type MapHandle = u64; // domain_id

    fn create_map(&mut self) -> Result<Self::MapHandle, CapaError> {
        // EPT roots are created lazily via PlatformDomain::ensure_ept()
        // when the first ChangeRights update is applied.
        // The "create" is implicit in register_domain().
        // Return a placeholder; real wiring in Phase A7.
        unimplemented!("create_map: wire up in Phase A7")
    }

    fn destroy_map(&mut self, _map: &mut Self::MapHandle) {
        // EPT teardown currently happens in RevokeDomain handler
        // (platform.rs apply_update → ept.free_all).
        unimplemented!("destroy_map: wire up in Phase A7")
    }

    fn map(
        &mut self,
        domain_id: &mut Self::MapHandle,
        gpa: u64,
        hpa: u64,
        _size: PageSize,
        _perms: MapPermissions,
    ) {
        // Delegates to the existing ChangeRights path in apply_update:
        //   PlatformDomain::ensure_ept()
        //   map_range_typed(ept, meta, gpa, hpa, size, flags, uc_ranges)
        let _ = (domain_id, gpa, hpa);
        unimplemented!("map: wire up in Phase A7")
    }

    fn unmap(&mut self, domain_id: &mut Self::MapHandle, gpa: u64, _size: PageSize) {
        // Delegates to: ept.unmap_range(meta, gpa, size)
        let _ = (domain_id, gpa);
        unimplemented!("unmap: wire up in Phase A7")
    }

    fn flush(&mut self, domain_id: &Self::MapHandle) {
        self.platform().invept_for_domain(*domain_id);
    }
}

// ── ArchCoreSignaling ────────────────────────────────────────────────────── //

impl ArchCoreSignaling for X86Platform {
    fn send_ipi(&self, target_core: u32) {
        // Delegates to ThemisPlatform's Platform::send_ipi (capability engine trait).
        // That method pushes CoreUpdate::TlbShootdown and sends INIT IPI
        // via xAPIC ICR.
        use capability_engine::Platform;
        self.platform().send_ipi(target_core as capability_engine::CoreId);
    }

    fn broadcast_flush(&self, domain_id: u64) {
        self.platform().invept_for_domain(domain_id);
    }

    fn logical_core_id(&self) -> u32 {
        self.platform()
            .current_core_id()
            .unwrap_or(0) as u32
    }

    fn max_cores(&self) -> u32 {
        self.platform().num_cores() as u32
    }
}

// ── ArchIommu ────────────────────────────────────────────────────────────── //

impl ArchIommu for X86Platform {
    fn assign_device(
        &mut self,
        domain_id: u64,
        device: DeviceId,
    ) -> Result<(), CapaError> {
        let bdf = ((device.bus as u16) << 8)
            | ((device.device as u16) << 3)
            | (device.function as u16);
        self.platform().assign_device(bdf, domain_id);
        Ok(())
    }

    fn release_device(&mut self, device: DeviceId) {
        let bdf = ((device.bus as u16) << 8)
            | ((device.device as u16) << 3)
            | (device.function as u16);
        self.platform().release_device(bdf);
    }

    fn map_dma(
        &mut self,
        _domain_id: u64,
        _iova: u64,
        _hpa: u64,
        _perms: MapPermissions,
    ) {
        // SLPT mapping is currently done inline in apply_update ChangeRights
        // handler (mirrors EPT mapping into iommu_pt).
        // Will be separated in Phase A7.
        unimplemented!("map_dma: wire up in Phase A7")
    }

    fn unmap_dma(&mut self, _domain_id: u64, _iova: u64) {
        unimplemented!("unmap_dma: wire up in Phase A7")
    }

    fn flush_dma(&mut self, _domain_id: u64) {
        // VT-d IOTLB flush — currently implicit in context table updates.
        unimplemented!("flush_dma: wire up in Phase A7")
    }
}

// ── ArchBootInfo ─────────────────────────────────────────────────────────── //

/// Boot info collected from Limine + ACPI + PCI discovery.
/// Currently assembled in boot.rs::init_themis().
pub struct X86BootInfo {
    pub hhdm_offset: u64,
    pub num_cores: usize,
}

impl ArchBoot for X86Platform {
    type BootInfo = X86BootInfo;

    fn early_boot() -> Self::BootInfo {
        // Currently done in boot.rs: parse Limine memory map, HHDM offset,
        // RSDP, ACPI tables.
        unimplemented!("early_boot: wire up in Phase A7")
    }

    fn init_bsp(_info: &Self::BootInfo) {
        // Currently done in main.rs::_start + boot.rs::init_themis:
        // GDT init, VMXON, per-core VMXON region allocation.
        unimplemented!("init_bsp: wire up in Phase A7")
    }

    fn init_ap(_cpu: u32, _info: &Self::BootInfo) {
        // Currently done in main.rs::ap_entry:
        // GDT load for AP, VMXON for AP.
        unimplemented!("init_ap: wire up in Phase A7")
    }

    fn enable_virtualization() {
        // VMX root mode enable — currently done in boot.rs via vmxon_phys.
        unimplemented!("enable_virtualization: wire up in Phase A7")
    }
}
