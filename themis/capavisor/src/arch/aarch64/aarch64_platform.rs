//! AArch64 (ARMv8-A EL2) implementation of the arch-backend traits.
//!
//! This is a skeleton that validates the trait API compiles for a non-x86 ISA.
//! All methods are `unimplemented!()` stubs.
//!
//! A real implementation would:
//! - Use EL2 exception vectors (VBAR_EL2) for trap entry
//! - Manage guest state via saved SPSR_EL2, ELR_EL2, ESR_EL2, etc.
//! - Use Stage-2 translation tables (VTTBR_EL2) for guest physical memory
//! - Use GICv3 (ICC_* / ICH_*) for interrupt injection via List Registers
//! - Use SMMUv3 for device isolation

use capability_engine::CapaError;

use crate::arch_traits::traits::{
    ArchBoot, ArchCoreSignaling, ArchGuestPhysMap, ArchIommu, ArchVpOps,
};
use crate::arch_traits::types::{
    DeviceId, ExitInfo, HypercallArgs, HypercallResult, MapPermissions, PageSize, SemanticExit,
};

// ── Aarch64Platform ──────────────────────────────────────────────────────── //

/// AArch64 arch backend (skeleton).
///
/// A real implementation would hold pointers to shared hypervisor state
/// (domain table, memory allocator, GIC distributor base, etc.).
pub struct Aarch64Platform {
    // Placeholder — will hold shared state pointer like X86Platform.
    _private: (),
}

/// Opaque VP handle for AArch64.
///
/// On ARM, this would contain saved EL1/EL0 register state, VTTBR_EL2,
/// HCR_EL2 config, GIC List Register state, and the virtual timer state.
pub struct ArmVpState {
    _private: (),
}

// ── ArchVpOps ────────────────────────────────────────────────────────────── //

impl ArchVpOps for Aarch64Platform {
    type VpHandle = ArmVpState;

    // ARM IRQ exception class (ESR_EL2.EC is not directly comparable, but
    // the external interrupt exit is signaled by the GIC, not ESR).
    // Use a sentinel value; real impl would define a proper exit reason space.
    const EXTERNAL_INTERRUPT_EXIT_REASON: u32 = 0x100;

    fn run(&mut self, _vp: &mut Self::VpHandle) -> SemanticExit {
        // Real impl: ERET to EL1, trap back to EL2, decode ESR_EL2.EC
        // into SemanticExit (HVC → Hypercall, IRQ → ExternalInterrupt,
        // Data Abort → Stage2Fault as PolicyDriven, etc.)
        unimplemented!("aarch64: run")
    }

    fn handle_local(&mut self, _vp: &mut Self::VpHandle, _reason: u32, _info: &ExitInfo) {
        unimplemented!("aarch64: handle_local")
    }

    fn get_hypercall_args(&self, _vp: &Self::VpHandle) -> HypercallArgs {
        // ARM SMCCC: X0=function ID, X1–X5=args.
        // Map to HypercallArgs { opcode: X0, arg0: X1, ... arg4: X5 }.
        unimplemented!("aarch64: get_hypercall_args")
    }

    fn set_hypercall_result(&mut self, _vp: &mut Self::VpHandle, _result: HypercallResult) {
        // ARM SMCCC: X0=status, X1–X3=return values.
        unimplemented!("aarch64: set_hypercall_result")
    }

    fn inject_interrupt(
        &mut self,
        _vp: &mut Self::VpHandle,
        _vector: u32,
    ) -> Result<(), CapaError> {
        // GICv3: write to ICH_LR<n>_EL2 (List Register) to inject a
        // virtual interrupt into the guest.
        unimplemented!("aarch64: inject_interrupt")
    }

    fn dispatch_hypercall(&mut self, _vp: &mut Self::VpHandle) {
        unimplemented!("aarch64: dispatch_hypercall")
    }

    fn forward_exit(&mut self, _vp: &mut Self::VpHandle, _reason: u32) {
        unimplemented!("aarch64: forward_exit")
    }

    fn forward_interrupt(&mut self, _vp: &mut Self::VpHandle, _vector: u32) {
        unimplemented!("aarch64: forward_interrupt")
    }

    fn reset_timer(&mut self, _vp: &mut Self::VpHandle) {
        // ARM EL2 physical timer: write CNTHP_TVAL_EL2 or CNTHP_CTL_EL2.
        unimplemented!("aarch64: reset_timer")
    }
}

// ── ArchGuestPhysMap ─────────────────────────────────────────────────────── //

/// On AArch64, the map handle would reference the Stage-2 translation table
/// root (VTTBR_EL2) and a page allocator for table pages.
impl ArchGuestPhysMap for Aarch64Platform {
    type MapHandle = u64; // placeholder — would be a Stage-2 root descriptor

    fn create_map(&mut self) -> Result<Self::MapHandle, CapaError> {
        unimplemented!("aarch64: create_map (Stage-2 table)")
    }

    fn destroy_map(&mut self, _map: &mut Self::MapHandle) {
        unimplemented!("aarch64: destroy_map")
    }

    fn map(
        &mut self,
        _map: &mut Self::MapHandle,
        _gpa: u64,
        _hpa: u64,
        _size: PageSize,
        _perms: MapPermissions,
    ) {
        // Write Stage-2 translation table entries.
        // PageSize::Page4K → 4K granule L3 block
        // PageSize::Page2M → 2M L2 block (if 4K granule)
        // PageSize::Page1G → 1G L1 block
        unimplemented!("aarch64: map (Stage-2)")
    }

    fn unmap(&mut self, _map: &mut Self::MapHandle, _gpa: u64, _size: PageSize) {
        unimplemented!("aarch64: unmap")
    }

    fn flush(&mut self, _map: &Self::MapHandle) {
        // TLBI VMALLS12E1IS — invalidate all Stage-1 and Stage-2 TLB entries
        // for the current VMID.
        unimplemented!("aarch64: flush (TLBI)")
    }
}

// ── ArchCoreSignaling ────────────────────────────────────────────────────── //

impl ArchCoreSignaling for Aarch64Platform {
    fn send_ipi(&self, _target_core: u32) {
        // GICv3: write ICC_SGI1R_EL1 to send a Software Generated Interrupt
        // to the target core's redistributor.
        unimplemented!("aarch64: send_ipi (GIC SGI)")
    }

    fn broadcast_flush(&self, _domain_id: u64) {
        // Send IPI to all cores running this domain, triggering TLBI on each.
        unimplemented!("aarch64: broadcast_flush")
    }

    fn logical_core_id(&self) -> u32 {
        // Read MPIDR_EL1, extract Aff0 (or use a software-assigned ID).
        unimplemented!("aarch64: logical_core_id (MPIDR)")
    }

    fn max_cores(&self) -> u32 {
        unimplemented!("aarch64: max_cores")
    }
}

// ── ArchIommu ────────────────────────────────────────────────────────────── //

/// SMMUv3 device isolation (optional — not all ARM platforms have SMMU).
impl ArchIommu for Aarch64Platform {
    fn assign_device(&mut self, _domain_id: u64, _device: DeviceId) -> Result<(), CapaError> {
        // SMMUv3: write Stream Table Entry for the device's StreamID.
        unimplemented!("aarch64: assign_device (SMMUv3)")
    }

    fn release_device(&mut self, _device: DeviceId) {
        unimplemented!("aarch64: release_device")
    }

    fn map_dma(&mut self, _domain_id: u64, _iova: u64, _hpa: u64, _perms: MapPermissions) {
        unimplemented!("aarch64: map_dma (SMMUv3)")
    }

    fn unmap_dma(&mut self, _domain_id: u64, _iova: u64) {
        unimplemented!("aarch64: unmap_dma")
    }

    fn flush_dma(&mut self, _domain_id: u64) {
        // SMMUv3: issue TLBI via command queue.
        unimplemented!("aarch64: flush_dma (SMMUv3 TLBI)")
    }
}

// ── ArchBoot ─────────────────────────────────────────────────────────────── //

/// AArch64 boot info — from Limine (aarch64 variant) or device tree.
pub struct Aarch64BootInfo {
    pub hhdm_offset: u64,
    pub num_cores: usize,
}

impl ArchBoot for Aarch64Platform {
    type BootInfo = Aarch64BootInfo;

    fn early_boot() -> Self::BootInfo {
        // Parse Limine memory map (aarch64) or device tree.
        // Discover GICD/GICR base addresses, SMMU, UART.
        unimplemented!("aarch64: early_boot")
    }

    fn init_bsp(_info: &Self::BootInfo) {
        // EL2 setup: configure HCR_EL2 (VM bit, trap controls),
        // set VBAR_EL2 for exception vectors, enable Stage-2 MMU,
        // initialize GICv3 (ICC/ICH system registers).
        unimplemented!("aarch64: init_bsp (EL2 setup)")
    }

    fn init_ap(_cpu: u32, _info: &Self::BootInfo) {
        // Secondary core: same EL2 setup, PSCI-based wakeup.
        unimplemented!("aarch64: init_ap")
    }

    fn enable_virtualization() {
        // Set HCR_EL2.VM=1 to enable Stage-2 translation.
        unimplemented!("aarch64: enable_virtualization (HCR_EL2)")
    }
}
