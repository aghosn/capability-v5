//! Architecture-backend traits for the capavisor.
//!
//! These traits define the boundary between platform-agnostic policy logic
//! and ISA-specific mechanism. Each trait covers one concern and is kept
//! small to avoid forcing one ISA's shape onto another.
//!
//! Implementations live under `crate::arch::<isa>/`.
//!
//! Many traits and methods are not yet called — they define the API boundary
//! for future arch backends (e.g., ARM AArch64).
#![allow(dead_code)]

use capability_engine::CapaError;

use super::types::{
    DeviceId, ExitInfo, HypercallArgs, HypercallResult, MapPermissions, PageSize, SemanticExit,
};

// ── VP lifecycle and guest entry/exit ────────────────────────────────────── //

/// Virtual processor operations: create, destroy, enter guest, inject interrupts.
///
/// This trait covers both low-level VP state access (for `apply_update`) and
/// monitor-level operations (for the generic run loop). The monitor loop uses
/// the `Vp<A>` wrapper which delegates to these methods.
pub trait ArchVpOps {
    /// Opaque handle to a VP's arch-specific state (VMCS on x86, saved regs on ARM).
    type VpHandle;

    /// Arch-specific exit reason code for external interrupts.
    /// Used by the generic monitor to look up exit policy for interrupt exits.
    /// On x86 this is VMX exit reason 1; on ARM it would be the ESR_EL2 EC value.
    const EXTERNAL_INTERRUPT_EXIT_REASON: u32;

    /// Enter the guest, wait for an exit, and fully decode it into a
    /// [`SemanticExit`]. Arch-internal exits (x86 XSETBV, INIT signal,
    /// interrupt-window drain) are handled inside this call and return
    /// `SemanticExit::ArchHandled`.
    fn run(&mut self, vp: &mut Self::VpHandle) -> SemanticExit;

    /// Handle a local (non-trapped) exit. Called by the generic monitor loop
    /// when ExitPolicy says `trap=false` for a `PolicyDriven` exit.
    fn handle_local(&mut self, vp: &mut Self::VpHandle, reason: u32, info: &ExitInfo);

    /// Read hypercall arguments from the VP's register state.
    fn get_hypercall_args(&self, vp: &Self::VpHandle) -> HypercallArgs;

    /// Write the hypercall result back into the VP's register state.
    fn set_hypercall_result(&mut self, vp: &mut Self::VpHandle, result: HypercallResult);

    /// Inject an interrupt into the VP (posted interrupt on x86, LR on ARM).
    fn inject_interrupt(&mut self, vp: &mut Self::VpHandle, vector: u32) -> Result<(), CapaError>;

    /// Advance the VP's instruction pointer past the current trap instruction.
    /// On x86, this advances RIP by `VMEXIT_INSTRUCTION_LEN` (the VMCALL length).
    /// On ARM, this would bump ELR_EL2 past the HVC.
    fn next_rip(&mut self, vp: &mut Self::VpHandle);

    // ── Monitor-level operations ─────────────────────────────────────────── //
    //
    // These methods are used by the generic monitor loop (via the `Vp<A>`
    // wrapper). They combine arch-specific VP access with capability-engine
    // calls.

    /// Full hypercall dispatch: decode args, execute via capability engine,
    /// write result back, advance IP. On a SWITCH hypercall, the VP handle
    /// is swapped to the new domain's VP internally.
    fn dispatch_hypercall(&mut self, vp: &mut Self::VpHandle);

    /// Forward an exit to the parent domain via the capability engine.
    fn forward_exit(&mut self, vp: &mut Self::VpHandle, reason: u32);

    /// Forward an interrupt to the handler domain via the capability engine.
    fn forward_interrupt(&mut self, vp: &mut Self::VpHandle, vector: u32);

    /// Reset the preemption / scheduling timer for the current VP.
    fn reset_timer(&mut self, vp: &mut Self::VpHandle);

    // ── Interposition emulation ─────────────────────────────────────────── //

    /// Write an emulated CPUID result into guest registers and advance IP.
    /// Called by the generic monitor loop when CPUID interposition policy
    /// returns Emulate for a leaf.
    fn emulate_cpuid(
        &mut self,
        vp: &mut Self::VpHandle,
        result: &capability_engine::interposition::CpuidResult,
    );

    /// Write an emulated MSR value into guest registers and advance IP.
    /// Called by the generic monitor loop when MSR interposition policy
    /// returns Emulate for a RDMSR exit.
    fn emulate_rdmsr(&mut self, vp: &mut Self::VpHandle, value: u64);
}

// ── Guest physical address space (EPT / Stage-2) ─────────────────────────── //

/// Guest-physical-to-host-physical mapping (EPT on x86, Stage-2 on AArch64).
pub trait ArchGuestPhysMap {
    /// Opaque per-domain mapping state (EPT root + allocator on x86).
    type MapHandle;

    /// Create a new empty guest physical address space.
    fn create_map(&mut self) -> Result<Self::MapHandle, CapaError>;

    /// Destroy a guest physical address space and free all backing page-table pages.
    fn destroy_map(&mut self, map: &mut Self::MapHandle);

    /// Map a guest physical region to host physical addresses.
    fn map(
        &mut self,
        map: &mut Self::MapHandle,
        gpa: u64,
        hpa: u64,
        size: PageSize,
        perms: MapPermissions,
    );

    /// Unmap a guest physical region.
    fn unmap(&mut self, map: &mut Self::MapHandle, gpa: u64, size: PageSize);

    /// Flush TLB / translation caches for this mapping (INVEPT / TLBI).
    fn flush(&mut self, map: &Self::MapHandle);
}

// ── Cross-core signaling ─────────────────────────────────────────────────── //

/// Inter-processor interrupts and TLB shootdowns.
pub trait ArchCoreSignaling {
    /// Send an IPI to `target_core` to interrupt its current execution.
    fn send_ipi(&self, target_core: u32);

    /// Broadcast a TLB flush for a domain's address space across all cores.
    fn broadcast_flush(&self, domain_id: u64);

    /// Return this core's logical ID.
    fn logical_core_id(&self) -> u32;

    /// Return the total number of active cores.
    fn max_cores(&self) -> u32;
}

// ── Device isolation (IOMMU) ─────────────────────────────────────────────── //

/// IOMMU device assignment and DMA mapping (VT-d on x86, SMMU on ARM).
///
/// This trait is optional — not all platforms have an IOMMU.
pub trait ArchIommu {
    /// Assign a device to a domain's IOMMU context.
    fn assign_device(&mut self, domain_id: u64, device: DeviceId) -> Result<(), CapaError>;

    /// Release a device from its current domain.
    fn release_device(&mut self, device: DeviceId);

    /// Map an IOVA range for DMA.
    fn map_dma(&mut self, domain_id: u64, iova: u64, hpa: u64, perms: MapPermissions);

    /// Unmap an IOVA range.
    fn unmap_dma(&mut self, domain_id: u64, iova: u64);

    /// Flush the IOMMU's IOTLB for a domain.
    fn flush_dma(&mut self, domain_id: u64);
}

// ── Boot (staged) ────────────────────────────────────────────────────────── //

/// Platform discovery and initialization, broken into stages so that
/// generic boot orchestration can call them in order without knowing
/// what each stage does internally.
pub trait ArchBoot {
    /// Platform-specific boot information (memory map, ACPI tables, etc.).
    type BootInfo;

    /// Earliest boot: parse firmware tables, discover memory layout.
    fn early_boot() -> Self::BootInfo;

    /// BSP-specific initialization (e.g., VMXON, GDT, IDT on x86).
    fn init_bsp(info: &Self::BootInfo);

    /// Per-AP initialization on secondary cores.
    fn init_ap(cpu: u32, info: &Self::BootInfo);

    /// Enable the virtualization extensions (VMX root on x86, EL2 on ARM).
    fn enable_virtualization();
}
