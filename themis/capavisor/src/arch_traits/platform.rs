//! Cross-arch platform contract.
//!
//! `ArchPlatform` is implemented by each arch's `ArchPlatformState`. The
//! cross-arch [`ThemisPlatform`](crate::platform::ThemisPlatform) brings this
//! trait into scope and calls trait methods on its `arch:
//! ArchPlatformState` field — the concrete impl is selected at compile time
//! by `cfg(target_arch)` (see [`crate::arch`]), so there is no `dyn`
//! overhead, but every arch is forced to provide every method at impl
//! definition time rather than failing at far-flung call sites.
//!
//! Methods on this trait are platform-wide cross-core operations that
//! `ThemisPlatform` needs to perform but whose mechanics are arch-specific
//! (e.g. APIC ICR write on x86 vs GICv3 SGI on ARM). Per-domain operations
//! (EPT/Stage-2 mapping, IOMMU/SMMU programming) belong on `ArchDomain` —
//! introduced as the migration progresses.

use capability_engine::CoreId;

/// Cross-arch contract implemented by every arch's `ArchPlatformState`.
pub trait ArchPlatform {
    /// Send a cross-core wake/IPI to `core_id`. The convention is that the
    /// IPI must always cause the target VP to exit non-root mode so the
    /// monitor loop can drain pending [`CoreUpdate`](capability_engine::CoreUpdate)s.
    ///
    /// On x86 this is an INIT-IPI (delivery=0x5, edge, assert) which always
    /// causes EXIT_REASON_INIT_SIGNAL regardless of pin-based controls.
    /// On AArch64 this will be a GICv3 SGI.
    ///
    /// `hhdm_offset` is the bootloader's higher-half direct map base; it is
    /// stored on the cross-arch [`ThemisPlatform`](crate::platform::ThemisPlatform)
    /// rather than on the arch state because both arches have the same
    /// concept (Limine on x86, the eventual ARM bootloader equivalent).
    fn send_ipi(&self, core_id: CoreId, hhdm_offset: u64);

    /// Resolve the running CPU's logical core ID, or `None` if the running
    /// CPU's hardware ID is not in the boot-time topology.
    ///
    /// On x86 this reads `CPUID.01h:EBX[31:24]` (initial APIC ID) and looks
    /// it up in the LAPIC ID table. On AArch64 this will read MPIDR_EL1 and
    /// look it up in the MPIDR table.
    fn current_core_id(&self) -> Option<CoreId>;
}
