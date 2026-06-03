//! Cross-arch per-domain contract.
//!
//! `ArchDomain` is implemented by each arch's `ArchDomainState`. The
//! cross-arch [`PlatformDomain`](crate::platform::PlatformDomain) carries
//! one such state in its `arch:` field, and `apply_update` in
//! [`ThemisPlatform`](crate::platform::ThemisPlatform) calls trait methods
//! on `domain.arch` to mutate the per-domain second-stage and IOMMU page
//! tables — concrete impl is selected at compile time via `cfg`.

use crate::arch::ArchPlatformState;
use crate::mem::{MetaAllocator, UncacheableRanges};
use capability_engine::Rights;

/// Bundle of cross-arch resources a per-domain second-stage map / unmap
/// operation needs from the cross-arch carrier.
///
/// `meta` is the *target* domain's META pool (page-table backing for its
/// second-stage tables). `root_meta` is the root (dom0) domain's META pool,
/// used for IOMMU page-table pages so that child META budgets are not
/// consumed by hypervisor-internal SLPT pages. It is `None` when the
/// operation targets the root domain itself (root has no IOMMU SLPT).
pub struct ChangeRightsCtx<'a> {
    pub meta: &'a mut MetaAllocator,
    pub root_meta: Option<&'a mut MetaAllocator>,
    pub uc_ranges: &'a UncacheableRanges,
    pub hhdm_offset: u64,
    pub is_child: bool,
}

/// Cross-arch contract implemented by every arch's `ArchDomainState`.
pub trait ArchDomain {
    /// Apply a ChangeRights update: map (`rights.bits() != 0`) or unmap
    /// (`rights.bits() == 0`) `[gpa, gpa+size)` → `[hpa, hpa+size)` in this
    /// domain's second-stage translation tables (EPT on x86, Stage-2 on ARM)
    /// and IOMMU tables (VT-d SLPT on x86, SMMU on ARM).
    ///
    /// The implementation is responsible for arch-specific quirks such as
    /// the LAPIC EPT mapping / APIC-virtualization detection on x86.
    ///
    /// `arch_plat` exposes per-platform arch state (DRHD units / GIC info)
    /// the per-domain operation may need to consult — e.g. the IOMMU page-
    /// table level on x86.
    fn change_rights(
        &mut self,
        arch_plat: &ArchPlatformState,
        gpa: u64,
        hpa: u64,
        size: usize,
        rights: &Rights,
        ctx: &mut ChangeRightsCtx<'_>,
    );

    /// Tear down all per-domain page-table state (second-stage root,
    /// IOMMU PT root). Called once from RevokeDomain.
    ///
    /// `root_meta` is `None` for the root domain (no IOMMU SLPT to free).
    fn destroy(&mut self, meta: &mut MetaAllocator, root_meta: Option<&mut MetaAllocator>);

    /// Snapshot of the per-LP translation-cache handle for this domain
    /// (x86: the EPTP; ARM: a VMID-derived value).  Returned as a raw
    /// `u64` so it can be queued in a cross-arch [`CoreUpdate`] and
    /// applied later via [`flush_tlb_handle`](crate::arch::flush_tlb_handle)
    /// without holding any reference to the (possibly-revoked) domain.
    ///
    /// "SLAT" = Second-Level Address Translation, the cross-arch name
    /// for what x86 calls EPT and ARM calls Stage-2.
    ///
    /// Returns `None` when no second-stage tables exist yet (a domain
    /// that has never been entered cannot have cached translations).
    fn slat(&self) -> Option<u64>;

    /// Flush this domain's per-LP translation cache on the *current*
    /// CPU.  Convenience wrapper around `slat()` +
    /// [`flush_tlb_handle`](crate::arch::flush_tlb_handle); a no-op when
    /// no second-stage tables exist yet.
    fn flush_tlb(&self);

    // ── VP slot ownership (cross-core handoff) ──────────────────────────── //
    //
    // Each domain owns a vector of per-VP "inactive" VP states. A core that
    // wants to run VP i takes the inactive state, activates it (loads it on
    // the CPU), runs the guest, then returns the inactive state when it
    // exits.  The atomic take/return machinery is arch-specific (x86 wraps
    // a heap-allocated `InactiveVcpu` in an `AtomicPtr`).

    /// Per-VP inactive state owned by the domain (x86: `InactiveVcpu`,
    /// AArch64: TBD).
    type InactiveVp;

    /// Insert `vcpu` at VP index `vp_id`, growing the per-domain VP vector
    /// as needed.  Used at VP construction time (boot for dom0, child VP
    /// creation for sealed children).
    ///
    /// # Panics
    /// Implementations may panic if the slot at `vp_id` is already
    /// populated (double-store bug).
    fn store_inactive_vp(&mut self, vp_id: usize, vcpu: Self::InactiveVp);

    /// Atomically take the inactive VP at index `vp_id`, leaving the slot
    /// empty.  Returns `None` if the slot is already empty (VP is active
    /// on another core, or out-of-range).
    fn take_inactive_vp(&self, vp_id: usize) -> Option<Self::InactiveVp>;

    /// Return a previously-taken inactive VP back to its slot after
    /// deactivation.  Symmetric to `take_inactive_vp`.
    ///
    /// # Panics
    /// Implementations may panic if the slot is not empty (double-return
    /// bug) or if `vp_id` is out-of-range.
    fn return_inactive_vp(&mut self, vp_id: usize, vcpu: Self::InactiveVp);
}
