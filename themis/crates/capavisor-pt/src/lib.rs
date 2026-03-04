//! Capavisor host page-table manager.
//!
//! # Status: STUB — Phase 0
//!
//! This crate is a placeholder.  The real implementation will be extracted
//! from `verified-nrkernel` (Verus-verified, SOSP'24 Distinguished Artifact)
//! per Phase 0c of the implementation plan.
//!
//! ## Extraction plan
//!
//! 1. Clone `https://github.com/matthias-brun/verified-nrkernel`.
//! 2. Vendor the relevant Rust source into this crate (git subtree or copy).
//! 3. Confirm the Verus proofs still pass:
//!    `verus crates/capavisor-pt/ --crate-type lib`
//! 4. Ensure the non-Verus build path compiles cleanly for
//!    `x86_64-unknown-none` (Verus annotations are erased by `rustc` when
//!    the `verus` tool is not involved).
//! 5. Extend `spec_t/hardware.rs` with Themis-specific invariants:
//!    - **META pages**: a frame mapped as META is accessible by Themis AND
//!      visible in a child domain's EPT — two simultaneous mappings are valid.
//!    - **HHDM identity region**: the bulk of physical memory is mapped
//!      identity (phys + HHDM_OFFSET = virt) and must remain so.
//!    Prove that `map_meta` and `unmap_meta` preserve both invariants.
//! 6. Verus proofs remain runnable as a regression check; in the normal
//!    `cargo build` path the same Rust compiles without Verus tooling.
//!
//! ## Usage (planned)
//!
//! When a parent domain calls `THEMIS_REGISTER_VP_META`, Themis:
//! 1. Calls `map_meta(phys_addr)` to insert the META physical frame into
//!    the capavisor's own 4-level root-mode page tables.
//! 2. Receives a `VirtAddr` usable in root mode to write `VpStateMeta`
//!    fields on every VMEXIT.
//! 3. At domain revocation calls `unmap_meta(phys_addr)` to remove the
//!    mapping and prove the invariant is restored.

#![no_std]

/// Physical address type — will be replaced with `capavisor::memory::PhysAddr`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct PhysAddr(pub u64);

/// Virtual address type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct VirtAddr(pub usize);

/// Stub host page-table manager.
pub struct HostPageTable;

impl HostPageTable {
    /// Map a META physical frame into the capavisor's host address space.
    /// Returns the virtual address at which the frame is now accessible.
    pub fn map_meta(&mut self, _phys: PhysAddr) -> VirtAddr {
        unimplemented!("capavisor-pt: vendor from verified-nrkernel (Phase 0c)")
    }

    /// Remove a META mapping previously installed with `map_meta`.
    pub fn unmap_meta(&mut self, _phys: PhysAddr) {
        unimplemented!("capavisor-pt: vendor from verified-nrkernel (Phase 0c)")
    }
}
