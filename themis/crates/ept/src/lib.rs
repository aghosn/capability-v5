//! Extended Page Table (EPT) mapper for Themis.
//!
//! # Status: STUB — Phase 0
//!
//! This crate is a placeholder.  The real implementation will be extracted
//! from `asterinas/hyperenclave` (Apache-2.0, ASPLOS'24) per Phase 0c of the
//! implementation plan.
//!
//! ## Extraction plan
//!
//! 1. Clone `https://github.com/asterinas/hyperenclave`.
//! 2. Identify the EPT source files under `src/mm/` (look for `EptMapper`,
//!    `EptEntry`, `EptLevel`, `InvEpt`).
//! 3. Strip the TEE/enclave ownership-tracking policy (attestation, enclave
//!    page types) — keep only the raw 4-level EPT walk, map, unmap, and
//!    INVEPT wrappers.
//! 4. Adapt the `FrameAllocator` hook to use `capavisor`'s `FrameAllocator`
//!    trait (defined in `capavisor::memory`).
//! 5. Verify `no_std` compilation against `x86_64-unknown-none`.
//! 6. Run the extracted unit tests (if any) under `cargo test --target
//!    x86_64-unknown-linux-gnu` with a hosted frame allocator.
//!
//! ## AMD NPT note
//!
//! AMD Nested Page Tables have the identical 4-level structure and permission
//! encoding as Intel EPT.  This crate will be reused for NPT — the only
//! difference is writing the root physical address to `VMCB.N_CR3` instead
//! of `VMCS.EPT_POINTER`.

#![no_std]

/// Physical address type — will be replaced with `capavisor::memory::PhysAddr`
/// once that module exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct PhysAddr(pub u64);

/// Stub EPT mapper — panics on every call until the real extraction lands.
pub struct EptMapper;

impl EptMapper {
    /// Allocate a new EPT root.  Returns the physical address of the PML4.
    pub fn new() -> (Self, PhysAddr) {
        unimplemented!("EPT: extract from asterinas/hyperenclave (Phase 0c)")
    }

    /// Map `size` bytes at guest-physical `gpa` to host-physical `hpa`
    /// with the given `rights`.
    pub fn map(&mut self, _gpa: u64, _hpa: PhysAddr, _size: u64, _rights: EptRights) {
        unimplemented!("EPT: extract from asterinas/hyperenclave (Phase 0c)")
    }

    /// Unmap the region starting at `gpa`.
    pub fn unmap(&mut self, _gpa: u64, _size: u64) {
        unimplemented!("EPT: extract from asterinas/hyperenclave (Phase 0c)")
    }

    /// Execute `INVEPT` for this EPT context.
    pub fn invept(&self) {
        unimplemented!("EPT: extract from asterinas/hyperenclave (Phase 0c)")
    }

    /// Return the EPT pointer value to write into `VMCS.EPT_POINTER` /
    /// `VMCB.N_CR3`.  Encodes: 4-level walk, WB memory type, accessed/dirty
    /// bits disabled.
    pub fn eptp(&self) -> u64 {
        unimplemented!("EPT: extract from asterinas/hyperenclave (Phase 0c)")
    }
}

bitflags::bitflags! {
    /// EPT page-table permission bits (Intel SDM Vol 3C §29.3.2).
    #[derive(Clone, Copy, Debug)]
    pub struct EptRights: u8 {
        const READ    = 1 << 0;
        const WRITE   = 1 << 1;
        const EXECUTE = 1 << 2;
    }
}
