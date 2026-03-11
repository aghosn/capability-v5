//! Themis hypercall ABI — shared between the capavisor and guest software.
//!
//! This crate is `no_std` so it can be linked into the bare-metal capavisor,
//! a Linux kernel module (`themis-vmm.ko`), and userspace VMMs alike.
//!
//! # Register convention (System V AMD64-style)
//!
//! ```text
//! IN:   RAX = opcode
//!       RDI = arg0,  RSI = arg1,  RDX = arg2,  RCX = arg3,  R8 = arg4
//!
//! OUT:  RAX = error code (0 = SUCCESS, see `errors` module)
//!       RDI = result0,  RSI = result1,  RDX = result2
//! ```

#![no_std]

// ── Hypercall opcodes (RAX) ──────────────────────────────────────────────── //

pub mod opcodes {
    /// Carve an exclusive sub-region from a parent memory capability.
    /// IN:  RDI = parent_handle, RSI = start, RDX = size, RCX = rights
    /// OUT: RDI = new_handle, RSI = sub_handle
    pub const THEMIS_CARVE:               u64 = 0x01;

    /// Alias a shared sub-region from a parent memory capability.
    /// IN:  RDI = parent_handle, RSI = start, RDX = size, RCX = rights
    /// OUT: RDI = new_handle, RSI = sub_handle
    pub const THEMIS_ALIAS:               u64 = 0x02;

    /// Send a memory capability to a receiver domain.
    /// IN:  RDI = cap_handle, RSI = receiver_domain_handle, RDX = attributes
    pub const THEMIS_SEND:                u64 = 0x03;

    /// Accept a pending memory capability.
    /// IN:  RDI = pending_id
    /// OUT: RDI = new_handle
    pub const THEMIS_ACCEPT:              u64 = 0x04;

    /// Reject a pending memory capability.
    /// IN:  RDI = pending_id
    pub const THEMIS_REJECT:              u64 = 0x05;

    /// Create a new child domain.
    /// IN:  RDI = cores_bitmask, RSI = api_flags, RDX = num_vps
    /// OUT: RDI = domain_handle
    pub const THEMIS_CREATE_DOMAIN:       u64 = 0x06;

    /// Seal a domain (transition Unsealed → Sealed).
    /// IN:  RDI = domain_handle
    pub const THEMIS_SEAL:                u64 = 0x07;

    /// Revoke a child of a memory capability.
    /// IN:  RDI = parent_handle, RSI = child_sub_handle
    pub const THEMIS_REVOKE_MEM:          u64 = 0x08;

    /// Revoke an entire child domain.
    /// IN:  RDI = child_domain_handle
    pub const THEMIS_REVOKE_DOMAIN:       u64 = 0x09;

    /// Switch to a target domain's VP (or return to caller).
    /// IN:  RDI = target_domain_handle (0 = return), RSI = target_vp_id
    pub const THEMIS_SWITCH:              u64 = 0x0A;

    /// Get a channel capability to a domain.
    /// IN:  RDI = domain_handle
    /// OUT: RDI = channel_handle
    pub const THEMIS_GET_CHAN:            u64 = 0x0B;

    /// Attest the current domain (self-attestation).
    /// OUT: RDI = hash_lo, RSI = hash_hi  (first 16 bytes of SHA-256)
    pub const THEMIS_ATTEST_SELF:         u64 = 0x0C;

    /// Attest another domain (remote attestation).
    /// IN:  RDI = domain_handle
    /// OUT: RDI = hash_lo, RSI = hash_hi
    pub const THEMIS_ATTEST:              u64 = 0x0D;

    /// Read a VP register from a child domain.
    /// IN:  RDI = domain_handle, RSI = vp_id, RDX = register_id
    /// OUT: RDI = value
    pub const THEMIS_GET_REG:             u64 = 0x0E;

    /// Write a VP register of a child domain.
    /// IN:  RDI = domain_handle, RSI = vp_id, RDX = register_id, RCX = value
    pub const THEMIS_SET_REG:             u64 = 0x0F;

    /// Set per-vector interrupt policy for a domain.
    /// IN:  RDI = domain_handle, RSI = vector, RDX = policy
    pub const THEMIS_SET_INTR_POLICY:     u64 = 0x10;

    /// Set default interrupt policy for a domain.
    /// IN:  RDI = domain_handle, RSI = policy
    pub const THEMIS_SET_DEF_INTR_POLICY: u64 = 0x11;

    /// Assign a PCI device to a domain.
    /// IN:  RDI = domain_handle, RSI = pci_bdf
    pub const THEMIS_ASSIGN_DEVICE:       u64 = 0x12;

    /// Enumerate pending capabilities / domain tree.
    pub const THEMIS_ENUMERATE:           u64 = 0x13;

    /// Register a VP META state page.
    /// IN:  RDI = domain_handle, RSI = vp_id, RDX = meta_cap_handle
    pub const THEMIS_REGISTER_VP_META:    u64 = 0x14;

    /// Register a doorbell page.
    pub const THEMIS_REGISTER_DOORBELL:   u64 = 0x15;

    /// Register an event flags page.
    pub const THEMIS_REGISTER_EVENT_FLAGS:u64 = 0x16;

    /// Register an interrupt channel.
    pub const THEMIS_REGISTER_INTR_CHAN:  u64 = 0x17;

    /// Register a COMM page owned by the caller, bound to a child VP.
    /// IN:  RDI = mem_cap_handle, RSI = child_domain_handle, RDX = vp_id
    pub const THEMIS_REGISTER_COMM:       u64 = 0x18;
}

// ── Hypercall return codes (RAX on return) ───────────────────────────────── //

pub mod errors {
    pub const SUCCESS:        u64 = 0;
    pub const ERR_INVALID:    u64 = 1;
    pub const ERR_NOPERM:     u64 = 2;
    pub const ERR_NOMEM:      u64 = 3;
    pub const ERR_BADSTATE:   u64 = 4;
    pub const ERR_NOTFOUND:   u64 = 5;
    pub const ERR_UNIMPL:     u64 = u64::MAX;
}

// ── VP register profile ───────────────────────────────────────────────────── //
//
// `VpGpRegs`, `VpSregs`, `SegmentReg`, `DescriptorTableReg`, and `VpRegister`
// are defined in the `regs` submodule and re-exported here for convenience.

pub mod regs;

pub mod domcomm;

pub use regs::{
    DescriptorTableReg, SegmentReg, VpCommPage, VpGpRegs, VpRegister, VpSregs,
};

// ── META VP-state page layout (Phase 10) ────────────────────────────────── //
//
// Placed here so both capavisor and the themis-vmm.ko driver share the exact
// same struct layout without a copy.  Defined as a raw layout constant for
// now; a full `#[repr(C)] struct VpStateMeta` will replace this in Phase 10.
//
// Offset 0x000 – 0x0BF: GP registers + RIP/RSP/RFLAGS/CR0/CR3/CR4/EFER
// Offset 0x0C0 – 0x0C7: exit_reason (u32) + exit_qualification (u64)
// Offset 0x0C8 – 0x0CB: dirty bitmask (atomic u32)
// Offset 0x0CC – 0x0CF: status flags (PENDING_IRQ | RESUME_WITH_IRQ | RESUME_NO_IRQ)
// Offset 0x100 – 0x13F: PostedInterruptDescriptor (64 B, 64 B-aligned)
// Remainder: reserved / zero

pub mod meta {
    pub const DIRTY_GPR: u32  = 1 << 0;
    pub const DIRTY_CR:  u32  = 1 << 1;
    pub const DIRTY_RIP: u32  = 1 << 2;
    pub const DIRTY_RSP: u32  = 1 << 3;

    pub const STATUS_PENDING_IRQ:    u32 = 1 << 0;
    pub const STATUS_RESUME_WITH_IRQ:u32 = 1 << 1;
    pub const STATUS_RESUME_NO_IRQ:  u32 = 1 << 2;

    /// Byte offset of the PostedInterruptDescriptor within VpStateMeta page.
    pub const PI_DESC_OFFSET: usize = 0x100;
    /// Size of a VpStateMeta page.
    pub const META_PAGE_SIZE: usize = 4096;
}
