//! Themis hypercall ABI — shared between the capavisor and guest software.
//!
//! This crate is `no_std` so it can be linked into the bare-metal capavisor,
//! a Linux kernel module (`themis-vmm.ko`), and userspace VMMs alike.

#![no_std]

// ── Hypercall opcodes (RAX) ──────────────────────────────────────────────── //

pub mod opcodes {
    pub const THEMIS_CARVE:               u64 = 0x01;
    pub const THEMIS_ALIAS:               u64 = 0x02;
    pub const THEMIS_SEND:                u64 = 0x03;
    pub const THEMIS_ACCEPT:              u64 = 0x04;
    pub const THEMIS_REJECT:              u64 = 0x05;
    pub const THEMIS_CREATE_DOMAIN:       u64 = 0x06;
    pub const THEMIS_SEAL:                u64 = 0x07;
    pub const THEMIS_REVOKE_MEM:          u64 = 0x08;
    pub const THEMIS_REVOKE_DOMAIN:       u64 = 0x09;
    pub const THEMIS_SWITCH:              u64 = 0x0A;
    pub const THEMIS_GET_CHAN:            u64 = 0x0B;
    pub const THEMIS_ATTEST_SELF:         u64 = 0x0C;
    pub const THEMIS_ATTEST:              u64 = 0x0D;
    pub const THEMIS_GET_REG:             u64 = 0x0E;
    pub const THEMIS_SET_REG:             u64 = 0x0F;
    pub const THEMIS_SET_INTR_POLICY:     u64 = 0x10;
    pub const THEMIS_SET_DEF_INTR_POLICY: u64 = 0x11;
    pub const THEMIS_ASSIGN_DEVICE:       u64 = 0x12;
    pub const THEMIS_ENUMERATE:           u64 = 0x13;
    pub const THEMIS_REGISTER_VP_META:    u64 = 0x14;
    pub const THEMIS_REGISTER_DOORBELL:   u64 = 0x15;
    pub const THEMIS_REGISTER_EVENT_FLAGS:u64 = 0x16;
    pub const THEMIS_REGISTER_INTR_CHAN:  u64 = 0x17;
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

// ── VP register indices (used with THEMIS_GET_REG / THEMIS_SET_REG) ─────── //

#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VpRegister {
    // General-purpose registers — saved/restored in the VMEXIT handler stub.
    Rax = 0x00, Rbx = 0x01, Rcx = 0x02, Rdx = 0x03,
    Rsi = 0x04, Rdi = 0x05, Rbp = 0x06,
    R8  = 0x07, R9  = 0x08, R10 = 0x09, R11 = 0x0A,
    R12 = 0x0B, R13 = 0x0C, R14 = 0x0D, R15 = 0x0E,
    // VMCS guest-state fields — committed at VMLAUNCH; read via VMREAD.
    Rip    = 0x20,
    Rsp    = 0x21,
    Rflags = 0x22,
    Cr0    = 0x23,
    Cr3    = 0x24,
    Cr4    = 0x25,
    Efer   = 0x26,
    // Segment selectors / bases
    Cs = 0x30, Ds = 0x31, Es = 0x32, Fs = 0x33,
    Gs = 0x34, Ss = 0x35, Tr = 0x36, Ldtr = 0x37,
    FsBase = 0x38, GsBase = 0x39, KernelGsBase = 0x3A,
    // SYSENTER MSRs
    SysenterCs  = 0x40,
    SysenterEsp = 0x41,
    SysenterEip = 0x42,
    // APIC
    ApicBase = 0x50,
    // Virtual APIC state — readable by parent via GET; written by Themis.
    Tpr = 0x60,
    Ppr = 0x61,
}

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
