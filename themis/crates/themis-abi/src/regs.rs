//! x86-64 Intel VP register profile — shared between capavisor, driver, and VMM.
//!
//! ## Two layers
//!
//! **Bulk structs** (`VpGpRegs`, `VpSregs`) — read/write a logical group of
//! registers in one call.  Used for initial VP setup, VP state save/restore,
//! and the Phase-10 META page layout.
//!
//! **Individual selector** (`VpRegister`) — names a single register for
//! `THEMIS_GET_REG` / `THEMIS_SET_REG` hypercalls, where the caller wants to
//! touch exactly one field without transferring a full struct.
//!
//! ## Segment access-rights encoding
//!
//! `SegmentReg::access_rights` uses the **VMX 32-bit access-rights** format
//! directly (Intel SDM Vol 3C §25.4.1):
//!
//! ```text
//!  [3:0]  type    (execute/read/write/accessed bits)
//!  [4]    S       (0 = system descriptor, 1 = code/data)
//!  [6:5]  DPL     (descriptor privilege level)
//!  [7]    P       (segment present)
//! [11:8]  reserved (MBZ)
//!  [12]   AVL     (available for OS use)
//!  [13]   L       (64-bit code segment)
//!  [14]   D/B     (default op size / big)
//!  [15]   G       (granularity: 0=byte, 1=4 KB)
//!  [16]   unusable (1 = segment is unusable; set for null-selector segs)
//! [31:17] reserved (MBZ)
//! ```
//!
//! This encoding can be written directly into VMCS guest-state access-rights
//! fields without conversion.
//!
//! ## Common access-rights constants
//!
//! ```rust
//! use themis_abi::regs::access_rights;
//!
//! // 64-bit code segment (L=1, P=1, S=1, type=0xA = execute/read)
//! let cs_ar = access_rights::CODE64;
//! // 64-bit data segment (P=1, S=1, type=0x3 = read/write/accessed)
//! let ds_ar = access_rights::DATA64;
//! // Unusable segment (e.g. null selector for FS/GS/LDT when not in use)
//! let null_ar = access_rights::UNUSABLE;
//! ```

// ── Bulk register structs ─────────────────────────────────────────────────── //

/// x86-64 general-purpose register state of a VP.
///
/// Covers all 15 caller/callee-save GPRs plus RSP, RIP, and RFLAGS.
/// RSP and RIP live in VMCS guest-state; the remaining GPRs are stored in the
/// per-VP register file in [`crate::vmx::vcpu::InactiveVcpu`].
///
/// On exit from `THEMIS_SWITCH`, the capavisor fills this with the values
/// that were live at the child's VMEXIT.  On entry (initial setup or resume),
/// the parent writes this to establish the child's register context.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VpGpRegs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rsp: u64,    // VMCS guest::RSP
    pub rip: u64,    // VMCS guest::RIP
    pub rflags: u64, // VMCS guest::RFLAGS
}

/// A single x86 segment register as seen by Intel VMX guest state.
///
/// Covers the four VMCS fields that describe each segment:
/// `{SEG}_SELECTOR`, `{SEG}_BASE`, `{SEG}_LIMIT`, `{SEG}_ACCESS_RIGHTS`.
///
/// Size: 24 bytes.  `_pad` fields ensure natural alignment and a fixed layout.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SegmentReg {
    /// VMCS `{SEG}_BASE` — linear base address of the segment.
    pub base: u64, // offset  0
    /// VMCS `{SEG}_LIMIT` — segment limit (byte or 4 KB granules per `G` bit).
    pub limit: u32, // offset  8
    /// VMCS `{SEG}_SELECTOR` — RPL/TI/index packed selector value.
    pub selector: u16, // offset 12
    pub _pad0: u16, // offset 14 — reserved, must be 0
    /// VMCS `{SEG}_ACCESS_RIGHTS` — VMX 32-bit access-rights encoding.
    /// See module-level documentation and [`access_rights`] for constants.
    pub access_rights: u32, // offset 16
    pub _pad1: u32, // offset 20 — reserved, must be 0
} // total:  24 bytes

/// A descriptor-table register (GDTR or IDTR) as seen by Intel VMX guest state.
///
/// Covers `{DT}_BASE` and `{DT}_LIMIT` VMCS fields.
///
/// Size: 16 bytes.  `_pad` ensures the struct aligns cleanly in `VpSregs`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct DescriptorTableReg {
    /// VMCS `GDTR_BASE` / `IDTR_BASE`.
    pub base: u64, // offset 0
    /// VMCS `GDTR_LIMIT` / `IDTR_LIMIT` — 16-bit limit.
    pub limit: u16, // offset 8
    pub _pad: [u8; 6], // offset 10 — reserved, must be 0
} // total: 16 bytes

/// x86-64 special register state of a VP.
///
/// Covers all segment descriptors, descriptor-table registers, control
/// registers, EFER, and the APIC base MSR.  Mirrors the information exposed
/// by KVM's `kvm_sregs` and MSHV's `MSHV_GET/SET_VP_STATE`, but uses the VMX
/// access-rights encoding for segment descriptors directly.
///
/// Size: 8×24 + 2×16 + 5×8 = 256 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VpSregs {
    // ── Segment descriptors (8 × 24 = 192 bytes) ──────────────────────── //
    pub cs: SegmentReg,
    pub ds: SegmentReg,
    pub es: SegmentReg,
    pub fs: SegmentReg,
    pub gs: SegmentReg,
    pub ss: SegmentReg,
    pub tr: SegmentReg,  // Task Register
    pub ldt: SegmentReg, // Local Descriptor Table Register

    // ── Descriptor-table registers (2 × 16 = 32 bytes) ────────────────── //
    pub gdt: DescriptorTableReg,
    pub idt: DescriptorTableReg,

    // ── Control registers and EFER (5 × 8 = 40 bytes) ─────────────────── //
    /// VMCS `guest::CR0` — protected-mode enable, paging, etc.
    pub cr0: u64,
    /// VMCS `guest::CR3` — page-table root physical address.
    pub cr3: u64,
    /// VMCS `guest::CR4` — PAE, VMXE, etc.
    pub cr4: u64,
    /// VMCS `guest::IA32_EFER_FULL` — LME, LMA, NXE, SCE.
    pub efer: u64,
    /// MSR `IA32_APIC_BASE` — LAPIC base address and enable bits.
    pub apic_base: u64,
}

// ── Common access-rights constants ───────────────────────────────────────── //

/// Pre-built VMX access-rights values for the most common segment types.
pub mod access_rights {
    /// Segment is unusable (null selector, or explicitly disabled).
    /// Sets bit 16 (unusable).  All other bits are ignored by hardware.
    pub const UNUSABLE: u32 = 1 << 16;

    /// 64-bit kernel code segment.
    /// P=1, S=1 (code/data), type=0xA (execute/read), L=1 (64-bit), G=1.
    pub const CODE64: u32 = 0xA09B;

    /// 64-bit kernel data/stack segment.
    /// P=1, S=1 (code/data), type=0x3 (read/write/accessed), G=1.
    pub const DATA64: u32 = 0xC093;

    /// 32-bit kernel code segment (used for early-boot / real-mode transitions).
    /// P=1, S=1, type=0xB (execute/read/accessed), D/B=1, G=1.
    pub const CODE32: u32 = 0xC09B;

    /// 32-bit kernel data segment.
    /// P=1, S=1, type=0x3, D/B=1, G=1.
    pub const DATA32: u32 = 0xC093;

    /// 16-bit real-mode code segment (type=0x3, present, byte granularity).
    pub const CODE16: u32 = 0x009B;

    /// 16-bit real-mode data segment.
    pub const DATA16: u32 = 0x0093;

    /// 32-bit busy TSS (Task State Segment).
    /// type=0xB (TSS busy 32-bit), P=1, S=0 (system).
    pub const TSS32_BUSY: u32 = 0x008B;

    /// 64-bit busy TSS.
    /// type=0xB, P=1, S=0, L=1.
    pub const TSS64_BUSY: u32 = 0x208B;
}

// ── Individual register selector for GET_REG / SET_REG ───────────────────── //

/// Identifies a single VP register for `THEMIS_GET_REG` / `THEMIS_SET_REG`.
///
/// Grouped by register bank; within each bank, contiguous values are
/// guaranteed so capavisor dispatch can use range checks.
///
/// Segment state is exposed per-field (selector, base, limit, access_rights)
/// so the parent can patch individual fields without reading the full `VpSregs`.
#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VpRegister {
    // ── General-purpose registers (0x00–0x0E) ──────────────────────────── //
    // Source: VP register file (saved/restored by VMEXIT trampoline).
    Rax = 0x00,
    Rbx = 0x01,
    Rcx = 0x02,
    Rdx = 0x03,
    Rsi = 0x04,
    Rdi = 0x05,
    Rbp = 0x06,
    R8 = 0x07,
    R9 = 0x08,
    R10 = 0x09,
    R11 = 0x0A,
    R12 = 0x0B,
    R13 = 0x0C,
    R14 = 0x0D,
    R15 = 0x0E,

    // ── Stack / instruction / flags (0x10–0x12) ────────────────────────── //
    // Source: VMCS guest-state fields.
    Rsp = 0x10,
    Rip = 0x11,
    Rflags = 0x12,

    // ── Control registers + EFER + DR7 (0x20–0x26) ────────────────────── //
    // Source: VMCS guest-state fields.
    Cr0 = 0x20,
    Cr3 = 0x21,
    Cr4 = 0x22,
    Efer = 0x23,
    Dr7 = 0x24,

    // ── Segment selectors (0x30–0x37) ─────────────────────────────────── //
    // Source: VMCS guest {SEG}_SELECTOR fields.
    CsSelector = 0x30,
    DsSelector = 0x31,
    EsSelector = 0x32,
    FsSelector = 0x33,
    GsSelector = 0x34,
    SsSelector = 0x35,
    TrSelector = 0x36,
    LdtrSelector = 0x37,

    // ── Segment base addresses (0x40–0x47) ────────────────────────────── //
    // Source: VMCS guest {SEG}_BASE fields.
    CsBase = 0x40,
    DsBase = 0x41,
    EsBase = 0x42,
    FsBase = 0x43,
    GsBase = 0x44,
    SsBase = 0x45,
    TrBase = 0x46,
    LdtrBase = 0x47,

    // ── Segment limits (0x50–0x57) ─────────────────────────────────────── //
    // Source: VMCS guest {SEG}_LIMIT fields.
    CsLimit = 0x50,
    DsLimit = 0x51,
    EsLimit = 0x52,
    FsLimit = 0x53,
    GsLimit = 0x54,
    SsLimit = 0x55,
    TrLimit = 0x56,
    LdtrLimit = 0x57,

    // ── Segment access rights (0x60–0x67) ─────────────────────────────── //
    // Source: VMCS guest {SEG}_ACCESS_RIGHTS fields (VMX encoding).
    CsAccessRights = 0x60,
    DsAccessRights = 0x61,
    EsAccessRights = 0x62,
    FsAccessRights = 0x63,
    GsAccessRights = 0x64,
    SsAccessRights = 0x65,
    TrAccessRights = 0x66,
    LdtrAccessRights = 0x67,

    // ── Descriptor-table registers (0x70–0x73) ────────────────────────── //
    // Source: VMCS guest GDTR/IDTR fields.
    GdtrBase = 0x70,
    GdtrLimit = 0x71,
    IdtrBase = 0x72,
    IdtrLimit = 0x73,

    // ── SYSENTER MSRs (0x80–0x82) ─────────────────────────────────────── //
    // Source: VMCS guest IA32_SYSENTER_{CS,ESP,EIP} fields.
    SysenterCs = 0x80,
    SysenterEsp = 0x81,
    SysenterEip = 0x82,

    // ── Segment-related MSRs (0x90–0x91) ──────────────────────────────── //
    // Source: MSR — written via VMCS or directly for the running domain.
    /// `IA32_FS_BASE` MSR (0xC000_0100).
    FsBaseMsr = 0x90,
    /// `IA32_GS_BASE` MSR (0xC000_0101).
    GsBaseMsr = 0x91,
    /// `IA32_KERNEL_GS_BASE` MSR (0xC000_0102) — swapped by SWAPGS.
    KernelGsBase = 0x92,

    // ── APIC / virtual APIC (0xA0–0xA2) ───────────────────────────────── //
    /// `IA32_APIC_BASE` MSR — LAPIC base and enable bits.
    ApicBase = 0xA0,
    /// Virtual TPR (Task Priority Register) — readable from VAPIC page.
    Tpr = 0xA1,
    /// Virtual PPR (Processor Priority Register) — readable from VAPIC page.
    Ppr = 0xA2,

    // ── VMCS activity / interruptibility / PAT (0xB0–0xB2) ───────────── //
    /// VMCS `ACTIVITY_STATE` — 0=active, 1=HLT, 2=shutdown, 3=wait-for-SIPI.
    ActivityState = 0xB0,
    /// VMCS `GUEST_INTERRUPTIBILITY_STATE` — blocking by STI, MOV SS, NMI, SMI.
    InterruptibilityState = 0xB1,
    /// VMCS `IA32_PAT_FULL` — page attribute table MSR (for VMCS-managed PAT).
    Pat = 0xB2,
}

impl VpRegister {
    /// Convert a raw discriminant value to a `VpRegister`, if valid.
    pub fn from_discriminant(n: u64) -> Option<VpRegister> {
        ALL_VP_REGISTERS.iter().find(|r| **r as u64 == n).copied()
    }
}

// ── COMM page: bulk register transfer via shared memory ───────────────────── //

/// Number of 64-bit words in the dirty / allowed bitmasks.
/// 3 words = 192 bits, covering all `VpRegister` discriminants (max 0xB2 = 178).
pub const VP_COMM_MASK_WORDS: usize = 3;

/// Byte offset at which register fields begin within [`VpCommPage`].
pub const VP_COMM_REGS_OFFSET: usize = 64;

/// Total size of the register-data section (header + all register fields).
/// The rest of the 4 KiB page is zero-padding.
pub const VP_COMM_DATA_SIZE: usize = 512;

/// A 4 KiB page shared between a parent domain and the capavisor that holds
/// a complete snapshot of a child VP's register state.
///
/// ## Protocol
///
/// **Setup (done once at `THEMIS_REGISTER_COMM`):**
/// The capavisor writes `allowed_mask` to reflect which registers the parent
/// is permitted to modify for this VP.  Read-only registers (e.g. `Tpr`,
/// `Ppr`, `ActivityState` on a sealed domain) will have their bits clear.
///
/// **Parent → capavisor (write path):**
/// 1. Write the desired value(s) to the relevant field(s).
/// 2. Set the corresponding bit(s) in `dirty_mask`
///    (`bit N` ↔ `VpRegister` discriminant `N`).
/// 3. Issue `THEMIS_SET_REGS` (or the dirty bits are consumed at the next
///    `THEMIS_SWITCH` automatically).
///
/// The capavisor validates `dirty_mask & !allowed_mask == 0` before applying
/// any changes.  Violations return `ERR_NOPERM` and leave the VP unchanged.
///
/// **Capavisor → parent (read path):**
/// After a VMEXIT the capavisor writes the current VP state into all fields
/// and sets `dirty_mask` to `allowed_mask` (all readable registers are fresh).
/// The parent clears individual bits as it consumes them.
///
/// ## Bit-index mapping
///
/// Bit `N` of the `dirty_mask` / `allowed_mask` words corresponds to
/// `VpRegister` discriminant `N`:
///
/// ```text
/// word 0 (dirty_mask[0]) → VpRegister discriminants 0x00–0x3F
/// word 1 (dirty_mask[1]) → VpRegister discriminants 0x40–0x7F
/// word 2 (dirty_mask[2]) → VpRegister discriminants 0x80–0xBF
/// ```
///
/// Helper: `mask_bit(reg)` returns `(word_index, bit_within_word)`.
///
/// ## Size
///
/// Exactly 4096 bytes (one page).  Mapped via `THEMIS_REGISTER_COMM` with
/// `vp_id` identifying the target child VP.
#[repr(C)]
pub struct VpCommPage {
    // ── Header (64 bytes) ─────────────────────────────────────────────── //
    /// Dirty bitmask written by the parent.
    /// Bit `N` set ↔ the field for `VpRegister(N)` has been updated and must
    /// be flushed to the VMCS / register file by the capavisor.
    /// Cleared (per bit) by the capavisor after each field is applied.
    pub dirty_mask: [u64; VP_COMM_MASK_WORDS], // offset   0

    /// Allowed-write bitmask written by the capavisor at registration time.
    /// A parent may only set bits in `dirty_mask` that are set here.
    /// Immutable after `THEMIS_REGISTER_COMM` returns.
    pub allowed_mask: [u64; VP_COMM_MASK_WORDS], // offset  24

    pub _hdr_pad: [u8; 16], // offset  48 — pad to 64

    // ── General-purpose registers (VpRegister 0x00–0x0E) ──────────────── //
    // offset 64
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,

    // ── Stack / instruction pointer / flags (VpRegister 0x10–0x12) ────── //
    // offset 184
    pub rsp: u64,
    pub rip: u64,
    pub rflags: u64,

    // ── Control registers + EFER + DR7 (VpRegister 0x20–0x24) ────────── //
    // offset 208
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub efer: u64,
    pub dr7: u64,

    // ── Segment selectors (VpRegister 0x30–0x37) ──────────────────────── //
    // offset 248
    pub cs_selector: u16,
    pub ds_selector: u16,
    pub es_selector: u16,
    pub fs_selector: u16,
    pub gs_selector: u16,
    pub ss_selector: u16,
    pub tr_selector: u16,
    pub ldtr_selector: u16,

    // ── Segment base addresses (VpRegister 0x40–0x47) ─────────────────── //
    // offset 264
    pub cs_base: u64,
    pub ds_base: u64,
    pub es_base: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub ss_base: u64,
    pub tr_base: u64,
    pub ldtr_base: u64,

    // ── Segment limits (VpRegister 0x50–0x57) ─────────────────────────── //
    // offset 328
    pub cs_limit: u32,
    pub ds_limit: u32,
    pub es_limit: u32,
    pub fs_limit: u32,
    pub gs_limit: u32,
    pub ss_limit: u32,
    pub tr_limit: u32,
    pub ldtr_limit: u32,

    // ── Segment access rights (VpRegister 0x60–0x67) ──────────────────── //
    // offset 360 — VMX access-rights encoding (see `access_rights` module)
    pub cs_access_rights: u32,
    pub ds_access_rights: u32,
    pub es_access_rights: u32,
    pub fs_access_rights: u32,
    pub gs_access_rights: u32,
    pub ss_access_rights: u32,
    pub tr_access_rights: u32,
    pub ldtr_access_rights: u32,

    // ── GDTR (VpRegister 0x70–0x71) ───────────────────────────────────── //
    // offset 392
    pub gdtr_base: u64,
    pub gdtr_limit: u16,
    pub _gdtr_pad: [u8; 6], // pad to 8-byte boundary

    // ── IDTR (VpRegister 0x72–0x73) ───────────────────────────────────── //
    // offset 408
    pub idtr_base: u64,
    pub idtr_limit: u16,
    pub _idtr_pad: [u8; 6], // pad to 8-byte boundary

    // ── SYSENTER MSRs (VpRegister 0x80–0x82) ──────────────────────────── //
    // offset 424
    pub sysenter_cs: u64,
    pub sysenter_esp: u64,
    pub sysenter_eip: u64,

    // ── Segment-related MSRs (VpRegister 0x90–0x92) ───────────────────── //
    // offset 448
    pub fs_base_msr: u64,
    pub gs_base_msr: u64,
    pub kernel_gs_base: u64,

    // ── APIC / virtual APIC (VpRegister 0xA0–0xA2) ────────────────────── //
    // offset 472
    pub apic_base: u64,
    pub tpr: u64, // read-only for parent; allowed_mask bit cleared
    pub ppr: u64, // read-only for parent; allowed_mask bit cleared

    // ── VMCS activity / interruptibility / PAT (VpRegister 0xB0–0xB2) ── //
    // offset 496
    pub activity_state: u32,
    pub interruptibility_state: u32,
    pub pat: u64, // offset 504

    // ── Padding to 4096 bytes ─────────────────────────────────────────── //
    // offset 512
    pub _pad: [u8; 3584],
}

const _VP_COMM_PAGE_SIZE_CHECK: () = assert!(core::mem::size_of::<VpCommPage>() == 4096);

impl VpCommPage {
    /// Return the `(word_index, bit_within_word)` for a given `VpRegister`
    /// in the `dirty_mask` / `allowed_mask` arrays.
    ///
    /// ```rust
    /// use themis_abi::regs::{VpCommPage, VpRegister};
    /// let (word, bit) = VpCommPage::mask_bit(VpRegister::Rip);
    /// assert_eq!(word, 0);
    /// assert_eq!(bit, VpRegister::Rip as u64 % 64);
    /// ```
    #[inline]
    pub const fn mask_bit(reg: VpRegister) -> (usize, u64) {
        let n = reg as u64;
        ((n / 64) as usize, n % 64)
    }

    /// Test whether a register's dirty bit is set.
    #[inline]
    pub fn is_dirty(&self, reg: VpRegister) -> bool {
        let (w, b) = Self::mask_bit(reg);
        self.dirty_mask[w] & (1 << b) != 0
    }

    /// Set a register's dirty bit.
    #[inline]
    pub fn mark_dirty(&mut self, reg: VpRegister) {
        let (w, b) = Self::mask_bit(reg);
        self.dirty_mask[w] |= 1 << b;
    }

    /// Clear a register's dirty bit (called by the capavisor after applying).
    #[inline]
    pub fn clear_dirty(&mut self, reg: VpRegister) {
        let (w, b) = Self::mask_bit(reg);
        self.dirty_mask[w] &= !(1 << b);
    }

    /// Test whether a register is writable by the parent (as set by capavisor).
    #[inline]
    pub fn is_allowed(&self, reg: VpRegister) -> bool {
        let (w, b) = Self::mask_bit(reg);
        self.allowed_mask[w] & (1 << b) != 0
    }

    /// Read a register value from the COMM page, zero-extended to u64.
    ///
    /// Selectors are stored as u16, limits and access rights as u32;
    /// all are zero-extended to u64 for a uniform interface.
    #[inline]
    pub fn read_reg(&self, reg: VpRegister) -> u64 {
        match reg {
            // GPRs (u64)
            VpRegister::Rax => self.rax,
            VpRegister::Rbx => self.rbx,
            VpRegister::Rcx => self.rcx,
            VpRegister::Rdx => self.rdx,
            VpRegister::Rsi => self.rsi,
            VpRegister::Rdi => self.rdi,
            VpRegister::Rbp => self.rbp,
            VpRegister::R8 => self.r8,
            VpRegister::R9 => self.r9,
            VpRegister::R10 => self.r10,
            VpRegister::R11 => self.r11,
            VpRegister::R12 => self.r12,
            VpRegister::R13 => self.r13,
            VpRegister::R14 => self.r14,
            VpRegister::R15 => self.r15,
            // Stack / IP / flags (u64)
            VpRegister::Rsp => self.rsp,
            VpRegister::Rip => self.rip,
            VpRegister::Rflags => self.rflags,
            // Control regs (u64)
            VpRegister::Cr0 => self.cr0,
            VpRegister::Cr3 => self.cr3,
            VpRegister::Cr4 => self.cr4,
            VpRegister::Efer => self.efer,
            VpRegister::Dr7 => self.dr7,
            // Segment selectors (u16 → u64)
            VpRegister::CsSelector => self.cs_selector as u64,
            VpRegister::DsSelector => self.ds_selector as u64,
            VpRegister::EsSelector => self.es_selector as u64,
            VpRegister::FsSelector => self.fs_selector as u64,
            VpRegister::GsSelector => self.gs_selector as u64,
            VpRegister::SsSelector => self.ss_selector as u64,
            VpRegister::TrSelector => self.tr_selector as u64,
            VpRegister::LdtrSelector => self.ldtr_selector as u64,
            // Segment bases (u64)
            VpRegister::CsBase => self.cs_base,
            VpRegister::DsBase => self.ds_base,
            VpRegister::EsBase => self.es_base,
            VpRegister::FsBase => self.fs_base,
            VpRegister::GsBase => self.gs_base,
            VpRegister::SsBase => self.ss_base,
            VpRegister::TrBase => self.tr_base,
            VpRegister::LdtrBase => self.ldtr_base,
            // Segment limits (u32 → u64)
            VpRegister::CsLimit => self.cs_limit as u64,
            VpRegister::DsLimit => self.ds_limit as u64,
            VpRegister::EsLimit => self.es_limit as u64,
            VpRegister::FsLimit => self.fs_limit as u64,
            VpRegister::GsLimit => self.gs_limit as u64,
            VpRegister::SsLimit => self.ss_limit as u64,
            VpRegister::TrLimit => self.tr_limit as u64,
            VpRegister::LdtrLimit => self.ldtr_limit as u64,
            // Segment access rights (u32 → u64)
            VpRegister::CsAccessRights => self.cs_access_rights as u64,
            VpRegister::DsAccessRights => self.ds_access_rights as u64,
            VpRegister::EsAccessRights => self.es_access_rights as u64,
            VpRegister::FsAccessRights => self.fs_access_rights as u64,
            VpRegister::GsAccessRights => self.gs_access_rights as u64,
            VpRegister::SsAccessRights => self.ss_access_rights as u64,
            VpRegister::TrAccessRights => self.tr_access_rights as u64,
            VpRegister::LdtrAccessRights => self.ldtr_access_rights as u64,
            // Descriptor tables
            VpRegister::GdtrBase => self.gdtr_base,
            VpRegister::GdtrLimit => self.gdtr_limit as u64,
            VpRegister::IdtrBase => self.idtr_base,
            VpRegister::IdtrLimit => self.idtr_limit as u64,
            // SYSENTER MSRs (u64)
            VpRegister::SysenterCs => self.sysenter_cs,
            VpRegister::SysenterEsp => self.sysenter_esp,
            VpRegister::SysenterEip => self.sysenter_eip,
            // Segment MSRs (u64)
            VpRegister::FsBaseMsr => self.fs_base_msr,
            VpRegister::GsBaseMsr => self.gs_base_msr,
            VpRegister::KernelGsBase => self.kernel_gs_base,
            // APIC (u64)
            VpRegister::ApicBase => self.apic_base,
            VpRegister::Tpr => self.tpr,
            VpRegister::Ppr => self.ppr,
            // Activity / interruptibility / PAT
            VpRegister::ActivityState => self.activity_state as u64,
            VpRegister::InterruptibilityState => self.interruptibility_state as u64,
            VpRegister::Pat => self.pat,
        }
    }

    /// Write a register value (u64, zero-extended) into the COMM page.
    ///
    /// Truncates to the natural width of the field (u16 for selectors,
    /// u32 for limits/access-rights/activity).
    #[inline]
    pub fn write_reg(&mut self, reg: VpRegister, val: u64) {
        match reg {
            VpRegister::Rax => self.rax = val,
            VpRegister::Rbx => self.rbx = val,
            VpRegister::Rcx => self.rcx = val,
            VpRegister::Rdx => self.rdx = val,
            VpRegister::Rsi => self.rsi = val,
            VpRegister::Rdi => self.rdi = val,
            VpRegister::Rbp => self.rbp = val,
            VpRegister::R8 => self.r8 = val,
            VpRegister::R9 => self.r9 = val,
            VpRegister::R10 => self.r10 = val,
            VpRegister::R11 => self.r11 = val,
            VpRegister::R12 => self.r12 = val,
            VpRegister::R13 => self.r13 = val,
            VpRegister::R14 => self.r14 = val,
            VpRegister::R15 => self.r15 = val,
            VpRegister::Rsp => self.rsp = val,
            VpRegister::Rip => self.rip = val,
            VpRegister::Rflags => self.rflags = val,
            VpRegister::Cr0 => self.cr0 = val,
            VpRegister::Cr3 => self.cr3 = val,
            VpRegister::Cr4 => self.cr4 = val,
            VpRegister::Efer => self.efer = val,
            VpRegister::Dr7 => self.dr7 = val,
            VpRegister::CsSelector => self.cs_selector = val as u16,
            VpRegister::DsSelector => self.ds_selector = val as u16,
            VpRegister::EsSelector => self.es_selector = val as u16,
            VpRegister::FsSelector => self.fs_selector = val as u16,
            VpRegister::GsSelector => self.gs_selector = val as u16,
            VpRegister::SsSelector => self.ss_selector = val as u16,
            VpRegister::TrSelector => self.tr_selector = val as u16,
            VpRegister::LdtrSelector => self.ldtr_selector = val as u16,
            VpRegister::CsBase => self.cs_base = val,
            VpRegister::DsBase => self.ds_base = val,
            VpRegister::EsBase => self.es_base = val,
            VpRegister::FsBase => self.fs_base = val,
            VpRegister::GsBase => self.gs_base = val,
            VpRegister::SsBase => self.ss_base = val,
            VpRegister::TrBase => self.tr_base = val,
            VpRegister::LdtrBase => self.ldtr_base = val,
            VpRegister::CsLimit => self.cs_limit = val as u32,
            VpRegister::DsLimit => self.ds_limit = val as u32,
            VpRegister::EsLimit => self.es_limit = val as u32,
            VpRegister::FsLimit => self.fs_limit = val as u32,
            VpRegister::GsLimit => self.gs_limit = val as u32,
            VpRegister::SsLimit => self.ss_limit = val as u32,
            VpRegister::TrLimit => self.tr_limit = val as u32,
            VpRegister::LdtrLimit => self.ldtr_limit = val as u32,
            VpRegister::CsAccessRights => self.cs_access_rights = val as u32,
            VpRegister::DsAccessRights => self.ds_access_rights = val as u32,
            VpRegister::EsAccessRights => self.es_access_rights = val as u32,
            VpRegister::FsAccessRights => self.fs_access_rights = val as u32,
            VpRegister::GsAccessRights => self.gs_access_rights = val as u32,
            VpRegister::SsAccessRights => self.ss_access_rights = val as u32,
            VpRegister::TrAccessRights => self.tr_access_rights = val as u32,
            VpRegister::LdtrAccessRights => self.ldtr_access_rights = val as u32,
            VpRegister::GdtrBase => self.gdtr_base = val,
            VpRegister::GdtrLimit => self.gdtr_limit = val as u16,
            VpRegister::IdtrBase => self.idtr_base = val,
            VpRegister::IdtrLimit => self.idtr_limit = val as u16,
            VpRegister::SysenterCs => self.sysenter_cs = val,
            VpRegister::SysenterEsp => self.sysenter_esp = val,
            VpRegister::SysenterEip => self.sysenter_eip = val,
            VpRegister::FsBaseMsr => self.fs_base_msr = val,
            VpRegister::GsBaseMsr => self.gs_base_msr = val,
            VpRegister::KernelGsBase => self.kernel_gs_base = val,
            VpRegister::ApicBase => self.apic_base = val,
            VpRegister::Tpr => self.tpr = val,
            VpRegister::Ppr => self.ppr = val,
            VpRegister::ActivityState => self.activity_state = val as u32,
            VpRegister::InterruptibilityState => self.interruptibility_state = val as u32,
            VpRegister::Pat => self.pat = val,
        }
    }
}

/// All valid `VpRegister` discriminants, in order.
///
/// Used by the capavisor to iterate over dirty bits and resolve each to
/// a `VpRegister` variant.
pub const ALL_VP_REGISTERS: &[VpRegister] = &[
    VpRegister::Rax,
    VpRegister::Rbx,
    VpRegister::Rcx,
    VpRegister::Rdx,
    VpRegister::Rsi,
    VpRegister::Rdi,
    VpRegister::Rbp,
    VpRegister::R8,
    VpRegister::R9,
    VpRegister::R10,
    VpRegister::R11,
    VpRegister::R12,
    VpRegister::R13,
    VpRegister::R14,
    VpRegister::R15,
    VpRegister::Rsp,
    VpRegister::Rip,
    VpRegister::Rflags,
    VpRegister::Cr0,
    VpRegister::Cr3,
    VpRegister::Cr4,
    VpRegister::Efer,
    VpRegister::Dr7,
    VpRegister::CsSelector,
    VpRegister::DsSelector,
    VpRegister::EsSelector,
    VpRegister::FsSelector,
    VpRegister::GsSelector,
    VpRegister::SsSelector,
    VpRegister::TrSelector,
    VpRegister::LdtrSelector,
    VpRegister::CsBase,
    VpRegister::DsBase,
    VpRegister::EsBase,
    VpRegister::FsBase,
    VpRegister::GsBase,
    VpRegister::SsBase,
    VpRegister::TrBase,
    VpRegister::LdtrBase,
    VpRegister::CsLimit,
    VpRegister::DsLimit,
    VpRegister::EsLimit,
    VpRegister::FsLimit,
    VpRegister::GsLimit,
    VpRegister::SsLimit,
    VpRegister::TrLimit,
    VpRegister::LdtrLimit,
    VpRegister::CsAccessRights,
    VpRegister::DsAccessRights,
    VpRegister::EsAccessRights,
    VpRegister::FsAccessRights,
    VpRegister::GsAccessRights,
    VpRegister::SsAccessRights,
    VpRegister::TrAccessRights,
    VpRegister::LdtrAccessRights,
    VpRegister::GdtrBase,
    VpRegister::GdtrLimit,
    VpRegister::IdtrBase,
    VpRegister::IdtrLimit,
    VpRegister::SysenterCs,
    VpRegister::SysenterEsp,
    VpRegister::SysenterEip,
    VpRegister::FsBaseMsr,
    VpRegister::GsBaseMsr,
    VpRegister::KernelGsBase,
    VpRegister::ApicBase,
    VpRegister::Tpr,
    VpRegister::Ppr,
    VpRegister::ActivityState,
    VpRegister::InterruptibilityState,
    VpRegister::Pat,
];

// ── Intercept message ────────────────────────────────────────────────────── //

/// Byte offset within the `VpCommPage` where the intercept message is stored.
pub const VP_COMM_INTERCEPT_OFFSET: usize = 512;

/// Message types (matches THEMIC_MSG_* in thhv.h).
pub const THEMIC_MSG_NONE: u32 = 0x0000;
pub const THEMIC_MSG_VP_INTERCEPT: u32 = 0x0001;

/// Message header preceding every message in the COMM page.
/// Matches `struct themic_message_header` in thhv.h (16 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ThemicMessageHeader {
    pub message_type: u32,
    pub payload_size: u32,
    pub sequence: u64,
}

/// VP exit intercept message — written by the capavisor to COMM page
/// offset 512 on a child VP exit.  The driver copies it to userspace.
///
/// Matches `struct themic_intercept_message` in thhv.h (120 bytes).
/// Slim intercept message — exit metadata only, no register values.
///
/// Register values live in the COMM page register area, gated by
/// `ExitPolicy.read_set`.  thhv reads registers from there and
/// assembles the full `themic_intercept_message` for CHV.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct InterceptMessage {
    pub header: ThemicMessageHeader,
    pub exit_reason: u32,
    pub instruction_length: u32,
    pub exit_qualification: u64,
    pub guest_physical_address: u64,
    // I/O port intercept fields (from exit_qualification, not registers).
    pub port_number: u16,
    pub access_size: u8,
    pub is_write: u8,
    pub _reserved: u32,
    // MMIO intercept fields.
    pub instruction_bytes: [u8; 16],
}

const _INTERCEPT_MSG_SIZE_CHECK: () = assert!(core::mem::size_of::<InterceptMessage>() == 64);
