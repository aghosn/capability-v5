//! Typed decoders for VMCS fields whose raw bit layout is otherwise
//! repeatedly open-coded in handlers.
//!
//! Currently covers:
//!   - `EXIT_QUALIFICATION` (reason-dependent decode: IO / APIC / EPT / CR /
//!     SIPI), wrapped by [`ExitQualification`].
//!   - VM-exit / VM-entry interruption-info (SDM Vol 3C §24.9.2, §26.6),
//!     wrapped by [`IntrInfo`].
//!
//! Each wrapper exposes named accessors and bit-builders so callers never
//! open-code `>> N & MASK` or `1 << K` over architectural fields.
//!
//! Pattern inspired by `vmxvmm::crates::vmx::bitmaps::exit_qualification`.

use crate::vcpu::{ActiveVcpu, Reg};
use crate::arch::x86_64::vcpu_ext::ActiveVcpuExt;

// ── Wrapper ─────────────────────────────────────────────────────────────── //

/// A raw VMX exit qualification word.  Interpret with a reason-specific
/// decoder (`.io()`, `.ept()`, `.apic()`, `.cr()`, `.sipi()`).
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)] // `raw`/`ept` are part of the public decoder surface.
pub struct ExitQualification(pub u64);

#[allow(dead_code)] // `raw`/`ept` part of decoder API surface.
impl ExitQualification {
    #[inline]
    pub fn raw(self) -> u64 {
        self.0
    }

    /// Decode as an I/O-instruction exit (reason 30).  Bit layout per SDM
    /// Table 27-5.
    #[inline]
    pub fn io(self) -> IoExitInfo {
        IoExitInfo::from_raw(self.0)
    }

    /// Decode as an EPT-violation exit (reason 48).  Bit layout per SDM
    /// Table 27-7.
    #[inline]
    pub fn ept(self) -> EptViolationInfo {
        EptViolationInfo(self.0)
    }

    /// Decode as an APIC-access exit (reason 44).  Bit layout per SDM
    /// Table 27-6.
    #[inline]
    pub fn apic(self) -> ApicAccessInfo {
        ApicAccessInfo::from_raw(self.0)
    }

    /// Decode as a control-register-access exit (reason 28).  Bit layout per
    /// SDM Table 27-3.
    #[inline]
    pub fn cr(self) -> CrAccessInfo {
        CrAccessInfo::from_raw(self.0)
    }

    /// Decode as a SIPI exit (reason 4).  Low byte is the vector page.
    #[inline]
    pub fn sipi_vector_page(self) -> u8 {
        (self.0 & 0xFF) as u8
    }
}

// ── I/O instruction ──────────────────────────────────────────────────────── //

/// Decoded I/O-instruction exit qualification (SDM Vol 3C §27.2.1 Table 27-5).
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)] // `is_string`/`is_rep` exposed for callers that emulate INS/OUTS.
pub struct IoExitInfo {
    /// Operand size in bytes (1, 2, or 4).
    pub size: u8,
    /// `true` for OUT (guest → port), `false` for IN.
    pub is_write: bool,
    /// String instruction (INS/OUTS) — `true` if set.
    pub is_string: bool,
    /// REP-prefixed (only valid when `is_string`).
    pub is_rep: bool,
    /// Port number.  If the qualification's operand-encoding bit indicates
    /// "port in DX", this field is `None` and the caller must read DX.
    pub port: Option<u16>,
}

// SDM Table 27-5 I/O-instruction qualification layout.
mod io_qual {
    /// Operand size encoding — bits 2:0 (encoded value + 1 = byte count).
    pub const SIZE_SHIFT: u32 = 0;
    pub const SIZE_MASK: u64 = 0b111;
    /// Direction — bit 3 (0 = OUT/write, 1 = IN/read).
    pub const DIRECTION_BIT: u64 = 1 << 3;
    /// String instruction (INS/OUTS) — bit 4.
    pub const STRING_BIT: u64 = 1 << 4;
    /// REP-prefixed — bit 5.
    pub const REP_BIT: u64 = 1 << 5;
    /// Operand encoding — bit 6 (0 = port in DX, 1 = immediate port).
    pub const IMMEDIATE_BIT: u64 = 1 << 6;
    /// Port number (when `IMMEDIATE_BIT` set) — bits 31:16.
    pub const PORT_SHIFT: u32 = 16;
    pub const PORT_MASK: u64 = 0xFFFF;
}

impl IoExitInfo {
    fn from_raw(qual: u64) -> Self {
        use io_qual::*;
        let size = (((qual >> SIZE_SHIFT) & SIZE_MASK) as u8) + 1;
        let is_write = qual & DIRECTION_BIT == 0;
        let is_string = qual & STRING_BIT != 0;
        let is_rep = qual & REP_BIT != 0;
        let port = if qual & IMMEDIATE_BIT != 0 {
            Some(((qual >> PORT_SHIFT) & PORT_MASK) as u16)
        } else {
            None
        };
        Self {
            size,
            is_write,
            is_string,
            is_rep,
            port,
        }
    }

    /// Resolve `port`, falling back to the guest's DX when the operand
    /// encoding indicates "port in DX".
    #[inline]
    pub fn port_or_dx(&self, vcpu: &ActiveVcpu) -> u16 {
        self.port
            .unwrap_or_else(|| (vcpu.reg(Reg::Rdx) & 0xFFFF) as u16)
    }
}

// ── EPT violation ────────────────────────────────────────────────────────── //

/// Decoded EPT-violation qualification (SDM Vol 3C §27.2.1 Table 27-7).
///
/// Kept as a transparent newtype so callers can pattern on individual bits
/// without paying for an upfront field decode.
#[derive(Clone, Copy, Debug)]
pub struct EptViolationInfo(pub u64);

impl EptViolationInfo {
    #[inline]
    #[allow(dead_code)] // Part of decoder API surface.
    pub fn raw(self) -> u64 {
        self.0
    }
}

#[allow(dead_code)] // Accessor surface kept for future consumers (ExitInfo::EptViolation still carries the raw qual).
impl EptViolationInfo {
    #[inline]
    pub fn is_read(self) -> bool {
        self.0 & (1 << 0) != 0
    }
    #[inline]
    pub fn is_write(self) -> bool {
        self.0 & (1 << 1) != 0
    }
    #[inline]
    pub fn is_instr_fetch(self) -> bool {
        self.0 & (1 << 2) != 0
    }
    /// EPT-mapping bits at time of the violation (R, W, X) for the target GPA.
    #[inline]
    pub fn ept_readable(self) -> bool {
        self.0 & (1 << 3) != 0
    }
    #[inline]
    pub fn ept_writable(self) -> bool {
        self.0 & (1 << 4) != 0
    }
    #[inline]
    pub fn ept_executable(self) -> bool {
        self.0 & (1 << 5) != 0
    }
    /// Guest linear address field in the VMCS is valid.
    #[inline]
    pub fn guest_linear_valid(self) -> bool {
        self.0 & (1 << 7) != 0
    }
    /// Violation was caused by translating the linear address (vs page-walk).
    #[inline]
    pub fn caused_by_translation(self) -> bool {
        self.0 & (1 << 8) != 0
    }
    /// NMI unblocking due to IRET.
    #[inline]
    pub fn nmi_unblocking_by_iret(self) -> bool {
        self.0 & (1 << 12) != 0
    }
}

// ── APIC access ──────────────────────────────────────────────────────────── //

/// Access type field of an APIC-access qualification (SDM Table 27-6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApicAccessType {
    DataRead = 0,
    DataWrite = 1,
    InstrFetch = 2,
    EventDeliveryLinear = 3,
    /// Linear-mode access of an unrecognized kind (bits 15:12 outside the
    /// linear-access range we explicitly enumerate).
    OtherLinear,
    /// GPA-mode access (any of 10–15); offset is meaningless in this case.
    Gpa,
}

impl ApicAccessType {
    fn from_raw(acc: u64) -> Self {
        use apic_qual::*;
        match acc {
            TYPE_DATA_READ => Self::DataRead,
            TYPE_DATA_WRITE => Self::DataWrite,
            TYPE_INSTR_FETCH => Self::InstrFetch,
            TYPE_EVENT_DELIVERY_LINEAR => Self::EventDeliveryLinear,
            x if x <= TYPE_OTHER_LINEAR_END => Self::OtherLinear,
            _ => Self::Gpa,
        }
    }
}

// SDM Table 27-6 APIC-access qualification layout.
mod apic_qual {
    /// Access offset within the 4 KiB APIC page — bits 11:0.
    pub const OFFSET_SHIFT: u32 = 0;
    pub const OFFSET_MASK: u64 = 0xFFF;
    /// Access type — bits 15:12.
    pub const ACCESS_TYPE_SHIFT: u32 = 12;
    pub const ACCESS_TYPE_MASK: u64 = 0xF;

    // SDM-defined access-type codes.
    pub const TYPE_DATA_READ: u64 = 0;
    pub const TYPE_DATA_WRITE: u64 = 1;
    pub const TYPE_INSTR_FETCH: u64 = 2;
    pub const TYPE_EVENT_DELIVERY_LINEAR: u64 = 3;
    /// Codes 4..=9 are linear-mode accesses we don't enumerate individually.
    pub const TYPE_OTHER_LINEAR_END: u64 = 9;
    // Codes 10..=15 are GPA-mode accesses.
}

/// Decoded APIC-access qualification.
#[derive(Clone, Copy, Debug)]
pub struct ApicAccessInfo {
    /// Byte offset within the 4 KiB APIC-access page, or `None` for GPA
    /// access types.
    pub offset: Option<usize>,
    pub access: ApicAccessType,
}

impl ApicAccessInfo {
    fn from_raw(qual: u64) -> Self {
        use apic_qual::*;
        let access =
            ApicAccessType::from_raw((qual >> ACCESS_TYPE_SHIFT) & ACCESS_TYPE_MASK);
        let offset = match access {
            ApicAccessType::Gpa => None,
            _ => Some(((qual >> OFFSET_SHIFT) & OFFSET_MASK) as usize),
        };
        Self { offset, access }
    }
}

// ── CR access ────────────────────────────────────────────────────────────── //

/// Control register identified by an exit qualification (bits 3:0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlReg {
    Cr0,
    Cr3,
    Cr4,
    Cr8,
    Other(u8),
}

// SDM Table 27-3 CR-access qualification layout.
mod cr_qual {
    /// CR number — bits 3:0.
    pub const CR_NUM_SHIFT: u32 = 0;
    pub const CR_NUM_MASK: u64 = 0xF;
    /// Access type — bits 5:4.
    pub const ACCESS_TYPE_SHIFT: u32 = 4;
    pub const ACCESS_TYPE_MASK: u64 = 0x3;
    /// LMSW operand source — bit 6 (0 = register, 1 = memory).
    pub const LMSW_MEMORY_BIT: u64 = 1 << 6;
    /// GPR index — bits 11:8.
    pub const GPR_INDEX_SHIFT: u32 = 8;
    pub const GPR_INDEX_MASK: u64 = 0xF;
    /// LMSW source data — bits 31:16 (only meaningful for the LMSW access type).
    pub const LMSW_SOURCE_SHIFT: u32 = 16;
    pub const LMSW_SOURCE_MASK: u64 = 0xFFFF;

    // SDM-defined access-type codes (the 2-bit value at ACCESS_TYPE_SHIFT).
    pub const ACCESS_MOV_TO_CR: u64 = 0;
    pub const ACCESS_MOV_FROM_CR: u64 = 1;
    pub const ACCESS_CLTS: u64 = 2;
    pub const ACCESS_LMSW: u64 = 3;

    // SDM-defined control-register encodings (bits 3:0).
    pub const CR_ENCODING_CR0: u8 = 0;
    pub const CR_ENCODING_CR3: u8 = 3;
    pub const CR_ENCODING_CR4: u8 = 4;
    pub const CR_ENCODING_CR8: u8 = 8;
}

impl ControlReg {
    fn from_raw(num: u8) -> Self {
        match num {
            cr_qual::CR_ENCODING_CR0 => Self::Cr0,
            cr_qual::CR_ENCODING_CR3 => Self::Cr3,
            cr_qual::CR_ENCODING_CR4 => Self::Cr4,
            cr_qual::CR_ENCODING_CR8 => Self::Cr8,
            n => Self::Other(n),
        }
    }
}

/// Guest general-purpose register identified by SDM Table 27-3 encoding
/// (CR-access exit qualification bits 11:8).
///
/// The discriminant is the SDM index, *not* the `Reg::*` discriminant — the
/// two enums differ because `Reg` omits `Rsp` (which lives in the VMCS).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gpr {
    Rax,
    Rcx,
    Rdx,
    Rbx,
    Rsp,
    Rbp,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

impl Gpr {
    /// SDM 4-bit GPR encoding: 0=RAX,1=RCX,2=RDX,3=RBX,4=RSP,5=RBP,6=RSI,
    /// 7=RDI,8–15=R8–R15.  Panics on out-of-range input (4-bit field is
    /// always 0..=15, so this is unreachable in practice).
    fn from_index(idx: u8) -> Self {
        match idx {
            0 => Self::Rax,
            1 => Self::Rcx,
            2 => Self::Rdx,
            3 => Self::Rbx,
            4 => Self::Rsp,
            5 => Self::Rbp,
            6 => Self::Rsi,
            7 => Self::Rdi,
            8 => Self::R8,
            9 => Self::R9,
            10 => Self::R10,
            11 => Self::R11,
            12 => Self::R12,
            13 => Self::R13,
            14 => Self::R14,
            15 => Self::R15,
            _ => unreachable!("4-bit field cannot exceed 15"),
        }
    }

    /// Read the current guest value of this GPR (RSP is sourced from the
    /// VMCS, all others from the register file).
    pub fn read(self, vcpu: &ActiveVcpu) -> u64 {
        match self {
            Self::Rax => vcpu.reg(Reg::Rax),
            Self::Rbx => vcpu.reg(Reg::Rbx),
            Self::Rcx => vcpu.reg(Reg::Rcx),
            Self::Rdx => vcpu.reg(Reg::Rdx),
            Self::Rsp => vcpu.rsp(),
            Self::Rbp => vcpu.reg(Reg::Rbp),
            Self::Rsi => vcpu.reg(Reg::Rsi),
            Self::Rdi => vcpu.reg(Reg::Rdi),
            Self::R8 => vcpu.reg(Reg::R8),
            Self::R9 => vcpu.reg(Reg::R9),
            Self::R10 => vcpu.reg(Reg::R10),
            Self::R11 => vcpu.reg(Reg::R11),
            Self::R12 => vcpu.reg(Reg::R12),
            Self::R13 => vcpu.reg(Reg::R13),
            Self::R14 => vcpu.reg(Reg::R14),
            Self::R15 => vcpu.reg(Reg::R15),
        }
    }

    /// Write the guest value of this GPR.
    pub fn write(self, vcpu: &mut ActiveVcpu, val: u64) {
        match self {
            Self::Rax => vcpu.set_reg(Reg::Rax, val),
            Self::Rbx => vcpu.set_reg(Reg::Rbx, val),
            Self::Rcx => vcpu.set_reg(Reg::Rcx, val),
            Self::Rdx => vcpu.set_reg(Reg::Rdx, val),
            Self::Rsp => vcpu.set_rsp(val),
            Self::Rbp => vcpu.set_reg(Reg::Rbp, val),
            Self::Rsi => vcpu.set_reg(Reg::Rsi, val),
            Self::Rdi => vcpu.set_reg(Reg::Rdi, val),
            Self::R8 => vcpu.set_reg(Reg::R8, val),
            Self::R9 => vcpu.set_reg(Reg::R9, val),
            Self::R10 => vcpu.set_reg(Reg::R10, val),
            Self::R11 => vcpu.set_reg(Reg::R11, val),
            Self::R12 => vcpu.set_reg(Reg::R12, val),
            Self::R13 => vcpu.set_reg(Reg::R13, val),
            Self::R14 => vcpu.set_reg(Reg::R14, val),
            Self::R15 => vcpu.set_reg(Reg::R15, val),
        }
    }
}

/// Decoded CR-access qualification (SDM Vol 3C §27.2.1 Table 27-3).
///
/// All operand registers are resolved upfront, so consumers never touch raw
/// indices.  `Lmsw` carries the immediate source value rather than a GPR.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)] // Lmsw payload kept for completeness; CLTS/LMSW not emulated yet.
pub enum CrAccessInfo {
    MovToCr { cr: ControlReg, src: Gpr },
    MovFromCr { cr: ControlReg, dst: Gpr },
    Clts,
    LmswRegister { src: Gpr, lmsw_source: u16 },
    LmswMemory { lmsw_source: u16 },
}

impl CrAccessInfo {
    fn from_raw(qual: u64) -> Self {
        use cr_qual::*;
        let cr =
            ControlReg::from_raw(((qual >> CR_NUM_SHIFT) & CR_NUM_MASK) as u8);
        let acc = (qual >> ACCESS_TYPE_SHIFT) & ACCESS_TYPE_MASK;
        let lmsw_mem = qual & LMSW_MEMORY_BIT != 0;
        let gpr = Gpr::from_index(((qual >> GPR_INDEX_SHIFT) & GPR_INDEX_MASK) as u8);
        let lmsw_source = ((qual >> LMSW_SOURCE_SHIFT) & LMSW_SOURCE_MASK) as u16;
        match acc {
            ACCESS_MOV_TO_CR => Self::MovToCr { cr, src: gpr },
            ACCESS_MOV_FROM_CR => Self::MovFromCr { cr, dst: gpr },
            ACCESS_CLTS => Self::Clts,
            ACCESS_LMSW if lmsw_mem => Self::LmswMemory { lmsw_source },
            ACCESS_LMSW => Self::LmswRegister {
                src: gpr,
                lmsw_source,
            },
            _ => unreachable!("2-bit field"),
        }
    }
}

// ── VM-exit / VM-entry interruption information ─────────────────────────── //

/// Interruption type field (SDM Vol 3C §24.9.2, Table 24-15).
#[allow(dead_code)] // full SDM-defined set; not all variants are observed today.
pub mod intr_type {
    pub const EXTERNAL_INTERRUPT: u8 = 0;
    pub const NMI: u8 = 2;
    pub const HARDWARE_EXCEPTION: u8 = 3;
    pub const SOFTWARE_INTERRUPT: u8 = 4;
    pub const PRIVILEGED_SW_EXCEPTION: u8 = 5;
    pub const SOFTWARE_EXCEPTION: u8 = 6;
    pub const OTHER_EVENT: u8 = 7;
}

// Bit layout of VMEXIT_INTERRUPTION_INFO / VMENTRY_INTERRUPTION_INFO_FIELD.
mod intr_info_bits {
    pub const VECTOR_SHIFT: u32 = 0;
    pub const VECTOR_MASK: u64 = 0xFF;
    pub const TYPE_SHIFT: u32 = 8;
    pub const TYPE_MASK: u64 = 0x7;
    pub const DELIVERS_ERROR_CODE_BIT: u64 = 1 << 11;
    pub const VALID_BIT: u64 = 1 << 31;
}

/// Decoded VM-exit interruption-info field (SDM Vol 3C §24.9.2) — also
/// re-usable to *build* a VM-entry interruption-info field (§26.6) via
/// [`IntrInfo::encode`].
#[derive(Clone, Copy, Debug)]
pub struct IntrInfo(pub u64);

#[allow(dead_code)] // `is_valid` part of public API surface.
impl IntrInfo {
    #[inline]
    pub fn vector(self) -> u8 {
        ((self.0 >> intr_info_bits::VECTOR_SHIFT) & intr_info_bits::VECTOR_MASK) as u8
    }

    #[inline]
    pub fn intr_type(self) -> u8 {
        ((self.0 >> intr_info_bits::TYPE_SHIFT) & intr_info_bits::TYPE_MASK) as u8
    }

    #[inline]
    pub fn delivers_error_code(self) -> bool {
        self.0 & intr_info_bits::DELIVERS_ERROR_CODE_BIT != 0
    }

    #[inline]
    pub fn is_valid(self) -> bool {
        self.0 & intr_info_bits::VALID_BIT != 0
    }

    /// Build a valid VM-entry interruption-info word.
    #[inline]
    pub fn encode(vector: u8, intr_type: u8, delivers_error_code: bool) -> u64 {
        use intr_info_bits::*;
        let mut word = VALID_BIT
            | ((intr_type as u64) << TYPE_SHIFT)
            | ((vector as u64) << VECTOR_SHIFT);
        if delivers_error_code {
            word |= DELIVERS_ERROR_CODE_BIT;
        }
        word
    }
}
