//! Linux bzImage boot protocol header parsing.
//!
//! A bzImage begins with a real-mode boot sector; the *setup header* lives at
//! byte offset `0x1f1` inside that sector.  We parse the fields Themis needs to
//! place the decompressed kernel and `struct boot_params` page when launching
//! dom0 (Phase 7).
//!
//! Reference: Linux `Documentation/arch/x86/boot.rst`, protocol version ≥ 2.12.
//! Struct layout: `arch/x86/include/uapi/asm/bootparam.h`.

use super::ModuleInfo;

// ── Constants ───────────────────────────────────────────────────────────── //

/// Byte offset of the setup header inside the bzImage.
const SETUP_HEADER_OFFSET: usize = 0x1f1;

/// Expected magic value at offset 0x202 (`"HdrS"` in little-endian).
const HDRS_MAGIC: u32 = 0x5372_6448;

/// Minimum boot protocol version we require (2.12).
const MIN_PROTOCOL_VERSION: u16 = 0x020c;

// ── Setup header (raw, on-disk layout) ──────────────────────────────────── //

/// Raw setup header as laid out in the bzImage starting at offset 0x1f1.
///
/// Only the fields Themis needs are named; the rest are reserved padding so
/// that the field offsets match the Linux spec exactly.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct RawSetupHeader {
    // 0x1f1
    setup_sects: u8,
    // 0x1f2
    root_flags: u16,
    // 0x1f4
    syssize: u32,
    // 0x1f8
    _ram_size: u16,
    // 0x1fa
    vid_mode: u16,
    // 0x1fc
    root_dev: u16,
    // 0x1fe
    boot_flag: u16,
    // 0x200
    _jump: u16,
    // 0x202
    header: u32,
    // 0x206
    version: u16,
    // 0x208
    _realmode_swtch: u32,
    // 0x20c
    _start_sys_seg: u16,
    // 0x20e
    _kernel_version: u16,
    // 0x210
    type_of_loader: u8,
    // 0x211
    loadflags: u8,
    // 0x212
    _setup_move_size: u16,
    // 0x214
    code32_start: u32,
    // 0x218
    ramdisk_image: u32,
    // 0x21c
    ramdisk_size: u32,
    // 0x220
    _bootsect_kludge: u32,
    // 0x224
    _heap_end_ptr: u16,
    // 0x226
    _ext_loader_ver: u8,
    // 0x227
    _ext_loader_type: u8,
    // 0x228
    cmd_line_ptr: u32,
    // 0x22c
    _initrd_addr_max: u32,
    // 0x230
    kernel_alignment: u32,
    // 0x234
    relocatable_kernel: u8,
    // 0x235
    min_alignment: u8,
    // 0x236
    xloadflags: u16,
    // 0x238
    cmdline_size: u32,
    // 0x23c
    _hardware_subarch: u32,
    // 0x240
    _hardware_subarch_data: u64,
    // 0x248
    payload_offset: u32,
    // 0x24c
    payload_length: u32,
    // 0x250
    _setup_data: u64,
    // 0x258
    pref_address: u64,
    // 0x260
    init_size: u32,
    // 0x264
    _handover_offset: u32,
}

// ── Public parsed header ────────────────────────────────────────────────── //

/// Parsed Linux boot protocol header with the fields Themis needs.
#[derive(Debug, Clone, Copy)]
pub struct BootHeader {
    /// Boot protocol version (e.g. 0x020f = 2.15).
    pub version: u16,
    /// Number of 512-byte setup sectors (0 means 4).
    pub setup_sects: u8,
    /// Preferred load address for the protected-mode kernel (typically 0x100_0000).
    pub pref_address: u64,
    /// Required alignment for the kernel load address.
    pub kernel_alignment: u32,
    /// Amount of linear memory the kernel requires at boot, starting from
    /// `pref_address` (or the aligned load address).  Covers the decompressed
    /// kernel, BSS, and the decompressor's scratch space.
    pub init_size: u32,
    /// Offset from the start of the protected-mode code to the compressed
    /// payload.  The protected-mode code starts at `(setup_sects + 1) * 512`.
    pub payload_offset: u32,
    /// Length of the compressed payload in bytes.
    pub payload_length: u32,
    /// The 32-bit entry point (physical address) for the protected-mode kernel.
    pub code32_start: u32,
    /// Whether the kernel can be loaded at any aligned address.
    pub relocatable: bool,
    /// Load flags (bit 0 = LOADED_HIGH — kernel must be loaded above 1 MiB).
    pub loadflags: u8,
    /// Extended load flags (bit 0 = XLF_KERNEL_64, bit 1 = XLF_CAN_BE_LOADED_ABOVE_4G, …).
    pub xloadflags: u16,
    /// Maximum size of the kernel command line (bytes).
    pub cmdline_size: u32,
}

/// Errors that can occur when parsing a bzImage header.
#[derive(Debug, Clone, Copy)]
pub enum BootHeaderError {
    /// The module is too small to contain a setup header.
    TooSmall,
    /// The `HdrS` magic at offset 0x202 is missing.
    BadMagic(u32),
    /// The boot protocol version is older than the minimum we support.
    OldProtocol(u16),
}

impl BootHeader {
    /// Parse a `BootHeader` from a bzImage loaded by Limine.
    ///
    /// # Safety
    /// `module.base` must point to a valid, readable Limine-loaded module of
    /// at least `module.size` bytes.  This is always the case when the
    /// `ModuleInfo` comes from `ModuleInfo::from_limine_file()`.
    pub fn from_module(module: &ModuleInfo) -> Result<Self, BootHeaderError> {
        let required = SETUP_HEADER_OFFSET + core::mem::size_of::<RawSetupHeader>();
        if (module.size as usize) < required {
            return Err(BootHeaderError::TooSmall);
        }

        // Safety: Limine guarantees the module memory is mapped and readable
        // via the HHDM.  We checked the size above.
        let raw: RawSetupHeader = unsafe {
            let ptr = module.base.add(SETUP_HEADER_OFFSET);
            core::ptr::read_unaligned(ptr as *const RawSetupHeader)
        };

        if raw.header != HDRS_MAGIC {
            return Err(BootHeaderError::BadMagic(raw.header));
        }
        if raw.version < MIN_PROTOCOL_VERSION {
            return Err(BootHeaderError::OldProtocol(raw.version));
        }

        Ok(Self {
            version: raw.version,
            setup_sects: if raw.setup_sects == 0 { 4 } else { raw.setup_sects },
            pref_address: raw.pref_address,
            kernel_alignment: raw.kernel_alignment,
            init_size: raw.init_size,
            payload_offset: raw.payload_offset,
            payload_length: raw.payload_length,
            code32_start: raw.code32_start,
            relocatable: raw.relocatable_kernel != 0,
            loadflags: raw.loadflags,
            xloadflags: raw.xloadflags,
            cmdline_size: raw.cmdline_size,
        })
    }

    /// Byte offset where the protected-mode kernel starts in the bzImage.
    pub fn protected_mode_offset(&self) -> usize {
        (self.setup_sects as usize + 1) * 512
    }

    /// Byte offset of the compressed payload within the bzImage.
    pub fn payload_file_offset(&self) -> usize {
        self.protected_mode_offset() + self.payload_offset as usize
    }

    /// `true` if the kernel supports 64-bit entry (`XLF_KERNEL_64`).
    pub fn is_64bit(&self) -> bool {
        self.xloadflags & 0x01 != 0
    }

    /// `true` if the kernel can be loaded above 4 GiB (`XLF_CAN_BE_LOADED_ABOVE_4G`).
    pub fn can_load_above_4g(&self) -> bool {
        self.xloadflags & 0x02 != 0
    }
}
