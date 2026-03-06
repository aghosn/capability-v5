//! Linux bzImage boot protocol header parsing and kernel loading.
//!
//! A bzImage begins with a real-mode boot sector; the *setup header* lives at
//! byte offset `0x1f1` inside that sector.  We parse the fields Themis needs to
//! place the decompressed kernel and `struct boot_params` page when launching
//! dom0 (Phase 7).
//!
//! Reference: Linux `Documentation/arch/x86/boot.rst`, protocol version ≥ 2.12.
//! Struct layout: `arch/x86/include/uapi/asm/bootparam.h`.

extern crate alloc;

use super::ModuleInfo;
use crate::mem::PhysRegion;
use crate::serial_println;

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

// ── E820 memory map entry ─────────────────────────────────────────────────── //

/// E820 memory map entry as defined by the Linux boot protocol
/// (`arch/x86/include/uapi/asm/e820.h`).  Each entry is exactly 20 bytes.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C, packed)]
pub struct E820Entry {
    pub addr: u64,
    pub size: u64,
    pub entry_type: u32,
}

impl E820Entry {
    pub const TYPE_RAM:      u32 = 1;
    pub const TYPE_RESERVED: u32 = 2;
    pub const TYPE_ACPI:     u32 = 3;
    pub const TYPE_NVS:      u32 = 4;
}

// ── boot_params wrapper ───────────────────────────────────────────────────── //

/// Wrapper around the 4096-byte `struct boot_params` (Linux x86 boot protocol).
///
/// Fields are written by byte offset to avoid mirroring the full (complex,
/// partially-obsolete) C layout.  Offsets verified against Linux
/// `arch/x86/include/uapi/asm/bootparam.h`.
pub struct BootParams([u8; 4096]);

impl BootParams {
    // ── Byte offsets ──────────────────────────────────────────────────────── //
    /// Physical address of the ACPI RSDP to expose to dom0.
    const ACPI_RSDP_OFF:      usize = 0x070;
    /// Number of valid e820 entries (u8).
    const E820_ENTRIES_OFF:   usize = 0x1e8;
    // setup_header fields — header starts at 0x1f1 in boot_params:
    /// Bootloader type identifier (0xFF = undefined/custom).
    const TYPE_OF_LOADER_OFF: usize = 0x210;
    /// Load flags (bit 0 = LOADED_HIGH: kernel above 1 MiB).
    const LOADFLAGS_OFF:      usize = 0x211;
    /// 32-bit physical address of the initrd image.
    const RAMDISK_IMAGE_OFF:  usize = 0x218;
    /// Byte length of the initrd image.
    const RAMDISK_SIZE_OFF:   usize = 0x21c;
    /// 32-bit physical address of the NUL-terminated command-line string.
    const CMD_LINE_PTR_OFF:   usize = 0x228;
    /// Start of the e820 table (128 × 20-byte entries).
    const E820_TABLE_OFF:     usize = 0x2d0;
    const E820_ENTRY_SIZE:    usize = 20;
    const E820_MAX:           usize = 128;

    /// Create a zeroed `boot_params` page.
    pub fn new() -> Self {
        Self([0u8; 4096])
    }

    fn write_u8(&mut self, off: usize, v: u8) {
        self.0[off] = v;
    }
    fn write_u32(&mut self, off: usize, v: u32) {
        self.0[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn write_u64(&mut self, off: usize, v: u64) {
        self.0[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// Set `type_of_loader` (0xFF = custom/undefined bootloader).
    pub fn set_type_of_loader(&mut self, v: u8) {
        self.write_u8(Self::TYPE_OF_LOADER_OFF, v);
    }

    /// Set `loadflags` (use [`LOADFLAG_LOADED_HIGH`] if kernel is above 1 MiB).
    pub fn set_loadflags(&mut self, v: u8) {
        self.write_u8(Self::LOADFLAGS_OFF, v);
    }

    /// Set the 32-bit physical address of the NUL-terminated command-line string.
    pub fn set_cmd_line_ptr(&mut self, addr: u32) {
        self.write_u32(Self::CMD_LINE_PTR_OFF, addr);
    }

    /// Set initrd physical base and byte length (pass 0/0 if no initrd).
    pub fn set_ramdisk(&mut self, image: u32, size: u32) {
        self.write_u32(Self::RAMDISK_IMAGE_OFF, image);
        self.write_u32(Self::RAMDISK_SIZE_OFF, size);
    }

    /// Set the physical address of the ACPI RSDP passed to dom0 (0 = let Linux scan).
    pub fn set_acpi_rsdp_addr(&mut self, addr: u64) {
        self.write_u64(Self::ACPI_RSDP_OFF, addr);
    }

    /// Write the e820 memory table and entry count.  Panics if `entries.len() > 128`.
    pub fn set_e820_table(&mut self, entries: &[E820Entry]) {
        assert!(entries.len() <= Self::E820_MAX, "too many e820 entries");
        self.write_u8(Self::E820_ENTRIES_OFF, entries.len() as u8);
        let mut off = Self::E820_TABLE_OFF;
        for e in entries {
            self.0[off..off + 8].copy_from_slice(&e.addr.to_le_bytes());
            self.0[off + 8..off + 16].copy_from_slice(&e.size.to_le_bytes());
            self.0[off + 16..off + 20].copy_from_slice(&e.entry_type.to_le_bytes());
            off += Self::E820_ENTRY_SIZE;
        }
    }

    /// Raw byte slice (for copying into guest physical memory).
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// `loadflags` bit 0: kernel image was loaded above 1 MiB (`code32_start`).
pub const LOADFLAG_LOADED_HIGH: u8 = 1 << 0;

// ── Linux load result ─────────────────────────────────────────────────────── //

/// Physical addresses produced by [`load_linux`] that the VMCS guest state must
/// reflect at VM entry.
pub struct LinuxLoadInfo {
    /// Physical address of the protected-mode entry point (`code32_start`, 0x100000).
    pub kernel_entry_phys: u64,
    /// Physical address of `struct boot_params`.
    /// Must be in **ESI** at VMLAUNCH (GPR, not a VMCS field — pass to P7g).
    pub boot_params_phys: u64,
}

// ── Kernel loader ─────────────────────────────────────────────────────────── //

/// Physical layout used by [`load_linux`]:
///
/// | Address     | Content                         |
/// |-------------|---------------------------------|
/// | `0x0_7000`  | `struct boot_params` (4 KiB)    |
/// | `0x0_8000`  | Kernel command-line string       |
/// | `0x0_8FF8`  | Initial guest stack top          |
/// | `0x10_0000` | Protected-mode kernel image      |
/// | after kern  | Initrd, 4-KiB aligned (if any)  |
pub const BOOT_PARAMS_PHYS: u64  = 0x0_7000;
pub const CMDLINE_PHYS: u64      = 0x0_8000;
pub const INITIAL_RSP_PHYS: u64  = 0x0_8FF8;
pub const KERNEL_LOAD_PHYS: u64  = 0x10_0000;

/// Load a Linux bzImage into dom0 physical memory and write `struct boot_params`.
///
/// Entry mode: **32-bit protected mode via the decompressor** (UNRESTRICTED_GUEST,
/// PE=1, no paging).  The kernel's own `startup_32` decompresses the payload and
/// transitions to 64-bit long mode.  dom0's page tables (CR3) are allocated from
/// its normal (non-META) memory by the decompressor — Themis has no involvement.
///
/// # Arguments
/// * `kernel`       — Limine module carrying the bzImage (already HHDM-mapped).
/// * `initrd`       — Optional initrd Limine module.
/// * `hhdm_offset`  — HHDM offset for phys → virt address conversion.
/// * `dom0_regions` — dom0-owned physical regions; reported as e820 TYPE_RAM.
/// * `meta_pool`    — META pool region; reported as e820 TYPE_RESERVED (hole for Linux).
/// * `non_ram`      — Non-RAM e820 entries (RESERVED/ACPI/NVS) from the Limine map.
/// * `cmdline`      — Kernel command line (truncated to 255 bytes).
pub fn load_linux(
    kernel: &ModuleInfo,
    initrd: Option<&ModuleInfo>,
    hhdm_offset: u64,
    dom0_regions: &[PhysRegion],
    meta_pool: PhysRegion,
    non_ram: &[E820Entry],
    cmdline: &str,
) -> LinuxLoadInfo {
    // ── Parse bzImage header ─────────────────────────────────────────────── //
    let hdr = BootHeader::from_module(kernel)
        .expect("load_linux: invalid bzImage header");
    serial_println!(
        "  Linux boot protocol v{:#06x}  is_64bit={}  init_size={:#x}",
        hdr.version, hdr.is_64bit(), hdr.init_size,
    );

    // ── Copy protected-mode kernel to code32_start (0x100000) ───────────── //
    let pm_off = hdr.protected_mode_offset();
    let total  = kernel.size as usize;
    assert!(pm_off < total, "load_linux: bzImage smaller than protected_mode_offset");
    let pm_len = total - pm_off;

    // SAFETY: Limine guarantees the module is fully HHDM-mapped and readable.
    let src = unsafe { kernel.base.add(pm_off) };
    let dst = (KERNEL_LOAD_PHYS + hhdm_offset) as *mut u8;
    unsafe { core::ptr::copy_nonoverlapping(src, dst, pm_len); }
    serial_println!("  Kernel PM: {:#x} bytes → phys {:#x}", pm_len, KERNEL_LOAD_PHYS);

    // ── Place initrd immediately after the kernel, 4-KiB aligned ─────────── //
    let (initrd_phys, initrd_size): (u32, u32) = if let Some(rd) = initrd {
        let start = (KERNEL_LOAD_PHYS + pm_len as u64 + 0xFFF) & !0xFFF;
        let rd_dst = (start + hhdm_offset) as *mut u8;
        unsafe { core::ptr::copy_nonoverlapping(rd.base, rd_dst, rd.size as usize); }
        serial_println!("  Initrd:    {:#x} bytes → phys {:#x}", rd.size, start);
        (start as u32, rd.size as u32)
    } else {
        serial_println!("  Initrd:    none");
        (0, 0)
    };

    // ── Write command line ────────────────────────────────────────────────── //
    let cl_dst = (CMDLINE_PHYS + hhdm_offset) as *mut u8;
    let cl_bytes = cmdline.as_bytes();
    let cl_len = cl_bytes.len().min(255);
    unsafe {
        core::ptr::copy_nonoverlapping(cl_bytes.as_ptr(), cl_dst, cl_len);
        *cl_dst.add(cl_len) = 0; // NUL-terminate
    }
    serial_println!("  Cmdline:   {:?}", &cmdline[..cl_len]);

    // ── Build boot_params ─────────────────────────────────────────────────── //
    let mut bp = BootParams::new();
    bp.set_type_of_loader(0xFF);
    bp.set_loadflags(LOADFLAG_LOADED_HIGH);
    bp.set_cmd_line_ptr(CMDLINE_PHYS as u32);
    if initrd_phys != 0 {
        bp.set_ramdisk(initrd_phys, initrd_size);
    }
    // ACPI RSDP: 0 → Linux will scan for it.
    // TODO(P7f-dmar): replace with a DMAR-stripped RSDP pointer.
    bp.set_acpi_rsdp_addr(0);

    // ── Build complete e820 table ─────────────────────────────────────────── //
    // Combine: dom0-owned RAM + META pool hole + all non-RAM entries (ACPI/NVS/RESERVED).
    // Sort by base address so Linux sees a well-ordered map.
    let mut e820_buf = [E820Entry::default(); 128];
    let mut count = 0usize;

    let push = |buf: &mut [E820Entry; 128], n: &mut usize, e: E820Entry| {
        if *n < 128 { buf[*n] = e; *n += 1; }
    };

    for r in dom0_regions {
        push(&mut e820_buf, &mut count, E820Entry {
            addr: r.base, size: r.length, entry_type: E820Entry::TYPE_RAM,
        });
    }
    // META pool is carved from dom0_owned but owned by the hypervisor — mark reserved.
    if meta_pool.length > 0 {
        push(&mut e820_buf, &mut count, E820Entry {
            addr: meta_pool.base, size: meta_pool.length, entry_type: E820Entry::TYPE_RESERVED,
        });
    }
    for e in non_ram {
        push(&mut e820_buf, &mut count, *e);
    }

    // Sort entries by base address (insertion sort — small N, no alloc needed).
    let entries = &mut e820_buf[..count];
    for i in 1..entries.len() {
        let mut j = i;
        while j > 0 && entries[j - 1].addr > entries[j].addr {
            entries.swap(j - 1, j);
            j -= 1;
        }
    }

    bp.set_e820_table(&e820_buf[..count]);

    // Copy boot_params into guest physical memory via HHDM.
    let bp_dst = (BOOT_PARAMS_PHYS + hhdm_offset) as *mut u8;
    unsafe { core::ptr::copy_nonoverlapping(bp.as_bytes().as_ptr(), bp_dst, 4096); }
    serial_println!(
        "  boot_params @ {:#x}  e820_entries={}  (RAM={} META=1 non-RAM={})",
        BOOT_PARAMS_PHYS, count, dom0_regions.len(), non_ram.len(),
    );

    LinuxLoadInfo {
        kernel_entry_phys: KERNEL_LOAD_PHYS,
        boot_params_phys:  BOOT_PARAMS_PHYS,
    }
}
