// boot_descriptor.rs — Parse the Themis Boot Descriptor (TBD) blob.
//
// The boot script generates a small binary descriptor listing all modules
// (kernel, initrd, etc.) with their load addresses and sizes.  This is the
// AArch64 equivalent of Limine's module discovery on x86.
//
// Format (little-endian):
//   Header (16 bytes):
//     magic:   u32 = 0x5444_4253  ("TDBS" — Themis Descriptor Boot Spec)
//     version: u32 = 1
//     count:   u32 = number of module entries
//     _pad:    u32 = 0
//
//   Per-module entry (48 bytes):
//     addr: u64        — physical load address
//     size: u64        — size in bytes
//     name: [u8; 32]   — null-terminated ASCII name (e.g. "dom0-kernel")

use crate::guest::ModuleInfo;

const TBD_MAGIC: u32 = 0x5444_4253; // "TDBS" little-endian
const TBD_VERSION: u32 = 1;
const ENTRY_SIZE: usize = 48;
const NAME_LEN: usize = 32;

/// Parse the boot descriptor blob at the given physical address.
///
/// Returns up to `MAX` modules.  The blob must be identity-mapped and readable.
///
/// # Safety
/// `base` must point to a valid, identity-mapped boot descriptor blob.
pub unsafe fn parse_descriptor<const MAX: usize>(
    base: *const u8,
) -> Result<([ModuleInfo; MAX], usize), &'static str> {
    let magic = read_u32(base, 0);
    if magic != TBD_MAGIC {
        return Err("boot descriptor: bad magic");
    }

    let version = read_u32(base, 4);
    if version != TBD_VERSION {
        return Err("boot descriptor: unsupported version");
    }

    let count = read_u32(base, 8) as usize;
    if count > MAX {
        return Err("boot descriptor: too many modules");
    }

    // Zero-init the output array.
    let mut modules: [ModuleInfo; MAX] = core::array::from_fn(|_| ModuleInfo {
        base: core::ptr::null(),
        size: 0,
        cmdline: "",
        path: "",
    });

    let entries_base = base.add(16); // skip header

    for i in 0..count {
        let entry = entries_base.add(i * ENTRY_SIZE);
        let addr = read_u64(entry, 0);
        let size = read_u64(entry, 8);

        // Name: find null terminator within NAME_LEN bytes.
        let name_ptr = entry.add(16);
        let mut name_len = 0;
        while name_len < NAME_LEN {
            if *name_ptr.add(name_len) == 0 {
                break;
            }
            name_len += 1;
        }

        // SAFETY: The descriptor blob lives for the entire program lifetime
        // (loaded by QEMU before entry, never freed).
        let name_slice = core::slice::from_raw_parts(name_ptr, name_len);
        let name = core::str::from_utf8(name_slice).unwrap_or("<invalid-utf8>");

        modules[i] = ModuleInfo {
            base: addr as *const u8,
            size,
            cmdline: name,
            path: "",
        };
    }

    Ok((modules, count))
}

fn read_u32(base: *const u8, offset: usize) -> u32 {
    unsafe {
        let ptr = base.add(offset) as *const u32;
        ptr.read_unaligned()
    }
}

fn read_u64(base: *const u8, offset: usize) -> u64 {
    unsafe {
        let ptr = base.add(offset) as *const u64;
        ptr.read_unaligned()
    }
}
