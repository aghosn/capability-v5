// fdt_patch.rs — Minimal FDT binary patcher for adding properties.
//
// Used to add linux,initrd-start / linux,initrd-end to /chosen before
// handing the FDT to the Linux guest. QEMU pads its FDT to ~1 MiB,
// so there is always room to insert a few extra properties.

use core::ptr;

const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;

fn align4(x: usize) -> usize {
    (x + 3) & !3
}

/// Read a big-endian u32 from an FDT byte slice.
fn get_u32(fdt: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([fdt[off], fdt[off + 1], fdt[off + 2], fdt[off + 3]])
}

/// Write a big-endian u32 into an FDT byte slice.
fn put_u32(fdt: &mut [u8], off: usize, val: u32) {
    let bytes = val.to_be_bytes();
    fdt[off..off + 4].copy_from_slice(&bytes);
}

/// Write a big-endian u64 into an FDT byte slice.
fn put_u64(fdt: &mut [u8], off: usize, val: u64) {
    let bytes = val.to_be_bytes();
    fdt[off..off + 8].copy_from_slice(&bytes);
}

/// Find a node by name in the structure block. Returns the offset of the
/// first token AFTER the node name (i.e., the start of its properties/children).
fn find_node(fdt: &[u8], struct_off: usize, struct_size: usize, name: &[u8]) -> Option<usize> {
    let end = struct_off + struct_size;
    let mut off = struct_off;

    while off < end {
        let token = get_u32(fdt, off);
        off += 4;
        match token {
            FDT_BEGIN_NODE => {
                // Node name follows, null-terminated, 4-byte aligned.
                let name_start = off;
                let mut name_end = name_start;
                while name_end < end && fdt[name_end] != 0 {
                    name_end += 1;
                }
                let node_name = &fdt[name_start..name_end];
                off = align4(name_end + 1); // skip null + pad

                if node_name == name {
                    return Some(off);
                }
            }
            FDT_END_NODE => {}
            FDT_PROP => {
                let len = get_u32(fdt, off) as usize;
                off += 8; // skip len + nameoff
                off = align4(off + len);
            }
            FDT_NOP => {}
            FDT_END => break,
            _ => break,
        }
    }
    None
}

/// Find the DT_END_NODE token for the current node (the one whose content
/// starts at `content_off`). Handles nested children.
fn find_end_node(fdt: &[u8], content_off: usize, struct_end: usize) -> Option<usize> {
    let mut off = content_off;
    let mut depth = 0u32;

    while off < struct_end {
        let token = get_u32(fdt, off);
        match token {
            FDT_BEGIN_NODE => {
                depth += 1;
                off += 4;
                // Skip node name.
                while off < struct_end && fdt[off] != 0 {
                    off += 1;
                }
                off = align4(off + 1);
            }
            FDT_END_NODE => {
                if depth == 0 {
                    return Some(off);
                }
                depth -= 1;
                off += 4;
            }
            FDT_PROP => {
                let len = get_u32(fdt, off + 4) as usize;
                off = align4(off + 4 + 8 + len); // token + len + nameoff + value
            }
            FDT_NOP => {
                off += 4;
            }
            FDT_END => break,
            _ => break,
        }
    }
    None
}

/// Add a string to the FDT strings block and return its offset.
/// Updates `size_dt_strings` in the header.
fn add_string(fdt: &mut [u8], name: &[u8]) -> u32 {
    let strings_off = get_u32(fdt, 0x0C) as usize; // off_dt_strings
    let strings_size = get_u32(fdt, 0x20) as usize; // size_dt_strings (offset 0x20)

    let new_off = strings_size;
    let dest = strings_off + new_off;
    fdt[dest..dest + name.len()].copy_from_slice(name);
    fdt[dest + name.len()] = 0; // null terminator

    // Update size_dt_strings (offset 0x20).
    put_u32(fdt, 0x20, (strings_size + name.len() + 1) as u32);

    new_off as u32
}

/// Build a FDT_PROP token sequence for a u64 value and return the bytes + length.
/// Layout: [FDT_PROP(4)] [len=8(4)] [nameoff(4)] [value(8)] = 20 bytes.
fn build_prop_u64(nameoff: u32, value: u64) -> [u8; 20] {
    let mut buf = [0u8; 20];
    // Token
    buf[0..4].copy_from_slice(&FDT_PROP.to_be_bytes());
    // Length = 8 (u64)
    buf[4..8].copy_from_slice(&8u32.to_be_bytes());
    // Name offset in strings block
    buf[8..12].copy_from_slice(&nameoff.to_be_bytes());
    // Value (big-endian u64)
    buf[12..20].copy_from_slice(&value.to_be_bytes());
    buf
}

/// Patch the FDT at `fdt_base` (in-place) to add initrd-start/end to /chosen.
///
/// The FDT must have enough slack space (QEMU typically pads to 1 MiB).
/// Returns Ok(()) on success, Err(&str) on failure.
pub fn patch_chosen_initrd(
    fdt_base: *mut u8,
    fdt_alloc_size: usize,
    initrd_start: u64,
    initrd_end: u64,
) -> Result<(), &'static str> {
    let fdt = unsafe { core::slice::from_raw_parts_mut(fdt_base, fdt_alloc_size) };

    // Validate magic.
    if get_u32(fdt, 0) != FDT_MAGIC {
        return Err("bad FDT magic");
    }

    let total_size = get_u32(fdt, 0x04) as usize;
    let struct_off = get_u32(fdt, 0x08) as usize;
    let strings_off = get_u32(fdt, 0x0C) as usize;
    // size_dt_struct (offset 0x24) may be 0 (QEMU doesn't always fill it in).
    // Compute from strings_off - struct_off as fallback.
    let struct_size = {
        let raw = get_u32(fdt, 0x24) as usize;
        if raw > 0 { raw } else { strings_off - struct_off }
    };

    // Find /chosen node.
    let chosen_content = find_node(fdt, struct_off, struct_size, b"chosen")
        .ok_or("cannot find /chosen node")?;

    // Find the DT_END_NODE for /chosen.
    let end_node_off = find_end_node(fdt, chosen_content, struct_off + struct_size)
        .ok_or("cannot find /chosen DT_END_NODE")?;

    let insert_size: usize = 40; // Two FDT_PROP entries of 20 bytes each (u64 values).
    let strings_size = get_u32(fdt, 0x20) as usize; // size_dt_strings (offset 0x20)
    let content_end = strings_off + strings_size;

    // Check we have room in the allocation.
    // We need insert_size for the struct expansion plus room for two new strings.
    let new_strings_len = b"linux,initrd-start\0linux,initrd-end\0".len();
    if content_end + insert_size + new_strings_len > fdt_alloc_size {
        return Err("FDT has no room for initrd properties");
    }

    // Step 1: Shift everything from end_node_off through content_end forward
    // by insert_size. This makes room in the struct block for the new properties
    // and moves the strings block forward.
    let tail_len = content_end - end_node_off;
    unsafe {
        ptr::copy(
            fdt_base.add(end_node_off),
            fdt_base.add(end_node_off + insert_size),
            tail_len,
        );
    }

    // Step 2: Update the strings block offset (it moved forward).
    let new_strings_off = strings_off + insert_size;
    put_u32(fdt, 0x0C, new_strings_off as u32);

    // Step 3: Add property name strings to the (shifted) strings block.
    // add_string reads off_dt_strings and size_dt_strings from the header.
    let nameoff_start = add_string(fdt, b"linux,initrd-start");
    let nameoff_end = add_string(fdt, b"linux,initrd-end");

    // Step 4: Build and insert the two property entries at end_node_off.
    let prop_start = build_prop_u64(nameoff_start, initrd_start);
    let prop_end = build_prop_u64(nameoff_end, initrd_end);
    fdt[end_node_off..end_node_off + 20].copy_from_slice(&prop_start);
    fdt[end_node_off + 20..end_node_off + 40].copy_from_slice(&prop_end);

    // Step 5: Update header fields.
    let new_struct_size = struct_size + insert_size;
    put_u32(fdt, 0x24, new_struct_size as u32); // size_dt_struct (offset 0x24)

    // Keep totalsize if it already covers the new content (QEMU pads to 1 MiB).
    let final_content_end = new_strings_off + get_u32(fdt, 0x20) as usize;
    if final_content_end > total_size {
        put_u32(fdt, 0x04, final_content_end as u32);
    }

    Ok(())
}
