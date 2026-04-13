//! C-FFI shims for `libthemis` — called from the `thhv` kernel module.
//!
//! Each function is `#[no_mangle] pub extern "C"` and returns a C-friendly
//! error code: 0 on success, negative errno-style values on failure.
//!
//! Output values are written through `*mut u64` out-pointers (NULL-safe).
//!
//! Enabled only when `feature = "ffi"` is active.

use crate::*;
use themis_abi::errors;

// ── Helpers ─────────────────────────────────────────────────────────────── //

/// Map Themis error codes to negative errno values.
fn to_errno(e: u64) -> i32 {
    match e {
        errors::ERR_INVALID => -22,  // EINVAL
        errors::ERR_NOPERM => -1,    // EPERM
        errors::ERR_NOMEM => -12,    // ENOMEM
        errors::ERR_BADSTATE => -16, // EBUSY
        errors::ERR_NOTFOUND => -2,  // ENOENT
        errors::ERR_UNIMPL => -38,   // ENOSYS
        _ => -5,                     // EIO
    }
}

/// Write to out-pointer if non-null.
unsafe fn write_out(ptr: *mut u64, val: u64) {
    if !ptr.is_null() {
        *ptr = val;
    }
}

// ── FFI wrappers ────────────────────────────────────────────────────────── //

#[no_mangle]
pub extern "C" fn themis_carve(
    parent: u64,
    start: u64,
    size: u64,
    rights: u64,
    out_handle: *mut u64,
    out_sub: *mut u64,
) -> i32 {
    match carve(parent, start, size, rights) {
        Ok((h, s)) => {
            unsafe {
                write_out(out_handle, h);
                write_out(out_sub, s);
            }
            0
        }
        Err(e) => to_errno(e),
    }
}

#[no_mangle]
pub extern "C" fn themis_alias(
    parent: u64,
    start: u64,
    size: u64,
    rights: u64,
    out_handle: *mut u64,
    out_sub: *mut u64,
) -> i32 {
    match alias(parent, start, size, rights) {
        Ok((h, s)) => {
            unsafe {
                write_out(out_handle, h);
                write_out(out_sub, s);
            }
            0
        }
        Err(e) => to_errno(e),
    }
}

#[no_mangle]
pub extern "C" fn themis_send(cap: u64, receiver: u64, attrs: u64) -> i32 {
    match send(cap, receiver, attrs) {
        Ok(()) => 0,
        Err(e) => to_errno(e),
    }
}

#[no_mangle]
pub extern "C" fn themis_send_at(cap: u64, receiver: u64, attrs: u64, child_gpa: u64) -> i32 {
    match send_at(cap, receiver, attrs, child_gpa) {
        Ok(()) => 0,
        Err(e) => to_errno(e),
    }
}

#[no_mangle]
pub extern "C" fn themis_accept(pending_id: u64, out_handle: *mut u64) -> i32 {
    match accept(pending_id) {
        Ok(h) => {
            unsafe {
                write_out(out_handle, h);
            }
            0
        }
        Err(e) => to_errno(e),
    }
}

#[no_mangle]
pub extern "C" fn themis_reject(pending_id: u64) -> i32 {
    match reject(pending_id) {
        Ok(()) => 0,
        Err(e) => to_errno(e),
    }
}

#[no_mangle]
pub extern "C" fn themis_create_domain(
    cores_mask: u64,
    api_flags: u64,
    num_vps: u64,
    out_handle: *mut u64,
) -> i32 {
    match create_domain(cores_mask, api_flags, num_vps) {
        Ok(h) => {
            unsafe {
                write_out(out_handle, h);
            }
            0
        }
        Err(e) => to_errno(e),
    }
}

#[no_mangle]
pub extern "C" fn themis_seal(domain: u64) -> i32 {
    match seal(domain) {
        Ok(()) => 0,
        Err(e) => to_errno(e),
    }
}

#[no_mangle]
pub extern "C" fn themis_revoke_mem(parent: u64, child_sub: u64) -> i32 {
    match revoke_mem(parent, child_sub) {
        Ok(()) => 0,
        Err(e) => to_errno(e),
    }
}

#[no_mangle]
pub extern "C" fn themis_revoke_domain(domain: u64) -> i32 {
    match revoke_domain(domain) {
        Ok(()) => 0,
        Err(e) => to_errno(e),
    }
}

#[no_mangle]
pub extern "C" fn themis_switch(target_domain: u64, vp_id: u64) -> i32 {
    match switch(target_domain, vp_id) {
        Ok(()) => 0,
        Err(e) => to_errno(e),
    }
}

#[no_mangle]
pub extern "C" fn themis_get_chan(domain: u64, out_handle: *mut u64) -> i32 {
    match get_chan(domain) {
        Ok(h) => {
            unsafe {
                write_out(out_handle, h);
            }
            0
        }
        Err(e) => to_errno(e),
    }
}

#[no_mangle]
pub extern "C" fn themis_attest_self(out_lo: *mut u64, out_hi: *mut u64) -> i32 {
    match attest_self() {
        Ok((lo, hi)) => {
            unsafe {
                write_out(out_lo, lo);
                write_out(out_hi, hi);
            }
            0
        }
        Err(e) => to_errno(e),
    }
}

#[no_mangle]
pub extern "C" fn themis_attest(domain: u64, out_lo: *mut u64, out_hi: *mut u64) -> i32 {
    match attest(domain) {
        Ok((lo, hi)) => {
            unsafe {
                write_out(out_lo, lo);
                write_out(out_hi, hi);
            }
            0
        }
        Err(e) => to_errno(e),
    }
}

#[no_mangle]
pub extern "C" fn themis_get_reg(domain: u64, vp_id: u64, reg: u64, out_val: *mut u64) -> i32 {
    // SAFETY: reg is validated by the capavisor; transmute is for the enum discriminant.
    let reg_enum = unsafe { core::mem::transmute::<u64, themis_abi::VpRegister>(reg) };
    match get_reg(domain, vp_id, reg_enum) {
        Ok(v) => {
            unsafe {
                write_out(out_val, v);
            }
            0
        }
        Err(e) => to_errno(e),
    }
}

#[no_mangle]
pub extern "C" fn themis_set_reg(domain: u64, vp_id: u64, reg: u64, value: u64) -> i32 {
    let reg_enum = unsafe { core::mem::transmute::<u64, themis_abi::VpRegister>(reg) };
    match set_reg(domain, vp_id, reg_enum, value) {
        Ok(()) => 0,
        Err(e) => to_errno(e),
    }
}

#[no_mangle]
pub extern "C" fn themis_set_policy_wrapper(
    domain: u64,
    kind: u64,
    key: u64,
    sub_key: u64,
    value: u64,
) -> i32 {
    match set_policy(domain, kind, key, sub_key, value) {
        Ok(()) => 0,
        Err(e) => to_errno(e),
    }
}

#[no_mangle]
pub extern "C" fn themis_assign_device(domain: u64, pci_bdf: u64) -> i32 {
    match assign_device(domain, pci_bdf) {
        Ok(()) => 0,
        Err(e) => to_errno(e),
    }
}

#[no_mangle]
pub extern "C" fn themis_register_comm(cap: u64, child_domain: u64, vp_id: u64) -> i32 {
    match crate::register_comm(cap, child_domain, vp_id) {
        Ok(()) => 0,
        Err(e) => to_errno(e),
    }
}
