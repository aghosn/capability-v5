//! Guest-side VMCALL wrappers for the Themis hypercall ABI.
//!
//! `libthemis` is a `no_std` library that guest software (Linux kernel
//! modules, bare-metal child domains) links against to issue Themis
//! hypercalls without hand-writing inline assembly.
//!
//! # Usage
//!
//! ```rust,ignore
//! let (handle, sub) = libthemis::carve(parent, start, size, rights)?;
//! libthemis::send(cap, receiver, 0)?;
//! let hash = libthemis::attest_self()?;
//! ```
//!
//! Every function returns `Result<T, u64>` where the error is a
//! [`themis_abi::errors`] code.

#![no_std]

use themis_abi::{errors, opcodes};

#[cfg(feature = "ffi")]
pub mod ffi;

// Panic handler only for staticlib builds (thhv kernel module).
// rlib consumers (eunomia) provide their own.
#[cfg(all(not(test), feature = "ffi"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// ── Raw VMCALL primitive ────────────────────────────────────────────────── //

/// Issue a VMCALL with up to 5 arguments.
///
/// Register convention (matches `themis_abi`):
///   IN:  RAX = opcode, RDI = a0, RSI = a1, RDX = a2, RCX = a3, R8 = a4
///   OUT: RAX = error,  RDI = r0, RSI = r1, RDX = r2
///
/// Returns `(rax, rdi, rsi, rdx)`.
///
/// # Safety
/// Only valid when running under a VMX hypervisor.
#[inline(always)]
pub unsafe fn raw_vmcall(
    opcode: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
) -> (u64, u64, u64, u64) {
    let rax: u64;
    let rdi: u64;
    let rsi: u64;
    let rdx: u64;
    core::arch::asm!(
        "vmcall",
        inlateout("rax") opcode => rax,
        inlateout("rdi") a0 => rdi,
        inlateout("rsi") a1 => rsi,
        inlateout("rdx") a2 => rdx,
        in("rcx") a3,
        in("r8") a4,
        // Clobbers: VMCALL may modify r9–r11 on some platforms.
        lateout("r9") _,
        lateout("r10") _,
        lateout("r11") _,
        // SWITCH and doorbells synchronize memory with another domain.
        options(nostack),
    );
    (rax, rdi, rsi, rdx)
}

/// Convenience: VMCALL with 0–4 args (fills unused regs with 0).
#[inline(always)]
#[allow(dead_code)]
unsafe fn vmcall0(op: u64) -> (u64, u64, u64, u64) {
    raw_vmcall(op, 0, 0, 0, 0, 0)
}
#[inline(always)]
unsafe fn vmcall1(op: u64, a0: u64) -> (u64, u64, u64, u64) {
    raw_vmcall(op, a0, 0, 0, 0, 0)
}
#[inline(always)]
unsafe fn vmcall2(op: u64, a0: u64, a1: u64) -> (u64, u64, u64, u64) {
    raw_vmcall(op, a0, a1, 0, 0, 0)
}
#[inline(always)]
unsafe fn vmcall3(op: u64, a0: u64, a1: u64, a2: u64) -> (u64, u64, u64, u64) {
    raw_vmcall(op, a0, a1, a2, 0, 0)
}
#[inline(always)]
unsafe fn vmcall4(op: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> (u64, u64, u64, u64) {
    raw_vmcall(op, a0, a1, a2, a3, 0)
}

/// Check RAX; return `Ok(())` on SUCCESS or `Err(code)`.
#[inline(always)]
fn check(rax: u64) -> Result<(), u64> {
    if rax == errors::SUCCESS {
        Ok(())
    } else {
        Err(rax)
    }
}

// ── Public API ──────────────────────────────────────────────────────────── //

/// Carve an exclusive sub-region from a parent memory capability.
///
/// Returns `(new_handle, sub_handle)`.
pub fn carve(parent: u64, start: u64, size: u64, rights: u64) -> Result<(u64, u64), u64> {
    let (rax, rdi, rsi, _) = unsafe { vmcall4(opcodes::THEMIS_CARVE, parent, start, size, rights) };
    check(rax)?;
    Ok((rdi, rsi))
}

/// Alias a shared sub-region from a parent memory capability.
///
/// Returns `(new_handle, sub_handle)`.
pub fn alias(parent: u64, start: u64, size: u64, rights: u64) -> Result<(u64, u64), u64> {
    let (rax, rdi, rsi, _) = unsafe { vmcall4(opcodes::THEMIS_ALIAS, parent, start, size, rights) };
    check(rax)?;
    Ok((rdi, rsi))
}

/// Remap a memory capability at a new GPA within the caller's address space.
pub fn map_self(cap: u64, new_gpa: u64) -> Result<(), u64> {
    let (rax, _, _, _) = unsafe { vmcall2(opcodes::THEMIS_MAP_SELF, cap, new_gpa) };
    check(rax)
}

/// Send a capability to a receiver domain or channel.
pub fn send(cap: u64, receiver: u64, attrs: u64) -> Result<(), u64> {
    let (rax, _, _, _) = unsafe { vmcall4(opcodes::THEMIS_SEND, cap, receiver, attrs, u64::MAX) };
    check(rax)
}

/// Send a memory capability with a GPA hint for the receiver.
///
/// `child_gpa` specifies where the region appears in the receiver's guest
/// address space. `u64::MAX` means no hint; zero is a valid explicit GPA.
pub fn send_at(cap: u64, receiver: u64, attrs: u64, child_gpa: u64) -> Result<(), u64> {
    let (rax, _, _, _) = unsafe { vmcall4(opcodes::THEMIS_SEND, cap, receiver, attrs, child_gpa) };
    check(rax)
}

/// Accept a pending capability.
///
/// Returns the new capability handle.
pub fn accept(pending_id: u64) -> Result<u64, u64> {
    let (rax, rdi, _, _) = unsafe { vmcall1(opcodes::THEMIS_ACCEPT, pending_id) };
    check(rax)?;
    Ok(rdi)
}

/// Reject a pending capability.
pub fn reject(pending_id: u64) -> Result<(), u64> {
    let (rax, _, _, _) = unsafe { vmcall1(opcodes::THEMIS_REJECT, pending_id) };
    check(rax)
}

/// Create a new child domain.
///
/// Returns the domain handle.
pub fn create_domain(cores_mask: u64, api_flags: u64, num_vps: u64) -> Result<u64, u64> {
    let (rax, rdi, _, _) = unsafe {
        vmcall3(
            opcodes::THEMIS_CREATE_DOMAIN,
            cores_mask,
            api_flags,
            num_vps,
        )
    };
    check(rax)?;
    Ok(rdi)
}

/// Seal a domain (transition Unsealed → Sealed).
pub fn seal(domain: u64) -> Result<(), u64> {
    let (rax, _, _, _) = unsafe { vmcall1(opcodes::THEMIS_SEAL, domain) };
    check(rax)
}

/// Revoke a tree child. A zero subhandle destroys an owned child domain.
pub fn revoke(parent: u64, child_sub: u64) -> Result<(), u64> {
    let (rax, _, _, _) = unsafe { vmcall2(opcodes::THEMIS_REVOKE, parent, child_sub) };
    check(rax)
}

/// Switch to a target domain's VP (RDI=0 to return to caller).
pub fn switch(target_domain: u64, vp_id: u64) -> Result<(), u64> {
    let (rax, _, _, _) = unsafe { vmcall2(opcodes::THEMIS_SWITCH, target_domain, vp_id) };
    check(rax)
}

/// Get a channel capability to a domain.
///
/// Returns the channel handle.
pub fn get_chan(domain: u64) -> Result<u64, u64> {
    let (rax, rdi, _, _) = unsafe { vmcall1(opcodes::THEMIS_GET_CHAN, domain) };
    check(rax)?;
    Ok(rdi)
}

/// Create an immutable endpoint; `None` selects self, otherwise an owned child.
/// Returns the invocation handle and recipient-tree port.
pub fn create_doorbell(
    child: Option<u64>,
    vector: u8,
    async_vp: Option<u64>,
) -> Result<(u64, u64), u64> {
    let (status, handle, port, _) = unsafe {
        raw_vmcall(
            opcodes::THEMIS_CREATE_DOORBELL,
            child.unwrap_or(u64::MAX),
            vector as u64,
            u64::from(async_vp.is_some()),
            async_vp.unwrap_or(0),
            0,
        )
    };
    check(status)?;
    Ok((handle, port))
}

/// Notify with an opaque value. Sync returns to its recipient's blocked caller.
pub fn notify(handle: u64, value: u64) -> Result<(), u64> {
    let (status, _, _, _) = unsafe { vmcall2(opcodes::THEMIS_NOTIFY, handle, value) };
    check(status)
}

/// Find the first pending offer at or after `start`, independent of type.
pub fn enumerate_pending(start: u64) -> Result<Option<u64>, u64> {
    let (status, id, found, _) = unsafe { vmcall1(opcodes::THEMIS_ENUMERATE, start) };
    check(status)?;
    Ok(if found == 0 { None } else { Some(id) })
}

/// Self-attestation (unsigned, offset=0).
/// Returns `(total_payload_size, bytes_written)`.
pub fn attest_self() -> Result<(u64, u64), u64> {
    attest_self_at(0)
}

/// Self-attestation (unsigned) starting at `offset` bytes into the report.
/// Returns `(total_payload_size, bytes_written)`.
/// Call with increasing offsets (dequeue between calls) to retrieve large reports.
pub fn attest_self_at(offset: u64) -> Result<(u64, u64), u64> {
    let (rax, rdi, rsi, _) = unsafe { vmcall2(opcodes::THEMIS_ATTEST_SELF, 0, offset) };
    check(rax)?;
    Ok((rdi, rsi))
}

/// Remote attestation of another domain.
///
/// Returns `(hash_lo, hash_hi)`.
pub fn attest(domain: u64) -> Result<(u64, u64), u64> {
    let (rax, rdi, rsi, _) = unsafe { vmcall1(opcodes::THEMIS_ATTEST, domain) };
    check(rax)?;
    Ok((rdi, rsi))
}

/// Read a VP register from a child domain.
pub fn get_reg(domain: u64, vp_id: u64, reg: themis_abi::VpRegister) -> Result<u64, u64> {
    let (rax, rdi, _, _) = unsafe { vmcall3(opcodes::THEMIS_GET_REG, domain, vp_id, reg as u64) };
    check(rax)?;
    Ok(rdi)
}

/// Write a VP register of a child domain.
pub fn set_reg(
    domain: u64,
    vp_id: u64,
    reg: themis_abi::VpRegister,
    value: u64,
) -> Result<(), u64> {
    let (rax, _, _, _) =
        unsafe { vmcall4(opcodes::THEMIS_SET_REG, domain, vp_id, reg as u64, value) };
    check(rax)
}

/// Unified policy-setting hypercall.
///
/// Maps to `Capability::set_policy` via THEMIS_SET_POLICY opcode.
pub fn set_policy(domain: u64, kind: u64, key: u64, sub_key: u64, value: u64) -> Result<(), u64> {
    let (rax, _, _, _) = unsafe {
        raw_vmcall(
            opcodes::THEMIS_SET_POLICY,
            domain,
            kind,
            key,
            sub_key,
            value,
        )
    };
    check(rax)
}

/// Assign a PCI device to a domain.
pub fn assign_device(domain: u64, pci_bdf: u64) -> Result<(), u64> {
    let (rax, _, _, _) = unsafe { vmcall2(opcodes::THEMIS_ASSIGN_DEVICE, domain, pci_bdf) };
    check(rax)
}

/// Add a virtual processor to a child domain.
///
/// IN:  RDI = child_domain_handle, RSI = comm_cap_handle
/// OUT: RDI = vp_id on success
pub fn add_vp(child_domain: u64, comm_cap: u64) -> Result<u64, u64> {
    let (rax, rdi, _, _) = unsafe { vmcall2(opcodes::THEMIS_ADD_VP, child_domain, comm_cap) };
    check(rax)?;
    Ok(rdi)
}

/// Register a COMM page owned by the caller, bound to a child domain's VP.
pub fn register_comm(cap: u64, child_domain: u64, vp_id: u64) -> Result<(), u64> {
    let (rax, _, _, _) =
        unsafe { vmcall3(opcodes::THEMIS_REGISTER_COMM, cap, child_domain, vp_id) };
    check(rax)
}
