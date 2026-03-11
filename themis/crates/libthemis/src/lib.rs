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

// When built as a staticlib (for linking into a kernel module), we need
// a panic handler.  In the kernel context, panics should never happen;
// if they do, loop forever (the kernel's own BUG() is the real handler).
#[cfg(not(test))]
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
#[inline(always)]
unsafe fn vmcall5(
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
        options(nomem, nostack),
    );
    (rax, rdi, rsi, rdx)
}

/// Convenience: VMCALL with 0–4 args (fills unused regs with 0).
#[inline(always)]
unsafe fn vmcall0(op: u64) -> (u64, u64, u64, u64) {
    vmcall5(op, 0, 0, 0, 0, 0)
}
#[inline(always)]
unsafe fn vmcall1(op: u64, a0: u64) -> (u64, u64, u64, u64) {
    vmcall5(op, a0, 0, 0, 0, 0)
}
#[inline(always)]
unsafe fn vmcall2(op: u64, a0: u64, a1: u64) -> (u64, u64, u64, u64) {
    vmcall5(op, a0, a1, 0, 0, 0)
}
#[inline(always)]
unsafe fn vmcall3(op: u64, a0: u64, a1: u64, a2: u64) -> (u64, u64, u64, u64) {
    vmcall5(op, a0, a1, a2, 0, 0)
}
#[inline(always)]
unsafe fn vmcall4(op: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> (u64, u64, u64, u64) {
    vmcall5(op, a0, a1, a2, a3, 0)
}

/// Check RAX; return `Ok(())` on SUCCESS or `Err(code)`.
#[inline(always)]
fn check(rax: u64) -> Result<(), u64> {
    if rax == errors::SUCCESS { Ok(()) } else { Err(rax) }
}

// ── Public API ──────────────────────────────────────────────────────────── //

/// Carve an exclusive sub-region from a parent memory capability.
///
/// Returns `(new_handle, sub_handle)`.
pub fn carve(parent: u64, start: u64, size: u64, rights: u64) -> Result<(u64, u64), u64> {
    let (rax, rdi, rsi, _) =
        unsafe { vmcall4(opcodes::THEMIS_CARVE, parent, start, size, rights) };
    check(rax)?;
    Ok((rdi, rsi))
}

/// Alias a shared sub-region from a parent memory capability.
///
/// Returns `(new_handle, sub_handle)`.
pub fn alias(parent: u64, start: u64, size: u64, rights: u64) -> Result<(u64, u64), u64> {
    let (rax, rdi, rsi, _) =
        unsafe { vmcall4(opcodes::THEMIS_ALIAS, parent, start, size, rights) };
    check(rax)?;
    Ok((rdi, rsi))
}

/// Send a memory capability to a receiver domain.
pub fn send(cap: u64, receiver: u64, attrs: u64) -> Result<(), u64> {
    let (rax, _, _, _) =
        unsafe { vmcall3(opcodes::THEMIS_SEND, cap, receiver, attrs) };
    check(rax)
}

/// Send a memory capability with a GPA hint for the receiver.
///
/// `child_gpa` specifies where the region appears in the receiver's guest
/// address space.  If 0, the capavisor uses identity mapping (GPA = HPA).
pub fn send_at(cap: u64, receiver: u64, attrs: u64, child_gpa: u64) -> Result<(), u64> {
    let (rax, _, _, _) =
        unsafe { vmcall4(opcodes::THEMIS_SEND, cap, receiver, attrs, child_gpa) };
    check(rax)
}

/// Accept a pending memory capability.
///
/// Returns the new capability handle.
pub fn accept(pending_id: u64) -> Result<u64, u64> {
    let (rax, rdi, _, _) = unsafe { vmcall1(opcodes::THEMIS_ACCEPT, pending_id) };
    check(rax)?;
    Ok(rdi)
}

/// Reject a pending memory capability.
pub fn reject(pending_id: u64) -> Result<(), u64> {
    let (rax, _, _, _) = unsafe { vmcall1(opcodes::THEMIS_REJECT, pending_id) };
    check(rax)
}

/// Create a new child domain.
///
/// Returns the domain handle.
pub fn create_domain(cores_mask: u64, api_flags: u64, num_vps: u64) -> Result<u64, u64> {
    let (rax, rdi, _, _) =
        unsafe { vmcall3(opcodes::THEMIS_CREATE_DOMAIN, cores_mask, api_flags, num_vps) };
    check(rax)?;
    Ok(rdi)
}

/// Seal a domain (transition Unsealed → Sealed).
pub fn seal(domain: u64) -> Result<(), u64> {
    let (rax, _, _, _) = unsafe { vmcall1(opcodes::THEMIS_SEAL, domain) };
    check(rax)
}

/// Revoke a child of a memory capability.
pub fn revoke_mem(parent: u64, child_sub: u64) -> Result<(), u64> {
    let (rax, _, _, _) =
        unsafe { vmcall2(opcodes::THEMIS_REVOKE_MEM, parent, child_sub) };
    check(rax)
}

/// Revoke an entire child domain.
pub fn revoke_domain(domain: u64) -> Result<(), u64> {
    let (rax, _, _, _) = unsafe { vmcall1(opcodes::THEMIS_REVOKE_DOMAIN, domain) };
    check(rax)
}

/// Switch to a target domain's VP (RDI=0 to return to caller).
pub fn switch(target_domain: u64, vp_id: u64) -> Result<(), u64> {
    let (rax, _, _, _) =
        unsafe { vmcall2(opcodes::THEMIS_SWITCH, target_domain, vp_id) };
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

/// Self-attestation: returns `(hash_lo, hash_hi)` — first 16 bytes of SHA-256.
pub fn attest_self() -> Result<(u64, u64), u64> {
    let (rax, rdi, rsi, _) = unsafe { vmcall0(opcodes::THEMIS_ATTEST_SELF) };
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
    let (rax, rdi, _, _) =
        unsafe { vmcall3(opcodes::THEMIS_GET_REG, domain, vp_id, reg as u64) };
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

/// Set per-vector interrupt policy for a domain.
pub fn set_intr_policy(domain: u64, vector: u64, policy: u64) -> Result<(), u64> {
    let (rax, _, _, _) =
        unsafe { vmcall3(opcodes::THEMIS_SET_INTR_POLICY, domain, vector, policy) };
    check(rax)
}

/// Set default interrupt policy for a domain.
pub fn set_def_intr_policy(domain: u64, policy: u64) -> Result<(), u64> {
    let (rax, _, _, _) =
        unsafe { vmcall2(opcodes::THEMIS_SET_DEF_INTR_POLICY, domain, policy) };
    check(rax)
}

/// Assign a PCI device to a domain.
pub fn assign_device(domain: u64, pci_bdf: u64) -> Result<(), u64> {
    let (rax, _, _, _) =
        unsafe { vmcall2(opcodes::THEMIS_ASSIGN_DEVICE, domain, pci_bdf) };
    check(rax)
}

/// Register a VP META state page.
pub fn register_vp_meta(domain: u64, vp_id: u64, meta_cap: u64) -> Result<(), u64> {
    let (rax, _, _, _) =
        unsafe { vmcall3(opcodes::THEMIS_REGISTER_VP_META, domain, vp_id, meta_cap) };
    check(rax)
}

/// Register a doorbell page.
pub fn register_doorbell(domain: u64, vp_id: u64, gpa: u64, slot: u64) -> Result<(), u64> {
    let (rax, _, _, _) =
        unsafe { vmcall4(opcodes::THEMIS_REGISTER_DOORBELL, domain, vp_id, gpa, slot) };
    check(rax)
}

/// Register an event flags page.
pub fn register_event_flags(domain: u64, vp_id: u64, meta_cap: u64) -> Result<(), u64> {
    let (rax, _, _, _) =
        unsafe { vmcall3(opcodes::THEMIS_REGISTER_EVENT_FLAGS, domain, vp_id, meta_cap) };
    check(rax)
}

/// Register an interrupt channel.
pub fn register_intr_chan(
    child: u64,
    vp_id: u64,
    slot: u64,
    vector: u64,
) -> Result<(), u64> {
    let (rax, _, _, _) =
        unsafe { vmcall4(opcodes::THEMIS_REGISTER_INTR_CHAN, child, vp_id, slot, vector) };
    check(rax)
}

/// Register a COMM page owned by the caller, bound to a child domain's VP.
pub fn register_comm(cap: u64, child_domain: u64, vp_id: u64) -> Result<(), u64> {
    let (rax, _, _, _) =
        unsafe { vmcall3(opcodes::THEMIS_REGISTER_COMM, cap, child_domain, vp_id) };
    check(rax)
}
