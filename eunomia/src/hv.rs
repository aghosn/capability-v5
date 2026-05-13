//! Themis hypervisor interface — hypercall ABI and trait implementations.
//!
//! Provides the low-level `vmcall` primitive and a `ThemisBackend` that
//! implements the `HypervisorInterface` trait for communication with the
//! Themis capavisor.
//!
//! When running outside Themis (e.g., under QEMU), use `StubBackend`.

use core::arch::asm;

// ── Hypercall numbers (from thhv/inc/thhv.h) ──────────────────────────── //

pub const HC_CARVE: u64 = 0x01;
pub const HC_ALIAS: u64 = 0x02;
pub const HC_SEND: u64 = 0x03;
pub const HC_ACCEPT: u64 = 0x04;
pub const HC_REJECT: u64 = 0x05;
pub const HC_CREATE_DOMAIN: u64 = 0x06;
pub const HC_SEAL: u64 = 0x07;
pub const HC_REVOKE_MEM: u64 = 0x08;
pub const HC_REVOKE_DOMAIN: u64 = 0x09;
pub const HC_SWITCH: u64 = 0x0A;
pub const HC_GET_CHAN: u64 = 0x0B;
pub const HC_ATTEST_SELF: u64 = 0x0C;
pub const HC_ATTEST: u64 = 0x0D;
pub const HC_GET_REG: u64 = 0x0E;
pub const HC_SET_REG: u64 = 0x0F;
pub const HC_ASSIGN_DEVICE: u64 = 0x12;
pub const HC_ENUMERATE: u64 = 0x13;
pub const HC_ADD_VP: u64 = 0x14;
pub const HC_REGISTER_DOORBELL: u64 = 0x15;
pub const HC_UNREGISTER_DOORBELL: u64 = 0x16;
pub const HC_SET_THEMIC_VECTOR: u64 = 0x17;
pub const HC_REGISTER_COMM: u64 = 0x18;
pub const HC_INJECT_INTERRUPT: u64 = 0x1B;
pub const HC_READ_PCR: u64 = 0x1E;
pub const HC_MAP_SELF: u64 = 0x1F;
pub const HC_SET_POLICY: u64 = 0x22;

// ── Error type ─────────────────────────────────────────────────────────── //

/// Hypervisor operation error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HvError {
    /// The hypercall is not supported (e.g., running without a hypervisor).
    NotSupported,
    /// The hypervisor returned an error code.
    HypercallFailed(u64),
    /// Invalid argument.
    InvalidArg,
}

// ── HypervisorInterface trait ──────────────────────────────────────────── //

/// Trait abstracting kernel-to-hypervisor communication.
///
/// Implementations:
/// - `ThemisBackend`: VMCALL-based, for running under Themis.
/// - `StubBackend`: no-op, for testing under QEMU without a hypervisor.
pub trait HypervisorInterface {
    /// Issue a raw hypercall.
    fn hypercall(&self, op: u64, args: [u64; 3]) -> Result<u64, HvError>;
    /// Signal controlled exit to the hypervisor.
    fn exit(&self, code: u64) -> !;
    /// Query whether we're running under this hypervisor.
    fn is_available(&self) -> bool;
}

// ── Raw VMCALL primitive ───────────────────────────────────────────────── //

/// Issue a Themis VMCALL hypercall.
///
/// ABI: RAX = opcode, RBX = arg1, RCX = arg2, RDX = arg3.
/// Returns RAX = result.
///
/// # Safety
/// Only valid when running under a VMX hypervisor (Themis/KVM).
#[inline(always)]
pub unsafe fn vmcall(op: u64, arg1: u64, arg2: u64, arg3: u64) -> u64 {
    let result: u64;
    asm!(
        "push rbx",
        "mov rbx, {a1}",
        "vmcall",
        "pop rbx",
        a1 = in(reg) arg1,
        inlateout("rax") op => result,
        in("rcx") arg2,
        in("rdx") arg3,
        options(nostack),
    );
    result
}

// ── ThemisBackend ──────────────────────────────────────────────────────── //

/// Production hypervisor backend using VMCALL.
pub struct ThemisBackend;

impl HypervisorInterface for ThemisBackend {
    fn hypercall(&self, op: u64, args: [u64; 3]) -> Result<u64, HvError> {
        let result = unsafe { vmcall(op, args[0], args[1], args[2]) };
        // Convention: 0 = success, non-zero = error code.
        if result == 0 {
            Ok(0)
        } else {
            // Some hypercalls return a positive value (e.g., GET_CHAN
            // returns a channel handle).  Negative values are errors.
            // For now, return the raw result and let callers interpret.
            Ok(result)
        }
    }

    fn exit(&self, code: u64) -> ! {
        // Use HC_SWITCH with a special "exit" encoding, or just HLT.
        // Under Themis, the parent domain regains control on VMEXIT.
        unsafe { vmcall(HC_SWITCH, code, 0, 0); }
        loop { unsafe { asm!("hlt"); } }
    }

    fn is_available(&self) -> bool {
        // Check for VMX by attempting CPUID leaf 1, ECX bit 5 (VMX).
        // If we're inside a VM, VMCALL should work.
        true // Assume available when compiled with ThemisBackend.
    }
}

// ── StubBackend ────────────────────────────────────────────────────────── //

/// No-op backend for testing without a hypervisor.
pub struct StubBackend;

impl HypervisorInterface for StubBackend {
    fn hypercall(&self, _op: u64, _args: [u64; 3]) -> Result<u64, HvError> {
        Err(HvError::NotSupported)
    }

    fn exit(&self, _code: u64) -> ! {
        // Use QEMU debug exit port.
        unsafe { asm!("out dx, al", in("dx") 0xF4u16, in("al") 0u8); }
        loop { unsafe { asm!("hlt"); } }
    }

    fn is_available(&self) -> bool {
        false
    }
}

// ── Convenience wrappers ───────────────────────────────────────────────── //

/// Enumerate capabilities visible to this domain.
pub fn enumerate(backend: &dyn HypervisorInterface) -> Result<u64, HvError> {
    backend.hypercall(HC_ENUMERATE, [0, 0, 0])
}

/// Get the domain's communication channel.
pub fn get_channel(backend: &dyn HypervisorInterface) -> Result<u64, HvError> {
    backend.hypercall(HC_GET_CHAN, [0, 0, 0])
}

/// Request attestation of this domain.
pub fn attest_self(backend: &dyn HypervisorInterface) -> Result<u64, HvError> {
    backend.hypercall(HC_ATTEST_SELF, [0, 0, 0])
}
