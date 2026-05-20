//! Themis hypervisor interface for Eunomia.
//!
//! Thin wrapper around [`libthemis`] (typed VMCALL wrappers) and
//! [`themis_abi`] (opcodes, error codes).  Provides a
//! `HypervisorInterface` trait with `ThemisBackend` (real VMCALL) and
//! `StubBackend` (no-op, for QEMU testing).
//!
//! All hypercall constants and typed wrappers are re-exported from
//! `themis_abi::opcodes` and `libthemis` respectively — no duplication.

pub use themis_abi::opcodes;
pub use themis_abi::errors;

// ── Error type ─────────────────────────────────────────────────────────── //

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HvError {
    NotSupported,
    HypercallFailed(u64),
}

// ── HypervisorInterface trait ──────────────────────────────────────────── //

/// Trait abstracting kernel-to-hypervisor communication.
///
/// `ThemisBackend`: VMCALL-based, for running under Themis.
/// `StubBackend`: no-op, for testing under QEMU without a hypervisor.
pub trait HypervisorInterface {
    fn hypercall(&self, op: u64, args: [u64; 5]) -> Result<(u64, u64, u64), HvError>;
    fn exit(&self, code: u64) -> !;
    fn is_available(&self) -> bool;
}

// ── ThemisBackend ──────────────────────────────────────────────────────── //

pub struct ThemisBackend;

impl HypervisorInterface for ThemisBackend {
    fn hypercall(&self, op: u64, args: [u64; 5]) -> Result<(u64, u64, u64), HvError> {
        // Delegate to libthemis raw vmcall (RDI/RSI/RDX/RCX/R8 ABI).
        let (rax, rdi, rsi, rdx) = unsafe {
            libthemis::raw_vmcall(op, args[0], args[1], args[2], args[3], args[4])
        };
        if rax == errors::SUCCESS {
            Ok((rdi, rsi, rdx))
        } else {
            Err(HvError::HypercallFailed(rax))
        }
    }

    fn exit(&self, code: u64) -> ! {
        let _ = libthemis::switch(code, 0);
        loop { unsafe { core::arch::asm!("hlt"); } }
    }

    fn is_available(&self) -> bool {
        true
    }
}

// ── StubBackend ────────────────────────────────────────────────────────── //

pub struct StubBackend;

impl HypervisorInterface for StubBackend {
    fn hypercall(&self, _op: u64, _args: [u64; 5]) -> Result<(u64, u64, u64), HvError> {
        Err(HvError::NotSupported)
    }

    fn exit(&self, _code: u64) -> ! {
        crate::test_harness::guest_exit(true);
    }

    fn is_available(&self) -> bool {
        false
    }
}
