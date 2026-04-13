//! Shared value types for cross-platform capavisor code.
//!
//! These types are the interface between the platform-agnostic core
//! (hypercall dispatch, domain lifecycle) and architecture-specific backends.
//! They use concrete values — not arch-specific handles — so that shared code
//! can inspect and route without knowing the underlying ISA.

use capability_engine::Rights;

// ── Hypercall arguments / results ────────────────────────────────────────── //

/// Architecture-neutral hypercall argument pack.
///
/// On x86 these come from RAX/RDI/RSI/RDX/RCX/R8.
/// On AArch64 they would come from X0–X5.
pub struct HypercallArgs {
    pub opcode: u64,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
}

/// Architecture-neutral hypercall return values.
///
/// On x86 these are written to RAX/RDI/RSI/RDX.
/// On AArch64 they would go to X0–X3.
pub struct HypercallResult {
    pub status: u64,
    pub val0: u64,
    pub val1: u64,
    pub val2: u64,
}

impl HypercallResult {
    pub fn success() -> Self {
        Self {
            status: 0,
            val0: 0,
            val1: 0,
            val2: 0,
        }
    }

    pub fn success_1(val0: u64) -> Self {
        Self {
            status: 0,
            val0,
            val1: 0,
            val2: 0,
        }
    }

    pub fn success_2(val0: u64, val1: u64) -> Self {
        Self {
            status: 0,
            val0,
            val1,
            val2: 0,
        }
    }

    pub fn error(code: u64) -> Self {
        Self {
            status: code,
            val0: 0,
            val1: 0,
            val2: 0,
        }
    }
}

// ── Semantic exit events ─────────────────────────────────────────────────── //

/// Architecture-neutral exit events.
///
/// Arch code decodes raw hardware exits (VMX exit reasons, ARM ESR_EL2.EC)
/// into this enum. Shared code pattern-matches on it for dispatch.
///
/// Events that are purely arch-internal (x86 XSETBV, ARM WFE trap) are
/// handled inside the arch backend and never reach this enum.
pub enum ArchExit {
    /// Guest executed a hypercall (VMCALL / HVC).
    Hypercall,
    /// External interrupt delivered to the hypervisor.
    ExternalInterrupt { vector: u32 },
    /// Preemption / scheduling timer fired.
    TimerExpired,
    /// Guest accessed an unmapped or protected GPA.
    GuestMemoryFault { gpa: u64, write: bool },
    /// Guest executed a port I/O instruction.
    IoInstruction {
        port: u16,
        size: u8,
        is_write: bool,
        value: u32,
    },
    /// Guest accessed an MMIO region (e.g., IOAPIC, virtio).
    MmioAccess {
        gpa: u64,
        is_write: bool,
        len: u8,
    },
    /// Exit that must be forwarded to the parent domain's VMM.
    /// The opaque `exit_info` carries arch-specific context for the parent.
    ForwardToParent,
    /// Secondary CPU startup event (SIPI on x86, PSCI CPU_ON on ARM).
    StartupEvent { target_cpu: u32, entry_addr: u64 },
    /// Guest halted (HLT / WFI).
    Halt,
    /// Guest shutdown / triple fault.
    Shutdown,
}

// ── Memory / permission types ────────────────────────────────────────────── //

/// Page sizes for guest physical mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageSize {
    Page4K,
    Page2M,
    Page1G,
}

impl PageSize {
    pub fn bytes(self) -> u64 {
        match self {
            PageSize::Page4K => 4096,
            PageSize::Page2M => 2 * 1024 * 1024,
            PageSize::Page1G => 1024 * 1024 * 1024,
        }
    }
}

/// Guest physical mapping permissions, derived from capability Rights.
#[derive(Debug, Clone, Copy)]
pub struct MapPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl From<&Rights> for MapPermissions {
    fn from(r: &Rights) -> Self {
        let bits = r.bits();
        Self {
            read: (bits & Rights::READ) != 0,
            write: (bits & Rights::WRITE) != 0,
            execute: (bits & Rights::EXECUTE) != 0,
        }
    }
}

// ── Device identification ────────────────────────────────────────────────── //

/// PCI Bus/Device/Function identifier for device assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceId {
    pub segment: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}
