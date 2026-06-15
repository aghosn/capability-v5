//! Shared value types for cross-platform capavisor code.
//!
//! These types are the interface between the platform-agnostic core
//! (hypercall dispatch, domain lifecycle) and architecture-specific backends.
//! They use concrete values — not arch-specific handles — so that shared code
//! can inspect and route without knowing the underlying ISA.
//!
//! Many types are not yet constructed — they define the API boundary for
//! future arch backends.
#![allow(dead_code)]

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

    pub fn unimpl() -> Self {
        Self::error(themis_abi::errors::ERR_UNIMPL)
    }
}

// ── Semantic exit events ─────────────────────────────────────────────────── //

/// Architecture-neutral exit events produced by `ArchVpOps::run`.
///
/// Arch code fully decodes raw hardware exits (VMX exit reasons, ARM ESR_EL2.EC)
/// into this enum. The generic monitor loop pattern-matches on it for dispatch.
///
/// Events that are purely arch-internal (x86 XSETBV, ARM WFE trap) are handled
/// inside `run` and surfaced as `ArchHandled`.
pub enum SemanticExit {
    /// Arch code handled the exit internally (XSETBV, INIT signal,
    /// interrupt-window drain, etc.). Generic loop just re-enters the guest.
    ArchHandled,

    /// Guest executed a hypercall (VMCALL / HVC). Always dispatched generically.
    Hypercall,

    /// External interrupt delivered to the hypervisor. Routed via InterruptPolicy.
    ExternalInterrupt { vector: u32 },

    /// Preemption / scheduling timer fired.
    TimerExpired,

    /// Exit governed by ExitPolicy. Generic loop consults
    /// `ExitPolicy.get_action(reason).trap` to decide forward-vs-local.
    ///
    /// `reason` is the raw exit reason code (passed through to ExitPolicy lookup
    /// and forwarded to parent). `info` carries arch-decoded details for the
    /// local handler if policy says trap=false.
    PolicyDriven { reason: u32, info: ExitInfo },

    /// Fatal exit — log and halt.
    Shutdown { reason: u32 },
}

/// Arch-decoded exit details carried inside `SemanticExit::PolicyDriven`.
///
/// Generic code does NOT inspect these variants — they are passed through to
/// `ArchVpOps::handle_local` when `ExitPolicy` says `trap=false`, and to
/// `forward_to_parent` for comm-page population when `trap=true`.
pub enum ExitInfo {
    Cpuid {
        leaf: u32,
        subleaf: u32,
    },
    Exception {
        vector: u8,
        error_code: Option<u32>,
        is_nmi: bool,
    },
    EptViolation {
        gpa: u64,
        qualification: u64,
    },
    IoInstruction {
        port: u16,
        size: u8,
        is_write: bool,
        value: u32,
    },
    CrAccess {
        qualification: u64,
    },
    Msr {
        number: u32,
        is_write: bool,
        value: u64,
    },
    ApicIcr {
        icr_low: u32,
        icr_high: u32,
    },
    Sipi {
        vector_page: u8,
    },
    /// AArch64: Stage-2 translation fault (IPA fault, analogous to EPT violation).
    Stage2Fault {
        ipa: u64,
        is_write: bool,
        fsc: u32,
    },
    /// AArch64: Trapped system register access (MRS/MSR to EL1 sysreg).
    SystemRegTrap {
        reg_encoding: u32,
        is_write: bool,
        value: u64,
    },
    /// AArch64: SMC (Secure Monitor Call) from guest.
    Smc {
        imm: u16,
    },
    /// AArch64: WFI/WFE trapped at EL2.
    Wfi,
    Halt,
    Other,
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

// ── Platform-agnostic VP wrapper ─────────────────────────────────────────── //

use super::traits::ArchVpOps;

/// Platform-agnostic virtual processor.
///
/// Wraps an arch backend (`A`) and its VP handle together into a single
/// value that the generic monitor loop can pass around. The monitor loop
/// calls methods on `Vp<A>` which delegate to `ArchVpOps` methods,
/// keeping the loop free of arch-specific types.
///
/// On x86 this wraps `X86Platform` + `ActiveVcpu`.
/// On ARM it would wrap `ArmPlatform` + `ArmVpState`.
pub struct Vp<A: ArchVpOps> {
    pub(crate) arch: A,
    pub(crate) handle: A::VpHandle,
}

impl<A: ArchVpOps> Vp<A> {
    /// Create a new platform-agnostic VP from an arch backend and handle.
    pub fn new(arch: A, handle: A::VpHandle) -> Self {
        Self { arch, handle }
    }

    /// Enter the guest and decode the exit.
    pub fn run(&mut self) -> SemanticExit {
        self.arch.run(&mut self.handle)
    }

    /// Handle a non-trapped (local) exit.
    pub fn handle_local(&mut self, reason: u32, info: &ExitInfo) {
        self.arch.handle_local(&mut self.handle, reason, info);
    }

    /// Dispatch a hypercall through the capability engine.
    pub fn dispatch_hypercall(&mut self) {
        self.arch.dispatch_hypercall(&mut self.handle);
    }

    /// Read hypercall arguments from the VP's register state.
    pub fn get_args(&self) -> super::types::HypercallArgs {
        self.arch.get_hypercall_args(&self.handle)
    }

    /// Write a hypercall result back to the VP's register state.
    /// Does NOT advance the instruction pointer — call `next_rip` after.
    pub fn write_reply(&mut self, result: super::types::HypercallResult) {
        self.arch.set_hypercall_result(&mut self.handle, result);
    }

    /// Advance the VP's instruction pointer past the trap that caused the exit.
    pub fn next_rip(&mut self) {
        self.arch.next_rip(&mut self.handle);
    }

    /// Forward an exit to the parent domain.
    pub fn forward_exit(&mut self, reason: u32) {
        self.arch.forward_exit(&mut self.handle, reason);
    }

    /// Forward an interrupt to the handler domain.
    pub fn forward_interrupt(&mut self, vector: u32) {
        self.arch.forward_interrupt(&mut self.handle, vector);
    }

    /// Reset the preemption timer.
    pub fn reset_timer(&mut self) {
        self.arch.reset_timer(&mut self.handle);
    }

    /// Write an emulated CPUID result and advance IP.
    pub fn emulate_cpuid(&mut self, result: &capability_engine::interposition::CpuidResult) {
        self.arch.emulate_cpuid(&mut self.handle, result);
    }

    /// Write an emulated MSR read result and advance IP.
    pub fn emulate_rdmsr(&mut self, value: u64) {
        self.arch.emulate_rdmsr(&mut self.handle, value);
    }

    /// Try to handle a WRMSR Emulate via capavisor's internal registry.
    /// Returns `Ok(())` if handled (caller resumes guest), `Err(())` if
    /// the caller should trap to parent.
    pub fn try_emulate_wrmsr(&mut self, msr: u32, value: u64) -> Result<(), ()> {
        self.arch.try_emulate_wrmsr(&mut self.handle, msr, value)
    }

    /// Give the arch-side MSR emulators a chance to consume a preemption-timer
    /// exit (e.g. TSC-deadline injection). Returns `true` if consumed.
    pub fn try_consume_preemption_timer(&mut self) -> bool {
        self.arch.try_consume_preemption_timer(&mut self.handle)
    }
}
