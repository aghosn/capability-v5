//! Architecture-specific backend selection.
//!
//! On x86-64, re-exports from `arch::x86_64`. On AArch64, from `arch::aarch64`.
//! The active arch is selected at compile time via `cfg(target_arch)`.
//!
//! # Cross-arch state pattern
//!
//! Cross-arch carrier types in the platform layer (`ThemisPlatform`,
//! `PlatformDomain`) embed a per-arch state field whose type is a
//! `cfg(target_arch)`-selected concrete struct:
//!
//! - `ThemisPlatform { arch: ArchPlatformState, ... }`
//! - `PlatformDomain { arch: ArchDomainState, ... }`
//!
//! Each arch's `arch_state.rs` defines its own concrete `ArchPlatformState` /
//! `ArchDomainState` with the same set of inherent method names. The cross-
//! arch carrier calls `self.arch.foo(...)` and the compiler resolves to the
//! per-arch implementation via cfg. There is intentionally **no `ArchPlatform`
//! / `ArchDomain` trait** today — the contract is implicit, enforced by call
//! sites in the cross-arch carrier (a missing method becomes a compile error
//! on that arch).
//!
//! Trade-off: this matches `std::sys`-style HAL code (no virtual dispatch,
//! no extra layer) at the cost of contract discoverability. A future
//! migration to an explicit `ArchPlatform` / `ArchDomain` trait (Option A)
//! is tracked as `arch-trait-migration` in the project todo list — revisit
//! once the ARM backend has a non-stub implementation that exercises the
//! cross-arch surface. If we migrate, do `ArchPlatformState` and
//! `ArchDomainState` together for consistency.
//!
//! # Boot-pipeline contract
//!
//! `main.rs` is the platform-independent boot orchestrator. Each arch backend
//! must expose a `boot` submodule providing the following entry points (their
//! signatures may take arch-specific arguments and return arch-specific state
//! types — orchestration in `main.rs` is feature-gated by `cfg(target_arch)`):
//!
//! - `boot::platform(...) -> PlatformInfo` — discover memory map, CPU
//!   topology, IOMMU/GIC, and other firmware-described resources.
//! - `boot::init_themis(&PlatformInfo) -> ThemisPlatform` — build the
//!   capability-engine `Platform` and seed dom0's META pool.
//! - `boot::capa(&PlatformInfo, ThemisPlatform) -> CapaState` — initialise
//!   the capability engine and the dom0 second-stage page tables (EPT on
//!   x86, Stage-2 on ARM).
//! - `boot::linux(&PlatformInfo, &[ModuleInfo]) -> LinuxState` — load the
//!   dom0 kernel + initrd into RAM via the arch-appropriate boot protocol.
//! - `boot::launch(&LinuxState, ...) -> ActiveVcpu` — perform the final
//!   transition into dom0 (VMLAUNCH on x86, ERET to EL1 on ARM).
//!
//! Arch-specific extras (e.g. `boot::vmx()` on x86 for VMXON, the eventual
//! `boot::el2_init()` on ARM) live alongside but are not part of the cross-
//! arch surface — `main.rs` calls them under `cfg(target_arch)`.
//!
//! Cross-arch types (`PlatformInfo`, `CapaState`, `LinuxState`, …) are
//! intentionally per-arch today; if/when they converge enough they can be
//! lifted to a common crate or expressed via a `BootBackend` trait.

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

// Re-export the active arch so callers can use `crate::arch::*`.
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

#[cfg(target_arch = "aarch64")]
pub use aarch64::*;
