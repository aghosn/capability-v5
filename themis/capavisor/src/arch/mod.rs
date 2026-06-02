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
//! The contract for those state structs is expressed as **explicit traits**:
//! [`crate::arch_traits::ArchPlatform`] and (forthcoming)
//! `crate::arch_traits::ArchDomain`. Each arch's `arch_state.rs` defines a
//! concrete struct AND implements the matching trait. The cross-arch carrier
//! brings the trait into scope and calls trait methods on `self.arch` —
//! compile-time selection of the concrete impl, no `dyn` overhead, but the
//! cross-arch surface is discoverable in one place.
//!
//! Why a trait instead of inherent methods on cfg-selected concrete types?
//! Adding a new method to `ArchPlatformState` on x86 without updating the
//! ARM impl produces a far-flung "no method named foo" error at the call
//! site. With a trait, the ARM impl is forced to provide a stub at impl
//! definition time. The migration from the older inherent-method pattern
//! is in progress — see Phase 11 in the plan; `ArchPlatform` already exists
//! and `ArchDomain` lands as we lift more x86 work out of `platform/mod.rs`.
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
