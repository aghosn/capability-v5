//! Minimal TPM 2.0 driver for bare-metal (no_std).
//!
//! Supports the TIS (TPM Interface Specification) MMIO interface at
//! `0xFED4_0000`.  This is sufficient for both real hardware TPM 2.0 chips
//! and QEMU's swtpm emulator (which presents a TIS-compatible device).
//!
//! Implemented commands:
//! - [`Tpm2::startup`] — `TPM2_Startup(TPM_SU_CLEAR)`
//! - [`Tpm2::pcr_extend`] — `TPM2_PCR_Extend` (SHA-256)
//! - [`Tpm2::pcr_read`] — `TPM2_PCR_Read` (SHA-256)
//! - [`Tpm2::get_random`] — `TPM2_GetRandom`
//! - [`Tpm2::create_primary_rsa`] — `TPM2_CreatePrimary` (RSA-2048 signing key)
//! - [`Tpm2::quote`] — `TPM2_Quote` (PCR attestation)
//!
//! # Safety
//!
//! This driver performs raw MMIO reads/writes.  The caller must ensure:
//! 1. The TPM MMIO region is identity-mapped in the page tables.
//! 2. No other software concurrently accesses the TPM (guaranteed by A5:
//!    META pool is capavisor-only, never in any domain's EPT).

#![no_std]

mod tis;
mod commands;

pub use commands::QuoteResult;
pub use tis::{Tpm2, Tpm2Error, TIS_BASE};
