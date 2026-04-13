//! Minimal TPM 2.0 driver for bare-metal (no_std).
//!
//! Supports two MMIO transports:
//! - **TIS** (FIFO) — byte-at-a-time via data FIFO register at `0xFED4_0000`
//! - **CRB** (Command Response Buffer) — bulk memory-mapped buffers
//!
//! The transport is selected at construction time based on the ACPI TPM2
//! table's `StartMethod` field:
//! - `StartMethod = 6` → TIS
//! - `StartMethod = 7` → CRB
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
#![allow(dead_code)] // Driver crate: spec constants/methods used selectively.

mod commands;
mod crb;
mod tis;

pub use commands::QuoteResult;
pub use tis::{Tpm2Error, TIS_BASE};

use commands::{CMD_BUF_SIZE, SHA256_DIGEST_SIZE};

/// TPM 2.0 driver with transport abstraction (TIS or CRB).
///
/// Construct with [`Tpm2::new`] (TIS) or [`Tpm2::new_crb`] (CRB).
#[allow(private_interfaces)]
pub enum Tpm2 {
    /// TIS (FIFO) transport.
    Tis(tis::TisTransport),
    /// CRB (Command Response Buffer) transport.
    Crb(crb::CrbTransport),
}

impl Tpm2 {
    /// Create a TIS-based TPM driver at the given MMIO virtual address.
    pub const fn new(base: u64) -> Self {
        Tpm2::Tis(tis::TisTransport::new(base))
    }

    /// Create a CRB-based TPM driver at the given locality base virtual address.
    ///
    /// The locality base is typically `TIS_BASE` (0xFED4_0000) + HHDM offset.
    /// CRB registers are at fixed offsets from this base.
    pub const fn new_crb(locality_base_va: u64) -> Self {
        Tpm2::Crb(crb::CrbTransport::new(locality_base_va))
    }

    /// Check whether a TPM is present.
    pub fn probe(&self) -> bool {
        match self {
            Tpm2::Tis(t) => t.probe(),
            Tpm2::Crb(c) => c.probe(),
        }
    }

    /// Send a command and receive the response (dispatch to transport).
    fn transact(
        &self,
        cmd: &commands::CmdBuf,
        resp: &mut [u8; CMD_BUF_SIZE],
    ) -> Result<usize, Tpm2Error> {
        match self {
            Tpm2::Tis(t) => t.transact(cmd, resp),
            Tpm2::Crb(c) => c.transact(cmd, resp),
        }
    }

    // ── Public API ───────────────────────────────────────────────────────

    /// Send `TPM2_Startup(TPM_SU_CLEAR)`.
    ///
    /// Safe to call even if the TPM is already started (e.g., by firmware) —
    /// in that case the TPM returns `TPM_RC_INITIALIZE`, which this function
    /// treats as success.
    pub fn startup(&self) -> Result<(), Tpm2Error> {
        if !self.probe() {
            return Err(Tpm2Error::NotPresent);
        }
        let cmd = commands::build_startup();
        let mut resp = [0u8; CMD_BUF_SIZE];
        match self.transact(&cmd, &mut resp) {
            Ok(_) => Ok(()),
            Err(Tpm2Error::TpmError(rc)) if rc == commands::TPM2_RC_INITIALIZE => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Extend PCR `pcr_index` with a SHA-256 `digest`.
    pub fn pcr_extend(
        &self,
        pcr_index: u32,
        digest: &[u8; SHA256_DIGEST_SIZE],
    ) -> Result<(), Tpm2Error> {
        let cmd = commands::build_pcr_extend(pcr_index, digest);
        let mut resp = [0u8; CMD_BUF_SIZE];
        self.transact(&cmd, &mut resp)?;
        Ok(())
    }

    /// Read PCR `pcr_index` from the SHA-256 bank.
    pub fn pcr_read(&self, pcr_index: u32) -> Result<[u8; SHA256_DIGEST_SIZE], Tpm2Error> {
        let cmd = commands::build_pcr_read(pcr_index);
        let mut resp = [0u8; CMD_BUF_SIZE];
        let len = self.transact(&cmd, &mut resp)?;
        commands::parse_pcr_read_response(&resp[..len]).ok_or(Tpm2Error::BadResponse)
    }

    /// Get `count` random bytes from the TPM's hardware RNG.
    pub fn get_random(&self, out: &mut [u8]) -> Result<usize, Tpm2Error> {
        let count = out.len().min(32) as u16;
        let cmd = commands::build_get_random(count);
        let mut resp = [0u8; CMD_BUF_SIZE];
        let len = self.transact(&cmd, &mut resp)?;
        commands::parse_get_random_response(&resp[..len], out).ok_or(Tpm2Error::BadResponse)
    }

    /// Create an RSA-2048 primary signing key under the Owner hierarchy.
    ///
    /// Returns `(key_handle, public_key_modulus)`.
    pub fn create_primary_rsa(&self) -> Result<(u32, [u8; 256]), Tpm2Error> {
        let cmd = commands::build_create_primary_rsa();
        let mut resp = [0u8; CMD_BUF_SIZE];
        let len = self.transact(&cmd, &mut resp)?;
        commands::parse_create_primary_response(&resp[..len]).ok_or(Tpm2Error::BadResponse)
    }

    /// Generate a TPM2_Quote: the TPM signs the selected PCR with the given key.
    pub fn quote(
        &self,
        ak_handle: u32,
        qualifying_data: &[u8],
        pcr_index: u32,
    ) -> Result<QuoteResult, Tpm2Error> {
        let cmd = commands::build_quote(ak_handle, qualifying_data, pcr_index);
        let mut resp = [0u8; CMD_BUF_SIZE];
        let len = self.transact(&cmd, &mut resp)?;
        commands::parse_quote_response(&resp[..len]).ok_or(Tpm2Error::BadResponse)
    }
}
