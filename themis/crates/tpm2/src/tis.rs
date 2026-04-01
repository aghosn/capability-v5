//! TPM 2.0 TIS (TPM Interface Specification) MMIO driver.
//!
//! The TIS interface is defined in the TCG PC Client Platform TPM Profile
//! Specification (PTP), §6.  It maps the TPM's register space at a fixed
//! MMIO base address (default `0xFED4_0000`).
//!
//! Communication follows a simple protocol:
//! 1. Request locality 0
//! 2. Check device is ready (`STS.commandReady`)
//! 3. Write command bytes to the data FIFO
//! 4. Execute (set `STS.tpmGo`)
//! 5. Poll `STS.dataAvail` until response is ready
//! 6. Read response bytes from the data FIFO
//! 7. Write `STS.commandReady` to return to idle

#![allow(dead_code)]

use crate::commands::{self, CMD_BUF_SIZE, QuoteResult, SHA256_DIGEST_SIZE};

// ── TIS MMIO register offsets (locality 0) ───────────────────────────────── //

/// Default MMIO base address for the TPM TIS interface.
pub const TIS_BASE: u64 = 0xFED4_0000;

const REG_ACCESS: u64 = 0x00;
const REG_STS: u64 = 0x18;
const REG_DATA_FIFO: u64 = 0x24;
const REG_DID_VID: u64 = 0xF00;

// ACCESS register bits
const ACCESS_TPM_REG_VALID_STS: u8 = 1 << 7;
const ACCESS_ACTIVE_LOCALITY: u8 = 1 << 5;
const ACCESS_REQUEST_USE: u8 = 1 << 1;

// STS register bits (32-bit register, we use the low byte for writes)
const STS_VALID: u32 = 1 << 7;
const STS_COMMAND_READY: u32 = 1 << 6;
const STS_TPM_GO: u32 = 1 << 5;
const STS_DATA_AVAIL: u32 = 1 << 4;
const STS_EXPECT: u32 = 1 << 3;

// Timeout limits (iteration counts, not time-based — we spin in bare metal)
const TIMEOUT_SPIN: u32 = 2_000_000;

// ── Error type ───────────────────────────────────────────────────────────── //

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tpm2Error {
    /// No TPM detected at the MMIO base address.
    NotPresent,
    /// Timed out waiting for TPM readiness.
    Timeout,
    /// TPM returned an error response code.
    TpmError(u32),
    /// Response was malformed or too short.
    BadResponse,
    /// Could not acquire locality.
    LocalityError,
}

// ── Driver ───────────────────────────────────────────────────────────────── //

/// A minimal TPM 2.0 driver using the TIS MMIO interface.
///
/// The MMIO base address is configurable (defaults to [`TIS_BASE`]).
/// All register accesses are volatile MMIO reads/writes.
pub struct Tpm2 {
    base: u64,
}

impl Tpm2 {
    /// Create a new TPM driver for the given MMIO base address.
    ///
    /// Does NOT perform any I/O — call [`Tpm2::probe`] to check for presence.
    pub const fn new(base: u64) -> Self {
        Tpm2 { base }
    }

    /// Create a driver at the default TIS address (`0xFED4_0000`).
    pub const fn default() -> Self {
        Tpm2::new(TIS_BASE)
    }

    // ── Low-level MMIO ───────────────────────────────────────────────────

    #[inline]
    unsafe fn read8(&self, offset: u64) -> u8 {
        let ptr = (self.base + offset) as *const u8;
        core::ptr::read_volatile(ptr)
    }

    #[inline]
    unsafe fn write8(&self, offset: u64, val: u8) {
        let ptr = (self.base + offset) as *mut u8;
        core::ptr::write_volatile(ptr, val);
    }

    #[inline]
    unsafe fn read32(&self, offset: u64) -> u32 {
        let ptr = (self.base + offset) as *const u32;
        core::ptr::read_volatile(ptr)
    }

    #[inline]
    unsafe fn write32(&self, offset: u64, val: u32) {
        let ptr = (self.base + offset) as *mut u32;
        core::ptr::write_volatile(ptr, val);
    }

    // ── Locality + status helpers ────────────────────────────────────────

    /// Check whether a TPM is present at the configured base address.
    ///
    /// Reads the DID/VID register — a value of `0xFFFF_FFFF` or `0` means
    /// no device is mapped.
    pub fn probe(&self) -> bool {
        let did_vid = unsafe { self.read32(REG_DID_VID) };
        did_vid != 0xFFFF_FFFF && did_vid != 0
    }

    /// Request locality 0.
    fn request_locality(&self) -> Result<(), Tpm2Error> {
        unsafe {
            // Check if locality is already active
            let access = self.read8(REG_ACCESS);
            if access & ACCESS_ACTIVE_LOCALITY != 0 {
                return Ok(());
            }

            // Request use
            self.write8(REG_ACCESS, ACCESS_REQUEST_USE);

            // Wait for locality to become active
            for _ in 0..TIMEOUT_SPIN {
                let a = self.read8(REG_ACCESS);
                if a & ACCESS_ACTIVE_LOCALITY != 0 {
                    return Ok(());
                }
                core::hint::spin_loop();
            }
        }
        Err(Tpm2Error::LocalityError)
    }

    /// Relinquish locality 0.
    fn release_locality(&self) {
        unsafe {
            self.write8(REG_ACCESS, ACCESS_ACTIVE_LOCALITY);
        }
    }

    /// Wait for `STS.commandReady` to be set.
    fn wait_command_ready(&self) -> Result<(), Tpm2Error> {
        unsafe {
            // First, signal that we want command ready
            self.write8(REG_STS, STS_COMMAND_READY as u8);

            for _ in 0..TIMEOUT_SPIN {
                let sts = self.read32(REG_STS);
                if sts & STS_COMMAND_READY != 0 {
                    return Ok(());
                }
                core::hint::spin_loop();
            }
        }
        Err(Tpm2Error::Timeout)
    }

    /// Write command bytes to the data FIFO.
    fn write_command(&self, data: &[u8]) -> Result<(), Tpm2Error> {
        unsafe {
            for &byte in data {
                self.write8(REG_DATA_FIFO, byte);
            }

            // Verify TPM is no longer expecting data
            for _ in 0..TIMEOUT_SPIN {
                let sts = self.read32(REG_STS);
                if sts & STS_VALID != 0 {
                    if sts & STS_EXPECT == 0 {
                        return Ok(());
                    }
                    // TPM still expects more data — but we're done.
                    // This shouldn't happen for well-formed commands.
                    return Err(Tpm2Error::BadResponse);
                }
                core::hint::spin_loop();
            }
        }
        Err(Tpm2Error::Timeout)
    }

    /// Signal the TPM to process the command.
    fn execute(&self) {
        unsafe {
            self.write8(REG_STS, STS_TPM_GO as u8);
        }
    }

    /// Wait for response data to become available, then read it.
    fn read_response(&self, buf: &mut [u8; CMD_BUF_SIZE]) -> Result<usize, Tpm2Error> {
        unsafe {
            // Wait for dataAvail
            for _ in 0..TIMEOUT_SPIN {
                let sts = self.read32(REG_STS);
                if sts & STS_DATA_AVAIL != 0 {
                    break;
                }
                if sts & STS_COMMAND_READY != 0 {
                    // TPM returned to idle without data — error
                    return Err(Tpm2Error::BadResponse);
                }
                core::hint::spin_loop();
            }

            // Read response header first (10 bytes: tag(2) + size(4) + rc(4))
            let mut len = 0usize;
            for i in 0..10 {
                buf[i] = self.read8(REG_DATA_FIFO);
                len += 1;
            }

            // Extract total response size from header bytes 2..6
            let total_size = commands::read_u32(buf, 2) as usize;
            if total_size > CMD_BUF_SIZE || total_size < 10 {
                self.write8(REG_STS, STS_COMMAND_READY as u8);
                return Err(Tpm2Error::BadResponse);
            }

            // Read remaining bytes
            for i in 10..total_size {
                // Check dataAvail before each byte (may need to wait)
                for _ in 0..TIMEOUT_SPIN {
                    let sts = self.read32(REG_STS);
                    if sts & STS_DATA_AVAIL != 0 {
                        break;
                    }
                    core::hint::spin_loop();
                }
                buf[i] = self.read8(REG_DATA_FIFO);
                len += 1;
            }

            // Return to idle
            self.write8(REG_STS, STS_COMMAND_READY as u8);

            Ok(len)
        }
    }

    // ── Full command transaction ──────────────────────────────────────────

    /// Send a command and receive the response.
    fn transact(
        &self,
        cmd: &commands::CmdBuf,
        resp: &mut [u8; CMD_BUF_SIZE],
    ) -> Result<usize, Tpm2Error> {
        self.request_locality()?;
        self.wait_command_ready()?;
        self.write_command(cmd.as_bytes())?;
        self.execute();
        let len = self.read_response(resp)?;

        // Check response code
        if len >= 10 {
            let rc = commands::read_u32(resp, 6);
            if rc != commands::TPM2_RC_SUCCESS {
                // TPM2_Startup returns TPM2_RC_INITIALIZE if already started;
                // callers may want to handle this.
                return Err(Tpm2Error::TpmError(rc));
            }
        }

        Ok(len)
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
            Err(Tpm2Error::TpmError(rc)) if rc == commands::TPM2_RC_INITIALIZE => {
                // Already started — not an error
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Extend PCR `pcr_index` with a SHA-256 `digest`.
    ///
    /// The new PCR value becomes `SHA-256(old_value ‖ digest)`.
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
    ///
    /// Returns the 32-byte digest value.
    pub fn pcr_read(&self, pcr_index: u32) -> Result<[u8; SHA256_DIGEST_SIZE], Tpm2Error> {
        let cmd = commands::build_pcr_read(pcr_index);
        let mut resp = [0u8; CMD_BUF_SIZE];
        let len = self.transact(&cmd, &mut resp)?;
        commands::parse_pcr_read_response(&resp[..len]).ok_or(Tpm2Error::BadResponse)
    }

    /// Get `count` random bytes from the TPM's hardware RNG.
    ///
    /// Returns the number of bytes actually written to `out` (may be less
    /// than `count` if the TPM returns fewer).
    pub fn get_random(&self, out: &mut [u8]) -> Result<usize, Tpm2Error> {
        let count = out.len().min(32) as u16; // TPM spec: max 32 bytes per call
        let cmd = commands::build_get_random(count);
        let mut resp = [0u8; CMD_BUF_SIZE];
        let len = self.transact(&cmd, &mut resp)?;
        commands::parse_get_random_response(&resp[..len], out).ok_or(Tpm2Error::BadResponse)
    }

    /// Create an RSA-2048 primary signing key under the Owner hierarchy.
    ///
    /// Returns `(key_handle, public_key_modulus)` where the modulus is
    /// the 256-byte big-endian RSA-2048 N value.
    pub fn create_primary_rsa(&self) -> Result<(u32, [u8; 256]), Tpm2Error> {
        let cmd = commands::build_create_primary_rsa();
        let mut resp = [0u8; CMD_BUF_SIZE];
        let len = self.transact(&cmd, &mut resp)?;
        commands::parse_create_primary_response(&resp[..len]).ok_or(Tpm2Error::BadResponse)
    }

    /// Generate a TPM2_Quote: the TPM signs the selected PCR with the given key.
    ///
    /// `ak_handle` is the signing key (e.g., from [`create_primary_rsa`]).
    /// `qualifying_data` is a nonce/challenge (up to 64 bytes).
    /// `pcr_index` selects which PCR to include in the quote.
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
