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

use crate::commands::{self, CMD_BUF_SIZE};

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
pub(crate) struct TisTransport {
    base: u64,
}

impl TisTransport {
    /// Create a new TIS transport for the given MMIO base address.
    pub const fn new(base: u64) -> Self {
        TisTransport { base }
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
    pub(crate) fn transact(
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
}
