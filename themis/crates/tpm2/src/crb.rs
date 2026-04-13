//! TPM 2.0 CRB (Command Response Buffer) MMIO driver.
//!
//! CRB is the modern TPM 2.0 interface defined in the TCG PC Client Platform
//! TPM Profile Specification (PTP), §7.  Unlike TIS (FIFO), CRB provides
//! memory-mapped command and response buffers — no byte-at-a-time FIFO.
//!
//! Protocol:
//! 1. Request locality via `LOC_CTRL`
//! 2. Write full command to the data buffer at `CTRL_CMD_LADDR`
//! 3. Write `1` to `CTRL_START`
//! 4. Poll `CTRL_START` until it reads `0` (command complete)
//! 5. Read response from the same data buffer

use crate::commands::{self, CMD_BUF_SIZE};

// ── CRB register offsets from the locality base (0xFED4_0000) ────────────── //
// All offsets per TCG PC Client PTP spec, Table 18.

const CRB_LOC_STATE: u64 = 0x00;
const CRB_LOC_CTRL: u64 = 0x08;
const CRB_LOC_STS: u64 = 0x0C;
const CRB_INTF_ID: u64 = 0x30;
const CRB_CTRL_REQ: u64 = 0x40;
const CRB_CTRL_STS: u64 = 0x44;
const CRB_CTRL_CANCEL: u64 = 0x48;
const CRB_CTRL_START: u64 = 0x4C;
const CRB_CTRL_CMD_SIZE: u64 = 0x58;
const CRB_CTRL_CMD_LADDR: u64 = 0x5C;
const CRB_CTRL_CMD_HADDR: u64 = 0x60;
const CRB_CTRL_RSP_SIZE: u64 = 0x64;
const CRB_CTRL_RSP_ADDR: u64 = 0x68;

// LOC_STATE bits
const LOC_STATE_ASSIGNED: u32 = 1 << 1;

// LOC_CTRL bits
const LOC_CTRL_REQUEST: u32 = 1 << 0;
const LOC_CTRL_RELINQUISH: u32 = 1 << 1;

// LOC_STS bits
const LOC_STS_GRANTED: u32 = 1 << 0;

// CTRL_REQ bits
const CTRL_REQ_CMD_READY: u32 = 1 << 0;
const CTRL_REQ_GO_IDLE: u32 = 1 << 1;

// CTRL_STS bits
const CTRL_STS_ERROR: u32 = 1 << 0;

// Timeout limits (spin counts)
const TIMEOUT_SPIN: u32 = 2_000_000;

use crate::tis::Tpm2Error;

// ── CRB Transport ────────────────────────────────────────────────────────── //

/// CRB transport: base is the locality base address (e.g., 0xFED4_0000 + HHDM).
///
/// All CRB registers are at fixed offsets from this base. The ACPI TPM2
/// table's "control_area" field points to offset 0x40 within this region,
/// but we use the locality base directly.
pub(crate) struct CrbTransport {
    /// Virtual address of the CRB locality base.
    base: u64,
}

impl CrbTransport {
    pub const fn new(locality_base_va: u64) -> Self {
        CrbTransport {
            base: locality_base_va,
        }
    }

    // ── Low-level MMIO ───────────────────────────────────────────────────

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

    #[inline]
    unsafe fn read8(&self, offset: u64) -> u8 {
        let ptr = (self.base + offset) as *const u8;
        core::ptr::read_volatile(ptr)
    }

    // ── Locality ─────────────────────────────────────────────────────────

    pub fn probe(&self) -> bool {
        let intf_id = unsafe { self.read32(CRB_INTF_ID) };
        // INTF_ID bits [3:0] = interface type: 1 = CRB
        // 0xFFFFFFFF or 0 means no device
        intf_id != 0xFFFF_FFFF && intf_id != 0
    }

    fn request_locality(&self) -> Result<(), Tpm2Error> {
        unsafe {
            // Check if already assigned
            let state = self.read32(CRB_LOC_STATE);
            if state & LOC_STATE_ASSIGNED != 0 {
                return Ok(());
            }

            // Request locality 0
            self.write32(CRB_LOC_CTRL, LOC_CTRL_REQUEST);

            for _ in 0..TIMEOUT_SPIN {
                let sts = self.read32(CRB_LOC_STS);
                if sts & LOC_STS_GRANTED != 0 {
                    return Ok(());
                }
                core::hint::spin_loop();
            }
        }
        Err(Tpm2Error::LocalityError)
    }

    fn release_locality(&self) {
        unsafe {
            self.write32(CRB_LOC_CTRL, LOC_CTRL_RELINQUISH);
        }
    }

    // ── Command Ready ────────────────────────────────────────────────────

    fn go_ready(&self) -> Result<(), Tpm2Error> {
        unsafe {
            self.write32(CRB_CTRL_REQ, CTRL_REQ_CMD_READY);

            for _ in 0..TIMEOUT_SPIN {
                let req = self.read32(CRB_CTRL_REQ);
                if req & CTRL_REQ_CMD_READY == 0 {
                    return Ok(());
                }
                core::hint::spin_loop();
            }
        }
        Err(Tpm2Error::Timeout)
    }

    // ── Transaction ──────────────────────────────────────────────────────

    /// Send a command and receive the response via CRB buffers.
    ///
    /// The command/response buffer is at offset 0x80 from the locality base.
    /// We use the already-mapped virtual address rather than reading
    /// CRB_CTRL_CMD_LADDR (which returns a physical address).
    pub fn transact(
        &self,
        cmd: &commands::CmdBuf,
        resp: &mut [u8; CMD_BUF_SIZE],
    ) -> Result<usize, Tpm2Error> {
        self.request_locality()?;
        self.go_ready()?;

        let cmd_bytes = cmd.as_bytes();
        let cmd_len = cmd_bytes.len();

        // Data buffer is at fixed offset 0x80 from locality base (already HHDM-mapped).
        const DATA_BUF_OFFSET: u64 = 0x80;
        let buf_va = self.base + DATA_BUF_OFFSET;

        unsafe {
            let cmd_buf_size = self.read32(CRB_CTRL_CMD_SIZE) as usize;
            if cmd_len > cmd_buf_size {
                return Err(Tpm2Error::BadResponse);
            }

            // Write the full command into the data buffer.
            let cmd_ptr = buf_va as *mut u8;
            for i in 0..cmd_len {
                core::ptr::write_volatile(cmd_ptr.add(i), cmd_bytes[i]);
            }

            // Kick off execution.
            self.write32(CRB_CTRL_START, 1);

            // Poll until CTRL_START clears (command complete).
            for _ in 0..TIMEOUT_SPIN {
                let start = self.read32(CRB_CTRL_START);
                if start == 0 {
                    break;
                }
                core::hint::spin_loop();
            }

            // Check for errors.
            let sts = self.read32(CRB_CTRL_STS);
            if sts & CTRL_STS_ERROR != 0 {
                return Err(Tpm2Error::BadResponse);
            }

            // Read response from the same data buffer.
            let rsp_buf_size = self.read32(CRB_CTRL_RSP_SIZE) as usize;
            let rsp_ptr = buf_va as *const u8;

            // Read header first (10 bytes) to get total size.
            if rsp_buf_size < 10 {
                return Err(Tpm2Error::BadResponse);
            }
            for i in 0..10 {
                resp[i] = core::ptr::read_volatile(rsp_ptr.add(i));
            }

            let total_size = commands::read_u32(resp, 2) as usize;
            if total_size > CMD_BUF_SIZE || total_size > rsp_buf_size || total_size < 10 {
                return Err(Tpm2Error::BadResponse);
            }

            // Read remaining bytes.
            for i in 10..total_size {
                resp[i] = core::ptr::read_volatile(rsp_ptr.add(i));
            }

            // Go idle.
            self.write32(CRB_CTRL_REQ, CTRL_REQ_GO_IDLE);

            // Check response code.
            let rc = commands::read_u32(resp, 6);
            if rc != commands::TPM2_RC_SUCCESS {
                return Err(Tpm2Error::TpmError(rc));
            }

            Ok(total_size)
        }
    }
}
