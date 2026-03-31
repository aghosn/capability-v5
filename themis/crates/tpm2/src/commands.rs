//! TPM 2.0 command serialization/deserialization.
//!
//! Each command is a packed big-endian byte buffer per the TPM 2.0 spec
//! (Part 3: Commands).  We build them inline rather than pulling in a
//! full TPM command library — we only need 4 commands.

// ── TPM 2.0 constants ────────────────────────────────────────────────────── //

/// Command/response header tag: no sessions.
pub const TPM2_ST_NO_SESSIONS: u16 = 0x8001;

/// Command/response header tag: has sessions (required for PCR_Extend).
pub const TPM2_ST_SESSIONS: u16 = 0x8002;

// Command codes (TPM_CC)
pub const TPM2_CC_STARTUP: u32 = 0x0000_0144;
pub const TPM2_CC_PCR_EXTEND: u32 = 0x0000_0182;
pub const TPM2_CC_PCR_READ: u32 = 0x0000_017E;
pub const TPM2_CC_GET_RANDOM: u32 = 0x0000_017B;

// Startup types
pub const TPM2_SU_CLEAR: u16 = 0x0000;

// Algorithm IDs
pub const TPM2_ALG_SHA256: u16 = 0x000B;

// PCR handle base (PCR 0 = 0x00000000, PCR N = base + N)
pub const TPM2_HR_PCR: u32 = 0x0000_0000;

// Response codes
pub const TPM2_RC_SUCCESS: u32 = 0x0000_0000;
pub const TPM2_RC_INITIALIZE: u32 = 0x0000_0100;

/// SHA-256 digest size.
pub const SHA256_DIGEST_SIZE: usize = 32;

// ── Command buffer helpers ───────────────────────────────────────────────── //

/// Fixed-size buffer for TPM command/response serialization.
/// 256 bytes is more than enough for our 4 commands (largest is PCR_Extend
/// at ~75 bytes).
pub const CMD_BUF_SIZE: usize = 256;

pub struct CmdBuf {
    pub data: [u8; CMD_BUF_SIZE],
    pub len: usize,
}

impl CmdBuf {
    pub fn new() -> Self {
        CmdBuf {
            data: [0u8; CMD_BUF_SIZE],
            len: 0,
        }
    }

    pub fn put_u8(&mut self, v: u8) {
        self.data[self.len] = v;
        self.len += 1;
    }

    pub fn put_u16(&mut self, v: u16) {
        let be = v.to_be_bytes();
        self.data[self.len..self.len + 2].copy_from_slice(&be);
        self.len += 2;
    }

    pub fn put_u32(&mut self, v: u32) {
        let be = v.to_be_bytes();
        self.data[self.len..self.len + 4].copy_from_slice(&be);
        self.len += 4;
    }

    pub fn put_bytes(&mut self, src: &[u8]) {
        self.data[self.len..self.len + src.len()].copy_from_slice(src);
        self.len += src.len();
    }

    /// Patch the command size field (bytes 2..6) with the final length.
    pub fn finalize(&mut self) {
        let size = (self.len as u32).to_be_bytes();
        self.data[2..6].copy_from_slice(&size);
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

// ── Response parsing ─────────────────────────────────────────────────────── //

/// Read a big-endian u16 from `buf[off..off+2]`.
pub fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off], buf[off + 1]])
}

/// Read a big-endian u32 from `buf[off..off+4]`.
pub fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

// ── Command builders ─────────────────────────────────────────────────────── //

/// Build `TPM2_Startup(TPM_SU_CLEAR)`.
pub fn build_startup() -> CmdBuf {
    let mut cmd = CmdBuf::new();
    cmd.put_u16(TPM2_ST_NO_SESSIONS); // tag
    cmd.put_u32(0); // size placeholder
    cmd.put_u32(TPM2_CC_STARTUP);
    cmd.put_u16(TPM2_SU_CLEAR);
    cmd.finalize();
    cmd
}

/// Build `TPM2_PCR_Extend(pcr_index, SHA-256, digest)`.
///
/// This command requires an authorization session (password session, empty
/// password).  The PCR handle is `TPM2_HR_PCR + pcr_index`.
pub fn build_pcr_extend(pcr_index: u32, digest: &[u8; SHA256_DIGEST_SIZE]) -> CmdBuf {
    let mut cmd = CmdBuf::new();
    cmd.put_u16(TPM2_ST_SESSIONS); // tag: sessions required
    cmd.put_u32(0); // size placeholder

    cmd.put_u32(TPM2_CC_PCR_EXTEND);
    cmd.put_u32(TPM2_HR_PCR + pcr_index); // pcrHandle

    // Authorization area (password session, empty password)
    // authorizationSize (u32) — size of the auth area that follows
    let auth_size: u32 = 4 + 2 + 1 + 2; // sessionHandle + nonceTpm.size + sessionAttributes + hmac.size
    cmd.put_u32(auth_size);
    cmd.put_u32(0x4000_0009); // TPM_RS_PW (password session handle)
    cmd.put_u16(0); // nonceTpm.size = 0
    cmd.put_u8(0); // sessionAttributes = 0 (continueSession=0)
    cmd.put_u16(0); // hmac.size = 0 (empty password)

    // TPML_DIGEST_VALUES: count=1, then one TPMT_HA
    cmd.put_u32(1); // count
    cmd.put_u16(TPM2_ALG_SHA256); // hashAlg
    cmd.put_bytes(digest); // digest (32 bytes)

    cmd.finalize();
    cmd
}

/// Build `TPM2_PCR_Read` for a single PCR with SHA-256 bank.
pub fn build_pcr_read(pcr_index: u32) -> CmdBuf {
    let mut cmd = CmdBuf::new();
    cmd.put_u16(TPM2_ST_NO_SESSIONS); // tag
    cmd.put_u32(0); // size placeholder
    cmd.put_u32(TPM2_CC_PCR_READ);

    // TPML_PCR_SELECTION: count=1, then one TPMS_PCR_SELECTION
    cmd.put_u32(1); // count
    cmd.put_u16(TPM2_ALG_SHA256); // hash
    cmd.put_u8(3); // sizeofSelect (3 bytes = 24 PCRs)

    // PCR select bitmap: set bit `pcr_index`
    let mut select = [0u8; 3];
    if pcr_index < 24 {
        select[(pcr_index / 8) as usize] = 1 << (pcr_index % 8);
    }
    cmd.put_bytes(&select);

    cmd.finalize();
    cmd
}

/// Parse a `TPM2_PCR_Read` response, extracting the SHA-256 digest.
///
/// Returns `Some(digest)` on success, `None` if the response is malformed
/// or contains no digests.
pub fn parse_pcr_read_response(buf: &[u8]) -> Option<[u8; SHA256_DIGEST_SIZE]> {
    // Response layout:
    //   [0..2]   tag
    //   [2..6]   responseSize
    //   [6..10]  responseCode
    //   [10..14] pcrUpdateCounter
    //   [14..]   TPML_PCR_SELECTION (pcrSelectionOut)
    //   [..]     TPML_DIGEST (pcrValues)

    if buf.len() < 14 {
        return None;
    }
    let rc = read_u32(buf, 6);
    if rc != TPM2_RC_SUCCESS {
        return None;
    }

    // Skip pcrUpdateCounter (4 bytes at offset 10)
    let mut off = 14;

    // Skip TPML_PCR_SELECTION
    if off + 4 > buf.len() {
        return None;
    }
    let sel_count = read_u32(buf, off) as usize;
    off += 4;
    for _ in 0..sel_count {
        // TPMS_PCR_SELECTION: hash(2) + sizeofSelect(1) + select[sizeofSelect]
        if off + 3 > buf.len() {
            return None;
        }
        let size_of_select = buf[off + 2] as usize;
        off += 3 + size_of_select;
    }

    // TPML_DIGEST: count(4) + TPML2B_DIGEST[count]
    if off + 4 > buf.len() {
        return None;
    }
    let digest_count = read_u32(buf, off);
    off += 4;
    if digest_count < 1 {
        return None;
    }

    // First TPM2B_DIGEST: size(2) + buffer[size]
    if off + 2 > buf.len() {
        return None;
    }
    let digest_size = read_u16(buf, off) as usize;
    off += 2;
    if digest_size != SHA256_DIGEST_SIZE || off + digest_size > buf.len() {
        return None;
    }

    let mut digest = [0u8; SHA256_DIGEST_SIZE];
    digest.copy_from_slice(&buf[off..off + SHA256_DIGEST_SIZE]);
    Some(digest)
}

/// Build `TPM2_GetRandom(bytesRequested)`.
pub fn build_get_random(bytes_requested: u16) -> CmdBuf {
    let mut cmd = CmdBuf::new();
    cmd.put_u16(TPM2_ST_NO_SESSIONS); // tag
    cmd.put_u32(0); // size placeholder
    cmd.put_u32(TPM2_CC_GET_RANDOM);
    cmd.put_u16(bytes_requested);
    cmd.finalize();
    cmd
}

/// Parse a `TPM2_GetRandom` response, copying random bytes into `out`.
///
/// Returns the number of bytes written, or `None` on error.
pub fn parse_get_random_response(buf: &[u8], out: &mut [u8]) -> Option<usize> {
    // Response layout:
    //   [0..2]   tag
    //   [2..6]   responseSize
    //   [6..10]  responseCode
    //   [10..12] randomBytes.size (u16)
    //   [12..]   randomBytes.buffer

    if buf.len() < 12 {
        return None;
    }
    let rc = read_u32(buf, 6);
    if rc != TPM2_RC_SUCCESS {
        return None;
    }
    let rand_size = read_u16(buf, 10) as usize;
    if 12 + rand_size > buf.len() {
        return None;
    }
    let copy_len = rand_size.min(out.len());
    out[..copy_len].copy_from_slice(&buf[12..12 + copy_len]);
    Some(copy_len)
}
