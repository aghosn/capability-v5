//! TPM 2.0 command serialization/deserialization.
//!
//! Each command is a packed big-endian byte buffer per the TPM 2.0 spec
//! (Part 3: Commands).  We build them inline rather than pulling in a
//! full TPM command library — we only need 6 commands.

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
pub const TPM2_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
pub const TPM2_CC_QUOTE: u32 = 0x0000_0158;

// Startup types
pub const TPM2_SU_CLEAR: u16 = 0x0000;

// Algorithm IDs
pub const TPM2_ALG_SHA256: u16 = 0x000B;
pub const TPM2_ALG_RSA: u16 = 0x0001;
pub const TPM2_ALG_RSASSA: u16 = 0x0014;
pub const TPM2_ALG_NULL: u16 = 0x0010;
pub const TPM2_ALG_CFB: u16 = 0x0043;
pub const TPM2_ALG_AES: u16 = 0x0006;

// PCR handle base (PCR 0 = 0x00000000, PCR N = base + N)
pub const TPM2_HR_PCR: u32 = 0x0000_0000;

// Hierarchy handles
pub const TPM2_RH_OWNER: u32 = 0x4000_0001;

// Response codes
pub const TPM2_RC_SUCCESS: u32 = 0x0000_0000;
pub const TPM2_RC_INITIALIZE: u32 = 0x0000_0100;

/// SHA-256 digest size.
pub const SHA256_DIGEST_SIZE: usize = 32;

// Object attributes
pub const TPMA_OBJECT_SIGN_ENCRYPT: u32 = 1 << 18;
pub const TPMA_OBJECT_FIXED_TPM: u32 = 1 << 1;
pub const TPMA_OBJECT_FIXED_PARENT: u32 = 1 << 4;
pub const TPMA_OBJECT_SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
pub const TPMA_OBJECT_USER_WITH_AUTH: u32 = 1 << 6;

// ── Command buffer helpers ───────────────────────────────────────────────── //

/// Fixed-size buffer for TPM command/response serialization.
/// 1024 bytes accommodates CreatePrimary responses (RSA-2048 public key).
pub const CMD_BUF_SIZE: usize = 1024;

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

// ── CreatePrimary (RSA-2048 signing key) ─────────────────────────────────── //

/// Build `TPM2_CreatePrimary` for an RSA-2048 signing key under Owner hierarchy.
pub fn build_create_primary_rsa() -> CmdBuf {
    let mut cmd = CmdBuf::new();
    cmd.put_u16(TPM2_ST_SESSIONS); // tag: sessions required
    cmd.put_u32(0); // size placeholder
    cmd.put_u32(TPM2_CC_CREATE_PRIMARY);

    // primaryHandle: Owner hierarchy
    cmd.put_u32(TPM2_RH_OWNER);

    // Authorization area (password session, empty password)
    let auth_size: u32 = 4 + 2 + 1 + 2; // sessionHandle + nonce.size + attrs + hmac.size
    cmd.put_u32(auth_size);
    cmd.put_u32(0x4000_0009); // TPM_RS_PW
    cmd.put_u16(0); // nonceTpm.size = 0
    cmd.put_u8(0); // sessionAttributes = 0
    cmd.put_u16(0); // hmac.size = 0 (empty password)

    // inSensitive: TPM2B_SENSITIVE_CREATE
    // Inner TPMS_SENSITIVE_CREATE = userAuth(2: size=0) + data(2: size=0) = 4 bytes
    cmd.put_u16(4); // TPM2B size
    cmd.put_u16(0); // userAuth.size = 0
    cmd.put_u16(0); // data.size = 0

    // inPublic: TPM2B_PUBLIC { size(2) + TPMT_PUBLIC }
    // TPMT_PUBLIC layout:
    //   type(2) + nameAlg(2) + objectAttributes(4) + authPolicy(2: size=0)
    //   + TPMS_RSA_PARMS { symmetric(2: NULL) + scheme(2+2: RSASSA+SHA256)
    //     + keyBits(2) + exponent(4) }
    //   + unique(2: size=0)
    // = 2+2+4+2 + (2+4+2+4) + 2 = 24 bytes
    let tpmt_public_size: u16 = 2 + 2 + 4 + 2 + (2 + 2 + 2 + 2 + 4) + 2;
    cmd.put_u16(tpmt_public_size); // TPM2B_PUBLIC.size

    cmd.put_u16(TPM2_ALG_RSA); // type
    cmd.put_u16(TPM2_ALG_SHA256); // nameAlg
    let attrs = TPMA_OBJECT_FIXED_TPM
        | TPMA_OBJECT_FIXED_PARENT
        | TPMA_OBJECT_SENSITIVE_DATA_ORIGIN
        | TPMA_OBJECT_USER_WITH_AUTH
        | TPMA_OBJECT_SIGN_ENCRYPT;
    cmd.put_u32(attrs); // objectAttributes
    cmd.put_u16(0); // authPolicy.size = 0

    // TPMS_RSA_PARMS
    cmd.put_u16(TPM2_ALG_NULL); // symmetric.algorithm = NULL
    cmd.put_u16(TPM2_ALG_RSASSA); // scheme.scheme = RSASSA
    cmd.put_u16(TPM2_ALG_SHA256); // scheme.details.hashAlg = SHA256
    cmd.put_u16(2048); // keyBits
    cmd.put_u32(0); // exponent (0 = default 65537)

    // unique: TPM2B_PUBLIC_KEY_RSA (empty — TPM generates the key)
    cmd.put_u16(0); // unique.size = 0

    // outsideInfo: TPM2B_DATA
    cmd.put_u16(0); // size = 0

    // creationPCR: TPML_PCR_SELECTION
    cmd.put_u32(0); // count = 0

    cmd.finalize();
    cmd
}

/// Parse a `TPM2_CreatePrimary` response, extracting key handle and RSA-2048
/// public modulus N (256 bytes).
///
/// Returns `Some((handle, n_bytes))` on success.
pub fn parse_create_primary_response(buf: &[u8]) -> Option<(u32, [u8; 256])> {
    // Response layout (TPM2_ST_SESSIONS):
    //   [0..2]   tag
    //   [2..6]   responseSize
    //   [6..10]  responseCode
    //   [10..14] handle (u32)
    //   [14..18] parameterSize (u32) — size of parameter area
    //   [18..]   outPublic (TPM2B_PUBLIC) + creationData + creationHash + ticket
    //   [..]     auth area

    if buf.len() < 18 {
        return None;
    }

    let handle = read_u32(buf, 10);

    // outPublic starts at offset 18
    let mut off = 18;

    // TPM2B_PUBLIC: size(2) + TPMT_PUBLIC
    if off + 2 > buf.len() {
        return None;
    }
    let pub_size = read_u16(buf, off) as usize;
    off += 2;
    if off + pub_size > buf.len() {
        return None;
    }

    // Parse TPMT_PUBLIC to find the unique field
    // type(2)
    if off + 2 > buf.len() {
        return None;
    }
    off += 2; // skip type (we know it's RSA)

    // nameAlg(2)
    off += 2;

    // objectAttributes(4)
    off += 4;

    // authPolicy: TPM2B_DIGEST { size(2) + data[size] }
    if off + 2 > buf.len() {
        return None;
    }
    let auth_policy_size = read_u16(buf, off) as usize;
    off += 2 + auth_policy_size;

    // TPMS_RSA_PARMS:
    //   symmetric: TPMT_SYM_DEF_OBJECT { algorithm(2), ... }
    if off + 2 > buf.len() {
        return None;
    }
    let sym_alg = read_u16(buf, off);
    off += 2;
    if sym_alg != TPM2_ALG_NULL {
        // symmetric has keyBits(2) + mode(2) if not NULL
        off += 2 + 2;
    }

    //   scheme: TPMT_RSA_SCHEME { scheme(2), ... }
    if off + 2 > buf.len() {
        return None;
    }
    let scheme_alg = read_u16(buf, off);
    off += 2;
    if scheme_alg != TPM2_ALG_NULL {
        // scheme has hashAlg(2)
        off += 2;
    }

    //   keyBits(2) + exponent(4)
    off += 2 + 4;

    // unique: TPM2B_PUBLIC_KEY_RSA { size(2) + buffer[size] }
    if off + 2 > buf.len() {
        return None;
    }
    let key_size = read_u16(buf, off) as usize;
    off += 2;

    if key_size != 256 || off + 256 > buf.len() {
        return None;
    }

    let mut n = [0u8; 256];
    n.copy_from_slice(&buf[off..off + 256]);

    Some((handle, n))
}

// ── Quote ────────────────────────────────────────────────────────────────── //

/// Result of a `TPM2_Quote` command.
pub struct QuoteResult {
    /// TPMS_ATTEST attestation blob.
    pub attest_data: [u8; 512],
    /// Actual size of data in `attest_data`.
    pub attest_size: usize,
    /// TPMT_SIGNATURE blob (sigAlg + hashAlg + signature).
    pub signature: [u8; 512],
    /// Actual size of data in `signature`.
    pub sig_size: usize,
}

/// Build `TPM2_Quote` for a single PCR (SHA-256 bank).
///
/// `ak_handle` is the signing key handle (e.g., from `create_primary_rsa`).
/// `qualifying_data` is the nonce/challenge (up to 64 bytes).
/// `pcr_index` is the PCR to quote.
pub fn build_quote(ak_handle: u32, qualifying_data: &[u8], pcr_index: u32) -> CmdBuf {
    let mut cmd = CmdBuf::new();
    cmd.put_u16(TPM2_ST_SESSIONS); // tag: sessions required
    cmd.put_u32(0); // size placeholder
    cmd.put_u32(TPM2_CC_QUOTE);

    // signHandle
    cmd.put_u32(ak_handle);

    // Authorization area (password session, empty password)
    let auth_size: u32 = 4 + 2 + 1 + 2;
    cmd.put_u32(auth_size);
    cmd.put_u32(0x4000_0009); // TPM_RS_PW
    cmd.put_u16(0); // nonceTpm.size = 0
    cmd.put_u8(0); // sessionAttributes = 0
    cmd.put_u16(0); // hmac.size = 0

    // qualifyingData: TPM2B_DATA
    cmd.put_u16(qualifying_data.len() as u16);
    cmd.put_bytes(qualifying_data);

    // inScheme: TPMT_SIG_SCHEME { scheme = NULL → use key's default }
    cmd.put_u16(TPM2_ALG_NULL);

    // PCRselect: TPML_PCR_SELECTION { count=1, then TPMS_PCR_SELECTION }
    cmd.put_u32(1); // count
    cmd.put_u16(TPM2_ALG_SHA256); // hash
    cmd.put_u8(3); // sizeofSelect (3 bytes = 24 PCRs)
    let mut select = [0u8; 3];
    if pcr_index < 24 {
        select[(pcr_index / 8) as usize] = 1 << (pcr_index % 8);
    }
    cmd.put_bytes(&select);

    cmd.finalize();
    cmd
}

/// Parse a `TPM2_Quote` response, extracting the attestation blob and signature.
pub fn parse_quote_response(buf: &[u8]) -> Option<QuoteResult> {
    // Response layout (TPM2_ST_SESSIONS):
    //   [0..2]   tag
    //   [2..6]   responseSize
    //   [6..10]  responseCode
    //   [10..14] parameterSize (u32)
    //   [14..]   quoted (TPM2B_ATTEST) + signature (TPMT_SIGNATURE)
    //   [..]     auth area

    if buf.len() < 14 {
        return None;
    }

    let param_size = read_u32(buf, 10) as usize;
    let mut off = 14;

    if off + param_size > buf.len() {
        return None;
    }
    let param_end = off + param_size;

    // quoted: TPM2B_ATTEST { size(2) + attestationData[size] }
    if off + 2 > param_end {
        return None;
    }
    let attest_size = read_u16(buf, off) as usize;
    off += 2;
    if attest_size > 512 || off + attest_size > param_end {
        return None;
    }

    let mut result = QuoteResult {
        attest_data: [0u8; 512],
        attest_size,
        signature: [0u8; 512],
        sig_size: 0,
    };
    result.attest_data[..attest_size].copy_from_slice(&buf[off..off + attest_size]);
    off += attest_size;

    // signature: TPMT_SIGNATURE — copy the rest of the parameter area
    let sig_size = param_end - off;
    if sig_size > 512 {
        return None;
    }
    result.signature[..sig_size].copy_from_slice(&buf[off..off + sig_size]);
    result.sig_size = sig_size;

    Some(result)
}
