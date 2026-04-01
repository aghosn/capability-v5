//! DomainComm — binary wire format for domain-level communication.
//!
//! These structures are shared between the capavisor (producer/consumer) and
//! the thhv driver (consumer/producer).  They must be `#[repr(C)]` and match
//! the C definitions in `thhv/inc/thhv.h` exactly.
//!
//! See `thhv/docs/domain-comm-v0.2.md` for the full design.

// ── DomainComm constants ─────────────────────────────────────────────────── //

pub const DOMCOMM_MAGIC: u32 = 0x444F_4D43; // "DOMC"
pub const DOMCOMM_VERSION_MAJOR: u16 = 0;
pub const DOMCOMM_VERSION_MINOR: u16 = 2;

/// CPUID leaf for DomainComm discovery.
/// EAX:EBX = base GPA (lo:hi), ECX = region size in pages, EDX = flags.
pub const CPUID_DOMCOMM_LEAF: u32 = 0x4000_0002;

// ── Message types ────────────────────────────────────────────────────────── //

/// Capavisor → Domain (RX ring)
pub mod msg_types {
    pub const NONE: u32 = 0x0000;
    pub const ATTEST: u32 = 0x0001;
    pub const VP_EXIT: u32 = 0x0002;
    pub const IRQ_NOTIFY: u32 = 0x0003;
    pub const DOMAIN_EVENT: u32 = 0x0004;
    pub const ERROR: u32 = 0x0005;
    pub const GROW_ACK: u32 = 0x0006;
    pub const DOORBELL_NOTIFY: u32 = 0x0007;

    /// Domain → Capavisor (TX ring)
    pub const ATTEST_REQ: u32 = 0x0100;
    pub const ACK: u32 = 0x0101;
    pub const BULK_REG_SET: u32 = 0x0102;
    pub const GROW_RX: u32 = 0x0103;
    pub const GROW_TX: u32 = 0x0104;
    pub const ENUM_CAP: u32 = 0x0105;
}

// ── Header flags ─────────────────────────────────────────────────────────── //

pub const DOMCOMM_FLAG_RX_READY: u32 = 1 << 0;
pub const DOMCOMM_FLAG_TX_READY: u32 = 1 << 1;

// ── Attestation flags ────────────────────────────────────────────────────── //

pub const DOMCOMM_ATTEST_F_SEALED: u32 = 1 << 0;

// ── Error codes ──────────────────────────────────────────────────────────── //

pub const DOMCOMM_ERR_RING_FULL: u32 = 1;
pub const DOMCOMM_ERR_BAD_REQUEST: u32 = 2;

// ── Wire format structures ───────────────────────────────────────────────── //

/// Ring metadata (embedded in header page, one per direction).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RingMeta {
    pub head: u32,
    pub tail: u32,
    pub page_offset: u32,
    pub page_count: u32,
}

/// DomainComm header — page 0 of the region (4096 bytes).
#[repr(C)]
pub struct Header {
    pub magic: u32,
    pub version_major: u16,
    pub version_minor: u16,
    pub total_pages: u32,
    pub flags: u32,

    /// RX ring metadata (capavisor → domain).
    pub rx: RingMeta,
    /// TX ring metadata (domain → capavisor).
    pub tx: RingMeta,

    pub notify_vector: u32,
    pub notify_flags: u32,

    pub reserved: [u8; 4096 - 0x38],
}

/// Message header (16 bytes, prefixed to every message).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MsgHeader {
    pub message_type: u32,
    pub total_size: u32,
    pub sequence: u64,
}

/// Maximum message payload within a single page.
pub const MAX_PAYLOAD: usize = 4096 - core::mem::size_of::<MsgHeader>();

// ── Binary attestation report ────────────────────────────────────────────── //

/// Binary attestation report header (variable-length payload follows).
///
/// Followed by packed arrays (contiguous, no padding between arrays):
///   `MemCapEntry[nr_mem_caps]`
///   `DomCapEntry[nr_dom_caps]`
///   `PaMapEntry[nr_pa_entries]`
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AttestReport {
    pub domain_id: u64,
    pub flags: u32,
    pub num_vps: u32,
    pub api_flags: u32,
    pub nr_mem_caps: u32,
    pub nr_dom_caps: u32,
    pub nr_pa_entries: u32,
    pub chunk_index: u16,
    pub total_chunks: u16,
    pub reserved: u32,
}

/// Memory capability entry in the attestation report.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemCapEntry {
    pub handle: u64,
    pub gpa_start: u64,
    pub size: u64,
    pub rights: u32,
    pub attributes: u32,
    pub hpa_start: u64,
}

/// Domain capability entry in the attestation report.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DomCapEntry {
    pub handle: u64,
    pub domain_id: u64,
}

/// PA map entry (GPA→HPA translation range).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PaMapEntry {
    pub gpa_start: u64,
    pub hpa_start: u64,
    pub size: u64,
}

// ── Ring growth messages ─────────────────────────────────────────────────── //

/// GROW_RX / GROW_TX request payload (domain → capavisor).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GrowRequest {
    pub cap_handle: u64,
    pub cap_sub: u64,
    pub nr_pages: u32,
    pub reserved: u32,
}

/// GROW_ACK payload (capavisor → domain).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GrowAck {
    pub new_page_count: u32,
    pub new_capacity: u32,
    pub status: u32,
    pub reserved: u32,
}

// ── Async VP exit ────────────────────────────────────────────────────────── //

/// VP_EXIT payload (capavisor → domain).
///
/// Contains the VP index and the ThemIC intercept message.
/// The intercept message is opaque bytes here; the driver interprets it
/// using `themic_intercept_message` from thhv.h.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VpExit {
    pub vp_id: u32,
    pub reserved: u32,
    /// Raw intercept message (ThemIC format, 120 bytes).
    /// Matches sizeof(themic_intercept_message) in thhv.h.
    pub intercept: [u8; THEMIC_INTERCEPT_MSG_SIZE],
}

/// Size of `themic_intercept_message` (must match C definition in thhv.h).
pub const THEMIC_INTERCEPT_MSG_SIZE: usize = 120;

// ── Error message ────────────────────────────────────────────────────────── //

/// DOORBELL_NOTIFY payload (capavisor → domain, on the RX ring).
///
/// Written when an EPT violation matches a registered doorbell entry.
/// The child VP is NOT stopped; it resumes immediately after the fast-path.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DoorbellNotify {
    pub doorbell_id: u32,  // matches the id returned by REGISTER_DOORBELL
    pub reserved: u32,
    pub gpa: u64,          // guest physical address that was written
    pub value: u64,        // data value written by the guest
    pub size: u32,         // write size in bytes (1/2/4/8)
    pub reserved2: u32,
}

// ── Error message ────────────────────────────────────────────────────────── //

/// ERROR payload (capavisor → domain).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ErrorMsg {
    pub error_code: u32,
    pub reserved: u32,
    pub detail: u64,
}

// ── Capability enumeration ───────────────────────────────────────────────── //

/// ENUM_CAP request payload (domain → capavisor).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EnumCapReq {
    pub handle: u64,
}

// ── Signed attestation report + request ──────────────────────────────────── //

/// Attestation request payload (TX ring, domain → capavisor).
///
/// Sent via `DOMCOMM_MSG_ATTEST_REQ` on the TX ring before issuing
/// `ATTEST_SELF` VMCALL with `arg0=1, arg1=msg_sequence`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AttestRequest {
    /// Verifier-supplied nonce (32 bytes, freshness challenge).
    pub nonce: [u8; ATTEST_NONCE_SIZE],
    /// Verifier's public key (32 bytes, bound into the signature).
    pub user_pub_key: [u8; ATTEST_KEY_SIZE],
}

/// Signed attestation report with user binding and optional TPM quote.
///
/// The signature covers `SHA-256(report_bytes ‖ nonce ‖ user_pub_key)`.
/// If a TPM is available, the response also includes a TPM2_Quote
/// (TPM-signed proof of PCR values).
///
/// Variable-length: the fixed header is followed by TPM data blobs
/// when `tpm_quote_size > 0`.
///
/// A remote verifier checks:
/// 1. `Ed25519_verify(pub_key, SHA-256(report_bytes ‖ nonce ‖ user_pub_key), signature)`
/// 2. TPM quote signature valid under `ak_pub`
/// 3. PCR[11] in quote == SHA-256(capavisor_binary ‖ pub_key)
/// 4. `nonce` and `user_pub_key` match what was sent
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SignedAttestReport {
    pub report: AttestReport,
    /// Ed25519 signature (64 bytes) over SHA-256(report ‖ nonce ‖ user_pub_key).
    pub signature: [u8; ATTEST_SIG_SIZE],
    /// Capavisor's attestation public key (Ed25519, 32 bytes).
    pub pub_key: [u8; ATTEST_KEY_SIZE],
    /// Verifier-supplied nonce (32 bytes).
    pub nonce: [u8; ATTEST_NONCE_SIZE],
    /// Verifier's public key (32 bytes, bound into the signature).
    pub user_pub_key: [u8; ATTEST_KEY_SIZE],
    /// Size of the TPMS_ATTEST blob following this header (0 if no TPM).
    pub tpm_quote_size: u16,
    /// Size of the TPM signature blob following the quote (0 if no TPM).
    pub tpm_sig_size: u16,
    /// Size of the AK public area following the signature (0 if no TPM).
    pub ak_pub_size: u16,
    /// Reserved, must be 0.
    pub reserved: u16,
}

// ── Boot attestation handoff ─────────────────────────────────────────────── //

/// Magic value for `BootAttestation` ("THM_ATST" as little-endian u64).
pub const BOOT_ATTEST_MAGIC: u64 = 0x5453_5441_5F4D_4854;

/// PCR index used for the capavisor boot measurement.
pub const ATTEST_PCR_INDEX: u32 = 11;

/// Ed25519 key size in bytes.
pub const ATTEST_KEY_SIZE: usize = 32;

/// Ed25519 signature size in bytes.
pub const ATTEST_SIG_SIZE: usize = 64;

/// Nonce size in bytes (4 × u64 registers).
pub const ATTEST_NONCE_SIZE: usize = 32;

/// Boot attestation handoff structure.
///
/// Written by the bootloader (or capavisor early boot) into a known memory
/// region. The capavisor reads it during `_start()`, stores the signing key
/// in META memory, and **zeroes the entire struct** (especially `priv_key`)
/// before creating any domain.
///
/// Layout: 128 bytes total, `#[repr(C)]` for C interop with the bootloader.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BootAttestation {
    /// Magic value — must equal `BOOT_ATTEST_MAGIC`.
    pub magic: u64,
    /// Ed25519 public key (32 bytes).
    pub pub_key: [u8; ATTEST_KEY_SIZE],
    /// Ed25519 private key seed (32 bytes). **ZERO AFTER READING.**
    pub priv_key: [u8; ATTEST_KEY_SIZE],
    /// SHA-256(capavisor_binary ‖ boot_info ‖ pub_key).
    pub measurement: [u8; 32],
    /// PCR index used (should be `ATTEST_PCR_INDEX`).
    pub pcr_index: u32,
    /// Reserved for future use (padding to 128 bytes).
    pub reserved: [u8; 20],
}

// ── Compile-time layout assertions ───────────────────────────────────────── //

const _: () = {
    assert!(core::mem::size_of::<Header>() == 4096);
    assert!(core::mem::size_of::<RingMeta>() == 16);
    assert!(core::mem::size_of::<MsgHeader>() == 16);
    assert!(core::mem::size_of::<AttestReport>() == 40);
    assert!(core::mem::size_of::<MemCapEntry>() == 40);
    assert!(core::mem::size_of::<DomCapEntry>() == 16);
    assert!(core::mem::size_of::<PaMapEntry>() == 24);
    assert!(core::mem::size_of::<GrowRequest>() == 24);
    assert!(core::mem::size_of::<GrowAck>() == 16);
    assert!(core::mem::size_of::<VpExit>() == 128);
    assert!(core::mem::size_of::<DoorbellNotify>() == 32);
    assert!(core::mem::size_of::<ErrorMsg>() == 16);
    assert!(core::mem::size_of::<EnumCapReq>() == 8);
    assert!(core::mem::size_of::<AttestRequest>() == 64);
    assert!(core::mem::size_of::<SignedAttestReport>() == 208);
    assert!(core::mem::size_of::<BootAttestation>() == 128);
};
