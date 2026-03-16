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
};
