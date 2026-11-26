//! DomainComm — binary wire format for domain-level communication.
//!
//! These structures are shared between the capavisor (producer/consumer) and
//! the thhv driver (consumer/producer).  They must be `#[repr(C)]` and match
//! the C definitions in `thhv/inc/thhv.h` exactly.
//!
//! See `docs/domain-comm.md` for the original design. Version 1 uses power-of-two
//! logical ring capacity and permits RX messages to cross backing pages.

// ── DomainComm constants ─────────────────────────────────────────────────── //

pub const DOMCOMM_MAGIC: u32 = 0x444F_4D43; // "DOMC"
pub const DOMCOMM_VERSION_MAJOR: u16 = 1;
pub const DOMCOMM_VERSION_MINOR: u16 = 0;

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
    // 0x0007 retired: address-matching notifications.
    pub const DOORBELL_EVENT: u32 = 0x0008;

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

/// Set in `AttestReport.flags` when the report is followed by a
/// [`SignedEnvelope`] (and optionally TPM blobs). When clear, the report is
/// an unsigned domain-config dump consumed by `thhv` at module init.
///
/// Receivers use this bit to distinguish unsigned vs signed reports without
/// guessing from total payload size.
pub const DOMCOMM_ATTEST_F_SEALED: u32 = 1 << 0;
/// Header offset 36 contains the doorbell count, with entries after the PA map.
pub const DOMCOMM_ATTEST_F_DOORBELLS: u32 = 1 << 2;

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

/// Power-of-two logical capacity makes u32 cursor rollover preserve ring offsets.
/// Extra backing pages become usable when growth reaches the next power of two.
pub fn ring_capacity(pages: usize) -> Option<usize> {
    let bytes = pages.checked_mul(4096)?;
    if bytes == 0 || bytes > u32::MAX as usize {
        return None;
    }
    Some(1usize << (usize::BITS - 1 - bytes.leading_zeros()))
}

/// Preserve unread bytes when growth changes the cursor-to-backing mapping.
pub struct RingResizePlan {
    tail: u32,
    len: usize,
    old_capacity: usize,
    new_capacity: usize,
}

impl RingResizePlan {
    pub fn new(head: u32, tail: u32, old_capacity: usize, new_capacity: usize) -> Option<Self> {
        let len = head.wrapping_sub(tail) as usize;
        if old_capacity < 4096 || !old_capacity.is_power_of_two()
            || !new_capacity.is_power_of_two() || new_capacity < old_capacity
            || new_capacity > u32::MAX as usize || len > old_capacity
        {
            return None;
        }
        Some(Self { tail, len, old_capacity, new_capacity })
    }

    /// Callbacks access backing offsets, splitting at physical page boundaries
    /// if necessary. Scratch is prepared before committing any backing change.
    pub fn copy(
        &self,
        scratch: &mut [u8],
        mut read: impl FnMut(usize, &mut [u8]),
        mut write: impl FnMut(usize, &[u8]),
    ) {
        assert!(scratch.len() >= self.len);
        let old_offset = self.tail as usize % self.old_capacity;
        let first = self.len.min(self.old_capacity - old_offset);
        read(old_offset, &mut scratch[..first]);
        read(0, &mut scratch[first..self.len]);
        let new_offset = self.tail as usize % self.new_capacity;
        let first = self.len.min(self.new_capacity - new_offset);
        write(new_offset, &scratch[..first]);
        write(0, &scratch[first..self.len]);
    }
}

/// A checked RX write spanning at most two backing pages. Construction never
/// touches shared memory; the producer validates both HPAs before copying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RxWritePlan {
    pub offset: usize,
    pub first_len: usize,
    pub second_offset: usize,
    pub second_len: usize,
    pub next_head: u32,
}

impl RxWritePlan {
    pub fn new(head: u32, tail: u32, capacity: usize, total: usize) -> Option<Self> {
        if capacity < 4096 || !capacity.is_power_of_two() || capacity > u32::MAX as usize
            || total < core::mem::size_of::<MsgHeader>() || total > 4096
        {
            return None;
        }
        let used = head.wrapping_sub(tail) as usize;
        if used > capacity || total > capacity - used {
            return None;
        }
        let offset = head as usize % capacity;
        let first_len = total.min(4096 - offset % 4096);
        Some(Self {
            offset,
            first_len,
            second_offset: (offset + first_len) % capacity,
            second_len: total - first_len,
            next_head: head.wrapping_add(total as u32),
        })
    }
}

#[cfg(test)]
mod rx_tests {
    use super::*;

    #[test]
    fn growth_preserves_wrapped_unread_bytes_in_place() {
        use core::cell::RefCell;
        for tail in [4090u32, 8186, u32::MAX - 5] {
            let backing = RefCell::new([0u8; 8192]);
            for i in 0..32 {
                backing.borrow_mut()[tail.wrapping_add(i) as usize % 4096] = i as u8;
            }
            let plan = RingResizePlan::new(tail.wrapping_add(32), tail, 4096, 8192).unwrap();
            plan.copy(&mut [0u8; 4096],
                |off, bytes| bytes.copy_from_slice(&backing.borrow()[off..off + bytes.len()]),
                |off, bytes| backing.borrow_mut()[off..off + bytes.len()].copy_from_slice(bytes));
            for i in 0..32 {
                assert_eq!(backing.borrow()[tail.wrapping_add(i) as usize % 8192], i as u8);
            }
        }
        assert!(RingResizePlan::new(4097, 0, 4096, 8192).is_none());
        assert!(RingResizePlan::new(0, 1, 4096, 8192).is_none());
        assert!(RingResizePlan::new(0, 0, 8192, 4096).is_none());
    }

    #[test]
    fn reservation_is_all_or_nothing_across_pages_and_cursor_rollover() {
        let plan = RxWritePlan::new(4090, 100, 8192, 48).unwrap();
        assert_eq!((plan.first_len, plan.second_offset, plan.second_len), (6, 4096, 42));
        let plan = RxWritePlan::new(u32::MAX - 5, u32::MAX - 100, 8192, 48).unwrap();
        assert_eq!((plan.offset, plan.first_len, plan.second_offset, plan.next_head),
                   (8186, 6, 0, 42));
        assert!(RxWritePlan::new(8190, 0, 8192, 48).is_none());
        assert!(RxWritePlan::new(10, 11, 8192, 48).is_none());
        assert!(RxWritePlan::new(0, 0, 0, 48).is_none());
        assert_eq!(ring_capacity(15), Some(32768));
    }
}

// ── Binary attestation report ────────────────────────────────────────────── //

/// Binary attestation report header (variable-length payload follows).
///
/// Followed by packed arrays (contiguous, no padding between arrays):
///   `MemCapEntry[nr_mem_caps]`
///   `DomCapEntry[nr_dom_caps]`
///   `PaMapEntry[nr_pa_entries]`
///   `DoorbellEntry[nr_doorbells]` (flag `DOMCOMM_ATTEST_F_DOORBELLS`)
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
    pub nr_doorbells: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DoorbellEntry {
    pub recipient: u64,
    pub port: u64,
    pub handle: u64,
    pub vp: u64,
    pub vector: u8,
    pub kind: u8,
    pub reserved: [u8; 6],
}

/// Resolve an attested endpoint identity to the reporting domain's local handle.
/// Tree-only records do not grant invocation authority.
pub fn find_attested_doorbell(
    report: &[u8],
    recipient: u64,
    port: u64,
) -> Result<DoorbellEntry, u64> {
    use crate::errors::{ERR_INVALID, ERR_NOTFOUND};
    use core::mem::size_of;

    if report.len() < size_of::<AttestReport>() {
        return Err(ERR_INVALID);
    }
    // SAFETY: the length was checked; the report need not be aligned.
    let header = unsafe { core::ptr::read_unaligned(report.as_ptr().cast::<AttestReport>()) };
    if header.flags & DOMCOMM_ATTEST_F_DOORBELLS == 0 || header.flags & 2 != 0 {
        if header.nr_doorbells != 0 || header.flags & 2 != 0 {
            return Err(ERR_INVALID);
        }
        return Err(ERR_NOTFOUND);
    }
    let mut offset = size_of::<AttestReport>();
    for (count, size) in [
        (header.nr_mem_caps, size_of::<MemCapEntry>()),
        (header.nr_dom_caps, size_of::<DomCapEntry>()),
        (header.nr_pa_entries, size_of::<PaMapEntry>()),
    ] {
        offset = (count as usize).checked_mul(size)
            .and_then(|len| offset.checked_add(len)).ok_or(ERR_INVALID)?;
    }
    let count = header.nr_doorbells as usize;
    let end = count.checked_mul(size_of::<DoorbellEntry>())
        .and_then(|len| offset.checked_add(len)).ok_or(ERR_INVALID)?;
    let entries = report.get(offset..end).ok_or(ERR_INVALID)?;
    let mut found = None;
    for bytes in entries.chunks_exact(size_of::<DoorbellEntry>()) {
        // SAFETY: chunks_exact supplies a complete entry; alignment is not assumed.
        let entry = unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<DoorbellEntry>()) };
        if entry.port == 0 || entry.kind > 1 || (entry.kind == 0 && entry.vp != 0)
            || entry.reserved != [0; 6]
        {
            return Err(ERR_INVALID);
        }
        if entry.recipient == recipient && entry.port == port && entry.handle != u64::MAX {
            if found.is_some() {
                return Err(ERR_INVALID);
            }
            found = Some(entry);
        }
    }
    found.ok_or(ERR_NOTFOUND)
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

/// Capability-authorized notification. The port is scoped to the recipient;
/// it is not the sender's local capability handle.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DoorbellEvent {
    pub port: u64,
    pub value: u64,
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

// ── Signed attestation envelope + request ────────────────────────────────── //

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

/// Signed attestation envelope, appended after the common-base attestation
/// payload (header, capabilities, PA map and notification bindings, as on the
/// unsigned path) when the caller asked for a signed report.
///
/// Wire layout of a signed attestation message:
///
/// ```text
/// [ AttestReport (40B) ]       ← flags |= DOMCOMM_ATTEST_F_SEALED on signed path
/// [ MemCapEntry × nr_mem_caps ]
/// [ DomCapEntry × nr_dom_caps ]
/// [ PaMapEntry  × nr_pa_entries ]
/// [ DoorbellEntry × nr_doorbells ]
/// ─────── common base ends here ───────
/// [ SignedEnvelope (168B) ]
/// [ tpm_quote (tpm_quote_size bytes) ]   (optional, 0 if no TPM)
/// [ tpm_sig   (tpm_sig_size bytes)   ]
/// [ ak_pub    (ak_pub_size bytes)    ]
/// ```
///
/// The `signature` field is `Ed25519(SHA-256(common_base ‖ nonce ‖ user_pub_key))`
/// — every byte of the common base is bound (cap inventory included).
///
/// Verification steps (see `thhv/test/test_attestation.c`):
/// 1. Locate envelope at offset
///    `40 + nr_mem_caps*40 + nr_dom_caps*16 + nr_pa_entries*24 + nr_doorbells*40`.
/// 2. Verify `Ed25519_verify(pub_key, SHA-256(base_bytes ‖ nonce ‖ user_pub_key), signature)`.
/// 3. If `tpm_quote_size > 0`: verify TPM quote signature under `ak_pub` and
///    that `PCR[11]` in the quote matches `SHA-256(capavisor_binary ‖ pub_key)`.
/// 4. Confirm `nonce` and `user_pub_key` echo back what the verifier sent.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SignedEnvelope {
    /// Ed25519 signature (64 bytes) over `SHA-256(common_base ‖ nonce ‖ user_pub_key)`.
    pub signature: [u8; ATTEST_SIG_SIZE],
    /// Capavisor's attestation public key (Ed25519, 32 bytes).
    pub pub_key: [u8; ATTEST_KEY_SIZE],
    /// Verifier-supplied nonce (32 bytes).
    pub nonce: [u8; ATTEST_NONCE_SIZE],
    /// Verifier's public key (32 bytes, bound into the signature).
    pub user_pub_key: [u8; ATTEST_KEY_SIZE],
    /// Size of the TPMS_ATTEST blob following this envelope (0 if no TPM).
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
    assert!(core::mem::size_of::<DoorbellEntry>() == 40);
    assert!(core::mem::size_of::<MemCapEntry>() == 40);
    assert!(core::mem::size_of::<DomCapEntry>() == 16);
    assert!(core::mem::size_of::<PaMapEntry>() == 24);
    assert!(core::mem::size_of::<GrowRequest>() == 24);
    assert!(core::mem::size_of::<GrowAck>() == 16);
    assert!(core::mem::size_of::<VpExit>() == 128);
    assert!(core::mem::size_of::<DoorbellEvent>() == 16);
    assert!(core::mem::size_of::<ErrorMsg>() == 16);
    assert!(core::mem::size_of::<EnumCapReq>() == 8);
    assert!(core::mem::size_of::<AttestRequest>() == 64);
    assert!(core::mem::size_of::<SignedEnvelope>() == 168);
    assert!(core::mem::size_of::<BootAttestation>() == 128);
};

// ── Typed RX-ring messages ───────────────────────────────────────────────── //

/// Marker for a fixed-size POD payload that the capavisor enqueues on a
/// domain's RX ring with a fixed message type.
///
/// Pinning `MSG_TYPE` to the struct via the trait makes it impossible to call
/// `enqueue_rx::<GrowAck>` with `MSG_TYPE = DOORBELL_NOTIFY` (or any other
/// mismatched tag) — the type system catches the error at compile time.
///
/// Only implement this for `#[repr(C)] Copy` payloads: the capavisor will
/// cast `&Self` to a byte slice of length `size_of::<Self>()` when copying
/// into the shared-memory ring.
pub trait DomCommMessage: Copy {
    const MSG_TYPE: u32;
}

impl DomCommMessage for GrowAck {
    const MSG_TYPE: u32 = msg_types::GROW_ACK;
}

impl DomCommMessage for DoorbellEvent {
    const MSG_TYPE: u32 = msg_types::DOORBELL_EVENT;
}

#[cfg(test)]
mod doorbell_attest_tests {
    use super::*;
    use crate::errors::{ERR_INVALID, ERR_NOTFOUND};

    fn inventory() -> [u8; 120] {
        let mut bytes = [0; 120];
        bytes[8..12].copy_from_slice(&DOMCOMM_ATTEST_F_DOORBELLS.to_le_bytes());
        bytes[36..40].copy_from_slice(&2u32.to_le_bytes());
        for (index, handle) in [u64::MAX, 17].into_iter().enumerate() {
            let off = 40 + index * 40;
            bytes[off..off + 8].copy_from_slice(&7u64.to_le_bytes());
            bytes[off + 8..off + 16].copy_from_slice(&9u64.to_le_bytes());
            bytes[off + 16..off + 24].copy_from_slice(&handle.to_le_bytes());
            bytes[off + 32] = 38;
        }
        bytes
    }

    #[test]
    fn lookup_requires_held_authority_and_exact_recipient_port() {
        let mut bytes = inventory();
        assert_eq!(find_attested_doorbell(&bytes, 7, 9).unwrap().handle, 17);
        assert!(matches!(find_attested_doorbell(&bytes, 8, 9), Err(ERR_NOTFOUND)));
        bytes[96..104].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(find_attested_doorbell(&bytes, 7, 9), Err(ERR_NOTFOUND)));
    }

    #[test]
    fn malformed_or_ambiguous_inventory_is_rejected() {
        let mut bytes = inventory();
        assert!(matches!(find_attested_doorbell(&bytes[..119], 7, 9), Err(ERR_INVALID)));
        bytes[56..64].copy_from_slice(&18u64.to_le_bytes());
        assert!(matches!(find_attested_doorbell(&bytes, 7, 9), Err(ERR_INVALID)));
        let mut bytes = inventory();
        bytes[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(find_attested_doorbell(&bytes, 7, 9), Err(ERR_INVALID)));
        let mut bytes = inventory();
        bytes[119] = 1;
        assert!(matches!(find_attested_doorbell(&bytes, 7, 9), Err(ERR_INVALID)));
    }
}
