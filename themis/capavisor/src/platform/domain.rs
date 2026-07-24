//! Per-domain hardware state (Tier 2): the [`PlatformDomain`] struct
//! and its bookkeeping (per-VP COMM pages, per-domain DomainComm region,
//! registered doorbells).

extern crate alloc;

use alloc::vec::Vec;

use capability_engine::DomainId;

use crate::arch::ArchDomainState;
use crate::mem::MetaAllocator;
use crate::serial_println;

// ── Per-domain hardware state ─────────────────────────────────────────────── //

/// Hardware state owned by a single domain.
pub struct PlatformDomain {
    /// Architecture-specific hardware state (EPT, IOMMU SLPT, VP slots,
    /// bitmap pages on x86; Stage-2, GIC state on ARM).
    pub arch: ArchDomainState,
    /// META page allocator — populated via `GiveMetaMem` updates.
    pub meta: MetaAllocator,
    /// Parent domain ID, stored for vital-memory revocation fallback.
    #[allow(dead_code)]
    pub parent: Option<DomainId>,
    /// HHDM offset, cached here so EPT root allocation can use it.
    hhdm_offset: u64,
    /// Per-VP COMM page physical addresses.  Index = VP ID.
    /// Set when CommRegion update is applied (or during do_add_vp).
    pub comm_hpas: Vec<u64>,

    /// DomainComm region: per-domain message ring with the capavisor.
    /// `None` until `init_domcomm()` allocates it.
    pub domcomm: Option<DomainCommState>,

    /// HPAs of pages sent with COMM attribute before seal.
    /// Consumed by `init_domcomm` at seal time, then cleared.
    pub pending_domcomm_hpas: Vec<u64>,

    /// Registered doorbell entries for this domain's child VPs (fast-path EPT violations).
    /// Keyed by doorbell_id; max THEMIC_MAX_DOORBELLS entries.
    pub doorbells: Vec<DoorbellEntry>,
    /// Counter for assigning unique doorbell IDs. Monotonically increasing.
    pub next_doorbell_id: u32,
}

/// Maximum number of doorbell entries per child domain.
pub const THEMIC_MAX_DOORBELLS: usize = 128;

/// Flags for doorbell matching behaviour.
pub const THEMIC_DOORBELL_FLAG_ANY_VALUE: u32 = 1 << 0; // ignore datamatch
pub const THEMIC_DOORBELL_FLAG_ANY_SIZE: u32 = 1 << 1; // ignore access size

/// A single registered doorbell entry (capavisor-internal, not a shared page).
#[derive(Clone)]
pub struct DoorbellEntry {
    pub doorbell_id: u32,
    pub gpa: u64,
    pub datamatch: u64,
    pub size: u32,
    pub flags: u32,
}

/// Per-ring page tracking for DomainComm growth.
pub struct DomainCommRing {
    /// Physical addresses of the ring's backing pages (growable).
    pub page_hpas: Vec<u64>,
}

impl DomainCommRing {
    fn new() -> Self {
        DomainCommRing {
            page_hpas: Vec::new(),
        }
    }

    fn capacity(&self) -> usize {
        self.page_hpas.len() * 0x1000
    }
}

/// Per-domain DomainComm region state (capavisor-side bookkeeping).
pub struct DomainCommState {
    /// Physical address of the header page (page 0).
    pub header_hpa: u64,
    /// RX ring pages (capavisor→domain, capavisor is producer).
    pub rx: DomainCommRing,
    /// TX ring pages (domain→capavisor, capavisor is consumer).
    pub tx: DomainCommRing,
    /// HHDM offset, cached for ring access.
    pub hhdm_offset: u64,
}

impl PlatformDomain {
    pub(super) fn new(hhdm_offset: u64, parent: Option<DomainId>) -> Self {
        PlatformDomain {
            arch: ArchDomainState::new(),
            meta: MetaAllocator::new(hhdm_offset),
            parent,
            hhdm_offset,
            comm_hpas: Vec::new(),
            domcomm: None,
            pending_domcomm_hpas: Vec::new(),
            doorbells: Vec::new(),
            next_doorbell_id: 1,
        }
    }

    /// Initialize DomainComm from a list of page HPAs (possibly non-contiguous).
    ///
    /// `page_hpas[0]` is the header page; the remaining pages are split
    /// between RX and TX rings (RX gets the majority).
    ///
    /// For dom0 the caller builds this list from a contiguous region.
    /// For child domains the pages are accumulated via `pending_domcomm_hpas`
    /// during `REGISTER_COMM` calls and consumed at seal time.
    pub(super) fn init_domcomm(&mut self, page_hpas: &[u64]) -> &DomainCommState {
        use themis_abi::domcomm;

        let nr_pages = page_hpas.len() as u32;
        assert!(
            nr_pages >= 2,
            "DomainComm needs at least 2 pages (header + 1 ring)"
        );

        let header_hpa = page_hpas[0];

        // Write header to page 0 via HHDM.
        let hdr_virt = (header_hpa + self.hhdm_offset) as *mut domcomm::Header;
        let rx_page_count = (nr_pages - 1).saturating_sub(1).max(1);
        let tx_page_count = nr_pages - 1 - rx_page_count;

        // Build per-ring page HPA lists from the (possibly sparse) page_hpas.
        let mut rx_ring = DomainCommRing::new();
        for i in 0..rx_page_count as usize {
            rx_ring.page_hpas.push(page_hpas[1 + i]);
        }
        let mut tx_ring = DomainCommRing::new();
        for i in 0..tx_page_count as usize {
            tx_ring
                .page_hpas
                .push(page_hpas[1 + rx_page_count as usize + i]);
        }

        unsafe {
            let hdr = &mut *hdr_virt;
            hdr.magic = domcomm::DOMCOMM_MAGIC;
            hdr.version_major = domcomm::DOMCOMM_VERSION_MAJOR;
            hdr.version_minor = domcomm::DOMCOMM_VERSION_MINOR;
            hdr.total_pages = nr_pages;
            hdr.flags = 0;

            hdr.rx = domcomm::RingMeta {
                head: 0,
                tail: 0,
                page_offset: 1,
                page_count: rx_page_count,
            };

            hdr.tx = domcomm::RingMeta {
                head: 0,
                tail: 0,
                page_offset: 1 + rx_page_count,
                page_count: tx_page_count,
            };

            hdr.notify_vector = 0;
            hdr.notify_flags = 0;
        }

        self.domcomm = Some(DomainCommState {
            header_hpa,
            rx: rx_ring,
            tx: tx_ring,
            hhdm_offset: self.hhdm_offset,
        });
        self.domcomm.as_ref().unwrap()
    }

    /// Write a message to the RX ring of this domain's DomainComm.
    ///
    /// The capavisor is the sole producer of the RX ring.
    /// Head/tail are monotonic (wrap only for page lookup).
    /// Returns the number of bytes written (including header), or 0 if ring full.
    pub fn domcomm_rx_enqueue(&mut self, msg_type: u32, payload: &[u8]) -> usize {
        use themis_abi::domcomm;

        let dc = self.domcomm.as_ref().expect("DomainComm not initialized");
        let hdr_virt = (dc.header_hpa + dc.hhdm_offset) as *mut domcomm::Header;

        let msg_hdr_size = core::mem::size_of::<domcomm::MsgHeader>();
        let total_size = ((msg_hdr_size + payload.len() + 7) / 8) * 8; // 8-byte align

        let capacity = dc.rx.capacity();
        let nr_pages = dc.rx.page_hpas.len();

        unsafe {
            let hdr = &mut *hdr_virt;
            let rx = &mut hdr.rx;
            let head = rx.head as usize;

            // Read tail (consumer = domain, monotonic) with acquire.
            let tail = core::ptr::read_volatile(&rx.tail) as usize;
            core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);

            // Check space using monotonic subtraction.
            let used = head.wrapping_sub(tail);
            if used > capacity || capacity - used < total_size {
                return 0; // Ring full
            }

            // Wrap head for page lookup.
            let wrapped_head = head % capacity;
            let ring_page_idx = wrapped_head / 4096;
            let page_off = wrapped_head % 4096;

            // Check if message fits in current page.
            if page_off + total_size > 4096 {
                // Write padding message to fill rest of page.
                let pad_size = 4096 - page_off;
                if ring_page_idx >= nr_pages {
                    serial_println!("[domcomm] RX enqueue: page_idx {} OOB", ring_page_idx);
                    return 0;
                }
                let pad_page_hpa = dc.rx.page_hpas[ring_page_idx];
                let pad_virt = (pad_page_hpa + dc.hhdm_offset) as *mut u8;
                let pad_hdr = pad_virt.add(page_off) as *mut domcomm::MsgHeader;
                (*pad_hdr).message_type = domcomm::msg_types::NONE;
                (*pad_hdr).total_size = pad_size as u32;
                (*pad_hdr).sequence = 0;

                // Advance head monotonically (no wrapping).
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                rx.head = (head + pad_size) as u32;

                // Recurse with the new head position.
                return self.domcomm_rx_enqueue(msg_type, payload);
            }

            if ring_page_idx >= nr_pages {
                serial_println!("[domcomm] RX enqueue: page_idx {} OOB", ring_page_idx);
                return 0;
            }

            // Write message within current page.
            let ring_page_hpa = dc.rx.page_hpas[ring_page_idx];
            let ring_page_virt = (ring_page_hpa + dc.hhdm_offset) as *mut u8;
            let msg_ptr = ring_page_virt.add(page_off);

            // Write payload first, then header (producer protocol).
            if !payload.is_empty() {
                core::ptr::copy_nonoverlapping(
                    payload.as_ptr(),
                    msg_ptr.add(msg_hdr_size),
                    payload.len(),
                );
            }

            // Write header.
            let msg_hdr_ptr = msg_ptr as *mut domcomm::MsgHeader;
            (*msg_hdr_ptr).message_type = msg_type;
            (*msg_hdr_ptr).total_size = total_size as u32;
            (*msg_hdr_ptr).sequence = 0; // TODO: monotonic counter per ring

            // Memory barrier + advance head monotonically.
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            rx.head = (head + total_size) as u32;
        }

        total_size
    }

    /// Typed enqueue: serialise a fixed-size `DomCommMessage` POD payload onto
    /// the RX ring with the message type that the trait pins to its struct.
    ///
    /// This concentrates the `&T → &[u8]` cast in one place and makes it
    /// impossible to enqueue a payload struct with the wrong `msg_type` tag.
    /// For variable-size payloads (e.g. attestation chunks), use
    /// [`domcomm_rx_enqueue`] directly with raw bytes.
    pub fn enqueue_rx<M: themis_abi::domcomm::DomCommMessage>(&mut self, msg: &M) -> usize {
        // SAFETY: `M: DomCommMessage` requires `Copy`, all impls are
        // `#[repr(C)]` POD payloads with no padding interpreted by the parent.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                msg as *const M as *const u8,
                core::mem::size_of::<M>(),
            )
        };
        self.domcomm_rx_enqueue(M::MSG_TYPE, bytes)
    }

    /// Read one message from the TX ring (domain→capavisor, we are consumer).
    ///
    /// Returns `Some((msg_type, payload_size))` on success, `None` if ring is empty.
    /// Handles padding messages transparently.
    ///
    /// Security: bounds-checks all domain-supplied values. Copies the message
    /// header before inspecting it to avoid TOCTOU on shared memory.
    pub fn domcomm_tx_dequeue(&mut self, buf: &mut [u8]) -> Option<(u32, usize, u64)> {
        use themis_abi::domcomm;

        let dc = self.domcomm.as_ref().expect("DomainComm not initialized");
        let hdr_virt = (dc.header_hpa + dc.hhdm_offset) as *mut domcomm::Header;

        let msg_hdr_size = core::mem::size_of::<domcomm::MsgHeader>();

        let capacity = dc.tx.capacity();
        if capacity == 0 {
            return None;
        }
        let nr_pages = dc.tx.page_hpas.len();

        unsafe {
            let hdr = &mut *hdr_virt;
            let tx = &mut hdr.tx;

            // Read head (producer = domain) with acquire fence.
            // Head/tail are monotonic (never wrapped by the domain).
            let head = core::ptr::read_volatile(&tx.head) as usize;
            core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
            let tail = tx.tail as usize;

            if head == tail {
                return None;
            }

            // Sanity: available data.
            let avail = head.wrapping_sub(tail);
            if avail > capacity {
                serial_println!(
                    "[domcomm] TX dequeue: corrupt ring (head={}, tail={}, cap={})",
                    head,
                    tail,
                    capacity
                );
                return None;
            }

            // Wrap tail for page lookup.
            let wrapped_tail = tail % capacity;
            let ring_page_idx = wrapped_tail / 4096;
            let page_off = wrapped_tail % 4096;

            if ring_page_idx >= nr_pages {
                serial_println!(
                    "[domcomm] TX dequeue: page_idx {} out of range (nr_pages={})",
                    ring_page_idx,
                    nr_pages
                );
                return None;
            }

            let page_hpa = dc.tx.page_hpas[ring_page_idx];
            let page_virt = (page_hpa + dc.hhdm_offset) as *const u8;

            // Copy the message header to a local variable (TOCTOU defense).
            let mut msg_hdr: domcomm::MsgHeader = core::mem::zeroed();
            core::ptr::copy_nonoverlapping(
                page_virt.add(page_off) as *const u8,
                &mut msg_hdr as *mut domcomm::MsgHeader as *mut u8,
                msg_hdr_size,
            );

            // Skip padding — use monotonic tail (no wrapping).
            if msg_hdr.message_type == domcomm::msg_types::NONE {
                let pad_size = msg_hdr.total_size as usize;
                if pad_size == 0 || pad_size > 4096 {
                    serial_println!("[domcomm] TX dequeue: invalid padding size {}", pad_size);
                    return None;
                }
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                tx.tail = (tail + pad_size) as u32;
                return self.domcomm_tx_dequeue(buf);
            }

            // Bounds-check total_size.
            let total_size = msg_hdr.total_size as usize;
            if total_size < msg_hdr_size || total_size > avail || total_size > 4096 {
                serial_println!(
                    "[domcomm] TX dequeue: invalid total_size {} (avail={}, hdr={})",
                    total_size,
                    avail,
                    msg_hdr_size
                );
                return None;
            }

            let payload_size = total_size - msg_hdr_size;
            if payload_size > buf.len() {
                serial_println!(
                    "[domcomm] TX message too large ({} > {})",
                    payload_size,
                    buf.len()
                );
                return None;
            }

            // Copy payload (skip header).
            if payload_size > 0 {
                let payload_src = page_virt.add(page_off + msg_hdr_size);
                core::ptr::copy_nonoverlapping(payload_src, buf.as_mut_ptr(), payload_size);
            }

            // Advance tail monotonically (match driver protocol).
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            tx.tail = (tail + total_size) as u32;

            Some((msg_hdr.message_type, payload_size, msg_hdr.sequence))
        }
    }

    /// Write `vector` into the DomainComm header's notify_vector field.
    /// Called by SET_THEMIC_VECTOR so the capavisor uses the right IDT vector
    /// when sending doorbell IPIs to this domain.
    pub fn set_notify_vector(&mut self, vector: u32) {
        use themis_abi::domcomm;
        let dc = match self.domcomm.as_ref() {
            Some(d) => d,
            None => return,
        };
        let hdr_virt = (dc.header_hpa + dc.hhdm_offset) as *mut domcomm::Header;
        unsafe {
            core::ptr::write_volatile(&mut (*hdr_virt).notify_vector, vector);
        }
    }

    /// Ensure an EPT root page exists, allocating from `self.meta` if needed.
    ///
    /// # Panics
    ///
    /// Panics if the META pool is empty (no `GiveMetaMem` update received yet).
    #[cfg(target_arch = "x86_64")]
    pub fn ensure_ept(&mut self) {
        self.arch.ensure_ept(&mut self.meta, self.hhdm_offset);
    }
}
