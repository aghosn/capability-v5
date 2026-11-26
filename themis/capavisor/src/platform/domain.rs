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
    /// One engine-derived report, retained across offset-based chunk retrieval.
    pub attest_payload: Option<Vec<u8>>,

    /// HPAs of pages sent with COMM attribute before seal.
    /// Consumed by `init_domcomm` at seal time, then cleared.
    pub pending_domcomm_hpas: Vec<u64>,

    /// Per-VP snapshot of COMM-page register writes, taken by
    /// `Platform::snapshot_comm_regs` while still under the engine's op
    /// lock. Index = VP ID. Drained (and cleared) by `do_switch` once the
    /// VP is actually running, via `take_pending_comm_regs`.
    pub pending_comm_regs: Vec<Vec<(themis_abi::regs::VpRegister, u64)>>,
}

pub struct PreparedRxWrite {
    plan: themis_abi::domcomm::RxWritePlan,
    first: *mut u8,
    second: *mut u8,
    head: *mut u32,
    total: usize,
}

/// Per-ring page tracking for DomainComm growth.
pub struct DomainCommRing {
    /// Physical addresses of the ring's backing pages (growable).
    pub page_hpas: Vec<u64>,
    pub page_gpas: Vec<u64>,
    /// Capavisor-authoritative cursor for whichever side of this ring
    /// capavisor owns: the producer `head` for the RX ring, the consumer
    /// `tail` for the TX ring.
    ///
    /// This field — not the mirrored copy in the shared DomainComm header
    /// page — is the source of truth. The header page holds both rings'
    /// metadata on a single page, so it is necessarily mapped read/write
    /// to the domain (it must be able to write its own cursor there); a
    /// malicious or buggy domain can therefore overwrite the *other*
    /// ring's cursor fields too. Capavisor must never read its own cursor
    /// back out of that shared copy — only ever write to it, to publish
    /// progress for the domain to observe.
    local_cursor: u32,
}

impl DomainCommRing {
    fn new() -> Self {
        DomainCommRing {
            page_hpas: Vec::new(),
            page_gpas: Vec::new(),
            local_cursor: 0,
        }
    }

    fn capacity(&self) -> usize {
        themis_abi::domcomm::ring_capacity(self.page_hpas.len()).unwrap_or(0)
    }

    fn read_bytes(&self, mut offset: usize, mut bytes: &mut [u8], hhdm: u64) {
        while !bytes.is_empty() {
            let len = bytes.len().min(4096 - offset % 4096);
            let ptr = self.checked_ptr(offset, len, hhdm).expect("validated ring backing");
            unsafe { core::ptr::copy_nonoverlapping(ptr, bytes.as_mut_ptr(), len) };
            bytes = &mut bytes[len..];
            offset += len;
        }
    }

    fn write_bytes(&self, mut offset: usize, mut bytes: &[u8], hhdm: u64) {
        while !bytes.is_empty() {
            let len = bytes.len().min(4096 - offset % 4096);
            let ptr = self.checked_ptr(offset, len, hhdm).expect("validated ring backing");
            unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, len) };
            bytes = &bytes[len..];
            offset += len;
        }
    }

    /// Validate `offset` (already wrapped into `0..capacity()`) and
    /// compute the HHDM virtual pointer for a `len`-byte region there.
    ///
    /// Returns `None` — without ever forming or dereferencing a pointer —
    /// if the region would cross a page boundary, or if it would fall
    /// outside the pages actually backing this ring. This is the single
    /// choke point that guarantees every raw pointer used against this
    /// ring stays inside the memory legitimately attributed to this
    /// DomainComm channel (those HPAs are themselves only ever populated
    /// from capability-engine-validated `REGISTER_COMM`/CARVE ranges),
    /// even if a corrupted or adversarial cursor value is fed in.
    fn checked_ptr(&self, offset: usize, len: usize, hhdm_offset: u64) -> Option<*mut u8> {
        let capacity = self.capacity();
        if capacity == 0 || offset >= capacity || len > capacity {
            return None;
        }
        let page_idx = offset / 0x1000;
        let page_off = offset % 0x1000;
        if page_off + len > 0x1000 {
            return None;
        }
        let page_hpa = *self.page_hpas.get(page_idx)?;
        Some(page_hpa.checked_add(hhdm_offset)?.checked_add(page_off as u64)? as *mut u8)
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

impl DomainCommState {
    pub fn page_gpa(&self, index: usize) -> Option<u64> {
        if index == 0 {
            Some(self.header_hpa)
        } else if index <= self.rx.page_gpas.len() {
            self.rx.page_gpas.get(index - 1).copied()
        } else {
            self.tx.page_gpas.get(index - 1 - self.rx.page_gpas.len()).copied()
        }
    }
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
            attest_payload: None,
            pending_domcomm_hpas: Vec::new(),
            pending_comm_regs: Vec::new(),
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
            rx_ring.page_gpas.push(page_hpas[1 + i]);
        }
        let mut tx_ring = DomainCommRing::new();
        for i in 0..tx_page_count as usize {
            tx_ring
                .page_hpas
                .push(page_hpas[1 + rx_page_count as usize + i]);
            tx_ring.page_gpas.push(page_hpas[1 + rx_page_count as usize + i]);
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

    pub fn grow_domcomm(
        &mut self, is_rx: bool, hpa: u64, gpa: u64, pages: u32,
    ) -> Result<(u64, u64), capability_engine::CapaError> {
        use capability_engine::CapaError;
        use themis_abi::domcomm::{ring_capacity, Header, RingResizePlan};
        let dc = self.domcomm.as_mut().ok_or(CapaError::NotFound)?;
        let size = u64::from(pages) * 4096;
        let end = hpa.checked_add(size).ok_or(CapaError::InvalidAccess)?;
        gpa.checked_add(size).ok_or(CapaError::InvalidAccess)?;
        end.checked_add(dc.hhdm_offset).ok_or(CapaError::InvalidAccess)?;
        if pages == 0 || hpa % 4096 != 0 || gpa % 4096 != 0
            || core::iter::once(&dc.header_hpa)
                .chain(dc.rx.page_hpas.iter()).chain(dc.tx.page_hpas.iter())
                .any(|page| *page >= hpa && *page < end)
        {
            return Err(CapaError::InvalidAccess);
        }
        let hdr = unsafe { &mut *((dc.header_hpa + dc.hhdm_offset) as *mut Header) };
        let ring = if is_rx { &mut dc.rx } else { &mut dc.tx };
        let old_capacity = ring.capacity();
        let count = ring.page_hpas.len().checked_add(pages as usize).ok_or(CapaError::NoMemory)?;
        let capacity = ring_capacity(count).ok_or(CapaError::NoMemory)?;
        let (head, tail) = if is_rx {
            (ring.local_cursor, unsafe { core::ptr::read_volatile(&hdr.rx.tail) })
        } else {
            (unsafe { core::ptr::read_volatile(&hdr.tx.head) }, ring.local_cursor)
        };
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        let plan = RingResizePlan::new(head, tail, old_capacity, capacity)
            .ok_or(CapaError::InvalidAccess)?;
        let mut scratch = Vec::new();
        if capacity != old_capacity {
            scratch.try_reserve_exact(old_capacity).map_err(|_| CapaError::NoMemory)?;
            scratch.resize(old_capacity, 0);
        }
        ring.page_hpas.try_reserve(pages as usize).map_err(|_| CapaError::NoMemory)?;
        ring.page_gpas.try_reserve(pages as usize).map_err(|_| CapaError::NoMemory)?;
        for i in 0..pages {
            ring.page_hpas.push(hpa + u64::from(i) * 4096);
            ring.page_gpas.push(gpa + u64::from(i) * 4096);
        }
        if capacity != old_capacity {
            plan.copy(&mut scratch,
                |off, bytes| ring.read_bytes(off, bytes, dc.hhdm_offset),
                |off, bytes| ring.write_bytes(off, bytes, dc.hhdm_offset));
        }
        hdr.rx.page_count = dc.rx.page_hpas.len() as u32;
        hdr.tx.page_count = dc.tx.page_hpas.len() as u32;
        hdr.tx.page_offset = 1 + hdr.rx.page_count;
        hdr.total_pages = 1 + hdr.rx.page_count + hdr.tx.page_count;
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        Ok((count as u64, capacity as u64))
    }

    /// Write a message to the RX ring of this domain's DomainComm.
    ///
    /// The capavisor is the sole producer of the RX ring.
    /// Head/tail are monotonic (wrap only for page lookup).
    /// Returns the number of bytes written (including header), or 0 if ring full.
    pub fn domcomm_rx_enqueue(&mut self, msg_type: u32, payload: &[u8]) -> usize {
        let Some(prepared) = self.prepare_rx_write(payload.len()) else { return 0 };
        let total = prepared.total;
        self.commit_rx_write(prepared, msg_type, payload);
        total
    }

    pub fn prepare_rx_write(&self, payload_len: usize) -> Option<PreparedRxWrite> {
        use themis_abi::domcomm::{Header, MsgHeader, RxWritePlan};
        let dc = self.domcomm.as_ref()?;
        let header = dc.header_hpa.checked_add(dc.hhdm_offset)? as *mut Header;
        let tail = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*header).rx.tail)) };
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        let total = core::mem::size_of::<MsgHeader>().checked_add(payload_len)?;
        let plan = RxWritePlan::new(dc.rx.local_cursor, tail, dc.rx.capacity(), total)?;
        let first = dc.rx.checked_ptr(plan.offset, plan.first_len, dc.hhdm_offset)?;
        let second = if plan.second_len != 0 {
            dc.rx.checked_ptr(plan.second_offset, plan.second_len, dc.hhdm_offset)?
        } else {
            core::ptr::null_mut()
        };
        Some(PreparedRxWrite {
            plan, first, second, total,
            head: unsafe { core::ptr::addr_of_mut!((*header).rx.head) },
        })
    }

    /// Called only while retaining the same PlatformDomain producer lock as prepare.
    pub fn commit_rx_write(&mut self, prepared: PreparedRxWrite, msg_type: u32, payload: &[u8]) {
        use themis_abi::domcomm::MsgHeader;
        let mut bytes = [0u8; 4096];
        let header_len = core::mem::size_of::<MsgHeader>();
        assert_eq!(header_len + payload.len(), prepared.total);
        bytes[..4].copy_from_slice(&msg_type.to_le_bytes());
        bytes[4..8].copy_from_slice(&(prepared.total as u32).to_le_bytes());
        bytes[header_len..prepared.total].copy_from_slice(payload);
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), prepared.first, prepared.plan.first_len);
            if prepared.plan.second_len != 0 {
                core::ptr::copy_nonoverlapping(bytes.as_ptr().add(prepared.plan.first_len),
                    prepared.second, prepared.plan.second_len);
            }
            self.domcomm.as_mut().expect("reserved RX ring").rx.local_cursor = prepared.plan.next_head;
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            core::ptr::write_volatile(prepared.head, prepared.plan.next_head);
        }
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

        let msg_hdr_size = core::mem::size_of::<domcomm::MsgHeader>();

        let dc = self.domcomm.as_mut().expect("DomainComm not initialized");
        let hdr_virt = (dc.header_hpa + dc.hhdm_offset) as *mut domcomm::Header;
        let hhdm_offset = dc.hhdm_offset;

        let capacity = dc.tx.capacity();
        if capacity == 0 {
            return None;
        }

        // Capavisor's own authoritative consumer cursor — never read back
        // from the shared header page (see `DomainCommRing::local_cursor`).
        let tail = dc.tx.local_cursor as usize;

        unsafe {
            let hdr = &mut *hdr_virt;
            let tx = &mut hdr.tx;

            // Read head (producer = domain) with acquire fence.
            // This is the domain's own cursor, legitimately read from
            // shared memory, but still untrusted content-wise.
            let head = core::ptr::read_volatile(&tx.head) as usize;
            core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);

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

            let hdr_ptr = match dc.tx.checked_ptr(wrapped_tail, msg_hdr_size, hhdm_offset) {
                Some(p) => p,
                None => {
                    serial_println!("[domcomm] TX dequeue: header ptr out of ring bounds");
                    return None;
                }
            };

            // Copy the message header to a local variable (TOCTOU defense).
            let mut msg_hdr: domcomm::MsgHeader = core::mem::zeroed();
            core::ptr::copy_nonoverlapping(
                hdr_ptr as *const u8,
                &mut msg_hdr as *mut domcomm::MsgHeader as *mut u8,
                msg_hdr_size,
            );

            // Skip padding — use monotonic tail (no wrapping).
            if msg_hdr.message_type == domcomm::msg_types::NONE {
                let pad_size = msg_hdr.total_size as usize;
                if pad_size == 0 || pad_size > 4096 || pad_size > avail {
                    serial_println!("[domcomm] TX dequeue: invalid padding size {}", pad_size);
                    return None;
                }
                let new_tail = tail + pad_size;
                dc.tx.local_cursor = new_tail as u32;
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                core::ptr::write_volatile(&mut tx.tail, new_tail as u32);
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
                let payload_src = match dc.tx.checked_ptr(
                    wrapped_tail + msg_hdr_size,
                    payload_size,
                    hhdm_offset,
                ) {
                    Some(p) => p,
                    None => {
                        serial_println!("[domcomm] TX dequeue: payload ptr out of ring bounds");
                        return None;
                    }
                };
                core::ptr::copy_nonoverlapping(payload_src, buf.as_mut_ptr(), payload_size);
            }

            // Advance tail monotonically: private cursor first, then
            // publish to the shared page for the domain to observe.
            let new_tail = tail + total_size;
            dc.tx.local_cursor = new_tail as u32;
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            core::ptr::write_volatile(&mut tx.tail, new_tail as u32);

            Some((msg_hdr.message_type, payload_size, msg_hdr.sequence))
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
