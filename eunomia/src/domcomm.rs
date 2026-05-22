//! DomainComm reader — discover and consume messages from the capavisor.
//!
//! The capavisor provisions a DomainComm ring for each domain:
//!   - Header page + RX ring pages + TX ring pages.
//!   - Discoverable via CPUID leaf `0x40000002` (GPA in EAX:EBX, pages in ECX).
//!   - The RX ring is pre-populated with the attestation report at seal time.
//!
//! Eunomia runs as a PVH guest with identity-mapped memory (GPA == VA),
//! so the discovered GPA is directly accessible as a pointer.

use core::ptr;
use themis_abi::domcomm;

// ── Discovery ────────────────────────────────────────────────────────────── //

/// CPUID-discovered DomainComm region descriptor.
pub struct DomainComm {
    header: *mut domcomm::Header,
    /// Virtual addresses of each ring page (RX then TX, contiguous layout).
    /// Page 0 = header, pages [1..1+rx_count) = RX, rest = TX.
    base_gpa: u64,
    #[allow(dead_code)]
    total_pages: u32,
}

/// Result of dequeuing one message from the RX ring.
pub struct RxMessage<'a> {
    pub msg_type: u32,
    pub payload: &'a [u8],
}

#[derive(Debug)]
pub enum DomCommError {
    /// CPUID returned no region (GPA=0 or pages=0).
    NotPresent,
    /// Header magic mismatch.
    BadMagic(u32),
    /// Major version mismatch.
    BadVersion(u16, u16),
    /// RX ring is empty.
    RxEmpty,
    /// Message larger than provided buffer.
    BufferTooSmall(u32),
}

/// Raw CPUID wrapper (saves/restores rbx for PIC).
#[inline(always)]
fn cpuid(leaf: u32) -> (u32, u32, u32, u32) {
    let (eax, ebx, ecx, edx): (u32, u32, u32, u32);
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            inlateout("eax") leaf => eax,
            ebx_out = out(reg) ebx,
            inlateout("ecx") 0u32 => ecx,
            out("edx") edx,
            options(nostack),
        );
    }
    (eax, ebx, ecx, edx)
}

impl DomainComm {
    /// Discover and validate the DomainComm region via CPUID.
    ///
    /// Requires running under Themis (checks hypervisor signature first).
    pub fn discover() -> Result<Self, DomCommError> {
        // Gate on Themis hypervisor detection — same check used by
        // ivshmem discovery and (future) Linux CoCo driver.
        if !themis_abi::cpuid::is_themis() {
            return Err(DomCommError::NotPresent);
        }

        let (eax, ebx, ecx, _edx) = cpuid(domcomm::CPUID_DOMCOMM_LEAF);
        let gpa = ((ebx as u64) << 32) | (eax as u64);
        let nr_pages = ecx;

        if gpa == 0 || nr_pages == 0 {
            return Err(DomCommError::NotPresent);
        }

        // The DomainComm GPA may be outside the boot identity map (above 4 GiB).
        // Map all pages into the guest page tables before accessing them.
        let size = (nr_pages as u64) * 0x1000;
        if !crate::paging::map_range(gpa, size) {
            return Err(DomCommError::BadMagic(0)); // mapping failed
        }

        // GPA == VA after mapping.
        let header = gpa as *mut domcomm::Header;

        // Validate header.
        let hdr = unsafe { &*header };
        if hdr.magic != domcomm::DOMCOMM_MAGIC {
            return Err(DomCommError::BadMagic(hdr.magic));
        }
        if hdr.version_major != domcomm::DOMCOMM_VERSION_MAJOR {
            return Err(DomCommError::BadVersion(
                hdr.version_major,
                domcomm::DOMCOMM_VERSION_MAJOR,
            ));
        }

        Ok(DomainComm {
            header,
            base_gpa: gpa,
            total_pages: nr_pages,
        })
    }

    /// Return a reference to the header.
    pub fn header(&self) -> &domcomm::Header {
        unsafe { &*self.header }
    }

    /// Dequeue one message from the RX ring into `buf`.
    ///
    /// Returns the message type and a slice of the payload within `buf`.
    /// The caller must provide a buffer large enough for the largest
    /// expected message payload.
    pub fn rx_dequeue<'a>(&self, buf: &'a mut [u8]) -> Result<RxMessage<'a>, DomCommError> {
        let hdr = self.header as *mut domcomm::Header;

        // Acquire-load the producer head.
        let head = unsafe { ptr::read_volatile(ptr::addr_of!((*hdr).rx.head)) };
        let tail = unsafe { ptr::read_volatile(ptr::addr_of!((*hdr).rx.tail)) };
        let page_offset = unsafe { (*hdr).rx.page_offset };
        let page_count = unsafe { (*hdr).rx.page_count };

        if head == tail {
            return Err(DomCommError::RxEmpty);
        }

        let capacity = (page_count as usize) * 4096;

        // Read message header.
        let msg_hdr = self.ring_read_struct::<domcomm::MsgHeader>(
            page_offset,
            page_count,
            tail,
            capacity,
        );

        // Skip padding messages (type == NONE).
        if msg_hdr.message_type == domcomm::msg_types::NONE {
            let wrapped = (tail as usize) % capacity;
            let page_remain = 4096 - (wrapped % 4096);
            let new_tail = tail + page_remain as u32;
            unsafe { ptr::write_volatile(ptr::addr_of_mut!((*hdr).rx.tail), new_tail) };
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            return self.rx_dequeue(buf);
        }

        let msg_hdr_size = core::mem::size_of::<domcomm::MsgHeader>() as u32;
        let payload_size = msg_hdr.total_size - msg_hdr_size;

        if payload_size as usize > buf.len() {
            return Err(DomCommError::BufferTooSmall(payload_size));
        }

        // Read payload.
        self.ring_read_bytes(
            page_offset,
            page_count,
            tail + msg_hdr_size,
            capacity,
            &mut buf[..payload_size as usize],
        );

        // Advance tail with release semantics.
        unsafe {
            ptr::write_volatile(
                ptr::addr_of_mut!((*hdr).rx.tail),
                tail + msg_hdr.total_size,
            )
        };
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);

        Ok(RxMessage {
            msg_type: msg_hdr.message_type,
            payload: &buf[..payload_size as usize],
        })
    }

    /// Read a `T` from the ring at logical byte offset `off`.
    fn ring_read_struct<T: Copy>(
        &self,
        page_offset: u32,
        page_count: u32,
        off: u32,
        capacity: usize,
    ) -> T {
        let mut result = core::mem::MaybeUninit::<T>::uninit();
        let dst = result.as_mut_ptr() as *mut u8;
        let len = core::mem::size_of::<T>();
        unsafe {
            self.ring_read_raw(page_offset, page_count, off, capacity, dst, len);
            result.assume_init()
        }
    }

    /// Read `len` bytes from the ring into `dst`.
    fn ring_read_bytes(
        &self,
        page_offset: u32,
        page_count: u32,
        off: u32,
        capacity: usize,
        dst: &mut [u8],
    ) {
        unsafe {
            self.ring_read_raw(
                page_offset,
                page_count,
                off,
                capacity,
                dst.as_mut_ptr(),
                dst.len(),
            );
        }
    }

    /// Low-level ring read handling page boundaries.
    ///
    /// Pages are at `base_gpa + (page_offset + page_index) * 4096`.
    /// For child domains, the pages may not be contiguous in HPA, but
    /// they ARE contiguous in GPA (the capavisor maps them sequentially).
    unsafe fn ring_read_raw(
        &self,
        page_offset: u32,
        _page_count: u32,
        off: u32,
        capacity: usize,
        mut dst: *mut u8,
        mut len: usize,
    ) {
        let mut byte_off = off as usize;

        while len > 0 {
            let wrapped = byte_off % capacity;
            let page_idx = wrapped / 4096;
            let page_off = wrapped % 4096;
            let chunk = core::cmp::min(len, 4096 - page_off);

            let page_va = self.base_gpa + ((page_offset as u64 + page_idx as u64) * 4096);
            let src = (page_va as *const u8).add(page_off);
            ptr::copy_nonoverlapping(src, dst, chunk);

            dst = dst.add(chunk);
            byte_off += chunk;
            len -= chunk;
        }
    }
}
