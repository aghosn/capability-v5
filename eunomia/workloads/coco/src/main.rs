//! CoCo workload — confidential computing simulation with vTOM double-map.
//!
//! Demonstrates the capability-based CoCo flow:
//!   1. Discover DomainComm, dequeue attestation report.
//!   2. Parse attestation: build GPA→HPA map, catalog capabilities.
//!   3. Allocate a page from the guest heap (identity-mapped, VA=GPA).
//!   4. Lookup the page's GPA→HPA, find covering capability.
//!   5. Alias the page:
//!      - Alias #1: MAP_SELF at VTOM + GPA (shared/decrypted view).
//!      - Alias #2: SEND to parent via channel (bounce buffer).
//!   6. Write through the vTOM alias, verify via the original mapping.
//!
//! This mirrors the SEV-SNP / TDX vTOM model where confidential memory
//! has a private view (normal GPA) and a shared/decrypted view (vTOM + GPA),
//! with the shared view used for I/O bounce buffers visible to the VMM.

#![no_std]
#![no_main]

extern crate alloc;
extern crate eunomia;

use alloc::vec::Vec;
use core::alloc::Layout;
use core::sync::atomic::{AtomicBool, Ordering};
use eunomia::domcomm::{DomainComm, DomCommError};
use eunomia::test_harness::TestCase;
use eunomia::themis_abi::domcomm as dc;

/// Simulated vTOM offset (must not collide with existing GPA space).
/// Real SEV-SNP uses bit 47; we use a modest offset for the 128M guest.
const VTOM: u64 = 0x10_0000_0000; // 64 GiB — well above 128M guest RAM

/// Rights bits (match capa-engine Rights).
const R_READ: u64 = 1;
const R_WRITE: u64 = 2;
const R_RW: u64 = R_READ | R_WRITE;

const PAGE_SIZE: usize = 4096;

// ── Shared attestation state (populated once, used by all tests) ─────────── //

static ATTEST_READY: AtomicBool = AtomicBool::new(false);

/// PA map entry: GPA→HPA translation from the attestation.
#[derive(Clone, Copy)]
struct PaEntry {
    gpa_start: u64,
    hpa_start: u64,
    size: u64,
}

struct AttestInfo {
    mem_caps: Vec<dc::MemCapEntry>,
    pa_map: Vec<PaEntry>,
    chan_handle: u64,
}

static mut ATTEST_INFO: Option<AttestInfo> = None;

#[allow(static_mut_refs)]
fn get_attest_info() -> &'static AttestInfo {
    unsafe { ATTEST_INFO.as_ref().expect("attestation not parsed") }
}

static TESTS: &[TestCase] = &[
    TestCase { name: "domcomm_discover", func: test_domcomm_discover },
    TestCase { name: "attest_dequeue", func: test_attest_dequeue },
    TestCase { name: "ivshmem_doorbell", func: test_ivshmem_doorbell },
    TestCase { name: "vtom_double_map", func: test_vtom_double_map },
    TestCase { name: "bounce_buffer_send", func: test_bounce_buffer_send },
];

#[no_mangle]
pub fn app_main(_services: &eunomia::KernelServices) -> ! {
    eunomia::test_harness::run(TESTS);
}

// ── Attestation fetching and parsing ─────────────────────────────────────── //

/// Fetch the full attestation report via offset-based chunked retrieval.
/// Returns the reassembled payload bytes.
fn fetch_attestation(dc: &DomainComm) -> Result<Vec<u8>, &'static str> {
    let mut full_payload = Vec::new();
    let mut offset: u64 = 0;

    loop {
        let (total_size, bytes_written) = eunomia::themis::attest_self_at(offset)
            .map_err(|_| "ATTEST_SELF hypercall failed")?;

        if total_size == 0 {
            return Err("domcomm not initialized");
        }
        if bytes_written == 0 {
            break;
        }

        // Dequeue the chunk from the RX ring.
        let mut buf = [0u8; 4096];
        let msg = dc.rx_dequeue(&mut buf).map_err(|e| match e {
            DomCommError::RxEmpty => "RX empty after attest_self",
            DomCommError::BufferTooSmall(_) => "chunk too large",
            _ => "dequeue failed",
        })?;

        if msg.msg_type != dc::msg_types::ATTEST {
            return Err("unexpected message type");
        }

        full_payload.extend_from_slice(msg.payload);
        offset += bytes_written;

        if offset >= total_size {
            break;
        }
    }

    Ok(full_payload)
}

fn parse_attestation(payload: &[u8]) -> Result<(), &'static str> {
    if payload.len() < core::mem::size_of::<dc::AttestReport>() {
        return Err("attestation payload too short");
    }

    let report = unsafe { &*(payload.as_ptr() as *const dc::AttestReport) };

    // Parse memory capability entries.
    let mem_off = core::mem::size_of::<dc::AttestReport>();
    let mem_entry_size = core::mem::size_of::<dc::MemCapEntry>();
    let nr = report.nr_mem_caps as usize;

    let mut mem_caps = Vec::with_capacity(nr);
    for i in 0..nr {
        let off = mem_off + i * mem_entry_size;
        if off + mem_entry_size > payload.len() {
            return Err("attestation truncated at mem_caps");
        }
        mem_caps.push(unsafe {
            *(payload.as_ptr().add(off) as *const dc::MemCapEntry)
        });
    }

    // Parse domain capability entries (channels).
    let dom_off = mem_off + nr * mem_entry_size;
    let dom_entry_size = core::mem::size_of::<dc::DomCapEntry>();
    let nr_dom = report.nr_dom_caps as usize;

    let mut chan_handle: u64 = 0;
    for i in 0..nr_dom {
        let off = dom_off + i * dom_entry_size;
        if off + dom_entry_size > payload.len() {
            return Err("attestation truncated at dom_caps");
        }
        let entry = unsafe {
            *(payload.as_ptr().add(off) as *const dc::DomCapEntry)
        };
        if i == 0 {
            chan_handle = entry.handle;
        }
    }

    // Parse PA map entries (GPA→HPA translations).
    let pa_off = dom_off + nr_dom * dom_entry_size;
    let pa_entry_size = core::mem::size_of::<dc::PaMapEntry>();
    let nr_pa = report.nr_pa_entries as usize;

    let mut pa_map = Vec::with_capacity(nr_pa);
    for i in 0..nr_pa {
        let off = pa_off + i * pa_entry_size;
        if off + pa_entry_size > payload.len() {
            return Err("attestation truncated at pa_map");
        }
        let entry = unsafe {
            *(payload.as_ptr().add(off) as *const dc::PaMapEntry)
        };
        pa_map.push(PaEntry {
            gpa_start: entry.gpa_start,
            hpa_start: entry.hpa_start,
            size: entry.size,
        });
    }

    if chan_handle == 0 {
        return Err("no channel handle in attestation");
    }

    #[allow(static_mut_refs)]
    unsafe {
        ATTEST_INFO = Some(AttestInfo { mem_caps, pa_map, chan_handle });
    }

    ATTEST_READY.store(true, Ordering::Release);
    Ok(())
}

/// Translate a GPA to HPA using the attestation PA map.
fn gpa_to_hpa(info: &AttestInfo, gpa: u64) -> Option<u64> {
    for e in &info.pa_map {
        if gpa >= e.gpa_start && gpa < e.gpa_start + e.size {
            return Some(e.hpa_start + (gpa - e.gpa_start));
        }
    }
    None
}

/// Find the memory capability (non-META, non-COMM) whose HPA range covers
/// the given HPA.  Returns the cap entry and the offset of `hpa` within it.
fn find_cap_for_hpa(info: &AttestInfo, hpa: u64) -> Option<(&dc::MemCapEntry, u64)> {
    for e in &info.mem_caps {
        // Skip META and COMM (canonicalized: META has CLEAN|VITAL, COMM has CLEAN).
        if e.attributes & 0x12 != 0 { continue; }
        let cap_hpa = e.hpa_start;
        if hpa >= cap_hpa && hpa < cap_hpa + e.size {
            return Some((e, hpa - cap_hpa));
        }
    }
    None
}

// ── ivshmem doorbell test ──────────────────────────────────────────────────── //

fn test_ivshmem_doorbell() -> Result<(), &'static str> {
    let devices = eunomia::ivshmem::discover().map_err(|e| match e {
        eunomia::ivshmem::IvshmemError::NotThemis => "not running under Themis",
        eunomia::ivshmem::IvshmemError::NoDevices => "no ivshmem devices",
        eunomia::ivshmem::IvshmemError::MapFailed(_) => "BAR2 map failed",
    })?;

    eunomia::println!("  found {} ivshmem device(s)", devices.len());

    for dev in &devices {
        eunomia::println!("  dev[{}]: bar0=0x{:x} bar2=0x{:x}",
            dev.index, dev.bar0_gpa, dev.bar2_gpa);

        // Ring the doorbell 5 times to verify the full pipeline.
        for i in 0..5 {
            dev.ring_doorbell(0x42 + i);
            eunomia::println!("  doorbell[{}] rung #{} with value {:#x}", dev.index, i, 0x42u32 + i);
        }
    }

    Ok(())
}

// ── Test functions ───────────────────────────────────────────────────────── //

fn test_domcomm_discover() -> Result<(), &'static str> {
    let dc = DomainComm::discover().map_err(|e| match e {
        DomCommError::NotPresent => "DomainComm not present",
        DomCommError::BadMagic(_) => "bad magic",
        DomCommError::BadVersion(_, _) => "version mismatch",
        _ => "discover failed",
    })?;

    let hdr = dc.header();
    eunomia::println!("  domcomm v{}.{}  pages={}  rx={} tx={}",
        hdr.version_major, hdr.version_minor, hdr.total_pages,
        hdr.rx.page_count, hdr.tx.page_count);

    Ok(())
}

fn test_attest_dequeue() -> Result<(), &'static str> {
    let dc = DomainComm::discover().map_err(|_| "discover failed")?;

    // Fetch attestation using offset-based chunked retrieval.
    let payload = fetch_attestation(&dc)?;
    eunomia::println!("  attest payload: {} bytes", payload.len());

    parse_attestation(&payload)?;
    let info = get_attest_info();
    eunomia::println!("  attest: {} mem_caps, {} pa_entries, chan=0x{:x}",
        info.mem_caps.len(), info.pa_map.len(), info.chan_handle);

    Ok(())
}

/// Allocate a page-aligned 4K page from the bump allocator.
/// Returns the GPA (= VA in identity-mapped guest).
fn alloc_page() -> Result<u64, &'static str> {
    let layout = Layout::from_size_align(PAGE_SIZE, PAGE_SIZE)
        .map_err(|_| "bad layout")?;
    let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
    if ptr.is_null() {
        return Err("page allocation failed");
    }
    Ok(ptr as u64)
}

fn test_vtom_double_map() -> Result<(), &'static str> {
    if !ATTEST_READY.load(Ordering::Acquire) {
        return Err("attestation not parsed yet");
    }
    let info = get_attest_info();

    // 1. Pick a page from a free capability that does NOT overlap eunomia's
    //    loaded image.  Use linker symbols to know our footprint.
    extern "C" { static __heap_end_reserved: u8; }
    let image_end = unsafe { &__heap_end_reserved as *const u8 as u64 };

    let cap = info.mem_caps.iter()
        .filter(|e| e.attributes & 0x12 == 0)   // skip META/COMM
        .filter(|e| e.size >= 0x2000)            // need at least 2 pages
        .filter(|e| e.gpa_start >= image_end)    // above eunomia image
        .max_by_key(|e| e.size)
        .ok_or("no usable free cap above image")?;

    // Use the first page of this capability.
    let page_gpa = cap.gpa_start;

    // GPAs below 4GB are already identity-mapped (2M boot pages).
    // Only call map_4k for addresses above 4GB.
    if page_gpa >= 0x1_0000_0000 && !eunomia::paging::map_4k(page_gpa, page_gpa) {
        return Err("paging map page failed");
    }

    // 2. Alias the first page from this capability.
    let alias_start = cap.hpa_start;
    let (vtom_handle, _) = eunomia::themis::alias(cap.handle, alias_start, 0x1000, R_RW)
        .map_err(|_| "alias for vTOM failed")?;

    // 3. MAP_SELF the alias at VTOM + GPA (the shared/decrypted address).
    eunomia::themis::map_self(vtom_handle, VTOM + page_gpa)
        .map_err(|_| "map_self vTOM failed")?;

    // 4. Map the vTOM alias VA in guest page tables.
    if !eunomia::paging::map_4k(VTOM + page_gpa, VTOM + page_gpa) {
        return Err("paging map vTOM failed");
    }

    // 5. Write through the vTOM alias (simulated "shared" view).
    let vtom_ptr = (VTOM + page_gpa) as *mut u64;
    let orig_ptr = page_gpa as *mut u64;
    unsafe {
        core::ptr::write_volatile(vtom_ptr, 0xDEAD_BEEF_C0C0_CAFE);
    }

    // 6. Read through the original mapping — both map the same physical page.
    let val = unsafe { core::ptr::read_volatile(orig_ptr) };
    if val != 0xDEAD_BEEF_C0C0_CAFE {
        return Err("vTOM write not visible through original mapping");
    }

    eunomia::println!("  vTOM double-map OK: wrote 0x{:x} at vtom+0x{:x}, read back from 0x{:x}",
        val, page_gpa, page_gpa);

    Ok(())
}

fn test_bounce_buffer_send() -> Result<(), &'static str> {
    if !ATTEST_READY.load(Ordering::Acquire) {
        return Err("attestation not parsed yet");
    }
    let info = get_attest_info();

    // 1. Pick a free page from a capability above eunomia's image.
    extern "C" { static __heap_end_reserved: u8; }
    let image_end = unsafe { &__heap_end_reserved as *const u8 as u64 };

    // Use second-largest cap (vtom_double_map may have taken the largest).
    let mut candidates: Vec<&dc::MemCapEntry> = info.mem_caps.iter()
        .filter(|e| e.attributes & 0x12 == 0)
        .filter(|e| e.size >= 0x2000)
        .filter(|e| e.gpa_start >= image_end)
        .collect();
    candidates.sort_by_key(|e| core::cmp::Reverse(e.size));
    // Use second candidate if available, else first (different from vtom test).
    let cap = if candidates.len() > 1 { candidates[1] } else {
        candidates.first().ok_or("no usable free cap for bounce")?
    };

    let bounce_gpa = cap.gpa_start;

    // Ensure mapped in guest page tables (only needed above 4GB).
    if bounce_gpa >= 0x1_0000_0000 && !eunomia::paging::map_4k(bounce_gpa, bounce_gpa) {
        return Err("paging map bounce page failed");
    }

    // 2. Write a marker before sharing.
    let bounce_ptr = bounce_gpa as *mut u64;
    unsafe {
        core::ptr::write_volatile(bounce_ptr, 0xB0_B0_CAFE_BABE);
    }

    // 3. Alias the page from the covering capability.
    let alias_start = cap.hpa_start;
    let (bounce_handle, _) = eunomia::themis::alias(cap.handle, alias_start, 0x1000, R_RW)
        .map_err(|_| "alias for bounce buffer failed")?;

    // 4. Send the memory alias to the parent via the channel handle.
    eunomia::themis::send(bounce_handle, info.chan_handle, 0)
        .map_err(|_| "send bounce buffer failed")?;

    eunomia::println!("  bounce buffer sent: gpa=0x{:x}", bounce_gpa);

    Ok(())
}
