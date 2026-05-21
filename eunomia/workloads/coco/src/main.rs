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
        // MemCapEntry.gpa_start is actually the HPA (access.start from root domain).
        let cap_hpa = e.gpa_start;
        if hpa >= cap_hpa && hpa < cap_hpa + e.size {
            return Some((e, hpa - cap_hpa));
        }
    }
    None
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

    // Print PA map for debugging.
    for (i, e) in info.pa_map.iter().enumerate() {
        eunomia::println!("    pa[{}]: gpa=0x{:x} hpa=0x{:x} size=0x{:x}",
            i, e.gpa_start, e.hpa_start, e.size);
    }

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

    // 1. Allocate a page from the guest heap (VA = GPA, identity-mapped).
    let page_gpa = alloc_page()?;

    // 2. Translate GPA → HPA via the attestation PA map.
    let page_hpa = gpa_to_hpa(info, page_gpa).ok_or("GPA not in PA map")?;

    // 3. Find the covering capability (exclusive carve) by HPA.
    let (cap, offset) = find_cap_for_hpa(info, page_hpa)
        .ok_or("no cap covers this HPA")?;

    eunomia::println!("  page_gpa=0x{:x} hpa=0x{:x} cap=0x{:x}+0x{:x}",
        page_gpa, page_hpa, cap.handle, offset);

    // 4. Alias the page from the covering capability at the HPA offset.
    let alias_start = cap.gpa_start + offset;
    let (vtom_handle, _) = eunomia::themis::alias(cap.handle, alias_start, 0x1000, R_RW)
        .map_err(|_| "alias for vTOM failed")?;

    // 5. MAP_SELF the alias at VTOM + GPA (the shared/decrypted address).
    eunomia::themis::map_self(vtom_handle, VTOM + page_gpa)
        .map_err(|_| "map_self vTOM failed")?;

    // 6. Map the vTOM alias VA in guest page tables (identity: VA = GPA).
    if !eunomia::paging::map_4k(VTOM + page_gpa, VTOM + page_gpa) {
        return Err("paging map vTOM failed");
    }

    // 7. Write through the vTOM alias (simulated "shared" view).
    let vtom_ptr = (VTOM + page_gpa) as *mut u64;
    let orig_ptr = page_gpa as *mut u64;
    unsafe {
        core::ptr::write_volatile(vtom_ptr, 0xDEAD_BEEF_C0C0_CAFE);
    }

    // 8. Read through the original mapping — both map the same physical page.
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

    // 1. Allocate a page for the bounce buffer.
    let bounce_gpa = alloc_page()?;

    // 2. GPA → HPA → covering capability.
    let bounce_hpa = gpa_to_hpa(info, bounce_gpa).ok_or("bounce GPA not in PA map")?;
    let (cap, offset) = find_cap_for_hpa(info, bounce_hpa)
        .ok_or("no cap covers bounce HPA")?;

    // 3. Write a marker before sharing.
    let bounce_ptr = bounce_gpa as *mut u64;
    unsafe {
        core::ptr::write_volatile(bounce_ptr, 0xB0_B0_CAFE_BABE);
    }

    // 4. Alias the page from the covering capability.
    let alias_start = cap.gpa_start + offset;
    let (bounce_handle, _) = eunomia::themis::alias(cap.handle, alias_start, 0x1000, R_RW)
        .map_err(|_| "alias for bounce buffer failed")?;

    // 5. Send the alias to the parent via the channel.
    eunomia::themis::send_chan(info.chan_handle, bounce_handle, 0)
        .map_err(|_| "send_chan bounce buffer failed")?;

    eunomia::println!("  bounce buffer sent via channel: gpa=0x{:x} handle=0x{:x}",
        bounce_gpa, bounce_handle);

    Ok(())
}
