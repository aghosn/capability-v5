//! CoCo workload — confidential computing simulation with vTOM double-map.
//!
//! Demonstrates the capability-based CoCo flow:
//!   1. Discover DomainComm, dequeue attestation report.
//!   2. Alias a page twice from an owned memory capability:
//!      - Alias #1: remapped at vTOM + original_gpa (simulated encrypted view).
//!      - Alias #2: sent to the parent via the channel (shared bounce buffer).
//!   3. Write through the vTOM alias, verify via the original mapping.
//!
//! This mirrors the SEV-SNP / TDX vTOM model where confidential memory
//! has a private view (normal GPA) and a shared/decrypted view (vTOM + GPA),
//! with the shared view used for I/O bounce buffers visible to the VMM.

#![no_std]
#![no_main]

extern crate eunomia;

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

// ── Shared attestation state (populated once, used by all tests) ─────────── //

static ATTEST_READY: AtomicBool = AtomicBool::new(false);

struct AttestInfo {
    mem_caps: [dc::MemCapEntry; 32],
    nr_mem_caps: usize,
    chan_handle: u64,
}

static mut ATTEST_INFO: AttestInfo = AttestInfo {
    mem_caps: [dc::MemCapEntry {
        handle: 0, gpa_start: 0, size: 0, rights: 0, attributes: 0, hpa_start: 0,
    }; 32],
    nr_mem_caps: 0,
    chan_handle: 0,
};

#[allow(static_mut_refs)]
fn get_attest_info() -> &'static AttestInfo {
    unsafe { &ATTEST_INFO }
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

// ── Attestation parsing ──────────────────────────────────────────────────── //

fn parse_attestation(payload: &[u8]) -> Result<(), &'static str> {
    if payload.len() < core::mem::size_of::<dc::AttestReport>() {
        return Err("attestation payload too short");
    }

    let report = unsafe { &*(payload.as_ptr() as *const dc::AttestReport) };

    #[allow(static_mut_refs)]
    let info = unsafe { &mut ATTEST_INFO };

    // Parse memory capability entries.
    let mem_off = core::mem::size_of::<dc::AttestReport>();
    let mem_entry_size = core::mem::size_of::<dc::MemCapEntry>();
    let nr = report.nr_mem_caps as usize;
    if nr > 32 { return Err("too many mem caps"); }

    for i in 0..nr {
        let off = mem_off + i * mem_entry_size;
        if off + mem_entry_size > payload.len() {
            return Err("attestation truncated at mem_caps");
        }
        info.mem_caps[i] = unsafe {
            *(payload.as_ptr().add(off) as *const dc::MemCapEntry)
        };
    }
    info.nr_mem_caps = nr;

    // Parse domain capability entries (channels).
    let dom_off = mem_off + nr * mem_entry_size;
    let dom_entry_size = core::mem::size_of::<dc::DomCapEntry>();
    let nr_dom = report.nr_dom_caps as usize;

    for i in 0..nr_dom {
        let off = dom_off + i * dom_entry_size;
        if off + dom_entry_size > payload.len() {
            return Err("attestation truncated at dom_caps");
        }
        let entry = unsafe {
            *(payload.as_ptr().add(off) as *const dc::DomCapEntry)
        };
        if i == 0 {
            info.chan_handle = entry.handle;
        }
    }

    if info.chan_handle == 0 {
        return Err("no channel handle in attestation");
    }

    ATTEST_READY.store(true, Ordering::Release);
    Ok(())
}

/// Find a usable (non-META, non-COMM) memory capability with at least 4K.
fn find_usable_mem_cap(info: &AttestInfo) -> Option<&dc::MemCapEntry> {
    for i in 0..info.nr_mem_caps {
        let e = &info.mem_caps[i];
        // Skip META (bit 1) and COMM (bit 4) regions.
        if e.attributes & 0x12 != 0 { continue; }
        if e.size >= 0x1000 {
            return Some(e);
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
    let mut buf = [0u8; 4096];
    let msg = dc.rx_dequeue(&mut buf).map_err(|e| match e {
        DomCommError::RxEmpty => "RX ring empty — no attestation?",
        DomCommError::BufferTooSmall(_) => "attestation too large for buffer",
        _ => "dequeue failed",
    })?;

    if msg.msg_type != dc::msg_types::ATTEST {
        return Err("first message is not ATTEST");
    }

    parse_attestation(msg.payload)?;
    let info = get_attest_info();
    eunomia::println!("  attest: {} mem_caps, chan=0x{:x}", info.nr_mem_caps, info.chan_handle);

    if let Some(cap) = find_usable_mem_cap(info) {
        eunomia::println!("  usable cap: handle=0x{:x} gpa=0x{:x} size=0x{:x}",
            cap.handle, cap.gpa_start, cap.size);
    }

    Ok(())
}

fn test_vtom_double_map() -> Result<(), &'static str> {
    if !ATTEST_READY.load(Ordering::Acquire) {
        return Err("attestation not parsed yet");
    }
    let info = get_attest_info();

    let cap = find_usable_mem_cap(info).ok_or("no usable mem cap")?;

    // Pick a 4K region from the end of the capability (avoid trampling code/stack).
    let page_gpa = cap.gpa_start + cap.size - 0x1000;

    // Alias #1: the vTOM alias — remap at VTOM + page_gpa.
    let (vtom_handle, _) = eunomia::themis::alias(cap.handle, page_gpa, 0x1000, R_RW)
        .map_err(|_| "alias for vTOM failed")?;

    eunomia::themis::map_self(vtom_handle, VTOM + page_gpa)
        .map_err(|_| "map_self vTOM failed")?;

    // Write through the vTOM alias (simulated "decrypted" / shared view).
    let vtom_ptr = (VTOM + page_gpa) as *mut u64;
    let orig_ptr = page_gpa as *mut u64;
    unsafe {
        core::ptr::write_volatile(vtom_ptr, 0xDEAD_BEEF_C0C0_CAFE);
    }

    // Read through the original mapping — should see the same value
    // (both map the same physical page).
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

    let cap = find_usable_mem_cap(info).ok_or("no usable mem cap")?;

    // Pick a different 4K region for the bounce buffer.
    let bounce_gpa = cap.gpa_start + cap.size - 0x2000;

    // Write a marker into the bounce buffer before sharing.
    let bounce_ptr = bounce_gpa as *mut u64;
    unsafe {
        core::ptr::write_volatile(bounce_ptr, 0xB0_B0_CAFE_BABE);
    }

    // Alias for the bounce buffer to share with parent.
    let (bounce_handle, _) = eunomia::themis::alias(cap.handle, bounce_gpa, 0x1000, R_RW)
        .map_err(|_| "alias for bounce buffer failed")?;

    // Send the bounce buffer alias to the parent via the channel.
    eunomia::themis::send_chan(info.chan_handle, bounce_handle, 0)
        .map_err(|_| "send_chan bounce buffer failed")?;

    eunomia::println!("  bounce buffer sent via channel: gpa=0x{:x} handle=0x{:x}",
        bounce_gpa, bounce_handle);

    Ok(())
}
