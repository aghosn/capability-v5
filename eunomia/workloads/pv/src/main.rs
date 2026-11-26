#![no_std]
#![no_main]

extern crate alloc;
extern crate eunomia;

use alloc::vec::Vec;
use eunomia::domcomm::DomainComm;
use eunomia::test_harness::TestCase;
use eunomia::themis_abi::{cpuid, domcomm as dc, pv};
use pv::{Client, ControlPage, Descriptor, Identity, Request, Service, Status};

static TESTS: &[TestCase] = &[TestCase {
    name: "shared_request_round_trip",
    func: round_trip,
}];

#[no_mangle]
pub fn app_main(_services: &eunomia::KernelServices) -> ! {
    eunomia::test_harness::run(TESTS);
}

fn map_page(gpa: u64) -> Result<(), &'static str> {
    const BOOT_MAP_END: u64 = 1 << 32;
    if gpa >= BOOT_MAP_END && !eunomia::paging::map_range(gpa, pv::PAGE_SIZE as u64) {
        return Err("map PV page");
    }
    Ok(())
}

fn round_trip() -> Result<(), &'static str> {
    if !cpuid::is_themis() {
        return Err("PV workload requires Themis");
    }
    let locator = core::arch::x86_64::__cpuid_count(cpuid::LEAF_PV, 0);
    if locator.ecx != pv::PAGE_SIZE as u32 || locator.edx != pv::descriptor::VERSION {
        return Err("missing or unsupported PV descriptor");
    }
    let gpa = u64::from(locator.eax) | (u64::from(locator.ebx) << 32);
    const GPA_LIMIT: u64 = 1 << 48;
    pv::descriptor::range_end(gpa, pv::PAGE_SIZE as u64, GPA_LIMIT)
        .map_err(|_| "invalid descriptor GPA")?;
    if gpa < pv::AUTO_GPA_START {
        return Err("descriptor outside bootstrap window");
    }
    map_page(gpa)?;
    let mut bytes = [0; pv::PAGE_SIZE];
    for (offset, dst) in bytes.iter_mut().enumerate() {
        // SAFETY: mapped descriptor page; copy before parsing untrusted metadata.
        *dst = unsafe { core::ptr::read_volatile((gpa as *const u8).add(offset)) };
    }
    let descriptor = Descriptor::decode(&bytes).map_err(|_| "malformed PV descriptor")?;
    descriptor
        .validate(gpa, GPA_LIMIT)
        .map_err(|_| "invalid PV layout")?;
    let doorbells = discover_doorbells(&descriptor)?;
    for (index, channel) in descriptor.channels().iter().enumerate() {
        let control = descriptor.regions()[channel.control as usize];
        map_page(control.gpa)?;
        // SAFETY: validated, aligned live control page, containing only atomic words.
        let page = unsafe { &*(control.gpa as *const ControlPage) };
        let mut client = Client::new(Identity {
            generation: descriptor.generation,
            channel: index as u32,
            vp: 0,
        });
        for iteration in 0..8 {
            let request = Request {
                service: Service::Control,
                opcode: if iteration == 0 {
                    pv::OP_NEGOTIATE
                } else {
                    pv::OP_ECHO
                },
                device: 0,
                args: [iteration, 2, 3, 4, 5, 6],
            };
            client
                .publish(page, request)
                .map_err(|_| "publish request")?;
            if iteration % 2 == 0 {
                eunomia::themis::notify(doorbells[index], pv::DOORBELL_VALUE)
                    .map_err(|_| "doorbell did not return SUCCESS")?;
            } else {
                eunomia::themis::switch(0, 0).map_err(|_| "voluntary return failed")?;
            }
            let result = client
                .complete(page)
                .map_err(|_| "missing or invalid completion")?;
            let expected = if iteration == 0 {
                [u64::from(pv::VERSION), Service::Control.bit(), 0, 0, 0, 0]
            } else {
                request.args
            };
            if result.status != Status::Success || result.values != expected {
                return Err("incorrect service completion");
            }
            eunomia::println!("  PV channel {} request {} completed", index, iteration);
        }
    }
    Ok(())
}

fn discover_doorbells(descriptor: &Descriptor) -> Result<Vec<u64>, &'static str> {
    let comm = DomainComm::discover().map_err(|_| "discover attestation channel")?;
    let mut report = Vec::new();
    loop {
        let (total, wrote) = eunomia::themis::attest_self_at(report.len() as u64)
            .map_err(|status| {
                eunomia::println!("  ATTEST_SELF failed: {:#x}", status);
                "fetch attestation"
            })?;
        if total == 0 || total > 1 << 20 || wrote == 0 {
            return Err("invalid attestation chunk size");
        }
        let mut chunk = [0; 4096];
        let msg = comm
            .rx_dequeue(&mut chunk)
            .map_err(|_| "read attestation")?;
        if msg.msg_type != dc::msg_types::ATTEST || msg.payload.len() as u64 != wrote {
            return Err("invalid attestation chunk");
        }
        report.extend_from_slice(msg.payload);
        if report.len() as u64 == total {
            break;
        }
        if report.len() as u64 > total {
            return Err("attestation exceeds declared size");
        }
    }
    if report.len() < core::mem::size_of::<dc::AttestReport>() {
        return Err("truncated attestation header");
    }
    let header = unsafe { core::ptr::read_unaligned(report.as_ptr().cast::<dc::AttestReport>()) };
    let mut handles = Vec::new();
    for channel in descriptor.channels() {
        let entry = dc::find_attested_doorbell(
            &report, channel.doorbell_recipient, channel.doorbell_port,
        ).map_err(|_| "descriptor doorbell absent or invalid in attestation")?;
        if entry.recipient == header.domain_id || entry.kind != 0 || entry.vp != 0 {
            return Err("PV requires an attested Sync doorbell to another domain");
        }
        handles.push(entry.handle);
    }
    eunomia::println!("  PV doorbell capabilities match domain attestation");
    Ok(handles)
}
