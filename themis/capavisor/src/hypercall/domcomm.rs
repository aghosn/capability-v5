//! DOMCOMM_NOTIFY (0x19) handler and the GROW_RX / GROW_TX ring extension.

use capability_engine::{CapabilityRef, Domain};
use themis_abi::errors;

use super::{try_domain, HypercallResult};
use crate::platform::ThemisPlatform;
use crate::serial_println;


/// DOMCOMM_NOTIFY (0x19): process pending messages on the caller's TX ring.
///
/// The domain enqueues messages (GROW_RX, GROW_TX, ENUM_CAP, etc.) on its
/// TX ring and then does this VMCALL to trigger the capavisor to process them.
pub(super) fn do_domcomm_notify(platform: &ThemisPlatform, caller: &CapabilityRef<Domain>) -> HypercallResult {
    use themis_abi::domcomm;

    let domain_id = caller.read().data.id;

    let pd = try_domain!(platform, domain_id);

    let mut pd_locked = pd.lock();
    if pd_locked.domcomm.is_none() {
        return HypercallResult::error(errors::ERR_BADSTATE);
    }

    // Drain all pending TX messages.
    let mut buf = [0u8; 4096];

    loop {
        let result = pd_locked.domcomm_tx_dequeue(&mut buf);
        match result {
            None => break,
            Some((msg_type, payload_size, _seq)) => match msg_type {
                domcomm::msg_types::GROW_RX | domcomm::msg_types::GROW_TX => {
                    let is_rx = msg_type == domcomm::msg_types::GROW_RX;
                    handle_grow(
                        platform,
                        caller,
                        &mut *pd_locked,
                        is_rx,
                        &buf[..payload_size],
                    );
                }
                _ => {
                    serial_println!(
                        "[domcomm] unknown TX msg type {:#x} from domain {}",
                        msg_type,
                        domain_id,
                    );
                }
            },
        }
    }

    HypercallResult::success()
}

/// Handle a GROW_RX or GROW_TX request from the domain.
///
/// The domain has CARVEd pages and REGISTER_COMM'd them (self-ref).
/// We look up the capability to find the HPAs, then extend the ring.
///
/// Security: the payload was already copied from shared memory by
/// domcomm_tx_dequeue (TOCTOU-safe). All domain-supplied values
/// (handle, nr_pages) are bounds-checked before use.
fn handle_grow(
    _platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    pd: &mut crate::platform::PlatformDomain,
    is_rx: bool,
    payload: &[u8],
) {
    use themis_abi::domcomm;

    let req_size = core::mem::size_of::<domcomm::GrowRequest>();
    if payload.len() < req_size {
        serial_println!("[domcomm] GROW payload too small ({})", payload.len());
        send_grow_ack(pd, 1);
        return;
    }

    // Copy to a local struct (payload is already a copy from domcomm_tx_dequeue,
    // but we do a typed copy for alignment safety).
    let mut req: domcomm::GrowRequest = unsafe { core::mem::zeroed() };
    unsafe {
        core::ptr::copy_nonoverlapping(
            payload.as_ptr(),
            &mut req as *mut domcomm::GrowRequest as *mut u8,
            req_size,
        );
    }

    serial_println!(
        "[domcomm] GROW_{}: cap_handle={} cap_sub={} nr_pages={}",
        if is_rx { "RX" } else { "TX" },
        req.cap_handle,
        req.cap_sub,
        req.nr_pages,
    );

    // Bounds-check nr_pages (prevent OOM from malicious domain).
    if req.nr_pages == 0 || req.nr_pages > 256 {
        serial_println!("[domcomm] GROW: invalid nr_pages {}", req.nr_pages);
        send_grow_ack(pd, 6);
        return;
    }

    // Look up the capability to find the HPAs.
    let hpa_start: u64;
    let cap_size: u64;
    {
        let dom = caller.read();
        let cap_weak = match dom.data.get_memory_capability(req.cap_handle) {
            Some(w) => w.clone(),
            None => {
                serial_println!("[domcomm] GROW: cap {} not found", req.cap_handle);
                send_grow_ack(pd, 2);
                return;
            }
        };
        drop(dom);

        let cap_ref = match cap_weak.upgrade() {
            Some(r) => r,
            None => {
                serial_println!("[domcomm] GROW: cap {} revoked", req.cap_handle);
                send_grow_ack(pd, 3);
                return;
            }
        };
        let c = cap_ref.read();
        hpa_start = c.data.access.start;
        cap_size = c.data.access.size;

        // Verify the cap has COMM attribute (was REGISTER_COMM'd).
        if !c.owned.attributes.comm() {
            serial_println!("[domcomm] GROW: cap {} not COMM-attributed", req.cap_handle);
            send_grow_ack(pd, 4);
            return;
        }
    }

    let expected_size = req.nr_pages as u64 * 0x1000;
    if cap_size < expected_size {
        serial_println!(
            "[domcomm] GROW: cap size {:#x} < expected {:#x}",
            cap_size,
            expected_size,
        );
        send_grow_ack(pd, 5);
        return;
    }

    // Extend the ring page list.
    let (new_page_count, new_capacity) = {
        let dc = pd.domcomm.as_mut().expect("DomainComm not init");
        let ring = if is_rx { &mut dc.rx } else { &mut dc.tx };
        for i in 0..req.nr_pages {
            ring.page_hpas.push(hpa_start + i as u64 * 0x1000);
        }

        // Update the header page's ring metadata.
        let hdr_virt = (dc.header_hpa + dc.hhdm_offset) as *mut domcomm::Header;
        unsafe {
            let hdr = &mut *hdr_virt;
            let ring_meta = if is_rx { &mut hdr.rx } else { &mut hdr.tx };
            ring_meta.page_count = ring.page_hpas.len() as u32;
        }

        (
            ring.page_hpas.len() as u32,
            ring.page_hpas.len() as u32 * 4096,
        )
    };

    // Send GROW_ACK on the RX ring.
    let ack = domcomm::GrowAck {
        new_page_count,
        new_capacity,
        status: 0,
        reserved: 0,
    };
    pd.enqueue_rx(&ack);
}

/// Send a GROW_ACK with an error status.
fn send_grow_ack(pd: &mut crate::platform::PlatformDomain, status: u32) {
    use themis_abi::domcomm;

    let ack = domcomm::GrowAck {
        new_page_count: 0,
        new_capacity: 0,
        status,
        reserved: 0,
    };
    pd.enqueue_rx(&ack);
}
