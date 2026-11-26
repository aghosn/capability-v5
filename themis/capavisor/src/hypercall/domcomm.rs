//! DOMCOMM_NOTIFY (0x19) and synchronous DomainComm ring growth.

use capability_engine::{CapaError, Capability, CapabilityRef, Domain};
use themis_abi::{domcomm, errors};

use super::{try_domain, HypercallResult};
use crate::platform::ThemisPlatform;
use crate::serial_println;

pub(super) fn do_domcomm_notify(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
) -> HypercallResult {
    let domain_id = caller.read().data.id;
    let pd_arc = try_domain!(platform, domain_id);
    if pd_arc.lock().domcomm.is_none() {
        return HypercallResult::error(errors::ERR_BADSTATE);
    }

    let mut buf = [0u8; 4096];
    loop {
        let dequeued = pd_arc.lock().domcomm_tx_dequeue(&mut buf);
        match dequeued {
            None => return HypercallResult::success(),
            Some((kind, size, _)) => match kind {
                domcomm::msg_types::GROW_RX | domcomm::msg_types::GROW_TX => {
                    // Finish this exchange in registers, not in the ring being
                    // resized. The driver installs its prepared mappings before
                    // releasing its RX/TX lock or consuming another message.
                    return match handle_grow(
                        platform,
                        caller,
                        &pd_arc,
                        kind == domcomm::msg_types::GROW_RX,
                        &buf[..size],
                    ) {
                        Ok((pages, capacity)) => HypercallResult::success_2(pages, capacity),
                        Err(error) => {
                            serial_println!(
                                "[domcomm] domain {} GROW failed: {:?}",
                                domain_id,
                                error
                            );
                            HypercallResult::from(error)
                        }
                    };
                }
                _ => {
                    serial_println!(
                        "[domcomm] unknown TX msg type {:#x} from domain {}",
                        kind,
                        domain_id,
                    );
                }
            },
        }
    }
}

fn handle_grow(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    pd_arc: &alloc::sync::Arc<spin::Mutex<crate::platform::PlatformDomain>>,
    is_rx: bool,
    payload: &[u8],
) -> Result<(u64, u64), CapaError> {
    if payload.len() != core::mem::size_of::<domcomm::GrowRequest>() {
        return Err(CapaError::InvalidOperation("invalid GROW payload".into()));
    }
    let req = unsafe { core::ptr::read_unaligned(payload.as_ptr().cast::<domcomm::GrowRequest>()) };
    if req.nr_pages == 0 || req.nr_pages > 256 || req.reserved != 0 {
        return Err(CapaError::InvalidOperation(
            "invalid GROW page count".into(),
        ));
    }
    Capability::with_domain_comm(platform, caller, req.cap_handle, |access, gpa| {
        if access.size != u64::from(req.nr_pages) * 4096 {
            return Err(CapaError::InvalidOperation(
                "GROW must use the entire COMM region".into(),
            ));
        }
        // Keep the engine operation lock through adoption; revocation cannot
        // invalidate the physical range between validation and ring mutation.
        pd_arc
            .lock()
            .grow_domcomm(is_rx, access.start, gpa, req.nr_pages)
    })
}
