//! ATTEST_SELF (0x0C) + READ_PCR (0x1E) handlers and their helpers.
//!
//! `do_attest_self` produces a `DOMCOMM_MSG_ATTEST` message on the caller's
//! RX ring; signed mode appends a `SignedEnvelope` whose Ed25519 signature
//! covers the entire common base. See `do_attest_self` doc-comment for the
//! wire layout.

extern crate alloc;

use capability_engine::{CapabilityRef, Domain};
use themis_abi::errors;

use super::HypercallResult;
use crate::platform::ThemisPlatform;
use crate::serial_println;

/// ATTEST_SELF (0x0C): self-attestation of the calling domain.
///
/// Wire layout of the produced `DOMCOMM_MSG_ATTEST` payload:
///
/// ```text
/// [ AttestReport (40B)       ]   ← flags |= SEALED on signed path
/// [ MemCapEntry × nr_mem_caps]   \
/// [ DomCapEntry × nr_dom_caps]    > "common base" — present on both paths
/// [ PaMapEntry  × nr_pa_ents ]   /
/// ─────────── signed-only tail ───────────
/// [ SignedEnvelope (168B)    ]   ← only when arg0 == 1
/// [ tpm_quote (variable)     ]   ← only when TPM is available
/// [ tpm_sig   (variable)     ]
/// [ ak_pub    (variable)     ]
/// ```
///
/// The signature in `SignedEnvelope` covers
/// `SHA-256(common_base ‖ nonce ‖ user_pub_key)` — every byte of the
/// common base (including cap entries) is under the signature.
///
/// arg0 == 0  →  Unsigned domain config. Used by `thhv` at module init
///                (`thhv_pa_map_init_from_attestation`) to learn its
///                memory capability handles.
/// arg0 == 1  →  Signed report; reads `AttestRequest {nonce, user_pub_key}`
///                from the TX ring and appends the signed envelope tail.
///                arg2 = expected TX ring message sequence (defense in depth).
/// arg1 = byte offset into the serialised payload; capavisor enqueues the
///        slice `payload[offset..]` (capped at the single-page message limit).
///
/// IN:  RDI = mode (0=unsigned, 1=signed), RSI = byte offset, RDX = tx_sequence (if signed)
/// OUT: Report delivered to caller's DomainComm RX ring.
///      RDI = total payload size, RSI = bytes written this call.
pub(super) fn do_attest_self(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    _arg3: u64,
) -> HypercallResult {
    use capability_engine::Capability;
    use themis_abi::domcomm;

    let is_signed = arg0 == 1;
    let offset = arg1 as usize;

    // Common base: AttestReport header + MemCap/DomCap/PaMap arrays.
    // Same wire format for both paths; dom0's thhv parses this verbatim at
    // boot — see thhv/src/thhv_translate.c::thhv_pa_map_init_from_attestation.
    //
    // Capability::attest_self_structured is the engine's own mediated
    // wrapper (execute()-protected, sealed + MonitorAPI::ATTEST-gated) around
    // build_structured_attestation, which walks the caller's memory/domain
    // capability maps and upgrades each weak ref -- doing that under the
    // engine's op lock keeps a concurrent revoke of one of those capabilities
    // from producing an inconsistent, non-atomic snapshot.
    let result = Capability::attest_self_structured(platform, caller);
    let mut attest = match result {
        Ok((a, _batch)) => a,
        Err(e) => return e.into(),
    };
    if is_signed {
        attest.flags |= domcomm::DOMCOMM_ATTEST_F_SEALED;
    }
    let domain_id = attest.domain_id;
    let mut payload = attest.to_bytes();

    // Locate the caller's domain and verify DomainComm is ready before doing
    // any TX-ring reads (signed path) or RX-ring writes.
    // Invariant: caller's own domain MUST be in the platform map — capa-engine
    // and platform-side registry can't be out of sync for a live caller.
    let pd_arc = platform
        .domain_arc(domain_id)
        .expect("[attest] caller's PlatformDomain missing (capa/platform desync)");
    let mut pd = pd_arc.lock();
    if pd.domcomm.is_none() {
        return HypercallResult::success_2(0, 0);
    }

    if is_signed {
        match build_signed_tail(&payload, &mut pd, arg2) {
            Ok(tail) => payload.extend_from_slice(&tail),
            Err(e) => return e,
        }
    }

    enqueue_attest_payload(&mut pd, &payload, offset)
}

/// Read the verifier's `AttestRequest` from the caller's TX ring.
///
/// Returns the parsed request (`nonce`, `user_pub_key`) on success, or an
/// already-formed `HypercallResult` error on TX-ring/sequence/type failures.
fn consume_attest_request(
    pd: &mut crate::platform::PlatformDomain,
    expected_seq: u64,
) -> Result<themis_abi::domcomm::AttestRequest, HypercallResult> {
    use themis_abi::domcomm;

    let mut tx_buf = [0u8; 128];
    let (msg_type, payload_size, msg_seq) = match pd.domcomm_tx_dequeue(&mut tx_buf) {
        Some(r) => r,
        None => {
            serial_println!("[attest] signed: no message on TX ring");
            return Err(HypercallResult::error(errors::ERR_BADSTATE));
        }
    };

    if msg_type != domcomm::msg_types::ATTEST_REQ {
        serial_println!(
            "[attest] signed: unexpected TX msg type {:#x} (expected ATTEST_REQ {:#x})",
            msg_type,
            domcomm::msg_types::ATTEST_REQ
        );
        return Err(HypercallResult::error(errors::ERR_BADSTATE));
    }

    // Defense in depth (A2): verify sequence matches what domain told us.
    if msg_seq != expected_seq {
        serial_println!(
            "[attest] signed: sequence mismatch (msg={}, expected={})",
            msg_seq,
            expected_seq
        );
        return Err(HypercallResult::error(errors::ERR_RACE));
    }

    if payload_size < core::mem::size_of::<domcomm::AttestRequest>() {
        serial_println!(
            "[attest] signed: payload too small ({} < {})",
            payload_size,
            core::mem::size_of::<domcomm::AttestRequest>()
        );
        return Err(HypercallResult::error(errors::ERR_BADSTATE));
    }

    // TOCTOU-safe: tx_buf is a local copy.
    Ok(unsafe {
        core::ptr::read_unaligned(tx_buf.as_ptr() as *const domcomm::AttestRequest)
    })
}

/// Build the signed-tail bytes that follow the common base on the signed path.
///
/// Layout: `[SignedEnvelope (168B)] [tpm_quote] [tpm_sig] [ak_pub]`. The
/// envelope's `signature` field is `Ed25519(SHA-256(common_base ‖ nonce ‖
/// user_pub_key))` — every byte of the common base (header + cap entries)
/// is under the signature.
fn build_signed_tail(
    common_base: &[u8],
    pd: &mut crate::platform::PlatformDomain,
    expected_seq: u64,
) -> Result<alloc::vec::Vec<u8>, HypercallResult> {
    use alloc::vec::Vec;
    use sha2::{Digest, Sha256};
    use themis_abi::domcomm;

    let req = consume_attest_request(pd, expected_seq)?;
    let nonce = req.nonce;
    let user_pub_key = req.user_pub_key;

    // Sign: SHA-256(common_base ‖ nonce ‖ user_pub_key).
    let mut hasher = Sha256::new();
    hasher.update(common_base);
    hasher.update(&nonce);
    hasher.update(&user_pub_key);
    let digest = hasher.finalize();
    let signature = crate::attestation::sign(&digest);
    let pub_key = crate::attestation::public_key();

    // Optional TPM2_Quote when an AK is provisioned.
    let mut tpm_quote_buf = [0u8; 512];
    let mut tpm_sig_buf = [0u8; 512];
    let mut tpm_quote_size: u16 = 0;
    let mut tpm_sig_size: u16 = 0;
    let mut ak_pub_buf = [0u8; 256];
    let mut ak_pub_size: u16 = 0;

    if let Some((ak_handle, ak_modulus)) = crate::attestation::ak_info() {
        if let Some(tpm) = crate::attestation::tpm_driver() {
            match tpm.quote(ak_handle, &nonce, domcomm::ATTEST_PCR_INDEX) {
                Ok(qr) => {
                    tpm_quote_size = qr.attest_size as u16;
                    tpm_sig_size = qr.sig_size as u16;
                    tpm_quote_buf[..qr.attest_size]
                        .copy_from_slice(&qr.attest_data[..qr.attest_size]);
                    tpm_sig_buf[..qr.sig_size].copy_from_slice(&qr.signature[..qr.sig_size]);
                    ak_pub_buf = *ak_modulus;
                    ak_pub_size = 256;
                    serial_println!(
                        "[attest] TPM2_Quote OK — attest={} sig={} bytes",
                        qr.attest_size,
                        qr.sig_size
                    );
                }
                Err(e) => {
                    serial_println!("[attest] TPM2_Quote failed: {:?} (continuing without)", e);
                }
            }
        }
    }

    let envelope = domcomm::SignedEnvelope {
        signature,
        pub_key,
        nonce,
        user_pub_key,
        tpm_quote_size,
        tpm_sig_size,
        ak_pub_size,
        reserved: 0,
    };

    let env_bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            &envelope as *const domcomm::SignedEnvelope as *const u8,
            core::mem::size_of::<domcomm::SignedEnvelope>(),
        )
    };

    let mut tail = Vec::with_capacity(
        env_bytes.len()
            + tpm_quote_size as usize
            + tpm_sig_size as usize
            + ak_pub_size as usize,
    );
    tail.extend_from_slice(env_bytes);
    if tpm_quote_size > 0 {
        tail.extend_from_slice(&tpm_quote_buf[..tpm_quote_size as usize]);
        tail.extend_from_slice(&tpm_sig_buf[..tpm_sig_size as usize]);
        tail.extend_from_slice(&ak_pub_buf[..ak_pub_size as usize]);
    }
    Ok(tail)
}

/// Enqueue `payload[offset..]` onto the caller's RX ring as a sequence of
/// `DOMCOMM_MSG_ATTEST` messages, each ≤ `MAX_PAYLOAD` bytes.
///
/// The full payload is split and pushed in a single hypercall so that the
/// caller doesn't need to re-invoke us per chunk — re-invocation would
/// require re-reading the (now-consumed) `AttestRequest` from the TX ring
/// on the signed path, which we cannot do.
///
/// Returns `RDI = total_size`, `RSI = payload bytes written this call`.
/// Values are in **payload bytes** (the ring's MsgHeaders and 8-byte
/// alignment padding are not exposed). When `offset == 0` and the full
/// payload was enqueued, `wrote == total_size`.
///
/// On ring-full, we return `ERR_BUSY` and roll back nothing (already-pushed
/// chunks remain in the ring; the caller is expected to drain them).
fn enqueue_attest_payload(
    pd: &mut crate::platform::PlatformDomain,
    payload: &[u8],
    offset: usize,
) -> HypercallResult {
    use themis_abi::domcomm;

    let total_size = payload.len();
    if offset >= total_size {
        return HypercallResult::success_2(total_size as u64, 0);
    }

    let mut written = 0usize;
    let mut cur = offset;
    while cur < total_size {
        let chunk_len = (total_size - cur).min(domcomm::MAX_PAYLOAD);
        let slice = &payload[cur..cur + chunk_len];
        let ring_bytes = pd.domcomm_rx_enqueue(domcomm::msg_types::ATTEST, slice);
        if ring_bytes == 0 {
            return HypercallResult::error(errors::ERR_BUSY);
        }
        cur += chunk_len;
        written += chunk_len;
    }

    HypercallResult::success_2(total_size as u64, written as u64)
}


/// READ_PCR (0x1E): read a TPM PCR value (capavisor-mediated, read-only).
///
/// IN:  RDI = pcr_index
/// OUT: RDI..RCX = PCR value (4 × u64 = 32 bytes, big-endian packed)
///      RAX = SUCCESS if TPM available, ERR_NOTFOUND if no TPM
pub(super) fn do_read_pcr(pcr_index: u32) -> HypercallResult {
    if !crate::attestation::tpm_available() {
        return HypercallResult::error(errors::ERR_NOTFOUND);
    }

    let Some(tpm) = crate::attestation::tpm_driver() else {
        return HypercallResult::error(errors::ERR_NOTFOUND);
    };
    match tpm.pcr_read(pcr_index) {
        Ok(digest) => {
            // Pack 32 bytes into 4 × u64 (little-endian)
            let val0 = u64::from_le_bytes(digest[0..8].try_into().unwrap());
            let val1 = u64::from_le_bytes(digest[8..16].try_into().unwrap());
            let val2 = u64::from_le_bytes(digest[16..24].try_into().unwrap());
            // HypercallResult exposes only three result slots (val0/val1/val2)
            // in addition to status; we therefore return the first 24 bytes
            // of the 32-byte digest. The fourth lane (bytes 24..32) is dropped.
            HypercallResult {
                status: errors::SUCCESS,
                val0,
                val1,
                val2,
            }
        }
        Err(_) => HypercallResult::error(errors::ERR_INVALID),
    }
}
