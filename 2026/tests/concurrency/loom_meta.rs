//! Loom concurrency tests for META memory region semantics.
//!
//! These tests verify that META-specific paths (exclusive-only send, no MMU
//! update for receiver) are race-free under all thread interleavings.
//!
//! # Running
//!
//! ```sh
//! cargo test --test loom_meta --features loom --release
//! ```
//!
//! # Tests
//!
//! M1. `loom_meta_concurrent_send_race` — two threads race to send the same cap
//!     as META; the freeze protocol ensures exactly one succeeds.  The winner
//!     emits an Unmap for the sender; the loser gets `PermissionDenied`.
//!     The receiver's address space remains empty in every ordering.
//!
//! M2. `loom_meta_send_vs_revoke` — one thread sends a cap as META (shared cap
//!     lock) while another revokes it by sub_handle (exclusive cap lock).
//!     Loom verifies both orderings are consistent: either the send wins
//!     (receiver holds the META cap, RevokeDomain emitted on revoke) or the
//!     revoke wins (send returns NotFound).

#![allow(dead_code)]

use loom::sync::{Arc, Mutex, RwLock};
use loom::thread;

use capability_engine::{
    Access, Attributes, CapaError, Capability, Domain, DomainId, DomainPolicy, LocalHandle,
    MemoryRegion, Rights, Update, UpdateBatch,
};

// ═════════════════════════════════════════════════════════════════════════════
// Execution harness (mirrors loom_e2e.rs)
// ═════════════════════════════════════════════════════════════════════════════

struct E2EState {
    applied: Vec<Update>,
}
impl E2EState {
    fn new() -> Self {
        E2EState { applied: Vec::new() }
    }
}

fn execute_shared<F, R>(
    op_lock: &Arc<RwLock<()>>,
    ul: &Arc<Mutex<()>>,
    state: &Arc<Mutex<E2EState>>,
    op: F,
) -> capability_engine::Result<R>
where
    F: FnOnce() -> capability_engine::Result<(R, UpdateBatch)>,
{
    let _guard = op_lock.read().unwrap();
    let (result, batch) = op()?;
    apply_batch(ul, state, &batch);
    Ok(result)
}

fn execute_exclusive<F, R>(
    op_lock: &Arc<RwLock<()>>,
    ul: &Arc<Mutex<()>>,
    state: &Arc<Mutex<E2EState>>,
    op: F,
) -> capability_engine::Result<R>
where
    F: FnOnce() -> capability_engine::Result<(R, UpdateBatch)>,
{
    let _guard = op_lock.write().unwrap();
    let (result, batch) = op()?;
    apply_batch(ul, state, &batch);
    Ok(result)
}

fn apply_batch(ul: &Arc<Mutex<()>>, state: &Arc<Mutex<E2EState>>, batch: &UpdateBatch) {
    if batch.updates().is_empty() {
        return;
    }
    let _ul_guard = ul.lock().unwrap();
    let mut s = state.lock().unwrap();
    for u in batch.updates() {
        s.applied.push(u.clone());
    }
}

fn new_exec_state() -> (Arc<RwLock<()>>, Arc<Mutex<()>>, Arc<Mutex<E2EState>>) {
    (
        Arc::new(RwLock::new(())),
        Arc::new(Mutex::new(())),
        Arc::new(Mutex::new(E2EState::new())),
    )
}

fn make_root(
    size: u64,
) -> (
    capability_engine::CapabilityRef<Domain>,
    LocalHandle,
    capability_engine::CapabilityRef<MemoryRegion>,
) {
    let dom_data = Domain::new_root(1);
    let dom: capability_engine::CapabilityRef<Domain> = Capability::new_root(0, 0, dom_data);
    let owner_id = dom.read().data.id;
    let h: LocalHandle = 1;
    let mem = Capability::new_root(owner_id, h, MemoryRegion::new_root(0x0, size));
    dom.write()
        .data
        .add_memory_capability(h, std::sync::Arc::downgrade(&mem));
    (dom, h, mem)
}

// ═════════════════════════════════════════════════════════════════════════════
// M1 — Two threads race to send the same cap as META
// ═════════════════════════════════════════════════════════════════════════════
//
// Setup: sealed root domain `dom` with a carved child cap `h_c` and two
// unsealed receiver domains recv_a, recv_b.
//
// Thread A: execute_shared → send_memory(dom, h_c, dh_a, META)
// Thread B: execute_shared → send_memory(dom, h_c, dh_b, META)
//
// The freeze-based commit ensures exactly one send wins.
// Winner: emits exactly one Unmap for dom (h_c leaves dom's view).
//         receiver's address space is empty (META excluded).
// Loser:  returns PermissionDenied (frozen handle).
//
// In every interleaving:
//  - total Unmap updates for dom == 1
//  - no ChangeRights update for either receiver
#[test]
fn loom_meta_concurrent_send_race() {
    loom::model(|| {
        let (op_lock, ul, state) = new_exec_state();
        let (dom, h_root, _root_mem) = make_root(0x2000);
        let dom_id = dom.read().data.id;

        // Carve one child that both threads will race to send as META.
        let (h_c, _sub, _) = Capability::<Domain>::carve_memory(
            &dom,
            h_root,
            Access::new(0x0, 0x1000, Rights::RWX),
        )
        .expect("carve");

        // Two unsealed receiver domains.
        let recv_a: capability_engine::CapabilityRef<Domain> =
            Capability::new_root(0, 0, Domain::new(DomainPolicy::new_restricted(0xf, capability_engine::MonitorAPI::ALL)));
        let recv_b: capability_engine::CapabilityRef<Domain> =
            Capability::new_root(0, 0, Domain::new(DomainPolicy::new_restricted(0xf, capability_engine::MonitorAPI::ALL)));
        let recv_a_id = recv_a.read().data.id;
        let recv_b_id = recv_b.read().data.id;
        let dh_a: LocalHandle = 10;
        let dh_b: LocalHandle = 11;
        dom.write()
            .data
            .add_domain_capability(dh_a, std::sync::Arc::downgrade(&recv_a));
        dom.write()
            .data
            .add_domain_capability(dh_b, std::sync::Arc::downgrade(&recv_b));

        let dom_a = dom.clone();
        let dom_b = dom.clone();
        let recv_a2 = recv_a.clone();
        let recv_b2 = recv_b.clone();
        let op_a = op_lock.clone();
        let op_b = op_lock.clone();
        let ul_a = ul.clone();
        let ul_b = ul.clone();
        let st_a = state.clone();
        let st_b = state.clone();

        let ta = thread::spawn(move || {
            execute_shared(&op_a, &ul_a, &st_a, || {
                let upd = Capability::<Domain>::send_memory(
                    &dom_a,
                    h_c,
                    dh_a,
                    Attributes::from_bits(Attributes::META),
                )?;
                Ok(((), upd))
            })
        });

        let tb = thread::spawn(move || {
            execute_shared(&op_b, &ul_b, &st_b, || {
                let upd = Capability::<Domain>::send_memory(
                    &dom_b,
                    h_c,
                    dh_b,
                    Attributes::from_bits(Attributes::META),
                )?;
                Ok(((), upd))
            })
        });

        let ra = ta.join().unwrap();
        let rb = tb.join().unwrap();

        // Exactly one must succeed.
        let wins = [&ra, &rb]
            .iter()
            .filter(|r| r.is_ok())
            .count();
        assert_eq!(wins, 1, "exactly one thread must win the META send race");

        // The loser must get NotFound (cap already removed by winner) or PermissionDenied.
        let loses = [ra, rb]
            .into_iter()
            .filter(|r| r.is_err())
            .all(|e| matches!(e.unwrap_err(), CapaError::PermissionDenied | CapaError::NotFound));
        assert!(loses, "losing thread must get NotFound or PermissionDenied");

        // Exactly one Unmap/ChangeRights update for the sender dom.
        let applied = state.lock().unwrap();
        let sender_updates: Vec<_> = applied
            .applied
            .iter()
            .filter(|op| matches!(op, Update::ChangeRights { domain, .. } if *domain == dom_id))
            .collect();
        assert_eq!(sender_updates.len(), 1, "exactly one ChangeRights for sender");

        // No ChangeRights for either receiver (META excluded from address space).
        let recv_updates: Vec<_> = applied
            .applied
            .iter()
            .filter(|op| match op {
                Update::ChangeRights { domain, .. } => {
                    *domain == recv_a_id || *domain == recv_b_id
                }
                _ => false,
            })
            .collect();
        assert!(
            recv_updates.is_empty(),
            "no ChangeRights must be emitted for either receiver"
        );
    });
}

// ═════════════════════════════════════════════════════════════════════════════
// M2 — META send races with revocation of the same cap
// ═════════════════════════════════════════════════════════════════════════════
//
// Thread A (shared):    send_memory(dom, h_c, dh_recv, META)
// Thread B (exclusive): revoke_memory_child(dom, h_root, sub_c)
//
// Two valid orderings:
//
//   A-first: send succeeds → recv holds META cap.
//            revoke then fires: RevokeDomain(recv_id) emitted.
//            Total updates: 1 ChangeRights(dom) + 1 RevokeDomain(recv).
//
//   B-first: revoke fires first → cap tree is gone.
//            send returns NotFound or PermissionDenied.
//            Total updates: 0 (cap was never in any view after carve
//            because revoke happened before send transferred it) or
//            revoke emits ChangeRights for the cap being removed.
//            No RevokeDomain because the cap was never META in recv.
#[test]
fn loom_meta_send_vs_revoke() {
    loom::model(|| {
        let (op_lock, ul, state) = new_exec_state();
        let (dom, h_root, _root_mem) = make_root(0x2000);

        let (h_c, sub_c, _) = Capability::<Domain>::carve_memory(
            &dom,
            h_root,
            Access::new(0x0, 0x1000, Rights::RWX),
        )
        .expect("carve");

        let recv: capability_engine::CapabilityRef<Domain> =
            Capability::new_root(0, 0, Domain::new(DomainPolicy::new_restricted(0xf, capability_engine::MonitorAPI::ALL)));
        let recv_id = recv.read().data.id;
        let dh_recv: LocalHandle = 10;
        dom.write()
            .data
            .add_domain_capability(dh_recv, std::sync::Arc::downgrade(&recv));

        let dom_a = dom.clone();
        let dom_b = dom.clone();
        let op_a = op_lock.clone();
        let op_b = op_lock.clone();
        let ul_a = ul.clone();
        let ul_b = ul.clone();
        let st_a = state.clone();
        let st_b = state.clone();

        // Thread A: send as META (shared lock).
        let ta = thread::spawn(move || {
            execute_shared(&op_a, &ul_a, &st_a, || {
                let upd = Capability::<Domain>::send_memory(
                    &dom_a,
                    h_c,
                    dh_recv,
                    Attributes::from_bits(Attributes::META),
                )?;
                Ok(((), upd))
            })
        });

        // Thread B: revoke the same cap (exclusive lock).
        let tb = thread::spawn(move || {
            execute_exclusive(&op_b, &ul_b, &st_b, || {
                let upd =
                    Capability::<Domain>::revoke_memory_child(&dom_b, h_root, sub_c)?;
                Ok(((), upd))
            })
        });

        let ra = ta.join().unwrap();
        let rb = tb.join().unwrap();

        let applied = state.lock().unwrap();

        if ra.is_ok() {
            // A-first: send succeeded, META cap is in recv.
            // Revoke must have emitted RevokeDomain for recv.
            assert!(rb.is_ok(), "revoke must succeed after send");
            let has_revoke_domain = applied.applied.iter().any(|op| {
                matches!(op, Update::RevokeDomain { domain, .. } if *domain == recv_id)
            });
            assert!(
                has_revoke_domain,
                "A-first: revoking a META cap must emit RevokeDomain for the receiver"
            );
        } else {
            // B-first: revoke fired before send; send must fail.
            assert!(
                matches!(ra.unwrap_err(), CapaError::NotFound | CapaError::PermissionDenied),
                "B-first: send must return NotFound or PermissionDenied"
            );
            // No RevokeDomain for recv because the cap was never META in recv.
            let has_recv_revoke = applied.applied.iter().any(|op| {
                matches!(op, Update::RevokeDomain { domain, .. } if *domain == recv_id)
            });
            assert!(
                !has_recv_revoke,
                "B-first: no RevokeDomain for recv when send never completed"
            );
        }
    });
}
