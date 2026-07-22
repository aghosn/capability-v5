//! End-to-end loom tests for the full execution pipeline:
//! capability-lock → domain-mediated operation → update-lock → apply updates.
//!
//! Unlike §7.6–§7.9 (which manually acquire a loom `RwLock` and call
//! domain-mediated primitives directly), these tests model the complete
//! `Platform::execute()` protocol using loom-tracked primitives:
//!
//!  * `op_lock` — `loom::sync::RwLock<()>` modelling the global capability
//!    read-write lock (shared for non-revoke ops, exclusive for revokes).
//!  * `update_lock` — `loom::sync::Mutex<()>` modelling mutual exclusion on
//!    hardware-update application (equivalent to the Platform update lock for
//!    correctness purposes; avoids spinloop state-space explosion in loom).
//!  * `state` — `loom::sync::Mutex<E2EState>` tracking applied hardware updates.
//!
//! The library's internal per-capability `RwLock`s are also loom-tracked (via
//! `--features loom` which swaps `crate::sync::RwLock` to a wrapper around
//! `loom::sync::RwLock`).  The two lock levels therefore both participate in
//! loom's exhaustive interleaving exploration.
//!
//! # Tests
//!
//! E1. `loom_e2e_concurrent_sends`           — two concurrent sends (shared cap lock);
//!                                            update_lock serialises Map updates.
//! E2. `loom_e2e_accept_race`                — two threads race to accept the same
//!                                            pending cap; exactly one Map update applied.
//! E3. `loom_e2e_revoke_child_vs_send`       — revoke memory child (exclusive) races
//!                                            against a send (shared); exactly one
//!                                            consistent update set applied.
//! E4. `loom_e2e_domain_revoke_vs_mem_send`  — revoke a child domain (exclusive)
//!                                            races against sending a memory cap
//!                                            (shared); both updates applied in order.
//! E5. `loom_e2e_send_to_domain_being_revoked` — send a memory cap to the exact
//!                                            domain that is concurrently being
//!                                            revoked; loom verifies both orderings
//!                                            (B wins: Map+RevokeDomain applied;
//!                                             A wins: NotFound for B, only
//!                                             RevokeDomain applied).
//!
//! # Same-domain conflicting operations (multiple "cores" on same domain object)
//!
//! E6. `loom_e2e_two_cores_race_send_same_cap`   — two shared-lock threads both try
//!                                            to send the *same* handle from the
//!                                            same domain to different receivers;
//!                                            exactly one Map applied, loser gets
//!                                            NotFound.
//! E7. `loom_e2e_send_vs_revoke_same_cap`    — one core sends h_c1 (shared), another
//!                                            revokes it by sub_handle (exclusive);
//!                                            A-first: Map+Unmap+Map (3 updates);
//!                                            B-first: 0 updates, A gets NotFound.
//! E8. `loom_e2e_two_cores_double_revoke_same_child` — both cores hold the exclusive
//!                                            lock and try to revoke the same memory
//!                                            child; one gets NotFound, 0 hardware
//!                                            updates in every ordering.
//! E9. `loom_e2e_domain_revoke_with_memory_vs_send` — revoke a child domain that
//!                                            owns memory (exclusive) races against
//!                                            a concurrent send (shared); memory
//!                                            restore updates verified under all
//!                                            interleavings.
//!
//! # Running
//!
//! ```sh
//! cargo test --test loom_e2e --features loom --release
//! ```

#![allow(dead_code)]

use loom::sync::{Arc, Mutex, RwLock};
use loom::thread;

use capability_engine::{
    Access, Attributes, CapaError, Capability, Domain, DomainId, DomainPolicy, LocalHandle,
    MemoryRegion, Rights, Update, UpdateBatch,
};

// ─────────────────────────────────────────────────────────────────────────────
// NullPlatform — no-op Platform for sequential setup calls.  The loom-tracked
// per-capability RwLocks still govern all concurrency; NullPlatform's lock
// methods are intentional no-ops so loom explores only the capability locks.
// ─────────────────────────────────────────────────────────────────────────────

struct NullGuard;
impl capability_engine::OpLockGuard for NullGuard {}
unsafe impl Send for NullGuard {}

struct NullPlatform;
unsafe impl Send for NullPlatform {}
unsafe impl Sync for NullPlatform {}

impl capability_engine::Platform for NullPlatform {
    fn acquire_shared_lock(&self) -> capability_engine::Result<Box<dyn capability_engine::OpLockGuard>> {
        Ok(Box::new(NullGuard))
    }
    fn acquire_exclusive_lock(&self) -> capability_engine::Result<Box<dyn capability_engine::OpLockGuard>> {
        Ok(Box::new(NullGuard))
    }
    fn send_ipi(&self, _: capability_engine::CoreId) {}
    fn sync_barrier(&self, _: u8, _: usize) {}
    fn apply_update(&self, _: &capability_engine::Update) {}
    fn on_domain_revoked(&self, _: capability_engine::DomainId, _: Option<capability_engine::DomainId>) {}
    fn register_domain(&self, _: capability_engine::DomainId, _: Option<capability_engine::DomainId>) {}
    fn set_core_context(&self, _: capability_engine::CoreId, _: &capability_engine::CapabilityRef<capability_engine::Domain>, _: u64) {}
    fn clear_core_domain(&self, _: capability_engine::CoreId) {}
    fn domain_cores(&self, _: capability_engine::DomainId) -> Vec<capability_engine::CoreId> { Vec::new() }
    fn try_acquire_update_lock(&self) -> bool { true }
    fn release_update_lock(&self) {}
    fn get_current_core(&self) -> Option<capability_engine::CoreId> { None }
    fn switch_manager(&self) -> &capability_engine::SwitchManager {
        static NULL_SWITCH_MANAGER: std::sync::OnceLock<capability_engine::SwitchManager> =
            std::sync::OnceLock::new();
        NULL_SWITCH_MANAGER.get_or_init(|| capability_engine::SwitchManager::new(4))
    }
}



// ═════════════════════════════════════════════════════════════════════════════
// Execution harness — models Platform::execute() with loom-tracked primitives
// ═════════════════════════════════════════════════════════════════════════════

/// Per-model-run platform state: the applied hardware-update log.
struct E2EState {
    applied: Vec<Update>,
}

impl E2EState {
    fn new() -> Self {
        E2EState {
            applied: Vec::new(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────

/// Run `op` under the **shared** capability lock, then apply the returned
/// `UpdateBatch` under the atomic update lock.
///
/// Models the shared-op (carve / alias / send) path of `Platform::execute()`.
fn execute_shared<F, R>(
    op_lock: &Arc<RwLock<()>>,
    ul: &Arc<Mutex<()>>,
    state: &Arc<Mutex<E2EState>>,
    op: F,
) -> capability_engine::Result<R>
where
    F: FnOnce() -> capability_engine::Result<(R, UpdateBatch)>,
{
    // Step 1: acquire shared capability lock (held through update application).
    let _guard = op_lock.read().unwrap();
    // Step 2: run the pure tree mutation.
    let (result, batch) = op()?;
    // Steps 3–5: serialise update application.
    apply_batch(ul, state, &batch);
    Ok(result)
    // _guard dropped here → shared cap lock released.
}

/// Run `op` under the **exclusive** capability lock (for revoke operations).
///
/// Models the exclusive-op (revoke) path of `Platform::execute()`.
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

/// Acquire the update lock (Mutex), push all updates to the shared log,
/// then release the lock.  No-op for empty batches.
///
/// Using a Mutex (rather than a CAS spinloop) keeps loom's state-space
/// tractable: a spinloop creates O(2^k) interleavings for k iterations,
/// whereas a Mutex is a single scheduling decision.  Both provide the same
/// mutual-exclusion guarantee so correctness properties are unaffected.
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

// ═════════════════════════════════════════════════════════════════════════════
// Test helpers
// ═════════════════════════════════════════════════════════════════════════════

/// Create a sealed root domain owning a `[0x0, size)` memory capability at
/// handle 1.  Mirrors `dm_make_root` from `loom_concurrency.rs`.
fn make_root(
    size: u64,
) -> (
    capability_engine::CapabilityRef<Domain>,
    LocalHandle,
    capability_engine::CapabilityRef<MemoryRegion>,
) {
    let dom_data = Domain::new_root(1); // sealed, id auto-allocated
    let dom: capability_engine::CapabilityRef<Domain> = Capability::new_root(0, 0, dom_data);
    let owner_id = dom.read().data.id;
    let h: LocalHandle = 1;
    let mem = Capability::new_root(owner_id, h, MemoryRegion::new_root(0x0, size));
    // std::sync::Arc::downgrade: CapabilityRef<T> is std::sync::Arc under the hood
    // (only the inner RwLock is swapped to loom via --features loom).
    dom.write()
        .data
        .add_memory_capability(h, std::sync::Arc::downgrade(&mem));
    (dom, h, mem)
}

/// Initialise the shared execution state for one model run.
///
/// Returns `(op_lock, update_lock, state)`:
///  * `op_lock`  — shared/exclusive capability lock (loom `RwLock<()>`).
///  * `update_lock` — serialises hardware-update application (loom `Mutex<()>`).
///  * `state`    — the applied hardware-update log.
fn new_exec_state() -> (Arc<RwLock<()>>, Arc<Mutex<()>>, Arc<Mutex<E2EState>>) {
    (
        Arc::new(RwLock::new(())),
        Arc::new(Mutex::new(())),
        Arc::new(Mutex::new(E2EState::new())),
    )
}

// ═════════════════════════════════════════════════════════════════════════════
// E1 — Concurrent immediate sends; update_lock serialises Map updates
// ═════════════════════════════════════════════════════════════════════════════
//
// | Thread A (shared cap lock)                     | Thread B (shared cap lock)                     |
// |------------------------------------------------|------------------------------------------------|
// | execute_shared → send(dom, h_c1, dh_a)  | execute_shared → send(dom, h_c2, dh_b)  |
//
// Setup: sealed root domain `dom` with root memory cap; two carved non-
// overlapping children c1 [0x0000, 0x1000) and c2 [0x2000, 0x1000);
// two unsealed child domains recv_a and recv_b created via create.
//
// Both sends to unsealed receivers are immediate (no pending queue).
// Each send produces Unmap(dom, range) + Map(recv, range) via view_diff
// (c1/c2 leave dom's view, enter recv's empty view).
//
// The update_lock ensures each pair of updates is applied atomically.
// Loom explores: A's mutation first or B's mutation first (serialised by
// dom.write()), and which thread acquires update_lock first.
//
// Valid outcomes (all schedules):
//  - applied contains Unmap(dom, c1), Map(recv_a_id, 0x0000),
//                      Unmap(dom, c2), Map(recv_b_id, 0x2000) in some order.
//  - recv_a holds c1; recv_b holds c2.
#[test]
fn loom_e2e_concurrent_sends() {
    loom::model(|| {
        let (op_lock, ul, state) = new_exec_state();
        let (dom, h_root, _root_mem) = make_root(0x4000);
        let dom_id = dom.read().data.id;

        // Sequential setup: carve two non-overlapping children.
        let (h_c1, _sub1, _) = Capability::<Domain>::carve(
            &NullPlatform, &dom,
            h_root,
            Access::new(0x0000, 0x1000, Rights::RW),
        )
        .expect("setup: carve c1");
        let (h_c2, _sub2, _) = Capability::<Domain>::carve(
            &NullPlatform, &dom,
            h_root,
            Access::new(0x2000, 0x1000, Rights::RW),
        )
        .expect("setup: carve c2");

        // Create two unsealed child domains as receivers via the domain-mediated API.
        let dh_a = Capability::<Domain>::create(&NullPlatform, &dom, DomainPolicy::new_root(1))
            .expect("setup: create recv_a").0;
        let dh_b = Capability::<Domain>::create(&NullPlatform, &dom, DomainPolicy::new_root(1))
            .expect("setup: create recv_b").0;
        let recv_a = {
            let r = dom.read();
            r.data.get_domain_capability(dh_a).unwrap().upgrade().unwrap()
        };
        let recv_b = {
            let r = dom.read();
            r.data.get_domain_capability(dh_b).unwrap().upgrade().unwrap()
        };
        let recv_a_id = recv_a.read().data.id;
        let recv_b_id = recv_b.read().data.id;

        // Thread A: send c1 → recv_a.
        let (opl, ul_a, st, d) = (op_lock.clone(), ul.clone(), state.clone(), dom.clone());
        let ta = thread::spawn(move || {
            execute_shared(&opl, &ul_a, &st, || {
                let batch = Capability::<Domain>::send(&NullPlatform, &d, h_c1, dh_a, Attributes::NONE)?;
                Ok(((), batch))
            })
        });

        // Thread B: send c2 → recv_b.
        let (opl, ul_b, st, d) = (op_lock.clone(), ul.clone(), state.clone(), dom.clone());
        let tb = thread::spawn(move || {
            execute_shared(&opl, &ul_b, &st, || {
                let batch = Capability::<Domain>::send(&NullPlatform, &d, h_c2, dh_b, Attributes::NONE)?;
                Ok(((), batch))
            })
        });

        ta.join().unwrap().expect("A: send c1 to recv_a");
        tb.join().unwrap().expect("B: send c2 to recv_b");

        let applied = state.lock().unwrap().applied.clone();
        assert_eq!(
            applied.len(),
            4,
            "2 Unmap + 2 Map updates (one pair per immediate send)"
        );

        let has_unmap_c1 = applied.iter().any(|u| {
            matches!(
                u, Update::ChangeRights { domain, address: 0x0000, size: 0x1000, rights, .. } if *domain == dom_id && *rights == Rights::NONE
            )
        });
        let has_unmap_c2 = applied.iter().any(|u| {
            matches!(
                u, Update::ChangeRights { domain, address: 0x2000, size: 0x1000, rights, .. } if *domain == dom_id && *rights == Rights::NONE
            )
        });
        let has_map_a = applied.iter().any(|u| {
            matches!(
                u, Update::ChangeRights { domain, address: 0x0000, size: 0x1000, shootdown_required: false, .. } if *domain == recv_a_id
            )
        });
        let has_map_b = applied.iter().any(|u| {
            matches!(
                u, Update::ChangeRights { domain, address: 0x2000, size: 0x1000, shootdown_required: false, .. } if *domain == recv_b_id
            )
        });
        assert!(has_unmap_c1, "Unmap(dom, c1 range) must be applied");
        assert!(has_unmap_c2, "Unmap(dom, c2 range) must be applied");
        assert!(has_map_a, "Map for recv_a must be applied");
        assert!(has_map_b, "Map for recv_b must be applied");

        // Each receiver must now hold its capability.
        assert_eq!(recv_a.read().data.memory_capability_handles().len(), 1);
        assert_eq!(recv_b.read().data.memory_capability_handles().len(), 1);
    });
}

// ═════════════════════════════════════════════════════════════════════════════
// E2 — Two threads race to accept the same pending cap; one Map update applied
// ═════════════════════════════════════════════════════════════════════════════
//
// | Thread A (shared cap lock)                      | Thread B (shared cap lock)                      |
// |-------------------------------------------------|-------------------------------------------------|
// | execute_shared → accept(recv, pending_id)| execute_shared → accept(recv, pending_id)|
//
// Setup: sender sends c1 to a sealed receiver → pending entry created.
// Both threads race to accept the same pending_id.
//
// accept removes the pending entry atomically (receiver.write() in the
// first step), so exactly one thread wins; the other gets NotFound.
//
// skip_unmap = true (c1's parent = root_mem, owned by sender = sender_id ==
// the sender_domain_id stored in the pending entry), so the winning accept
// generates exactly one Map update.
//
// Valid outcomes (all schedules):
//  - Exactly one accept succeeds; exactly one Map(recv_id) applied.
//  - recv holds the cap at one handle; pending queue empty.
#[test]
fn loom_e2e_accept_race() {
    loom::model(|| {
        let (op_lock, ul, state) = new_exec_state();

        // Sealed sender (root domain) with a memory cap.
        let (sender, h_root, _root_mem) = make_root(0x2000);
        let sender_id = sender.read().data.id;

        // Sealed child domain as receiver (supports receive_after_seal).
        // Use create + seal so it is properly parented under sender.
        let dh_recv = Capability::<Domain>::create(&NullPlatform, &sender, DomainPolicy::new_root(1))
            .expect("setup: create recv").0;
        Capability::<Domain>::seal(&NullPlatform, &sender, dh_recv)
            .expect("setup: seal recv");
        let recv = {
            let r = sender.read();
            r.data.get_domain_capability(dh_recv).unwrap().upgrade().unwrap()
        };
        let recv_id = recv.read().data.id;

        // Carve c1 and send to the sealed receiver → pending queue path.
        let (h_c1, _sub1, _) = Capability::<Domain>::carve(
            &NullPlatform, &sender,
            h_root,
            Access::new(0x0, 0x1000, Rights::RW),
        )
        .expect("setup: carve c1");
        Capability::<Domain>::send(&NullPlatform, &sender, h_c1, dh_recv, Attributes::NONE)
            .expect("setup: send to sealed receiver");

        // Capture the single pending_id (setup is sequential, so exactly one).
        let pending_ids = recv.read().data.get_pending_ids();
        assert_eq!(pending_ids.len(), 1, "one pending entry before races");
        let pending_id = pending_ids[0];

        // Thread A: try to accept.
        let (opl, ul_a, st, r) = (op_lock.clone(), ul.clone(), state.clone(), recv.clone());
        let ta = thread::spawn(move || {
            execute_shared(&opl, &ul_a, &st, || {
                let (handle, batch) = Capability::<Domain>::accept(&NullPlatform, &r, pending_id)?;
                Ok((handle, batch))
            })
        });

        // Thread B: also try to accept the same pending_id.
        let (opl, ul_b, st, r) = (op_lock.clone(), ul.clone(), state.clone(), recv.clone());
        let tb = thread::spawn(move || {
            execute_shared(&opl, &ul_b, &st, || {
                let (handle, batch) = Capability::<Domain>::accept(&NullPlatform, &r, pending_id)?;
                Ok((handle, batch))
            })
        });

        let res_a = ta.join().unwrap();
        let res_b = tb.join().unwrap();

        // Exactly one accept must succeed.
        let successes = [res_a.is_ok(), res_b.is_ok()]
            .iter()
            .filter(|&&x| x)
            .count();
        assert_eq!(successes, 1, "exactly one accept must succeed");

        // Loser must get NotFound.
        let loser = if res_a.is_err() { &res_a } else { &res_b };
        assert_eq!(*loser.as_ref().unwrap_err(), CapaError::NotFound);

        // accept generates Unmap(sender) + Map(recv): sender's frozen cap is
        // removed at accept time, shrinking sender's view and triggering a shootdown.
        let applied = state.lock().unwrap().applied.clone();
        assert_eq!(applied.len(), 2, "Unmap(sender) + Map(recv) from accept");
        assert!(
            applied.iter().any(|u| matches!(
                u, Update::ChangeRights { domain, rights, .. } if *domain == sender_id && *rights == Rights::NONE
            )),
            "Unmap for sender must be applied"
        );
        assert!(
            applied.iter().any(|u| matches!(
                u, Update::ChangeRights { domain, shootdown_required: false, .. } if *domain == recv_id
            )),
            "Map for recv_id must be applied"
        );

        // Pending queue must be empty; recv holds exactly one cap.
        assert!(recv.read().data.get_pending_ids().is_empty());
        assert_eq!(recv.read().data.memory_capability_handles().len(), 1);
    });
}

// ═════════════════════════════════════════════════════════════════════════════
// E3 — Revoke memory child (exclusive) races against a sibling send (shared)
// ═════════════════════════════════════════════════════════════════════════════
//
// | Thread A (exclusive cap lock)                           | Thread B (shared cap lock)                    |
// |---------------------------------------------------------|-----------------------------------------------|
// | execute_exclusive → revoke(dom, root, sub1)| execute_shared → send(dom, h_c2, dh_b) |
//
// Setup:
//   1. dom (sealed root) with root_mem at h_root.
//   2. Carve c1 [0x0000, 0x1000) and c2 [0x2000, 0x1000).
//   3. Immediately send c1 to unsealed recv_a (dom_id → recv_a_id transfer).
//      After send: c1.owned.owner = recv_a_id; c1 still in tree under root_mem.
//   4. Create unsealed recv_b.
//
// Thread A (exclusive): revoke(dom, h_root, sub_c1).
//   revoke_subtree: c1.parent = root_mem (owned by dom_id),
//                  c1.owner  = recv_a_id  →  skip_unmap = false
//   Batch: [Unmap(recv_a_id, 0x0000, 0x1000), Map(dom_id, 0x0000, 0x1000)]
//
// Thread B (shared): send(dom, h_c2, dh_b, NONE) → Map(recv_b_id, 0x2000)
//   skip_unmap = true (c2's parent = root_mem owned by dom).
//
// Because A holds the exclusive cap lock, A and B are strictly serialised.
// Loom explores: A completes before B starts, or B completes before A starts.
// In both orderings all three updates are present in the applied log.
//
// Valid outcomes (all schedules):
//  - applied contains Unmap(recv_a_id, 0x0000), Map(dom_id, 0x0000),
//    Map(recv_b_id, 0x2000).
//  - The Unmap and its companion Map always appear as a consecutive batch.
#[test]
fn loom_e2e_revoke_child_vs_send() {
    loom::model(|| {
        let (op_lock, ul, state) = new_exec_state();
        let (dom, h_root, _root_mem) = make_root(0x4000);
        let dom_id = dom.read().data.id;

        // Carve c1 and c2.
        let (h_c1, sub_c1, _) = Capability::<Domain>::carve(
            &NullPlatform, &dom,
            h_root,
            Access::new(0x0000, 0x1000, Rights::RW),
        )
        .expect("setup: carve c1");
        let (h_c2, _sub2, _) = Capability::<Domain>::carve(
            &NullPlatform, &dom,
            h_root,
            Access::new(0x2000, 0x1000, Rights::RW),
        )
        .expect("setup: carve c2");

        // Create recv_a and recv_b as proper child domains via create.
        let dh_a = Capability::<Domain>::create(&NullPlatform, &dom, DomainPolicy::new_root(1))
            .expect("setup: create recv_a").0;
        let recv_a = {
            let r = dom.read();
            r.data.get_domain_capability(dh_a).unwrap().upgrade().unwrap()
        };
        let recv_a_id = recv_a.read().data.id;

        // Immediately send c1 to unsealed recv_a (updates discarded — setup only).
        Capability::<Domain>::send(&NullPlatform, &dom, h_c1, dh_a, Attributes::NONE)
            .expect("setup: send c1 to recv_a");
        // After send: h_c1 removed from dom's table; c1.owner = recv_a_id.

        // Register recv_b for Thread B's send.
        let dh_b = Capability::<Domain>::create(&NullPlatform, &dom, DomainPolicy::new_root(1))
            .expect("setup: create recv_b").0;
        let recv_b = {
            let r = dom.read();
            r.data.get_domain_capability(dh_b).unwrap().upgrade().unwrap()
        };
        let recv_b_id = recv_b.read().data.id;

        // Thread A (exclusive): revoke c1 by its stable sub_handle.
        let (opl, ul_a, st, d) = (op_lock.clone(), ul.clone(), state.clone(), dom.clone());
        let ta = thread::spawn(move || {
            execute_exclusive(&opl, &ul_a, &st, || {
                let batch = Capability::<Domain>::revoke(&NullPlatform, &d, h_root, sub_c1)?;
                Ok(((), batch))
            })
        });

        // Thread B (shared): send c2 to recv_b.
        let (opl, ul_b, st, d) = (op_lock.clone(), ul.clone(), state.clone(), dom.clone());
        let tb = thread::spawn(move || {
            execute_shared(&opl, &ul_b, &st, || {
                let batch = Capability::<Domain>::send(&NullPlatform, &d, h_c2, dh_b, Attributes::NONE)?;
                Ok(((), batch))
            })
        });

        ta.join().unwrap().expect("A: revoke c1");
        tb.join().unwrap().expect("B: send c2 to recv_b");

        let applied = state.lock().unwrap().applied.clone();
        // 4 updates: Unmap(recv_a) + Map(dom) from revoke,
        // Unmap(dom, c2 range) + Map(recv_b) from send (view-diff).
        assert_eq!(applied.len(), 4, "4 updates total");

        let has_unmap_a = applied.iter().any(|u| {
            matches!(
                u, Update::ChangeRights { domain, address: 0x0000, size: 0x1000, rights, .. } if *domain == recv_a_id && *rights == Rights::NONE
            )
        });
        let has_map_dom = applied.iter().any(|u| {
            matches!(
                u, Update::ChangeRights { domain, address: 0x0000, size: 0x1000, shootdown_required: false, .. } if *domain == dom_id
            )
        });
        let has_map_b = applied.iter().any(|u| {
            matches!(
                u, Update::ChangeRights { domain, address: 0x2000, size: 0x1000, shootdown_required: false, .. } if *domain == recv_b_id
            )
        });
        let has_unmap_dom_c2 = applied.iter().any(|u| {
            matches!(
                u, Update::ChangeRights { domain, address: 0x2000, size: 0x1000, rights, .. } if *domain == dom_id && *rights == Rights::NONE
            )
        });
        assert!(has_unmap_a, "Unmap(recv_a) must be applied");
        assert!(has_map_dom, "Map(dom, reclaim c1) must be applied");
        assert!(has_map_b, "Map(recv_b) from send must be applied");
        assert!(
            has_unmap_dom_c2,
            "Unmap(dom, c2 range) from send must be applied"
        );

        // The two revoke updates (Unmap + Map) must be adjacent in the log —
        // the update_lock guarantees the batch is applied atomically.
        let unmap_pos = applied
            .iter()
            .position(|u| {
                matches!(
                    u, Update::ChangeRights { domain, rights, .. } if *domain == recv_a_id && *rights == Rights::NONE
                )
            })
            .unwrap();
        let map_dom_pos = applied
            .iter()
            .position(|u| {
                matches!(
                    u, Update::ChangeRights { domain, address: 0x0000, shootdown_required: false, .. } if *domain == dom_id
                )
            })
            .unwrap();
        assert_eq!(
            map_dom_pos,
            unmap_pos + 1,
            "Unmap(recv_a) and Map(dom) must be consecutive (atomic batch)"
        );
    });
}

// ═════════════════════════════════════════════════════════════════════════════
// E4 — Revoke a child domain (exclusive) races against a memory send (shared)
// ═════════════════════════════════════════════════════════════════════════════
//
// | Thread A (exclusive cap lock)                    | Thread B (shared cap lock)                    |
// |--------------------------------------------------|-----------------------------------------------|
// | execute_exclusive → revoke_domain(dom, h_child)  | execute_shared → send(dom, h_c1, dh_r) |
//
// Setup:
//   1. dom (sealed root) with root_mem at h_root.
//   2. Carve c1 [0x0000, 0x1000) from root_mem.
//   3. Create child domain ch1 under dom; capture ch1_id.
//   4. Create unsealed memory receiver recv_m.
//
// Thread A (exclusive): revoke_domain(dom, h_child).
//   revoke_domain_subtree: emits RevokeDomain(ch1_id, fallback=Some(dom_id)).
//   Batch: [RevokeDomain(ch1_id)]
//
// Thread B (shared): send(dom, h_c1, dh_r, NONE).
//   Immediate send (unsealed recv_m); skip_unmap = true.
//   Batch: [Map(recv_m_id, 0x0000, 0x1000)]
//
// Because A holds the exclusive cap lock, A and B are strictly serialised.
// Loom explores A-first and B-first orderings.
// In both orderings the RevokeDomain and Map updates are both present.
//
// Valid outcomes (all schedules):
//  - applied contains RevokeDomain(ch1_id) and Map(recv_m_id).
//  - ch1 is marked revoked; recv_m holds c1.
#[test]
fn loom_e2e_domain_revoke_vs_mem_send() {
    loom::model(|| {
        let (op_lock, ul, state) = new_exec_state();
        let (dom, h_root, _root_mem) = make_root(0x2000);
        let dom_id = dom.read().data.id;

        // Carve c1 for Thread B to send.
        let (h_c1, _sub1, _) = Capability::<Domain>::carve(
            &NullPlatform, &dom,
            h_root,
            Access::new(0x0000, 0x1000, Rights::RW),
        )
        .expect("setup: carve c1");

        // Create child domain ch1 under dom.
        let h_child = Capability::<Domain>::create(&NullPlatform, &dom, DomainPolicy::new_root(1))
            .expect("setup: create child domain").0;
        let ch1_id: DomainId = dom
            .read()
            .data
            .get_domain_capability(h_child)
            .unwrap()
            .upgrade()
            .unwrap()
            .read()
            .data
            .id;

        // Create an unsealed memory receiver as a proper child domain.
        // h_child was allocated as handle 1; recv_m gets handle 2.
        let dh_r = Capability::<Domain>::create(&NullPlatform, &dom, DomainPolicy::new_root(1))
            .expect("setup: create recv_m").0;
        let recv_m = {
            let r = dom.read();
            r.data.get_domain_capability(dh_r).unwrap().upgrade().unwrap()
        };
        let recv_m_id = recv_m.read().data.id;

        // Thread A (exclusive): revoke the child domain.
        let (opl, ul_a, st, d) = (op_lock.clone(), ul.clone(), state.clone(), dom.clone());
        let ta = thread::spawn(move || {
            execute_exclusive(&opl, &ul_a, &st, || {
                let batch = Capability::<Domain>::revoke_domain(&NullPlatform, &d, h_child)?;
                Ok(((), batch))
            })
        });

        // Thread B (shared): send c1 to recv_m.
        let (opl, ul_b, st, d) = (op_lock.clone(), ul.clone(), state.clone(), dom.clone());
        let tb = thread::spawn(move || {
            execute_shared(&opl, &ul_b, &st, || {
                let batch = Capability::<Domain>::send(&NullPlatform, &d, h_c1, dh_r, Attributes::NONE)?;
                Ok(((), batch))
            })
        });

        ta.join().unwrap().expect("A: revoke child domain");
        tb.join().unwrap().expect("B: send c1 to recv_m");

        let applied = state.lock().unwrap().applied.clone();
        // 3 updates: RevokeDomain(ch1_id) from A,
        // Unmap(dom_id, c1 range) + Map(recv_m_id) from B (view-diff).
        assert_eq!(applied.len(), 3, "3 updates total");

        let has_revoke = applied.iter().any(|u| {
            matches!(
                u, Update::RevokeDomain { domain, .. } if *domain == ch1_id
            )
        });
        let has_map = applied.iter().any(|u| {
            matches!(
                u, Update::ChangeRights { domain, address: 0x0000, size: 0x1000, shootdown_required: false, .. } if *domain == recv_m_id
            )
        });
        let has_unmap_dom = applied.iter().any(|u| {
            matches!(
                u, Update::ChangeRights { domain, address: 0x0000, size: 0x1000, rights, .. } if *domain == dom_id && *rights == Rights::NONE
            )
        });
        assert!(has_revoke, "RevokeDomain(ch1_id) must be applied");
        assert!(has_map, "Map(recv_m_id) from send must be applied");
        assert!(has_unmap_dom, "Unmap(dom_id) from send must be applied");

        // ch1 revoke confirmed by RevokeDomain update above.
        // recv_m must hold c1.
        assert_eq!(recv_m.read().data.memory_capability_handles().len(), 1);
        // dom's domain table must not contain h_child (removed by revoke_domain).
        assert!(dom.read().data.get_domain_capability(h_child).is_none());
    });
}

// ═════════════════════════════════════════════════════════════════════════════
// E5 — Send a memory cap to the exact domain being concurrently revoked
// ═════════════════════════════════════════════════════════════════════════════
//
// | Thread A (exclusive cap lock)                    | Thread B (shared cap lock)                      |
// |--------------------------------------------------|--------------------------------------------------|
// | execute_exclusive → revoke_domain(dom, h_child)  | execute_shared → send(dom, h_c1, h_child)|
//
// Setup:
//   1. dom (sealed root) with root_mem at h_root.
//   2. Carve c1 [0x0000, 0x1000) from root_mem.
//   3. Create child domain ch1 via create (unsealed); h_child is the
//      LocalHandle for ch1 in dom's domain-capability table.
//   4. Capture ch1_id.
//
// Thread A (exclusive): revoke_domain(dom, h_child).
//   Removes h_child from dom's domain table; emits RevokeDomain(ch1_id).
//
// Thread B (shared): send(dom, h_c1, h_child, NONE).
//   Looks up h_child in dom's domain table to find the recipient ch1.
//   ch1 is unsealed → immediate transfer path.
//   skip_unmap = true (c1's parent = root_mem owned by dom).
//   Batch: [Map(ch1_id, 0x0, 0x1000)] if B wins, or NotFound if A already
//   removed h_child from the table.
//
// Because A holds the exclusive cap lock, A and B are strictly serialised —
// no partial interleaving is possible.  Loom explores two orderings:
//
//  B-first: send succeeds → Map(ch1_id) applied; then A revokes (ch1 now
//           owns c1) → Unmap(ch1_id) + Restore(dom_id) + RevokeDomain.
//           applied = [Unmap(dom), Map(ch1_id), Unmap(ch1_id),
//                      Restore(dom), RevokeDomain(ch1_id)].
//           Map must precede RevokeDomain in the log.
//
//  A-first: revoke removes h_child from dom's table → B's domain-cap lookup
//           returns None → NotFound.
//           applied = [RevokeDomain(ch1_id)].
//
// In both orderings: dom's domain table must not contain h_child after both
// threads have completed.
#[test]
fn loom_e2e_send_to_domain_being_revoked() {
    loom::model(|| {
        let (op_lock, ul, state) = new_exec_state();
        let (dom, h_root, _root_mem) = make_root(0x2000);
        let dom_id = dom.read().data.id;

        // Carve c1 for Thread B to send.
        let (h_c1, _sub1, _) = Capability::<Domain>::carve(
            &NullPlatform, &dom,
            h_root,
            Access::new(0x0000, 0x1000, Rights::RW),
        )
        .expect("setup: carve c1");

        // Create child domain ch1 under dom (unsealed — supports immediate send).
        let h_child = Capability::<Domain>::create(&NullPlatform, &dom, DomainPolicy::new_root(1))
            .expect("setup: create ch1").0;
        let ch1_id: DomainId = dom
            .read()
            .data
            .get_domain_capability(h_child)
            .unwrap()
            .upgrade()
            .unwrap()
            .read()
            .data
            .id;

        // Thread A (exclusive): revoke child domain ch1.
        let (opl, ul_a, st, d) = (op_lock.clone(), ul.clone(), state.clone(), dom.clone());
        let ta = thread::spawn(move || {
            execute_exclusive(&opl, &ul_a, &st, || {
                let batch = Capability::<Domain>::revoke_domain(&NullPlatform, &d, h_child)?;
                Ok(((), batch))
            })
        });

        // Thread B (shared): send c1 to ch1 — the exact domain A is revoking.
        let (opl, ul_b, st, d) = (op_lock.clone(), ul.clone(), state.clone(), dom.clone());
        let tb = thread::spawn(move || {
            execute_shared(&opl, &ul_b, &st, || {
                let batch = Capability::<Domain>::send(&NullPlatform, &d, h_c1, h_child, Attributes::NONE)?;
                Ok(((), batch))
            })
        });

        ta.join()
            .unwrap()
            .expect("A: revoke_domain must always succeed");
        let res_b = tb.join().unwrap();

        let applied = state.lock().unwrap().applied.clone();

        match res_b {
            Ok(()) => {
                // B-first ordering: send generates Unmap(dom) + Map(ch1_id),
                // then A revokes ch1 which now owns c1 →
                //   Restore(dom_id) + RevokeDomain(ch1_id).
                // No Unmap(ch1_id): RevokeDomain is emitted first and frees the
                // EPT; a subsequent unmap would touch an already-torn-down domain.
                // Total: 4 updates.
                assert_eq!(applied.len(), 4, "B-first: exactly 4 updates");
                assert!(
                    applied.iter().any(|u| matches!(
                        u, Update::ChangeRights { domain, address: 0x0000, size: 0x1000, rights, .. }
                        if *domain == dom_id && *rights == Rights::NONE
                    )),
                    "B-first: Unmap(dom_id) from send must be present"
                );
                assert!(
                    applied.iter().any(|u| matches!(
                        u, Update::ChangeRights { domain, address: 0x0000, size: 0x1000, shootdown_required: false, .. }
                        if *domain == ch1_id
                    )),
                    "B-first: Map(ch1_id) from send must be present"
                );
                // Memory restore: ch1's owned c1 is revoked back to dom.
                let has_restore_dom = applied.iter().any(|u| matches!(
                    u, Update::ChangeRights { domain, address: 0x0000, size: 0x1000, shootdown_required: false, .. }
                    if *domain == dom_id
                ));
                assert!(has_restore_dom, "B-first: Restore(dom_id) from memory revoke must be present");
                assert!(
                    applied.iter().any(|u| matches!(
                        u, Update::RevokeDomain { domain, .. } if *domain == ch1_id
                    )),
                    "B-first: RevokeDomain(ch1_id) must be present"
                );
                // B ran before A: Map(ch1_id) must appear before RevokeDomain.
                let map_pos = applied
                    .iter()
                    .position(|u| {
                        matches!(
                            u, Update::ChangeRights { domain, shootdown_required: false, .. } if *domain == ch1_id
                        )
                    })
                    .unwrap();
                let revoke_pos = applied
                    .iter()
                    .position(|u| {
                        matches!(
                            u, Update::RevokeDomain { domain, .. } if *domain == ch1_id
                        )
                    })
                    .unwrap();
                assert!(
                    map_pos < revoke_pos,
                    "B-first: Map(ch1_id) must precede RevokeDomain(ch1_id)"
                );
            }
            Err(e) => {
                // A-first ordering: revoke removed h_child from dom's table before
                // B could look it up → B gets NotFound.
                // ch1 had no memory (B never ran) → only RevokeDomain applied.
                assert_eq!(e, CapaError::NotFound, "A-first: B must get NotFound");
                assert_eq!(applied.len(), 1, "A-first: only RevokeDomain applied");
                assert!(
                    applied.iter().any(|u| matches!(
                        u, Update::RevokeDomain { domain, .. } if *domain == ch1_id
                    )),
                    "A-first: RevokeDomain(ch1_id) must be applied"
                );
            }
        }

        // Both orderings: h_child must be gone from dom's domain table.
        assert!(
            dom.read().data.get_domain_capability(h_child).is_none(),
            "h_child must not remain in dom's domain table after revoke"
        );
    });
}

// ═════════════════════════════════════════════════════════════════════════════
// E6 — Two cores of the same domain race to send the same cap
// ═════════════════════════════════════════════════════════════════════════════
//
// | Thread A (shared cap lock)                       | Thread B (shared cap lock)                       |
// |--------------------------------------------------|--------------------------------------------------|
// | execute_shared → send(dom, h_c1, dh_a)   | execute_shared → send(dom, h_c1, dh_b)   |
//
// Both threads target the *same* LocalHandle (h_c1) in dom's memory table.
// Since both hold shared cap locks they can truly interleave; the inner
// per-capability write lock on dom's data serialises the actual removal of
// h_c1 — only one thread wins the slot.
//
// Setup: dom (sealed root) with root_mem; one carved child c1; two unsealed
// child domains recv_a and recv_b created via create.
//
// Valid outcomes (all schedules):
//  - Exactly one send succeeds → Unmap(dom) + Map(winner) applied.
//  - Loser's send returns NotFound (h_c1 removed from dom's table by
//    winner under the write lock) or PermissionDenied (pre-flight owner
//    check observed the cap already transferred — both are correct race
//    outcomes since the authoritative commit is remove_memory_capability).
//  - The winning receiver holds c1; the losing receiver holds nothing.
#[test]
fn loom_e2e_two_cores_race_send_same_cap() {
    loom::model(|| {
        let (op_lock, ul, state) = new_exec_state();
        let (dom, h_root, _root_mem) = make_root(0x2000);
        let dom_id = dom.read().data.id;

        // One cap that both threads will race to send.
        let (h_c1, _sub1, _) = Capability::<Domain>::carve(
            &NullPlatform, &dom,
            h_root,
            Access::new(0x0000, 0x1000, Rights::RW),
        )
        .expect("setup: carve c1");

        // Two distinct unsealed child domains as receivers.
        let dh_a = Capability::<Domain>::create(&NullPlatform, &dom, DomainPolicy::new_root(1))
            .expect("setup: create recv_a").0;
        let dh_b = Capability::<Domain>::create(&NullPlatform, &dom, DomainPolicy::new_root(1))
            .expect("setup: create recv_b").0;
        let recv_a = {
            let r = dom.read();
            r.data.get_domain_capability(dh_a).unwrap().upgrade().unwrap()
        };
        let recv_b = {
            let r = dom.read();
            r.data.get_domain_capability(dh_b).unwrap().upgrade().unwrap()
        };
        let recv_a_id = recv_a.read().data.id;
        let recv_b_id = recv_b.read().data.id;

        // Thread A: send h_c1 → recv_a.
        let (opl, ul_a, st, d) = (op_lock.clone(), ul.clone(), state.clone(), dom.clone());
        let ta = thread::spawn(move || {
            execute_shared(&opl, &ul_a, &st, || {
                let batch = Capability::<Domain>::send(&NullPlatform, &d, h_c1, dh_a, Attributes::NONE)?;
                Ok(((), batch))
            })
        });

        // Thread B: send h_c1 → recv_b (same source handle).
        let (opl, ul_b, st, d) = (op_lock.clone(), ul.clone(), state.clone(), dom.clone());
        let tb = thread::spawn(move || {
            execute_shared(&opl, &ul_b, &st, || {
                let batch = Capability::<Domain>::send(&NullPlatform, &d, h_c1, dh_b, Attributes::NONE)?;
                Ok(((), batch))
            })
        });

        let res_a = ta.join().unwrap();
        let res_b = tb.join().unwrap();

        // Exactly one send must succeed.
        let successes = [res_a.is_ok(), res_b.is_ok()]
            .iter()
            .filter(|&&x| x)
            .count();
        assert_eq!(successes, 1, "exactly one send must succeed");

        // Loser gets NotFound (h_c1 already removed from dom's table by the
        // winner inside its write lock) or PermissionDenied (pre-flight
        // owner check saw the updated owner after the winner's transfer).
        // Both are correct: the authoritative commit is remove_memory_capability.
        let loser = if res_a.is_err() { &res_a } else { &res_b };
        let loser_err = loser.as_ref().unwrap_err().clone();
        assert!(
            loser_err == CapaError::NotFound || loser_err == CapaError::PermissionDenied,
            "loser must get NotFound or PermissionDenied, got {loser_err:?}",
        );

        // Winning send generates Unmap(dom) + Map(winner_recv).
        let applied = state.lock().unwrap().applied.clone();
        assert_eq!(
            applied.len(),
            2,
            "Unmap(dom) + Map(winner) from winning send"
        );
        let has_unmap_dom = applied.iter().any(|u| {
            matches!(
                u, Update::ChangeRights { domain, address: 0x0000, size: 0x1000, rights, .. } if *domain == dom_id && *rights == Rights::NONE
            )
        });
        assert!(has_unmap_dom, "Unmap(dom) for the sent cap must be applied");

        // The Map is for exactly one of the two receivers (XOR).
        let map_a = applied.iter().any(|u| {
            matches!(
                u, Update::ChangeRights { domain, shootdown_required: false, .. } if *domain == recv_a_id
            )
        });
        let map_b = applied.iter().any(|u| {
            matches!(
                u, Update::ChangeRights { domain, shootdown_required: false, .. } if *domain == recv_b_id
            )
        });
        assert!(map_a ^ map_b, "Map for exactly one receiver");

        // The winning receiver holds the cap; the other is empty.
        let a_count = recv_a.read().data.memory_capability_handles().len();
        let b_count = recv_b.read().data.memory_capability_handles().len();
        assert_eq!(a_count + b_count, 1, "exactly one receiver holds the cap");
        assert!(
            (map_a && a_count == 1) || (map_b && b_count == 1),
            "Map and receiver ownership agree"
        );
    });
}

// ═════════════════════════════════════════════════════════════════════════════
// E7 — One core sends a cap while another revokes it via its sub_handle
// ═════════════════════════════════════════════════════════════════════════════
//
// | Thread A (shared cap lock)                       | Thread B (exclusive cap lock)                    |
// |--------------------------------------------------|--------------------------------------------------|
// | execute_shared → send(dom, h_c1, dh_recv) | execute_exclusive → revoke(h_root, sub_c1) |
//
// The same capability node is reachable via two independent "addresses":
//   h_c1   — LocalHandle in dom's memory-capability table (used by send).
//   sub_c1 — SubHandle in root_mem's children tree (used by revoke).
//
// Loom explores both orderings:
//
//  A-first (send wins):
//    c1.owner → recv_id, h_c1 removed from dom.
//    B's revoke finds c1 via sub_c1; c1.owner=recv_id ≠ root_mem.owner=dom_id
//    → skip_unmap=false → Unmap(recv_id) + Map(dom_id).
//    Applied: [Map(recv_id, 0x0, 0x1000),
//              Unmap(recv_id, 0x0, 0x1000), Map(dom_id, 0x0, 0x1000)].
//    Map(recv_id) precedes Unmap(recv_id) in the log (A's batch before B's).
//    Unmap and its companion Map are consecutive (B's batch is atomic).
//
//  B-first (revoke wins):
//    c1.owner=dom_id == root_mem.owner=dom_id → skip_unmap=true → empty batch.
//    h_c1 removed from dom's memory table by the revoke.
//    A's send finds no h_c1 in dom → NotFound.
//    Applied: [].
//
//  Thread B (revoke by sub_handle) succeeds in every ordering because
//  sub_c1 is a tree-level address independent of dom's local handle table.
#[test]
fn loom_e2e_send_vs_revoke_same_cap() {
    loom::model(|| {
        let (op_lock, ul, state) = new_exec_state();
        let (dom, h_root, _root_mem) = make_root(0x2000);
        let dom_id = dom.read().data.id;

        // Carve c1; keep both the LocalHandle and the SubHandle.
        let (h_c1, sub_c1, _) = Capability::<Domain>::carve(
            &NullPlatform, &dom,
            h_root,
            Access::new(0x0000, 0x1000, Rights::RW),
        )
        .expect("setup: carve c1");

        // Unsealed child domain as receiver for Thread A's immediate send.
        let dh_recv = Capability::<Domain>::create(&NullPlatform, &dom, DomainPolicy::new_root(1))
            .expect("setup: create recv").0;
        let recv = {
            let r = dom.read();
            r.data.get_domain_capability(dh_recv).unwrap().upgrade().unwrap()
        };
        let recv_id = recv.read().data.id;

        // Thread A (shared): send h_c1 to recv.
        let (opl, ul_a, st, d) = (op_lock.clone(), ul.clone(), state.clone(), dom.clone());
        let ta = thread::spawn(move || {
            execute_shared(&opl, &ul_a, &st, || {
                let batch = Capability::<Domain>::send(&NullPlatform, &d, h_c1, dh_recv, Attributes::NONE)?;
                Ok(((), batch))
            })
        });

        // Thread B (exclusive): revoke c1 by sub_handle — always succeeds.
        let (opl, ul_b, st, d) = (op_lock.clone(), ul.clone(), state.clone(), dom.clone());
        let tb = thread::spawn(move || {
            execute_exclusive(&opl, &ul_b, &st, || {
                let batch = Capability::<Domain>::revoke(&NullPlatform, &d, h_root, sub_c1)?;
                Ok(((), batch))
            })
        });

        let res_a = ta.join().unwrap();
        tb.join()
            .unwrap()
            .expect("B: revoke must always succeed");

        let applied = state.lock().unwrap().applied.clone();

        match res_a {
            Ok(()) => {
                // A-first: send succeeded; B then revoked c1 from recv.
                // Four updates: Unmap(dom_id) + Map(recv_id) from send,
                // Unmap(recv_id) + Map(dom_id) from revoke.
                assert_eq!(applied.len(), 4, "A-first: 4 updates");
                assert!(
                    applied.iter().any(|u| matches!(
                        u, Update::ChangeRights { domain, address: 0x0000, size: 0x1000, rights, .. }
                        if *domain == dom_id && *rights == Rights::NONE
                    )),
                    "A-first: Unmap(dom_id) from send"
                );
                assert!(
                    applied.iter().any(|u| matches!(
                        u, Update::ChangeRights { domain, address: 0x0000, size: 0x1000, shootdown_required: false, .. }
                        if *domain == recv_id
                    )),
                    "A-first: Map(recv_id) from send"
                );
                assert!(
                    applied.iter().any(|u| matches!(
                        u, Update::ChangeRights { domain, address: 0x0000, size: 0x1000, rights, .. }
                        if *domain == recv_id && *rights == Rights::NONE
                    )),
                    "A-first: Unmap(recv_id) from revoke"
                );
                assert!(
                    applied.iter().any(|u| matches!(
                        u, Update::ChangeRights { domain, address: 0x0000, size: 0x1000, shootdown_required: false, .. }
                        if *domain == dom_id
                    )),
                    "A-first: Map(dom_id) reclaim from revoke"
                );

                // A's Map(recv_id) must come before B's Unmap(recv_id).
                let map_recv_pos = applied
                    .iter()
                    .position(|u| {
                        matches!(
                            u, Update::ChangeRights { domain, shootdown_required: false, .. } if *domain == recv_id
                        )
                    })
                    .unwrap();
                let unmap_pos = applied
                    .iter()
                    .position(|u| {
                        matches!(
                            u, Update::ChangeRights { domain, rights, .. } if *domain == recv_id && *rights == Rights::NONE
                        )
                    })
                    .unwrap();
                assert!(
                    map_recv_pos < unmap_pos,
                    "A-first: Map(recv) precedes Unmap(recv)"
                );

                // B's Unmap and Map(dom_id) must be consecutive (atomic batch).
                let map_dom_pos = applied
                    .iter()
                    .position(|u| {
                        matches!(
                            u, Update::ChangeRights { domain, address: 0x0000, shootdown_required: false, .. } if *domain == dom_id
                        )
                    })
                    .unwrap();
                assert_eq!(
                    map_dom_pos,
                    unmap_pos + 1,
                    "A-first: Unmap and reclaim Map must be consecutive"
                );

                // revoke_subtree now eagerly removes the capability from the
                // receiver's tracking table via remove_memory_capability_by_ref.
                assert_eq!(
                    recv.read().data.memory_capability_handles().len(),
                    0,
                    "A-first: revoke cleans up recv's table"
                );
            }
            Err(e) => {
                // B-first: revoke ran first (same-owner → empty batch);
                // dom's memory table still has h_c1 but the Weak is dead (c1
                // deallocated when revoke_child dropped its Arc); send gets NotFound.
                assert_eq!(e, CapaError::NotFound, "B-first: send must get NotFound");
                assert_eq!(applied.len(), 0, "B-first: no hardware updates");
                // recv was never sent to; its table is empty.
                assert_eq!(
                    recv.read().data.memory_capability_handles().len(),
                    0,
                    "B-first: recv never received anything"
                );
            }
        }
    });
}

// ═════════════════════════════════════════════════════════════════════════════
// E8 — Two cores both try to revoke the same memory child (exclusive vs exclusive)
// ═════════════════════════════════════════════════════════════════════════════
//
// | Thread A (exclusive cap lock)                           | Thread B (exclusive cap lock)                           |
// |---------------------------------------------------------|---------------------------------------------------------|
// | execute_exclusive → revoke(h_root, sub_c1) | execute_exclusive → revoke(h_root, sub_c1) |
//
// Both cores hold references to the same domain and race to revoke the
// same child node (same sub_c1).  The exclusive lock serialises them;
// loom explores A-first and B-first.
//
// Since c1.owner == dom_id == root_mem.owner (c1 has never been sent),
// skip_unmap=true in both cases → the winner's batch is empty.  The
// update_lock is never acquired.
//
// Valid outcomes (all schedules):
//  - Winner: revoke succeeds, batch = [].
//  - Loser:  revoke returns NotFound (sub_c1 already gone).
//  - Applied updates: [] in every ordering.
//  - h_c1 is absent from dom's memory table after both threads complete.
#[test]
fn loom_e2e_two_cores_double_revoke_same_child() {
    loom::model(|| {
        let (op_lock, ul, state) = new_exec_state();
        let (dom, h_root, _root_mem) = make_root(0x2000);

        // Carve c1 — both threads will race to revoke it.
        let (_h_c1, sub_c1, _) = Capability::<Domain>::carve(
            &NullPlatform, &dom,
            h_root,
            Access::new(0x0000, 0x1000, Rights::RW),
        )
        .expect("setup: carve c1");

        // Thread A (exclusive): revoke c1 by sub_handle.
        let (opl, ul_a, st, d) = (op_lock.clone(), ul.clone(), state.clone(), dom.clone());
        let ta = thread::spawn(move || {
            execute_exclusive(&opl, &ul_a, &st, || {
                let batch = Capability::<Domain>::revoke(&NullPlatform, &d, h_root, sub_c1)?;
                Ok(((), batch))
            })
        });

        // Thread B (exclusive): also revoke c1 by the same sub_handle.
        let (opl, ul_b, st, d) = (op_lock.clone(), ul.clone(), state.clone(), dom.clone());
        let tb = thread::spawn(move || {
            execute_exclusive(&opl, &ul_b, &st, || {
                let batch = Capability::<Domain>::revoke(&NullPlatform, &d, h_root, sub_c1)?;
                Ok(((), batch))
            })
        });

        let res_a = ta.join().unwrap();
        let res_b = tb.join().unwrap();

        // Exactly one revoke must succeed.
        let successes = [res_a.is_ok(), res_b.is_ok()]
            .iter()
            .filter(|&&x| x)
            .count();
        assert_eq!(successes, 1, "exactly one revoke must succeed");

        // Loser gets NotFound — c1 already removed from the tree.
        let loser = if res_a.is_err() { &res_a } else { &res_b };
        assert_eq!(*loser.as_ref().unwrap_err(), CapaError::NotFound);

        // Both orderings: same-owner revoke → skip_unmap=true → empty batch.
        // The update_lock is never contended; applied log stays empty.
        let applied = state.lock().unwrap().applied.clone();
        assert_eq!(
            applied.len(),
            0,
            "no hardware updates for same-owner revoke"
        );
    });
}

// ═════════════════════════════════════════════════════════════════════════════
// E9 — Revoke a child domain that owns memory (exclusive) races against a
//      concurrent send of a different cap (shared)
// ═════════════════════════════════════════════════════════════════════════════
//
// | Thread A (exclusive cap lock)                    | Thread B (shared cap lock)                    |
// |--------------------------------------------------|-----------------------------------------------|
// | execute_exclusive → revoke_domain(dom, h_child)  | execute_shared → send(dom, h_c2, dh_r)       |
//
// Setup:
//   1. dom (sealed root) with root_mem [0x0, 0x4000) at h_root.
//   2. Carve c1 [0x0, 0x1000) RW from root_mem; send to ch1 (unsealed child).
//   3. Carve c2 [0x2000, 0x1000) RW from root_mem for Thread B.
//   4. Create unsealed receiver recv for Thread B.
//
// Thread A (exclusive): revoke_domain(dom, h_child).
//   revoke_domain_subtree revokes ch1 (marked revoked first) then its memory:
//     RevokeDomain(ch1_id)                           — emitted at the top
//     ChangeRights(dom_id, 0x0, 0x1000, restore)    — restore c1 to dom
//   No Unmap(ch1_id): RevokeDomain is emitted first and frees the EPT;
//   a subsequent unmap would touch an already-torn-down domain.
//
// Thread B (shared): send(dom, h_c2, dh_r, NONE).
//   Immediate send (unsealed recv).
//     ChangeRights(dom_id, 0x2000, 0x1000, NONE)    — unmap c2 from dom
//     ChangeRights(recv_id, 0x2000, 0x1000, map)     — map c2 to recv
//
// Both orderings produce the same 4 updates (different order).
#[test]
fn loom_e2e_domain_revoke_with_memory_vs_send() {
    loom::model(|| {
        let (op_lock, ul, state) = new_exec_state();
        let (dom, h_root, _root_mem) = make_root(0x4000);
        let dom_id = dom.read().data.id;

        // Carve c1 [0x0, 0x1000) and send to ch1 (so ch1 owns memory).
        let (h_c1, _sub1, _) = Capability::<Domain>::carve(
            &NullPlatform, &dom,
            h_root,
            Access::new(0x0000, 0x1000, Rights::RW),
        )
        .expect("setup: carve c1");

        let h_child = Capability::<Domain>::create(&NullPlatform, &dom, DomainPolicy::new_root(1))
            .expect("setup: create ch1").0;
        let ch1_id: DomainId = dom
            .read()
            .data
            .get_domain_capability(h_child)
            .unwrap()
            .upgrade()
            .unwrap()
            .read()
            .data
            .id;

        // Send c1 to ch1 — immediate transfer (ch1 is unsealed).
        Capability::<Domain>::send(&NullPlatform, &dom, h_c1, h_child, Attributes::NONE)
            .expect("setup: send c1 to ch1");

        // Carve c2 [0x2000, 0x1000) for Thread B to send.
        let (h_c2, _sub2, _) = Capability::<Domain>::carve(
            &NullPlatform, &dom,
            h_root,
            Access::new(0x2000, 0x1000, Rights::RW),
        )
        .expect("setup: carve c2");

        // Create unsealed receiver for Thread B.
        let dh_r = Capability::<Domain>::create(&NullPlatform, &dom, DomainPolicy::new_root(1))
            .expect("setup: create recv").0;
        let recv_id: DomainId = dom
            .read()
            .data
            .get_domain_capability(dh_r)
            .unwrap()
            .upgrade()
            .unwrap()
            .read()
            .data
            .id;

        // Thread A (exclusive): revoke child domain that owns memory.
        let (opl, ul_a, st, d) = (op_lock.clone(), ul.clone(), state.clone(), dom.clone());
        let ta = thread::spawn(move || {
            execute_exclusive(&opl, &ul_a, &st, || {
                let batch = Capability::<Domain>::revoke_domain(&NullPlatform, &d, h_child)?;
                Ok(((), batch))
            })
        });

        // Thread B (shared): send c2 to recv.
        let (opl, ul_b, st, d) = (op_lock.clone(), ul.clone(), state.clone(), dom.clone());
        let tb = thread::spawn(move || {
            execute_shared(&opl, &ul_b, &st, || {
                let batch = Capability::<Domain>::send(&NullPlatform, &d, h_c2, dh_r, Attributes::NONE)?;
                Ok(((), batch))
            })
        });

        ta.join().unwrap().expect("A: revoke_domain must succeed");
        tb.join().unwrap().expect("B: send c2 must succeed");

        let applied = state.lock().unwrap().applied.clone();

        // A: 2 updates (restore dom + RevokeDomain; no unmap ch1 — EPT freed by RevokeDomain)
        // B: ≥2 updates (at least unmap dom + map recv from view diffs)
        assert!(applied.len() >= 4, "at least 4 updates, got {}", applied.len());

        // A: memory restored to dom
        let has_restore = applied.iter().any(|u| {
            matches!(
                u, Update::ChangeRights { domain, address: 0x0000, size: 0x1000, shootdown_required: false, .. }
                if *domain == dom_id
            )
        });
        assert!(has_restore, "ChangeRights restoring c1 to dom must be present");

        // A: RevokeDomain
        let has_revoke = applied.iter().any(|u| {
            matches!(
                u, Update::RevokeDomain { domain, .. } if *domain == ch1_id
            )
        });
        assert!(has_revoke, "RevokeDomain(ch1_id) must be present");

        // B: map c2 to recv
        let has_map_recv = applied.iter().any(|u| {
            matches!(
                u, Update::ChangeRights { domain, address: 0x2000, size: 0x1000, shootdown_required: false, .. }
                if *domain == recv_id
            )
        });
        assert!(has_map_recv, "Map(recv_id) from send must be present");

        // B: unmap c2 from dom
        let has_unmap_c2 = applied.iter().any(|u| {
            matches!(
                u, Update::ChangeRights { domain, address: 0x2000, size: 0x1000, rights, .. }
                if *domain == dom_id && *rights == Rights::NONE
            )
        });
        assert!(has_unmap_c2, "Unmap(dom_id, c2 range) from send must be present");

        // dom's domain table must not contain h_child.
        assert!(dom.read().data.get_domain_capability(h_child).is_none());
    });
}
