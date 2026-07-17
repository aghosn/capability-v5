//! Loom tests for VP-aware domain switching (`Capability::switch`).
//!
//! Tests the key invariant: **atomic VP claim** — only one core can transition
//! a VP from `Available → Running` at a time, regardless of schedule.
//!
//! # Design
//!
//! `switch` operates on per-VP `crate::sync::RwLock<VpRunState>` objects.
//! Under `--features loom` these become `loom::sync::RwLock`, so loom explores
//! every valid interleaving of the write-lock acquisitions that guard state
//! transitions.
//!
//! The tests do NOT go through `execute()` (which adds the platform op-lock
//! layer); they call `switch` directly, matching real usage where the
//! caller already holds the appropriate lock.  The `LoomPlatform` below provides
//! a minimal `Platform` implementation backed by `loom::sync` primitives.
//!
//! # Tests
//!
//! V1. `vp_race_two_cores_same_vp`           — two cores race to claim VP[0] of a
//!                                             target domain; exactly one wins.
//! V2. `vp_two_cores_different_vps`          — two cores claim VP[0] and VP[1] of
//!                                             the same target; both must win.
//! V3. `vp_concurrent_return_and_claim`      — core 0 returns from domain B while
//!                                             core 1 tries to claim B's VP; VP state
//!                                             is verified consistent in all orderings.
//! V4. `vp_interrupt_delivery_vs_claim_race` — core 0 delivers an interrupt (setting
//!                                             dom2.vp0 Running→Interrupted) while
//!                                             core 1 tries to claim dom2.vp0; the
//!                                             claim must always fail regardless of
//!                                             scheduling order.
//! V5. `vp_two_cores_race_suspended_vp`      — two cores concurrently try to claim
//!                                             the same Suspended VP; exactly one wins
//!                                             and the Interrupted callee is freed
//!                                             exactly once.
//!
//! # Running
//!
//! ```sh
//! cargo test --test loom_vp_switch --features loom --release
//! ```

#![allow(dead_code)]

use loom::sync::{Arc, Mutex};
use loom::thread;

use std::collections::BTreeMap;

use capability_engine::{
    Capability, CapabilityRef, CoreId, Domain, DomainId, DomainPolicy, LocalHandle, MonitorAPI,
    OpLockGuard, Platform, Result, Update, VpCallContext, VpRunState,
};

// ═════════════════════════════════════════════════════════════════════════════
// Minimal loom platform
// ═════════════════════════════════════════════════════════════════════════════

/// Shared mutable state tracked under a loom Mutex.
#[derive(Default)]
struct LoomPlatformState {
    core_to_domain: BTreeMap<CoreId, DomainId>,
    core_to_vp: BTreeMap<CoreId, u64>,
}

/// Per-core platform instance.  Each "core" (thread) creates its own
/// `LoomPlatform` with a fixed `current_core`, but shares the same
/// `Arc<Mutex<LoomPlatformState>>` with other cores.
struct LoomPlatform {
    current_core: CoreId,
    state: Arc<Mutex<LoomPlatformState>>,
}

impl LoomPlatform {
    fn new(current_core: CoreId, state: Arc<Mutex<LoomPlatformState>>) -> Self {
        LoomPlatform {
            current_core,
            state,
        }
    }
}

// VP tests call switch directly (not via execute()), so the op-lock
// methods are never invoked.  A dummy guard satisfies the trait bound.
struct DummyGuard;
impl OpLockGuard for DummyGuard {}
unsafe impl Send for DummyGuard {}

// Safety: LoomPlatform only contains CoreId (Copy) and Arc<Mutex<...>> which
// is Send + Sync, so LoomPlatform is Send + Sync.
unsafe impl Send for LoomPlatform {}
unsafe impl Sync for LoomPlatform {}

// ─────────────────────────────────────────────────────────────────────────────
// NullPlatform — no-op Platform for sequential setup calls.
// ─────────────────────────────────────────────────────────────────────────────

struct NullPlatform;
unsafe impl Send for NullPlatform {}
unsafe impl Sync for NullPlatform {}

impl Platform for NullPlatform {
    fn acquire_shared_lock(&self) -> Result<Box<dyn OpLockGuard>> {
        Ok(Box::new(DummyGuard))
    }
    fn acquire_exclusive_lock(&self) -> Result<Box<dyn OpLockGuard>> {
        Ok(Box::new(DummyGuard))
    }
    fn send_ipi(&self, _: CoreId) {}
    fn sync_barrier(&self, _: u8, _: usize) {}
    fn apply_update(&self, _: &Update) {}
    fn on_domain_revoked(&self, _: DomainId, _: Option<DomainId>) {}
    fn register_domain(&self, _: DomainId, _: Option<DomainId>) {}
    fn set_core_context(&self, _: CoreId, _: &CapabilityRef<Domain>, _: u64) {}
    fn clear_core_domain(&self, _: CoreId) {}
    fn domain_cores(&self, _: DomainId) -> Vec<CoreId> { Vec::new() }
    fn try_acquire_update_lock(&self) -> bool { true }
    fn release_update_lock(&self) {}
    fn get_current_core(&self) -> Option<CoreId> { None }
}


impl Platform for LoomPlatform {
    fn acquire_shared_lock(&self) -> Result<Box<dyn OpLockGuard>> {
        Ok(Box::new(DummyGuard))
    }
    fn acquire_exclusive_lock(&self) -> Result<Box<dyn OpLockGuard>> {
        Ok(Box::new(DummyGuard))
    }
    fn send_ipi(&self, _: CoreId) {}
    fn sync_barrier(&self, _: u8, _: usize) {}
    fn apply_update(&self, _: &Update) {}
    fn on_domain_revoked(&self, _: DomainId, _: Option<DomainId>) {}
    fn register_domain(&self, _: DomainId, _: Option<DomainId>) {}

    fn set_core_context(&self, core_id: CoreId, domain_cap: &CapabilityRef<Domain>, vp_id: u64) {
        let domain_id = domain_cap.read().data.id;
        let mut st = self.state.lock().unwrap();
        st.core_to_domain.insert(core_id, domain_id);
        st.core_to_vp.insert(core_id, vp_id);
    }
    fn clear_core_domain(&self, core_id: CoreId) {
        self.state.lock().unwrap().core_to_domain.remove(&core_id);
    }
    fn domain_cores(&self, domain_id: DomainId) -> Vec<CoreId> {
        let st = self.state.lock().unwrap();
        st.core_to_domain
            .iter()
            .filter(|(_, &did)| did == domain_id)
            .map(|(&cid, _)| cid)
            .collect()
    }
    fn try_acquire_update_lock(&self) -> bool {
        true
    }
    fn release_update_lock(&self) {}
    fn get_current_core(&self) -> Option<CoreId> {
        Some(self.current_core)
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Test helpers
// ═════════════════════════════════════════════════════════════════════════════

/// Forcibly set VP[`vp_id`] of `domain` to `Running { core, caller: None }`.
/// Call this BEFORE spawning loom threads (sequential setup only).
fn init_vp_running(domain: &CapabilityRef<Domain>, vp_id: usize, core: u64) {
    let d = domain.read();
    let vp = d.data.policy.vprocessor_states[vp_id].clone();
    drop(d);
    *vp.run_state.write() = VpRunState::Running { core, caller: None };
}

/// Create a sealed child domain under `parent` and return `(child_ref, handle)`.
/// Child has all-core access and full API (including SWITCH).
fn make_sealed_child(parent: &CapabilityRef<Domain>) -> (CapabilityRef<Domain>, LocalHandle) {
    let policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::ALL);
    let num_vps = policy.num_vprocessors;
    let h = Capability::create(&NullPlatform, parent, policy).unwrap().0;
    let child = parent.read().data.domain_capabilities[&h]
        .upgrade()
        .unwrap();
    for _ in 0..num_vps as u64 {
        child.write().data.add_vprocessor().unwrap();
    }
    Capability::seal(&NullPlatform, parent, h).unwrap();
    (child, h)
}

// ═════════════════════════════════════════════════════════════════════════════
// V1 — Two cores race for the same VP
// ═════════════════════════════════════════════════════════════════════════════

/// Two cores concurrently call `switch` targeting VP[0] of the same
/// domain.  Exactly one should succeed (`Available → Running`); the other
/// should fail ("target VP is not available").
#[test]
fn vp_race_two_cores_same_vp() {
    loom::model(|| {
        // ── Setup (sequential) ──────────────────────────────────────────────
        let root = Capability::new_root(0, 0, Domain::new_root(4));
        let (target, target_h) = make_sealed_child(&root);

        // VP[0] and VP[1] of root are Running on cores 0 and 1 respectively.
        init_vp_running(&root, 0, 0);
        init_vp_running(&root, 1, 1);
        // target has 4 VPs, all Available.

        // ── Shared platform state ───────────────────────────────────────────
        let shared = Arc::new(Mutex::new(LoomPlatformState::default()));

        // Clone Arcs for each thread.
        let root_t0 = root.clone();
        let root_t1 = root.clone();
        let target_t0 = target.clone();
        let state_t0 = shared.clone();
        let state_t1 = shared.clone();

        // ── Threads ─────────────────────────────────────────────────────────
        let t0 = thread::spawn(move || {
            let _target = target_t0; // keep alive
            let plat = LoomPlatform::new(0, state_t0);
            // Core 0 claims target VP[0].
            Capability::switch(&plat, &root_t0, target_h, 0)
        });

        let t1 = thread::spawn(move || {
            let plat = LoomPlatform::new(1, state_t1);
            // Core 1 also tries to claim target VP[0].
            Capability::switch(&plat, &root_t1, target_h, 0)
        });

        let r0 = t0.join().unwrap();
        let r1 = t1.join().unwrap();

        // ── Invariant: exactly one core won the VP ──────────────────────────
        assert!(
            r0.is_ok() ^ r1.is_ok(),
            "exactly one core should claim the VP, got r0={} r1={}",
            r0.is_ok(),
            r1.is_ok()
        );

        // Target VP[0] must be in Running state.
        let vp0_state = {
            let t = target.read();
            let vp = t.data.policy.vprocessor_states[0].clone();
            drop(t);
            let guard = vp.run_state.read();
            matches!(*guard, VpRunState::Running { .. })
        };
        assert!(vp0_state, "target VP[0] must be Running after one winner");
    });
}

// ═════════════════════════════════════════════════════════════════════════════
// V2 — Two cores claim different VPs (no conflict)
// ═════════════════════════════════════════════════════════════════════════════

/// Two cores concurrently claim VP[0] and VP[1] of the same target domain.
/// Since the VPs are distinct, both operations must succeed regardless of
/// scheduling order.
#[test]
fn vp_two_cores_different_vps() {
    loom::model(|| {
        // ── Setup ───────────────────────────────────────────────────────────
        let root = Capability::new_root(0, 0, Domain::new_root(4));
        let (target, target_h) = make_sealed_child(&root);

        init_vp_running(&root, 0, 0); // core 0 runs root VP[0]
        init_vp_running(&root, 1, 1); // core 1 runs root VP[1]
                                      // target VP[0] and VP[1] start Available.

        let shared = Arc::new(Mutex::new(LoomPlatformState::default()));

        let root_t0 = root.clone();
        let root_t1 = root.clone();
        let target_t0 = target.clone();
        let state_t0 = shared.clone();
        let state_t1 = shared.clone();

        // ── Threads ─────────────────────────────────────────────────────────
        let t0 = thread::spawn(move || {
            let _target = target_t0;
            let plat = LoomPlatform::new(0, state_t0);
            // Core 0 claims VP[0].
            Capability::switch(&plat, &root_t0, target_h, 0)
        });

        let t1 = thread::spawn(move || {
            let plat = LoomPlatform::new(1, state_t1);
            // Core 1 claims VP[1].
            Capability::switch(&plat, &root_t1, target_h, 1)
        });

        let r0 = t0.join().unwrap();
        let r1 = t1.join().unwrap();

        // ── Invariant: both cores succeed (non-conflicting VPs) ─────────────
        assert!(r0.is_ok(), "core 0 should claim VP[0]: {:?}", r0.err());
        assert!(r1.is_ok(), "core 1 should claim VP[1]: {:?}", r1.err());

        // Both VPs must be Running.
        let t = target.read();
        let vp0_arc = t.data.policy.vprocessor_states[0].clone();
        let vp1_arc = t.data.policy.vprocessor_states[1].clone();
        drop(t);
        let vp0_running = {
            let g = vp0_arc.run_state.read();
            matches!(*g, VpRunState::Running { core: 0, .. })
        };
        let vp1_running = {
            let g = vp1_arc.run_state.read();
            matches!(*g, VpRunState::Running { core: 1, .. })
        };
        assert!(vp0_running, "target VP[0] must be Running on core 0");
        assert!(vp1_running, "target VP[1] must be Running on core 1");
    });
}

// ═════════════════════════════════════════════════════════════════════════════
// V3 — Concurrent return and claim attempt
// ═════════════════════════════════════════════════════════════════════════════

/// Pre-state: core 0 is inside domain B (B.VP[0] Running, caller = root.VP[0]).
/// Core 1 is inside domain root (root.VP[1] Running).
///
/// Concurrently:
/// * Thread 0 (core 0): returns from B to root (switch(&B, 0, 0, &plat0)).
/// * Thread 1 (core 1): tries to switch from root into B, claiming B.VP[0]
///                      (switch(&root, B_h, 0, &plat1)).
///
/// Two valid orderings under loom:
///
/// * **Thread 0 first**: B.VP[0] → Available, root.VP[0] → Running.
///   Thread 1 then claims B.VP[0] → Running{core:1}.  Both succeed.
///
/// * **Thread 1 first** (or interleaved before Thread 0 frees VP):
///   Thread 1 sees B.VP[0] = Running → fails.  Thread 0 returns.
///
/// Invariant: Thread 0 always succeeds; VP state is consistent afterwards.
#[test]
fn vp_concurrent_return_and_claim() {
    loom::model(|| {
        // ── Setup (sequential) ──────────────────────────────────────────────
        let root = Capability::new_root(0, 0, Domain::new_root(4));

        // Build domain B as a sealed child of root.
        let (b_domain, b_h) = make_sealed_child(&root);

        // root VP[0] is "Locked" (it called into B).
        // root VP[1] is Running on core 1.
        // B.VP[0] is Running on core 0, with root.VP[0] as its caller.
        {
            let rd = root.read();
            let vp0 = rd.data.policy.vprocessor_states[0].clone();
            let vp1 = rd.data.policy.vprocessor_states[1].clone();
            drop(rd);

            // root.VP[0]: Locked (waiting for B.VP[0] to return)
            *vp0.run_state.write() = VpRunState::Locked {
                callee_domain_id: b_domain.read().data.id,
                callee_vp_id: 0,
                prev_caller: None,
            };
            // root.VP[1]: Running on core 1
            *vp1.run_state.write() = VpRunState::Running {
                core: 1,
                caller: None,
            };
        }
        {
            let bd = b_domain.read();
            let bvp0 = bd.data.policy.vprocessor_states[0].clone();
            drop(bd);

            let root_id = root.read().data.id;
            let root_vp0_weak = std::sync::Arc::downgrade(&root);

            *bvp0.run_state.write() = VpRunState::Running {
                core: 0,
                caller: Some(VpCallContext {
                    domain: root_vp0_weak,
                    domain_id: root_id,
                    vp_id: 0,
                }),
            };
        }

        let shared = Arc::new(Mutex::new(LoomPlatformState::default()));

        let root_t1 = root.clone();
        let b_t0 = b_domain.clone();
        let state_t0 = shared.clone();
        let state_t1 = shared.clone();

        // ── Threads ─────────────────────────────────────────────────────────

        // Thread 0 (core 0): return from B → root.
        let t0 = thread::spawn(move || {
            let plat = LoomPlatform::new(0, state_t0);
            Capability::switch(&plat, &b_t0, 0, 0)
        });

        // Thread 1 (core 1): try to switch from root → B, claiming VP[0].
        let t1 = thread::spawn(move || {
            let plat = LoomPlatform::new(1, state_t1);
            Capability::switch(&plat, &root_t1, b_h, 0)
        });

        let r0 = t0.join().unwrap();
        let r1 = t1.join().unwrap();

        // ── Invariants ──────────────────────────────────────────────────────

        // Thread 0 (return) must always succeed: root VP[0] was Locked waiting
        // for B.VP[0], and B.VP[0] was Running on core 0.
        assert!(r0.is_ok(), "return from B must succeed: {:?}", r0.err());

        // Thread 1 outcome depends on scheduling:
        // * If Thread 0 freed B.VP[0] first → Thread 1 claims it → Ok.
        // * If Thread 1 saw B.VP[0] Running → Err.
        // Both are valid; we only assert VP state consistency.
        let b_vp0_state_is_running = {
            let bd = b_domain.read();
            let vp = bd.data.policy.vprocessor_states[0].clone();
            drop(bd);
            let g = vp.run_state.read();
            matches!(*g, VpRunState::Running { .. })
        };
        let root_vp0_state_is_running = {
            let rd = root.read();
            let vp = rd.data.policy.vprocessor_states[0].clone();
            drop(rd);
            let g = vp.run_state.read();
            matches!(*g, VpRunState::Running { .. })
        };

        if r1.is_ok() {
            // Thread 1 claimed B.VP[0] after Thread 0 freed it.
            // B.VP[0] must be Running (claimed by core 1).
            assert!(
                b_vp0_state_is_running,
                "B.VP[0] must be Running (Thread 1 claimed it)"
            );
            // root.VP[0] must be Running (Thread 0 restored it).
            assert!(
                root_vp0_state_is_running,
                "root.VP[0] must be Running (Thread 0 returned)"
            );
        } else {
            // Thread 1 failed — B.VP[0] must be Available (Thread 0 freed it).
            assert!(
                !b_vp0_state_is_running,
                "B.VP[0] must be Available (Thread 0 returned, Thread 1 failed)"
            );
            assert!(
                root_vp0_state_is_running,
                "root.VP[0] must be Running (Thread 0 returned)"
            );
        }
    });
}

// ═════════════════════════════════════════════════════════════════════════════
// V4 — Interrupted VP cannot be claimed during or after interrupt delivery
// ═════════════════════════════════════════════════════════════════════════════

/// Pre-state: 3-domain call chain on core 0.
///   dom0.vp0 (Locked) → dom1.vp0 (Locked) → dom2.vp0 (Running on core 0)
/// dom1.vp1 is Running on core 1.
///
/// Concurrently:
/// * Thread 0 (core 0): `deliver_interrupt_vp(&dom2, dom0_id, 0)` —
///                       sets dom2.vp0 Running→Interrupted, dom1.vp0 Locked→Suspended,
///                       dom0.vp0 Locked→Running.
/// * Thread 1 (core 1): `switch(&dom1, dom2_h, 0)` —
///                       dom1.vp1 tries to forward-switch to dom2.vp0.
///
/// Invariants in **all** loom-explored orderings:
/// * Thread 0 always succeeds — the chain is well-formed throughout.
/// * Thread 1 always fails — dom2.vp0 is either `Running` or `Interrupted`,
///   never `Available` or `Suspended`, so the forward-switch rejects it.
///
/// This is the key safety property of the lazy-unwind interrupt model:
/// the interrupted VP cannot be stolen by any concurrent claim, regardless
/// of how `deliver_interrupt_vp` and `switch` interleave.
#[test]
fn vp_interrupt_delivery_vs_claim_race() {
    loom::model(|| {
        // ── Sequential setup ────────────────────────────────────────────────
        let shared = Arc::new(Mutex::new(LoomPlatformState::default()));
        let plat_setup = LoomPlatform::new(0, shared.clone());

        // dom0: root with 4 VPs — will be the DELIVER handler.
        let dom0 = Capability::new_root(0, 0, Domain::new_root(4));
        let dom0_id = dom0.read().data.id;

        // dom1: child of dom0 with 4 VPs — intermediate (REPORT) domain.
        let (dom1, dom1_h_in_dom0) = make_sealed_child(&dom0);

        // dom2: child of dom0 with 4 VPs — the domain running when interrupt fires.
        let (dom2, _) = make_sealed_child(&dom0);

        // Give dom1 a handle to dom2 so it can switch to dom2.
        let dom2_h_in_dom1: LocalHandle = {
            let dom2_weak = std::sync::Arc::downgrade(&dom2);
            let mut d1 = dom1.write();
            let h = d1.data.allocate_domain_handle();
            d1.data.add_domain_capability(h, dom2_weak);
            h
        };

        // Build call chain on core 0: dom0.vp0 → dom1.vp0 → dom2.vp0.
        //   dom0.vp0 = Running{core:0}
        init_vp_running(&dom0, 0, 0);
        //   dom0 switches to dom1.vp0 → dom0.vp0=Locked, dom1.vp0=Running{core:0}
        Capability::switch(&plat_setup, &dom0, dom1_h_in_dom0, 0).unwrap();
        //   dom1 switches to dom2.vp0 → dom1.vp0=Locked, dom2.vp0=Running{core:0}
        Capability::switch(&plat_setup, &dom1, dom2_h_in_dom1, 0).unwrap();

        // dom1.vp1 = Running on core 1: the "attacker" VP that will try to steal dom2.vp0.
        init_vp_running(&dom1, 1, 1);

        // ── Arcs for threads ─────────────────────────────────────────────────
        let dom2_t0 = dom2.clone();
        let dom1_t1 = dom1.clone();
        let state_t0 = shared.clone();
        let state_t1 = shared.clone();

        // ── Concurrent phase ─────────────────────────────────────────────────

        // Thread 0 (core 0): deliver interrupt — dom0 is the DELIVER handler.
        // Walks the VP chain: dom2.vp0→Interrupted, dom1.vp0→Suspended, dom0.vp0→Running.
        let t0 = thread::spawn(move || {
            let plat = LoomPlatform::new(0, state_t0);
            Capability::<Domain>::deliver_interrupt_vp(&plat, &dom2_t0, dom0_id, 0, 0)
        });

        // Thread 1 (core 1): dom1.vp1 tries to claim dom2.vp0 via forward switch.
        // dom2.vp0 is either Running (before Thread 0's write) or Interrupted
        // (after Thread 0's write) — neither is Available or Suspended — always fails.
        let t1 = thread::spawn(move || {
            let plat = LoomPlatform::new(1, state_t1);
            Capability::switch(&plat, &dom1_t1, dom2_h_in_dom1, 0)
        });

        let r0 = t0.join().unwrap();
        let r1 = t1.join().unwrap();

        // ── Invariants ───────────────────────────────────────────────────────

        // Interrupt delivery must always succeed.
        assert!(
            r0.is_ok(),
            "deliver_interrupt_vp must succeed in all orderings: {:?}",
            r0.err()
        );

        // The claim attempt must always fail — dom2.vp0 is never Available or Suspended.
        assert!(
            r1.is_err(),
            "switch to a Running/Interrupted VP must always fail"
        );
    });
}

// ═════════════════════════════════════════════════════════════════════════════
// V5 — Two cores race to claim the same Suspended VP
// ═════════════════════════════════════════════════════════════════════════════

/// Pre-state (after an interrupt has been delivered to a 3-domain chain):
///   dom0.vp0  Running  { core: 0 }   — handler VP; first to try to resume
///   dom0.vp1  Running  { core: 1 }   — second VP; also wants dom1.vp0
///   dom1.vp0  Suspended{ callee = dom2.vp0 }
///   dom2.vp0  Interrupted
///
/// Concurrently:
/// * Thread 0 (core 0, dom0.vp0): `switch(&dom0, dom1_h, 0)` — claim dom1.vp0.
/// * Thread 1 (core 1, dom0.vp1): `switch(&dom0, dom1_h, 0)` — same target.
///
/// Invariants in **all** loom-explored orderings:
/// * Exactly one core wins the write-lock on dom1.vp0's run_state.
/// * dom1.vp0 ends up `Running` (claimed by the winner).
/// * dom2.vp0 ends up `Available` — the winner's `Suspended → Running` path frees
///   the `Interrupted` callee exactly once (inside the same write-lock block, so the
///   loser never reaches the callee-freeing code).
/// * The losing thread returns an error.
#[test]
fn vp_two_cores_race_suspended_vp() {
    loom::model(|| {
        // ── Sequential setup ────────────────────────────────────────────────
        let dom0 = Capability::new_root(0, 0, Domain::new_root(4));
        let (dom1, dom1_h_in_dom0) = make_sealed_child(&dom0);
        let (dom2, _) = make_sealed_child(&dom0);
        let dom2_id = dom2.read().data.id;

        // dom0 has two Running VPs: one on core 0, one on core 1.
        init_vp_running(&dom0, 0, 0);
        init_vp_running(&dom0, 1, 1);

        // Manually construct the post-interrupt VP states (avoids depending on
        // deliver_interrupt_vp correctness, which is already covered by V4).
        {
            let dom2_weak = std::sync::Arc::downgrade(&dom2);
            let d = dom1.read();
            let vp0 = d.data.policy.vprocessor_states[0].clone();
            drop(d);
            *vp0.run_state.write() = VpRunState::Suspended {
                callee_domain: dom2_weak,
                callee_domain_id: dom2_id,
                callee_vp_id: 0,
                vector: 0,
            };
        }
        {
            let d = dom2.read();
            let vp0 = d.data.policy.vprocessor_states[0].clone();
            drop(d);
            *vp0.run_state.write() = VpRunState::Interrupted { vector: 0 };
        }

        // ── Arcs for threads ─────────────────────────────────────────────────
        let shared = Arc::new(Mutex::new(LoomPlatformState::default()));
        let dom0_t0 = dom0.clone();
        let dom0_t1 = dom0.clone();
        let state_t0 = shared.clone();
        let state_t1 = shared.clone();

        // ── Concurrent phase ─────────────────────────────────────────────────

        // Thread 0 (core 0, dom0.vp0): try to claim dom1.vp0.
        let t0 = thread::spawn(move || {
            let plat = LoomPlatform::new(0, state_t0);
            Capability::switch(&plat, &dom0_t0, dom1_h_in_dom0, 0)
        });

        // Thread 1 (core 1, dom0.vp1): same target.
        let t1 = thread::spawn(move || {
            let plat = LoomPlatform::new(1, state_t1);
            Capability::switch(&plat, &dom0_t1, dom1_h_in_dom0, 0)
        });

        let r0 = t0.join().unwrap();
        let r1 = t1.join().unwrap();

        // ── Invariants ───────────────────────────────────────────────────────

        // Exactly one core wins the Suspended → Running transition.
        assert!(
            r0.is_ok() ^ r1.is_ok(),
            "exactly one core should claim the Suspended VP: r0={} r1={}",
            r0.is_ok(),
            r1.is_ok()
        );

        // dom1.vp0 must be Running (held by the winner).
        {
            let d = dom1.read();
            let vp = d.data.policy.vprocessor_states[0].clone();
            drop(d);
            assert!(
                matches!(*vp.run_state.read(), VpRunState::Running { .. }),
                "dom1.vp0 must be Running after one winner"
            );
        }

        // dom2.vp0 must be Available — freed exactly once by the winner.
        // The loser never reaches the callee-free path because it sees Running and returns early.
        {
            let d = dom2.read();
            let vp = d.data.policy.vprocessor_states[0].clone();
            drop(d);
            assert!(
                matches!(*vp.run_state.read(), VpRunState::Available { .. }),
                "dom2.vp0 must be Available after its Suspended parent was claimed"
            );
        }
    });
}
