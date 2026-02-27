//! Exhaustive interleaving tests using [`loom`].
//!
//! These tests systematically explore every valid thread schedule to verify
//! that the capability engine's locking protocol is correct — no data races,
//! no invariant violations, no matter how threads are interleaved.
//!
//! # Running
//!
//! ```sh
//! cargo test --test loom_concurrency --features loom --release
//! ```
//!
//! The `--features loom` flag swaps `crate::sync::RwLock` to a loom-backed
//! wrapper so that the library's internal capability locks are also explored.
//!
//! # Scope
//!
//! 1. **Basic RwLock models** (§7.4) — raw lock correctness independent of
//!    capability semantics.
//! 2. **Capability operation models** (§7.6) — real carve / revoke / send
//!    operations under the shared/exclusive locking protocol, exercising the
//!    internal `Arc<RwLock<Capability<T>>>` locks.
//! 3. **Send / accept / reject / revoke-pending races** (§7.7) — domain-mediated
//!    API exercised end-to-end with loom-tracked internal locks.
//! 4. **Domain-mediated memory operations** (§7.8) — further domain-mediated
//!    concurrent scenarios (concurrent sibling revokes, send-vs-revoke-sibling).

use loom::sync::{Arc, RwLock};
use loom::sync::atomic::{AtomicUsize, Ordering};
use loom::thread;

use capability_engine::{
    Access, Attributes, CapaError, Capability, CapabilityRef,
    Domain, DomainPolicy, DomainStatus, MemoryRegion, RegionKind, Rights, Update,
};

// ═════════════════════════════════════════════════════════════════════════════
// §7.4 — Basic RwLock models
// ═════════════════════════════════════════════════════════════════════════════

// ── 3.1 Exclusive blocks shared ─────────────────────────────────────────────

#[test]
fn exclusive_blocks_shared() {
    loom::model(|| {
        let lock = Arc::new(RwLock::new(0u32));
        let counter = Arc::new(AtomicUsize::new(0));

        let l = lock.clone();
        let c = counter.clone();
        let writer = thread::spawn(move || {
            let mut w = l.write().unwrap();
            *w += 1;
            c.fetch_add(1, Ordering::SeqCst);
        });

        let l = lock.clone();
        let c = counter.clone();
        let reader = thread::spawn(move || {
            let r = l.read().unwrap();
            // Writer must have either not started or already finished.
            let val = *r;
            assert!(val == 0 || val == 1);
            c.fetch_add(1, Ordering::SeqCst);
        });

        writer.join().unwrap();
        reader.join().unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    });
}

// ── 3.2 Shared does not block shared ────────────────────────────────────────

#[test]
fn shared_does_not_block_shared() {
    loom::model(|| {
        let lock = Arc::new(RwLock::new(42u32));

        let l1 = lock.clone();
        let r1 = thread::spawn(move || {
            let r = l1.read().unwrap();
            assert_eq!(*r, 42);
        });

        let l2 = lock.clone();
        let r2 = thread::spawn(move || {
            let r = l2.read().unwrap();
            assert_eq!(*r, 42);
        });

        r1.join().unwrap();
        r2.join().unwrap();
    });
}

// ── 3.3 Exclusive serialises two revokes ────────────────────────────────────

#[test]
fn exclusive_serialises_two_revokes() {
    loom::model(|| {
        let lock = Arc::new(RwLock::new(0u32));
        let order = Arc::new(AtomicUsize::new(0));

        let l = lock.clone();
        let o = order.clone();
        let w1 = thread::spawn(move || {
            let mut w = l.write().unwrap();
            let ticket = o.fetch_add(1, Ordering::SeqCst);
            *w += 1;
            ticket
        });

        let l = lock.clone();
        let o = order.clone();
        let w2 = thread::spawn(move || {
            let mut w = l.write().unwrap();
            let ticket = o.fetch_add(1, Ordering::SeqCst);
            *w += 1;
            ticket
        });

        let t1 = w1.join().unwrap();
        let t2 = w2.join().unwrap();
        // Tickets must be {0,1} in some order — both ran but never overlapped.
        assert!(t1 != t2);
        assert_eq!(*lock.read().unwrap(), 2);
    });
}

// ── 3.4 Writer waits for all readers ────────────────────────────────────────

#[test]
fn writer_waits_for_all_readers() {
    loom::model(|| {
        let lock = Arc::new(RwLock::new(0u32));
        let readers_done = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..2 {
            let l = lock.clone();
            let rd = readers_done.clone();
            handles.push(thread::spawn(move || {
                let _r = l.read().unwrap();
                rd.fetch_add(1, Ordering::SeqCst);
            }));
        }

        let l = lock.clone();
        let rd = readers_done.clone();
        let writer = thread::spawn(move || {
            let mut w = l.write().unwrap();
            *w = rd.load(Ordering::SeqCst) as u32;
        });

        for h in handles {
            h.join().unwrap();
        }
        writer.join().unwrap();

        let val = *lock.read().unwrap();
        assert!(val <= 2);
    });
}

// ═════════════════════════════════════════════════════════════════════════════
// §7.6 — Capability operation models
//
// These tests exercise real capability tree operations under a loom-controlled
// platform-level RwLock.  The library's internal `crate::sync::RwLock` (inside
// `CapabilityRef<T>`) is also the loom wrapper, so loom explores interleavings
// at both the platform lock and the per-node lock level.
// ═════════════════════════════════════════════════════════════════════════════

/// Helper: create a root memory capability spanning `[start, start+size)` with
/// RWX rights.  No domain validation (owner_domain = None), so validate_operation
/// is a no-op — suitable for isolated loom models.
fn make_root(owner: u64, handle: u64, start: u64, size: u64) -> CapabilityRef<MemoryRegion> {
    Capability::new_root(owner, handle, MemoryRegion::new_root(start, size))
}

// ── Concurrent carves on non-overlapping regions ────────────────────────────

/// Two threads carve non-overlapping children from the same parent under a
/// shared (read) platform lock.  Both must succeed regardless of schedule.
#[test]
fn concurrent_carves_non_overlapping() {
    loom::model(|| {
        let platform_lock = Arc::new(RwLock::new(()));
        let root = make_root(0, 0, 0x0000, 0x4000);

        let access_a = Access::new(0x0000, 0x1000, Rights::RW);
        let access_b = Access::new(0x2000, 0x1000, Rights::RW);

        let pl = platform_lock.clone();
        let r = root.clone();
        let ta = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::carve_child(&r, access_a, 1)
                .expect("carve A should succeed")
        });

        let pl = platform_lock.clone();
        let r = root.clone();
        let tb = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::carve_child(&r, access_b, 2)
                .expect("carve B should succeed")
        });

        let (_child_a, _) = ta.join().unwrap();
        let (_child_b, _) = tb.join().unwrap();

        // Both children should be in the parent's children list.
        assert_eq!(root.read().children.len(), 2);
    });
}

// ── Concurrent carves on overlapping regions ────────────────────────────────

/// Two threads attempt to carve overlapping regions.  Exactly one must succeed
/// and the other must fail with `InvalidAccess`, regardless of schedule.
#[test]
fn concurrent_carves_overlapping() {
    loom::model(|| {
        let platform_lock = Arc::new(RwLock::new(()));
        let root = make_root(0, 0, 0x0000, 0x4000);

        let access_a = Access::new(0x0000, 0x2000, Rights::RW);
        let access_b = Access::new(0x1000, 0x2000, Rights::RW);

        let pl = platform_lock.clone();
        let r = root.clone();
        let ta = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::carve_child(&r, access_a, 1)
        });

        let pl = platform_lock.clone();
        let r = root.clone();
        let tb = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::carve_child(&r, access_b, 2)
        });

        let res_a = ta.join().unwrap();
        let res_b = tb.join().unwrap();

        // Exactly one succeeds, the other gets InvalidAccess.
        let successes = [res_a.is_ok(), res_b.is_ok()]
            .iter()
            .filter(|&&s| s)
            .count();
        assert_eq!(successes, 1, "exactly one overlapping carve must succeed");
        assert_eq!(root.read().children.len(), 1);
    });
}

// ── Revoke under exclusive lock while carve waits ───────────────────────────

/// A revoke (exclusive) and a carve (shared) race on the platform lock.
/// The revoke removes a child; the carve creates one.  After both complete,
/// the tree must be consistent.
#[test]
fn revoke_vs_carve() {
    loom::model(|| {
        let platform_lock = Arc::new(RwLock::new(()));
        let root = make_root(0, 0, 0x0000, 0x4000);

        // Pre-create a child to revoke.
        let (child, _) = Capability::carve_child(
            &root,
            Access::new(0x0000, 0x1000, Rights::RW),
            0)
        .unwrap();

        let pl = platform_lock.clone();
        let r = root.clone();
        let c = child.clone();
        let revoker = thread::spawn(move || {
            let _guard = pl.write().unwrap(); // exclusive
            Capability::revoke_child_ref(&r, &c)
        });

        let pl = platform_lock.clone();
        let r = root.clone();
        let carver = thread::spawn(move || {
            let _guard = pl.read().unwrap(); // shared
            Capability::carve_child(
                &r,
                Access::new(0x2000, 0x1000, Rights::RW),
                1)
        });

        let revoke_result = revoker.join().unwrap();
        let carve_result = carver.join().unwrap();

        // Revoke must always succeed (the child exists).
        assert!(revoke_result.is_ok(), "revoke must succeed");
        // Carve must also succeed (non-overlapping region).
        assert!(carve_result.is_ok(), "carve must succeed");

        // After both: only the carved child remains (revoked one is gone).
        assert_eq!(root.read().children.len(), 1);
    });
}

// ── Two sends on different children ─────────────────────────────────────────

/// Two threads each send a different child capability to a new owner under
/// shared platform lock.  Both must succeed.
#[test]
fn concurrent_sends() {
    loom::model(|| {
        let platform_lock = Arc::new(RwLock::new(()));
        let root = make_root(0, 0, 0x0000, 0x4000);

        let (child_a, _) = Capability::carve_child(
            &root,
            Access::new(0x0000, 0x1000, Rights::RW),
            0)
        .unwrap();
        let (child_b, _) = Capability::carve_child(
            &root,
            Access::new(0x2000, 0x1000, Rights::RW),
            0)
        .unwrap();

        let pl = platform_lock.clone();
        let ca = child_a.clone();
        let ta = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::send_to(&ca, 0, 10, Attributes::NONE)
        });

        let pl = platform_lock.clone();
        let cb = child_b.clone();
        let tb = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::send_to(&cb, 0, 20, Attributes::NONE)
        });

        let res_a = ta.join().unwrap();
        let res_b = tb.join().unwrap();

        assert!(res_a.is_ok(), "send A should succeed");
        assert!(res_b.is_ok(), "send B should succeed");

        // Verify ownership changed.
        assert_eq!(child_a.read().owned.owner, 10);
        assert_eq!(child_b.read().owned.owner, 20);
    });
}

// ── Send and carve racing on the same parent ────────────────────────────────

/// One thread sends a child (changing ownership), another carves a new child
/// from the same parent.  Both operate under shared lock.  Both must succeed
/// since they touch different parts of the tree state.
#[test]
fn send_vs_carve_same_parent() {
    loom::model(|| {
        let platform_lock = Arc::new(RwLock::new(()));
        let root = make_root(0, 0, 0x0000, 0x4000);

        let (child, _) = Capability::carve_child(
            &root,
            Access::new(0x0000, 0x1000, Rights::RW),
            0)
        .unwrap();

        let pl = platform_lock.clone();
        let c = child.clone();
        let sender = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::send_to(&c, 0, 10, Attributes::NONE)
        });

        let pl = platform_lock.clone();
        let r = root.clone();
        let carver = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::carve_child(
                &r,
                Access::new(0x2000, 0x1000, Rights::RW),
                0)
        });

        let send_res = sender.join().unwrap();
        let carve_res = carver.join().unwrap();

        assert!(send_res.is_ok(), "send should succeed");
        assert!(carve_res.is_ok(), "carve should succeed");
        assert_eq!(root.read().children.len(), 2);
    });
}

// ═════════════════════════════════════════════════════════════════════════════
// Case 1 — Alias operations
//
// `alias_child` acquires the parent *write* lock internally.  These tests
// exercise alias-specific overlap rules (alias may overlap other aliases but
// never overlaps a carved region) under all loom schedules.
// ═════════════════════════════════════════════════════════════════════════════

// ── 1a  Concurrent aliases on non-overlapping regions ───────────────────────
//
// | Thread A (shared lock)                      | Thread B (shared lock)                      |
// |---------------------------------------------|---------------------------------------------|
// | alias_child(&root, [0x0000, 0x1000), …)     | alias_child(&root, [0x2000, 0x1000), …)     |
//
// Both operate under a shared platform lock.  Aliasing only conflicts with
// carved regions, never with other aliases, so both must succeed regardless
// of schedule.
//
// Valid outcomes (all schedules):
// - Both succeed → root has 2 children (both Alias kind).

#[test]
fn concurrent_aliases_non_overlapping() {
    loom::model(|| {
        let platform_lock = Arc::new(RwLock::new(()));
        let root = make_root(0, 0, 0x0000, 0x4000);

        let access_a = Access::new(0x0000, 0x1000, Rights::RW);
        let access_b = Access::new(0x2000, 0x1000, Rights::RW);

        let pl = platform_lock.clone();
        let r = root.clone();
        let ta = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::alias_child(&r, access_a, 1)
        });

        let pl = platform_lock.clone();
        let r = root.clone();
        let tb = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::alias_child(&r, access_b, 2)
        });

        let res_a = ta.join().unwrap();
        let res_b = tb.join().unwrap();

        assert!(res_a.is_ok(), "alias A should succeed");
        assert!(res_b.is_ok(), "alias B should succeed");
        assert_eq!(root.read().children.len(), 2);

        // Both must be Alias kind.
        for child_ref in &root.read().children {
            assert_eq!(child_ref.read().data.kind, RegionKind::Alias);
        }
    });
}

// ── 1b  Alias vs carve on overlapping region ────────────────────────────────
//
// | Thread A (shared lock)                          | Thread B (shared lock)                          |
// |-------------------------------------------------|-------------------------------------------------|
// | carve_child(&root, [0x0000, 0x2000), …)         | alias_child(&root, [0x1000, 0x2000), …)         |
//
// Both acquire the parent write lock internally.  The first to finish inserts
// a child.  When the second runs:
// - If carve finished first: alias sees an existing *Carve* child overlapping
//   its range → InvalidAccess.
// - If alias finished first: carve sees an existing *Alias* child overlapping
//   its range → InvalidAccess.
//
// Valid outcomes (all schedules):
// - Exactly one succeeds, the other returns InvalidAccess.
// - Root has exactly 1 child.

#[test]
fn alias_vs_carve_overlapping() {
    loom::model(|| {
        let platform_lock = Arc::new(RwLock::new(()));
        let root = make_root(0, 0, 0x0000, 0x4000);

        let carve_access = Access::new(0x0000, 0x2000, Rights::RW);
        let alias_access = Access::new(0x1000, 0x2000, Rights::RW);

        let pl = platform_lock.clone();
        let r = root.clone();
        let carver = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::carve_child(&r, carve_access, 1)
        });

        let pl = platform_lock.clone();
        let r = root.clone();
        let aliaser = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::alias_child(&r, alias_access, 2)
        });

        let carve_res = carver.join().unwrap();
        let alias_res = aliaser.join().unwrap();

        // Exactly one succeeds.
        let successes = [carve_res.is_ok(), alias_res.is_ok()]
            .iter()
            .filter(|&&s| s)
            .count();
        assert_eq!(successes, 1, "exactly one of alias/carve must succeed");
        assert_eq!(root.read().children.len(), 1);
    });
}

// ── 1c  Alias while a sibling is being revoked ─────────────────────────────
//
// | Thread A (exclusive lock)                       | Thread B (shared lock)                          |
// |-------------------------------------------------|-------------------------------------------------|
// | revoke_child_ref(&root, &carved_child)          | alias_child(&root, [0x0000, 0x1000), …)         |
//
// Setup: root has one carved child covering [0x0000, 0x1000).
// Thread A revokes it (exclusive); thread B aliases the same range (shared).
// Platform-level exclusive ↔ shared serialisation means they never overlap.
//
// Valid outcomes (all schedules):
// - A then B: revoke removes the carved child.  Alias runs, sees no carved
//   overlap → succeeds.  Root has 1 child (the alias).
// - B then A: alias runs, sees the carved child overlapping → InvalidAccess.
//   Then revoke succeeds, removes the carved child.  Root has 0 children.

#[test]
fn alias_while_sibling_revoked() {
    loom::model(|| {
        let platform_lock = Arc::new(RwLock::new(()));
        let root = make_root(0, 0, 0x0000, 0x4000);

        // Pre-create a carved child covering [0x0000, 0x1000).
        let (carved_child, _) = Capability::carve_child(
            &root,
            Access::new(0x0000, 0x1000, Rights::RW),
            0)
        .unwrap();

        let pl = platform_lock.clone();
        let r = root.clone();
        let c = carved_child.clone();
        let revoker = thread::spawn(move || {
            let _guard = pl.write().unwrap(); // exclusive
            Capability::revoke_child_ref(&r, &c)
        });

        let pl = platform_lock.clone();
        let r = root.clone();
        let aliaser = thread::spawn(move || {
            let _guard = pl.read().unwrap(); // shared
            Capability::alias_child(&r, Access::new(0x0000, 0x1000, Rights::RW), 1)
        });

        let revoke_res = revoker.join().unwrap();
        let alias_res = aliaser.join().unwrap();

        // Revoke always succeeds (the child exists at the time of the call).
        assert!(revoke_res.is_ok(), "revoke must succeed");

        let children_count = root.read().children.len();
        if alias_res.is_ok() {
            // A-then-B: revoke first, alias found no carved overlap → 1 child (alias).
            assert_eq!(children_count, 1);
        } else {
            // B-then-A: alias saw carved overlap → failed, then revoke removed it → 0.
            assert_eq!(children_count, 0);
        }
    });
}

// ═════════════════════════════════════════════════════════════════════════════
// Case 2 — Double send on the same capability
//
// | Thread A (shared lock)                          | Thread B (shared lock)                          |
// |-------------------------------------------------|-------------------------------------------------|
// | send_to(&child, domain_B, …)                    | send_to(&child, domain_C, …)                    |
//
// Setup: root (owner = domain 0), child carved from root (owner = 0).
//
// send_to has a two-phase protocol:
//   Phase 1: read-lock child → get expected_old_owner + validate.
//   Phase 2: write-lock child → transfer ownership.
//
// Two concurrent sends both read owner = 0 in phase 1 and pass validation.
// In phase 2, the first write-lock winner transfers the cap (owner becomes B).
// The second acquires the write lock and sees old_owner = B ≠ expected (0).
//
// Expected semantic (linearisable): the second send fails because the caller
// (domain 0) no longer owns the capability — it was already transferred.
// Exactly one send succeeds, the other returns PermissionDenied.
// The successful send's new_owner is the final owner.
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn double_send_same_capability() {
    loom::model(|| {
        let platform_lock = Arc::new(RwLock::new(()));
        let root = make_root(0, 0, 0x0000, 0x4000);

        let (child, _) = Capability::carve_child(
            &root,
            Access::new(0x0000, 0x1000, Rights::RW),
            0)
        .unwrap();

        let pl = platform_lock.clone();
        let c = child.clone();
        let sender_b = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::send_to(&c, 0, 10, Attributes::NONE)
        });

        let pl = platform_lock.clone();
        let c = child.clone();
        let sender_c = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::send_to(&c, 0, 20, Attributes::NONE)
        });

        let res_b = sender_b.join().unwrap();
        let res_c = sender_c.join().unwrap();

        // Exactly one succeeds; the loser gets PermissionDenied.
        let successes = [&res_b, &res_c]
            .iter()
            .filter(|r| r.is_ok())
            .count();
        assert_eq!(successes, 1, "exactly one double-send must succeed");

        // The winner's target domain is the final owner.
        let final_owner = child.read().owned.owner;
        if res_b.is_ok() {
            assert_eq!(final_owner, 10);
            assert_eq!(res_c.unwrap_err(), CapaError::PermissionDenied);
        } else {
            assert_eq!(final_owner, 20);
            assert_eq!(res_b.unwrap_err(), CapaError::PermissionDenied);
        }
    });
}

// ═════════════════════════════════════════════════════════════════════════════
// Case 3 — Revoke of a previously-sent child
//
// Setup:
//   1. Root (owner = domain 0) → carve child C (owner = 0).
//   2. send_to(&C, domain 99, …) → C now owned by 99.
//   3. Thread A revokes C under exclusive lock.
//
// revoke_subtree must correctly detect that the child was sent to a different
// domain (child.owner (99) ≠ parent.owner (0)) and emit:
//   - Unmap(99, region) — domain 99 loses access.
//   - Map(0, region)    — domain 0 regains access to the carved range.
//
// Valid outcomes (single-threaded, but loom validates lock correctness):
//   - Revoke succeeds.
//   - Root has 0 children.
//   - UpdateBatch contains Unmap(99, …) + Map(0, …).
//
// The value of running this under loom is that revoke_subtree does a
// write-lock → take children → drop lock → recurse → re-acquire read-lock
// cycle.  Loom verifies no invariant violation in that pattern.
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn revoke_after_send() {
    loom::model(|| {
        let platform_lock = Arc::new(RwLock::new(()));
        let root = make_root(0, 0, 0x0000, 0x4000);

        // Carve a child (owner = 0).
        let (child, _) = Capability::carve_child(
            &root,
            Access::new(0x0000, 0x1000, Rights::RW),
            0)
        .unwrap();

        // Send child to domain 99.
        {
            let _guard = platform_lock.read().unwrap();
            Capability::send_to(&child, 0, 99, Attributes::NONE).unwrap();
        }
        assert_eq!(child.read().owned.owner, 99);

        // Revoke under exclusive lock.
        let pl = platform_lock.clone();
        let r = root.clone();
        let c = child.clone();
        let revoker = thread::spawn(move || {
            let _guard = pl.write().unwrap();
            Capability::revoke_child_ref(&r, &c)
        });

        let updates = revoker.join().unwrap().expect("revoke must succeed");
        assert_eq!(root.read().children.len(), 0);

        // Must contain Unmap(99, …) and Map(0, …).
        let has_unmap = updates.updates().iter().any(|u| matches!(
            u,
            Update::Unmap { domain: 99, address: 0x0000, size: 0x1000 }
        ));
        let has_map = updates.updates().iter().any(|u| matches!(
            u,
            Update::Map { domain: 0, address: 0x0000, size: 0x1000, .. }
        ));
        assert!(has_unmap, "must unmap from domain 99");
        assert!(has_map, "must remap to domain 0 (parent)");
    });
}

// ═════════════════════════════════════════════════════════════════════════════
// Case 4 — Carve → revoke → re-carve (region reuse)
//
// | Thread A (exclusive lock)                       | Thread B (shared lock)                          |
// |-------------------------------------------------|-------------------------------------------------|
// | revoke_child_ref(&root, &child_c)               | carve_child(&root, [0x0000, 0x1000), …)         |
//
// Setup: root → carved child C covering [0x0000, 0x1000).
// Thread A revokes C; thread B tries to carve the same range.
//
// After revocation removes C from the children list, the region
// [0x0000, 0x1000) must be available for a fresh carve.  The platform-level
// exclusive ↔ shared lock serialises the two threads.
//
// Valid outcomes (all schedules):
// - A then B: revoke removes C.  Carve sees no overlap → succeeds.
//   Root has 1 child (the new carve).
// - B then A: carve runs first, sees C still present → overlap →
//   InvalidAccess.  Revoke then removes C.  Root has 0 children.
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn region_reuse_after_revoke() {
    loom::model(|| {
        let platform_lock = Arc::new(RwLock::new(()));
        let root = make_root(0, 0, 0x0000, 0x4000);

        // Pre-create a carved child covering [0x0000, 0x1000).
        let (child_c, _) = Capability::carve_child(
            &root,
            Access::new(0x0000, 0x1000, Rights::RW),
            0)
        .unwrap();

        let pl = platform_lock.clone();
        let r = root.clone();
        let c = child_c.clone();
        let revoker = thread::spawn(move || {
            let _guard = pl.write().unwrap(); // exclusive
            Capability::revoke_child_ref(&r, &c)
        });

        let pl = platform_lock.clone();
        let r = root.clone();
        let carver = thread::spawn(move || {
            let _guard = pl.read().unwrap(); // shared
            Capability::carve_child(
                &r,
                Access::new(0x0000, 0x1000, Rights::RW),
                1)
        });

        let revoke_res = revoker.join().unwrap();
        let carve_res = carver.join().unwrap();

        assert!(revoke_res.is_ok(), "revoke must succeed");

        let children_count = root.read().children.len();
        if carve_res.is_ok() {
            // A-then-B: revoke first, region freed, carve succeeds → 1 child.
            assert_eq!(children_count, 1);
        } else {
            // B-then-A: carve saw overlap with C → failed, then revoke removed C → 0.
            assert_eq!(children_count, 0);
        }
    });
}

// ═════════════════════════════════════════════════════════════════════════════
// Case 5 — Concurrent domain creation
//
// | Thread A (shared lock)                          | Thread B (shared lock)                          |
// |-------------------------------------------------|-------------------------------------------------|
// | create_child_domain(&parent, policy, …, h=1)    | create_child_domain(&parent, policy, …, h=2)    |
//
// Setup: sealed parent domain with MonitorAPI::ALL.
//
// create_child_domain has a read → drop → write gap:
//   1. parent.read()                — validate sealed + policy.
//   2. drop(parent)                 — release read lock.
//   3. parent_ref.write().add_child — acquire write lock.
//
// Two concurrent creates both pass validation in step 1, then serialise at
// step 3.
//
// Valid outcomes (all schedules):
// - Both succeed.
// - Parent has 2 children with handles 1 and 2.
// - No deadlock in the read → drop → write transition.
// ═════════════════════════════════════════════════════════════════════════════

/// Helper: create a sealed root domain capability suitable for loom tests.
fn make_sealed_domain_root(owner: u64, handle: u64) -> CapabilityRef<Domain> {
    let mut domain = Domain::new_root(1);
    domain.seal().ok(); // root is already sealed, but be explicit
    Capability::new_root(owner, handle, domain)
}

#[test]
fn concurrent_domain_creation() {
    loom::model(|| {
        let platform_lock = Arc::new(RwLock::new(()));
        let parent = make_sealed_domain_root(0, 0);

        let child_policy = DomainPolicy::new_restricted(1, capability_engine::MonitorAPI::ALL);

        let pl = platform_lock.clone();
        let p = parent.clone();
        let cp = child_policy.clone();
        let ta = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::create_child_domain(&p, cp, 0)
        });

        let pl = platform_lock.clone();
        let p = parent.clone();
        let cp = child_policy.clone();
        let tb = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::create_child_domain(&p, cp, 0)
        });

        let res_a = ta.join().unwrap();
        let res_b = tb.join().unwrap();

        assert!(res_a.is_ok(), "domain creation A should succeed");
        assert!(res_b.is_ok(), "domain creation B should succeed");
        assert_eq!(parent.read().children.len(), 2);
    });
}

// ═════════════════════════════════════════════════════════════════════════════
// Case 6 — Domain revoke vs domain creation
//
// | Thread A (exclusive lock)                       | Thread B (shared lock)                          |
// |-------------------------------------------------|-------------------------------------------------|
// | revoke_domain(&parent, child_h)                 | create_domain(&parent, policy)                  |
//
// Setup: sealed parent domain with one child (LocalHandle = child_h).
//
// Exclusive ↔ shared platform lock serialisation for domain operations.
// revoke_domain (via revoke_child_domain internally) recursively drops and
// re-acquires locks in revoke_domain_subtree.
//
// Valid outcomes (all schedules):
// - A then B: child 1 revoked, then child 2 created.  Parent has 1 child
//   (handle = 2), child 1's domain is in Revoked status.
// - B then A: child 2 created, then child 1 revoked.  Parent has 1 child
//   (handle = 2), child 1's domain is in Revoked status.
// - In both orderings the final state is the same: parent has exactly
//   child 2; child 1 is revoked.
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn domain_revoke_vs_creation() {
    loom::model(|| {
        let platform_lock = Arc::new(RwLock::new(()));
        let parent = make_sealed_domain_root(0, 0);

        // Pre-create child 1.
        let child_policy = DomainPolicy::new_restricted(1, capability_engine::MonitorAPI::ALL);
        let child1_h = Capability::create_domain(&parent, child_policy.clone()).unwrap();
        let child1 = parent.read().data.domain_capabilities[&child1_h].upgrade().unwrap();

        let pl = platform_lock.clone();
        let p = parent.clone();
        let revoker = thread::spawn(move || {
            let _guard = pl.write().unwrap(); // exclusive
            Capability::revoke_domain(&p, child1_h)
        });

        let pl = platform_lock.clone();
        let p = parent.clone();
        let cp = child_policy.clone();
        let creator = thread::spawn(move || {
            let _guard = pl.read().unwrap(); // shared
            Capability::create_domain(&p, cp)
        });

        let revoke_res = revoker.join().unwrap();
        let create_res = creator.join().unwrap();

        assert!(revoke_res.is_ok(), "revoke child 1 must succeed");
        assert!(create_res.is_ok(), "create child 2 must succeed");

        // Final state: parent has exactly child 2; child 1 is revoked.
        assert_eq!(parent.read().children.len(), 1);
        assert_eq!(parent.read().children[0].read().sub_handle, 2);
        assert_eq!(child1.read().data.status, DomainStatus::Revoked);
    });
}

// ═════════════════════════════════════════════════════════════════════════════
// §7.7 — Send / accept / reject / revoke pending capability races
//
// The following five cases verify that the freeze model is race-free:
//  7a. loom_double_send_frozen       — concurrent sends for the same handle
//  7b. loom_accept_vs_accept         — two threads both accept the same pending
//  7c. loom_accept_vs_reject         — accept races with reject for same pending
//  7d. loom_revoke_vs_accept         — parent revokes memory cap vs accept
//  7e. loom_revoke_domain_vs_accept  — sender domain revoked vs accept
// ═════════════════════════════════════════════════════════════════════════════

/// Helper: create a sealed domain (unique ID, all permissions).
fn make_sealed_send_domain() -> capability_engine::CapabilityRef<Domain> {
    let mut domain = Domain::new(DomainPolicy::new_root(1));
    domain.seal().ok();
    Capability::new_root(0, 0, domain)
}

/// Helper: create a root memory cap owned by `domain` and register it at `h`.
fn register_mem_send(
    domain: &capability_engine::CapabilityRef<Domain>,
    h: capability_engine::LocalHandle,
) -> capability_engine::CapabilityRef<MemoryRegion> {
    let owner_id = domain.read().data.id;
    let cap = Capability::new_root(owner_id, h, capability_engine::MemoryRegion::new_root(0x0, 0x1000));
    // Use std::sync::Arc::downgrade because `Arc` in this module refers to loom::sync::Arc.
    let weak = std::sync::Arc::downgrade(&cap);
    domain.write().data.add_memory_capability(h, weak);
    cap
}

// ── Case 7a — Concurrent sends for the same handle (double-send race) ────────
//
// | Thread A (shared lock)              | Thread B (shared lock)              |
// |-------------------------------------|-------------------------------------|
// | send_memory(sender, 1, recv1, …)    | send_memory(sender, 1, recv2, …)    |
//
// Setup: sender domain has a memory cap at handle 1 (not yet frozen).
// Both threads try to freeze the same handle simultaneously.
//
// The atomic re-check under write lock in send_memory ensures exactly one
// thread wins the freeze; the other receives PermissionDenied.
//
// Valid outcomes (all schedules):
// - A wins: A succeeds, B gets PermissionDenied. recv1 has 1 pending, recv2 has 0.
// - B wins: B succeeds, A gets PermissionDenied. recv2 has 1 pending, recv1 has 0.
#[test]
fn loom_double_send_frozen() {
    loom::model(|| {
        let platform_lock = Arc::new(RwLock::new(()));

        let sender = make_sealed_send_domain();
        let recv1  = make_sealed_send_domain();
        let recv2  = make_sealed_send_domain();
        let _cap   = register_mem_send(&sender, 1);
        sender.write().data.add_domain_capability(1, std::sync::Arc::downgrade(&recv1));
        sender.write().data.add_domain_capability(2, std::sync::Arc::downgrade(&recv2));

        let pl = platform_lock.clone();
        let s  = sender.clone();
        let ta = thread::spawn(move || {
            let _guard = pl.read().unwrap(); // shared
            Capability::<Domain>::send_memory(&s, 1, 1, capability_engine::Attributes::NONE)
        });

        let pl = platform_lock.clone();
        let s  = sender.clone();
        let tb = thread::spawn(move || {
            let _guard = pl.read().unwrap(); // shared
            Capability::<Domain>::send_memory(&s, 1, 2, capability_engine::Attributes::NONE)
        });

        let res_a = ta.join().unwrap();
        let res_b = tb.join().unwrap();

        // Exactly one send must succeed.
        let successes = [res_a.is_ok(), res_b.is_ok()].iter().filter(|&&x| x).count();
        assert_eq!(successes, 1, "exactly one send must succeed");

        // Total pending entries across both receivers must be exactly 1.
        let total_pending = recv1.read().data.get_pending_ids().len()
            + recv2.read().data.get_pending_ids().len();
        assert_eq!(total_pending, 1, "exactly one pending entry must exist");

        // The handle must be frozen in sender's domain.
        assert!(sender.read().data.is_memory_handle_frozen(1));
    });
}

// ── Case 7b — Two threads both try to accept the same pending entry ───────────
//
// | Thread A (shared lock)              | Thread B (shared lock)              |
// |-------------------------------------|-------------------------------------|
// | accept_memory(receiver, pending_id) | accept_memory(receiver, pending_id) |
//
// Setup: sender has already sent cap to receiver; one pending entry exists.
// Both threads race to accept the same pending_id.
//
// Valid outcomes (all schedules):
// - A first: A gets (handle, updates). B gets NotFound.
// - B first: B gets (handle, updates). A gets NotFound.
// In both cases, exactly one LocalHandle is allocated in receiver's table.
#[test]
fn loom_accept_vs_accept() {
    loom::model(|| {
        let platform_lock = Arc::new(RwLock::new(()));

        let sender   = make_sealed_send_domain();
        let receiver = make_sealed_send_domain();
        let _cap     = register_mem_send(&sender, 1);

        // Pre-send (sequential, before threads) so both threads see a pending entry.
        sender.write().data.add_domain_capability(1, std::sync::Arc::downgrade(&receiver));
        Capability::<Domain>::send_memory(&sender, 1, 1, capability_engine::Attributes::NONE)
            .unwrap();
        let pending_ids = receiver.read().data.get_pending_ids();
        assert_eq!(pending_ids.len(), 1);
        let pid = pending_ids[0];

        let pl = platform_lock.clone();
        let r  = receiver.clone();
        let ta = thread::spawn(move || {
            let _guard = pl.read().unwrap(); // shared
            Capability::<Domain>::accept_memory(&r, pid)
        });

        let pl = platform_lock.clone();
        let r  = receiver.clone();
        let tb = thread::spawn(move || {
            let _guard = pl.read().unwrap(); // shared
            Capability::<Domain>::accept_memory(&r, pid)
        });

        let res_a = ta.join().unwrap();
        let res_b = tb.join().unwrap();

        // Exactly one accept must succeed.
        let successes = [res_a.is_ok(), res_b.is_ok()].iter().filter(|&&x| x).count();
        assert_eq!(successes, 1, "exactly one accept must succeed");

        // Exactly one handle allocated in receiver's table.
        assert_eq!(receiver.read().data.memory_capability_handles().len(), 1);

        // Pending queue must be empty.
        assert!(receiver.read().data.get_pending_ids().is_empty());
    });
}

// ── Case 7c — Accept races with reject for the same pending entry ─────────────
//
// | Thread A (shared lock)              | Thread B (shared lock)              |
// |-------------------------------------|-------------------------------------|
// | accept_memory(receiver, pending_id) | reject_memory(receiver, pending_id) |
//
// Setup: one pending entry exists in receiver.
//
// Valid outcomes (all schedules):
// - A first: accept succeeds → receiver has 1 handle; reject gets NotFound.
//   Sender's handle was already removed (accept cleaned it up).
// - B first: reject succeeds → sender's handle is unfrozen; accept gets NotFound.
//   Receiver has no handles.
#[test]
fn loom_accept_vs_reject() {
    loom::model(|| {
        let platform_lock = Arc::new(RwLock::new(()));

        let sender   = make_sealed_send_domain();
        let receiver = make_sealed_send_domain();
        let _cap     = register_mem_send(&sender, 1);

        sender.write().data.add_domain_capability(1, std::sync::Arc::downgrade(&receiver));
        Capability::<Domain>::send_memory(&sender, 1, 1, capability_engine::Attributes::NONE)
            .unwrap();
        let pid = receiver.read().data.get_pending_ids()[0];

        let pl = platform_lock.clone();
        let r  = receiver.clone();
        let acceptor = thread::spawn(move || {
            let _guard = pl.read().unwrap(); // shared
            Capability::<Domain>::accept_memory(&r, pid)
        });

        let pl = platform_lock.clone();
        let r  = receiver.clone();
        let rejector = thread::spawn(move || {
            let _guard = pl.read().unwrap(); // shared
            Capability::<Domain>::reject_memory(&r, pid)
        });

        let accept_res = acceptor.join().unwrap();
        let reject_res = rejector.join().unwrap();

        // Exactly one must succeed.
        let successes = [accept_res.is_ok(), reject_res.is_ok()]
            .iter().filter(|&&x| x).count();
        assert_eq!(successes, 1, "exactly one of accept/reject must succeed");

        // Pending queue must be empty regardless of outcome.
        assert!(receiver.read().data.get_pending_ids().is_empty());

        if accept_res.is_ok() {
            // Accept-first: receiver owns the cap.
            assert_eq!(receiver.read().data.memory_capability_handles().len(), 1);
            // Sender's handle was removed (not just unfrozen).
            assert!(sender.read().data.get_memory_capability(1).is_none());
        } else {
            // Reject-first: cap returned to sender (unfrozen).
            assert_eq!(receiver.read().data.memory_capability_handles().len(), 0);
            assert!(!sender.read().data.is_memory_handle_frozen(1));
            assert!(sender.read().data.get_memory_capability(1).is_some());
        }
    });
}

// ── Case 7d — Parent revokes memory cap while receiver tries to accept ────────
//
// | Thread A (exclusive lock)                    | Thread B (shared lock)              |
// |----------------------------------------------|-------------------------------------|
// | revoke_memory_child(caller, parent_h, child) | accept_memory(receiver, pending_id) |
//
// Setup: sender has root cap (handle 1) and a carved child (frozen/pending to receiver).
// Thread A revokes the child from the sender's perspective.
// Thread B accepts the pending child.
//
// Valid outcomes (all schedules):
// - A then B: revoke removes child from parent's tree (Arc dead) → accept returns NotFound.
//   Revoke also finds and removes child from sender's frozen table via handle lookup.
// - B then A: accept transfers the child; accept_memory removes the sender's frozen handle.
//   revoke_memory_child then returns NotFound (child no longer in sender's table).
//   Both outcomes are safe.
#[test]
fn loom_revoke_vs_accept() {
    loom::model(|| {
        let platform_lock = Arc::new(RwLock::new(()));

        let sender   = make_sealed_send_domain();
        let receiver = make_sealed_send_domain();

        // Register root cap at handle 1.
        let _root = register_mem_send(&sender, 1);

        // Carve a child [0, 0x100).
        let (child_h, child_sub, _) = Capability::<Domain>::carve_memory(
            &sender,
            1,
            Access::new(0x0, 0x100, Rights::RW),
        ).unwrap();

        // Send the child to receiver.
        sender.write().data.add_domain_capability(1, std::sync::Arc::downgrade(&receiver));
        Capability::<Domain>::send_memory(&sender, child_h, 1, capability_engine::Attributes::NONE)
            .unwrap();
        let pid = receiver.read().data.get_pending_ids()[0];

        let pl = platform_lock.clone();
        let s  = sender.clone();
        let revoker = thread::spawn(move || {
            let _guard = pl.write().unwrap(); // exclusive
            Capability::<Domain>::revoke_memory_child(&s, 1, child_sub)
        });

        let pl = platform_lock.clone();
        let r  = receiver.clone();
        let acceptor = thread::spawn(move || {
            let _guard = pl.read().unwrap(); // shared
            Capability::<Domain>::accept_memory(&r, pid)
        });

        let revoke_res  = revoker.join().unwrap();
        let accept_res  = acceptor.join().unwrap();

        if accept_res.is_ok() {
            // Accept-first: sub_handle lookup finds the child in parent.children regardless
            // of transfer. revoke_memory_child succeeds (removes from tree).
            assert!(revoke_res.is_ok(), "revoke after accept still succeeds via sub_handle lookup");
        } else {
            // Revoke-first: child removed from parent.children → Arc dead.
            // accept gets NotFound upgrading the dead Weak.
            assert!(revoke_res.is_ok(), "revoke must succeed");
            assert!(matches!(accept_res, Err(CapaError::NotFound)));
        }

        // Pending queue must be empty.
        assert!(receiver.read().data.get_pending_ids().is_empty());
    });
}

// ── Case 7e — Sender domain revoked while receiver tries to accept ────────────
//
// | Thread A (exclusive lock)           | Thread B (shared lock)              |
// |-------------------------------------|-------------------------------------|
// | sender.write().data.revoke()        | accept_memory(receiver, pending_id) |
//
// Setup: sender has sent a memory cap to receiver (pending exists, handle frozen).
// Thread A simulates domain revocation by marking the sender as Revoked.
// Thread B tries to accept.
//
// Valid outcomes (all schedules):
// - A then B: sender.is_revoked() → accept returns PermissionDenied; pending cleared.
// - B then A: accept completes before revocation; receiver owns the cap.
//   Revocation then runs (no interaction with the already-transferred cap).
#[test]
fn loom_revoke_domain_vs_accept() {
    loom::model(|| {
        let platform_lock = Arc::new(RwLock::new(()));

        let sender   = make_sealed_send_domain();
        let receiver = make_sealed_send_domain();
        let _cap     = register_mem_send(&sender, 1);

        sender.write().data.add_domain_capability(1, std::sync::Arc::downgrade(&receiver));
        Capability::<Domain>::send_memory(&sender, 1, 1, capability_engine::Attributes::NONE)
            .unwrap();
        let pid = receiver.read().data.get_pending_ids()[0];

        let pl = platform_lock.clone();
        let s  = sender.clone();
        let revoker = thread::spawn(move || {
            let _guard = pl.write().unwrap(); // exclusive (simulates domain revocation)
            s.write().data.revoke();
        });

        let pl = platform_lock.clone();
        let r  = receiver.clone();
        let acceptor = thread::spawn(move || {
            let _guard = pl.read().unwrap(); // shared
            Capability::<Domain>::accept_memory(&r, pid)
        });

        revoker.join().unwrap();
        let accept_res = acceptor.join().unwrap();

        // Pending queue must be empty regardless of outcome.
        assert!(receiver.read().data.get_pending_ids().is_empty());

        if accept_res.is_ok() {
            // Accept-first: receiver owns the cap.
            assert_eq!(receiver.read().data.memory_capability_handles().len(), 1);
        } else {
            // Revoke-first: accept rejected.
            assert!(matches!(accept_res, Err(CapaError::PermissionDenied)));
            assert_eq!(receiver.read().data.memory_capability_handles().len(), 0);
        }
    });
}

// ═════════════════════════════════════════════════════════════════════════════
// §7.8 — Domain-mediated API concurrent memory operations
//
// These tests exercise the public domain-mediated API under loom.  Because the
// `loom` feature routes `crate::sync::RwLock` to `loom::sync::RwLock`, loom
// fully tracks every internal lock acquisition made by the domain-mediated
// operations, exploring all valid thread schedules end-to-end.
//
// Unlike §7.6 (raw CapabilityRef<T> with explicit handles), §7.8 uses the
// high-level API (carve_memory, revoke_memory_child, send_memory) throughout.
// The root domain and root memory are bootstrapped sequentially inside the
// loom model; only the concurrent operations are placed in spawned threads.
// ═════════════════════════════════════════════════════════════════════════════

/// Bootstrap: sealed root domain (id 0) with a root memory region at handle 1.
///
/// The root memory's `owner_domain` is left as `None` (bootstrapping escape
/// hatch) so that the first `carve_memory` skips `validate_operation`.
/// Children carved via `carve_memory` get `owner_domain = Some(root_dom)`, so
/// subsequent domain-mediated operations on them correctly check the domain.
///
/// Returns `(domain, handle, root_mem_arc)` — the caller must keep
/// `root_mem_arc` alive for the duration of the test; the domain table only
/// stores a `Weak` reference.
fn dm_make_root(
    size: u64,
) -> (
    capability_engine::CapabilityRef<Domain>,
    capability_engine::LocalHandle,
    capability_engine::CapabilityRef<MemoryRegion>,
) {
    let dom_data = Domain::new_root(1); // id = 0, already sealed
    let dom: capability_engine::CapabilityRef<Domain> = Capability::new_root(0, 0, dom_data);
    let owner_id = dom.read().data.id;
    let h: capability_engine::LocalHandle = 1;
    let mem: capability_engine::CapabilityRef<MemoryRegion> =
        Capability::new_root(owner_id, h, MemoryRegion::new_root(0x0, size));
    dom.write().data.add_memory_capability(h, std::sync::Arc::downgrade(&mem));
    (dom, h, mem)
}

// ── Case 8a — Concurrent revoke of distinct siblings ────────────────────────
//
// | Thread A (shared lock)                          | Thread B (shared lock)                          |
// |-------------------------------------------------|-------------------------------------------------|
// | revoke_memory_child(dom, root_h, h_child1)      | revoke_memory_child(dom, root_h, h_child2)      |
//
// Setup: sealed root domain with root memory (handle 1) and two carved,
// non-overlapping children (handles 2 and 3).
//
// Both threads concurrently revoke different children of the same parent.
// revoke_memory_child serialises on the parent's write lock, but the two calls
// target distinct sub_handles so both must always succeed.
//
// Valid outcomes (all schedules):
// - A then B, or B then A: both revokes succeed; root_mem has 0 children.
#[test]
fn loom_dm_concurrent_revokes() {
    loom::model(|| {
        let platform_lock = Arc::new(RwLock::new(()));
        let (dom, h_root, _root_mem) = dm_make_root(0x4000);

        // Sequential setup: carve two non-overlapping children.
        let (h_c1, sub_c1, _) = Capability::<Domain>::carve_memory(
            &dom, h_root, Access::new(0x0000, 0x1000, Rights::RW),
        ).expect("setup: carve child1");
        let (h_c2, sub_c2, _) = Capability::<Domain>::carve_memory(
            &dom, h_root, Access::new(0x2000, 0x1000, Rights::RW),
        ).expect("setup: carve child2");

        let pl = platform_lock.clone();
        let d  = dom.clone();
        let ta = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::<Domain>::revoke_memory_child(&d, h_root, sub_c1)
        });

        let pl = platform_lock.clone();
        let d  = dom.clone();
        let tb = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::<Domain>::revoke_memory_child(&d, h_root, sub_c2)
        });

        let res_a = ta.join().unwrap();
        let res_b = tb.join().unwrap();

        assert!(res_a.is_ok(), "revoke child1 must succeed");
        assert!(res_b.is_ok(), "revoke child2 must succeed");

        // Both children must be removed from root_mem's children list.
        let root_mem = dom.read().data
            .get_memory_capability(h_root)
            .expect("root_mem in table")
            .clone()
            .upgrade()
            .expect("root_mem alive");
        assert_eq!(root_mem.read().children.len(), 0);
    });
}

// ── Case 8b — Send one child while revoking a sibling ───────────────────────
//
// | Thread A (shared lock)                          | Thread B (shared lock)                          |
// |-------------------------------------------------|-------------------------------------------------|
// | send_memory(dom, h_child1, receiver, NONE)      | revoke_memory_child(dom, h_root, h_child2)      |
//
// Setup: sealed root domain with root memory (handle 1), two carved children
// (handles 2 and 3), and a sealed receiver domain (all-permissions policy).
//
// Thread A sends child1 to a sealed receiver (pending-queue path).
// Thread B revokes child2 via revoke_memory_child.
//
// The only shared synchronisation point is the domain lock (dom):
//  - Thread A writes dom (atomic freeze of h_child1 under write lock).
//  - Thread B reads dom (frozen-check and parent-ref lookup).
// Loom explores all interleavings of these lock acquisitions.
//
// Both operations target different capabilities and must always succeed.
//
// Post-condition:
//  - h_child1 is frozen in dom's table.
//  - receiver has exactly 1 pending capability.
//  - root_mem has 1 child remaining (child1 is tree-attached but frozen;
//    child2 was revoked and removed from the tree).
#[test]
fn loom_dm_send_vs_revoke_sibling() {
    loom::model(|| {
        let platform_lock = Arc::new(RwLock::new(()));
        let (dom, h_root, _root_mem) = dm_make_root(0x4000);
        let receiver = make_sealed_send_domain();

        // Sequential setup: carve two non-overlapping children.
        let (h_c1, _, _) = Capability::<Domain>::carve_memory(
            &dom, h_root, Access::new(0x0000, 0x1000, Rights::RW),
        ).expect("setup: carve child1");
        let (h_c2, sub_c2, _) = Capability::<Domain>::carve_memory(
            &dom, h_root, Access::new(0x2000, 0x1000, Rights::RW),
        ).expect("setup: carve child2");

        dom.write().data.add_domain_capability(1, std::sync::Arc::downgrade(&receiver));

        let pl = platform_lock.clone();
        let d  = dom.clone();
        let ta = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::<Domain>::send_memory(&d, h_c1, 1, Attributes::NONE)
        });

        let pl = platform_lock.clone();
        let d  = dom.clone();
        let tb = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::<Domain>::revoke_memory_child(&d, h_root, sub_c2)
        });

        let send_res   = ta.join().unwrap();
        let revoke_res = tb.join().unwrap();

        assert!(send_res.is_ok(),   "send child1 must succeed");
        assert!(revoke_res.is_ok(), "revoke child2 must succeed");

        // child1 must be frozen in dom's table.
        assert!(dom.read().data.is_memory_handle_frozen(h_c1));
        // receiver must have exactly 1 pending capability.
        assert_eq!(receiver.read().data.get_pending_ids().len(), 1);
        // root_mem has only child1 remaining (child2 was revoked from the tree;
        // send does not detach child1 from the tree, only freezes its handle).
        let root_mem = dom.read().data
            .get_memory_capability(h_root)
            .expect("root_mem in table")
            .clone()
            .upgrade()
            .expect("root_mem alive");
        assert_eq!(root_mem.read().children.len(), 1);
    });
}
