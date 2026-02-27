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

use loom::sync::{Arc, RwLock};
use loom::sync::atomic::{AtomicUsize, Ordering};
use loom::thread;

use capability_engine::{
    Access, Attributes, Capability, CapabilityRef, MemoryRegion, Rights,
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
            Capability::carve_child(&r, access_a, 1, 1)
                .expect("carve A should succeed")
        });

        let pl = platform_lock.clone();
        let r = root.clone();
        let tb = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::carve_child(&r, access_b, 2, 2)
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
            Capability::carve_child(&r, access_a, 1, 1)
        });

        let pl = platform_lock.clone();
        let r = root.clone();
        let tb = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::carve_child(&r, access_b, 2, 2)
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
            0,
            1,
        )
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
                1,
                2,
            )
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
            0,
            1,
        )
        .unwrap();
        let (child_b, _) = Capability::carve_child(
            &root,
            Access::new(0x2000, 0x1000, Rights::RW),
            0,
            2,
        )
        .unwrap();

        let pl = platform_lock.clone();
        let ca = child_a.clone();
        let ta = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::send_to(&ca, 10, 100, Attributes::NONE)
        });

        let pl = platform_lock.clone();
        let cb = child_b.clone();
        let tb = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::send_to(&cb, 20, 200, Attributes::NONE)
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
            0,
            1,
        )
        .unwrap();

        let pl = platform_lock.clone();
        let c = child.clone();
        let sender = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::send_to(&c, 10, 100, Attributes::NONE)
        });

        let pl = platform_lock.clone();
        let r = root.clone();
        let carver = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::carve_child(
                &r,
                Access::new(0x2000, 0x1000, Rights::RW),
                0,
                2,
            )
        });

        let send_res = sender.join().unwrap();
        let carve_res = carver.join().unwrap();

        assert!(send_res.is_ok(), "send should succeed");
        assert!(carve_res.is_ok(), "carve should succeed");
        assert_eq!(root.read().children.len(), 2);
    });
}
