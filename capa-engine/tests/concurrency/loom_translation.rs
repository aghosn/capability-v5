//! Loom tests for address-translation hooks under concurrent interleavings.
//!
//! These tests verify that `AddressMap` mutations in `send_at`, `accept_at`,
//! and `revoke` are consistent when multiple threads operate concurrently.
//!
//! # Running
//!
//! ```sh
//! cargo test --test loom_translation --features loom,address_translation --release
//! ```

use loom::sync::{Arc, RwLock};
use loom::thread;

use capability_engine::{
    Access, Attributes, CapaError, Capability, CapabilityRef, Domain, DomainPolicy, LocalHandle,
    MemoryRegion, MonitorAPI, Rights,
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



// ── Helpers (mirror integration/translation.rs) ─────────────────────────────

/// Bootstrap root domain + root memory region at handle 1 with identity map.
/// The returned `CapabilityRef<MemoryRegion>` must be kept alive (strong ref).
fn bootstrap() -> (CapabilityRef<Domain>, CapabilityRef<MemoryRegion>, LocalHandle) {
    let root_domain = Domain::new_root(4);
    let root = Capability::new_root(0, 0, root_domain);
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let r0 = Capability::new_root(0, 1, root_region);
    root.write()
        .data
        .add_memory_capability(1, std::sync::Arc::downgrade(&r0));
    // Seed identity map so carve/send hooks see the HPA range.
    {
        let mut w = root.write();
        let _ = w.data.address_map.insert(
            0x0,
            0x10000,
            Rights::RWX,
            #[cfg(feature = "cache_coloring")]
            None,
            None,
        );
    }
    (root, r0, 1)
}

/// Create an unsealed child domain under `root` via `Capability::create`.
fn make_child(root: &CapabilityRef<Domain>) -> (LocalHandle, CapabilityRef<Domain>) {
    let api = MonitorAPI::from_bits(0xfff);
    let policy = DomainPolicy::new_restricted(0b1111, api);
    let h = Capability::create(&NullPlatform, root, policy).unwrap().0;
    let dom = root
        .read()
        .data
        .domain_capabilities[&h]
        .upgrade()
        .unwrap();
    (h, dom)
}

/// Create a sealed child domain under `root` (receives to pending).
fn make_sealed_child(root: &CapabilityRef<Domain>) -> (LocalHandle, CapabilityRef<Domain>) {
    let api = MonitorAPI::from_bits(0xfff | MonitorAPI::RECEIVE_AFTER_SEAL);
    let policy = DomainPolicy::new_restricted(0b1111, api);
    let h = Capability::create(&NullPlatform, root, policy).unwrap().0;
    Capability::<Domain>::seal(&NullPlatform, root, h).unwrap();
    let dom = root
        .read()
        .data
        .domain_capabilities[&h]
        .upgrade()
        .unwrap();
    (h, dom)
}

// ═════════════════════════════════════════════════════════════════════════════
// §1 — Concurrent send_at to same receiver with different GPAs
// ═════════════════════════════════════════════════════════════════════════════

/// Two threads send different carved caps to the same unsealed domain at
/// different GPAs.  Both should succeed.  The receiver's AddressMap should
/// have both entries.
#[test]
fn loom_concurrent_send_at_different_gpas() {
    loom::model(|| {
        let platform_lock = Arc::new(RwLock::new(()));

        let (root, _r0, r0_h) = bootstrap();

        // Carve two disjoint children from root's memory (handle 1).
        let (h_a, _, _) =
            Capability::<Domain>::carve(&NullPlatform, &root, r0_h, Access::new(0x0000, 0x1000, Rights::RW))
                .unwrap();
        let (h_b, _, _) =
            Capability::<Domain>::carve(&NullPlatform, &root, r0_h, Access::new(0x2000, 0x1000, Rights::RW))
                .unwrap();

        // Create an unsealed child domain via domain-mediated API.
        let (dom_h, dom) = make_child(&root);

        let pl = platform_lock.clone();
        let r = root.clone();
        let ta = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::<Domain>::send_at(&NullPlatform, &r, h_a, dom_h, Attributes::NONE, Some(0xA_0000))
        });

        let pl = platform_lock.clone();
        let r = root.clone();
        let tb = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::<Domain>::send_at(&NullPlatform, &r, h_b, dom_h, Attributes::NONE, Some(0xB_0000))
        });

        let res_a = ta.join().unwrap();
        let res_b = tb.join().unwrap();

        assert!(res_a.is_ok(), "send A failed: {:?}", res_a);
        assert!(res_b.is_ok(), "send B failed: {:?}", res_b);

        // Both GPAs should be in the receiver's AddressMap.
        let d = dom.read();
        assert_eq!(
            d.data.address_map.entries().len(),
            2,
            "receiver should have 2 AddressMap entries"
        );
    });
}

// ═════════════════════════════════════════════════════════════════════════════
// §2 — Concurrent send_at to same GPA (conflict)
// ═════════════════════════════════════════════════════════════════════════════

/// Two threads try to send different caps to the same GPA.
/// Exactly one should succeed; the other gets RegionOverlap.
#[test]
fn loom_concurrent_send_at_same_gpa() {
    loom::model(|| {
        let platform_lock = Arc::new(RwLock::new(()));

        let (root, _r0, r0_h) = bootstrap();

        let (h_a, _, _) =
            Capability::<Domain>::carve(&NullPlatform, &root, r0_h, Access::new(0x0000, 0x1000, Rights::RW))
                .unwrap();
        let (h_b, _, _) =
            Capability::<Domain>::carve(&NullPlatform, &root, r0_h, Access::new(0x2000, 0x1000, Rights::RW))
                .unwrap();

        let (dom_h, dom) = make_child(&root);

        let pl = platform_lock.clone();
        let r = root.clone();
        let ta = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::<Domain>::send_at(&NullPlatform, &r, h_a, dom_h, Attributes::NONE, Some(0xA_0000))
        });

        let pl = platform_lock.clone();
        let r = root.clone();
        let tb = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::<Domain>::send_at(&NullPlatform, &r, h_b, dom_h, Attributes::NONE, Some(0xA_0000))
        });

        let res_a = ta.join().unwrap();
        let res_b = tb.join().unwrap();

        let successes = [res_a.is_ok(), res_b.is_ok()]
            .iter()
            .filter(|&&x| x)
            .count();
        assert_eq!(successes, 1, "exactly one send_at must succeed at the same GPA");

        let failures = [&res_a, &res_b]
            .iter()
            .filter(|r| matches!(r, Err(CapaError::RegionOverlap)))
            .count();
        assert_eq!(failures, 1, "exactly one must get RegionOverlap");

        let d = dom.read();
        assert_eq!(d.data.address_map.entries().len(), 1);
    });
}

// ═════════════════════════════════════════════════════════════════════════════
// §3 — Concurrent accept_at: two threads accept the same pending
// ═════════════════════════════════════════════════════════════════════════════

/// Two threads race to accept the same pending entry.  Exactly one succeeds
/// and the AddressMap gets exactly one entry.
#[test]
fn loom_concurrent_accept_at() {
    loom::model(|| {
        let platform_lock = Arc::new(RwLock::new(()));

        let (root, _r0, r0_h) = bootstrap();

        let (c_h, _, _) =
            Capability::<Domain>::carve(&NullPlatform, &root, r0_h, Access::new(0x0000, 0x1000, Rights::RW))
                .unwrap();

        // Sealed child: send goes to pending.
        let (dom_h, dom) = make_sealed_child(&root);

        Capability::<Domain>::send_at(&NullPlatform, &root, c_h, dom_h, Attributes::NONE, Some(0xA_0000))
            .unwrap();

        let pending_ids = dom.read().data.get_pending_ids();
        assert_eq!(pending_ids.len(), 1);
        let pid = pending_ids[0];

        let pl = platform_lock.clone();
        let d = dom.clone();
        let ta = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::<Domain>::accept_at(&NullPlatform, &d, pid, None)
        });

        let pl = platform_lock.clone();
        let d = dom.clone();
        let tb = thread::spawn(move || {
            let _guard = pl.read().unwrap();
            Capability::<Domain>::accept_at(&NullPlatform, &d, pid, None)
        });

        let res_a = ta.join().unwrap();
        let res_b = tb.join().unwrap();

        let successes = [res_a.is_ok(), res_b.is_ok()]
            .iter()
            .filter(|&&x| x)
            .count();
        assert_eq!(successes, 1, "exactly one accept must succeed");

        let d = dom.read();
        assert_eq!(d.data.address_map.entries().len(), 1);
        assert!(d.data.address_map.entries().contains_key(&0xA_0000));
    });
}

// ═════════════════════════════════════════════════════════════════════════════
// §4 — Revoke vs accept_at: AddressMap consistency
// ═════════════════════════════════════════════════════════════════════════════

/// One thread revokes the carved cap while another accepts the pending entry.
/// Same capability — so the outcomes are:
///   - Accept first: accept succeeds, revoke cascades and cleans up → map empty
///   - Revoke first: cap Arc dropped, accept gets NotFound → map empty
/// In both cases the receiver's AddressMap ends up empty.
#[test]
fn loom_revoke_vs_accept_at_map_consistency() {
    loom::model(|| {
        let platform_lock = Arc::new(RwLock::new(()));

        let (root, _r0, r0_h) = bootstrap();

        let (c_h, c_sub, _) =
            Capability::<Domain>::carve(&NullPlatform, &root, r0_h, Access::new(0x0000, 0x1000, Rights::RW))
                .unwrap();

        // Sealed child: send goes to pending.
        let (dom_h, dom) = make_sealed_child(&root);

        Capability::<Domain>::send_at(&NullPlatform, &root, c_h, dom_h, Attributes::NONE, Some(0xC_0000))
            .unwrap();

        let pid = dom.read().data.get_pending_ids()[0];

        let pl = platform_lock.clone();
        let r = root.clone();
        let revoker = thread::spawn(move || {
            let _guard = pl.write().unwrap(); // exclusive
            Capability::<Domain>::revoke(&NullPlatform, &r, r0_h, c_sub)
        });

        let pl = platform_lock.clone();
        let d = dom.clone();
        let acceptor = thread::spawn(move || {
            let _guard = pl.read().unwrap(); // shared
            Capability::<Domain>::accept_at(&NullPlatform, &d, pid, Some(0xC_0000))
        });

        let revoke_res = revoker.join().unwrap();
        let accept_res = acceptor.join().unwrap();

        // Revoke always succeeds.
        assert!(revoke_res.is_ok(), "revoke must succeed");

        // Exactly one ordering:
        if accept_res.is_ok() {
            // Accept ran first, then revoke cascaded and removed the map entry.
            // Map should be empty (revoke cleaned up).
        } else {
            // Revoke ran first, cap Arc dropped → accept got NotFound.
            assert!(
                matches!(accept_res, Err(CapaError::NotFound)),
                "accept should fail with NotFound, got {:?}",
                accept_res
            );
        }

        // In both orderings the receiver's map ends up empty.
        let d = dom.read();
        assert!(
            d.data.address_map.entries().is_empty(),
            "map must be empty regardless of ordering, got {} entries",
            d.data.address_map.entries().len()
        );
    });
}
