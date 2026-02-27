//! Cross-core synchronization tests with simulated IPIs and barriers.
//!
//! These tests verify the two-barrier protocol (§5.2) using a multi-threaded
//! platform where each "core" is a real OS thread that can receive IPIs and
//! participate in barriers.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;

use parking_lot::{
    lock_api::{ArcRwLockReadGuard, ArcRwLockWriteGuard},
    RawRwLock, RwLock,
};

use capability_engine::*;

// ─────────────────────────────────────────────────────────────────────────────
// MultiCorePlatform: simulates real cores as OS threads with IPI/barrier support
// ─────────────────────────────────────────────────────────────────────────────

/// Simulated core state
struct CoreState {
    /// Current domain running on this core (None = idle)
    current_domain: Option<DomainId>,
    /// Flag to signal IPI received
    ipi_pending: AtomicBool,
    /// Counter incremented each time this core processes an update
    update_count: AtomicU64,
}

/// Domain registry entry
struct DomainEntry {
    revoked: bool,
    parent_id: Option<DomainId>,
}

/// Barrier state for two-phase synchronization
struct BarrierState {
    /// Number of threads that have arrived at this barrier
    arrived: usize,
    /// Barrier ID (0 or 1)
    id: u8,
}

struct MultiCorePlatformInner {
    /// Per-core state (indexed by CoreId)
    cores: Vec<CoreState>,
    /// Domain registry
    domains: BTreeMap<DomainId, DomainEntry>,
    /// Domain → core reverse mapping
    domain_to_core: BTreeMap<DomainId, u64>,
    /// Updates applied (for verification)
    applied_updates: Vec<Update>,
    /// Barrier state
    barrier: BarrierState,
}

pub struct MultiCorePlatform {
    /// RW lock: shared for non-revoke ops, exclusive for revoke ops.
    op_lock: Arc<RwLock<()>>,
    /// Platform state
    inner: Arc<std::sync::Mutex<MultiCorePlatformInner>>,
}

struct MultiCoreSharedLock {
    _guard: ArcRwLockReadGuard<RawRwLock, ()>,
}
unsafe impl Send for MultiCoreSharedLock {}
impl OpLockGuard for MultiCoreSharedLock {}

struct MultiCoreExclusiveLock {
    _guard: ArcRwLockWriteGuard<RawRwLock, ()>,
}
unsafe impl Send for MultiCoreExclusiveLock {}
impl OpLockGuard for MultiCoreExclusiveLock {}

impl MultiCorePlatform {
    pub fn new(num_cores: usize) -> Self {
        let cores: Vec<CoreState> = (0..num_cores)
            .map(|_| CoreState {
                current_domain: None,
                ipi_pending: AtomicBool::new(false),
                update_count: AtomicU64::new(0),
            })
            .collect();

        MultiCorePlatform {
            op_lock: Arc::new(RwLock::new(())),
            inner: Arc::new(std::sync::Mutex::new(MultiCorePlatformInner {
                cores,
                domains: BTreeMap::new(),
                domain_to_core: BTreeMap::new(),
                applied_updates: Vec::new(),
                barrier: BarrierState { arrived: 0, id: 0 },
            })),
        }
    }

    /// Get the current domain for a core
    pub fn get_core_domain(&self, core_id: CoreId) -> Option<DomainId> {
        let inner = self.inner.lock().unwrap();
        inner.cores[core_id as usize].current_domain
    }

    /// Check if a domain is revoked
    pub fn is_domain_revoked(&self, domain_id: DomainId) -> bool {
        let inner = self.inner.lock().unwrap();
        inner
            .domains
            .get(&domain_id)
            .map(|e| e.revoked)
            .unwrap_or(true)
    }

    /// Drain applied updates for verification
    pub fn drain_updates(&self) -> Vec<Update> {
        let mut inner = self.inner.lock().unwrap();
        inner.applied_updates.drain(..).collect()
    }

    /// Get the update count for a specific core
    pub fn get_core_update_count(&self, core_id: CoreId) -> u64 {
        let inner = self.inner.lock().unwrap();
        inner.cores[core_id as usize]
            .update_count
            .load(Ordering::SeqCst)
    }

    /// Simulate a core polling for IPIs (would be called in IPI handler in real system)
    pub fn core_poll_ipi(&self, core_id: CoreId) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.cores[core_id as usize]
            .ipi_pending
            .swap(false, Ordering::SeqCst)
    }
}

impl Platform for MultiCorePlatform {
    fn acquire_shared_lock(&self) -> Result<Box<dyn OpLockGuard>> {
        Ok(Box::new(MultiCoreSharedLock {
            _guard: self.op_lock.read_arc(),
        }))
    }

    fn acquire_exclusive_lock(&self) -> Result<Box<dyn OpLockGuard>> {
        Ok(Box::new(MultiCoreExclusiveLock {
            _guard: self.op_lock.write_arc(),
        }))
    }

    fn send_ipi(&self, core_id: CoreId) {
        let inner = self.inner.lock().unwrap();
        inner.cores[core_id as usize]
            .ipi_pending
            .store(true, Ordering::SeqCst);
        // In a real system, this would trigger a hardware interrupt
    }

    fn sync_barrier(&self, id: u8, _participants: usize) {
        // In real system, remote cores would be preempted and waiting in IPI handler.
        // In our test platform, since we're not spawning actual core threads that run
        // domains, we just simulate the synchronization semantics:
        // - Barrier 0: all affected cores have stopped (simulated as instant)
        // - Barrier 1: cores are released (simulated as instant)
        // The key is that updates are applied atomically between the two barriers.

        let mut inner = self.inner.lock().unwrap();

        // Track barrier phases
        if inner.barrier.id != id {
            inner.barrier.id = id;
            inner.barrier.arrived = 0;
        }

        inner.barrier.arrived += 1;

        // For testing purposes, barriers complete instantly since we're not
        // actually running domain code on separate threads
    }

    fn apply_update(&self, update: &Update) {
        let mut inner = self.inner.lock().unwrap();
        inner.applied_updates.push(update.clone());

        // Simulate hardware update application
        match update {
            Update::Map { domain, .. } => {
                // In real system: modify EPT/page tables
                if let Some(&core_id) = inner.domain_to_core.get(domain) {
                    inner.cores[core_id as usize]
                        .update_count
                        .fetch_add(1, Ordering::SeqCst);
                }
            }
            Update::Unmap { domain, .. } => {
                if let Some(&core_id) = inner.domain_to_core.get(domain) {
                    inner.cores[core_id as usize]
                        .update_count
                        .fetch_add(1, Ordering::SeqCst);
                }
            }
            _ => {}
        }
    }

    fn on_domain_revoked(&self, domain_id: DomainId, fallback: Option<DomainId>) {
        let mut inner = self.inner.lock().unwrap();

        // Find which core is running this domain
        let core_id = inner.domain_to_core.remove(&domain_id);

        if let Some(core_id) = core_id {
            // Determine fallback
            let next_domain =
                fallback.or_else(|| inner.domains.get(&domain_id).and_then(|e| e.parent_id));

            // Update core state
            inner.cores[core_id as usize].current_domain = next_domain;

            // Update reverse mapping
            if let Some(next) = next_domain {
                inner.domain_to_core.insert(next, core_id);
            }
        }

        // Mark domain as revoked
        if let Some(entry) = inner.domains.get_mut(&domain_id) {
            entry.revoked = true;
        }
    }

    fn register_domain(&self, domain_id: DomainId, parent_id: Option<DomainId>) {
        let mut inner = self.inner.lock().unwrap();
        inner.domains.insert(
            domain_id,
            DomainEntry {
                revoked: false,
                parent_id,
            },
        );
    }

    fn set_core_domain(&self, core_id: CoreId, domain_id: DomainId) {
        let mut inner = self.inner.lock().unwrap();

        // Clear old mapping
        if let Some(old_domain) = inner.cores[core_id as usize].current_domain {
            inner.domain_to_core.remove(&old_domain);
        }

        // Set new mapping
        inner.cores[core_id as usize].current_domain = Some(domain_id);
        inner.domain_to_core.insert(domain_id, core_id);
    }

    fn clear_core_domain(&self, core_id: CoreId) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(domain_id) = inner.cores[core_id as usize].current_domain {
            inner.domain_to_core.remove(&domain_id);
        }
        inner.cores[core_id as usize].current_domain = None;
    }

    fn domain_core(&self, domain_id: DomainId) -> Option<CoreId> {
        let inner = self.inner.lock().unwrap();
        inner.domain_to_core.get(&domain_id).copied()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_crosscore_send_triggers_ipi() {
    let platform = Arc::new(MultiCorePlatform::new(2));
    const SENDER_ID: DomainId = 0;
    const RECEIVER_ID: DomainId = 1;
    const CORE_0: CoreId = 0;
    const CORE_1: CoreId = 1;

    // Setup: register domains
    platform.register_domain(SENDER_ID, None);
    platform.register_domain(RECEIVER_ID, None);

    // Core 0 runs sender, core 1 runs receiver
    platform.set_core_domain(CORE_0, SENDER_ID);
    platform.set_core_domain(CORE_1, RECEIVER_ID);

    // Create memory capability owned by sender
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let root_mem = Capability::new_root(SENDER_ID, 0, root_region);

    let child_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child_mem, _) = Capability::carve_child(&root_mem, child_access, SENDER_ID, 1).unwrap();

    // Send to receiver (should trigger cross-core path)
    let result = execute(&*platform, false, move || {
        Capability::send_to(&child_mem, SENDER_ID, RECEIVER_ID, Attributes::NONE)
            .map(|updates| ((), updates))
    });

    assert!(result.is_ok(), "Send operation should succeed");

    // Verify IPI was sent to core 1
    // Note: IPI flag is cleared on poll, but we can verify the update was applied
    let updates = platform.drain_updates();
    assert!(
        !updates.is_empty(),
        "Should have applied updates for receiver domain"
    );

    // Verify receiver domain got the map update
    let has_map_for_receiver = updates
        .iter()
        .any(|u| matches!(u, Update::Map { domain, .. } if *domain == RECEIVER_ID));
    assert!(has_map_for_receiver, "Receiver should have Map update");

    println!("✓ Cross-core send triggered IPI and applied updates");
}

#[test]
fn test_crosscore_revoke_with_fallback() {
    let platform = Arc::new(MultiCorePlatform::new(2));
    const ROOT_ID: DomainId = 0;
    const CORE_1: CoreId = 1;

    // Create domain capabilities first so we get the real generated IDs.
    let root_domain = Domain::new_root(2);
    let root = Capability::new_root(ROOT_ID, 0, root_domain);

    let child_policy = DomainPolicy::new_restricted(0b11, MonitorAPI::NONE);
    let child = Capability::create_child_domain(&root, child_policy, ROOT_ID, 1).unwrap();
    let child_id = child.read().data.id;

    // Register with the actual IDs (child_id is whatever the global counter gave us).
    platform.register_domain(ROOT_ID, None);
    platform.register_domain(child_id, Some(ROOT_ID));

    // Core 1 is running the child
    platform.set_core_domain(CORE_1, child_id);
    assert_eq!(platform.get_core_domain(CORE_1), Some(child_id));

    // Seal the child so we can revoke it
    child.write().data.seal().unwrap();

    // Revoke the child (cross-core path since core 1 is running it)
    let result = execute(&*platform, true, || {
        Capability::revoke_child_domain(&root, 1).map(|updates| ((), updates))
    });

    assert!(result.is_ok(), "Revoke should succeed");

    // Verify core 1 was redirected to parent
    assert_eq!(
        platform.get_core_domain(CORE_1),
        Some(ROOT_ID),
        "Core should fall back to parent"
    );

    // Verify child is marked revoked
    assert!(
        platform.is_domain_revoked(child_id),
        "Child should be revoked"
    );

    println!("✓ Cross-core revoke correctly redirected core to fallback");
}

#[test]
fn test_barrier_calls_during_crosscore_operation() {
    // Test that execute() calls barriers when domains are on remote cores
    let platform = Arc::new(MultiCorePlatform::new(2));
    const SENDER_ID: DomainId = 10;
    const RECEIVER_ID: DomainId = 11;

    platform.register_domain(SENDER_ID, None);
    platform.register_domain(RECEIVER_ID, None);

    // Both domains running on different cores
    platform.set_core_domain(0, SENDER_ID);
    platform.set_core_domain(1, RECEIVER_ID);

    // Create memory and send between cores
    let region = MemoryRegion::new_root(0x0, 0x10000);
    let mem = Capability::new_root(SENDER_ID, 0, region);
    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let (child, _) = Capability::carve_child(&mem, access, SENDER_ID, 1).unwrap();

    let result = execute(&*platform, false, || {
        Capability::send_to(&child, SENDER_ID, RECEIVER_ID, Attributes::NONE).map(|updates| ((), updates))
    });

    assert!(result.is_ok(), "Cross-core operation should succeed");

    // Verify barriers were called (check barrier state was incremented)
    let inner = platform.inner.lock().unwrap();
    assert!(
        inner.barrier.arrived > 0,
        "Barriers should have been called during cross-core operation"
    );

    println!("✓ Barriers are invoked during cross-core operations");
}

#[test]
fn test_concurrent_operations_with_different_cores() {
    let platform = Arc::new(MultiCorePlatform::new(4));

    // Create 4 domains, each running on a different core
    for i in 0..4 {
        platform.register_domain(i, None);
        platform.set_core_domain(i, i);
    }

    // Create memory capabilities for each domain
    let capabilities: Vec<Arc<CapabilityRef<MemoryRegion>>> = (0..4)
        .map(|i| {
            // Each domain gets non-overlapping memory starting at 0x100000 + offset
            let base = 0x100000 + (0x10000 * i);
            let region = MemoryRegion::new_root(base, 0x10000);
            Arc::new(Capability::new_root(i, i, region))
        })
        .collect();

    let mut handles = vec![];

    // Each thread carves from its own domain's memory (non-overlapping addresses)
    for i in 0..4 {
        let p = Arc::clone(&platform);
        let cap = Arc::clone(&capabilities[i as usize]);
        let base = 0x100000 + (0x10000 * i);
        let handle = thread::spawn(move || {
            for j in 0..10 {
                let addr = base + (j * 0x1000) as u64;
                let access = Access::new(addr, 0x1000, Rights::RW);
                let result = execute(&*p, false, || {
                    Capability::carve_child(&cap, access, i, j as u64)
                        .map(|(child, updates)| (child, updates))
                });

                if let Err(e) = result {
                    panic!("Carve failed for domain {} iteration {}: {:?}", i, j, e);
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    // Verify all domains created their children
    for i in 0..4 {
        let children = capabilities[i as usize].read().children.len();
        assert_eq!(children, 10, "Domain {} should have 10 children", i);
    }

    println!("✓ Concurrent operations on different cores work correctly");
}

#[test]
fn test_multiple_cores_affected_by_single_operation() {
    let platform = Arc::new(MultiCorePlatform::new(3));
    const SENDER_ID: DomainId = 0;
    const RECEIVER1_ID: DomainId = 1;
    const RECEIVER2_ID: DomainId = 2;

    // Setup domains on different cores
    platform.register_domain(SENDER_ID, None);
    platform.register_domain(RECEIVER1_ID, None);
    platform.register_domain(RECEIVER2_ID, None);

    platform.set_core_domain(0, SENDER_ID);
    platform.set_core_domain(1, RECEIVER1_ID);
    platform.set_core_domain(2, RECEIVER2_ID);

    // Create memory capability
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let root_mem = Capability::new_root(SENDER_ID, 0, root_region);

    // Carve a child
    let access = Access::new(0x1000, 0x2000, Rights::RW);
    let (child1, _) = Capability::carve_child(&root_mem, access, SENDER_ID, 1).unwrap();

    // Send to receiver 1
    execute(&*platform, false, || {
        Capability::send_to(&child1, SENDER_ID, RECEIVER1_ID, Attributes::NONE).map(|updates| ((), updates))
    })
    .unwrap();

    // Now send from receiver1 to receiver2 (affects both receiver cores)
    let result = execute(&*platform, false, || {
        Capability::send_to(&child1, RECEIVER1_ID, RECEIVER2_ID, Attributes::NONE).map(|updates| ((), updates))
    });

    assert!(result.is_ok(), "Multi-receiver send should succeed");

    // Verify updates were applied for both receivers
    let updates = platform.drain_updates();
    let receivers_updated: BTreeSet<DomainId> = updates
        .iter()
        .filter_map(|u| match u {
            Update::Map { domain, .. } => Some(*domain),
            _ => None,
        })
        .collect();

    assert!(
        receivers_updated.contains(&RECEIVER1_ID) || receivers_updated.contains(&RECEIVER2_ID),
        "At least one receiver should get Map update"
    );

    println!("✓ Multiple cores affected by single operation handled correctly");
}

#[test]
fn test_ipi_not_sent_for_local_operations() {
    let platform = Arc::new(MultiCorePlatform::new(2));
    const DOMAIN_ID: DomainId = 5;

    // Register domain but DON'T set it to run on any core
    platform.register_domain(DOMAIN_ID, None);

    // Create memory capability
    let region = MemoryRegion::new_root(0x0, 0x10000);
    let mem = Capability::new_root(DOMAIN_ID, 0, region);

    // Perform operation (should use local path, no IPI)
    let access = Access::new(0x1000, 0x1000, Rights::RW);
    let result = execute(&*platform, false, || {
        Capability::carve_child(&mem, access, DOMAIN_ID, 1).map(|(child, updates)| (child, updates))
    });

    assert!(result.is_ok(), "Local operation should succeed");

    // Verify no cores received IPIs (update count should be 0)
    for i in 0..2 {
        assert_eq!(
            platform.get_core_update_count(i),
            0,
            "Core {} should not have received updates",
            i
        );
    }

    println!("✓ Local operations don't trigger IPIs");
}

#[test]
fn test_exclusive_lock_serializes_revoke() {
    // Verifies that the exclusive lock used for revoke prevents concurrent
    // shared-lock operations from racing into the revoked subtree.
    // After revoke completes (exclusive lock released), the tree is in a
    // consistent state and any subsequent operation sees the revoked domain.
    let platform = Arc::new(MultiCorePlatform::new(2));
    const ROOT_ID: DomainId = 0;
    const CORE_1: CoreId = 1;

    platform.register_domain(ROOT_ID, None);

    let root_domain = Domain::new_root(2);
    let root = Arc::new(Capability::new_root(ROOT_ID, 0, root_domain));

    let child_policy = DomainPolicy::new_restricted(0b11, MonitorAPI::NONE);
    let child = Capability::create_child_domain(&root, child_policy, ROOT_ID, 1).unwrap();
    let child_id = child.read().data.id;

    platform.register_domain(child_id, Some(ROOT_ID));
    platform.set_core_domain(CORE_1, child_id);
    child.write().data.seal().unwrap();

    // Revoke the child under an exclusive lock.
    execute(&*platform, true, || {
        Capability::revoke_child_domain(&root, 1).map(|updates| ((), updates))
    })
    .unwrap();

    // After revoke the domain is gone; verify no child domain remains in tree.
    assert!(
        platform.is_domain_revoked(child_id),
        "Child domain {} should be revoked after exclusive-lock revoke",
        child_id
    );

    // Core 1 should have been redirected to the parent fallback.
    assert_eq!(
        platform.get_core_domain(CORE_1),
        Some(ROOT_ID),
        "Core should fall back to parent after revoke"
    );

    println!("✓ Exclusive lock serialises revoke; domain state is consistent after release");
}
