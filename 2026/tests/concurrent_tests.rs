//! Multi-threaded tests to verify thread-safety of the capability engine

use capability_engine::*;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[test]
fn test_concurrent_reads() {
    // Create a root domain and share it across threads
    let root_domain = Domain::new_root();
    let root = Capability::new_root(0, 0, root_domain);

    // Clone the Arc for sharing across threads
    let root_shared = Arc::new(root);

    let mut handles = vec![];

    // Spawn 10 threads that all try to read the domain concurrently
    for i in 0..10 {
        let root_clone = Arc::clone(&root_shared);
        let handle = thread::spawn(move || {
            for _ in 0..100 {
                let domain = root_clone.read();
                assert_eq!(domain.data.id, 0);
                assert!(domain.data.is_sealed());
                // Small sleep to increase chance of interleaving
                thread::sleep(Duration::from_micros(1));
            }
            println!("Thread {} completed reads", i);
        });
        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }

    println!("Concurrent reads test passed!");
}

#[test]
fn test_concurrent_child_creation() {
    // Create a root domain
    let root_domain = Domain::new_root();
    let root = Capability::new_root(0, 0, root_domain);
    let root_shared = Arc::new(root);

    let mut handles = vec![];

    // Spawn 5 threads that each try to create child domains
    for i in 0..5 {
        let root_clone = Arc::clone(&root_shared);
        let handle = thread::spawn(move || {
            let child_policy = DomainPolicy::new_restricted(0b1, MonitorAPI::NONE);

            // Each thread creates 10 children
            for j in 0..10 {
                let handle_id = (i * 10 + j) as u64;
                match Capability::create_child_domain(&root_clone, child_policy.clone(), i as u64, handle_id) {
                    Ok(child) => {
                        let child_read = child.read();
                        assert_eq!(child_read.data.policy.cores, 0b1);
                        assert!(!child_read.data.is_sealed());
                    }
                    Err(e) => panic!("Failed to create child: {}", e),
                }
            }
            println!("Thread {} created 10 children", i);
        });
        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }

    // Verify all children were created
    let children_count = root_shared.read().children.len();
    assert_eq!(children_count, 50, "Expected 50 children, got {}", children_count);

    println!("Concurrent child creation test passed! Created {} children", children_count);
}

#[test]
fn test_concurrent_memory_operations() {
    // Create a root memory region
    let root_region = MemoryRegion::new_root(0x0, 0x1000000); // 16MB
    let mem_root = Capability::new_root(0, 0, root_region);
    let mem_shared = Arc::new(mem_root);

    let mut handles = vec![];

    // Spawn threads that create aliased regions (safe to do concurrently)
    for i in 0..8 {
        let mem_clone = Arc::clone(&mem_shared);
        let handle = thread::spawn(move || {
            let base_addr = (i as u64) * 0x10000;
            for j in 0..10 {
                let addr = base_addr + (j * 0x1000);
                let access = Access::new(addr, 0x1000, Rights::RW);

                match Capability::alias_child(&mem_clone, access, i as u64, j as u64) {
                    Ok(child) => {
                        let child_read = child.read();
                        assert_eq!(child_read.data.status, RegionStatus::Aliased);
                        assert_eq!(child_read.data.access.start, addr);
                    }
                    Err(e) => panic!("Failed to alias region: {}", e),
                }
            }
            println!("Thread {} created 10 aliases", i);
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let children_count = mem_shared.read().children.len();
    assert_eq!(children_count, 80, "Expected 80 aliased children, got {}", children_count);

    println!("Concurrent memory operations test passed! Created {} aliases", children_count);
}

#[test]
fn test_concurrent_carve_operations() {
    // Create a root memory region
    let root_region = MemoryRegion::new_root(0x0, 0x100000); // 1MB
    let mem_root = Capability::new_root(0, 0, root_region);
    let mem_shared = Arc::new(mem_root);

    let mut handles = vec![];

    // Spawn threads that carve non-overlapping regions
    for i in 0..4 {
        let mem_clone = Arc::clone(&mem_shared);
        let handle = thread::spawn(move || {
            // Each thread carves from a different 256KB section
            let base = (i as u64) * 0x40000; // 256KB sections
            let access = Access::new(base, 0x10000, Rights::RWX); // Carve 64KB

            match Capability::carve_child(&mem_clone, access, i as u64, i as u64) {
                Ok((child, updates)) => {
                    let child_read = child.read();
                    assert_eq!(child_read.data.status, RegionStatus::Exclusive);
                    assert!(!updates.is_empty());
                    println!("Thread {} carved region at {:#x}", i, base);
                }
                Err(e) => panic!("Thread {} failed to carve: {}", i, e),
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let children_count = mem_shared.read().children.len();
    assert_eq!(children_count, 4, "Expected 4 carved children");

    println!("Concurrent carve test passed!");
}

#[test]
fn test_concurrent_read_write_mix() {
    let root_domain = Domain::new_root();
    let root = Capability::new_root(0, 0, root_domain);
    let root_shared = Arc::new(root);

    let mut handles = vec![];

    // Spawn reader threads
    for i in 0..5 {
        let root_clone = Arc::clone(&root_shared);
        let handle = thread::spawn(move || {
            for _ in 0..50 {
                let domain = root_clone.read();
                assert_eq!(domain.data.id, 0);
                thread::sleep(Duration::from_micros(1));
            }
            println!("Reader thread {} done", i);
        });
        handles.push(handle);
    }

    // Spawn writer threads (adding children)
    for i in 0..3 {
        let root_clone = Arc::clone(&root_shared);
        let handle = thread::spawn(move || {
            for j in 0..10 {
                let child_policy = DomainPolicy::new_restricted(0b1, MonitorAPI::NONE);
                let handle_id = (i * 10 + j) as u64;
                match Capability::create_child_domain(&root_clone, child_policy, i as u64, handle_id) {
                    Ok(_) => {
                        thread::sleep(Duration::from_micros(2));
                    }
                    Err(e) => panic!("Writer {} failed: {}", i, e),
                }
            }
            println!("Writer thread {} done", i);
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let children_count = root_shared.read().children.len();
    assert_eq!(children_count, 30);

    println!("Concurrent read-write mix test passed!");
}

#[test]
fn test_concurrent_revocation() {
    // Create root with multiple children
    let root_domain = Domain::new_root();
    let root = Capability::new_root(0, 0, root_domain);
    let root_shared = Arc::new(root);

    // First, create children sequentially
    let mut child_handles = vec![];
    for i in 0..10 {
        let child_policy = DomainPolicy::new_restricted(0b1, MonitorAPI::NONE);
        let _child = Capability::create_child_domain(&root_shared, child_policy, i, i).unwrap();
        child_handles.push(i);
    }

    println!("Created 10 children, now testing concurrent revocation");

    let mut handles = vec![];

    // Spawn threads that try to revoke different children concurrently
    for i in 0..5 {
        let root_clone = Arc::clone(&root_shared);
        let child_handle = child_handles[i];
        let handle = thread::spawn(move || {
            match Capability::revoke_child_domain(&root_clone, child_handle) {
                Ok(updates) => {
                    println!("Thread {} successfully revoked child {}, updates: {}", i, child_handle, updates.len());
                }
                Err(e) => {
                    println!("Thread {} failed to revoke child {}: {}", i, child_handle, e);
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    // Verify that 5 children were revoked
    let remaining = root_shared.read().children.len();
    assert_eq!(remaining, 5, "Expected 5 remaining children, got {}", remaining);

    println!("Concurrent revocation test passed! {} children remaining", remaining);
}

#[test]
fn test_memory_view_computation_concurrent() {
    // Create root region
    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let mem_root = Capability::new_root(0, 0, root_region);
    let mem_shared = Arc::new(mem_root);

    // Carve some regions first
    let _child1 = Capability::carve_child(&mem_shared, Access::new(0x1000, 0x1000, Rights::RW), 1, 1).unwrap();
    let _child2 = Capability::carve_child(&mem_shared, Access::new(0x3000, 0x1000, Rights::RW), 1, 2).unwrap();

    let mut handles = vec![];

    // Spawn threads that all compute the view concurrently
    for i in 0..10 {
        let mem_clone = Arc::clone(&mem_shared);
        let handle = thread::spawn(move || {
            for _ in 0..100 {
                let mem = mem_clone.read();
                let view = mem.compute_view();

                // View should exclude the two carved regions
                assert!(view.len() >= 2); // Should be split around carved regions

                thread::sleep(Duration::from_micros(1));
            }
            println!("Thread {} completed view computations", i);
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    println!("Concurrent view computation test passed!");
}

#[test]
fn test_attestation_concurrent() {
    let root_domain = Domain::new_root();
    let root = Capability::new_root(0, 0, root_domain);
    let root_shared = Arc::new(root);

    // Create some children
    for i in 0..5 {
        let child_policy = DomainPolicy::new_restricted(0b1, MonitorAPI::NONE);
        let _child = Capability::create_child_domain(&root_shared, child_policy, i, i).unwrap();
    }

    let mut handles = vec![];

    // Spawn threads that all generate attestations concurrently
    for i in 0..10 {
        let root_clone = Arc::clone(&root_shared);
        let handle = thread::spawn(move || {
            for _ in 0..50 {
                let report = attest_domain(&root_clone);
                assert!(report.report.contains("Domain ID"));
                assert!(report.report.contains("Status"));
                thread::sleep(Duration::from_micros(1));
            }
            println!("Thread {} completed attestations", i);
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    println!("Concurrent attestation test passed!");
}

#[test]
fn test_stress_test_mixed_operations() {
    println!("\n=== Running stress test with mixed operations ===");

    let root_domain = Domain::new_root();
    let root = Capability::new_root(0, 0, root_domain);
    let root_shared = Arc::new(root);

    let root_region = MemoryRegion::new_root(0x0, 0x10000000); // 256MB
    let mem_root = Capability::new_root(0, 1, root_region);
    let mem_shared = Arc::new(mem_root);

    let mut handles = vec![];

    // Readers
    for _i in 0..5 {
        let root_clone = Arc::clone(&root_shared);
        let handle = thread::spawn(move || {
            for _ in 0..100 {
                let _domain = root_clone.read();
                thread::yield_now();
            }
        });
        handles.push(handle);
    }

    // Domain creators
    for i in 0..3 {
        let root_clone = Arc::clone(&root_shared);
        let handle = thread::spawn(move || {
            for j in 0..20 {
                let child_policy = DomainPolicy::new_restricted(0b1111, MonitorAPI::NONE);
                let _ = Capability::create_child_domain(&root_clone, child_policy, i as u64, (i * 20 + j) as u64);
                thread::yield_now();
            }
        });
        handles.push(handle);
    }

    // Memory aliasers
    for i in 0..4 {
        let mem_clone = Arc::clone(&mem_shared);
        let handle = thread::spawn(move || {
            let base = (i as u64) * 0x100000;
            for j in 0..15 {
                let addr = base + (j * 0x10000);
                let access = Access::new(addr, 0x1000, Rights::RW);
                let _ = Capability::alias_child(&mem_clone, access, i as u64, j as u64);
                thread::yield_now();
            }
        });
        handles.push(handle);
    }

    // Attestation generators
    for _i in 0..3 {
        let root_clone = Arc::clone(&root_shared);
        let handle = thread::spawn(move || {
            for _ in 0..50 {
                let _ = attest_domain(&root_clone);
                thread::yield_now();
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let domain_children = root_shared.read().children.len();
    let mem_children = mem_shared.read().children.len();

    println!("Stress test completed!");
    println!("  Domain children created: {}", domain_children);
    println!("  Memory children created: {}", mem_children);

    assert!(domain_children > 0);
    assert!(mem_children > 0);
}
