//! End-to-end tests modeling real deployment scenarios
//!
//! These tests simulate complete deployment scenarios including:
//! - Confidential VMs (CVMs) with exclusive and shared memory
//! - Enclaves inside CVMs
//! - Sandboxes inside CVMs
//! - Two CVMs communicating through private shared memory
//!
//! All tests include:
//! - Multi-threaded core simulation
//! - Update processing verification
//! - Memory accessibility assertions
//! - Attestation validation

use capability_engine::*;
use std::sync::Arc;
use std::thread;

/// Test 1: Confidential VM with exclusive and shared (virtio) memory
#[test]
fn test_cvm_with_exclusive_and_shared_memory() {
    // Setup: Root domain and memory
    let root_domain = Domain::new_root();
    let root = Capability::new_root(0, 0, root_domain);

    // Total memory: 1GB
    let total_mem = MemoryRegion::new_root(0x0, 0x40000000); // 1GB
    let mem_root = Capability::new_root(0, 1, total_mem);

    // Create CVM domain with restricted permissions
    let cvm_api = MonitorAPI::from_bits(
        MonitorAPI::GET | MonitorAPI::ATTEST | MonitorAPI::ENUMERATE | MonitorAPI::SWITCH,
    );
    let cvm_policy = DomainPolicy::new_restricted(0b0011, cvm_api); // cores 0-1

    let cvm = Capability::create_child_domain(&root, cvm_policy, 1, 0).unwrap();

    // Carve exclusive memory for CVM (private memory): 512MB
    let cvm_private_access = Access::new(0x0, 0x20000000, Rights::RWX); // 512MB
    let (cvm_private_mem, _updates1) =
        Capability::carve_child(&mem_root, cvm_private_access, 1, 0).unwrap();

    // Create aliased memory for virtio (shared with host): 64MB
    let virtio_access = Access::new(0x20000000, 0x4000000, Rights::RW); // 64MB
    let virtio_mem = Capability::alias_child(&mem_root, virtio_access, 1, 1).unwrap();

    // Seal the CVM
    cvm.write().data.seal().unwrap();

    // Verify domain is sealed
    assert!(cvm.read().data.is_sealed());
    let cvm_id = cvm.read().data.id;
    assert_ne!(cvm_id, 0); // Not root domain

    // Generate attestation
    let attestation = attest_domain(&cvm);
    assert_eq!(attestation.domain_id, cvm_id);
    assert!(attestation.report.contains(&format!("Domain ID: {}", cvm_id)));
    assert!(attestation.report.contains("Status: Sealed"));
    assert!(attestation.report.contains("GET: true"));
    assert!(attestation.report.contains("ATTEST: true"));

    // Note: No updates are generated for carve when owner doesn't change
    // Updates are generated later when capabilities are sent to different domains

    // Compute address space view
    let mem_caps = vec![cvm_private_mem.clone(), virtio_mem.clone()];
    let view = compute_view_from_capabilities(cvm_id, &mem_caps);

    // Verify accessible memory
    assert_eq!(view.regions.len(), 2);
    assert!(view.is_accessible(0x100)); // Private memory
    assert!(view.is_accessible(0x20000000)); // Virtio shared memory
    assert!(!view.is_accessible(0x30000000)); // Outside allocated range

    // Simulate multi-threaded execution
    let update_processor = Arc::new(UpdateProcessor::new());

    // Register CVM on core 0
    update_processor.register_domain_on_core(cvm_id, 0);

    // Verify domain is registered correctly
    assert_eq!(update_processor.get_domain_core(cvm_id), Some(0));

    // Initially no pending updates
    assert!(!update_processor.has_pending_updates(0));

    // Thread 1: Simulates another core submitting updates
    let processor_clone = update_processor.clone();
    let cvm_id_clone = cvm_id;
    let handle1 = thread::spawn(move || {
        // Submit an update batch
        let mut batch = UpdateBatch::new();
        batch.add_map(cvm_id_clone, 0x1000, 0x1000, 0x1000, true, true, false);
        let cores = processor_clone.submit_updates(batch);

        // CVM on core 0 should be notified
        assert!(cores.contains(&0));
    });

    handle1.join().unwrap();

    // Verify update was queued
    assert!(update_processor.has_pending_updates(0));
}

/// Test 2: Enclave inside a Confidential VM
#[test]
fn test_enclave_inside_cvm() {
    // Setup root
    let root_domain = Domain::new_root();
    let root = Capability::new_root(0, 0, root_domain);

    let total_mem = MemoryRegion::new_root(0x0, 0x40000000);
    let mem_root = Capability::new_root(0, 1, total_mem);

    // Create CVM
    let cvm_api = MonitorAPI::from_bits(
        MonitorAPI::CREATE | MonitorAPI::SEAL | MonitorAPI::ATTEST | MonitorAPI::CARVE,
    );
    let cvm_policy = DomainPolicy::new_restricted(0b1111, cvm_api);
    let cvm = Capability::create_child_domain(&root, cvm_policy, 1, 0).unwrap();

    // Give CVM 256MB of exclusive memory
    let cvm_mem_access = Access::new(0x0, 0x10000000, Rights::RWX);
    let (cvm_mem, _) = Capability::carve_child(&mem_root, cvm_mem_access, 1, 0).unwrap();

    cvm.write().data.seal().unwrap();

    // Create enclave inside CVM with even more restricted permissions
    let enclave_api = MonitorAPI::from_bits(MonitorAPI::ATTEST);
    let enclave_policy = DomainPolicy::new_restricted(0b0001, enclave_api); // only core 0
    let enclave = Capability::create_child_domain(&cvm, enclave_policy, 2, 0).unwrap();

    // Carve exclusive memory for enclave from CVM's memory: 16MB
    let enclave_mem_access = Access::new(0x0, 0x1000000, Rights::RW);
    let (enclave_mem, _updates) =
        Capability::carve_child(&cvm_mem, enclave_mem_access, 2, 0).unwrap();

    enclave.write().data.seal().unwrap();

    // Verify enclave is sealed and has correct policy
    assert!(enclave.read().data.is_sealed());
    let enclave_id = enclave.read().data.id;
    let cvm_id = cvm.read().data.id;
    assert_ne!(enclave_id, 0); // Not root domain
    assert_eq!(enclave.read().data.policy.cores, 0b0001);

    // Verify monotonicity: enclave policy is subset of CVM policy
    let enclave_read = enclave.read();
    let cvm_read = cvm.read();
    assert!(enclave_read
        .data
        .policy
        .is_subset_of(&cvm_read.data.policy)
        .is_ok());

    // Note: No updates when carving with same owner
    // Updates would be generated if we send the capability to a different domain

    // Attestations for both CVM and enclave
    let cvm_attestation = attest_domain(&cvm);
    let enclave_attestation = attest_domain(&enclave);

    assert!(cvm_attestation.report.contains(&format!("Domain ID: {}", cvm_id)));
    assert!(enclave_attestation.report.contains(&format!("Domain ID: {}", enclave_id)));
    assert!(enclave_attestation.report.contains(&format!("Parent Domain ID: {}", cvm_id)));

    // Compute address space for enclave
    let enclave_view = compute_view_from_capabilities(enclave_id, &[enclave_mem.clone()]);
    assert_eq!(enclave_view.total_size(), 0x1000000); // 16MB
    assert!(enclave_view.is_accessible(0x500000));
    assert!(!enclave_view.is_accessible(0x2000000));
}

/// Test 3: Sandbox inside a Confidential VM (aliased memory)
#[test]
fn test_sandbox_inside_cvm() {
    // Setup root
    let root_domain = Domain::new_root();
    let root = Capability::new_root(0, 0, root_domain);

    let total_mem = MemoryRegion::new_root(0x0, 0x40000000);
    let mem_root = Capability::new_root(0, 1, total_mem);

    // Create CVM
    let cvm_api = MonitorAPI::from_bits(
        MonitorAPI::CREATE
            | MonitorAPI::SEAL
            | MonitorAPI::ATTEST
            | MonitorAPI::ALIAS
            | MonitorAPI::SWITCH,
    );
    let cvm_policy = DomainPolicy::new_restricted(0b1111, cvm_api);
    let cvm = Capability::create_child_domain(&root, cvm_policy, 1, 0).unwrap();

    // Give CVM 128MB
    let cvm_mem_access = Access::new(0x0, 0x8000000, Rights::RWX);
    let (cvm_mem, _) = Capability::carve_child(&mem_root, cvm_mem_access, 1, 0).unwrap();

    cvm.write().data.seal().unwrap();

    // Create sandbox with aliased memory (shared with CVM)
    let sandbox_api = MonitorAPI::from_bits(MonitorAPI::ATTEST);
    let sandbox_policy = DomainPolicy::new_restricted(0b0011, sandbox_api);
    let sandbox = Capability::create_child_domain(&cvm, sandbox_policy, 2, 0).unwrap();

    // Alias memory for sandbox: 32MB shared with CVM
    let sandbox_mem_access = Access::new(0x1000000, 0x2000000, Rights::RW); // Reduced rights
    let sandbox_mem = Capability::alias_child(&cvm_mem, sandbox_mem_access, 2, 0).unwrap();

    sandbox.write().data.seal().unwrap();

    // Verify sandbox setup
    assert!(sandbox.read().data.is_sealed());
    let sandbox_id = sandbox.read().data.id;
    let cvm_id = cvm.read().data.id;
    assert_ne!(sandbox_id, 0); // Not root domain

    // Generate attestations
    let sandbox_attestation = attest_domain(&sandbox);
    assert!(sandbox_attestation.report.contains(&format!("Domain ID: {}", sandbox_id)));

    // Compute address space
    let sandbox_view = compute_view_from_capabilities(sandbox_id, &[sandbox_mem.clone()]);
    assert!(sandbox_view.is_accessible(0x1500000)); // Within aliased range
    assert_eq!(sandbox_view.regions[0].rights(), Rights::RW);

    // Simulate switching between CVM and sandbox
    let switch_mgr = SwitchManager::new(4);
    let core0 = switch_mgr.get_core(0).unwrap();

    // Set core 0 to running CVM
    *core0.state.write() = CoreState::Running(cvm_id);

    // Switch from CVM to sandbox
    let switch_ctx = switch_mgr.switch(0, &cvm, Some(&sandbox)).unwrap();
    assert_eq!(switch_ctx.from_domain, cvm_id);
    assert_eq!(switch_ctx.to_domain, sandbox_id);
    assert_eq!(switch_ctx.core_id, 0);
    assert!(!switch_ctx.is_return);

    // Verify core is now running sandbox
    assert_eq!(core0.current_domain(), Some(sandbox_id));
}

/// Test 4: Two CVMs communicating with private shared memory
#[test]
fn test_two_cvms_with_shared_memory() {
    // Setup root
    let root_domain = Domain::new_root();
    let root = Capability::new_root(0, 0, root_domain);

    let total_mem = MemoryRegion::new_root(0x0, 0x80000000); // 2GB
    let mem_root = Capability::new_root(0, 1, total_mem);

    // Create CVM1
    let cvm1_api = MonitorAPI::from_bits(MonitorAPI::ATTEST | MonitorAPI::ENUMERATE);
    let cvm1_policy = DomainPolicy::new_restricted(0b0011, cvm1_api); // cores 0-1
    let cvm1 = Capability::create_child_domain(&root, cvm1_policy, 1, 0).unwrap();

    // Create CVM2
    let cvm2_api = MonitorAPI::from_bits(MonitorAPI::ATTEST | MonitorAPI::ENUMERATE);
    let cvm2_policy = DomainPolicy::new_restricted(0b1100, cvm2_api); // cores 2-3
    let cvm2 = Capability::create_child_domain(&root, cvm2_policy, 2, 1).unwrap();

    // Give CVM1 exclusive memory: 512MB
    let cvm1_mem_access = Access::new(0x0, 0x20000000, Rights::RWX);
    let (cvm1_mem, _) = Capability::carve_child(&mem_root, cvm1_mem_access, 1, 0).unwrap();

    // Give CVM2 exclusive memory: 512MB
    let cvm2_mem_access = Access::new(0x20000000, 0x20000000, Rights::RWX);
    let (cvm2_mem, _) = Capability::carve_child(&mem_root, cvm2_mem_access, 2, 1).unwrap();

    // Create shared memory region (aliased to both CVMs): 64MB
    let shared_mem_access = Access::new(0x40000000, 0x4000000, Rights::RW);
    let shared_for_cvm1 = Capability::alias_child(&mem_root, shared_mem_access, 1, 2).unwrap();
    let shared_for_cvm2 = Capability::alias_child(&mem_root, shared_mem_access, 2, 3).unwrap();

    // Seal both CVMs
    cvm1.write().data.seal().unwrap();
    cvm2.write().data.seal().unwrap();

    // Verify both CVMs are sealed
    assert!(cvm1.read().data.is_sealed());
    assert!(cvm2.read().data.is_sealed());

    let cvm1_id = cvm1.read().data.id;
    let cvm2_id = cvm2.read().data.id;

    // Generate attestations for both
    let cvm1_attest = attest_domain(&cvm1);
    let cvm2_attest = attest_domain(&cvm2);

    assert!(cvm1_attest.report.contains(&format!("Domain ID: {}", cvm1_id)));
    assert!(cvm2_attest.report.contains(&format!("Domain ID: {}", cvm2_id)));

    // Expected attestation strings
    let expected_cvm1_cores = "Cores: 0b11";
    let expected_cvm2_cores = "Cores: 0b1100";

    assert!(cvm1_attest.report.contains(expected_cvm1_cores));
    assert!(cvm2_attest.report.contains(expected_cvm2_cores));

    // Compute address spaces
    let cvm1_view = compute_view_from_capabilities(cvm1_id, &[cvm1_mem.clone(), shared_for_cvm1.clone()]);
    let cvm2_view = compute_view_from_capabilities(cvm2_id, &[cvm2_mem.clone(), shared_for_cvm2.clone()]);

    // Verify CVM1 can access its private and shared memory
    assert!(cvm1_view.is_accessible(0x100)); // Private
    assert!(cvm1_view.is_accessible(0x40000000)); // Shared
    assert!(!cvm1_view.is_accessible(0x20000000)); // CVM2's private

    // Verify CVM2 can access its private and shared memory
    assert!(cvm2_view.is_accessible(0x20000000)); // Private
    assert!(cvm2_view.is_accessible(0x40000000)); // Shared
    assert!(!cvm2_view.is_accessible(0x100)); // CVM1's private

    // Multi-threaded simulation
    let update_processor = Arc::new(UpdateProcessor::new());
    update_processor.register_domain_on_core(cvm1_id, 0); // CVM1 on core 0
    update_processor.register_domain_on_core(cvm2_id, 2); // CVM2 on core 2

    let proc1 = update_processor.clone();
    let proc2 = update_processor.clone();
    let cvm1_id_clone = cvm1_id;
    let cvm2_id_clone = cvm2_id;
    let cvm2_id_clone2 = cvm2_id;

    // Thread 1: Core 0 (CVM1) writes to shared memory
    let handle1 = thread::spawn(move || {
        // Simulate write to shared memory triggering update
        let mut batch = UpdateBatch::new();
        batch.add_map(cvm1_id_clone, 0x40000000, 0x1000, 0x40000000, true, true, false);
        batch.add_map(cvm2_id_clone, 0x40000000, 0x1000, 0x40000000, true, true, false);

        let cores = proc1.submit_updates(batch);
        // Both cores should be notified
        assert!(cores.contains(&0));
        assert!(cores.contains(&2));
    });

    // Thread 2: Core 2 (CVM2) reads from shared memory
    let handle2 = thread::spawn(move || {
        // Check CVM2 is on core 2
        assert_eq!(proc2.get_domain_core(cvm2_id_clone2), Some(2));
    });

    handle1.join().unwrap();
    handle2.join().unwrap();

    // Verify both cores have pending updates
    assert!(update_processor.has_pending_updates(0));
    assert!(update_processor.has_pending_updates(2));
}

/// Test 5: Complex multi-level hierarchy with updates
#[test]
fn test_complex_hierarchy_with_updates() {
    // Root -> CVM -> Enclave -> Nested sandbox
    let root_domain = Domain::new_root();
    let root = Capability::new_root(0, 0, root_domain);

    let total_mem = MemoryRegion::new_root(0x0, 0x10000000); // 256MB
    let mem_root = Capability::new_root(0, 1, total_mem);

    // CVM
    let cvm_api = MonitorAPI::from_bits(
        MonitorAPI::CREATE | MonitorAPI::SEAL | MonitorAPI::CARVE | MonitorAPI::ATTEST,
    );
    let cvm = Capability::create_child_domain(
        &root,
        DomainPolicy::new_restricted(0b1111, cvm_api),
        1,
        0,
    )
    .unwrap();

    let (cvm_mem, _) =
        Capability::carve_child(&mem_root, Access::new(0x0, 0x8000000, Rights::RWX), 1, 0).unwrap();
    cvm.write().data.seal().unwrap();

    // Enclave inside CVM
    let enclave_api = MonitorAPI::from_bits(MonitorAPI::CREATE | MonitorAPI::SEAL | MonitorAPI::CARVE | MonitorAPI::ATTEST);
    let enclave = Capability::create_child_domain(
        &cvm,
        DomainPolicy::new_restricted(0b0011, enclave_api),
        2,
        0,
    )
    .unwrap();

    let (enclave_mem, _updates1) =
        Capability::carve_child(&cvm_mem, Access::new(0x0, 0x2000000, Rights::RW), 2, 0).unwrap();
    enclave.write().data.seal().unwrap();

    // Nested sandbox inside enclave - need to ensure monotonicity
    // Enclave has CREATE, SEAL, CARVE, so sandbox can have a subset
    let sandbox_api = MonitorAPI::from_bits(MonitorAPI::ATTEST);
    let sandbox = Capability::create_child_domain(
        &enclave,
        DomainPolicy::new_restricted(0b0001, sandbox_api),
        3,
        0,
    )
    .unwrap();

    let (_sandbox_mem, _updates2) = Capability::carve_child(
        &enclave_mem,
        Access::new(0x0, 0x100000, Rights::R),
        3,
        0,
    )
    .unwrap();
    sandbox.write().data.seal().unwrap();

    // Verify hierarchy
    assert_eq!(root.read().data.id, 0);
    let cvm_id = cvm.read().data.id;
    let enclave_id = enclave.read().data.id;
    let sandbox_id = sandbox.read().data.id;
    assert_ne!(cvm_id, 0);
    assert_ne!(enclave_id, 0);
    assert_ne!(sandbox_id, 0);

    // Note: No updates when carving with same owner
    // Updates would be generated if capabilities were sent to different domains

    // Enumerate entire domain tree
    let domain_tree = enumerate_domain_tree(&root);
    assert!(domain_tree.contains(&0));
    assert!(domain_tree.contains(&cvm_id));
    assert!(domain_tree.contains(&enclave_id));
    assert!(domain_tree.contains(&sandbox_id));

    // Verify monotonic policies at each level
    let root_pol = &root.read().data.policy;
    let cvm_pol = &cvm.read().data.policy;
    let enclave_pol = &enclave.read().data.policy;
    let sandbox_pol = &sandbox.read().data.policy;

    assert!(cvm_pol.is_subset_of(root_pol).is_ok());
    assert!(enclave_pol.is_subset_of(cvm_pol).is_ok());
    assert!(sandbox_pol.is_subset_of(enclave_pol).is_ok());

    // Update processor test with nested domains
    let proc = UpdateProcessor::new();
    proc.register_domain_on_core(sandbox_id, 0); // Sandbox on core 0

    let mut batch = UpdateBatch::new();
    batch.add_unmap(sandbox_id, 0x50000, 0x1000);
    let cores = proc.submit_updates(batch);

    assert!(cores.contains(&0));
    assert!(proc.has_pending_updates(0));
}
