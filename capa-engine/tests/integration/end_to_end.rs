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

use capability_engine::memory::Rights;
use capability_engine::*;
use std::sync::Arc;
use std::thread;

#[path = "../common/mod.rs"]
mod common;

/// Test 1: Confidential VM with exclusive and shared (virtio) memory
#[test]
fn test_cvm_with_exclusive_and_shared_memory() {
    let platform = common::TestPlatform::new();
    // Bootstrap: root domain (already sealed by new_root) + memory root
    let root_domain = Domain::new_root(4);
    let root = Capability::new_root(0, 0, root_domain);
    let total_mem = MemoryRegion::new_root(0x0, 0x40000000); // 1GB
    let mem_root = Capability::new_root(0, 1, total_mem);
    root.write()
        .data
        .add_memory_capability(1, Arc::downgrade(&mem_root));
    let mem_root_h: LocalHandle = 1;

    // Create CVM domain with restricted permissions
    let cvm_api = MonitorAPI::from_bits(
        MonitorAPI::GET | MonitorAPI::ATTEST | MonitorAPI::ENUMERATE | MonitorAPI::SWITCH,
    );
    let cvm_policy = DomainPolicy::new_restricted(0b0011, cvm_api); // cores 0-1
    let cvm_h = Capability::create(&platform, &root, cvm_policy).unwrap().0;
    let cvm = root.read().data.domain_capabilities[&cvm_h]
        .upgrade()
        .unwrap();

    // Carve exclusive memory for CVM (private memory): 512MB
    let cvm_private_access = Access::new(0x0, 0x20000000, Rights::RWX);
    let (cvm_private_mem_h, _, _updates1) =
        Capability::carve(&platform, &root, mem_root_h, cvm_private_access).unwrap();
    let cvm_private_mem = root.read().data.memory_capabilities[&cvm_private_mem_h]
        .upgrade()
        .unwrap();

    // Create aliased memory for virtio (shared with host): 64MB
    let virtio_access = Access::new(0x20000000, 0x4000000, Rights::RW);
    let (virtio_mem_h, _, _)= Capability::alias(&platform, &root, mem_root_h, virtio_access).unwrap();
    let virtio_mem = root.read().data.memory_capabilities[&virtio_mem_h]
        .upgrade()
        .unwrap();

    // Seal the CVM
    Capability::seal(&platform, &root, cvm_h).unwrap();

    // Verify domain is sealed
    assert!(cvm.read().data.is_sealed());
    let cvm_id = cvm.read().data.id;
    assert_ne!(cvm_id, 0); // Not root domain

    // Generate attestation
    let attestation = attest_domain(&cvm);
    assert_eq!(attestation.domain_id, cvm_id);
    assert!(attestation
        .report
        .contains(&format!("Domain ID: {}", cvm_id)));
    assert!(attestation.report.contains("Status: Sealed"));
    assert!(attestation.report.contains("GET: true"));
    assert!(attestation.report.contains("ATTEST: true"));

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
        let mut batch = UpdateBatch::new();
        batch.add_change_rights(cvm_id_clone, 0x1000, 0x1000, 0x1000, Rights::RW, false);
        let cores = processor_clone.submit_updates(batch);
        assert!(cores.contains(&0));
    });

    handle1.join().unwrap();

    // Verify update was queued
    assert!(update_processor.has_pending_updates(0));
}

/// Test 2: Enclave inside a Confidential VM
#[test]
fn test_enclave_inside_cvm() {
    let platform = common::TestPlatform::new();
    // Bootstrap
    let root_domain = Domain::new_root(4);
    let root = Capability::new_root(0, 0, root_domain);
    let total_mem = MemoryRegion::new_root(0x0, 0x40000000);
    let mem_root = Capability::new_root(0, 1, total_mem);
    root.write()
        .data
        .add_memory_capability(1, Arc::downgrade(&mem_root));
    let mem_root_h: LocalHandle = 1;

    // Create CVM
    let cvm_api = MonitorAPI::from_bits(
        MonitorAPI::CREATE | MonitorAPI::SEAL | MonitorAPI::ATTEST | MonitorAPI::CARVE,
    );
    let cvm_policy = DomainPolicy::new_restricted(0b1111, cvm_api);
    let cvm_h = Capability::create(&platform, &root, cvm_policy).unwrap().0;
    let cvm = root.read().data.domain_capabilities[&cvm_h]
        .upgrade()
        .unwrap();

    // Give CVM 256MB of exclusive memory
    let cvm_mem_access = Access::new(0x0, 0x10000000, Rights::RWX);
    let (cvm_mem_h, _, _) = Capability::carve(&platform, &root, mem_root_h, cvm_mem_access).unwrap();

    // Seal CVM
    Capability::seal(&platform, &root, cvm_h).unwrap();

    // Create enclave inside CVM with even more restricted permissions
    let enclave_api = MonitorAPI::from_bits(MonitorAPI::ATTEST);
    let enclave_policy = DomainPolicy::new_restricted(0b0001, enclave_api); // only core 0
    let enclave_h = Capability::create(&platform, &cvm, enclave_policy).unwrap().0;
    let enclave = cvm.read().data.domain_capabilities[&enclave_h]
        .upgrade()
        .unwrap();

    // Carve exclusive memory for enclave from CVM's memory: 16MB
    let enclave_mem_access = Access::new(0x0, 0x1000000, Rights::RW);
    let (enclave_mem_h, _, _updates) =
        Capability::carve(&platform, &root, cvm_mem_h, enclave_mem_access).unwrap();
    let enclave_mem = root.read().data.memory_capabilities[&enclave_mem_h]
        .upgrade()
        .unwrap();

    // Seal enclave
    Capability::seal(&platform, &cvm, enclave_h).unwrap();

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

    // Attestations for both CVM and enclave
    let cvm_attestation = attest_domain(&cvm);
    let enclave_attestation = attest_domain(&enclave);

    assert!(cvm_attestation
        .report
        .contains(&format!("Domain ID: {}", cvm_id)));
    assert!(enclave_attestation
        .report
        .contains(&format!("Domain ID: {}", enclave_id)));
    assert!(enclave_attestation
        .report
        .contains(&format!("Parent Domain ID: {}", cvm_id)));

    // Compute address space for enclave
    let enclave_view = compute_view_from_capabilities(enclave_id, &[enclave_mem.clone()]);
    assert_eq!(enclave_view.total_size(), 0x1000000); // 16MB
    assert!(enclave_view.is_accessible(0x500000));
    assert!(!enclave_view.is_accessible(0x2000000));
}

/// Test 3: Sandbox inside a Confidential VM (aliased memory)
#[test]
fn test_sandbox_inside_cvm() {
    let platform = common::TestPlatform::new();
    // Bootstrap
    let root_domain = Domain::new_root(4);
    let root = Capability::new_root(0, 0, root_domain);
    let total_mem = MemoryRegion::new_root(0x0, 0x40000000);
    let mem_root = Capability::new_root(0, 1, total_mem);
    root.write()
        .data
        .add_memory_capability(1, Arc::downgrade(&mem_root));
    let mem_root_h: LocalHandle = 1;

    // Create CVM
    let cvm_api = MonitorAPI::from_bits(
        MonitorAPI::CREATE
            | MonitorAPI::SEAL
            | MonitorAPI::ATTEST
            | MonitorAPI::ALIAS
            | MonitorAPI::SWITCH,
    );
    let cvm_policy = DomainPolicy::new_restricted(0b1111, cvm_api);
    let cvm_h = Capability::create(&platform, &root, cvm_policy).unwrap().0;
    let cvm = root.read().data.domain_capabilities[&cvm_h]
        .upgrade()
        .unwrap();

    // Add VPs to CVM (must happen before seal)
    for _ in 0..4u64 {
        cvm.write().data.add_vprocessor().unwrap();
    }

    // Give CVM 128MB
    let cvm_mem_access = Access::new(0x0, 0x8000000, Rights::RWX);
    let (cvm_mem_h, _, _) = Capability::carve(&platform, &root, mem_root_h, cvm_mem_access).unwrap();

    // Seal CVM
    Capability::seal(&platform, &root, cvm_h).unwrap();

    // Create sandbox with aliased memory (shared with CVM)
    let sandbox_api = MonitorAPI::from_bits(MonitorAPI::ATTEST);
    let sandbox_policy = DomainPolicy::new_restricted(0b0011, sandbox_api);
    let sandbox_h = Capability::create(&platform, &cvm, sandbox_policy).unwrap().0;
    let sandbox = cvm.read().data.domain_capabilities[&sandbox_h]
        .upgrade()
        .unwrap();

    // Add VPs to sandbox (must happen before seal)
    for _ in 0..2u64 {
        sandbox.write().data.add_vprocessor().unwrap();
    }

    // Alias memory for sandbox: 32MB shared with CVM
    let sandbox_mem_access = Access::new(0x1000000, 0x2000000, Rights::RW); // Reduced rights
    let (sandbox_mem_h, _, _)=
        Capability::alias(&platform, &root, cvm_mem_h, sandbox_mem_access).unwrap();
    let sandbox_mem = root.read().data.memory_capabilities[&sandbox_mem_h]
        .upgrade()
        .unwrap();

    // Seal sandbox
    Capability::seal(&platform, &cvm, sandbox_h).unwrap();

    // Verify sandbox setup
    assert!(sandbox.read().data.is_sealed());
    let sandbox_id = sandbox.read().data.id;
    let cvm_id = cvm.read().data.id;
    assert_ne!(sandbox_id, 0); // Not root domain

    // Generate attestations
    let sandbox_attestation = attest_domain(&sandbox);
    assert!(sandbox_attestation
        .report
        .contains(&format!("Domain ID: {}", sandbox_id)));

    // Compute address space
    let sandbox_view = compute_view_from_capabilities(sandbox_id, &[sandbox_mem.clone()]);
    assert!(sandbox_view.is_accessible(0x1500000)); // Within aliased range
    assert_eq!(sandbox_view.regions[0].rights(), Rights::RW);

    // Simulate VP-aware switching between CVM and sandbox.
    let platform = common::TestPlatform::new();
    platform.register_domain(cvm_id, None);
    platform.register_domain(sandbox_id, Some(cvm_id));
    platform.set_core_context(0, &cvm, 0);
    platform.set_current_core(Some(0));

    // Initialise CVM VP[0] as Running on core 0
    {
        let c = cvm.read();
        let vp0 = c.data.policy.vprocessor_states[0].clone();
        drop(c);
        *vp0.run_state.write() = VpRunState::Running {
            core: 0,
            caller: None,
        };
    }

    // VP-aware switch from CVM to sandbox (sandbox VP[0])
    let switch_ctx = Capability::switch(&platform, &cvm, sandbox_h, 0).unwrap().0;
    assert_eq!(switch_ctx.from_domain.as_ref().unwrap().read().data.id, cvm_id);
    assert_eq!(switch_ctx.to_domain.read().data.id, sandbox_id);
    assert_eq!(switch_ctx.core_id, 0);
    assert!(!switch_ctx.is_return);
    assert_eq!(switch_ctx.from_vp_id, Some(0));
    assert_eq!(switch_ctx.to_vp_id, Some(0));

    // Platform tracking updated — core 0 now runs sandbox
    assert_eq!(platform.get_core_domain(0), Some(sandbox_id));

    // VP-aware return from sandbox back to CVM
    let ret_ctx = Capability::switch(&platform, &sandbox, 0, 0).unwrap().0;
    assert_eq!(ret_ctx.from_domain.as_ref().unwrap().read().data.id, sandbox_id);
    assert_eq!(ret_ctx.to_domain.read().data.id, cvm_id);
    assert!(ret_ctx.is_return);
}

/// Test 4: Two CVMs communicating with private shared memory
#[test]
fn test_two_cvms_with_shared_memory() {
    let platform = common::TestPlatform::new();
    // Bootstrap
    let root_domain = Domain::new_root(4);
    let root = Capability::new_root(0, 0, root_domain);
    let total_mem = MemoryRegion::new_root(0x0, 0x80000000); // 2GB
    let mem_root = Capability::new_root(0, 1, total_mem);
    root.write()
        .data
        .add_memory_capability(1, Arc::downgrade(&mem_root));
    let mem_root_h: LocalHandle = 1;

    // Create CVM1
    let cvm1_api = MonitorAPI::from_bits(MonitorAPI::ATTEST | MonitorAPI::ENUMERATE);
    let cvm1_policy = DomainPolicy::new_restricted(0b0011, cvm1_api); // cores 0-1
    let cvm1_h = Capability::create(&platform, &root, cvm1_policy).unwrap().0;
    let cvm1 = root.read().data.domain_capabilities[&cvm1_h]
        .upgrade()
        .unwrap();

    // Create CVM2
    let cvm2_api = MonitorAPI::from_bits(MonitorAPI::ATTEST | MonitorAPI::ENUMERATE);
    let cvm2_policy = DomainPolicy::new_restricted(0b1100, cvm2_api); // cores 2-3
    let cvm2_h = Capability::create(&platform, &root, cvm2_policy).unwrap().0;
    let cvm2 = root.read().data.domain_capabilities[&cvm2_h]
        .upgrade()
        .unwrap();

    // Give CVM1 exclusive memory: 512MB
    let cvm1_mem_access = Access::new(0x0, 0x20000000, Rights::RWX);
    let (cvm1_mem_h, _, _) = Capability::carve(&platform, &root, mem_root_h, cvm1_mem_access).unwrap();
    let cvm1_mem = root.read().data.memory_capabilities[&cvm1_mem_h]
        .upgrade()
        .unwrap();

    // Give CVM2 exclusive memory: 512MB
    let cvm2_mem_access = Access::new(0x20000000, 0x20000000, Rights::RWX);
    let (cvm2_mem_h, _, _) = Capability::carve(&platform, &root, mem_root_h, cvm2_mem_access).unwrap();
    let cvm2_mem = root.read().data.memory_capabilities[&cvm2_mem_h]
        .upgrade()
        .unwrap();

    // Create shared memory region (aliased to both CVMs): 64MB
    let shared_mem_access = Access::new(0x40000000, 0x4000000, Rights::RW);
    let (shared_for_cvm1_h, _, _)=
        Capability::alias(&platform, &root, mem_root_h, shared_mem_access).unwrap();
    let shared_for_cvm1 = root.read().data.memory_capabilities[&shared_for_cvm1_h]
        .upgrade()
        .unwrap();
    let (shared_for_cvm2_h, _, _)=
        Capability::alias(&platform, &root, mem_root_h, shared_mem_access).unwrap();
    let shared_for_cvm2 = root.read().data.memory_capabilities[&shared_for_cvm2_h]
        .upgrade()
        .unwrap();

    // Seal both CVMs
    Capability::seal(&platform, &root, cvm1_h).unwrap();
    Capability::seal(&platform, &root, cvm2_h).unwrap();

    // Verify both CVMs are sealed
    assert!(cvm1.read().data.is_sealed());
    assert!(cvm2.read().data.is_sealed());

    let cvm1_id = cvm1.read().data.id;
    let cvm2_id = cvm2.read().data.id;

    // Generate attestations for both
    let cvm1_attest = attest_domain(&cvm1);
    let cvm2_attest = attest_domain(&cvm2);

    assert!(cvm1_attest
        .report
        .contains(&format!("Domain ID: {}", cvm1_id)));
    assert!(cvm2_attest
        .report
        .contains(&format!("Domain ID: {}", cvm2_id)));

    // Expected attestation strings
    let expected_cvm1_cores = "Cores: 0b11";
    let expected_cvm2_cores = "Cores: 0b1100";

    assert!(cvm1_attest.report.contains(expected_cvm1_cores));
    assert!(cvm2_attest.report.contains(expected_cvm2_cores));

    // Compute address spaces
    let cvm1_view =
        compute_view_from_capabilities(cvm1_id, &[cvm1_mem.clone(), shared_for_cvm1.clone()]);
    let cvm2_view =
        compute_view_from_capabilities(cvm2_id, &[cvm2_mem.clone(), shared_for_cvm2.clone()]);

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
        let mut batch = UpdateBatch::new();
        batch.add_change_rights(
            cvm1_id_clone,
            0x40000000,
            0x1000,
            0x40000000,
            Rights::RW,
            false,
        );
        batch.add_change_rights(
            cvm2_id_clone,
            0x40000000,
            0x1000,
            0x40000000,
            Rights::RW,
            false,
        );
        let cores = proc1.submit_updates(batch);
        assert!(cores.contains(&0));
        assert!(cores.contains(&2));
    });

    // Thread 2: Core 2 (CVM2) reads from shared memory
    let handle2 = thread::spawn(move || {
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
    let platform = common::TestPlatform::new();
    // Root -> CVM -> Enclave -> Nested sandbox
    let root_domain = Domain::new_root(4);
    let root = Capability::new_root(0, 0, root_domain);
    let total_mem = MemoryRegion::new_root(0x0, 0x10000000); // 256MB
    let mem_root = Capability::new_root(0, 1, total_mem);
    root.write()
        .data
        .add_memory_capability(1, Arc::downgrade(&mem_root));
    let mem_root_h: LocalHandle = 1;

    // CVM
    let cvm_api = MonitorAPI::from_bits(
        MonitorAPI::CREATE | MonitorAPI::SEAL | MonitorAPI::CARVE | MonitorAPI::ATTEST,
    );
    let cvm_h =
        Capability::create(&platform, &root, DomainPolicy::new_restricted(0b1111, cvm_api)).unwrap().0;
    let cvm = root.read().data.domain_capabilities[&cvm_h]
        .upgrade()
        .unwrap();

    let (cvm_mem_h, _, _) =
        Capability::carve(&platform, &root, mem_root_h, Access::new(0x0, 0x8000000, Rights::RWX))
            .unwrap();
    Capability::seal(&platform, &root, cvm_h).unwrap();

    // Enclave inside CVM
    let enclave_api = MonitorAPI::from_bits(
        MonitorAPI::CREATE | MonitorAPI::SEAL | MonitorAPI::CARVE | MonitorAPI::ATTEST,
    );
    let enclave_h =
        Capability::create(&platform, &cvm, DomainPolicy::new_restricted(0b0011, enclave_api)).unwrap().0;
    let enclave = cvm.read().data.domain_capabilities[&enclave_h]
        .upgrade()
        .unwrap();

    let (enclave_mem_h, _, _) =
        Capability::carve(&platform, &root, cvm_mem_h, Access::new(0x0, 0x2000000, Rights::RW))
            .unwrap();
    Capability::seal(&platform, &cvm, enclave_h).unwrap();

    // Nested sandbox inside enclave
    let sandbox_api = MonitorAPI::from_bits(MonitorAPI::ATTEST);
    let sandbox_h =
        Capability::create(&platform, &enclave, DomainPolicy::new_restricted(0b0001, sandbox_api))
            .unwrap().0;
    let sandbox = enclave.read().data.domain_capabilities[&sandbox_h]
        .upgrade()
        .unwrap();

    let (_sandbox_mem_h, _, _) =
        Capability::carve(&platform, &root, enclave_mem_h, Access::new(0x0, 0x100000, Rights::R))
            .unwrap();
    Capability::seal(&platform, &enclave, sandbox_h).unwrap();

    // Verify hierarchy
    assert_eq!(root.read().data.id, 0);
    let cvm_id = cvm.read().data.id;
    let enclave_id = enclave.read().data.id;
    let sandbox_id = sandbox.read().data.id;
    assert_ne!(cvm_id, 0);
    assert_ne!(enclave_id, 0);
    assert_ne!(sandbox_id, 0);

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
    batch.add_change_rights(sandbox_id, 0x50000, 0x1000, 0x50000, Rights::NONE, true);
    let cores = proc.submit_updates(batch);

    assert!(cores.contains(&0));
    assert!(proc.has_pending_updates(0));
}

#[test]
fn test_complex_memory_update_scenario() {
    let platform = common::TestPlatform::new();
    // ================================================================
    // Initial setup: Dom0 with r0 = [0x0, 0x10000) RWX
    // Domain::new_root creates a sealed domain (id=0, status=Sealed).
    // ================================================================
    let root_domain = Domain::new_root(4);
    let dom0 = Capability::new_root(0, 0, root_domain);

    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let r0 = Capability::new_root(0, 1, root_region);
    dom0.write()
        .data
        .add_memory_capability(1, Arc::downgrade(&r0));
    let r0_h: LocalHandle = 1;

    // ── Create Dom1, carve r1, send to Dom1, seal ─────────────────────
    let dom1_policy = DomainPolicy::new_restricted(
        0b1111,
        MonitorAPI::from_bits(
            MonitorAPI::CREATE
                | MonitorAPI::SEAL
                | MonitorAPI::ALIAS
                | MonitorAPI::CARVE
                | MonitorAPI::SEND
                | MonitorAPI::REVOKE
                | MonitorAPI::GET
                | MonitorAPI::ATTEST,
        ),
    );
    let dom1_h = Capability::create(&platform, &dom0, dom1_policy).unwrap().0;
    let dom1 = dom0.read().data.domain_capabilities[&dom1_h]
        .upgrade()
        .unwrap();

    let r1_access = Access::new(0x1000, 0x2000, Rights::RWX);
    let (r1_h, _, _) = Capability::carve(&platform, &dom0, r0_h, r1_access).unwrap();
    Capability::send(&platform, &dom0, r1_h, dom1_h, Attributes::NONE).unwrap();
    let r1_h_in_dom1: LocalHandle = 1;
    Capability::seal(&platform, &dom0, dom1_h).unwrap();

    let dom1_view = compute_address_space(&dom1);
    assert!(dom1_view.is_accessible(0x1000));
    assert!(dom1_view.is_accessible(0x2FFF));
    let r1_arc = dom1.read().data.memory_capabilities[&r1_h_in_dom1]
        .upgrade()
        .unwrap();
    assert_eq!(r1_arc.read().data.kind, RegionKind::Carve);

    // ── Create Dom2, carve r2 (reduced rights), alias r3, send r2 ────
    let dom2_policy = DomainPolicy::new_restricted(
        0b1111,
        MonitorAPI::from_bits(MonitorAPI::GET | MonitorAPI::ATTEST | MonitorAPI::REVOKE),
    );
    let dom2_h = Capability::create(&platform, &dom1, dom2_policy).unwrap().0;
    let dom2 = dom1.read().data.domain_capabilities[&dom2_h]
        .upgrade()
        .unwrap();

    let r2_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (r2_h_in_dom1, r2_sub, _) =
        Capability::carve(&platform, &dom1, r1_h_in_dom1, r2_access).unwrap();

    let r3_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (_, r3_sub, _)= Capability::alias(&platform, &dom1, r2_h_in_dom1, r3_access).unwrap();

    Capability::send(&platform, &dom1, r2_h_in_dom1, dom2_h, Attributes::NONE).unwrap();
    let r2_h_in_dom2: LocalHandle = 1;

    let r2_arc = dom2.read().data.memory_capabilities[&r2_h_in_dom2]
        .upgrade()
        .unwrap();
    let r2_rights = r2_arc.read().data.access.rights;
    assert!(r2_rights.read() && r2_rights.write() && !r2_rights.execute());

    Capability::seal(&platform, &dom1, dom2_h).unwrap();

    let dom1_view_after = compute_address_space(&dom1);
    assert!(dom1_view_after.is_accessible(0x1000));
    assert!(dom1_view_after.is_accessible(0x1FFF));

    // ── Revoke r3 from r2, then r2 from r1 ───────────────────────────
    Capability::revoke(&platform, &dom2, r2_h_in_dom2, r3_sub).unwrap();
    Capability::revoke(&platform, &dom1, r1_h_in_dom1, r2_sub).unwrap();

    let r1_rights_after = r1_arc.read().data.access.rights;
    assert!(r1_rights_after.read() && r1_rights_after.write() && r1_rights_after.execute());

    // ── Revoke Dom1 (and transitively Dom2) from Dom0 ─────────────────
    Capability::revoke_domain(&platform, &dom0, dom1_h).unwrap();

    assert_eq!(dom1.read().data.status, DomainStatus::Revoked);
    assert_eq!(dom2.read().data.status, DomainStatus::Revoked);
    assert_eq!(dom0.read().children.len(), 0);

    let dom0_final_view = compute_address_space(&dom0);
    assert!(dom0_final_view.is_accessible(0x0));
    assert!(dom0_final_view.is_accessible(0xFFFF));
}
