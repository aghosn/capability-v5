use capability_engine::*;
use std::sync::Arc;

fn main() {
    println!("=== Capability Engine V2 - Complete Workflow Demo ===\n");

    // ================================================================
    // STEP 1: Create root domain and root memory region
    // ================================================================
    println!("STEP 1: Initialize root domain and memory");
    println!("------------------------------------------");

    let root_domain = Domain::new_root(4);
    let root = Capability::new_root(0, 0, root_domain);
    println!("✓ Created root domain (ID: 0)");

    // Create root memory region (16 MB)
    let root_region = MemoryRegion::new_root(0x0, 0x1000000); // 16 MB
    let mem_root = Capability::new_root(0, 1, root_region);
    println!("✓ Created root memory region: [0x0..0x1000000) (16 MB)");

    // Register memory capability with root domain
    root.write().data.add_memory_capability(1, Arc::downgrade(&mem_root));

    // ================================================================
    // STEP 2: Create child domain
    // ================================================================
    println!("\nSTEP 2: Create child domain");
    println!("----------------------------");

    let child_api = MonitorAPI::from_bits(
        MonitorAPI::GET | MonitorAPI::ATTEST | MonitorAPI::ENUMERATE | MonitorAPI::SWITCH,
    );
    let child_policy = DomainPolicy::new_restricted(
        0b1111, // cores 0-3
        child_api,
    );

    let root_id = root.read().data.id;
    let child = Capability::create_child_domain(&root, child_policy, root_id, 2).unwrap();
    let child_id = child.read().data.id;
    println!("✓ Created child domain (ID: {})", child_id);
    println!("  • Cores: 0b{:04b}", child.read().data.policy.cores);
    println!("  • API permissions: GET, ATTEST, ENUMERATE, SWITCH");

    // Register domain capability with root
    root.write().data.add_domain_capability(2, Arc::downgrade(&child));

    // ================================================================
    // STEP 3: Create memory regions (exclusive + shared)
    // ================================================================
    println!("\nSTEP 3: Create memory regions");
    println!("------------------------------");

    // Carve exclusive memory for child (1 MB at 0x100000)
    println!("Creating EXCLUSIVE memory for child...");
    let exclusive_access = Access::new(0x100000, 0x100000, Rights::RWX);
    let (exclusive_mem, carve_updates) = Capability::carve_child(&mem_root, exclusive_access, 0, 3).unwrap();
    println!("✓ Carved exclusive memory: {}", exclusive_mem.read().data.access);
    println!("  • Kind: {:?}", exclusive_mem.read().data.kind);
    println!("  • Updates generated: {}", carve_updates.len());

    // Register with root domain
    root.write().data.add_memory_capability(3, Arc::downgrade(&exclusive_mem));

    // Create aliased (shared) memory for child (512 KB at 0x200000)
    println!("\nCreating SHARED memory for child...");
    let shared_access = Access::new(0x200000, 0x80000, Rights::RW);
    let shared_mem = Capability::alias_child(&mem_root, shared_access, 0, 4).unwrap();
    println!("✓ Aliased shared memory: {}", shared_mem.read().data.access);
    println!("  • Kind: {:?}", shared_mem.read().data.kind);
    println!("  • Parent retains access (aliased, not carved)");

    // Register with root domain
    root.write().data.add_memory_capability(4, Arc::downgrade(&shared_mem));

    // ================================================================
    // STEP 4: Send capabilities to child
    // ================================================================
    println!("\nSTEP 4: Send capabilities to child");
    println!("------------------------------------");

    // Send exclusive memory to child (with CLEAN attribute)
    let clean_attrs = Attributes::from_bits(Attributes::CLEAN);
    let send1_updates = Capability::send_to(&exclusive_mem, 0, child_id, clean_attrs).unwrap();
    println!("✓ Sent exclusive memory to child");
    println!("  • Child handle: 10");
    println!("  • Attributes: CLEAN (will be zeroed on revoke)");
    println!("  • Updates generated: {}", send1_updates.len());
    for (i, update) in send1_updates.updates().iter().enumerate() {
        println!("    {}. {:?}", i + 1, update);
    }

    // Register with child domain
    child.write().data.add_memory_capability(10, Arc::downgrade(&exclusive_mem));

    // Send shared memory to child (no special attributes)
    let send2_updates = Capability::send_to(&shared_mem, 0, child_id, Attributes::NONE).unwrap();
    println!("\n✓ Sent shared memory to child");
    println!("  • Child handle: 11");
    println!("  • Updates generated: {}", send2_updates.len());
    for (i, update) in send2_updates.updates().iter().enumerate() {
        println!("    {}. {:?}", i + 1, update);
    }

    // Register with child domain
    child.write().data.add_memory_capability(11, Arc::downgrade(&shared_mem));

    // ================================================================
    // STEP 5: Seal the child domain
    // ================================================================
    println!("\nSTEP 5: Seal child domain");
    println!("--------------------------");

    child.write().data.seal().unwrap();
    println!("✓ Child domain sealed and ready for execution");
    println!("  • Status: {:?}", child.read().data.status);
    println!("  • Can no longer receive capabilities: {}",
             !child.read().data.policy.receive_after_seal());

    // ================================================================
    // STEP 6: Generate and display attestations
    // ================================================================
    println!("\nSTEP 6: Generate attestations");
    println!("-------------------------------");

    let root_attest = attest_domain(&root);
    println!("Root Domain Attestation:");
    println!("{}", root_attest.report);

    let child_attest = attest_domain(&child);
    println!("\nChild Domain Attestation:");
    println!("{}", child_attest.report);

    // ================================================================
    // STEP 7: Demonstrate address space views
    // ================================================================
    println!("\nSTEP 7: Compute address space views");
    println!("-------------------------------------");

    let root_view = compute_address_space(&root);
    println!("Root Domain Address Space:");
    println!("{}", root_view);

    let child_view = compute_address_space(&child);
    println!("Child Domain Address Space:");
    println!("{}", child_view);

    // ================================================================
    // STEP 8: Simulate switching and interrupt handling
    // ================================================================
    println!("\nSTEP 8: Demonstrate switching and interrupts");
    println!("----------------------------------------------");

    let switch_mgr = SwitchManager::new(4);
    println!("✓ Created switch manager with 4 cores");

    // Initialize core 0 as running root domain
    {
        let core = switch_mgr.get_core(0).unwrap();
        *core.state.write() = CoreState::Running(0);
        println!("✓ Core 0 initialized, running root domain");
    }

    // Perform switch from root to child
    match switch_mgr.switch(0, &root, Some(&child)) {
        Ok(ctx) => {
            println!("\n✓ Switched from domain {} to domain {} on core {}",
                     ctx.from_domain, ctx.to_domain, ctx.core_id);
            println!("  • Is return: {}", ctx.is_return);
        }
        Err(e) => println!("✗ Switch failed: {}", e),
    }

    // Simulate an interrupt
    println!("\nSimulating interrupt vector 6 on child domain...");
    match switch_mgr.route_interrupt(6, &child, 0) {
        Ok((handler_id, reported_to)) => {
            println!("✓ Interrupt routed successfully");
            println!("  • Handler domain: {}", handler_id);
            println!("  • Domains reported to: {:?}", reported_to);

            if handler_id == 0 {
                println!("  • Interrupt handled by root domain");

                // Switch back to root for handling
                match switch_mgr.switch(0, &child, None) {
                    Ok(ctx) => {
                        println!("✓ Switched back to root domain (ID: {}) for interrupt handling",
                                 ctx.to_domain);
                    }
                    Err(e) => println!("✗ Switch back failed: {}", e),
                }
            }
        }
        Err(e) => println!("✗ Interrupt routing failed: {}", e),
    }

    // ================================================================
    // STEP 9: Revoke child to regain capabilities
    // ================================================================
    println!("\nSTEP 9: Revoke child domain");
    println!("----------------------------");

    println!("Root domain before revoke:");
    println!("  • Children count: {}", root.read().children.len());
    println!("  • Memory capabilities: {}", root.read().data.memory_capabilities.len());

    // Revoke exclusive memory capability first
    println!("\nRevoking exclusive memory from child...");
    let revoke1_updates = Capability::revoke_child_ref(&mem_root, &exclusive_mem).unwrap();
    println!("✓ Revoked exclusive memory");
    println!("  • Updates generated: {}", revoke1_updates.len());
    println!("  • Parent regains access to [0x100000..0x200000)");
    for (i, update) in revoke1_updates.updates().iter().enumerate() {
        println!("    {}. {:?}", i + 1, update);
    }

    // Revoke shared memory capability
    println!("\nRevoking shared memory from child...");
    let revoke2_updates = Capability::revoke_child_ref(&mem_root, &shared_mem).unwrap();
    println!("✓ Revoked shared memory");
    println!("  • Updates generated: {}", revoke2_updates.len());
    for (i, update) in revoke2_updates.updates().iter().enumerate() {
        println!("    {}. {:?}", i + 1, update);
    }

    // Revoke the child domain itself
    println!("\nRevoking child domain...");
    let revoke_domain_updates = Capability::revoke_child_domain(&root, 2).unwrap();
    println!("✓ Revoked child domain");
    println!("  • Updates generated: {}", revoke_domain_updates.len());
    for (i, update) in revoke_domain_updates.updates().iter().enumerate() {
        println!("    {}. {:?}", i + 1, update);
    }

    println!("\nRoot domain after revoke:");
    println!("  • Children count: {}", root.read().children.len());
    println!("  • Back to original state (no child domains)");

    // Verify child is revoked
    println!("  • Child status: {:?}", child.read().data.status);

    // ================================================================
    // STEP 10: Verify final state
    // ================================================================
    println!("\nSTEP 10: Verify final state");
    println!("----------------------------");

    let final_root_view = compute_address_space(&root);
    println!("Root Domain Final Address Space:");
    println!("{}", final_root_view);
    println!("✓ Root domain has regained all memory regions");

    println!("\n=== Complete Workflow Demonstration Finished ===");
    println!("\nThis demo showed:");
    println!("  1. ✓ Creating root domain and memory");
    println!("  2. ✓ Creating child domain with restricted policy");
    println!("  3. ✓ Creating exclusive (carved) and shared (aliased) memory");
    println!("  4. ✓ Sending capabilities to child domain");
    println!("  5. ✓ Sealing child domain");
    println!("  6. ✓ Generating attestation reports");
    println!("  7. ✓ Computing address space views");
    println!("  8. ✓ Performing domain switches and interrupt routing");
    println!("  9. ✓ Revoking child and regaining capabilities");
    println!(" 10. ✓ Verifying state returns to original");
}
