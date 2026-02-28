use capability_engine::*;

fn main() {
    println!("=== Capability Engine V2 - Complete Workflow Demo ===\n");

    // ================================================================
    // STEP 1: Create root domain and root memory region
    // ================================================================
    println!("STEP 1: Initialize root domain and memory");
    println!("------------------------------------------");

    // Root domain: the bootstrap domain, owns everything.
    let root = Capability::new_root(0, 0, Domain::new_root(4));
    let root_id = root.read().data.id;
    println!("✓ Created root domain (ID: {})", root_id);

    // Root memory region (16 MB), registered at handle 1 in root's table.
    let root_region = MemoryRegion::new_root(0x0, 0x1000000);
    let mem_root = Capability::new_root(root_id, 1, root_region);
    mem_root.write().owned.owner_domain = Some(std::sync::Arc::downgrade(&root));
    root.write().data.add_memory_capability(1, std::sync::Arc::downgrade(&mem_root));
    println!("✓ Created root memory region: [0x0..0x1000000) (16 MB)");

    // Domain::new_root creates the domain already sealed.
    println!("✓ Root domain sealed (Domain::new_root seals on creation)");

    // ================================================================
    // STEP 2: Create child domain  (domain-mediated)
    // ================================================================
    println!("\nSTEP 2: Create child domain");
    println!("----------------------------");

    let child_api = MonitorAPI::from_bits(
        MonitorAPI::GET | MonitorAPI::ATTEST | MonitorAPI::ENUMERATE | MonitorAPI::SWITCH,
    );
    let child_policy = DomainPolicy::new_restricted(0b1111, child_api);

    let child_h = Capability::create_domain(&root, child_policy).unwrap();

    // Resolve Arc for later use (attestation, view, switch).
    let child = root.read().data
        .get_domain_capability(child_h).unwrap().upgrade().unwrap();
    let child_id = child.read().data.id;
    println!("✓ Created child domain (ID: {}, handle: {})", child_id, child_h);
    println!("  • Cores: 0b{:04b}", child.read().data.policy.cores);
    println!("  • API permissions: GET, ATTEST, ENUMERATE, SWITCH");

    // ================================================================
    // STEP 3: Create memory regions  (domain-mediated)
    // ================================================================
    println!("\nSTEP 3: Create memory regions");
    println!("------------------------------");

    // Carve exclusive memory for child (1 MB at 0x100000).
    println!("Creating EXCLUSIVE memory for child...");
    let exclusive_access = Access::new(0x100000, 0x100000, Rights::RWX);
    let (excl_h, excl_sub, carve_updates) =
        Capability::carve_memory(&root, 1, exclusive_access).unwrap();
    println!("✓ Carved exclusive memory at handle {} (sub {})", excl_h, excl_sub);
    println!("  • Updates generated: {}", carve_updates.len());

    // Alias shared memory for child (512 KB at 0x200000).
    println!("\nCreating SHARED memory for child...");
    let shared_access = Access::new(0x200000, 0x80000, Rights::RW);
    let (shared_h, shared_sub) =
        Capability::alias_memory(&root, 1, shared_access).unwrap();
    println!("✓ Aliased shared memory at handle {} (sub {})", shared_h, shared_sub);
    println!("  • Parent retains access (aliased, not carved)");

    // ================================================================
    // STEP 4: Send capabilities to child  (domain-mediated)
    // ================================================================
    println!("\nSTEP 4: Send capabilities to child");
    println!("------------------------------------");

    let clean_attrs = Attributes::from_bits(Attributes::CLEAN);
    let send1_updates = Capability::send_memory(&root, excl_h, child_h, clean_attrs).unwrap();
    println!("✓ Sent exclusive memory to child (handle {} removed from root)", excl_h);
    println!("  • Attributes: CLEAN (zeroed on revoke)");
    println!("  • Updates generated: {}", send1_updates.len());
    for (i, update) in send1_updates.updates().iter().enumerate() {
        println!("    {}. {:?}", i + 1, update);
    }

    let send2_updates = Capability::send_memory(&root, shared_h, child_h, Attributes::NONE).unwrap();
    println!("\n✓ Sent shared memory to child (handle {} removed from root)", shared_h);
    println!("  • Updates generated: {}", send2_updates.len());
    for (i, update) in send2_updates.updates().iter().enumerate() {
        println!("    {}. {:?}", i + 1, update);
    }

    // ================================================================
    // STEP 5: Seal the child domain  (domain-mediated)
    // ================================================================
    println!("\nSTEP 5: Seal child domain");
    println!("--------------------------");

    Capability::seal_domain_op(&root, child_h).unwrap();
    println!("✓ Child domain sealed");
    println!("  • Status: {:?}", child.read().data.status);

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

    {
        let core = switch_mgr.get_core(0).unwrap();
        *core.state.write() = CoreState::Running(0);
        println!("✓ Core 0 initialized, running root domain");
    }

    match switch_mgr.switch(0, &root, Some(&child)) {
        Ok(ctx) => {
            println!("\n✓ Switched from domain {} to domain {} on core {}",
                     ctx.from_domain, ctx.to_domain, ctx.core_id);
        }
        Err(e) => println!("✗ Switch failed: {}", e),
    }

    println!("\nSimulating interrupt vector 6 on child domain...");
    match switch_mgr.route_interrupt(6, &child, 0) {
        Ok((handler_id, reported_to)) => {
            println!("✓ Interrupt routed. Handler: {}, reported to: {:?}",
                     handler_id, reported_to);
            if handler_id == 0 {
                match switch_mgr.switch(0, &child, None) {
                    Ok(ctx) => println!("✓ Switched back to root (ID: {}) for interrupt", ctx.to_domain),
                    Err(e) => println!("✗ Switch back failed: {}", e),
                }
            }
        }
        Err(e) => println!("✗ Interrupt routing failed: {}", e),
    }

    // ================================================================
    // STEP 9: Revoke child capabilities  (domain-mediated)
    // ================================================================
    println!("\nSTEP 9: Revoke child domain");
    println!("----------------------------");

    // Revoke exclusive and shared memory from root's parent capability (handle 1 = mem_root).
    // sub_handles are stable even though the caps were sent away.
    let rev1 = Capability::revoke_memory_child(&root, 1, excl_sub).unwrap();
    println!("✓ Revoked exclusive memory (sub {}): {} updates", excl_sub, rev1.len());
    for (i, u) in rev1.updates().iter().enumerate() {
        println!("    {}. {:?}", i + 1, u);
    }

    let rev2 = Capability::revoke_memory_child(&root, 1, shared_sub).unwrap();
    println!("✓ Revoked shared memory (sub {}): {} updates", shared_sub, rev2.len());
    for (i, u) in rev2.updates().iter().enumerate() {
        println!("    {}. {:?}", i + 1, u);
    }

    // Revoke the child domain itself.
    let rev_dom = Capability::revoke_domain(&root, child_h).unwrap();
    println!("✓ Revoked child domain (handle {}): {} updates", child_h, rev_dom.len());
    println!("  • Child status: {:?}", child.read().data.status);

    // ================================================================
    // STEP 10: Verify final state
    // ================================================================
    println!("\nSTEP 10: Verify final state");
    println!("----------------------------");

    let final_view = compute_address_space(&root);
    println!("Root Domain Final Address Space:");
    println!("{}", final_view);
    println!("✓ Root domain has regained all memory regions");

    println!("\n=== Demo finished — all operations used the domain-mediated API ===");
}
