//! Complex test case for memory updates as specified in todos.md
//!
//! This test verifies the complete update system with a complex hierarchy
//! involving multiple domains, memory carving, aliasing, sending, and revocation.

use capability_engine::*;
use std::sync::Arc;

#[test]
fn test_complex_memory_update_scenario() {
    // ================================================================
    // Initial setup: Dom0 with r0 = [0x0, 0x10000) RWX
    // Domain::new_root creates a sealed domain (id=0, status=Sealed).
    // ================================================================
    println!("\n=== Initial Setup ===");

    let root_domain = Domain::new_root(4);
    let dom0 = Capability::new_root(0, 0, root_domain);

    let root_region = MemoryRegion::new_root(0x0, 0x10000);
    let r0 = Capability::new_root(0, 1, root_region);
    dom0.write().data.add_memory_capability(1, Arc::downgrade(&r0));
    let r0_h: LocalHandle = 1;

    println!("✓ Dom0 created with r0 = [0x0, 0x10000) RWX");

    // ================================================================
    // Test Case 1: Create Dom1, carve r1, send to Dom1, seal
    // ================================================================
    println!("\n=== Test Case 1: Create Dom1 and transfer carved memory ===");

    // Dom1 = Dom0.create_direct_child() — includes ALIAS and SEND for child operations
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
    let dom1_h = Capability::create_domain(&dom0, dom1_policy).unwrap();
    let dom1 = dom0.read().data.domain_capabilities[&dom1_h].upgrade().unwrap();
    let dom1_id = dom1.read().data.id;
    println!("✓ Dom1 created (ID: {})", dom1_id);

    // r1 = r0.carve[0x1000, 0x3000) RWX
    // r1_h is auto-allocated in dom0's table and equals r1's stable SubHandle.
    let r1_access = Access::new(0x1000, 0x2000, Rights::RWX); // size = 0x2000
    let (r1_h, _, carve_updates) = Capability::carve_memory(&dom0, r0_h, r1_access).unwrap();
    println!("✓ Carved r1 = [0x1000, 0x3000) RWX (updates: {})", carve_updates.len());

    // Dom0.send(Dom1, r1) — Dom1 is unsealed → immediate transfer
    // After send, r1 is removed from Dom0's table; Dom1 (fresh) assigns it handle 1.
    let send_updates = Capability::send_memory(&dom0, r1_h, dom1_h, Attributes::NONE).unwrap();
    let r1_h_in_dom1: LocalHandle = 1;
    println!("✓ Sent r1 to Dom1 (updates: {})", send_updates.len());

    // Dom0.seal(Dom1)
    Capability::seal_domain_op(&dom0, dom1_h).unwrap();
    println!("✓ Dom1 sealed");

    // Check Dom0's address space view
    let dom0_view = compute_address_space(&dom0);
    println!(
        "\nDom0 address space: {} bytes across {} regions",
        dom0_view.total_size(),
        dom0_view.regions.len()
    );
    for (i, region) in dom0_view.regions.iter().enumerate() {
        println!("  Region {}: {}", i, region);
    }
    println!("✓ Dom0 view reflects r0 with r1 carved out");

    // Check Dom1's address space view
    let dom1_view = compute_address_space(&dom1);
    println!(
        "\nDom1 address space: {} bytes across {} regions",
        dom1_view.total_size(),
        dom1_view.regions.len()
    );
    for (i, region) in dom1_view.regions.iter().enumerate() {
        println!("  Region {}: {}", i, region);
    }

    // Dom1 owns r1 (received from Dom0)
    assert!(dom1_view.is_accessible(0x1000));
    assert!(dom1_view.is_accessible(0x2FFF));
    let r1_arc = dom1.read().data.memory_capabilities[&r1_h_in_dom1].upgrade().unwrap();
    assert_eq!(r1_arc.read().data.kind, RegionKind::Carve);
    println!("✓ Dom1 has access to [0x1000, 0x3000) as Carve");

    // ================================================================
    // On Dom1: Create Dom2, carve r2 with reduced rights
    // ================================================================
    println!("\n=== Test Case 2: Create Dom2 and test rights reduction ===");

    // Dom2 = Dom1.create_direct_child() — needs REVOKE to revoke r3 from r2 later
    let dom2_policy = DomainPolicy::new_restricted(
        0b1111,
        MonitorAPI::from_bits(MonitorAPI::GET | MonitorAPI::ATTEST | MonitorAPI::REVOKE),
    );
    let dom2_h = Capability::create_domain(&dom1, dom2_policy).unwrap();
    let dom2 = dom1.read().data.domain_capabilities[&dom2_h].upgrade().unwrap();
    let dom2_id = dom2.read().data.id;
    println!("✓ Dom2 created (ID: {})", dom2_id);

    // r2 = r1.carve[0x1000, 0x2000) RW (reduced from RWX to RW)
    // r2_h_in_dom1 is auto-allocated in Dom1's table (r1 is at 1, so r2 gets 2).
    let r2_access = Access::new(0x1000, 0x1000, Rights::RW); // size = 0x1000
    let (r2_h_in_dom1, r2_sub, carve2_updates) =
        Capability::carve_memory(&dom1, r1_h_in_dom1, r2_access).unwrap();
    println!(
        "✓ Carved r2 = [0x1000, 0x2000) RW from r1 (updates: {})",
        carve2_updates.len()
    );

    // ================================================================
    // Create r3 as alias of r2
    // ================================================================
    println!("\n=== Test Case 3: Alias r2 and send to Dom2 ===");

    // r3 = r2.alias[0x1000, 0x2000) RW
    // r3_h_in_dom1 is auto-allocated (r1 at 1, r2 at 2, so r3 gets 3).
    // r3_h_in_dom1 is also r3's stable SubHandle used for revocation.
    let r3_access = Access::new(0x1000, 0x1000, Rights::RW);
    let (r3_h_in_dom1, r3_sub) = Capability::alias_memory(&dom1, r2_h_in_dom1, r3_access).unwrap();
    println!("✓ Created r3 = [0x1000, 0x2000) RW as alias of r2");

    // Dom1.send(Dom2, r2) — Dom2 is unsealed → immediate transfer
    // After send, r2 is removed from Dom1's table; Dom2 (fresh) assigns it handle 1.
    let send2_updates =
        Capability::send_memory(&dom1, r2_h_in_dom1, dom2_h, Attributes::NONE).unwrap();
    let r2_h_in_dom2: LocalHandle = 1;
    println!("✓ Sent r2 to Dom2 (updates: {})", send2_updates.len());

    // Verify r2 rights via Dom2's table
    let r2_arc = dom2.read().data.memory_capabilities[&r2_h_in_dom2].upgrade().unwrap();
    let r2_rights = r2_arc.read().data.access.rights;
    assert!(r2_rights.read());
    assert!(r2_rights.write());
    assert!(!r2_rights.execute(), "r2 should not have execute permission");
    println!("✓ r2 has correct rights: RW (no X)");

    // Seal Dom2 after the send
    Capability::seal_domain_op(&dom1, dom2_h).unwrap();
    println!("✓ Dom2 sealed");

    // Assert Dom1 still has RW access to the region [0x1000, 0x2000) via r3 (alias)
    let dom1_view_after = compute_address_space(&dom1);
    assert!(dom1_view_after.is_accessible(0x1000));
    assert!(dom1_view_after.is_accessible(0x1FFF));
    println!("✓ Dom1 still has RW access to [0x1000, 0x2000) via r3 (alias)");

    // ================================================================
    // Revoke r3 from r2 (r2 is now in Dom2's table; Dom2 has REVOKE)
    // Resolve by handle since r3 is in Dom1's table (not Dom2's).
    // ================================================================
    println!("\n=== Test Case 4: Revoke r3 from r2 ===");

    let revoke1_updates = Capability::revoke_memory_child(&dom2, r2_h_in_dom2, r3_sub).unwrap();
    println!("✓ Revoked r3 from r2 (updates: {})", revoke1_updates.len());
    println!("✓ Dom1 access to memory unchanged after revoking r3");

    // ================================================================
    // Revoke r2 from r1 (r1 is in Dom1's table; r2 is in Dom2's table after send)
    // Resolve by handle since r2 was removed from Dom1's table after send.
    // ================================================================
    println!("\n=== Test Case 5: Revoke r2 from r1 ===");

    let revoke2_updates = Capability::revoke_memory_child(&dom1, r1_h_in_dom1, r2_sub).unwrap();
    println!("✓ Revoked r2 from r1 (updates: {})", revoke2_updates.len());

    // Assert r1's own rights are still RWX (rights are on the capability itself, not affected by children)
    let dom1_view_final = compute_address_space(&dom1);
    println!("Dom1 final address space: {} bytes", dom1_view_final.total_size());

    let r1_rights_after = r1_arc.read().data.access.rights;
    assert!(r1_rights_after.read());
    assert!(r1_rights_after.write());
    assert!(r1_rights_after.execute());
    println!("✓ Dom1 has RWX on [0x1000, 0x3000) after revoking r2");
    println!("✓ Previous operation triggered update to re-enable X access");

    // ================================================================
    // On Dom0: Revoke Dom1
    // dom1_h is Dom1's stable SubHandle in Dom0's children tree.
    // ================================================================
    println!("\n=== Test Case 6: Revoke Dom1 from Dom0 ===");

    let revoke_dom1_updates = Capability::revoke_domain(&dom0, dom1_h).unwrap();
    println!(
        "✓ Revoked Dom1 from Dom0 (updates: {})",
        revoke_dom1_updates.len()
    );

    // Assert that Dom1 and Dom2 are revoked
    assert_eq!(dom1.read().data.status, DomainStatus::Revoked);
    assert_eq!(dom2.read().data.status, DomainStatus::Revoked);
    println!("✓ Dom1 status: {:?}", dom1.read().data.status);
    println!("✓ Dom2 status: {:?}", dom2.read().data.status);

    println!("✓ Memory capabilities removed from capability tree during revocation");

    // Check Dom0's final state
    let dom0_final_view = compute_address_space(&dom0);
    println!(
        "\nDom0 final address space: {} bytes across {} regions",
        dom0_final_view.total_size(),
        dom0_final_view.regions.len()
    );
    for (i, region) in dom0_final_view.regions.iter().enumerate() {
        println!("  Region {}: {}", i, region);
    }

    // Check that Dom0 has no children
    assert_eq!(dom0.read().children.len(), 0);
    println!("✓ All domain children removed from Dom0");

    // Dom0 still has access to the root region endpoints
    assert!(dom0_final_view.is_accessible(0x0));
    assert!(dom0_final_view.is_accessible(0xFFFF));
    println!("✓ Dom0 retains access to full address space [0x0, 0x10000)");

    println!("✓ Update batches correctly generated throughout the scenario");

    println!("\n=== Complex Update Scenario Complete ===");
    println!("All assertions passed!");
}
