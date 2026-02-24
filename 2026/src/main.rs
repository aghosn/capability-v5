use capability_engine::*;

fn main() {
    println!("=== Capability Engine V2 Demo ===\n");

    // Create root domain (domain 0)
    let root_domain = Domain::new_root();
    let root = Capability::new_root(0, 0, root_domain);
    println!("Created root domain (ID: 0)");

    // Create root memory region
    let root_region = MemoryRegion::new_root(0x0, 0x100000);
    let mem_root = Capability::new_root(0, 1, root_region);
    println!("Created root memory region: [0x0..0x100000)");

    // Create a child domain with restricted permissions
    let child_policy = DomainPolicy::new_restricted(
        0b1111, // cores 0-3
        MonitorAPI {
            create: false,
            set: false,
            get: true,
            send: false,
            seal: false,
            attest: true,
            enumerate: true,
            switch: true,
            alias: false,
            carve: false,
            revoke: false,
            getchan: false,
        },
    );

    match Capability::create_child_domain(&root, child_policy, 1, 0) {
        Ok(child) => {
            println!("\nCreated child domain (ID: {})", child.read().data.id);
            println!("  Cores: 0b{:04b}", child.read().data.policy.cores);
            println!("  API.get: {}", child.read().data.policy.api.get);
            println!("  API.attest: {}", child.read().data.policy.api.attest);

            // Carve memory for the child
            let child_access = Access::new(0x10000, 0x10000, Rights::RWX);
            match Capability::carve_child(&mem_root, child_access, 1, 0) {
                Ok((child_mem, updates)) => {
                    println!("\nCarved memory for child:");
                    println!("  Range: {}", child_mem.read().data.access);
                    println!("  Status: {:?}", child_mem.read().data.status);
                    println!("\nGenerated {} updates:", updates.len());
                    for (i, update) in updates.updates().iter().enumerate() {
                        println!("  {}. {:?}", i + 1, update);
                    }

                    // Seal the child domain
                    if child.write().data.seal().is_ok() {
                        println!("\nSealed child domain");
                    }

                    // Generate attestation
                    let attestation = attest_domain(&child);
                    println!("\n=== Attestation Report ===");
                    println!("{}", attestation.report);

                    // Create a switch manager
                    let _mgr = SwitchManager::new(4);
                    println!("=== Switch Manager ===");
                    println!("Created switch manager with 4 cores");

                    println!("\n=== Demo Complete ===");
                }
                Err(e) => eprintln!("Error carving memory: {}", e),
            }
        }
        Err(e) => eprintln!("Error creating child domain: {}", e),
    }
}
