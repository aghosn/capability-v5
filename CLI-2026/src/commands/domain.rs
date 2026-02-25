//! Domain-related commands: init, create-domain, seal, revoke, set-interrupt-policy

use capability_engine::*;
use colored::*;
use std::sync::Arc;

use crate::parser::{parse_api, parse_number};
use crate::session::Command;
use crate::state::CliState;
use crate::update_processor::process_updates;

/// Initialize root domain and memory region
pub fn cmd_init(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.len() != 2 {
        return Err("Usage: init <name> <size>".to_string());
    }

    let name = args[0];
    let size = parse_number(args[1])?;

    // Create root domain with the specified number of cores
    let root_domain = Domain::new_root(state.num_cores);
    let root_cap_id = state.next_id();
    let root = Capability::new_root(0, root_cap_id, root_domain);
    let root_name = name.to_string();

    // Track domain name for reverse lookup
    state.register_domain_name(0, root_name.clone());
    state.domains.insert(root_name.clone(), root.clone());

    // Create root memory region
    let root_region = MemoryRegion::new_root(0x0, size);
    let mem_cap_id = state.next_id();
    let mem_root = Capability::new_root(0, mem_cap_id, root_region);
    let mem_name = "r0".to_string();
    state.memories.insert(mem_name.clone(), mem_root.clone());

    // Register memory capability with root domain
    root.write()
        .data
        .add_memory_capability(mem_cap_id, Arc::downgrade(&mem_root));

    // Automatically schedule root domain on all cores
    let num_cores = state.num_cores as u64;
    for core_id in 0..num_cores {
        if let Ok(core_ref) = state.switch_manager.get_core(core_id) {
            *core_ref.state.write() = CoreState::Running(0); // Root domain ID is 0
        }
    }

    // Record command
    state.session.add_command(Command::Init {
        name: name.to_string(),
        size,
    });

    println!(
        "{} Created root domain '{}' and memory region '{}' (size: 0x{:x})",
        "✓".bright_green().bold(),
        root_name.bright_white(),
        mem_name.bright_white(),
        size
    );
    println!(
        "  {} Scheduled root domain on {} core(s)",
        "→".bright_blue(),
        num_cores
    );

    Ok(())
}

/// Create a child domain
pub fn cmd_create_domain(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.len() != 4 {
        return Err("Usage: create-domain <parent> <name> <cores> <api>".to_string());
    }

    let parent_name = args[0];
    let child_name = args[1];
    let cores = parse_number(args[2])?;
    let api = parse_api(args[3])?;

    let child_policy = DomainPolicy::new_restricted(cores, api);
    let child_cap_id = state.next_id();

    let parent = state
        .domains
        .get(parent_name)
        .ok_or_else(|| format!("Domain '{}' not found", parent_name))?;

    let child = parent
        .create_child(child_policy, child_cap_id)
        .map_err(|e| format!("Failed to create child: {:?}", e))?;

    let child_id = child.read().data.id;

    // Register domain capability with parent
    parent
        .write()
        .data
        .add_domain_capability(child_cap_id, Arc::downgrade(&child));

    // Track domain name for reverse lookup
    state.register_domain_name(child_id, child_name.to_string());
    state.domains.insert(child_name.to_string(), child);

    // Record command
    state.session.add_command(Command::CreateDomain {
        parent: parent_name.to_string(),
        name: child_name.to_string(),
        cores,
        api_bits: api.bits() as u64,
    });

    println!(
        "{} Created domain '{}' (ID: {}, cores: 0b{:b})",
        "✓".bright_green().bold(),
        child_name.bright_white(),
        child_id,
        cores
    );

    Ok(())
}

/// Seal a domain (make it ready for execution)
pub fn cmd_seal(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.len() != 1 {
        return Err("Usage: seal <domain>".to_string());
    }

    let domain_name = args[0];
    let domain = state
        .domains
        .get(domain_name)
        .ok_or_else(|| format!("Domain '{}' not found", domain_name))?;

    domain
        .write()
        .data
        .seal()
        .map_err(|e| format!("Failed to seal: {:?}", e))?;

    // Record command
    state.session.add_command(Command::Seal {
        domain: domain_name.to_string(),
    });

    println!(
        "{} Sealed domain '{}'",
        "✓".bright_green().bold(),
        domain_name.bright_white()
    );

    Ok(())
}

/// Revoke a child capability (memory or domain)
pub fn cmd_revoke(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.len() != 2 {
        return Err("Usage: revoke <parent> <child>".to_string());
    }

    let parent_name = args[0];
    let child_name = args[1];

    // Try to revoke as memory region first
    if let (Some(parent), Some(child)) = (state.memories.get(parent_name), state.memories.get(child_name)) {
        let updates = parent
            .revoke_ref(child)
            .map_err(|e| format!("Failed to revoke memory: {:?}", e))?;

        println!(
            "{} Revoked memory '{}' from '{}'",
            "✓".bright_green().bold(),
            child_name.bright_white(),
            parent_name.bright_white()
        );

        // Process updates (this will remove revoked capabilities from state)
        process_updates(state, &updates);

        // Record command
        state.session.add_command(Command::Revoke {
            parent: parent_name.to_string(),
            child: child_name.to_string(),
        });

        return Ok(());
    }

    // Try to revoke as domain
    if let (Some(parent), Some(child)) = (state.domains.get(parent_name), state.domains.get(child_name)) {
        // Find the handle for the child domain in the parent
        let child_id = child.read().data.id;
        let parent_read = parent.read();

        let handle = parent_read
            .data
            .domain_capabilities
            .iter()
            .find(|(_, weak_cap)| {
                if let Some(cap) = weak_cap.upgrade() {
                    cap.read().data.id == child_id
                } else {
                    false
                }
            })
            .map(|(h, _)| *h)
            .ok_or_else(|| format!("Child domain '{}' not found in parent '{}'", child_name, parent_name))?;

        drop(parent_read);

        let updates = parent
            .revoke_child(handle)
            .map_err(|e| format!("Failed to revoke domain: {:?}", e))?;

        println!(
            "{} Revoked domain '{}' from '{}' - cascading to all children and capabilities",
            "✓".bright_green().bold(),
            child_name.bright_white(),
            parent_name.bright_white()
        );

        // Process updates (this will remove revoked domains and their capabilities from state)
        process_updates(state, &updates);

        // Record command
        state.session.add_command(Command::Revoke {
            parent: parent_name.to_string(),
            child: child_name.to_string(),
        });

        return Ok(());
    }

    Err(format!(
        "Could not find '{}' and '{}' as either memory regions or domains",
        parent_name, child_name
    ))
}

/// Set interrupt policy for a specific vector
pub fn cmd_set_interrupt_policy(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.len() != 3 {
        return Err("Usage: set-interrupt-policy <domain> <vector> <visibility>".to_string());
    }

    let domain_name = args[0];
    let vector = parse_number(args[1])? as u8;
    let visibility_str = args[2].to_uppercase();

    let visibility = match visibility_str.as_str() {
        "DELIVER" => InterruptVisibility::Deliver,
        "REPORT" => InterruptVisibility::Report,
        "NOTREPORT" => InterruptVisibility::NotReport,
        _ => return Err(format!("Invalid visibility: {}. Use DELIVER, REPORT, or NOTREPORT", args[2])),
    };

    let domain = state
        .domains
        .get(domain_name)
        .ok_or_else(|| format!("Domain '{}' not found", domain_name))?;

    let policy = VectorPolicy {
        visibility,
        read_set: 0,
        write_set: 0,
    };

    domain.write().data.policy.interrupts.set_policy(vector, policy);

    println!(
        "{} Set interrupt policy for vector {} on domain '{}': {:?}",
        "✓".bright_green().bold(),
        vector,
        domain_name.bright_white(),
        visibility
    );

    Ok(())
}

/// Set default interrupt policy for all vectors
pub fn cmd_set_default_interrupt_policy(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.len() != 2 {
        return Err("Usage: set-default-interrupt-policy <domain> <visibility>".to_string());
    }

    let domain_name = args[0];
    let visibility_str = args[1].to_uppercase();

    let visibility = match visibility_str.as_str() {
        "DELIVER" => InterruptVisibility::Deliver,
        "REPORT" => InterruptVisibility::Report,
        "NOTREPORT" => InterruptVisibility::NotReport,
        _ => return Err(format!("Invalid visibility: {}. Use DELIVER, REPORT, or NOTREPORT", args[1])),
    };

    let domain = state
        .domains
        .get(domain_name)
        .ok_or_else(|| format!("Domain '{}' not found", domain_name))?;

    let policy = VectorPolicy {
        visibility,
        read_set: 0,
        write_set: 0,
    };

    domain.write().data.policy.interrupts.default = policy;

    println!(
        "{} Set default interrupt policy for domain '{}': {:?}",
        "✓".bright_green().bold(),
        domain_name.bright_white(),
        visibility
    );

    Ok(())
}
