//! Domain-related commands: init, create-domain, seal, revoke, set-interrupt-policy, enumerate-pending, accept-capability

use capability_engine::*;
use capability_engine::domain::PendingCapability;
use colored::*;
use std::sync::Arc;

use crate::parser::{parse_api, parse_number, format_api};
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
        api: format_api(&api),
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

/// Enumerate pending capabilities for a sealed domain
pub fn cmd_enumerate_pending(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.len() != 1 {
        return Err("Usage: enumerate-pending <domain>".to_string());
    }

    let domain_name = args[0];
    let domain = state
        .domains
        .get(domain_name)
        .ok_or_else(|| format!("Domain '{}' not found", domain_name))?;

    let domain_read = domain.read();
    let pending_ids = domain_read.data.get_pending_ids();

    if pending_ids.is_empty() {
        println!(
            "  {} No pending capabilities for domain '{}'",
            "ℹ".bright_blue(),
            domain_name.bright_white()
        );
        return Ok(());
    }

    println!(
        "\n{} Pending capabilities for domain '{}':",
        "📋".bright_cyan().bold(),
        domain_name.bright_white()
    );

    for pending_id in pending_ids {
        if let Some(pending_cap) = domain_read.data.get_pending_capability(pending_id) {
            match pending_cap {
                PendingCapability::Memory(weak_ref) => {
                    if let Some(mem_ref) = weak_ref.upgrade() {
                        let mem = mem_ref.read();
                        println!(
                            "  {} [ID: {}] Memory [0x{:x}..0x{:x}) {:?} (owner: {})",
                            "→".bright_blue(),
                            pending_id,
                            mem.data.access.start,
                            mem.data.access.end(),
                            mem.data.access.rights,
                            mem.owned.owner
                        );
                    }
                }
                PendingCapability::Domain(weak_ref) => {
                    if let Some(dom_ref) = weak_ref.upgrade() {
                        let dom = dom_ref.read();
                        println!(
                            "  {} [ID: {}] Domain (ID: {}, status: {:?})",
                            "→".bright_blue(),
                            pending_id,
                            dom.data.id,
                            dom.data.status
                        );
                    }
                }
            }
        }
    }
    println!();

    // Record command
    state.session.add_command(Command::EnumeratePending {
        domain: domain_name.to_string(),
    });

    Ok(())
}

/// Accept a pending capability and assign it a handle
pub fn cmd_accept_capability(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.len() != 2 && args.len() != 3 {
        return Err("Usage: accept-capability <domain> <pending_id> [handle]".to_string());
    }

    let domain_name = args[0];
    let pending_id = parse_number(args[1])?;

    let domain = state
        .domains
        .get(domain_name)
        .ok_or_else(|| format!("Domain '{}' not found", domain_name))?;

    let domain_id = domain.read().data.id;

    // Determine handle: either user-provided or auto-allocated
    let handle = if args.len() == 3 {
        parse_number(args[2])?
    } else {
        // Auto-allocate based on capability type
        // We need to peek at the pending capability first
        let domain_read = domain.read();
        let pending_cap = domain_read
            .data
            .get_pending_capability(pending_id)
            .ok_or_else(|| format!("Pending capability {} not found", pending_id))?;

        match pending_cap {
            PendingCapability::Memory(_) => domain_read.data.allocate_memory_handle(),
            PendingCapability::Domain(_) => domain_read.data.allocate_domain_handle(),
        }
    };

    // Now accept the capability
    let accepted_cap = domain
        .write()
        .data
        .accept_pending_capability(pending_id, handle)
        .map_err(|e| format!("Failed to accept capability: {:?}", e))?;

    // Now we need to update ownership and generate MMU updates
    match accepted_cap {
        PendingCapability::Memory(weak_ref) => {
            if let Some(mem_ref) = weak_ref.upgrade() {
                // Update the capability's ownership
                let mut mem = mem_ref.write();
                let old_owner = mem.owned.owner;
                mem.owned.owner = domain_id;
                mem.owned.handle = handle;

                // Generate MMU updates
                let mut updates = UpdateBatch::new();

                // Unmap from old owner if needed
                if old_owner != domain_id {
                    updates.add_unmap(old_owner, mem.data.access.start, mem.data.access.size);
                }

                // Map to new owner
                updates.add_map(
                    domain_id,
                    mem.data.access.start,
                    mem.data.access.size,
                    mem.data.access.start,
                    mem.data.access.rights.read(),
                    mem.data.access.rights.write(),
                    mem.data.access.rights.execute(),
                );

                drop(mem);

                // Process updates
                process_updates(state, &updates);

                println!(
                    "{} Accepted pending memory capability {} as handle {}",
                    "✓".bright_green().bold(),
                    pending_id,
                    handle
                );
            }
        }
        PendingCapability::Domain(_) => {
            println!(
                "{} Accepted pending domain capability {} as handle {}",
                "✓".bright_green().bold(),
                pending_id,
                handle
            );
        }
    }

    // Record command
    state.session.add_command(Command::AcceptCapability {
        domain: domain_name.to_string(),
        pending_id,
        handle,
    });

    Ok(())
}

/// Reject (discard) a pending capability
pub fn cmd_reject_capability(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.len() != 2 {
        return Err("Usage: reject-capability <domain> <pending_id>".to_string());
    }

    let domain_name = args[0];
    let pending_id = parse_number(args[1])?;

    let domain = state
        .domains
        .get(domain_name)
        .ok_or_else(|| format!("Domain '{}' not found", domain_name))?;

    let rejected = domain
        .write()
        .data
        .reject_pending_capability(pending_id)
        .map_err(|e| format!("Failed to reject capability: {:?}", e))?;

    match rejected {
        PendingCapability::Memory(weak_ref) => {
            let range = weak_ref.upgrade().map(|m| {
                let r = m.read();
                format!("Memory [0x{:x}..0x{:x})", r.data.access.start, r.data.access.end())
            }).unwrap_or_else(|| "Memory (dropped)".to_string());
            println!(
                "{} Rejected pending capability {} ({}) for domain '{}'",
                "✓".bright_green().bold(), pending_id, range, domain_name.bright_white()
            );
        }
        PendingCapability::Domain(weak_ref) => {
            let id = weak_ref.upgrade().map(|d| d.read().data.id.to_string())
                .unwrap_or_else(|| "?".to_string());
            println!(
                "{} Rejected pending capability {} (Domain ID: {}) for domain '{}'",
                "✓".bright_green().bold(), pending_id, id, domain_name.bright_white()
            );
        }
    }

    // Record command
    state.session.add_command(Command::RejectCapability {
        domain: domain_name.to_string(),
        pending_id,
    });

    Ok(())
}
