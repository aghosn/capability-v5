//! Domain-related commands: init, create-domain, seal, revoke, set-interrupt-policy, enumerate-pending, accept-capability

use capability_engine::*;
use colored::*;
use std::sync::Arc;

use crate::parser::{format_api, parse_api, parse_number};
use crate::session::Command;
use crate::state::{CliState, find_domain_handle, find_memory_handle};
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

    // Automatically schedule root domain on all cores and initialise VP run-states.
    let num_cores = state.num_cores as u64;
    state.platform.register_domain(0, None);
    for core_id in 0..num_cores {
        state.platform.set_core_domain(core_id, 0); // Root domain ID is 0

        // Mark root VP[core_id] as Running on core_id so VP-aware switches work.
        let vp = root.read().data.policy.vprocessor_states.get(core_id as usize).cloned();
        if let Some(vp_arc) = vp {
            *vp_arc.run_state.write() = VpRunState::Running { core: core_id, caller: None };
            state.platform.set_core_vp(core_id, Some(core_id));
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

    let parent = state
        .domains
        .get(parent_name)
        .ok_or_else(|| format!("Domain '{}' not found", parent_name))?
        .clone();

    let parent_id = parent.read().data.id;

    // Use the domain-mediated interface: allocates handle, sets owner_domain, registers in table.
    let child_handle =
        Capability::create_domain(&parent, child_policy)
            .map_err(|e| format!("Failed to create child: {:?}", e))?;

    // Retrieve the new child Arc from parent's table.
    let child = parent
        .read()
        .data
        .domain_capabilities
        .get(&child_handle)
        .and_then(|w| w.upgrade())
        .ok_or("Internal error: child not found in parent table after creation")?;

    let child_id = child.read().data.id;

    // Track domain name for reverse lookup
    state.register_domain_name(child_id, child_name.to_string());
    state.domains.insert(child_name.to_string(), child);

    // Register with platform
    state.platform.register_domain(child_id, Some(parent_id));

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
        .ok_or_else(|| format!("Domain '{}' not found", domain_name))?
        .clone();

    // Find the owner domain and the handle it holds for this domain.
    let owner_id = domain.read().owned.owner;
    let owner = state
        .get_domain_cap_by_id(owner_id)
        .ok_or_else(|| format!("Owner domain (ID: {}) not found", owner_id))?;

    let cap_handle = find_domain_handle(&owner, &domain)
        .ok_or_else(|| format!("Domain '{}' not found in owner's capability table", domain_name))?;

    Capability::seal_domain(&owner, cap_handle)
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
    if let (Some(parent), Some(child)) = (
        state.memories.get(parent_name).cloned(),
        state.memories.get(child_name).cloned(),
    ) {
        let child_sub = child.read().sub_handle;

        // Find the owner of the parent memory and its handle for parent
        let owner_id = parent.read().owned.owner;
        let owner = state
            .get_domain_cap_by_id(owner_id)
            .ok_or_else(|| format!("Owner domain (ID: {}) not found", owner_id))?;
        let parent_handle = find_memory_handle(&owner, &parent)
            .ok_or_else(|| format!("Memory '{}' not found in owner's capability table", parent_name))?;

        let platform = state.platform.clone();
        let (_, batch) = execute(&*platform, true, || {
            let updates = Capability::revoke_memory_child(&owner, parent_handle, child_sub)?;
            Ok(((), updates))
        })
        .map_err(|e| format!("Failed to revoke memory: {:?}", e))?;

        println!(
            "{} Revoked memory '{}' from '{}'",
            "✓".bright_green().bold(),
            child_name.bright_white(),
            parent_name.bright_white()
        );

        // Process updates (this will remove revoked capabilities from state)
        process_updates(state, &batch);

        // Record command
        state.session.add_command(Command::Revoke {
            parent: parent_name.to_string(),
            child: child_name.to_string(),
        });

        return Ok(());
    }

    // Try to revoke as domain
    if let (Some(parent), Some(child)) = (
        state.domains.get(parent_name).cloned(),
        state.domains.get(child_name).cloned(),
    ) {
        let child_handle = find_domain_handle(&parent, &child)
            .ok_or_else(|| format!("Domain '{}' not found in parent '{}' capability table", child_name, parent_name))?;

        let platform = state.platform.clone();
        let (_, batch) = execute(&*platform, true, || {
            let updates = Capability::revoke_domain(&parent, child_handle)?;
            Ok(((), updates))
        })
        .map_err(|e| format!("Failed to revoke domain: {:?}", e))?;

        println!(
            "{} Revoked domain '{}' from '{}' - cascading to all children and capabilities",
            "✓".bright_green().bold(),
            child_name.bright_white(),
            parent_name.bright_white()
        );

        // Process updates (this will remove revoked domains and their capabilities from state)
        process_updates(state, &batch);

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
pub fn cmd_set_interrupt_policy(
    state: &mut CliState,
    args: &[&str],
) -> std::result::Result<(), String> {
    if args.len() != 3 {
        return Err("Usage: set-interrupt-policy <domain> <vector> <visibility>".to_string());
    }

    let domain_name = args[0];
    let vector = parse_number(args[1])? as u8;
    let visibility = parse_visibility(args[2])?;

    let domain = state
        .domains
        .get(domain_name)
        .ok_or_else(|| format!("Domain '{}' not found", domain_name))?
        .clone();

    let owner_id = domain.read().owned.owner;
    let owner = state
        .get_domain_cap_by_id(owner_id)
        .ok_or_else(|| format!("Owner domain (ID: {}) not found", owner_id))?;
    let cap_handle = find_domain_handle(&owner, &domain)
        .ok_or_else(|| format!("Domain '{}' not found in owner's capability table", domain_name))?;

    Capability::set_policy(
        &owner,
        cap_handle,
        PolicyIdentifier::VectorVisibility(vector),
        visibility as u64,
    )
    .map_err(|e| format!("Failed to set interrupt policy: {:?}", e))?;

    println!(
        "{} Set interrupt policy for vector {} on domain '{}': {:?}",
        "✓".bright_green().bold(),
        vector,
        domain_name.bright_white(),
        visibility as u64
    );

    Ok(())
}

/// Set default interrupt policy for all vectors
pub fn cmd_set_default_interrupt_policy(
    state: &mut CliState,
    args: &[&str],
) -> std::result::Result<(), String> {
    if args.len() != 2 {
        return Err("Usage: set-default-interrupt-policy <domain> <visibility>".to_string());
    }

    let domain_name = args[0];
    let visibility = parse_visibility(args[1])?;

    let domain = state
        .domains
        .get(domain_name)
        .ok_or_else(|| format!("Domain '{}' not found", domain_name))?
        .clone();

    let owner_id = domain.read().owned.owner;
    let owner = state
        .get_domain_cap_by_id(owner_id)
        .ok_or_else(|| format!("Owner domain (ID: {}) not found", owner_id))?;
    let cap_handle = find_domain_handle(&owner, &domain)
        .ok_or_else(|| format!("Domain '{}' not found in owner's capability table", domain_name))?;

    Capability::set_policy(
        &owner,
        cap_handle,
        PolicyIdentifier::DefaultInterruptVisibility,
        visibility as u64,
    )
    .map_err(|e| format!("Failed to set default interrupt policy: {:?}", e))?;

    println!(
        "{} Set default interrupt policy for domain '{}': {:?}",
        "✓".bright_green().bold(),
        domain_name.bright_white(),
        visibility as u64
    );

    Ok(())
}

fn parse_visibility(s: &str) -> std::result::Result<InterruptVisibility, String> {
    match s.to_uppercase().as_str() {
        "DELIVER" => Ok(InterruptVisibility::Deliver),
        "REPORT" => Ok(InterruptVisibility::Report),
        "NOTREPORT" => Ok(InterruptVisibility::NotReport),
        _ => Err(format!(
            "Invalid visibility: {}. Use DELIVER, REPORT, or NOTREPORT",
            s
        )),
    }
}

/// Set any policy on a child domain: set-policy <parent> <child> <policy> <value>
pub fn cmd_set_policy(
    state: &mut CliState,
    args: &[&str],
) -> std::result::Result<(), String> {
    if args.len() != 4 {
        return Err(
            "Usage: set-policy <parent> <child> <policy> <value>\n  Policies: cores, api-monitor, default-visibility, vector-visibility:<v>, vector-read:<v>, vector-write:<v>".to_string(),
        );
    }

    let parent_name = args[0];
    let child_name = args[1];
    let policy_str = args[2];
    let value = parse_number(args[3])?;

    let parent = state
        .domains
        .get(parent_name)
        .ok_or_else(|| format!("Domain '{}' not found", parent_name))?
        .clone();
    let child = state
        .domains
        .get(child_name)
        .ok_or_else(|| format!("Domain '{}' not found", child_name))?
        .clone();

    let cap_handle = find_domain_handle(&parent, &child)
        .ok_or_else(|| format!("Domain '{}' not found in '{}' capability table", child_name, parent_name))?;

    let policy_id = parse_policy_id(policy_str)?;

    Capability::set_policy(&parent, cap_handle, policy_id, value)
        .map_err(|e| format!("Failed to set policy: {:?}", e))?;

    println!(
        "{} Set policy '{}' = {} on domain '{}' (via '{}')",
        "✓".bright_green().bold(),
        policy_str,
        value,
        child_name.bright_white(),
        parent_name
    );

    Ok(())
}

/// Get any policy from a child domain: get-policy <parent> <child> <policy>
pub fn cmd_get_policy(
    state: &mut CliState,
    args: &[&str],
) -> std::result::Result<(), String> {
    if args.len() != 3 {
        return Err(
            "Usage: get-policy <parent> <child> <policy>".to_string(),
        );
    }

    let parent_name = args[0];
    let child_name = args[1];
    let policy_str = args[2];

    let parent = state
        .domains
        .get(parent_name)
        .ok_or_else(|| format!("Domain '{}' not found", parent_name))?
        .clone();
    let child = state
        .domains
        .get(child_name)
        .ok_or_else(|| format!("Domain '{}' not found", child_name))?
        .clone();

    let cap_handle = find_domain_handle(&parent, &child)
        .ok_or_else(|| format!("Domain '{}' not found in '{}' capability table", child_name, parent_name))?;

    let policy_id = parse_policy_id(policy_str)?;

    let value = Capability::get_policy(&parent, cap_handle, policy_id)
        .map_err(|e| format!("Failed to get policy: {:?}", e))?;

    println!(
        "{} Policy '{}' on domain '{}': {}",
        "✓".bright_green().bold(),
        policy_str,
        child_name.bright_white(),
        value
    );

    Ok(())
}

/// Set a VP register: set-register <parent> <child> <vp_id> <reg_id> <value>
pub fn cmd_set_register(
    state: &mut CliState,
    args: &[&str],
) -> std::result::Result<(), String> {
    if args.len() != 5 {
        return Err("Usage: set-register <parent> <child> <vp_id> <reg_id> <value>".to_string());
    }

    let parent_name = args[0];
    let child_name = args[1];
    let vp_id = parse_number(args[2])?;
    let reg_id = parse_number(args[3])?;
    let value = parse_number(args[4])?;

    let parent = state
        .domains
        .get(parent_name)
        .ok_or_else(|| format!("Domain '{}' not found", parent_name))?
        .clone();
    let child = state
        .domains
        .get(child_name)
        .ok_or_else(|| format!("Domain '{}' not found", child_name))?
        .clone();

    let cap_handle = find_domain_handle(&parent, &child)
        .ok_or_else(|| format!("Domain '{}' not found in '{}' capability table", child_name, parent_name))?;

    Capability::set_register(&parent, cap_handle, vp_id, reg_id, value, state.platform.as_ref())
        .map_err(|e| format!("Failed to set register: {:?}", e))?;

    println!(
        "{} Set VP[{}] reg[{}] = {} on domain '{}'",
        "✓".bright_green().bold(),
        vp_id,
        reg_id,
        value,
        child_name.bright_white()
    );

    Ok(())
}

/// Get a VP register: get-register <parent> <child> <vp_id> <reg_id>
pub fn cmd_get_register(
    state: &mut CliState,
    args: &[&str],
) -> std::result::Result<(), String> {
    if args.len() != 4 {
        return Err("Usage: get-register <parent> <child> <vp_id> <reg_id>".to_string());
    }

    let parent_name = args[0];
    let child_name = args[1];
    let vp_id = parse_number(args[2])?;
    let reg_id = parse_number(args[3])?;

    let parent = state
        .domains
        .get(parent_name)
        .ok_or_else(|| format!("Domain '{}' not found", parent_name))?
        .clone();
    let child = state
        .domains
        .get(child_name)
        .ok_or_else(|| format!("Domain '{}' not found", child_name))?
        .clone();

    let cap_handle = find_domain_handle(&parent, &child)
        .ok_or_else(|| format!("Domain '{}' not found in '{}' capability table", child_name, parent_name))?;

    let value = Capability::get_register(&parent, cap_handle, vp_id, reg_id, state.platform.as_ref())
        .map_err(|e| format!("Failed to get register: {:?}", e))?;

    println!(
        "{} VP[{}] reg[{}] on domain '{}': {}",
        "✓".bright_green().bold(),
        vp_id,
        reg_id,
        child_name.bright_white(),
        value
    );

    Ok(())
}

fn parse_policy_id(s: &str) -> std::result::Result<PolicyIdentifier, String> {
    if s.eq_ignore_ascii_case("cores") {
        return Ok(PolicyIdentifier::Cores);
    }
    if s.eq_ignore_ascii_case("api-monitor") {
        return Ok(PolicyIdentifier::ApiMonitor);
    }
    if s.eq_ignore_ascii_case("default-visibility") {
        return Ok(PolicyIdentifier::DefaultInterruptVisibility);
    }
    if let Some(rest) = s.strip_prefix("vector-visibility:") {
        let v = rest.parse::<u8>().map_err(|_| format!("Invalid vector: {}", rest))?;
        return Ok(PolicyIdentifier::VectorVisibility(v));
    }
    if let Some(rest) = s.strip_prefix("vector-read:") {
        let v = rest.parse::<u8>().map_err(|_| format!("Invalid vector: {}", rest))?;
        return Ok(PolicyIdentifier::VectorRegReadSet(v));
    }
    if let Some(rest) = s.strip_prefix("vector-write:") {
        let v = rest.parse::<u8>().map_err(|_| format!("Invalid vector: {}", rest))?;
        return Ok(PolicyIdentifier::VectorRegWriteSet(v));
    }
    Err(format!("Unknown policy: '{}'. Use: cores, api-monitor, default-visibility, vector-visibility:<v>, vector-read:<v>, vector-write:<v>", s))
}

/// Enumerate pending capabilities for a sealed domain
pub fn cmd_enumerate_pending(
    state: &mut CliState,
    args: &[&str],
) -> std::result::Result<(), String> {
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
        if let Some(pending_cap) = domain_read.data.pending_capabilities.get(&pending_id) {
            if let Some(mem_ref) = pending_cap.cap.upgrade() {
                let mem = mem_ref.read();
                println!(
                    "  {} [ID: {}] Memory [0x{:x}..0x{:x}) {:?} (sender: {})",
                    "→".bright_blue(),
                    pending_id,
                    mem.data.access.start,
                    mem.data.access.end(),
                    mem.data.access.rights,
                    pending_cap.sender_domain_id
                );
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
pub fn cmd_accept_capability(
    state: &mut CliState,
    args: &[&str],
) -> std::result::Result<(), String> {
    if args.len() != 2 {
        return Err("Usage: accept-capability <domain> <pending_id>".to_string());
    }

    let domain_name = args[0];
    let pending_id = parse_number(args[1])?;

    let domain = state
        .domains
        .get(domain_name)
        .ok_or_else(|| format!("Domain '{}' not found", domain_name))?;

    // Accept the pending memory capability using the new API
    let platform = state.platform.clone();
    let (handle, batch) = execute(&*platform, false, || {
        let (h, updates) = Capability::accept_memory(domain, pending_id)?;
        Ok((h, updates))
    })
    .map_err(|e| format!("Failed to accept capability: {:?}", e))?;

    // Process updates
    process_updates(state, &batch);

    println!(
        "{} Accepted pending memory capability {} as handle {}",
        "✓".bright_green().bold(),
        pending_id,
        handle
    );

    // Record command
    state.session.add_command(Command::AcceptCapability {
        domain: domain_name.to_string(),
        pending_id,
    });

    Ok(())
}

/// Reject (discard) a pending capability
pub fn cmd_reject_capability(
    state: &mut CliState,
    args: &[&str],
) -> std::result::Result<(), String> {
    if args.len() != 2 {
        return Err("Usage: reject-capability <domain> <pending_id>".to_string());
    }

    let domain_name = args[0];
    let pending_id = parse_number(args[1])?;

    let domain = state
        .domains
        .get(domain_name)
        .ok_or_else(|| format!("Domain '{}' not found", domain_name))?;

    Capability::reject_memory(domain, pending_id)
        .map_err(|e| format!("Failed to reject capability: {:?}", e))?;

    println!(
        "{} Rejected pending capability {} for domain '{}'",
        "✓".bright_green().bold(),
        pending_id,
        domain_name.bright_white()
    );

    // Record command
    state.session.add_command(Command::RejectCapability {
        domain: domain_name.to_string(),
        pending_id,
    });

    Ok(())
}
