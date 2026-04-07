//! Domain-related commands routed through the Backend trait.
//!
//! Every operation goes through `state.backend.*` — no direct `capability_engine`
//! calls except for type-level imports used in argument parsing.

use colored::*;

use crate::parser::{format_api, parse_api, parse_number};
use crate::session::Command;
use crate::state::CliState;
use crate::update_processor::process_updates;

// InterruptVisibility values (Deliver=0, Report=1, NotReport=2) — matches
// capability_engine::InterruptVisibility enum discriminants.
fn parse_visibility(s: &str) -> std::result::Result<u64, String> {
    match s.to_uppercase().as_str() {
        "DELIVER" => Ok(0),
        "REPORT" => Ok(1),
        "NOTREPORT" => Ok(2),
        _ => Err(format!(
            "Invalid visibility: {}. Use DELIVER, REPORT, or NOTREPORT",
            s
        )),
    }
}

/// Initialize root domain and memory region
pub fn cmd_init(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.len() != 2 {
        return Err("Usage: init <name> <size>".to_string());
    }

    let name = args[0];
    let size = parse_number(args[1])?;

    let result = state
        .backend
        .init(size)
        .map_err(|e| format!("Failed to initialize: {}", e))?;

    let domain_id = result.domain_id;
    let mem_uid = result.mem_uid;

    state.register_domain_name(domain_id, name.to_string());
    state.mem_names.insert("r0".to_string(), mem_uid);
    state.mem_owners.insert(mem_uid, domain_id);

    state.session.add_command(Command::Init {
        name: name.to_string(),
        size,
    });

    let num_cores = state.num_cores;
    println!(
        "{} Created root domain '{}' and memory region '{}' (size: 0x{:x})",
        "✓".bright_green().bold(),
        name.bright_white(),
        "r0".bright_white(),
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

    let parent_id = *state
        .domain_names
        .get(parent_name)
        .ok_or_else(|| format!("Domain '{}' not found", parent_name))?;

    let (child_id, updates) = state
        .backend
        .create_domain(parent_id, cores, api.bits() as u64)
        .map_err(|e| format!("Failed to create child: {}", e))?;

    state.register_domain_name(child_id, child_name.to_string());
    state.domain_parents.insert(child_id, parent_id);

    process_updates(state, &updates);

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
    let child_id = *state
        .domain_names
        .get(domain_name)
        .ok_or_else(|| format!("Domain '{}' not found", domain_name))?;

    let owner_id = *state
        .domain_parents
        .get(&child_id)
        .ok_or_else(|| format!("Owner of domain '{}' not found", domain_name))?;

    state
        .backend
        .seal(owner_id, child_id)
        .map_err(|e| format!("Failed to seal: {}", e))?;

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

    // Try memory revoke first
    if let (Some(&parent_uid), Some(&child_uid)) = (
        state.mem_names.get(parent_name),
        state.mem_names.get(child_name),
    ) {
        let owner_id = *state
            .mem_owners
            .get(&parent_uid)
            .ok_or_else(|| format!("Owner of memory '{}' not found", parent_name))?;

        let updates = state
            .backend
            .revoke_mem(owner_id, parent_uid, child_uid)
            .map_err(|e| format!("Failed to revoke memory: {}", e))?;

        println!(
            "{} Revoked memory '{}' from '{}'",
            "✓".bright_green().bold(),
            child_name.bright_white(),
            parent_name.bright_white()
        );

        process_updates(state, &updates);

        // Remove the child from state maps
        if let Some(uid) = state.mem_names.remove(child_name) {
            state.mem_owners.remove(&uid);
        }

        state.session.add_command(Command::Revoke {
            parent: parent_name.to_string(),
            child: child_name.to_string(),
        });

        return Ok(());
    }

    // Try domain revoke
    if let (Some(&parent_id), Some(&child_id)) = (
        state.domain_names.get(parent_name),
        state.domain_names.get(child_name),
    ) {
        let updates = state
            .backend
            .revoke_domain(parent_id, child_id)
            .map_err(|e| format!("Failed to revoke domain: {}", e))?;

        println!(
            "{} Revoked domain '{}' from '{}' - cascading to all children and capabilities",
            "✓".bright_green().bold(),
            child_name.bright_white(),
            parent_name.bright_white()
        );

        process_updates(state, &updates);

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

    let child_id = *state
        .domain_names
        .get(domain_name)
        .ok_or_else(|| format!("Domain '{}' not found", domain_name))?;

    let owner_id = *state
        .domain_parents
        .get(&child_id)
        .ok_or_else(|| format!("Owner of domain '{}' not found", domain_name))?;

    state
        .backend
        .set_interrupt_policy(owner_id, child_id, vector, visibility)
        .map_err(|e| format!("Failed to set interrupt policy: {}", e))?;

    println!(
        "{} Set interrupt policy for vector {} on domain '{}': {}",
        "✓".bright_green().bold(),
        vector,
        domain_name.bright_white(),
        visibility
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

    let child_id = *state
        .domain_names
        .get(domain_name)
        .ok_or_else(|| format!("Domain '{}' not found", domain_name))?;

    let owner_id = *state
        .domain_parents
        .get(&child_id)
        .ok_or_else(|| format!("Owner of domain '{}' not found", domain_name))?;

    state
        .backend
        .set_policy(owner_id, child_id, "default-visibility", visibility)
        .map_err(|e| format!("Failed to set default interrupt policy: {}", e))?;

    println!(
        "{} Set default interrupt policy for domain '{}': {}",
        "✓".bright_green().bold(),
        domain_name.bright_white(),
        visibility
    );

    Ok(())
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

    let parent_id = *state
        .domain_names
        .get(parent_name)
        .ok_or_else(|| format!("Domain '{}' not found", parent_name))?;
    let child_id = *state
        .domain_names
        .get(child_name)
        .ok_or_else(|| format!("Domain '{}' not found", child_name))?;

    state
        .backend
        .set_policy(parent_id, child_id, policy_str, value)
        .map_err(|e| format!("Failed to set policy: {}", e))?;

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
        return Err("Usage: get-policy <parent> <child> <policy>".to_string());
    }

    let parent_name = args[0];
    let child_name = args[1];
    let policy_str = args[2];

    let parent_id = *state
        .domain_names
        .get(parent_name)
        .ok_or_else(|| format!("Domain '{}' not found", parent_name))?;
    let child_id = *state
        .domain_names
        .get(child_name)
        .ok_or_else(|| format!("Domain '{}' not found", child_name))?;

    let value = state
        .backend
        .get_policy(parent_id, child_id, policy_str)
        .map_err(|e| format!("Failed to get policy: {}", e))?;

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

    let parent_id = *state
        .domain_names
        .get(parent_name)
        .ok_or_else(|| format!("Domain '{}' not found", parent_name))?;
    let child_id = *state
        .domain_names
        .get(child_name)
        .ok_or_else(|| format!("Domain '{}' not found", child_name))?;

    state
        .backend
        .set_register(parent_id, child_id, vp_id, reg_id, value)
        .map_err(|e| format!("Failed to set register: {}", e))?;

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

    let parent_id = *state
        .domain_names
        .get(parent_name)
        .ok_or_else(|| format!("Domain '{}' not found", parent_name))?;
    let child_id = *state
        .domain_names
        .get(child_name)
        .ok_or_else(|| format!("Domain '{}' not found", child_name))?;

    let value = state
        .backend
        .get_register(parent_id, child_id, vp_id, reg_id)
        .map_err(|e| format!("Failed to get register: {}", e))?;

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

/// Enumerate pending capabilities for a sealed domain
pub fn cmd_enumerate_pending(
    state: &mut CliState,
    args: &[&str],
) -> std::result::Result<(), String> {
    if args.len() != 1 {
        return Err("Usage: enumerate-pending <domain>".to_string());
    }

    let domain_name = args[0];
    let domain_id = *state
        .domain_names
        .get(domain_name)
        .ok_or_else(|| format!("Domain '{}' not found", domain_name))?;

    let pending = state.backend.get_pending_caps(domain_id);

    if pending.is_empty() {
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

    for p in &pending {
        if p.is_domain {
            println!(
                "  {} [ID: {}] Channel (sender: {})",
                "→".bright_blue(),
                p.pending_id,
                p.sender_id
            );
        } else {
            println!(
                "  {} [ID: {}] Memory [0x{:x}..0x{:x}) {} (sender: {})",
                "→".bright_blue(),
                p.pending_id,
                p.start,
                p.end,
                p.rights,
                p.sender_id
            );
        }
    }
    println!();

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
    if args.len() < 2 || args.len() > 4 {
        return Err("Usage: accept-capability <domain> <pending_id> [at <gpa>]".to_string());
    }

    let domain_name = args[0];
    let pending_id = parse_number(args[1])?;

    // Parse optional "at <gpa>".
    let gpa_override: Option<u64> = if args.len() >= 4 && args[2] == "at" {
        Some(parse_number(args[3])?)
    } else if args.len() > 2 {
        return Err("Usage: accept-capability <domain> <pending_id> [at <gpa>]".to_string());
    } else {
        None
    };

    let domain_id = *state
        .domain_names
        .get(domain_name)
        .ok_or_else(|| format!("Domain '{}' not found", domain_name))?;

    let (mem_uid, updates) = state
        .backend
        .accept(domain_id, pending_id, gpa_override)
        .map_err(|e| format!("Failed to accept capability: {}", e))?;

    process_updates(state, &updates);

    // Track the accepted memory's ownership
    state.mem_owners.insert(mem_uid, domain_id);

    let gpa_msg = gpa_override.map_or(String::new(), |g| format!(" at GPA {:#x}", g));
    println!(
        "{} Accepted pending memory capability {} as uid {}{}",
        "✓".bright_green().bold(),
        pending_id,
        mem_uid,
        gpa_msg,
    );

    state.session.add_command(Command::AcceptCapability {
        domain: domain_name.to_string(),
        pending_id,
    });

    Ok(())
}

/// Obtain a channel capability: get-chan <target> <chan_name>
/// The caller is inferred as the parent of <target>.
pub fn cmd_get_chan(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.len() != 2 {
        return Err("Usage: get-chan <target> <chan_name>".to_string());
    }
    let target_name = args[0];
    let chan_name = args[1];

    let target_id = *state
        .domain_names
        .get(target_name)
        .ok_or_else(|| format!("Domain '{}' not found", target_name))?;

    let caller_id = *state
        .domain_parents
        .get(&target_id)
        .ok_or_else(|| format!("No domain found that owns '{}'", target_name))?;

    let caller_name = state
        .get_domain_name(caller_id)
        .ok_or_else(|| format!("Caller domain ID {} not found", caller_id))?
        .to_string();

    let chan_id = state
        .backend
        .get_chan(caller_id, target_id)
        .map_err(|e| format!("get-chan failed: {}", e))?;

    state.register_domain_name(chan_id, chan_name.to_string());
    state.domain_parents.insert(chan_id, caller_id);

    state.session.add_command(Command::GetChan {
        caller: caller_name.clone(),
        target: target_name.to_string(),
        chan_name: chan_name.to_string(),
    });

    println!(
        "{} Created channel '{}' → '{}' (owned by '{}')",
        "✓".bright_green().bold(),
        chan_name.bright_white(),
        target_name.bright_white(),
        caller_name.bright_white(),
    );
    Ok(())
}

/// Create a self-channel: get-chan-self <domain> <chan_name>
/// The domain gets a channel pointing back to itself.
pub fn cmd_get_chan_self(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.len() != 2 {
        return Err("Usage: get-chan-self <domain> <chan_name>".to_string());
    }
    let domain_name = args[0];
    let chan_name = args[1];

    let domain_id = *state
        .domain_names
        .get(domain_name)
        .ok_or_else(|| format!("Domain '{}' not found", domain_name))?;

    let chan_id = state
        .backend
        .get_chan_self(domain_id)
        .map_err(|e| format!("get-chan-self failed: {}", e))?;

    state.register_domain_name(chan_id, chan_name.to_string());
    state.domain_parents.insert(chan_id, domain_id);

    state.session.add_command(Command::GetChanSelf {
        domain: domain_name.to_string(),
        chan_name: chan_name.to_string(),
    });

    println!(
        "{} Created self-channel '{}' → '{}' (owned by '{}')",
        "✓".bright_green().bold(),
        chan_name.bright_white(),
        domain_name.bright_white(),
        domain_name.bright_white(),
    );
    Ok(())
}

/// Accept a pending channel: accept-channel <receiver> <pending_id> <chan_name>
pub fn cmd_accept_channel(
    state: &mut CliState,
    args: &[&str],
) -> std::result::Result<(), String> {
    if args.len() != 3 {
        return Err("Usage: accept-channel <receiver> <pending_id> <chan_name>".to_string());
    }
    let receiver_name = args[0];
    let pending_id = parse_number(args[1])?;
    let chan_name = args[2];

    let receiver_id = *state
        .domain_names
        .get(receiver_name)
        .ok_or_else(|| format!("Domain '{}' not found", receiver_name))?;

    let chan_id = state
        .backend
        .accept_channel(receiver_id, pending_id)
        .map_err(|e| format!("accept-channel failed: {}", e))?;

    state.register_domain_name(chan_id, chan_name.to_string());
    state.domain_parents.insert(chan_id, receiver_id);

    state.session.add_command(Command::AcceptChannel {
        receiver: receiver_name.to_string(),
        pending_id,
        chan_name: chan_name.to_string(),
    });

    println!(
        "{} '{}' accepted channel as '{}'",
        "✓".bright_green().bold(),
        receiver_name.bright_white(),
        chan_name.bright_white(),
    );
    Ok(())
}

/// Reject a pending channel: reject-channel <receiver> <pending_id>
pub fn cmd_reject_channel(
    state: &mut CliState,
    args: &[&str],
) -> std::result::Result<(), String> {
    if args.len() != 2 {
        return Err("Usage: reject-channel <receiver> <pending_id>".to_string());
    }
    let receiver_name = args[0];
    let pending_id = parse_number(args[1])?;

    let receiver_id = *state
        .domain_names
        .get(receiver_name)
        .ok_or_else(|| format!("Domain '{}' not found", receiver_name))?;

    state
        .backend
        .reject_channel(receiver_id, pending_id)
        .map_err(|e| format!("reject-channel failed: {}", e))?;

    state.session.add_command(Command::RejectChannel {
        receiver: receiver_name.to_string(),
        pending_id,
    });

    println!(
        "{} '{}' rejected pending channel {}",
        "✓".bright_green().bold(),
        receiver_name.bright_white(),
        pending_id,
    );
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

    let domain_id = *state
        .domain_names
        .get(domain_name)
        .ok_or_else(|| format!("Domain '{}' not found", domain_name))?;

    state
        .backend
        .reject(domain_id, pending_id)
        .map_err(|e| format!("Failed to reject capability: {}", e))?;

    println!(
        "{} Rejected pending capability {} for domain '{}'",
        "✓".bright_green().bold(),
        pending_id,
        domain_name.bright_white()
    );

    state.session.add_command(Command::RejectCapability {
        domain: domain_name.to_string(),
        pending_id,
    });

    Ok(())
}

