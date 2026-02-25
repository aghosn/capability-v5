//! Memory-related commands: carve, alias, send

use capability_engine::*;
use capability_engine::domain::PendingCapability;
use colored::*;
use std::sync::Arc;

use crate::parser::{parse_attributes, parse_number, parse_rights};
use crate::session::Command;
use crate::state::CliState;
use crate::update_processor::process_updates;

/// Carve exclusive memory from parent
pub fn cmd_carve(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.len() != 5 {
        return Err("Usage: carve <parent> <name> <start> <size> <rights>".to_string());
    }

    let parent_name = args[0];
    let child_name = args[1];
    let start = parse_number(args[2])?;
    let size = parse_number(args[3])?;
    let rights = parse_rights(args[4])?;

    let access = Access::new(start, size, rights);
    let child_cap_id = state.next_id();

    let parent = state
        .memories
        .get(parent_name)
        .ok_or_else(|| format!("Memory region '{}' not found", parent_name))?;

    let (child, updates): (_, UpdateBatch) = parent
        .carve(access, child_cap_id)
        .map_err(|e| format!("Failed to carve: {:?}", e))?;

    state.memories.insert(child_name.to_string(), child);

    // Process updates
    process_updates(state, &updates);

    // Record command
    state.session.add_command(Command::Carve {
        parent: parent_name.to_string(),
        name: child_name.to_string(),
        start,
        size,
        rights: format!("{:?}", rights),
    });

    println!(
        "{} Carved memory region '{}' [0x{:x}..0x{:x}) {:?}",
        "✓".bright_green().bold(),
        child_name.bright_white(),
        start,
        start + size,
        rights
    );

    Ok(())
}

/// Create aliased (shared) memory from parent
pub fn cmd_alias(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.len() != 5 {
        return Err("Usage: alias <parent> <name> <start> <size> <rights>".to_string());
    }

    let parent_name = args[0];
    let child_name = args[1];
    let start = parse_number(args[2])?;
    let size = parse_number(args[3])?;
    let rights = parse_rights(args[4])?;

    let access = Access::new(start, size, rights);
    let child_cap_id = state.next_id();

    let parent = state
        .memories
        .get(parent_name)
        .ok_or_else(|| format!("Memory region '{}' not found", parent_name))?;

    let child = parent
        .alias(access, child_cap_id)
        .map_err(|e| format!("Failed to alias: {:?}", e))?;

    state.memories.insert(child_name.to_string(), child);

    // Record command
    state.session.add_command(Command::Alias {
        parent: parent_name.to_string(),
        name: child_name.to_string(),
        start,
        size,
        rights: format!("{:?}", rights),
    });

    println!(
        "{} Aliased memory region '{}' [0x{:x}..0x{:x}) {:?}",
        "✓".bright_green().bold(),
        child_name.bright_white(),
        start,
        start + size,
        rights
    );

    Ok(())
}

/// Send memory capability to domain (handle auto-allocated)
pub fn cmd_send(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.len() < 2 || args.len() > 3 {
        return Err("Usage: send <mem> <domain> [attrs]".to_string());
    }

    let mem_name = args[0];
    let domain_name = args[1];
    let attrs = if args.len() == 3 {
        parse_attributes(args[2])?
    } else {
        Attributes::NONE
    };

    let mem = state
        .memories
        .get(mem_name)
        .ok_or_else(|| format!("Memory region '{}' not found", mem_name))?;

    let domain = state
        .domains
        .get(domain_name)
        .ok_or_else(|| format!("Domain '{}' not found", domain_name))?;

    let domain_id = domain.read().data.id;
    let is_sealed = domain.read().data.is_sealed();
    let can_receive_after_seal = domain.read().data.policy.receive_after_seal();

    // Check if we need to use pending queue
    if is_sealed && can_receive_after_seal {
        // Domain is sealed with RECEIVE_AFTER_SEAL - add to pending queue
        let pending_id = domain
            .write()
            .data
            .add_pending_capability(PendingCapability::Memory(Arc::downgrade(mem)));

        // Record command
        state.session.add_command(Command::Send {
            mem: mem_name.to_string(),
            domain: domain_name.to_string(),
            handle: pending_id, // Use pending_id as handle for recording
            attrs: format!("{:?}", attrs),
        });

        println!(
            "{} Sent '{}' to sealed domain '{}' - pending acceptance (ID: {})",
            "⏸".bright_yellow().bold(),
            mem_name.bright_white(),
            domain_name.bright_white(),
            pending_id
        );
    } else if is_sealed && !can_receive_after_seal {
        // Domain is sealed and cannot receive capabilities
        return Err(format!(
            "Domain '{}' is sealed and does not have RECEIVE_AFTER_SEAL permission",
            domain_name
        ));
    } else {
        // Domain is unsealed - proceed normally
        let handle = domain.read().data.allocate_memory_handle();

        let updates = mem
            .send(domain_id, handle, attrs)
            .map_err(|e| format!("Failed to send: {:?}", e))?;

        // Register memory capability with domain
        domain
            .write()
            .data
            .add_memory_capability(handle, Arc::downgrade(mem));

        // Process updates
        process_updates(state, &updates);

        // Record command
        state.session.add_command(Command::Send {
            mem: mem_name.to_string(),
            domain: domain_name.to_string(),
            handle,
            attrs: format!("{:?}", attrs),
        });

        println!(
            "{} Sent '{}' to unsealed domain '{}' with auto-allocated handle {}",
            "✓".bright_green().bold(),
            mem_name.bright_white(),
            domain_name.bright_white(),
            handle
        );
    }

    Ok(())
}
