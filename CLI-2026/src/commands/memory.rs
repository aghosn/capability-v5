//! Memory-related commands: carve, alias, send

use capability_engine::*;
use colored::*;

use crate::parser::{parse_attributes, parse_number, parse_rights, format_rights, format_attributes};
use crate::session::Command;
use crate::state::{CliState, find_memory_handle};
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

    let parent = state
        .memories
        .get(parent_name)
        .ok_or_else(|| format!("Memory region '{}' not found", parent_name))?
        .clone();

    // Find the owner domain and the handle it holds for parent.
    let owner_id = parent.read().owned.owner;
    let owner = state
        .get_domain_cap_by_id(owner_id)
        .ok_or_else(|| format!("Owner domain (ID: {}) not found", owner_id))?;
    let parent_handle = find_memory_handle(&owner, &parent)
        .ok_or_else(|| format!("Memory '{}' not found in owner's capability table", parent_name))?;

    let platform = state.platform.clone();
    let (child_handle, batch) = execute(&*platform, false, || {
        Capability::carve_memory(&owner, parent_handle, access)
            .map(|(h, b)| (h, b))
    }).map_err(|e| format!("Failed to carve: {:?}", e))?;

    // Retrieve the child Arc from owner's memory table.
    let child = owner
        .read()
        .data
        .memory_capabilities
        .get(&child_handle)
        .and_then(|w| w.upgrade())
        .ok_or("Internal error: child not found in owner table after carve")?;

    state.memories.insert(child_name.to_string(), child);

    // Process updates
    process_updates(state, &batch);

    // Record command
    state.session.add_command(Command::Carve {
        parent: parent_name.to_string(),
        name: child_name.to_string(),
        start,
        size,
        rights: format_rights(&rights),
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

    let parent = state
        .memories
        .get(parent_name)
        .ok_or_else(|| format!("Memory region '{}' not found", parent_name))?
        .clone();

    // Find the owner domain and its handle for parent.
    let owner_id = parent.read().owned.owner;
    let owner = state
        .get_domain_cap_by_id(owner_id)
        .ok_or_else(|| format!("Owner domain (ID: {}) not found", owner_id))?;
    let parent_handle = find_memory_handle(&owner, &parent)
        .ok_or_else(|| format!("Memory '{}' not found in owner's capability table", parent_name))?;

    let child_handle = Capability::alias_memory(&owner, parent_handle, access)
        .map_err(|e| format!("Failed to alias: {:?}", e))?;

    // Retrieve the child Arc from owner's memory table.
    let child = owner
        .read()
        .data
        .memory_capabilities
        .get(&child_handle)
        .and_then(|w| w.upgrade())
        .ok_or("Internal error: child not found in owner table after alias")?;

    state.memories.insert(child_name.to_string(), child);

    // Record command
    state.session.add_command(Command::Alias {
        parent: parent_name.to_string(),
        name: child_name.to_string(),
        start,
        size,
        rights: format_rights(&rights),
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

/// Send memory capability to domain
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
        .ok_or_else(|| format!("Memory region '{}' not found", mem_name))?
        .clone();

    let domain = state
        .domains
        .get(domain_name)
        .ok_or_else(|| format!("Domain '{}' not found", domain_name))?
        .clone();

    // Find the sender domain
    let sender_domain_id = mem.read().owned.owner;
    let sender_domain = state
        .get_domain_cap_by_id(sender_domain_id)
        .ok_or_else(|| format!("Sender domain (ID: {}) not found", sender_domain_id))?;

    // Find the sender's handle for this memory capability
    let sender_handle = find_memory_handle(&sender_domain, &mem)
        .ok_or_else(|| "Memory capability not found in sender's table".to_string())?;

    let is_sealed = domain.read().data.is_sealed();

    let platform = state.platform.clone();
    let (_, batch) = execute(&*platform, !is_sealed, || {
        let updates = Capability::send_memory(&sender_domain, sender_handle, &domain, attrs)?;
        Ok(((), updates))
    }).map_err(|e| format!("Failed to send: {:?}", e))?;

    // Process updates
    process_updates(state, &batch);

    // Record command
    state.session.add_command(Command::Send {
        mem: mem_name.to_string(),
        domain: domain_name.to_string(),
        handle: sender_handle,
        attrs: format_attributes(&attrs),
    });

    if is_sealed {
        println!(
            "{} Sent '{}' to sealed domain '{}' - pending acceptance",
            "⏸".bright_yellow().bold(),
            mem_name.bright_white(),
            domain_name.bright_white(),
        );
    } else {
        println!(
            "{} Sent '{}' to domain '{}'",
            "✓".bright_green().bold(),
            mem_name.bright_white(),
            domain_name.bright_white(),
        );
    }

    Ok(())
}
