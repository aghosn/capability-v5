//! Memory-related commands: carve, alias, send

use capability_engine::*;
use capability_engine::domain::PendingCapability;
use colored::*;
use std::sync::Arc;

use crate::parser::{parse_attributes, parse_number, parse_rights, format_rights, format_attributes};
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
        .ok_or_else(|| format!("Memory region '{}' not found", parent_name))?
        .clone();

    let platform = state.platform.clone();
    let (child, batch) = execute(&*platform, false, || {
        let owner = parent.read().owned.owner;
        let (child, updates) = Capability::carve_child(&parent, access, owner, child_cap_id)?;
        Ok((child, updates))
    }).map_err(|e| format!("Failed to carve: {:?}", e))?;

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
    let child_cap_id = state.next_id();

    let parent = state
        .memories
        .get(parent_name)
        .ok_or_else(|| format!("Memory region '{}' not found", parent_name))?;

    let owner = parent.read().owned.owner;
    let child = Capability::alias_child(parent, access, owner, child_cap_id)
        .map_err(|e| format!("Failed to alias: {:?}", e))?;

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
        .ok_or_else(|| format!("Memory region '{}' not found", mem_name))?
        .clone();

    let domain = state
        .domains
        .get(domain_name)
        .ok_or_else(|| format!("Domain '{}' not found", domain_name))?
        .clone();

    let domain_id = domain.read().data.id;
    let is_sealed = domain.read().data.is_sealed();
    let can_receive_after_seal = domain.read().data.policy.receive_after_seal();

    // Always validate that the sender's domain allows SEND.
    mem.read()
        .owned
        .validate_operation(MonitorAPI::SEND)
        .map_err(|e| format!("Send not allowed: {:?}", e))?;

    // Check if we need to use pending queue
    if is_sealed && can_receive_after_seal {
        // Domain is sealed with RECEIVE_AFTER_SEAL - use freeze-based send.
        // Find the sender domain for this memory capability
        let sender_domain_id = mem.read().owned.owner;
        let sender_domain = state.domains.values()
            .find(|d| d.read().data.id == sender_domain_id)
            .cloned()
            .ok_or_else(|| format!("Sender domain (ID: {}) not found", sender_domain_id))?;

        // Find the sender's handle for this memory capability
        let sender_handle = {
            let sd = sender_domain.read();
            let mem_ptr = Arc::as_ptr(&mem);
            sd.data.memory_capabilities.iter()
                .find(|(_, weak)| {
                    weak.upgrade().map(|r| Arc::as_ptr(&r) == mem_ptr).unwrap_or(false)
                })
                .map(|(h, _)| *h)
                .ok_or_else(|| "Memory capability not found in sender's table".to_string())?
        };

        // Build PendingCapability and freeze the sender's handle
        let pending = PendingCapability {
            cap: Arc::downgrade(&mem),
            sender_domain_id,
            sender_handle,
            sender_domain: Arc::downgrade(&sender_domain),
        };
        sender_domain.write().data.freeze_memory_handle(sender_handle);
        mem.write().owned.attributes = attrs;
        let pending_id = domain.write().data.add_pending_capability(pending);

        // Record command
        state.session.add_command(Command::Send {
            mem: mem_name.to_string(),
            domain: domain_name.to_string(),
            handle: pending_id,
            attrs: format_attributes(&attrs),
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
        // Domain is unsealed - proceed with direct send
        let caller_id = mem.read().owned.owner;
        let handle = domain.read().data.allocate_memory_handle();
        let platform = state.platform.clone();
        let (_, batch) = execute(&*platform, false, || {
            let updates = Capability::send_to(&mem, caller_id, domain_id, attrs)?;
            Ok(((), updates))
        }).map_err(|e| format!("Failed to send: {:?}", e))?;

        // Register memory capability with domain
        domain
            .write()
            .data
            .add_memory_capability(handle, Arc::downgrade(&mem));

        // Set owner_domain so future operations on this capability enforce
        // that the new owner domain is sealed with the required API permission.
        mem.write().owned.set_owner_domain(Arc::downgrade(&domain));

        // Process updates
        process_updates(state, &batch);

        // Record command
        state.session.add_command(Command::Send {
            mem: mem_name.to_string(),
            domain: domain_name.to_string(),
            handle,
            attrs: format_attributes(&attrs),
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
