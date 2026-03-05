//! Memory-related commands: carve, alias, send

use capability_engine::*;
use colored::*;

use crate::parser::{parse_attributes, parse_number, parse_rights, format_rights, format_attributes};
use crate::session::Command;
use crate::state::{CliState, find_domain_handle, find_domain_owner, find_memory_handle};
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
        Capability::carve(&owner, parent_handle, access)
            .map(|(h, _sub, b)| (h, b))
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

    let (child_handle, _) = Capability::alias(&owner, parent_handle, access)
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
    // Detect channel send: first arg is a domain cap (channel), not a memory region.
    if args.len() >= 1 && state.domains.contains_key(args[0]) {
        if args.len() != 2 {
            return Err("Usage: send <chan> <receiver>".to_string());
        }
        let chan_name     = args[0];
        let receiver_name = args[1];

        let chan_ref = state.domains.get(chan_name).unwrap().clone();
        let receiver = state.domains.get(receiver_name)
            .ok_or_else(|| format!("Domain '{}' not found", receiver_name))?.clone();

        // Infer sender from who owns the channel cap — mirrors memory send's owner lookup.
        let (caller_name, caller, chan_handle) = find_domain_owner(state, &chan_ref)
            .ok_or_else(|| format!("No domain found that owns channel '{}'", chan_name))?;

        let recv_handle = find_domain_handle(&caller, &receiver)
            .ok_or_else(|| format!("Domain '{}' not found in '{}' capability table", receiver_name, caller_name))?;

        Capability::<Domain>::send_channel(&caller, chan_handle, recv_handle, Attributes::NONE)
            .map_err(|e| format!("send failed: {:?}", e))?;

        let recv_sealed = receiver.read().data.is_sealed();
        if recv_sealed {
            println!(
                "{} Channel '{}' sent to '{}' (pending — use accept-channel or reject-channel)",
                "✓".bright_green().bold(), chan_name.bright_white(), receiver_name.bright_white(),
            );
        } else {
            state.domains.remove(chan_name);
            println!(
                "{} Channel '{}' transferred to '{}'",
                "✓".bright_green().bold(), chan_name.bright_white(), receiver_name.bright_white(),
            );
        }

        state.session.add_command(Command::SendChannel {
            caller: caller_name,
            chan_name: chan_name.to_string(),
            receiver: receiver_name.to_string(),
        });
        return Ok(());
    }

    // Memory send: send <mem> <domain> [attrs] [at <gpa>]
    if args.len() < 2 || args.len() > 5 {
        return Err("Usage: send <mem> <domain> [attrs] [at <gpa>]".to_string());
    }

    let mem_name = args[0];
    let domain_name = args[1];

    // Parse optional attrs and "at <gpa>" from remaining args.
    let mut attrs = Attributes::NONE;
    let mut gpa_hint: Option<u64> = None;
    let mut i = 2;
    while i < args.len() {
        if args[i] == "at" {
            if i + 1 >= args.len() {
                return Err("Usage: send <mem> <domain> [attrs] [at <gpa>]".to_string());
            }
            gpa_hint = Some(parse_number(args[i + 1])?);
            i += 2;
        } else if gpa_hint.is_none() && attrs == Attributes::NONE {
            attrs = parse_attributes(args[i])?;
            i += 1;
        } else {
            return Err("Usage: send <mem> <domain> [attrs] [at <gpa>]".to_string());
        }
    }

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
        let recv_h = find_domain_handle(&sender_domain, &domain)
            .ok_or(CapaError::NotFound)?;
        let updates = Capability::send_at(&sender_domain, sender_handle, recv_h, attrs, gpa_hint)?;
        Ok(((), updates))
    }).map_err(|e| format!("Failed to send: {:?}", e))?;

    // Process updates
    process_updates(state, &batch);

    // Record command
    state.session.add_command(Command::Send {
        mem: mem_name.to_string(),
        domain: domain_name.to_string(),
        attrs: format_attributes(&attrs),
        gpa_hint,
    });

    let gpa_msg = gpa_hint.map_or(String::new(), |g| format!(" at GPA {:#x}", g));

    if is_sealed {
        println!(
            "{} Sent '{}' to sealed domain '{}'{} - pending acceptance",
            "⏸".bright_yellow().bold(),
            mem_name.bright_white(),
            domain_name.bright_white(),
            gpa_msg,
        );
    } else {
        println!(
            "{} Sent '{}' to domain '{}'{}",
            "✓".bright_green().bold(),
            mem_name.bright_white(),
            domain_name.bright_white(),
            gpa_msg,
        );
    }

    Ok(())
}
