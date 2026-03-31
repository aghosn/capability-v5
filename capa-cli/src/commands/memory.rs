//! Memory-related commands routed through the Backend trait.

use colored::*;

use crate::parser::{parse_attributes, parse_number, parse_rights, format_rights};
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

    let parent_uid = *state
        .mem_names
        .get(parent_name)
        .ok_or_else(|| format!("Memory region '{}' not found", parent_name))?;

    let owner_id = *state
        .mem_owners
        .get(&parent_uid)
        .ok_or_else(|| format!("Owner of memory '{}' not found", parent_name))?;

    let (child_uid, updates) = state
        .backend
        .carve(owner_id, parent_uid, start, size, rights.bits())
        .map_err(|e| format!("Failed to carve: {}", e))?;

    state.mem_names.insert(child_name.to_string(), child_uid);
    state.mem_owners.insert(child_uid, owner_id);

    process_updates(state, &updates);

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

    let parent_uid = *state
        .mem_names
        .get(parent_name)
        .ok_or_else(|| format!("Memory region '{}' not found", parent_name))?;

    let owner_id = *state
        .mem_owners
        .get(&parent_uid)
        .ok_or_else(|| format!("Owner of memory '{}' not found", parent_name))?;

    let (child_uid, updates) = state
        .backend
        .alias(owner_id, parent_uid, start, size, rights.bits())
        .map_err(|e| format!("Failed to alias: {}", e))?;

    state.mem_names.insert(child_name.to_string(), child_uid);
    state.mem_owners.insert(child_uid, owner_id);

    process_updates(state, &updates);

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

/// Send memory or channel capability to domain
pub fn cmd_send(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    // Detect channel send: first arg is a domain cap (channel), not a memory region.
    if !args.is_empty() && state.domain_names.contains_key(args[0]) {
        if args.len() != 2 {
            return Err("Usage: send <chan> <receiver>".to_string());
        }
        let chan_name = args[0];
        let receiver_name = args[1];

        let chan_id = *state.domain_names.get(chan_name).unwrap();
        let receiver_id = *state
            .domain_names
            .get(receiver_name)
            .ok_or_else(|| format!("Domain '{}' not found", receiver_name))?;

        // Infer caller from who owns the channel cap
        let caller_id = *state
            .domain_parents
            .get(&chan_id)
            .ok_or_else(|| format!("No domain found that owns channel '{}'", chan_name))?;

        let caller_name = state
            .get_domain_name(caller_id)
            .ok_or_else(|| format!("Caller domain ID {} not found", caller_id))?
            .to_string();

        state
            .backend
            .send_channel(caller_id, chan_id, receiver_id)
            .map_err(|e| format!("send failed: {}", e))?;

        // Check if receiver is sealed (channel becomes pending) or not (transferred)
        let is_sealed = state
            .backend
            .list_domains()
            .iter()
            .any(|d| d.id == receiver_id && d.status == "Sealed");

        if is_sealed {
            println!(
                "{} Channel '{}' sent to '{}' (pending — use accept-channel or reject-channel)",
                "✓".bright_green().bold(),
                chan_name.bright_white(),
                receiver_name.bright_white(),
            );
        } else {
            state.domain_names.remove(chan_name);
            state.domain_id_to_name.remove(&chan_id);
            state.domain_parents.remove(&chan_id);
            println!(
                "{} Channel '{}' transferred to '{}'",
                "✓".bright_green().bold(),
                chan_name.bright_white(),
                receiver_name.bright_white(),
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
    let mut attrs_parsed = false;
    let mut attrs_bits: u8 = 0;
    let mut gpa_hint: Option<u64> = None;
    let mut i = 2;
    while i < args.len() {
        if args[i] == "at" {
            if i + 1 >= args.len() {
                return Err("Usage: send <mem> <domain> [attrs] [at <gpa>]".to_string());
            }
            gpa_hint = Some(parse_number(args[i + 1])?);
            i += 2;
        } else if gpa_hint.is_none() && !attrs_parsed {
            let parsed = parse_attributes(args[i])?;
            attrs_bits = parsed.bits();
            attrs_parsed = true;
            i += 1;
        } else {
            return Err("Usage: send <mem> <domain> [attrs] [at <gpa>]".to_string());
        }
    }

    let mem_uid = *state
        .mem_names
        .get(mem_name)
        .ok_or_else(|| format!("Memory region '{}' not found", mem_name))?;

    let receiver_id = *state
        .domain_names
        .get(domain_name)
        .ok_or_else(|| format!("Domain '{}' not found", domain_name))?;

    // Check if receiver is sealed before send (for the message)
    let is_sealed = state
        .backend
        .list_domains()
        .iter()
        .any(|d| d.id == receiver_id && d.status == "Sealed");

    let updates = state
        .backend
        .send(mem_uid, receiver_id, attrs_bits, gpa_hint)
        .map_err(|e| format!("Failed to send: {}", e))?;

    process_updates(state, &updates);

    // When the receiver is not sealed, ownership transfers immediately.
    if !is_sealed {
        state.mem_owners.insert(mem_uid, receiver_id);
    }

    // Record command — reconstruct the attrs string for the session recorder.
    let attrs_str = if attrs_parsed {
        args[2].to_string()
    } else {
        "NONE".to_string()
    };
    state.session.add_command(Command::Send {
        mem: mem_name.to_string(),
        domain: domain_name.to_string(),
        attrs: attrs_str,
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

/// Register a memory capability as a COMM page bound to a child domain's VP.
pub fn cmd_register_comm(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.len() != 3 {
        return Err("Usage: register-comm <mem> <child_domain> <vp_id>".to_string());
    }

    let mem_name = args[0];
    let child_domain_name = args[1];
    let vp_id: u32 = args[2]
        .parse()
        .map_err(|_| format!("Invalid vp_id: '{}'", args[2]))?;

    let mem_uid = *state
        .mem_names
        .get(mem_name)
        .ok_or_else(|| format!("Memory region '{}' not found", mem_name))?;

    let owner_id = *state
        .mem_owners
        .get(&mem_uid)
        .ok_or_else(|| format!("Owner of memory '{}' not found", mem_name))?;

    let child_id = *state
        .domain_names
        .get(child_domain_name)
        .ok_or_else(|| format!("Child domain '{}' not found", child_domain_name))?;

    let updates = state
        .backend
        .register_comm(owner_id, mem_uid, child_id, vp_id)
        .map_err(|e| format!("register-comm failed: {}", e))?;

    process_updates(state, &updates);

    state.session.add_command(Command::RegisterComm {
        mem: mem_name.to_string(),
        child_domain: child_domain_name.to_string(),
        vp_id,
    });

    println!(
        "{} '{}' registered as COMM page for domain '{}' VP {}",
        "✓".bright_green().bold(),
        mem_name.bright_white(),
        child_domain_name.bright_white(),
        vp_id,
    );

    Ok(())
}
