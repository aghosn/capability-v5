//! Execution commands routed through the Backend trait.

use colored::*;

use crate::parser::parse_number;
use crate::session::Command;
use crate::state::CliState;

/// Switch between domains on a core using the VP-aware domain-mediated API.
///
/// Supported formats:
/// 1. `switch <core>`                   — return to the VP that called into the current domain
/// 2. `switch <domain> <core> <vp_id>`  — call into `<domain>` VP `<vp_id>` from the current VP
pub fn cmd_switch(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    match args.len() {
        // ── VP return: switch <core> ─────────────────────────────────────────
        1 => {
            let core = parse_number(args[0])?;

            let ctx = state
                .backend
                .switch_return(core)
                .map_err(|e| format!("Failed to return: {}", e))?;

            let from_name = state
                .get_domain_name(ctx.from_domain)
                .unwrap_or("unknown")
                .to_string();
            let to_name = state
                .get_domain_name(ctx.to_domain)
                .unwrap_or("unknown")
                .to_string();

            state.session.add_command(Command::Switch {
                core,
                from: from_name.clone(),
                to: to_name.clone(),
                vp_id: None,
            });

            println!(
                "{} Returned on core {} from domain '{}' (VP {}) to domain '{}' (VP {})",
                "✓".bright_green().bold(),
                core,
                from_name.bright_white(),
                ctx.from_vp
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "?".to_string()),
                to_name.bright_white(),
                ctx.to_vp
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "?".to_string()),
            );

            Ok(())
        }

        // ── VP-aware forward switch: switch <domain> <core> <vp_id> ─────────
        3 => {
            let to_name = args[0];
            let core = parse_number(args[1])?;
            let to_vp_id = parse_number(args[2])?;

            let to_id = *state
                .domain_names
                .get(to_name)
                .ok_or_else(|| format!("Domain '{}' not found", to_name))?;

            let ctx = state
                .backend
                .switch_forward(to_id, core, to_vp_id)
                .map_err(|e| format!("Failed to VP-switch: {}", e))?;

            let from_name = state
                .get_domain_name(ctx.from_domain)
                .unwrap_or("unknown")
                .to_string();
            // The actual resumed domain/VP can differ from the requested
            // target: resuming a Suspended VP walks its interrupt-resume
            // chain, which may transparently collapse past NOTREPORT
            // domains straight to the interrupted leaf. Report what the
            // engine actually did, not just what was requested.
            let actual_to_name = state
                .get_domain_name(ctx.to_domain)
                .unwrap_or("unknown")
                .to_string();

            state.session.add_command(Command::Switch {
                core,
                from: from_name.clone(),
                to: to_name.to_string(),
                vp_id: Some(to_vp_id),
            });

            println!(
                "{} Switched on core {} from '{}' (VP {}) to '{}' (VP {})",
                "✓".bright_green().bold(),
                core,
                from_name.bright_white(),
                ctx.from_vp
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "?".to_string()),
                actual_to_name.bright_white(),
                ctx.to_vp
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "?".to_string()),
            );

            if actual_to_name != to_name {
                println!(
                    "  {} Requested '{}', but the resume chain collapsed through \
                     to '{}' (intermediate domains had NOTREPORT for the pending \
                     interrupt)",
                    "ℹ".bright_blue().bold(),
                    to_name,
                    actual_to_name.bright_white(),
                );
            }
            if let Some(vector) = ctx.interrupt_return {
                println!(
                    "  {} Resumed with a pending interrupt to observe: vector {}",
                    "ℹ".bright_blue().bold(),
                    vector,
                );
            }

            Ok(())
        }

        _ => Err("Usage: switch <core>  |  switch <domain> <core> <vp_id>".to_string()),
    }
}

/// Deliver interrupt to domain
/// Supports two formats:
/// 1. Simple format: interrupt <vector> <core> (delivers to current domain on core)
/// 2. Explicit format: interrupt <vector> <domain> <core>
pub fn cmd_interrupt(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    let (vector, domain_id, domain_name, core) = if args.len() == 2 {
        // Simple format: interrupt <vector> <core>
        let vector = parse_number(args[0])? as u8;
        let core = parse_number(args[1])?;

        // Get current domain on this core from backend
        let core_states = state.backend.get_core_states();
        let cs = core_states
            .iter()
            .find(|c| c.core_id == core)
            .ok_or_else(|| format!("Core {} not found", core))?;

        let domain_id = cs
            .domain_id
            .ok_or_else(|| {
                format!(
                    "Core {} is idle, no domain to deliver interrupt to",
                    core
                )
            })?;

        let domain_name = state
            .get_domain_name(domain_id)
            .ok_or_else(|| format!("Current domain ID {} not found in name mapping", domain_id))?
            .to_string();

        (vector, domain_id, domain_name, core)
    } else if args.len() == 3 {
        // Explicit format: interrupt <vector> <domain> <core>
        let vector = parse_number(args[0])? as u8;
        let domain_name = args[1];
        let core = parse_number(args[2])?;

        let domain_id = *state
            .domain_names
            .get(domain_name)
            .ok_or_else(|| format!("Domain '{}' not found", domain_name))?;

        (vector, domain_id, domain_name.to_string(), core)
    } else {
        return Err(
            "Usage: interrupt <vector> <core> OR interrupt <vector> <domain> <core>".to_string(),
        );
    };

    state
        .backend
        .deliver_interrupt(vector, domain_id, core)
        .map_err(|e| format!("Failed to deliver interrupt: {}", e))?;

    // Record command
    state.session.add_command(Command::Interrupt {
        vector: vector as u64,
        domain: domain_name.clone(),
        core,
    });

    // Show interrupt delivery
    println!(
        "{} Interrupt {} on core {}: delivered to domain '{}' (ID: {})",
        "⚡".bright_yellow().bold(),
        vector,
        core,
        domain_name.bright_white(),
        domain_id
    );

    // Check if the core switched to a different domain (handler routing)
    let core_states = state.backend.get_core_states();
    if let Some(cs) = core_states.iter().find(|c| c.core_id == core) {
        if let Some(new_id) = cs.domain_id {
            if new_id != domain_id {
                let handler_name = state
                    .get_domain_name(new_id)
                    .unwrap_or("unknown");
                println!(
                    "{} Routed to handler domain '{}' (ID: {})",
                    "✓".bright_green().bold(),
                    handler_name.bright_white(),
                    new_id
                );
                println!(
                    "  {} Automatically switched core {} from '{}' to '{}'",
                    "→".bright_blue(),
                    core,
                    domain_name.bright_white(),
                    handler_name.bright_white()
                );
            } else {
                println!(
                    "{} Delivered to domain '{}' (ID: {})",
                    "✓".bright_green().bold(),
                    domain_name.bright_white(),
                    domain_id
                );
            }
        }
    }

    Ok(())
}
