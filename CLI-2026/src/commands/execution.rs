//! Execution commands: switch, interrupt

use capability_engine::*;
use colored::*;

use crate::parser::parse_number;
use crate::session::Command;
use crate::state::CliState;

/// Switch between domains on a core
/// Supports two formats:
/// 1. New format: switch <domain> <core> (auto-detects current domain)
/// 2. Legacy format: switch <core> <from> <to>
pub fn cmd_switch(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    let (core, from, to, from_name, to_name) = if args.len() == 2 {
        // New format: switch <domain> <core>
        let to_name = args[0];
        let core = parse_number(args[1])?;

        let to = state
            .domains
            .get(to_name)
            .ok_or_else(|| format!("Domain '{}' not found", to_name))?;

        // Get current domain on this core
        let core_ref = state
            .platform
            .get_core(core)
            .map_err(|e| format!("Core {} not found: {:?}", core, e))?;

        let current_state = core_ref.state.read();
        let from_id = match *current_state {
            CoreState::Running(id) => id,
            CoreState::Idle => {
                // First switch on this core, initialize it
                drop(current_state);
                let to_id = to.read().data.id;
                *core_ref.state.write() = CoreState::Running(to_id);

                println!(
                    "{} Initialized core {} with domain '{}' (ID: {})",
                    "✓".bright_green().bold(),
                    core,
                    to_name.bright_white(),
                    to_id
                );
                return Ok(());
            }
        };
        drop(current_state);

        let from_name = state
            .get_domain_name(from_id)
            .ok_or_else(|| format!("Current domain ID {} not found in name mapping", from_id))?
            .to_string();

        let from = state
            .domains
            .get(&from_name)
            .ok_or_else(|| format!("Domain '{}' not found", from_name))?;

        (core, from.clone(), to.clone(), from_name, to_name.to_string())
    } else if args.len() == 3 {
        // Old format: switch <core> <from> <to>
        let core = parse_number(args[0])?;
        let from_name = args[1];
        let to_name = args[2];

        let from = state
            .domains
            .get(from_name)
            .ok_or_else(|| format!("Domain '{}' not found", from_name))?;

        let to = state
            .domains
            .get(to_name)
            .ok_or_else(|| format!("Domain '{}' not found", to_name))?;

        // Initialize core if needed
        {
            let core_ref = state
                .platform
                .get_core(core)
                .map_err(|e| format!("Core {} not found: {:?}", core, e))?;
            let current_state = core_ref.state.read();
            if matches!(*current_state, CoreState::Idle) {
                drop(current_state);
                *core_ref.state.write() = CoreState::Running(from.read().data.id);
            }
        }

        (core, from.clone(), to.clone(), from_name.to_string(), to_name.to_string())
    } else {
        return Err("Usage: switch <domain> <core> OR switch <core> <from> <to>".to_string());
    };

    let _ctx = state
        .platform
        .switch(core, &from, Some(&to))
        .map_err(|e| format!("Failed to switch: {:?}", e))?;

    // Record command
    state.session.add_command(Command::Switch {
        core,
        from: from_name.clone(),
        to: to_name.clone(),
    });

    println!(
        "{} Switched on core {} from domain '{}' to domain '{}'",
        "✓".bright_green().bold(),
        core,
        from_name.bright_white(),
        to_name.bright_white()
    );

    Ok(())
}

/// Deliver interrupt to domain
/// Supports two formats:
/// 1. Simple format: interrupt <vector> <core> (delivers to current domain on core)
/// 2. Explicit format: interrupt <vector> <domain> <core>
pub fn cmd_interrupt(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    let (vector, domain, domain_name, core) = if args.len() == 2 {
        // Simple format: interrupt <vector> <core>
        let vector = parse_number(args[0])? as u8;
        let core = parse_number(args[1])?;

        // Get current domain on this core
        let core_ref = state
            .platform
            .get_core(core)
            .map_err(|e| format!("Core {} not found: {:?}", core, e))?;

        let current_state = core_ref.state.read();
        let domain_id = match *current_state {
            CoreState::Running(id) => id,
            CoreState::Idle => {
                return Err(format!("Core {} is idle, no domain to deliver interrupt to", core));
            }
        };
        drop(current_state);

        let domain_name = state
            .get_domain_name(domain_id)
            .ok_or_else(|| format!("Current domain ID {} not found in name mapping", domain_id))?
            .to_string();

        let domain = state
            .domains
            .get(&domain_name)
            .ok_or_else(|| format!("Domain '{}' not found", domain_name))?;

        (vector, domain.clone(), domain_name, core)
    } else if args.len() == 3 {
        // Explicit format: interrupt <vector> <domain> <core>
        let vector = parse_number(args[0])? as u8;
        let domain_name = args[1];
        let core = parse_number(args[2])?;

        let domain = state
            .domains
            .get(domain_name)
            .ok_or_else(|| format!("Domain '{}' not found", domain_name))?;

        (vector, domain.clone(), domain_name.to_string(), core)
    } else {
        return Err("Usage: interrupt <vector> <core> OR interrupt <vector> <domain> <core>".to_string());
    };

    let interrupted_id = domain.read().data.id;

    let (handler_id, reported_to) = state
        .platform
        .route_interrupt(vector, &domain, core)
        .map_err(|e| format!("Failed to route interrupt: {:?}", e))?;

    // Record command
    state.session.add_command(Command::Interrupt {
        vector: vector as u64,
        domain: domain_name.clone(),
        core,
    });

    // Show interrupt routing information
    println!(
        "{} Interrupt {} on core {}: interrupted domain '{}' (ID: {})",
        "⚡".bright_yellow().bold(),
        vector,
        core,
        domain_name.bright_white(),
        interrupted_id
    );

    // Show reported domains if any
    if !reported_to.is_empty() {
        println!("  {} Reported to {} domain(s): {:?}",
            "→".bright_blue(),
            reported_to.len(),
            reported_to
        );
    }

    // Find handler domain name
    let handler_name = state
        .get_domain_name(handler_id)
        .ok_or_else(|| format!("Handler domain ID {} not found in name mapping", handler_id))?;

    // If handler is different from interrupted domain, perform automatic context switch
    if handler_id != interrupted_id {
        // Update core state to run handler domain
        let core_ref = state
            .platform
            .get_core(core)
            .map_err(|e| format!("Core {} not found: {:?}", core, e))?;

        *core_ref.state.write() = CoreState::Running(handler_id);

        println!(
            "{} Routed to handler domain '{}' (ID: {})",
            "✓".bright_green().bold(),
            handler_name.bright_white(),
            handler_id
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
            handler_name.bright_white(),
            handler_id
        );
    }

    Ok(())
}
