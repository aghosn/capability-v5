//! Execution commands: switch, interrupt

use capability_engine::*;
use colored::*;

use crate::parser::parse_number;
use crate::session::Command;
use crate::state::{CliState, find_domain_handle};

/// Switch between domains on a core using the VP-aware domain-mediated API.
///
/// Supported formats:
/// 1. `switch <core>`                  — return to the VP that called into the current domain
/// 2. `switch <domain> <core> <vp_id>` — call into `<domain>` VP `<vp_id>` from the current VP
///
/// Both operations go through `Capability::switch_domain` (handle=0 signals return),
/// which enforces all VP invariants (sealed caller, SWITCH permission, VP availability, etc.)
/// and updates platform core tracking transparently.
pub fn cmd_switch(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    match args.len() {
        // ── VP return: switch <core> ─────────────────────────────────────────
        1 => {
            let core = parse_number(args[0])?;

            let core_ref = state
                .platform
                .get_core(core)
                .map_err(|e| format!("Core {} not found: {:?}", core, e))?;

            let current_state = core_ref.state.read();
            let domain_id = match *current_state {
                CoreState::Running(id) => id,
                CoreState::Idle => return Err(format!("Core {} is idle, no domain to return from", core)),
            };
            drop(current_state);

            let domain_name = state
                .get_domain_name(domain_id)
                .ok_or_else(|| format!("Domain ID {} not found in name mapping", domain_id))?
                .to_string();

            let domain_ref = state
                .domains
                .get(&domain_name)
                .ok_or_else(|| format!("Domain '{}' not found", domain_name))?
                .clone();

            // Tell the platform which core is executing this call.
            state.platform.set_current_core(Some(core));

            let ctx = execute(
                state.platform.as_ref(),
                false,
                || {
                    // handle=0 signals "return to caller VP" in switch_domain.
                    let ctx = Capability::<Domain>::switch_domain(
                        &domain_ref,
                        0,
                        0,
                        state.platform.as_ref(),
                    )?;
                    Ok((ctx, UpdateBatch::new()))
                },
            )
            .map(|(ctx, _)| ctx)
            .map_err(|e| format!("Failed to return: {:?}", e))?;

            state.platform.set_current_core(None);

            let to_name = state
                .get_domain_name(ctx.to_domain)
                .unwrap_or("unknown")
                .to_string();

            state.session.add_command(Command::Switch {
                core,
                from: domain_name.clone(),
                to: to_name.clone(),
            });

            println!(
                "{} Returned on core {} from domain '{}' (VP {}) to domain '{}' (VP {})",
                "✓".bright_green().bold(),
                core,
                domain_name.bright_white(),
                ctx.from_vp_id.map(|v| v.to_string()).unwrap_or_else(|| "?".to_string()),
                to_name.bright_white(),
                ctx.to_vp_id.map(|v| v.to_string()).unwrap_or_else(|| "?".to_string()),
            );

            Ok(())
        }

        // ── VP-aware forward switch: switch <domain> <core> <vp_id> ─────────
        3 => {
            let to_name = args[0];
            let core = parse_number(args[1])?;
            let to_vp_id = parse_number(args[2])?;

            let core_ref = state
                .platform
                .get_core(core)
                .map_err(|e| format!("Core {} not found: {:?}", core, e))?;

            let current_state = core_ref.state.read();
            let domain_id = match *current_state {
                CoreState::Running(id) => id,
                CoreState::Idle => return Err(format!("Core {} is idle, cannot VP-switch", core)),
            };
            drop(current_state);

            let from_name = state
                .get_domain_name(domain_id)
                .ok_or_else(|| format!("Domain ID {} not found", domain_id))?
                .to_string();
            let from_ref = state
                .domains
                .get(&from_name)
                .ok_or_else(|| format!("Domain '{}' not found", from_name))?
                .clone();
            let to_ref = state
                .domains
                .get(to_name)
                .ok_or_else(|| format!("Domain '{}' not found", to_name))?
                .clone();

            // Find the LocalHandle that from_ref holds for to_ref.
            let to_handle = find_domain_handle(&from_ref, &to_ref)
                .ok_or_else(|| format!(
                    "Domain '{}' does not hold a handle to '{}'", from_name, to_name
                ))?;

            // Tell the platform which core is executing this call.
            state.platform.set_current_core(Some(core));

            let ctx = execute(
                state.platform.as_ref(),
                false,
                || {
                    let ctx = Capability::<Domain>::switch_domain(
                        &from_ref,
                        to_handle,
                        to_vp_id,
                        state.platform.as_ref(),
                    )?;
                    Ok((ctx, UpdateBatch::new()))
                },
            )
            .map(|(ctx, _)| ctx)
            .map_err(|e| format!("Failed to VP-switch: {:?}", e))?;

            state.platform.set_current_core(None);

            state.session.add_command(Command::Switch {
                core,
                from: from_name.clone(),
                to: to_name.to_string(),
            });

            println!(
                "{} Switched on core {} from '{}' (VP {}) to '{}' (VP {})",
                "✓".bright_green().bold(),
                core,
                from_name.bright_white(),
                ctx.from_vp_id.map(|v| v.to_string()).unwrap_or_else(|| "?".to_string()),
                to_name.bright_white(),
                ctx.to_vp_id.map(|v| v.to_string()).unwrap_or_else(|| "?".to_string()),
            );

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

    // VP-aware interrupt delivery (lazy-unwind model).
    //
    // When VPs are configured on the core, this walks the VP call chain from
    // the interrupted VP up to the DELIVER handler VP, setting:
    //   - interrupted VP: Running → Interrupted (frozen, not claimable)
    //   - intermediate VPs: Locked → Suspended (claimable, frees callee on resume)
    //   - handler VP: Locked → Running (woken to handle the interrupt)
    //
    // Falls back to a simple core-state update when VPs are not set up
    // (e.g. domains switched via the non-VP SwitchManager path).
    let vp_delivery = Capability::<Domain>::deliver_interrupt_vp(
        &domain, handler_id, core, state.platform.as_ref(),
    );

    if vp_delivery.is_err() && handler_id != interrupted_id {
        // Non-VP fallback: just redirect the core to the handler domain.
        state.platform.set_core_domain(core, handler_id);
    }

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

    // Show routing result
    if handler_id != interrupted_id {
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
