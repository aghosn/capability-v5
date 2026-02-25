//! Information commands: attest, view, list

use capability_engine::*;
use colored::*;

use crate::session::Command;
use crate::state::CliState;

/// Generate attestation report for domain
pub fn cmd_attest(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.len() != 1 {
        return Err("Usage: attest <domain>".to_string());
    }

    let domain_name = args[0];
    let domain = state
        .domains
        .get(domain_name)
        .ok_or_else(|| format!("Domain '{}' not found", domain_name))?;

    let attestation = attest_domain(domain);

    // Record command
    state.session.add_command(Command::Attest {
        domain: domain_name.to_string(),
    });

    println!("\n{}", "Attestation Report:".bright_cyan().bold());
    println!("{}", attestation.report);

    Ok(())
}

/// Show address space view for domain
pub fn cmd_view(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.len() != 1 {
        return Err("Usage: view <domain>".to_string());
    }

    let domain_name = args[0];
    let domain = state
        .domains
        .get(domain_name)
        .ok_or_else(|| format!("Domain '{}' not found", domain_name))?;

    let view = compute_address_space(domain);

    // Record command
    state.session.add_command(Command::View {
        domain: domain_name.to_string(),
    });

    println!("\n{}", "Address Space View:".bright_cyan().bold());
    println!("{}", view);

    Ok(())
}

/// List all domains and memory regions with active core status
pub fn cmd_list(state: &mut CliState) -> std::result::Result<(), String> {
    // Show active domains per core
    println!("\n{}", "Active Domains per Core:".bright_cyan().bold());
    let num_cores = 4; // Match the number in CliState::new
    for core_id in 0..num_cores {
        if let Ok(core_ref) = state.switch_manager.get_core(core_id as u64) {
            let core_state = core_ref.state.read();
            match *core_state {
                CoreState::Running(domain_id) => {
                    let domain_name = state
                        .get_domain_name(domain_id)
                        .unwrap_or("unknown");
                    println!(
                        "  {} Core {}: {} (ID: {})",
                        "✓".bright_green(),
                        core_id,
                        domain_name.bright_white(),
                        domain_id
                    );
                }
                CoreState::Idle => {
                    println!("  {} Core {}: {}", "○".bright_black(), core_id, "idle".bright_black());
                }
            }
        }
    }

    println!("\n{}", "Domains:".bright_cyan().bold());
    if state.domains.is_empty() {
        println!("  (none)");
    } else {
        for (name, domain) in &state.domains {
            let d = domain.read();
            println!(
                "  {} {} (ID: {}, status: {:?})",
                "•".bright_yellow(),
                name.bright_white(),
                d.data.id,
                d.data.status
            );
        }
    }

    println!("\n{}", "Memory Regions:".bright_cyan().bold());
    if state.memories.is_empty() {
        println!("  (none)");
    } else {
        for (name, mem) in &state.memories {
            let m = mem.read();
            println!(
                "  {} {} {} (kind: {:?}, owner: {}, handle: {}, attrs: {}, children: {})",
                "•".bright_yellow(),
                name.bright_white(),
                m.data.access,
                m.data.kind,
                m.owned.owner,
                m.owned.handle,
                m.owned.attributes,
                m.children.len()
            );
        }
    }

    println!();
    Ok(())
}
