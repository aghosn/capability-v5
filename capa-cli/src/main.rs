//! Capability Engine CLI Simulator
//!
//! An interactive command-line interface for exploring and demonstrating
//! the capability-based security model.

use colored::*;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use rustyline::Config;
use std::sync::Arc;
use parking_lot::RwLock;

mod commands;
mod completer;
mod parser;
mod platform;
mod session;
mod state;
mod update_processor;

use completer::CliHelper;
use state::CliState;

fn main() {
    println!("{}", "=== Capability Engine CLI Simulator ===".bright_cyan().bold());
    println!("Type 'help' for available commands, 'exit' to quit");
    println!("{}", "Press TAB for command completion and hints\n".bright_black());

    let state = Arc::new(RwLock::new(CliState::new(4))); // 4 cores

    // Configure rustyline with our custom helper
    let config = Config::builder()
        .auto_add_history(false)
        .build();

    let mut helper = CliHelper::new();
    helper.set_state(Arc::downgrade(&state));
    let mut rl = Editor::with_config(config).expect("Failed to create readline editor");
    rl.set_helper(Some(helper));

    // Load command history
    let _ = rl.load_history(".capability_cli_history");

    // Main REPL loop
    loop {
        let readline = rl.readline(&format!("{} ", "cap>".bright_green().bold()));
        match readline {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                let _ = rl.add_history_entry(line);

                if line == "exit" || line == "quit" {
                    println!("{}", "Goodbye!".bright_yellow());
                    break;
                }

                if line == "help" {
                    show_help();
                    continue;
                }

                match handle_command(&state, line) {
                    Ok(_) => {
                        // If auto-list is enabled and command is not list/help/exit,
                        // automatically run list
                        let should_auto_list = state.read().auto_list;
                        if should_auto_list && line != "list" && line != "help" && !line.starts_with("auto-list") {
                            let _ = commands::dispatch(&mut state.write(), "list", &[]);
                        }
                    }
                    Err(e) => {
                        println!("{} {}", "Error:".bright_red().bold(), e);
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("{}", "Use 'exit' to quit".bright_yellow());
                continue;
            }
            Err(ReadlineError::Eof) => {
                println!("{}", "Goodbye!".bright_yellow());
                break;
            }
            Err(err) => {
                println!("{} {:?}", "Error:".bright_red().bold(), err);
                break;
            }
        }
    }

    // Save command history
    let _ = rl.save_history(".capability_cli_history");
}

/// Handle a command by dispatching to the appropriate handler
fn handle_command(state: &Arc<RwLock<CliState>>, line: &str) -> Result<(), String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return Ok(());
    }

    let cmd = parts[0];
    let args = &parts[1..];

    commands::dispatch(&mut state.write(), cmd, args)
}

/// Display help information
fn show_help() {
    println!("\n{}", "Available Commands:".bright_cyan().bold());
    println!();

    println!("{}", "Initialization:".bright_yellow());
    println!("  {} <name> <size>", "init".bright_white().bold());
    println!("    Initialize root domain and memory region");
    println!("    Example: init root 0x1000000");
    println!();

    println!("{}", "Domain Management:".bright_yellow());
    println!("  {} <parent> <name> <cores> <api>", "create-domain".bright_white().bold());
    println!("    Create a child domain");
    println!("    Example: create-domain root child1 0b1111 GET,ATTEST,SWITCH");
    println!("  {} <domain>", "seal".bright_white().bold());
    println!("    Seal a domain (make it ready for execution)");
    println!("    Example: seal child1");
    println!("  {} <domain> <vector> <visibility>", "set-interrupt-policy".bright_white().bold());
    println!("    Set interrupt policy for a specific vector (DELIVER, REPORT, NOTREPORT)");
    println!("    Example: set-interrupt-policy child1 55 REPORT");
    println!("  {} <domain> <visibility>", "set-default-interrupt-policy".bright_white().bold());
    println!("    Set default interrupt policy for all vectors");
    println!("    Example: set-default-interrupt-policy child1 NOTREPORT");
    println!("  {} <domain>", "enumerate-pending".bright_white().bold());
    println!("    List pending capabilities waiting for acceptance");
    println!("    Example: enumerate-pending child1");
    println!("  {} <domain> <pending_id> [at <gpa>]", "accept-capability".bright_white().bold());
    println!("    Accept a pending capability, optionally placing it at a specific GPA");
    println!("    Example: accept-capability child1 0");
    println!("    Example: accept-capability child1 0 at 0xA0000");
    println!("  {} <domain> <pending_id>", "reject-capability".bright_white().bold());
    println!("    Reject (discard) a pending capability without activating it");
    println!("    Example: reject-capability child1 0");
    println!();

    println!("{}", "Channel Operations:".bright_yellow());
    println!("  {} <target> <chan_name>", "get-chan".bright_white().bold());
    println!("    Create a channel capability to target (caller inferred from ownership)");
    println!("    Example: get-chan dom2 chan1");
    println!("  {} <chan> <receiver>", "send".bright_white().bold());
    println!("    Transfer a channel capability (same as memory send — caller inferred)");
    println!("    Example: send chan1 dom2");
    println!("  {} <receiver> <pending_id> <chan_name>", "accept-channel".bright_white().bold());
    println!("    Accept a pending channel capability");
    println!("    Example: accept-channel dom2 0 chan1");
    println!("  {} <receiver> <pending_id>", "reject-channel".bright_white().bold());
    println!("    Reject a pending channel capability");
    println!("    Example: reject-channel dom2 0");
    println!();

    println!("{}", "Memory Operations:".bright_yellow());
    println!("  {} <parent> <name> <start> <size> <rights>", "carve".bright_white().bold());
    println!("    Carve exclusive memory from parent");
    println!("    Example: carve root_mem mem1 0x1000 0x1000 RWX");
    println!("  {} <parent> <name> <start> <size> <rights>", "alias".bright_white().bold());
    println!("    Create aliased (shared) memory from parent");
    println!("    Example: alias root_mem mem2 0x2000 0x1000 RW");
    println!();

    println!("{}", "Capability Transfer:".bright_yellow());
    println!("  {} <mem> <domain> [attrs] [at <gpa>]", "send".bright_white().bold());
    println!("    Send memory capability to domain, optionally at a specific GPA");
    println!("    Example: send mem1 child1 CLEAN");
    println!("    Example: send mem1 child1 at 0xA0000");
    println!("  {} <parent> <child>", "revoke".bright_white().bold());
    println!("    Revoke a child capability (memory or domain)");
    println!("    Example: revoke root_mem mem1");
    println!();

    println!("{}", "Information:".bright_yellow());
    println!("  {} <domain>", "attest".bright_white().bold());
    println!("    Generate attestation report for domain");
    println!("    Example: attest child1");
    println!("  {} <domain>", "view".bright_white().bold());
    println!("    Show address space view for domain");
    println!("    Example: view child1");
    println!("  {}", "list".bright_white().bold());
    println!("    List all domains, memory regions, and core status");
    println!("  {}", "mem-usage".bright_white().bold());
    println!("    Report logical memory consumption of all capability engine objects");
    println!();

    println!("{}", "Execution:".bright_yellow());
    println!("  {} <domain> <core> <vp_id>", "switch".bright_white().bold());
    println!("    Enter domain: claim VP <vp_id> in <domain> from the current VP on <core>");
    println!("    All capability checks (sealed, SWITCH permission, VP availability) are");
    println!("    enforced transparently by the library.");
    println!("    Example: switch child1 0 0");
    println!("  {} <core>", "switch".bright_white().bold());
    println!("    Return: unwind the VP call chain on <core> back to the calling VP");
    println!("    Example: switch 0");
    println!("  {} <vector> <core>", "interrupt".bright_white().bold());
    println!("    Deliver interrupt to current domain on core");
    println!("    Example: interrupt 55 2");
    println!("  {} <vector> <domain> <core>", "interrupt".bright_white().bold());
    println!("    Deliver interrupt to specific domain (legacy format)");
    println!("    Example: interrupt 6 child1 0");
    println!();

    println!("{}", "Session Management:".bright_yellow());
    println!("  {} <filename>", "save-session".bright_white().bold());
    println!("    Save current session as CLI commands for later replay");
    println!("    Example: save-session my_session.txt");
    println!("  {} <filename>", "export-as-unit-test".bright_white().bold());
    println!("    Export current session as a Rust unit test");
    println!("    Example: export-as-unit-test my_test.rs");
    println!("  {}", "clear-session".bright_white().bold());
    println!("    Clear session history");
    println!("  {}", "reset".bright_white().bold());
    println!("    Reset CLI to initial state (clear all domains and memory)");
    println!("  {} <filename>", "load".bright_white().bold());
    println!("    Load and execute commands from a saved session file");
    println!("    Example: load my_session.txt");
    println!("  {}", "auto-list".bright_white().bold());
    println!("    Toggle auto-list mode (automatically run 'list' after each command)");
    println!();

    println!("{}", "Learning:".bright_yellow());
    println!("  {} [number]", "tutos".bright_white().bold());
    println!("    Interactive tutorials for learning the capability model");
    println!("    Example: tutos (list all) or tutos 1 (run tutorial 1)");
    println!();

    println!("{}", "Other:".bright_yellow());
    println!("  {}", "help".bright_white().bold());
    println!("    Show this help message");
    println!("  {}", "exit".bright_white().bold());
    println!("    Exit the CLI");
    println!();
}
