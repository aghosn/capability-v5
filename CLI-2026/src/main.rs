//! Capability Engine CLI Simulator
//!
//! An interactive command-line interface for exploring and demonstrating
//! the capability-based security model.

use colored::*;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use rustyline::Config;

mod commands;
mod completer;
mod parser;
mod session;
mod state;
mod update_processor;

use completer::CliHelper;
use state::CliState;

fn main() {
    println!("{}", "=== Capability Engine CLI Simulator ===".bright_cyan().bold());
    println!("Type 'help' for available commands, 'exit' to quit");
    println!("{}", "Press TAB for command completion and hints\n".bright_black());

    let mut state = CliState::new(4); // 4 cores

    // Configure rustyline with our custom helper
    let config = Config::builder()
        .auto_add_history(false)
        .build();

    let helper = CliHelper::new();
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

                if let Err(e) = handle_command(&mut state, line) {
                    println!("{} {}", "Error:".bright_red().bold(), e);
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
fn handle_command(state: &mut CliState, line: &str) -> Result<(), String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return Ok(());
    }

    let cmd = parts[0];
    let args = &parts[1..];

    commands::dispatch(state, cmd, args)
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
    println!("  {} <mem> <domain> [attrs]", "send".bright_white().bold());
    println!("    Send memory capability to domain (handle auto-allocated)");
    println!("    Example: send mem1 child1 CLEAN");
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
    println!();

    println!("{}", "Execution:".bright_yellow());
    println!("  {} <domain> <core>", "switch".bright_white().bold());
    println!("    Switch to a domain on a core (auto-detects current domain)");
    println!("    Example: switch child1 0");
    println!("  {} <core> <from> <to>", "switch".bright_white().bold());
    println!("    Switch between domains on a core (legacy format)");
    println!("    Example: switch 0 root child1");
    println!("  {} <vector> <core>", "interrupt".bright_white().bold());
    println!("    Deliver interrupt to current domain on core");
    println!("    Example: interrupt 55 2");
    println!("  {} <vector> <domain> <core>", "interrupt".bright_white().bold());
    println!("    Deliver interrupt to specific domain (legacy format)");
    println!("    Example: interrupt 6 child1 0");
    println!();

    println!("{}", "Session Management:".bright_yellow());
    println!("  {} <filename>", "save-session".bright_white().bold());
    println!("    Save current session as a unit test");
    println!("    Example: save-session my_test.rs");
    println!("  {}", "clear-session".bright_white().bold());
    println!("    Clear session history");
    println!();

    println!("{}", "Other:".bright_yellow());
    println!("  {}", "help".bright_white().bold());
    println!("    Show this help message");
    println!("  {}", "exit".bright_white().bold());
    println!("    Exit the CLI");
    println!();
}
