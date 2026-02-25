//! Session management commands: save-session, clear-session, reset, load

use colored::*;
use std::fs;
use std::io::{self, BufRead};

use crate::commands;
use crate::state::CliState;

/// Save current session as a unit test
pub fn cmd_save_session(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.is_empty() {
        return Err("Usage: save-session <filename>".to_string());
    }

    let filename = args[0];
    state
        .session
        .save_as_test(filename)
        .map_err(|e| format!("Failed to save session: {}", e))?;

    println!(
        "{} Session saved to '{}'",
        "✓".bright_green().bold(),
        filename.bright_white()
    );

    Ok(())
}

/// Clear session history
pub fn cmd_clear_session(state: &mut CliState) -> std::result::Result<(), String> {
    state.session.clear();
    println!("{} Session cleared", "✓".bright_green().bold());
    Ok(())
}

/// Reset CLI to initial state
pub fn cmd_reset(state: &mut CliState) -> std::result::Result<(), String> {
    // Get the current number of cores before resetting
    let num_cores = state.num_cores;

    // Replace state with a fresh one
    *state = CliState::new(num_cores);

    println!(
        "{} CLI reset to initial state ({} cores)",
        "✓".bright_green().bold(),
        num_cores
    );

    Ok(())
}

/// Load and execute commands from a file
pub fn cmd_load(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.is_empty() {
        return Err("Usage: load <filename>".to_string());
    }

    let filename = args[0];

    // Read the file
    let file = fs::File::open(filename)
        .map_err(|e| format!("Failed to open file '{}': {}", filename, e))?;

    let reader = io::BufReader::new(file);
    let lines: Vec<String> = reader
        .lines()
        .collect::<Result<_, _>>()
        .map_err(|e| format!("Failed to read file: {}", e))?;

    println!(
        "{} Loading commands from '{}'...",
        "📂".bright_cyan().bold(),
        filename.bright_white()
    );

    let mut executed = 0;
    let mut failed = 0;

    for (line_num, line) in lines.iter().enumerate() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Parse and execute the command
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let cmd = parts[0];
        let cmd_args = &parts[1..];

        // Execute the command
        match commands::dispatch(state, cmd, cmd_args) {
            Ok(_) => {
                executed += 1;
            }
            Err(e) => {
                failed += 1;
                println!(
                    "{} Line {}: {} - {}",
                    "✗".bright_red().bold(),
                    line_num + 1,
                    line.bright_white(),
                    e.bright_red()
                );
            }
        }
    }

    println!(
        "\n{} Loaded {} commands from '{}' ({} succeeded, {} failed)",
        "✓".bright_green().bold(),
        executed + failed,
        filename.bright_white(),
        executed,
        failed
    );

    Ok(())
}
