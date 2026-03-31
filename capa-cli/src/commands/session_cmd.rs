//! Session management commands: save-session, export-as-unit-test, clear-session, reset, load

use colored::*;
use std::fs;
use std::io::{self, BufRead};

use crate::commands;
use crate::state::CliState;

/// Save current session as plain CLI commands for later replay via `load`
pub fn cmd_save_session(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.is_empty() {
        return Err("Usage: save-session <filename>".to_string());
    }

    let filename = args[0];
    state
        .session
        .save_as_commands(filename)
        .map_err(|e| format!("Failed to save session: {}", e))?;

    println!(
        "{} Session saved to '{}' (replay with: load {})",
        "✓".bright_green().bold(),
        filename.bright_white(),
        filename
    );

    Ok(())
}

/// Export current session as a Rust unit test
pub fn cmd_export_as_unit_test(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.is_empty() {
        return Err("Usage: export-as-unit-test <filename>".to_string());
    }

    let filename = args[0];
    state
        .session
        .save_as_test(filename)
        .map_err(|e| format!("Failed to export unit test: {}", e))?;

    println!(
        "{} Session exported as unit test to '{}'",
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
    let num_cores = state.num_cores;
    state.reset();

    println!(
        "{} CLI reset to initial state ({} cores)",
        "✓".bright_green().bold(),
        num_cores
    );

    Ok(())
}

/// Toggle auto-list mode on or off
pub fn cmd_toggle_auto_list(state: &mut CliState, _args: &[&str]) -> std::result::Result<(), String> {
    state.auto_list = !state.auto_list;
    let status = if state.auto_list { "ON" } else { "OFF" };
    println!(
        "{} Auto-list mode: {}",
        "✓".bright_green().bold(),
        status.bright_white().bold()
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
    let mut expect_next_fail = false;

    for (line_num, line) in lines.iter().enumerate() {
        let line = line.trim();

        // Skip empty lines, @msg narrative lines, and plain comments.
        // A `# EXPECT_FAIL` marker means the very next command is expected to
        // return an error; if it succeeds instead, that is treated as a failure.
        if line.is_empty() || line.starts_with("@msg") {
            continue;
        }
        if line.starts_with('#') {
            expect_next_fail = line == "# EXPECT_FAIL";
            continue;
        }

        // Parse and execute the command
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let cmd = parts[0];
        let cmd_args = &parts[1..];

        let should_fail = expect_next_fail;
        expect_next_fail = false;

        // Execute the command
        match commands::dispatch(state, cmd, cmd_args) {
            Ok(_) if should_fail => {
                failed += 1;
                println!(
                    "{} Line {}: {} - expected failure but command succeeded",
                    "✗".bright_red().bold(),
                    line_num + 1,
                    line.bright_white(),
                );
            }
            Ok(_) => {
                executed += 1;
            }
            Err(_) if should_fail => {
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
