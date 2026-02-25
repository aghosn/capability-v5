//! Session management commands: save-session, clear-session

use colored::*;

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
