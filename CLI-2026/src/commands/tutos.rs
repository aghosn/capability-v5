//! Tutorial command - interactive tutorials for learning the capability model

use colored::*;
use std::fs;
use std::io::{self, BufRead};
use std::path::Path;

use crate::commands;
use crate::state::CliState;

/// Tutorial metadata
#[derive(Debug)]
struct Tutorial {
    filename: String,
    title: String,
    description: String,
}

/// Load tutorial index
fn load_tutorial_index() -> Result<Vec<Tutorial>, String> {
    let index_path = "tutos/index.txt";

    if !Path::new(index_path).exists() {
        return Err(format!(
            "Tutorial index not found at '{}'. Please ensure the tutos folder exists.",
            index_path
        ));
    }

    let file = fs::File::open(index_path)
        .map_err(|e| format!("Failed to open tutorial index: {}", e))?;

    let reader = io::BufReader::new(file);
    let mut tutorials = Vec::new();

    for line in reader.lines() {
        let line = line.map_err(|e| format!("Failed to read line: {}", e))?;
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Parse format: filename|title|description
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() == 3 {
            tutorials.push(Tutorial {
                filename: parts[0].trim().to_string(),
                title: parts[1].trim().to_string(),
                description: parts[2].trim().to_string(),
            });
        }
    }

    Ok(tutorials)
}

/// Execute a tutorial file
fn execute_tutorial(state: &mut CliState, filename: &str) -> Result<(), String> {
    let tutorial_path = format!("tutos/{}", filename);

    let file = fs::File::open(&tutorial_path)
        .map_err(|e| format!("Failed to open tutorial '{}': {}", tutorial_path, e))?;

    let reader = io::BufReader::new(file);
    let lines: Vec<String> = reader
        .lines()
        .collect::<Result<_, _>>()
        .map_err(|e| format!("Failed to read tutorial: {}", e))?;

    println!();

    for line in lines.iter() {
        let line = line.trim();

        // Skip empty lines
        if line.is_empty() {
            println!();
            continue;
        }

        // Handle message lines (explanatory text)
        if line.starts_with("@msg") {
            let msg = line.strip_prefix("@msg").unwrap_or("").trim();
            if msg.is_empty() {
                println!();
            } else {
                println!("{}", msg.bright_black());
            }
            continue;
        }

        // Skip comment lines that aren't messages
        if line.starts_with('#') {
            continue;
        }

        // Parse and execute command
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let cmd = parts[0];
        let cmd_args = &parts[1..];

        // Show the command being executed
        println!("{} {}", "►".bright_cyan().bold(), line.bright_white());

        // Execute the command
        match commands::dispatch(state, cmd, cmd_args) {
            Ok(_) => {
                // Command succeeded - output already printed by command
            }
            Err(e) => {
                // Show error but continue with tutorial
                println!("  {} {}", "✗".bright_red().bold(), e.bright_red());
            }
        }

        println!();
    }

    Ok(())
}

/// List all available tutorials
pub fn cmd_tutos(state: &mut CliState, args: &[&str]) -> Result<(), String> {
    let tutorials = load_tutorial_index()?;

    if args.is_empty() {
        // No arguments - show tutorial menu
        println!("\n{}", "Available Tutorials:".bright_cyan().bold());
        println!();

        println!("{}", "Basic Tutorials:".bright_yellow().bold());
        for (i, tutorial) in tutorials.iter().enumerate().filter(|(i, _)| *i < 5) {
            println!(
                "  {} {} - {}",
                format!("[{}]", i + 1).bright_green(),
                tutorial.title.bright_white(),
                tutorial.description
            );
        }

        println!();
        println!("{}", "Advanced Tutorials:".bright_yellow().bold());
        for (i, tutorial) in tutorials.iter().enumerate().filter(|(i, _)| *i >= 5) {
            println!(
                "  {} {} - {}",
                format!("[{}]", i + 1).bright_green(),
                tutorial.title.bright_white(),
                tutorial.description
            );
        }

        println!();
        println!(
            "{} Use {} to run a tutorial",
            "ℹ".bright_blue(),
            "tutos <number>".bright_white()
        );
        println!(
            "   Example: {}",
            "tutos 1".bright_white()
        );
        println!();

        return Ok(());
    }

    // Parse tutorial number
    let tutorial_num: usize = args[0]
        .parse()
        .map_err(|_| format!("Invalid tutorial number: {}", args[0]))?;

    if tutorial_num == 0 || tutorial_num > tutorials.len() {
        return Err(format!(
            "Tutorial {} not found. Use 'tutos' to see available tutorials.",
            tutorial_num
        ));
    }

    let tutorial = &tutorials[tutorial_num - 1];

    // Print tutorial header
    println!();
    println!("{}", "═".repeat(60).bright_cyan());
    println!(
        "{} {}",
        "📚".bright_cyan(),
        tutorial.title.bright_cyan().bold()
    );
    println!("{}", tutorial.description.bright_black());
    println!("{}", "═".repeat(60).bright_cyan());

    // Execute the tutorial
    execute_tutorial(state, &tutorial.filename)?;

    // Print footer
    println!("{}", "═".repeat(60).bright_cyan());
    println!(
        "{} Tutorial completed!",
        "✓".bright_green().bold()
    );
    println!(
        "   Use {} to reset and try another tutorial.",
        "reset".bright_white()
    );
    println!("{}", "═".repeat(60).bright_cyan());
    println!();

    Ok(())
}
