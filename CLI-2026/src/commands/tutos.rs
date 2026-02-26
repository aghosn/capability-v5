//! Tutorial command - interactive tutorials for learning the capability model

use colored::*;
use crossterm::event;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::time::Duration;

use crate::commands;
use crate::state::CliState;

// ── Timing constants ────────────────────────────────────────────────────────

/// Milliseconds between each character when typing a command.
const CHAR_MS: u64 = 35;
/// Milliseconds delay before printing each @msg line.
const MSG_LINE_MS: u64 = 60;
/// Milliseconds to pause after a command finishes executing.
const POST_CMD_MS: u64 = 600;

// ── Tutorial metadata ────────────────────────────────────────────────────────

#[derive(Debug)]
struct Tutorial {
    filename: String,
    title: String,
    description: String,
}

// ── Pacer ────────────────────────────────────────────────────────────────────

/// Controls tutorial pacing.
///
/// We intentionally stay in **cooked (normal) mode** the whole time so that
/// all `println!` output from command execution is formatted correctly
/// (`\n` → `\r\n` by the terminal).  In cooked mode, `crossterm::event::poll`
/// still works: it detects that stdin has data once the user presses Enter
/// (the line buffer is flushed).  That is enough to trigger fast-forward.
struct Pacer {
    fast: bool,
}

impl Pacer {
    fn new() -> Self {
        use std::io::IsTerminal;
        // Non-TTY (piped / test): skip all delays immediately.
        Pacer { fast: !io::stdin().is_terminal() }
    }

    /// Drain any pending input events; set fast-mode if anything is available.
    ///
    /// In cooked mode events arrive only after the user presses Enter, which
    /// is exactly the interaction we advertise: "press Enter to fast-forward".
    fn poll_input(&mut self) {
        if self.fast {
            return;
        }
        // Non-blocking poll: returns immediately if no input is ready.
        if event::poll(Duration::ZERO).unwrap_or(false) {
            // Drain all buffered events so they don't leak into rustyline.
            while event::poll(Duration::ZERO).unwrap_or(false) {
                let _ = event::read();
            }
            self.fast = true;
        }
    }

    /// Sleep for up to `ms` milliseconds, breaking early on input.
    fn sleep_ms(&mut self, ms: u64) {
        if self.fast {
            return;
        }
        let deadline = std::time::Instant::now() + Duration::from_millis(ms);
        while std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(8));
            self.poll_input();
            if self.fast {
                return;
            }
        }
    }

    /// Print an `@msg` line after a short leading delay.
    fn print_msg(&mut self, colored_line: &str) {
        self.sleep_ms(MSG_LINE_MS);
        println!("{}", colored_line);
    }

    /// Print a blank line with a half-delay.
    fn print_blank(&mut self) {
        self.sleep_ms(MSG_LINE_MS / 2);
        println!();
    }

    /// Typewrite a command line character by character.
    ///
    /// Prints `► ` instantly (already colored), then prints each character of
    /// the raw command text with a per-character delay.  If fast-mode kicks in
    /// mid-word the remainder is flushed instantly.
    fn typewrite_cmd(&mut self, raw_cmd: &str) {
        print!("{} ", "►".bright_cyan().bold());
        let _ = io::stdout().flush();

        if self.fast {
            println!("{}", raw_cmd);
            return;
        }

        let chars: Vec<char> = raw_cmd.chars().collect();
        for (i, &ch) in chars.iter().enumerate() {
            print!("{}", ch);
            let _ = io::stdout().flush();

            if i + 1 < chars.len() {
                self.sleep_ms(CHAR_MS);
                if self.fast {
                    let rest: String = chars[i + 1..].iter().collect();
                    print!("{}", rest);
                    let _ = io::stdout().flush();
                    break;
                }
            }
        }
        println!();
    }

    /// Pause after a command's output before the next tutorial section.
    fn post_cmd_pause(&mut self) {
        self.sleep_ms(POST_CMD_MS);
    }
}

// ── Tutorial index loader ─────────────────────────────────────────────────────

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
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
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

// ── Tutorial executor ─────────────────────────────────────────────────────────

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

    // Print fast-forward hint.
    println!(
        "{}",
        "  Press any key to fast-forward…".bright_black().italic()
    );
    println!();

    // Clear any buffered input events before starting the tutorial
    // to prevent immediate fast-forward from leftover Enter key presses
    while event::poll(Duration::ZERO).unwrap_or(false) {
        let _ = event::read();
    }

    let mut pacer = Pacer::new();

    for line in lines.iter() {
        let line = line.trim();

        if line.is_empty() {
            pacer.print_blank();
            continue;
        }

        if line.starts_with("@msg") {
            let msg = line.strip_prefix("@msg").unwrap_or("").trim();
            if msg.is_empty() {
                pacer.print_blank();
            } else {
                pacer.print_msg(&format!("{}", msg.bright_black()));
            }
            continue;
        }

        if line.starts_with('#') {
            continue;
        }

        // It's a command line.
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        pacer.typewrite_cmd(line);

        match commands::dispatch(state, parts[0], &parts[1..]) {
            Ok(_) => {}
            Err(e) => {
                println!("  {} {}", "✗".bright_red().bold(), e.bright_red());
            }
        }

        pacer.post_cmd_pause();
    }

    // Drop pacer here → disable_raw_mode called in Drop.
    Ok(())
}

// ── Public command ────────────────────────────────────────────────────────────

pub fn cmd_tutos(state: &mut CliState, args: &[&str]) -> Result<(), String> {
    let tutorials = load_tutorial_index()?;

    if args.is_empty() {
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
        println!("   Example: {}", "tutos 1".bright_white());
        println!();
        return Ok(());
    }

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

    println!();
    println!("{}", "═".repeat(60).bright_cyan());
    println!("{} {}", "📚".bright_cyan(), tutorial.title.bright_cyan().bold());
    println!("{}", tutorial.description.bright_black());
    println!("{}", "═".repeat(60).bright_cyan());

    execute_tutorial(state, &tutorial.filename)?;

    println!("{}", "═".repeat(60).bright_cyan());
    println!("{} Tutorial completed!", "✓".bright_green().bold());
    println!("   Use {} to reset and try another tutorial.", "reset".bright_white());
    println!("{}", "═".repeat(60).bright_cyan());
    println!();

    Ok(())
}

