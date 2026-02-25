//! Tab completion and hints for CLI commands

use rustyline::completion::{Completer, Pair};
use rustyline::hint::Hinter;
use rustyline::highlight::Highlighter;
use rustyline::validate::Validator;
use rustyline::{Context, Helper};
use std::borrow::Cow;

/// Command information for completion and hints
struct CommandInfo {
    name: &'static str,
    usage: &'static str,
    description: &'static str,
}

const COMMANDS: &[CommandInfo] = &[
    CommandInfo {
        name: "init",
        usage: "init <name> <size>",
        description: "Initialize root domain and memory region",
    },
    CommandInfo {
        name: "create-domain",
        usage: "create-domain <parent> <name> <cores> <api>",
        description: "Create a child domain",
    },
    CommandInfo {
        name: "seal",
        usage: "seal <domain>",
        description: "Seal a domain (make it ready for execution)",
    },
    CommandInfo {
        name: "carve",
        usage: "carve <parent> <name> <start> <size> <rights>",
        description: "Carve exclusive memory from parent",
    },
    CommandInfo {
        name: "alias",
        usage: "alias <parent> <name> <start> <size> <rights>",
        description: "Create aliased (shared) memory from parent",
    },
    CommandInfo {
        name: "send",
        usage: "send <mem> <domain> [attrs]",
        description: "Send memory capability to domain",
    },
    CommandInfo {
        name: "revoke",
        usage: "revoke <parent> <child>",
        description: "Revoke a child capability",
    },
    CommandInfo {
        name: "attest",
        usage: "attest <domain>",
        description: "Generate attestation report for domain",
    },
    CommandInfo {
        name: "view",
        usage: "view <domain>",
        description: "Show address space view for domain",
    },
    CommandInfo {
        name: "list",
        usage: "list",
        description: "List all domains and memory regions",
    },
    CommandInfo {
        name: "set-interrupt-policy",
        usage: "set-interrupt-policy <domain> <vector> <visibility>",
        description: "Set interrupt policy for a vector",
    },
    CommandInfo {
        name: "set-default-interrupt-policy",
        usage: "set-default-interrupt-policy <domain> <visibility>",
        description: "Set default interrupt policy",
    },
    CommandInfo {
        name: "switch",
        usage: "switch <domain> <core>",
        description: "Switch to domain on core",
    },
    CommandInfo {
        name: "interrupt",
        usage: "interrupt <vector> <core>",
        description: "Deliver interrupt to core",
    },
    CommandInfo {
        name: "save-session",
        usage: "save-session <filename>",
        description: "Save current session",
    },
    CommandInfo {
        name: "clear-session",
        usage: "clear-session",
        description: "Clear session history",
    },
    CommandInfo {
        name: "help",
        usage: "help",
        description: "Show help message",
    },
    CommandInfo {
        name: "exit",
        usage: "exit",
        description: "Exit the CLI",
    },
];

pub struct CliHelper;

impl CliHelper {
    pub fn new() -> Self {
        CliHelper
    }
}

impl Completer for CliHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let mut candidates = Vec::new();

        // Only complete at the beginning of the line (command names)
        if line[..pos].trim().split_whitespace().count() <= 1 {
            let prefix = line[..pos].trim();
            for cmd in COMMANDS {
                if cmd.name.starts_with(prefix) {
                    candidates.push(Pair {
                        display: format!("{} - {}", cmd.name, cmd.description),
                        replacement: cmd.name.to_string(),
                    });
                }
            }
        }

        Ok((0, candidates))
    }
}

impl Hinter for CliHelper {
    type Hint = String;

    fn hint(&self, line: &str, _pos: usize, _ctx: &Context<'_>) -> Option<String> {
        let trimmed = line.trim();

        // If line is empty or just whitespace, don't show hint
        if trimmed.is_empty() {
            return None;
        }

        // Extract the command (first word)
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.is_empty() {
            return None;
        }

        let cmd = parts[0];

        // Find matching command
        for command_info in COMMANDS {
            if command_info.name == cmd {
                // Show the full usage, graying out what's already typed
                let hint = command_info.usage.to_string();
                if hint.starts_with(trimmed) {
                    // Show the remaining part of the usage
                    return Some(hint[trimmed.len()..].to_string());
                } else if parts.len() == 1 {
                    // Just the command name is typed, show usage without the command name
                    return Some(format!(" {}", &hint[cmd.len()..].trim()));
                }
                break;
            }
        }

        None
    }
}

impl Highlighter for CliHelper {
    fn highlight<'l>(&self, line: &'l str, _pos: usize) -> Cow<'l, str> {
        Cow::Borrowed(line)
    }

    fn highlight_char(&self, _line: &str, _pos: usize, _forced: bool) -> bool {
        false
    }
}

impl Validator for CliHelper {}

impl Helper for CliHelper {}
