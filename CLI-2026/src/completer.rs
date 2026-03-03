//! Tab completion and hints for CLI commands

use rustyline::completion::{Completer, FilenameCompleter, Pair};
use rustyline::hint::Hinter;
use rustyline::highlight::Highlighter;
use rustyline::validate::Validator;
use rustyline::{Context, Helper};
use std::borrow::Cow;
use std::sync::Weak;
use parking_lot::RwLock;
use crate::state::CliState;

/// Commands whose first argument is a filename (eligible for path completion)
const FILENAME_COMMANDS: &[&str] = &["load", "save-session", "export-as-unit-test"];

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
        name: "mem-usage",
        usage: "mem-usage",
        description: "Report logical memory consumption of capability engine objects",
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
        name: "enumerate-pending",
        usage: "enumerate-pending <domain>",
        description: "List pending capabilities for domain",
    },
    CommandInfo {
        name: "accept-capability",
        usage: "accept-capability <domain> <pending_id> [handle]",
        description: "Accept a pending capability",
    },
    CommandInfo {
        name: "reject-capability",
        usage: "reject-capability <domain> <pending_id>",
        description: "Reject (discard) a pending capability",
    },
    CommandInfo {
        name: "get-chan",
        usage: "get-chan <target> <chan_name>",
        description: "Create a channel capability to target (caller inferred from ownership)",
    },
    CommandInfo {
        name: "accept-channel",
        usage: "accept-channel <receiver> <pending_id> <chan_name>",
        description: "Accept a pending channel capability",
    },
    CommandInfo {
        name: "reject-channel",
        usage: "reject-channel <receiver> <pending_id>",
        description: "Reject a pending channel capability",
    },
    CommandInfo {
        name: "reset",
        usage: "reset",
        description: "Reset CLI to initial state",
    },
    CommandInfo {
        name: "load",
        usage: "load <filename>",
        description: "Load and execute commands from file",
    },
    CommandInfo {
        name: "switch",
        usage: "switch <core>  |  switch <domain> <core> <vp_id>",
        description: "Return to caller VP on core, or forward-switch to domain VP",
    },
    CommandInfo {
        name: "interrupt",
        usage: "interrupt <vector> <core>",
        description: "Deliver interrupt to core",
    },
    CommandInfo {
        name: "save-session",
        usage: "save-session <filename>",
        description: "Save current session as CLI commands for later replay via load",
    },
    CommandInfo {
        name: "export-as-unit-test",
        usage: "export-as-unit-test <filename>",
        description: "Export current session as a Rust unit test",
    },
    CommandInfo {
        name: "clear-session",
        usage: "clear-session",
        description: "Clear session history",
    },
    CommandInfo {
        name: "auto-list",
        usage: "auto-list",
        description: "Toggle auto-list mode on/off",
    },
    CommandInfo {
        name: "tutos",
        usage: "tutos [number]",
        description: "Interactive tutorials",
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

pub struct CliHelper {
    filename_completer: FilenameCompleter,
    state: Weak<RwLock<CliState>>,
}

impl CliHelper {
    pub fn new() -> Self {
        CliHelper {
            filename_completer: FilenameCompleter::new(),
            state: Weak::new(),
        }
    }

    pub fn set_state(&mut self, state: Weak<RwLock<CliState>>) {
        self.state = state;
    }

    /// Get capability names for completion based on command and argument position
    fn get_capability_completions(&self, cmd: &str, arg_index: usize, prefix: &str) -> Vec<Pair> {
        let state = match self.state.upgrade() {
            Some(s) => s,
            None => return Vec::new(),
        };

        let state = state.read();
        let mut candidates = Vec::new();

        // Determine what type of capability to suggest based on command and argument position
        match (cmd, arg_index) {
            // Commands where first arg is a domain name
            ("seal", 1) | ("attest", 1) | ("view", 1) | ("enumerate-pending", 1)
            | ("set-interrupt-policy", 1) | ("set-default-interrupt-policy", 1)
            | ("accept-capability", 1) | ("reject-capability", 1)
            | ("get-chan", 1)
            | ("accept-channel", 1) | ("reject-channel", 1) => {
                for name in state.domains.keys() {
                    if name.starts_with(prefix) {
                        candidates.push(Pair {
                            display: format!("{} (domain)", name),
                            replacement: name.clone(),
                        });
                    }
                }
            }
            // create-domain: first arg is parent domain
            ("create-domain", 1) => {
                for name in state.domains.keys() {
                    if name.starts_with(prefix) {
                        candidates.push(Pair {
                            display: format!("{} (parent domain)", name),
                            replacement: name.clone(),
                        });
                    }
                }
            }
            // carve/alias: first arg is parent memory
            ("carve", 1) | ("alias", 1) => {
                for name in state.memories.keys() {
                    if name.starts_with(prefix) {
                        candidates.push(Pair {
                            display: format!("{} (parent memory)", name),
                            replacement: name.clone(),
                        });
                    }
                }
            }
            // send: first arg is memory, second arg is domain
            ("send", 1) => {
                for name in state.memories.keys() {
                    if name.starts_with(prefix) {
                        candidates.push(Pair {
                            display: format!("{} (memory)", name),
                            replacement: name.clone(),
                        });
                    }
                }
            }
            ("send", 2) => {
                for name in state.domains.keys() {
                    if name.starts_with(prefix) {
                        candidates.push(Pair {
                            display: format!("{} (domain)", name),
                            replacement: name.clone(),
                        });
                    }
                }
            }
            // revoke: first arg is parent (domain or memory), second arg is child
            ("revoke", 1) => {
                for name in state.domains.keys() {
                    if name.starts_with(prefix) {
                        candidates.push(Pair {
                            display: format!("{} (domain)", name),
                            replacement: name.clone(),
                        });
                    }
                }
                for name in state.memories.keys() {
                    if name.starts_with(prefix) {
                        candidates.push(Pair {
                            display: format!("{} (memory)", name),
                            replacement: name.clone(),
                        });
                    }
                }
            }
            ("revoke", 2) => {
                for name in state.domains.keys() {
                    if name.starts_with(prefix) {
                        candidates.push(Pair {
                            display: format!("{} (domain)", name),
                            replacement: name.clone(),
                        });
                    }
                }
                for name in state.memories.keys() {
                    if name.starts_with(prefix) {
                        candidates.push(Pair {
                            display: format!("{} (memory)", name),
                            replacement: name.clone(),
                        });
                    }
                }
            }
            // switch: first arg is domain
            ("switch", 1) => {
                for name in state.domains.keys() {
                    if name.starts_with(prefix) {
                        candidates.push(Pair {
                            display: format!("{} (domain)", name),
                            replacement: name.clone(),
                        });
                    }
                }
            }
            _ => {}
        }

        candidates.sort_by(|a, b| a.replacement.cmp(&b.replacement));
        candidates
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
        let before_cursor = &line[..pos];
        let parts: Vec<&str> = before_cursor.split_whitespace().collect();
        let trailing_space = before_cursor.ends_with(' ');
        let word_count = parts.len();

        // Determine what we're completing
        let cmd = parts.first().copied().unwrap_or("");
        let arg_index = if trailing_space { word_count } else { word_count - 1 };

        // If we're typing the first argument of a filename command, do path completion.
        if word_count >= 1 && FILENAME_COMMANDS.contains(&cmd) && arg_index == 1 {
            return self.filename_completer.complete_path(line, pos);
        }

        // Complete command names when on the first word
        if word_count == 0 || (word_count == 1 && !trailing_space) {
            let prefix = before_cursor.trim();
            let mut candidates = Vec::new();
            for cmd_info in COMMANDS {
                if cmd_info.name.starts_with(prefix) {
                    candidates.push(Pair {
                        display: format!("{} - {}", cmd_info.name, cmd_info.description),
                        replacement: cmd_info.name.to_string(),
                    });
                }
            }
            return Ok((0, candidates));
        }

        // Complete capability names for command arguments
        if word_count >= 1 {
            let current_word = if trailing_space {
                ""
            } else {
                parts.last().copied().unwrap_or("")
            };

            let candidates = self.get_capability_completions(cmd, arg_index, current_word);

            if !candidates.is_empty() {
                // Calculate the start position for replacement
                let start = if trailing_space {
                    pos
                } else {
                    pos - current_word.len()
                };
                return Ok((start, candidates));
            }
        }

        Ok((0, Vec::new()))
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
