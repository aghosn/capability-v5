use capability_engine::*;
use colored::*;
use parking_lot::RwLock;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use std::collections::HashMap;
use std::sync::Arc;

mod session;
use session::{Command, Session};

/// CLI state maintaining all capabilities and domains
struct CliState {
    /// Map from user-assigned names to domain capabilities
    domains: HashMap<String, Arc<RwLock<Capability<Domain>>>>,
    /// Map from user-assigned names to memory capabilities
    memories: HashMap<String, Arc<RwLock<Capability<MemoryRegion>>>>,
    /// Switch manager for domain switching
    switch_manager: SwitchManager,
    /// Session recorder
    session: Session,
    /// Next available capability ID
    next_cap_id: u64,
    /// Map from domain ID to user-assigned name (for reverse lookup)
    domain_id_to_name: HashMap<u64, String>,
}

impl CliState {
    fn new(num_cores: usize) -> Self {
        CliState {
            domains: HashMap::new(),
            memories: HashMap::new(),
            switch_manager: SwitchManager::new(num_cores),
            session: Session::new(),
            next_cap_id: 0,
            domain_id_to_name: HashMap::new(),
        }
    }

    fn next_id(&mut self) -> u64 {
        let id = self.next_cap_id;
        self.next_cap_id += 1;
        id
    }
}

fn main() {
    println!("{}", "=== Capability Engine CLI Simulator ===".bright_cyan().bold());
    println!("Type 'help' for available commands, 'exit' to quit\n");

    let mut state = CliState::new(4);
    let mut rl = DefaultEditor::new().expect("Failed to create readline editor");

    // Add command history
    let _ = rl.load_history(".capability_cli_history");

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

    let _ = rl.save_history(".capability_cli_history");
}

fn handle_command(state: &mut CliState, line: &str) -> std::result::Result<(), String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return Ok(());
    }

    let cmd = parts[0];

    match cmd {
        "help" => show_help(),
        "init" => cmd_init(state, &parts[1..])?,
        "create-domain" => cmd_create_domain(state, &parts[1..])?,
        "carve" => cmd_carve(state, &parts[1..])?,
        "alias" => cmd_alias(state, &parts[1..])?,
        "send" => cmd_send(state, &parts[1..])?,
        "seal" => cmd_seal(state, &parts[1..])?,
        "revoke" => cmd_revoke(state, &parts[1..])?,
        "attest" => cmd_attest(state, &parts[1..])?,
        "view" => cmd_view(state, &parts[1..])?,
        "switch" => cmd_switch(state, &parts[1..])?,
        "interrupt" => cmd_interrupt(state, &parts[1..])?,
        "list" => cmd_list(state)?,
        "save-session" => cmd_save_session(state, &parts[1..])?,
        "clear-session" => cmd_clear_session(state)?,
        _ => return Err(format!("Unknown command: {}", cmd)),
    }

    Ok(())
}

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
    println!("    Revoke a child capability");
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
    println!("    List all domains and memory regions");
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

fn cmd_init(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.len() != 2 {
        return Err("Usage: init <name> <size>".to_string());
    }

    let name = args[0];
    let size = parse_number(args[1])?;

    // Create root domain
    let root_domain = Domain::new_root();
    let root_cap_id = state.next_id();
    let root = Capability::new_root(0, root_cap_id, root_domain);
    let root_name = format!("{}_domain", name);

    // Track domain name for reverse lookup
    state.domain_id_to_name.insert(0, root_name.clone());
    state.domains.insert(root_name.clone(), root.clone());

    // Create root memory region
    let root_region = MemoryRegion::new_root(0x0, size);
    let mem_cap_id = state.next_id();
    let mem_root = Capability::new_root(0, mem_cap_id, root_region);
    let mem_name = format!("{}_mem", name);
    state.memories.insert(mem_name.clone(), mem_root.clone());

    // Register memory capability with root domain
    root.write()
        .data
        .add_memory_capability(mem_cap_id, Arc::downgrade(&mem_root));

    // Record command
    state.session.add_command(Command::Init {
        name: name.to_string(),
        size,
    });

    println!(
        "{} Created root domain '{}' and memory region '{}' (size: 0x{:x})",
        "✓".bright_green().bold(),
        root_name.bright_white(),
        mem_name.bright_white(),
        size
    );

    Ok(())
}

fn cmd_create_domain(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.len() != 4 {
        return Err("Usage: create-domain <parent> <name> <cores> <api>".to_string());
    }

    let parent_name = args[0];
    let child_name = args[1];
    let cores = parse_number(args[2])?;
    let api = parse_api(args[3])?;

    let child_policy = DomainPolicy::new_restricted(cores, api);
    let child_cap_id = state.next_id();

    let parent = state
        .domains
        .get(parent_name)
        .ok_or_else(|| format!("Domain '{}' not found", parent_name))?;

    let child = parent
        .create_child(child_policy, child_cap_id)
        .map_err(|e| format!("Failed to create child: {:?}", e))?;

    let child_id = child.read().data.id;

    // Register domain capability with parent
    parent
        .write()
        .data
        .add_domain_capability(child_cap_id, Arc::downgrade(&child));

    // Track domain name for reverse lookup
    state.domain_id_to_name.insert(child_id, child_name.to_string());
    state.domains.insert(child_name.to_string(), child);

    // Record command
    state.session.add_command(Command::CreateDomain {
        parent: parent_name.to_string(),
        name: child_name.to_string(),
        cores,
        api_bits: api.bits() as u64,
    });

    println!(
        "{} Created domain '{}' (ID: {}, cores: 0b{:b})",
        "✓".bright_green().bold(),
        child_name.bright_white(),
        child_id,
        cores
    );

    Ok(())
}

fn cmd_carve(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.len() != 5 {
        return Err("Usage: carve <parent> <name> <start> <size> <rights>".to_string());
    }

    let parent_name = args[0];
    let child_name = args[1];
    let start = parse_number(args[2])?;
    let size = parse_number(args[3])?;
    let rights = parse_rights(args[4])?;

    let access = Access::new(start, size, rights);
    let child_cap_id = state.next_id();

    let parent = state
        .memories
        .get(parent_name)
        .ok_or_else(|| format!("Memory region '{}' not found", parent_name))?;

    let (child, updates): (_, UpdateBatch) = parent
        .carve(access, child_cap_id)
        .map_err(|e| format!("Failed to carve: {:?}", e))?;

    state.memories.insert(child_name.to_string(), child);

    // Record command
    state.session.add_command(Command::Carve {
        parent: parent_name.to_string(),
        name: child_name.to_string(),
        start,
        size,
        rights: format!("{:?}", rights),
    });

    println!(
        "{} Carved memory region '{}' [0x{:x}..0x{:x}) {:?} ({} updates)",
        "✓".bright_green().bold(),
        child_name.bright_white(),
        start,
        start + size,
        rights,
        updates.len()
    );

    Ok(())
}

fn cmd_alias(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.len() != 5 {
        return Err("Usage: alias <parent> <name> <start> <size> <rights>".to_string());
    }

    let parent_name = args[0];
    let child_name = args[1];
    let start = parse_number(args[2])?;
    let size = parse_number(args[3])?;
    let rights = parse_rights(args[4])?;

    let access = Access::new(start, size, rights);
    let child_cap_id = state.next_id();

    let parent = state
        .memories
        .get(parent_name)
        .ok_or_else(|| format!("Memory region '{}' not found", parent_name))?;

    let child = parent
        .alias(access, child_cap_id)
        .map_err(|e| format!("Failed to alias: {:?}", e))?;

    state.memories.insert(child_name.to_string(), child);

    // Record command
    state.session.add_command(Command::Alias {
        parent: parent_name.to_string(),
        name: child_name.to_string(),
        start,
        size,
        rights: format!("{:?}", rights),
    });

    println!(
        "{} Aliased memory region '{}' [0x{:x}..0x{:x}) {:?}",
        "✓".bright_green().bold(),
        child_name.bright_white(),
        start,
        start + size,
        rights
    );

    Ok(())
}

fn cmd_send(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.len() < 2 || args.len() > 3 {
        return Err("Usage: send <mem> <domain> [attrs]".to_string());
    }

    let mem_name = args[0];
    let domain_name = args[1];
    let attrs = if args.len() == 3 {
        parse_attributes(args[2])?
    } else {
        Attributes::NONE
    };

    let mem = state
        .memories
        .get(mem_name)
        .ok_or_else(|| format!("Memory region '{}' not found", mem_name))?;

    let domain = state
        .domains
        .get(domain_name)
        .ok_or_else(|| format!("Domain '{}' not found", domain_name))?;

    let domain_id = domain.read().data.id;

    // Automatically allocate handle in the receiving domain
    let handle = domain.read().data.allocate_memory_handle();

    let updates = mem
        .send(domain_id, handle, attrs)
        .map_err(|e| format!("Failed to send: {:?}", e))?;

    // Register memory capability with domain
    domain
        .write()
        .data
        .add_memory_capability(handle, Arc::downgrade(mem));

    // Record command
    state.session.add_command(Command::Send {
        mem: mem_name.to_string(),
        domain: domain_name.to_string(),
        handle,
        attrs: format!("{:?}", attrs),
    });

    println!(
        "{} Sent '{}' to '{}' with auto-allocated handle {} ({} updates)",
        "✓".bright_green().bold(),
        mem_name.bright_white(),
        domain_name.bright_white(),
        handle,
        updates.len()
    );

    Ok(())
}

fn cmd_seal(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.len() != 1 {
        return Err("Usage: seal <domain>".to_string());
    }

    let domain_name = args[0];
    let domain = state
        .domains
        .get(domain_name)
        .ok_or_else(|| format!("Domain '{}' not found", domain_name))?;

    domain
        .write()
        .data
        .seal()
        .map_err(|e| format!("Failed to seal: {:?}", e))?;

    // Record command
    state.session.add_command(Command::Seal {
        domain: domain_name.to_string(),
    });

    println!(
        "{} Sealed domain '{}'",
        "✓".bright_green().bold(),
        domain_name.bright_white()
    );

    Ok(())
}

fn cmd_revoke(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.len() != 2 {
        return Err("Usage: revoke <parent> <child>".to_string());
    }

    let parent_name = args[0];
    let child_name = args[1];

    // Try to revoke as memory region first
    if let (Some(parent), Some(child)) = (state.memories.get(parent_name), state.memories.get(child_name)) {
        let updates = parent
            .revoke_ref(child)
            .map_err(|e| format!("Failed to revoke memory: {:?}", e))?;

        // Record command
        state.session.add_command(Command::Revoke {
            parent: parent_name.to_string(),
            child: child_name.to_string(),
        });

        println!(
            "{} Revoked memory '{}' from '{}' ({} updates)",
            "✓".bright_green().bold(),
            child_name.bright_white(),
            parent_name.bright_white(),
            updates.len()
        );

        return Ok(());
    }

    // Try to revoke as domain
    if let (Some(parent), Some(child)) = (state.domains.get(parent_name), state.domains.get(child_name)) {
        // Find the handle for the child domain in the parent
        let child_id = child.read().data.id;
        let parent_read = parent.read();

        let handle = parent_read
            .data
            .domain_capabilities
            .iter()
            .find(|(_, weak_cap)| {
                if let Some(cap) = weak_cap.upgrade() {
                    cap.read().data.id == child_id
                } else {
                    false
                }
            })
            .map(|(h, _)| *h)
            .ok_or_else(|| format!("Child domain '{}' not found in parent '{}'", child_name, parent_name))?;

        drop(parent_read);

        let updates = parent
            .revoke_child(handle)
            .map_err(|e| format!("Failed to revoke domain: {:?}", e))?;

        // Record command
        state.session.add_command(Command::Revoke {
            parent: parent_name.to_string(),
            child: child_name.to_string(),
        });

        println!(
            "{} Revoked domain '{}' from '{}' ({} updates) - cascaded to all children and capabilities",
            "✓".bright_green().bold(),
            child_name.bright_white(),
            parent_name.bright_white(),
            updates.len()
        );

        return Ok(());
    }

    Err(format!(
        "Could not find '{}' and '{}' as either memory regions or domains",
        parent_name, child_name
    ))
}

fn cmd_attest(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
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

fn cmd_view(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
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

fn cmd_switch(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    // Support two formats:
    // 1. New format: switch <domain> <core>
    // 2. Old format: switch <core> <from> <to>

    let (core, from, to, from_name, to_name) = if args.len() == 2 {
        // New format: switch <domain> <core>
        let to_name = args[0];
        let core = parse_number(args[1])?;

        let to = state
            .domains
            .get(to_name)
            .ok_or_else(|| format!("Domain '{}' not found", to_name))?;

        // Get current domain on this core
        let core_ref = state
            .switch_manager
            .get_core(core)
            .map_err(|e| format!("Core {} not found: {:?}", core, e))?;

        let current_state = core_ref.state.read();
        let from_id = match *current_state {
            CoreState::Running(id) => id,
            CoreState::Idle => {
                // First switch on this core, initialize it
                drop(current_state);
                let to_id = to.read().data.id;
                *core_ref.state.write() = CoreState::Running(to_id);

                println!(
                    "{} Initialized core {} with domain '{}' (ID: {})",
                    "✓".bright_green().bold(),
                    core,
                    to_name.bright_white(),
                    to_id
                );
                return Ok(());
            }
        };
        drop(current_state);

        let from_name = state
            .domain_id_to_name
            .get(&from_id)
            .ok_or_else(|| format!("Current domain ID {} not found in name mapping", from_id))?
            .clone();

        let from = state
            .domains
            .get(&from_name)
            .ok_or_else(|| format!("Domain '{}' not found", from_name))?;

        (core, from.clone(), to.clone(), from_name, to_name.to_string())
    } else if args.len() == 3 {
        // Old format: switch <core> <from> <to>
        let core = parse_number(args[0])?;
        let from_name = args[1];
        let to_name = args[2];

        let from = state
            .domains
            .get(from_name)
            .ok_or_else(|| format!("Domain '{}' not found", from_name))?;

        let to = state
            .domains
            .get(to_name)
            .ok_or_else(|| format!("Domain '{}' not found", to_name))?;

        // Initialize core if needed
        {
            let core_ref = state
                .switch_manager
                .get_core(core)
                .map_err(|e| format!("Core {} not found: {:?}", core, e))?;
            let current_state = core_ref.state.read();
            if matches!(*current_state, CoreState::Idle) {
                drop(current_state);
                *core_ref.state.write() = CoreState::Running(from.read().data.id);
            }
        }

        (core, from.clone(), to.clone(), from_name.to_string(), to_name.to_string())
    } else {
        return Err("Usage: switch <domain> <core> OR switch <core> <from> <to>".to_string());
    };

    let ctx = state
        .switch_manager
        .switch(core, &from, Some(&to))
        .map_err(|e| format!("Failed to switch: {:?}", e))?;

    // Record command
    state.session.add_command(Command::Switch {
        core,
        from: from_name.clone(),
        to: to_name.clone(),
    });

    println!(
        "{} Switched on core {} from domain '{}' to domain '{}'",
        "✓".bright_green().bold(),
        core,
        from_name.bright_white(),
        to_name.bright_white()
    );

    Ok(())
}

fn cmd_interrupt(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    // Support two formats:
    // 1. Simple format: interrupt <vector> <core> (delivers to current domain on core)
    // 2. Explicit format: interrupt <vector> <domain> <core>

    let (vector, domain, domain_name, core) = if args.len() == 2 {
        // Simple format: interrupt <vector> <core>
        let vector = parse_number(args[0])? as u8;
        let core = parse_number(args[1])?;

        // Get current domain on this core
        let core_ref = state
            .switch_manager
            .get_core(core)
            .map_err(|e| format!("Core {} not found: {:?}", core, e))?;

        let current_state = core_ref.state.read();
        let domain_id = match *current_state {
            CoreState::Running(id) => id,
            CoreState::Idle => {
                return Err(format!("Core {} is idle, no domain to deliver interrupt to", core));
            }
        };
        drop(current_state);

        let domain_name = state
            .domain_id_to_name
            .get(&domain_id)
            .ok_or_else(|| format!("Current domain ID {} not found in name mapping", domain_id))?
            .clone();

        let domain = state
            .domains
            .get(&domain_name)
            .ok_or_else(|| format!("Domain '{}' not found", domain_name))?;

        (vector, domain.clone(), domain_name, core)
    } else if args.len() == 3 {
        // Explicit format: interrupt <vector> <domain> <core>
        let vector = parse_number(args[0])? as u8;
        let domain_name = args[1];
        let core = parse_number(args[2])?;

        let domain = state
            .domains
            .get(domain_name)
            .ok_or_else(|| format!("Domain '{}' not found", domain_name))?;

        (vector, domain.clone(), domain_name.to_string(), core)
    } else {
        return Err("Usage: interrupt <vector> <core> OR interrupt <vector> <domain> <core>".to_string());
    };

    let (handler_id, reported_to) = state
        .switch_manager
        .route_interrupt(vector, &domain, core)
        .map_err(|e| format!("Failed to route interrupt: {:?}", e))?;

    // Record command
    state.session.add_command(Command::Interrupt {
        vector: vector as u64,
        domain: domain_name.clone(),
        core,
    });

    println!(
        "{} Interrupt {} delivered to domain '{}' on core {} (handler: {}, reported to {} domains)",
        "✓".bright_green().bold(),
        vector,
        domain_name.bright_white(),
        core,
        handler_id,
        reported_to.len()
    );

    Ok(())
}

fn cmd_list(state: &mut CliState) -> std::result::Result<(), String> {
    // Show active domains per core
    println!("\n{}", "Active Domains per Core:".bright_cyan().bold());
    let num_cores = 4; // Match the number in CliState::new
    for core_id in 0..num_cores {
        if let Ok(core_ref) = state.switch_manager.get_core(core_id as u64) {
            let core_state = core_ref.state.read();
            match *core_state {
                CoreState::Running(domain_id) => {
                    let domain_name = state
                        .domain_id_to_name
                        .get(&domain_id)
                        .map(|s| s.as_str())
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

fn cmd_save_session(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
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

fn cmd_clear_session(state: &mut CliState) -> std::result::Result<(), String> {
    state.session.clear();
    println!("{} Session cleared", "✓".bright_green().bold());
    Ok(())
}

// Parsing utilities

fn parse_number(s: &str) -> std::result::Result<u64, String> {
    if s.starts_with("0x") {
        u64::from_str_radix(&s[2..], 16).map_err(|e| format!("Invalid hex number: {}", e))
    } else if s.starts_with("0b") {
        u64::from_str_radix(&s[2..], 2).map_err(|e| format!("Invalid binary number: {}", e))
    } else {
        s.parse::<u64>()
            .map_err(|e| format!("Invalid number: {}", e))
    }
}

fn parse_rights(s: &str) -> std::result::Result<Rights, String> {
    let mut rights_bits: u8 = 0;
    for c in s.chars() {
        match c {
            'R' | 'r' => rights_bits |= Rights::READ,
            'W' | 'w' => rights_bits |= Rights::WRITE,
            'X' | 'x' => rights_bits |= Rights::EXECUTE,
            '-' => {}
            _ => return Err(format!("Invalid rights character: {}", c)),
        }
    }
    Ok(Rights::from_bits(rights_bits))
}

fn parse_api(s: &str) -> std::result::Result<MonitorAPI, String> {
    let mut api_bits: u16 = 0;
    for part in s.split(',') {
        let part = part.trim().to_uppercase();
        let flag_bits = match part.as_str() {
            "CREATE" => MonitorAPI::CREATE as u16,
            "SET" => MonitorAPI::SET as u16,
            "GET" => MonitorAPI::GET as u16,
            "SEND" => MonitorAPI::SEND as u16,
            "SEAL" => MonitorAPI::SEAL as u16,
            "ATTEST" => MonitorAPI::ATTEST as u16,
            "ENUMERATE" => MonitorAPI::ENUMERATE as u16,
            "SWITCH" => MonitorAPI::SWITCH as u16,
            "ALIAS" => MonitorAPI::ALIAS as u16,
            "CARVE" => MonitorAPI::CARVE as u16,
            "REVOKE" => MonitorAPI::REVOKE as u16,
            "GETCHAN" => MonitorAPI::GETCHAN as u16,
            "RECEIVE_AFTER_SEAL" => MonitorAPI::RECEIVE_AFTER_SEAL as u16,
            "ALL" => return Ok(MonitorAPI::from_bits(0x1FFF)),
            "NONE" => return Ok(MonitorAPI::from_bits(0)),
            _ => return Err(format!("Invalid API permission: {}", part)),
        };
        api_bits |= flag_bits;
    }
    Ok(MonitorAPI::from_bits(api_bits))
}

fn parse_attributes(s: &str) -> std::result::Result<Attributes, String> {
    let mut attrs_bits: u8 = 0;
    for part in s.split(',') {
        let part = part.trim().to_uppercase();
        let flag_bits = match part.as_str() {
            "CLEAN" => Attributes::CLEAN as u8,
            "VITAL" => Attributes::VITAL as u8,
            "NONE" => return Ok(Attributes::from_bits(0)),
            _ => return Err(format!("Invalid attribute: {}", part)),
        };
        attrs_bits |= flag_bits;
    }
    Ok(Attributes::from_bits(attrs_bits))
}
