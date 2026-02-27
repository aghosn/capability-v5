use std::fs::File;
use std::io::Write;

/// Represents a recorded command in the session
#[derive(Debug, Clone)]
pub enum Command {
    Init {
        name: String,
        size: u64,
    },
    CreateDomain {
        parent: String,
        name: String,
        cores: u64,
        api: String,
    },
    Carve {
        parent: String,
        name: String,
        start: u64,
        size: u64,
        rights: String,
    },
    Alias {
        parent: String,
        name: String,
        start: u64,
        size: u64,
        rights: String,
    },
    Send {
        mem: String,
        domain: String,
        handle: u64,
        attrs: String,
    },
    Seal {
        domain: String,
    },
    Revoke {
        parent: String,
        child: String,
    },
    Attest {
        domain: String,
    },
    View {
        domain: String,
    },
    Switch {
        core: u64,
        from: String,
        to: String,
    },
    Interrupt {
        vector: u64,
        domain: String,
        core: u64,
    },
    EnumeratePending {
        domain: String,
    },
    AcceptCapability {
        domain: String,
        pending_id: u64,
        handle: u64,
    },
    RejectCapability {
        domain: String,
        pending_id: u64,
    },
}

/// Session recorder that can export commands as unit tests
pub struct Session {
    commands: Vec<Command>,
}

impl Session {
    pub fn new() -> Self {
        Session {
            commands: Vec::new(),
        }
    }

    pub fn add_command(&mut self, cmd: Command) {
        self.commands.push(cmd);
    }

    pub fn clear(&mut self) {
        self.commands.clear();
    }

    /// Save the session as plain CLI commands for later replay via `load`
    pub fn save_as_commands(&self, filename: &str) -> std::io::Result<()> {
        let mut file = File::create(filename)?;

        writeln!(file, "# Capability CLI session — replay with: load {}", filename)?;

        for cmd in &self.commands {
            let line = match cmd {
                Command::Init { name, size } => {
                    format!("init {} 0x{:x}", name, size)
                }
                Command::CreateDomain { parent, name, cores, api } => {
                    format!("create-domain {} {} {} {}", parent, name, cores, api)
                }
                Command::Carve { parent, name, start, size, rights } => {
                    format!("carve {} {} 0x{:x} 0x{:x} {}", parent, name, start, size, rights)
                }
                Command::Alias { parent, name, start, size, rights } => {
                    format!("alias {} {} 0x{:x} 0x{:x} {}", parent, name, start, size, rights)
                }
                Command::Send { mem, domain, handle: _, attrs } => {
                    format!("send {} {} {}", mem, domain, attrs)
                }
                Command::Seal { domain } => {
                    format!("seal {}", domain)
                }
                Command::Revoke { parent, child } => {
                    format!("revoke {} {}", parent, child)
                }
                Command::Attest { domain } => {
                    format!("attest {}", domain)
                }
                Command::View { domain } => {
                    format!("view {}", domain)
                }
                Command::Switch { core, from, to } => {
                    format!("switch {} {} {}", core, from, to)
                }
                Command::Interrupt { vector, domain, core } => {
                    format!("interrupt {} {} {}", vector, domain, core)
                }
                Command::EnumeratePending { domain } => {
                    format!("enumerate-pending {}", domain)
                }
                Command::AcceptCapability { domain, pending_id, handle: _ } => {
                    format!("accept-capability {} {}", domain, pending_id)
                }
                Command::RejectCapability { domain, pending_id } => {
                    format!("reject-capability {} {}", domain, pending_id)
                }
            };
            writeln!(file, "{}", line)?;
        }

        Ok(())
    }

    /// Save the session as a Rust unit test
    pub fn save_as_test(&self, filename: &str) -> std::io::Result<()> {
        let mut file = File::create(filename)?;

        // Write test header
        writeln!(file, "//! Test generated from CLI session\n")?;
        writeln!(file, "use capability_engine::*;")?;
        writeln!(file, "use std::sync::Arc;\n")?;
        writeln!(file, "#[test]")?;
        writeln!(file, "fn test_session() {{")?;

        // Track variable names for generated code
        let mut var_map = std::collections::HashMap::new();

        for cmd in &self.commands {
            match cmd {
                Command::Init { name, size } => {
                    let domain_var = format!("{}_domain", sanitize_name(name));
                    let mem_var = format!("{}_mem", sanitize_name(name));

                    writeln!(file, "    // Initialize root domain and memory")?;
                    writeln!(file, "    let root_domain = Domain::new_root();")?;
                    writeln!(
                        file,
                        "    let {} = Capability::new_root(0, 0, root_domain);",
                        domain_var
                    )?;
                    writeln!(
                        file,
                        "    let root_region = MemoryRegion::new_root(0x0, 0x{:x});",
                        size
                    )?;
                    writeln!(
                        file,
                        "    let {} = Capability::new_root(0, 1, root_region);",
                        mem_var
                    )?;
                    writeln!(
                        file,
                        "    {}.write().data.add_memory_capability(1, Arc::downgrade(&{}));",
                        domain_var, mem_var
                    )?;
                    writeln!(file)?;

                    var_map.insert(format!("{}_domain", name), domain_var.clone());
                    var_map.insert(format!("{}_mem", name), mem_var.clone());
                }

                Command::CreateDomain {
                    parent,
                    name,
                    cores,
                    api,
                } => {
                    let parent_var = var_map
                        .get(parent)
                        .cloned()
                        .unwrap_or_else(|| sanitize_name(parent));
                    let child_var = sanitize_name(name);

                    writeln!(file, "    // Create child domain: {}", name)?;
                    writeln!(
                        file,
                        "    let api = parse_api(\"{}\").unwrap();",
                        api
                    )?;
                    writeln!(
                        file,
                        "    let policy = DomainPolicy::new_restricted(0x{:x}, api);",
                        cores
                    )?;
                    writeln!(
                        file,
                        "    let owner = {}.read().owned.owner;",
                        parent_var
                    )?;
                    writeln!(
                        file,
                        "    let {} = Capability::create_child_domain(&{}, policy, owner, {}).unwrap();",
                        child_var,
                        parent_var,
                        get_next_cap_id(&var_map)
                    )?;
                    writeln!(
                        file,
                        "    {}.write().data.add_domain_capability({}, Arc::downgrade(&{}));",
                        parent_var,
                        get_next_cap_id(&var_map),
                        child_var
                    )?;
                    writeln!(file)?;

                    var_map.insert(name.clone(), child_var);
                }

                Command::Carve {
                    parent,
                    name,
                    start,
                    size,
                    rights,
                } => {
                    let parent_var = var_map
                        .get(parent)
                        .cloned()
                        .unwrap_or_else(|| sanitize_name(parent));
                    let child_var = sanitize_name(name);

                    writeln!(file, "    // Carve memory region: {}", name)?;
                    writeln!(
                        file,
                        "    let access = Access::new(0x{:x}, 0x{:x}, {});",
                        start, size, rights
                    )?;
                    writeln!(
                        file,
                        "    let owner = {}.read().owned.owner;",
                        parent_var
                    )?;
                    writeln!(
                        file,
                        "    let ({}, _) = Capability::carve_child(&{}, access, owner, {}).unwrap();",
                        child_var,
                        parent_var,
                        get_next_cap_id(&var_map)
                    )?;
                    writeln!(file)?;

                    var_map.insert(name.clone(), child_var);
                }

                Command::Alias {
                    parent,
                    name,
                    start,
                    size,
                    rights,
                } => {
                    let parent_var = var_map
                        .get(parent)
                        .cloned()
                        .unwrap_or_else(|| sanitize_name(parent));
                    let child_var = sanitize_name(name);

                    writeln!(file, "    // Alias memory region: {}", name)?;
                    writeln!(
                        file,
                        "    let access = Access::new(0x{:x}, 0x{:x}, {});",
                        start, size, rights
                    )?;
                    writeln!(
                        file,
                        "    let owner = {}.read().owned.owner;",
                        parent_var
                    )?;
                    writeln!(
                        file,
                        "    let {} = Capability::alias_child(&{}, access, owner, {}).unwrap();",
                        child_var,
                        parent_var,
                        get_next_cap_id(&var_map)
                    )?;
                    writeln!(file)?;

                    var_map.insert(name.clone(), child_var);
                }

                Command::Send {
                    mem,
                    domain,
                    handle,
                    attrs,
                } => {
                    let mem_var = var_map
                        .get(mem)
                        .cloned()
                        .unwrap_or_else(|| sanitize_name(mem));
                    let domain_var = var_map
                        .get(domain)
                        .cloned()
                        .unwrap_or_else(|| sanitize_name(domain));

                    writeln!(file, "    // Send {} to {}", mem, domain)?;
                    writeln!(
                        file,
                        "    let domain_id = {}.read().data.id;",
                        domain_var
                    )?;
                    writeln!(
                        file,
                        "    let caller_id = {}.read().owned.owner;",
                        mem_var
                    )?;
                    writeln!(
                        file,
                        "    let _updates = Capability::send_to(&{}, caller_id, domain_id, {}).unwrap();",
                        mem_var, attrs
                    )?;
                    writeln!(
                        file,
                        "    {}.write().data.add_memory_capability({}, Arc::downgrade(&{}));",
                        domain_var, handle, mem_var
                    )?;
                    writeln!(file)?;
                }

                Command::Seal { domain } => {
                    let domain_var = var_map
                        .get(domain)
                        .cloned()
                        .unwrap_or_else(|| sanitize_name(domain));

                    writeln!(file, "    // Seal domain: {}", domain)?;
                    writeln!(file, "    {}.write().data.seal().unwrap();", domain_var)?;
                    writeln!(file)?;
                }

                Command::Revoke { parent, child } => {
                    let parent_var = var_map
                        .get(parent)
                        .cloned()
                        .unwrap_or_else(|| sanitize_name(parent));
                    let child_var = var_map
                        .get(child)
                        .cloned()
                        .unwrap_or_else(|| sanitize_name(child));

                    writeln!(file, "    // Revoke {} from {}", child, parent)?;
                    writeln!(
                        file,
                        "    let _updates = Capability::revoke_child_ref(&{}, &{}).unwrap();",
                        parent_var, child_var
                    )?;
                    writeln!(file)?;
                }

                Command::Attest { domain } => {
                    let domain_var = var_map
                        .get(domain)
                        .cloned()
                        .unwrap_or_else(|| sanitize_name(domain));

                    writeln!(file, "    // Attest domain: {}", domain)?;
                    writeln!(
                        file,
                        "    let _attestation = attest_domain(&{});",
                        domain_var
                    )?;
                    writeln!(file, "    // Verify attestation if needed")?;
                    writeln!(file)?;
                }

                Command::View { domain } => {
                    let domain_var = var_map
                        .get(domain)
                        .cloned()
                        .unwrap_or_else(|| sanitize_name(domain));

                    writeln!(file, "    // View address space: {}", domain)?;
                    writeln!(
                        file,
                        "    let _view = compute_address_space(&{});",
                        domain_var
                    )?;
                    writeln!(file, "    // Add assertions on view if needed")?;
                    writeln!(file)?;
                }

                Command::Switch { core, from, to } => {
                    let from_var = var_map
                        .get(from)
                        .cloned()
                        .unwrap_or_else(|| sanitize_name(from));
                    let to_var = var_map
                        .get(to)
                        .cloned()
                        .unwrap_or_else(|| sanitize_name(to));

                    writeln!(file, "    // Switch on core {} from {} to {}", core, from, to)?;
                    writeln!(file, "    let switch_mgr = SwitchManager::new(4);")?;
                    writeln!(file, "    {{")?;
                    writeln!(
                        file,
                        "        let core_ref = switch_mgr.get_core({}).unwrap();",
                        core
                    )?;
                    writeln!(file, "        *core_ref.state.write() = CoreState::Running({}.read().data.id);", from_var)?;
                    writeln!(file, "    }}")?;
                    writeln!(
                        file,
                        "    let _ctx = switch_mgr.switch({}, &{}, Some(&{})).unwrap();",
                        core, from_var, to_var
                    )?;
                    writeln!(file)?;
                }

                Command::Interrupt {
                    vector,
                    domain,
                    core,
                } => {
                    let domain_var = var_map
                        .get(domain)
                        .cloned()
                        .unwrap_or_else(|| sanitize_name(domain));

                    writeln!(
                        file,
                        "    // Route interrupt {} on {} (core {})",
                        vector, domain, core
                    )?;
                    writeln!(file, "    let switch_mgr = SwitchManager::new(4);")?;
                    writeln!(
                        file,
                        "    let (handler_id, reported_to) = switch_mgr.route_interrupt({}, &{}, {}).unwrap();",
                        vector, domain_var, core
                    )?;
                    writeln!(file, "    // Add assertions on handler_id and reported_to if needed")?;
                    writeln!(file)?;
                }

                Command::EnumeratePending { domain } => {
                    let domain_var = var_map
                        .get(domain)
                        .cloned()
                        .unwrap_or_else(|| sanitize_name(domain));

                    writeln!(file, "    // Enumerate pending capabilities for {}", domain)?;
                    writeln!(file, "    let pending_ids = {}.read().data.get_pending_ids();", domain_var)?;
                    writeln!(file, "    // Add assertions on pending_ids if needed")?;
                    writeln!(file)?;
                }

                Command::AcceptCapability { domain, pending_id, handle: _ } => {
                    let domain_var = var_map
                        .get(domain)
                        .cloned()
                        .unwrap_or_else(|| sanitize_name(domain));

                    writeln!(file, "    // Accept pending capability {} for {}", pending_id, domain)?;
                    writeln!(
                        file,
                        "    let (_handle, _updates) = Capability::accept_memory(&{}, {}).unwrap();",
                        domain_var, pending_id
                    )?;
                    writeln!(file)?;
                }

                Command::RejectCapability { domain, pending_id } => {
                    let domain_var = var_map
                        .get(domain)
                        .cloned()
                        .unwrap_or_else(|| sanitize_name(domain));

                    writeln!(file, "    // Reject pending capability {} for {}", pending_id, domain)?;
                    writeln!(
                        file,
                        "    Capability::reject_memory(&{}, {}).unwrap();",
                        domain_var, pending_id
                    )?;
                    writeln!(file)?;
                }
            }
        }

        writeln!(file, "    // Test completed successfully")?;
        writeln!(file, "}}")?;

        Ok(())
    }
}

/// Sanitize a name to be a valid Rust identifier
fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' })
        .collect()
}

/// Get next capability ID (simplified - in real code would track properly)
fn get_next_cap_id(_var_map: &std::collections::HashMap<String, String>) -> usize {
    // This is a simplification - in a real implementation we'd track the next ID properly
    // For now, just return a reasonable value
    2
}
