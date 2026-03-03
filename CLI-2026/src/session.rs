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
    },
    RejectCapability {
        domain: String,
        pending_id: u64,
    },
    GetChan {
        caller: String,
        target: String,
        chan_name: String,
    },
    SendChannel {
        caller: String,
        chan_name: String,
        receiver: String,
    },
    AcceptChannel {
        receiver: String,
        pending_id: u64,
        chan_name: String,
    },
    RejectChannel {
        receiver: String,
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
                Command::Send { mem, domain, attrs } => {
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
                Command::AcceptCapability { domain, pending_id } => {
                    format!("accept-capability {} {}", domain, pending_id)
                }
                Command::RejectCapability { domain, pending_id } => {
                    format!("reject-capability {} {}", domain, pending_id)
                }
                Command::GetChan { caller: _, target, chan_name } => {
                    format!("get-chan {} {}", target, chan_name)
                }
                Command::SendChannel { caller: _, chan_name, receiver } => {
                    format!("send {} {}", chan_name, receiver)
                }
                Command::AcceptChannel { receiver, pending_id, chan_name } => {
                    format!("accept-channel {} {} {}", receiver, pending_id, chan_name)
                }
                Command::RejectChannel { receiver, pending_id } => {
                    format!("reject-channel {} {}", receiver, pending_id)
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

        // Maps tracking generated variable names and ownership for domain-mediated API calls.
        //   arc_map:    name  → Rust var name for the Arc (domain or memory capability)
        //   handle_map: name  → Rust var name for the LocalHandle in its owner's table
        //   owner_map:  name  → owner domain name (for looking up which domain to call through)
        //   is_domain:  set of names that are domains (vs. memory regions)
        let mut arc_map:        std::collections::HashMap<String, String> = std::collections::HashMap::new();
        let mut handle_map:     std::collections::HashMap<String, String> = std::collections::HashMap::new();
        let mut sub_handle_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        let mut owner_map:      std::collections::HashMap<String, String> = std::collections::HashMap::new();
        let mut is_domain:      std::collections::HashSet<String>         = std::collections::HashSet::new();

        for cmd in &self.commands {
            match cmd {
                Command::Init { name, size } => {
                    let domain_var = format!("{}_cap", sanitize_name(name));
                    let mem_var    = format!("{}_mem_cap", sanitize_name(name));
                    let mem_name   = format!("{}_mem", sanitize_name(name));

                    writeln!(file, "    // Initialize root domain and memory")?;
                    writeln!(file, "    let root_domain_data = Domain::new_root(4);")?;
                    writeln!(file, "    let {domain_var} = Capability::new_root(0, 0, root_domain_data);")?;
                    writeln!(file, "    let root_region = MemoryRegion::new_root(0x0, 0x{size:x});")?;
                    writeln!(file, "    let {mem_var} = Capability::new_root(0, 1, root_region);")?;
                    writeln!(file, "    {domain_var}.write().data.add_memory_capability(1, Arc::downgrade(&{mem_var}));")?;
                    writeln!(file, "    let r0_handle: LocalHandle = 1;")?;
                    writeln!(file)?;

                    arc_map.insert(name.clone(), domain_var);
                    is_domain.insert(name.clone());
                    arc_map.insert(mem_name.clone(), mem_var);
                    handle_map.insert(mem_name.clone(), "r0_handle".to_string());
                    owner_map.insert(mem_name, name.clone());
                }

                Command::CreateDomain { parent, name, cores, api } => {
                    let parent_arc = arc_map.get(parent)
                        .cloned().unwrap_or_else(|| sanitize_name(parent));
                    let child_var    = format!("{}_cap", sanitize_name(name));
                    let handle_var   = format!("{}_handle", sanitize_name(name));

                    writeln!(file, "    // Create child domain: {name}")?;
                    writeln!(file, "    let {name}_api = MonitorAPI::from_bits({api_bits});",
                        api_bits = parse_api_bits(api))?;
                    writeln!(file, "    let {name}_policy = DomainPolicy::new_restricted(0x{cores:x}, {name}_api);")?;
                    writeln!(file, "    let {handle_var} = Capability::create(&{parent_arc}, {name}_policy).unwrap();")?;
                    writeln!(file, "    let {child_var} = {parent_arc}.read().data")?;
                    writeln!(file, "        .domain_capabilities[&{handle_var}].upgrade().unwrap();")?;
                    writeln!(file)?;

                    arc_map.insert(name.clone(), child_var);
                    handle_map.insert(name.clone(), handle_var);
                    owner_map.insert(name.clone(), parent.clone());
                    is_domain.insert(name.clone());
                }

                Command::Seal { domain } => {
                    let owner_name = owner_map.get(domain)
                        .cloned().unwrap_or_default();
                    let owner_arc  = arc_map.get(&owner_name)
                        .cloned().unwrap_or_else(|| sanitize_name(&owner_name));
                    let handle_var = handle_map.get(domain)
                        .cloned().unwrap_or_else(|| format!("{}_handle", sanitize_name(domain)));

                    writeln!(file, "    // Seal domain: {domain}")?;
                    writeln!(file, "    Capability::seal(&{owner_arc}, {handle_var}).unwrap();")?;
                    writeln!(file)?;
                }

                Command::Carve { parent, name, start, size, rights } => {
                    let parent_owner = owner_map.get(parent)
                        .cloned().unwrap_or_default();
                    let owner_arc    = arc_map.get(&parent_owner)
                        .cloned().unwrap_or_else(|| sanitize_name(&parent_owner));
                    let parent_handle = handle_map.get(parent)
                        .cloned().unwrap_or_else(|| format!("{}_handle", sanitize_name(parent)));
                    let child_var   = format!("{}_cap", sanitize_name(name));
                    let handle_var  = format!("{}_handle", sanitize_name(name));
                    let sub_var     = format!("{}_sub_handle", sanitize_name(name));

                    writeln!(file, "    // Carve memory region: {name}")?;
                    writeln!(file, "    let {name}_access = Access::new(0x{start:x}, 0x{size:x}, {rights});")?;
                    writeln!(file, "    let ({handle_var}, {sub_var}, _) = Capability::carve(&{owner_arc}, {parent_handle}, {name}_access).unwrap();")?;
                    writeln!(file, "    let {child_var} = {owner_arc}.read().data")?;
                    writeln!(file, "        .memory_capabilities[&{handle_var}].upgrade().unwrap();")?;
                    writeln!(file)?;

                    arc_map.insert(name.clone(), child_var);
                    handle_map.insert(name.clone(), handle_var);
                    sub_handle_map.insert(name.clone(), sub_var);
                    owner_map.insert(name.clone(), parent_owner);
                }

                Command::Alias { parent, name, start, size, rights } => {
                    let parent_owner = owner_map.get(parent)
                        .cloned().unwrap_or_default();
                    let owner_arc    = arc_map.get(&parent_owner)
                        .cloned().unwrap_or_else(|| sanitize_name(&parent_owner));
                    let parent_handle = handle_map.get(parent)
                        .cloned().unwrap_or_else(|| format!("{}_handle", sanitize_name(parent)));
                    let child_var   = format!("{}_cap", sanitize_name(name));
                    let handle_var  = format!("{}_handle", sanitize_name(name));
                    let sub_var     = format!("{}_sub_handle", sanitize_name(name));

                    writeln!(file, "    // Alias memory region: {name}")?;
                    writeln!(file, "    let {name}_access = Access::new(0x{start:x}, 0x{size:x}, {rights});")?;
                    writeln!(file, "    let ({handle_var}, {sub_var}) = Capability::alias(&{owner_arc}, {parent_handle}, {name}_access).unwrap();")?;
                    writeln!(file, "    let {child_var} = {owner_arc}.read().data")?;
                    writeln!(file, "        .memory_capabilities[&{handle_var}].upgrade().unwrap();")?;
                    writeln!(file)?;

                    arc_map.insert(name.clone(), child_var);
                    handle_map.insert(name.clone(), handle_var);
                    sub_handle_map.insert(name.clone(), sub_var);
                    owner_map.insert(name.clone(), parent_owner);
                }

                Command::Send { mem, domain, attrs } => {
                    let mem_owner   = owner_map.get(mem)
                        .cloned().unwrap_or_default();
                    let sender_arc  = arc_map.get(&mem_owner)
                        .cloned().unwrap_or_else(|| sanitize_name(&mem_owner));
                    let mem_handle  = handle_map.get(mem)
                        .cloned().unwrap_or_else(|| format!("{}_handle", sanitize_name(mem)));
                    let recv_arc    = arc_map.get(domain)
                        .cloned().unwrap_or_else(|| sanitize_name(domain));
                    let recv_domain_handle_var = format!("{}_recv_dom_h", sanitize_name(domain));

                    writeln!(file, "    // Send {mem} to {domain}")?;
                    writeln!(file, "    let {recv_domain_handle_var} = {sender_arc}.read().data")?;
                    writeln!(file, "        .domain_capabilities.iter().find(|(_, w)| w.upgrade().map_or(false, |a| std::sync::Arc::ptr_eq(&a, &{recv_arc}))).map(|(h, _)| *h)")?;
                    writeln!(file, "        .unwrap_or_else(|| {{")?;
                    writeln!(file, "            let h = {sender_arc}.read().data.allocate_domain_handle();")?;
                    writeln!(file, "            {sender_arc}.write().data.add_domain_capability(h, std::sync::Arc::downgrade(&{recv_arc}));")?;
                    writeln!(file, "            h")?;
                    writeln!(file, "        }});")?;
                    writeln!(file, "    let _ = Capability::send(&{sender_arc}, {mem_handle}, {recv_domain_handle_var}, {attrs}).unwrap();")?;
                    writeln!(file, "    // Note: {mem} is now owned by {domain}; handle lookup needed for further ops.")?;
                    writeln!(file)?;

                    // Update ownership tracking after the send
                    owner_map.insert(mem.clone(), domain.clone());
                    handle_map.remove(mem); // handle in new owner's table is unknown
                }

                Command::Revoke { parent, child } => {
                    if is_domain.contains(child) {
                        // Domain revoke
                        let parent_arc  = arc_map.get(parent)
                            .cloned().unwrap_or_else(|| sanitize_name(parent));
                        let child_handle = handle_map.get(child)
                            .cloned().unwrap_or_else(|| format!("{}_handle", sanitize_name(child)));

                        writeln!(file, "    // Revoke domain {child} from {parent}")?;
                        writeln!(file, "    let _ = Capability::revoke_domain(&{parent_arc}, {child_handle}).unwrap();")?;
                    } else {
                        // Memory revoke
                        let owner_name   = owner_map.get(parent)
                            .cloned().unwrap_or_default();
                        let owner_arc    = arc_map.get(&owner_name)
                            .cloned().unwrap_or_else(|| sanitize_name(&owner_name));
                        let parent_handle = handle_map.get(parent)
                            .cloned().unwrap_or_else(|| format!("{}_handle", sanitize_name(parent)));
                        let child_sub    = sub_handle_map.get(child)
                            .cloned().unwrap_or_else(|| format!("{}_sub_handle", sanitize_name(child)));

                        writeln!(file, "    // Revoke memory {child} from {parent}")?;
                        writeln!(file, "    let _ = Capability::revoke(&{owner_arc}, {parent_handle}, {child_sub}).unwrap();")?;
                    }
                    writeln!(file)?;
                }

                Command::Attest { domain } => {
                    let domain_arc = arc_map.get(domain)
                        .cloned().unwrap_or_else(|| sanitize_name(domain));

                    writeln!(file, "    // Attest domain: {domain}")?;
                    writeln!(file, "    let _attestation = attest_domain(&{domain_arc});")?;
                    writeln!(file, "    // Verify attestation if needed")?;
                    writeln!(file)?;
                }

                Command::View { domain } => {
                    let domain_arc = arc_map.get(domain)
                        .cloned().unwrap_or_else(|| sanitize_name(domain));

                    writeln!(file, "    // View address space: {domain}")?;
                    writeln!(file, "    let _view = compute_address_space(&{domain_arc});")?;
                    writeln!(file, "    // Add assertions on view if needed")?;
                    writeln!(file)?;
                }

                Command::Switch { core, from, to } => {
                    let from_arc = arc_map.get(from)
                        .cloned().unwrap_or_else(|| sanitize_name(from));
                    let to_arc   = arc_map.get(to)
                        .cloned().unwrap_or_else(|| sanitize_name(to));

                    writeln!(file, "    // Switch on core {core} from {from} to {to}")?;
                    writeln!(file, "    let switch_mgr = SwitchManager::new(4);")?;
                    writeln!(file, "    {{")?;
                    writeln!(file, "        let core_ref = switch_mgr.get_core({core}).unwrap();")?;
                    writeln!(file, "        *core_ref.state.write() = CoreState::Running({from_arc}.read().data.id);")?;
                    writeln!(file, "    }}")?;
                    writeln!(file, "    let _ctx = switch_mgr.switch({core}, &{from_arc}, Some(&{to_arc})).unwrap();")?;
                    writeln!(file)?;
                }

                Command::Interrupt { vector, domain, core } => {
                    let domain_arc = arc_map.get(domain)
                        .cloned().unwrap_or_else(|| sanitize_name(domain));

                    writeln!(file, "    // Route interrupt {vector} on {domain} (core {core})")?;
                    writeln!(file, "    let switch_mgr = SwitchManager::new(4);")?;
                    writeln!(file, "    let (handler_id, reported_to) = switch_mgr.route_interrupt({vector}, &{domain_arc}, {core}).unwrap();")?;
                    writeln!(file, "    // Add assertions on handler_id and reported_to if needed")?;
                    writeln!(file)?;
                }

                Command::EnumeratePending { domain } => {
                    let domain_arc = arc_map.get(domain)
                        .cloned().unwrap_or_else(|| sanitize_name(domain));

                    writeln!(file, "    // Enumerate pending capabilities for {domain}")?;
                    writeln!(file, "    let _pending_ids = {domain_arc}.read().data.get_pending_ids();")?;
                    writeln!(file, "    // Add assertions on _pending_ids if needed")?;
                    writeln!(file)?;
                }

                Command::AcceptCapability { domain, pending_id } => {
                    let domain_arc = arc_map.get(domain)
                        .cloned().unwrap_or_else(|| sanitize_name(domain));

                    writeln!(file, "    // Accept pending capability {pending_id} for {domain}")?;
                    writeln!(file, "    let (_handle, _updates) = Capability::accept(&{domain_arc}, {pending_id}).unwrap();")?;
                    writeln!(file)?;
                }

                Command::RejectCapability { domain, pending_id } => {
                    let domain_arc = arc_map.get(domain)
                        .cloned().unwrap_or_else(|| sanitize_name(domain));

                    writeln!(file, "    // Reject pending capability {pending_id} for {domain}")?;
                    writeln!(file, "    Capability::reject(&{domain_arc}, {pending_id}).unwrap();")?;
                    writeln!(file)?;
                }

                Command::GetChan { caller, target, chan_name } => {
                    let caller_arc  = arc_map.get(caller)
                        .cloned().unwrap_or_else(|| sanitize_name(caller));
                    let target_handle = handle_map.get(target)
                        .cloned().unwrap_or_else(|| format!("{}_handle", sanitize_name(target)));
                    let chan_var     = format!("{}_cap", sanitize_name(chan_name));
                    let chan_handle_var = format!("{}_handle", sanitize_name(chan_name));

                    writeln!(file, "    // get-chan: create channel from {caller} to {target} as {chan_name}")?;
                    writeln!(file, "    let {chan_handle_var} = Capability::get_chan(&{caller_arc}, {target_handle}).unwrap();")?;
                    writeln!(file, "    let {chan_var} = {caller_arc}.read().data")?;
                    writeln!(file, "        .domain_capabilities[&{chan_handle_var}].upgrade().unwrap();")?;
                    writeln!(file)?;

                    arc_map.insert(chan_name.clone(), chan_var);
                    handle_map.insert(chan_name.clone(), chan_handle_var);
                    owner_map.insert(chan_name.clone(), caller.clone());
                    is_domain.insert(chan_name.clone());
                }

                Command::SendChannel { caller, chan_name, receiver } => {
                    let caller_arc  = arc_map.get(caller)
                        .cloned().unwrap_or_else(|| sanitize_name(caller));
                    let chan_handle  = handle_map.get(chan_name)
                        .cloned().unwrap_or_else(|| format!("{}_handle", sanitize_name(chan_name)));
                    let recv_arc    = arc_map.get(receiver)
                        .cloned().unwrap_or_else(|| sanitize_name(receiver));
                    let recv_handle_var = format!("{}_recv_dom_h", sanitize_name(receiver));

                    writeln!(file, "    // send-channel: transfer {chan_name} from {caller} to {receiver}")?;
                    writeln!(file, "    let {recv_handle_var} = {caller_arc}.read().data")?;
                    writeln!(file, "        .domain_capabilities.iter().find(|(_, w)| w.upgrade().map_or(false, |a| std::sync::Arc::ptr_eq(&a, &{recv_arc}))).map(|(h, _)| *h)")?;
                    writeln!(file, "        .expect(\"receiver handle not found in caller's table\");")?;
                    writeln!(file, "    Capability::<Domain>::send_channel(&{caller_arc}, {chan_handle}, {recv_handle_var}, Attributes::NONE).unwrap();")?;
                    writeln!(file)?;

                    owner_map.insert(chan_name.clone(), receiver.clone());
                    handle_map.remove(chan_name);
                }

                Command::AcceptChannel { receiver, pending_id, chan_name } => {
                    let recv_arc    = arc_map.get(receiver)
                        .cloned().unwrap_or_else(|| sanitize_name(receiver));
                    let chan_var     = format!("{}_cap", sanitize_name(chan_name));
                    let chan_handle_var = format!("{}_handle", sanitize_name(chan_name));

                    writeln!(file, "    // accept-channel: {receiver} accepts pending channel {pending_id} as {chan_name}")?;
                    writeln!(file, "    let {chan_handle_var} = Capability::<Domain>::accept_channel(&{recv_arc}, {pending_id}).unwrap();")?;
                    writeln!(file, "    let {chan_var} = {recv_arc}.read().data")?;
                    writeln!(file, "        .domain_capabilities[&{chan_handle_var}].upgrade().unwrap();")?;
                    writeln!(file)?;

                    arc_map.insert(chan_name.clone(), chan_var);
                    handle_map.insert(chan_name.clone(), chan_handle_var);
                    owner_map.insert(chan_name.clone(), receiver.clone());
                    is_domain.insert(chan_name.clone());
                }

                Command::RejectChannel { receiver, pending_id } => {
                    let recv_arc = arc_map.get(receiver)
                        .cloned().unwrap_or_else(|| sanitize_name(receiver));

                    writeln!(file, "    // reject-channel: {receiver} rejects pending channel {pending_id}")?;
                    writeln!(file, "    Capability::<Domain>::reject_channel(&{recv_arc}, {pending_id}).unwrap();")?;
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

/// Convert a comma-separated API flag string (e.g. "GET,ATTEST,SWITCH") to a
/// `MonitorAPI::from_bits(…)` expression suitable for use in generated test code.
fn parse_api_bits(api: &str) -> String {
    let mut bits: u16 = 0;
    for part in api.split(',') {
        bits |= match part.trim().to_uppercase().as_str() {
            "CREATE"            => 1 << 0,
            "SET"               => 1 << 1,
            "GET"               => 1 << 2,
            "SEND"              => 1 << 3,
            "SEAL"              => 1 << 4,
            "ATTEST"            => 1 << 5,
            "ENUMERATE"         => 1 << 6,
            "SWITCH"            => 1 << 7,
            "ALIAS"             => 1 << 8,
            "CARVE"             => 1 << 9,
            "REVOKE"            => 1 << 10,
            "GETCHAN"           => 1 << 11,
            "RECEIVE_AFTER_SEAL"=> 1 << 12,
            "ALL"               => 0x1FFF,
            _                   => 0,
        };
    }
    format!("MonitorAPI::from_bits(0x{bits:x})")
}
