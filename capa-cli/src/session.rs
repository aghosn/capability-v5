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
        gpa_hint: Option<u64>,
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
        vp_id: Option<u64>,
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
        gpa_hint: Option<u64>,
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
    GetChanSelf {
        domain: String,
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
    RegisterComm {
        mem: String,
        child_domain: String,
        vp_id: u32,
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
                Command::Send { mem, domain, attrs, gpa_hint } => {
                    let mut line = format!("send {} {}", mem, domain);
                    if attrs != "NONE" {
                        line.push_str(&format!(" {}", attrs));
                    }
                    if let Some(gpa) = gpa_hint {
                        line.push_str(&format!(" at 0x{:x}", gpa));
                    }
                    line
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
                Command::Switch { core, from: _, to, vp_id } => {
                    match vp_id {
                        Some(vp) => format!("switch {} {} {}", to, core, vp),
                        None => format!("switch {}", core),
                    }
                }
                Command::Interrupt { vector, domain, core } => {
                    format!("interrupt {} {} {}", vector, domain, core)
                }
                Command::EnumeratePending { domain } => {
                    format!("enumerate-pending {}", domain)
                }
                Command::AcceptCapability { domain, pending_id, gpa_hint } => {
                    match gpa_hint {
                        Some(gpa) => format!("accept-capability {} {} at 0x{:x}", domain, pending_id, gpa),
                        None => format!("accept-capability {} {}", domain, pending_id),
                    }
                }
                Command::RejectCapability { domain, pending_id } => {
                    format!("reject-capability {} {}", domain, pending_id)
                }
                Command::GetChan { caller: _, target, chan_name } => {
                    format!("get-chan {} {}", target, chan_name)
                }
                Command::GetChanSelf { domain, chan_name } => {
                    format!("get-chan-self {} {}", domain, chan_name)
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
                Command::RegisterComm { mem, child_domain, vp_id } => {
                    format!("register-comm {} {} {}", mem, child_domain, vp_id)
                }
            };
            writeln!(file, "{}", line)?;
        }

        Ok(())
    }

    /// Save the session as a Rust unit test
    ///
    /// The generated file must be placed one directory level under
    /// `capa-engine/tests/` (e.g. `capa-engine/tests/unit/<name>.rs`) so that
    /// its `#[path = "../common/mod.rs"] mod common;` resolves, and needs a
    /// matching `[[test]]` entry added to `capa-engine/Cargo.toml` to be run
    /// by `cargo test` (mirroring every other file under `tests/unit/`).
    pub fn save_as_test(&self, filename: &str) -> std::io::Result<()> {
        let mut file = File::create(filename)?;

        // Write test header
        writeln!(file, "//! Test generated from CLI session\n")?;
        writeln!(file, "//! NOTE: place this file at capa-engine/tests/unit/<name>.rs")?;
        writeln!(file, "//! and add a matching [[test]] entry to capa-engine/Cargo.toml.\n")?;
        writeln!(file, "use capability_engine::*;")?;
        writeln!(file, "use std::sync::Arc;\n")?;
        writeln!(file, "#[path = \"../common/mod.rs\"]")?;
        writeln!(file, "mod common;\n")?;
        writeln!(file, "#[test]")?;
        writeln!(file, "fn test_session() {{")?;
        writeln!(file, "    let platform = common::TestPlatform::new();")?;
        writeln!(file)?;

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
                    // `cmd_init` (commands/domain.rs) always tracks the root memory
                    // region under the literal name "r0" regardless of the domain's
                    // name, so tutorial scripts always refer to it as "r0" (e.g.
                    // `carve r0 ...`). Mirror that literal key here, or later
                    // Carve/Send/Revoke lookups on "r0" will silently miss.
                    let mem_name   = "r0".to_string();

                    writeln!(file, "    // Initialize root domain and memory")?;
                    writeln!(file, "    let root_domain_data = Domain::new_root(4);")?;
                    writeln!(file, "    let {domain_var} = Capability::new_root(0, 0, root_domain_data);")?;
                    writeln!(file, "    let root_region = MemoryRegion::new_root(0x0, 0x{size:x});")?;
                    writeln!(file, "    let {mem_var} = Capability::new_root(0, 1, root_region);")?;
                    writeln!(file, "    {domain_var}.write().data.add_memory_capability(1, Arc::downgrade(&{mem_var}));")?;
                    writeln!(file, "    let r0_handle: LocalHandle = 1;")?;
                    writeln!(file, "    platform.register_domain({domain_var}.read().data.id, None);")?;
                    writeln!(file, "    for core in 0..4u64 {{")?;
                    writeln!(file, "        platform.set_core_context(core, &{domain_var}, core);")?;
                    writeln!(file, "        let vp = {domain_var}.read().data.policy.vprocessor_states[core as usize].clone();")?;
                    writeln!(file, "        *vp.run_state.write() = VpRunState::Running {{ core }};")?;
                    writeln!(file, "    }}")?;
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
                    writeln!(file, "    let {name}_api = {api_bits};",
                        api_bits = parse_api_bits(api))?;
                    writeln!(file, "    let {name}_policy = DomainPolicy::new_restricted(0x{cores:x}, {name}_api);")?;
                    writeln!(file, "    let {handle_var} = Capability::create(&platform, &{parent_arc}, {name}_policy).unwrap().0;")?;
                    writeln!(file, "    let {child_var} = {parent_arc}.read().data")?;
                    writeln!(file, "        .domain_capabilities[&{handle_var}].upgrade().unwrap();")?;
                    writeln!(file, "    platform.register_domain({child_var}.read().data.id, Some({parent_arc}.read().data.id));")?;
                    writeln!(file, "    let {name}_num_vps = {child_var}.read().data.policy.num_vprocessors;")?;
                    writeln!(file, "    for _ in 0..{name}_num_vps {{")?;
                    writeln!(file, "        {child_var}.write().data.add_vprocessor().unwrap();")?;
                    writeln!(file, "    }}")?;
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
                    writeln!(file, "    Capability::seal(&platform, &{owner_arc}, {handle_var}).unwrap();")?;
                    writeln!(file)?;
                }

                Command::Carve { parent, name, start, size, rights } => {
                    let parent_owner = owner_map.get(parent)
                        .cloned().unwrap_or_default();
                    let owner_arc    = arc_map.get(&parent_owner)
                        .cloned().unwrap_or_else(|| sanitize_name(&parent_owner));
                    let parent_arc   = arc_map.get(parent)
                        .cloned().unwrap_or_else(|| sanitize_name(parent));
                    let child_var   = format!("{}_cap", sanitize_name(name));
                    let handle_var  = format!("{}_handle", sanitize_name(name));
                    let sub_var     = format!("{}_sub_handle", sanitize_name(name));

                    writeln!(file, "    // Carve memory region: {name}")?;
                    let parent_handle = resolve_mem_handle(&mut file, &handle_map, parent, &parent_arc, &owner_arc)?;
                    writeln!(file, "    let {name}_access = Access::new(0x{start:x}, 0x{size:x}, {rights_expr});", rights_expr = parse_rights_expr(rights))?;
                    writeln!(file, "    let ({handle_var}, {sub_var}, _) = Capability::carve(&platform, &{owner_arc}, {parent_handle}, {name}_access).unwrap();")?;
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
                    let parent_arc   = arc_map.get(parent)
                        .cloned().unwrap_or_else(|| sanitize_name(parent));
                    let child_var   = format!("{}_cap", sanitize_name(name));
                    let handle_var  = format!("{}_handle", sanitize_name(name));
                    let sub_var     = format!("{}_sub_handle", sanitize_name(name));

                    writeln!(file, "    // Alias memory region: {name}")?;
                    let parent_handle = resolve_mem_handle(&mut file, &handle_map, parent, &parent_arc, &owner_arc)?;
                    writeln!(file, "    let {name}_access = Access::new(0x{start:x}, 0x{size:x}, {rights_expr});", rights_expr = parse_rights_expr(rights))?;
                    writeln!(file, "    let ({handle_var}, {sub_var}, _) = Capability::alias(&platform, &{owner_arc}, {parent_handle}, {name}_access).unwrap();")?;
                    writeln!(file, "    let {child_var} = {owner_arc}.read().data")?;
                    writeln!(file, "        .memory_capabilities[&{handle_var}].upgrade().unwrap();")?;
                    writeln!(file)?;

                    arc_map.insert(name.clone(), child_var);
                    handle_map.insert(name.clone(), handle_var);
                    sub_handle_map.insert(name.clone(), sub_var);
                    owner_map.insert(name.clone(), parent_owner);
                }

                Command::Send { mem, domain, attrs, gpa_hint } => {
                    let mem_owner   = owner_map.get(mem)
                        .cloned().unwrap_or_default();
                    let sender_arc  = arc_map.get(&mem_owner)
                        .cloned().unwrap_or_else(|| sanitize_name(&mem_owner));
                    let mem_arc     = arc_map.get(mem)
                        .cloned().unwrap_or_else(|| sanitize_name(mem));
                    let recv_arc    = arc_map.get(domain)
                        .cloned().unwrap_or_else(|| sanitize_name(domain));
                    let recv_domain_handle_var = format!("{}_recv_dom_h", sanitize_name(domain));

                    writeln!(file, "    // Send {mem} to {domain}")?;
                    let mem_handle = resolve_mem_handle(&mut file, &handle_map, mem, &mem_arc, &sender_arc)?;
                    writeln!(file, "    let {recv_domain_handle_var} = {sender_arc}.read().data")?;
                    writeln!(file, "        .domain_capabilities.iter().find(|(_, w)| w.upgrade().map_or(false, |a| std::sync::Arc::ptr_eq(&a, &{recv_arc}))).map(|(h, _)| *h)")?;
                    writeln!(file, "        .unwrap_or_else(|| {{")?;
                    writeln!(file, "            let h = {sender_arc}.read().data.allocate_domain_handle();")?;
                    writeln!(file, "            {sender_arc}.write().data.add_domain_capability(h, std::sync::Arc::downgrade(&{recv_arc}));")?;
                    writeln!(file, "            h")?;
                    writeln!(file, "        }});")?;
                    let gpa_arg = match gpa_hint {
                        Some(gpa) => format!("Some(0x{:x})", gpa),
                        None => "None".to_string(),
                    };
                    writeln!(file, "    let _ = Capability::send_at(&platform, &{sender_arc}, {mem_handle}, {recv_domain_handle_var}, {attrs_expr}, {gpa_arg}).unwrap();", attrs_expr = parse_attrs_expr(attrs))?;
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
                        writeln!(file, "    let _ = Capability::revoke_domain(&platform, &{parent_arc}, {child_handle}).unwrap();")?;
                    } else {
                        // Memory revoke
                        let owner_name   = owner_map.get(parent)
                            .cloned().unwrap_or_default();
                        let owner_arc    = arc_map.get(&owner_name)
                            .cloned().unwrap_or_else(|| sanitize_name(&owner_name));
                        let parent_arc   = arc_map.get(parent)
                            .cloned().unwrap_or_else(|| sanitize_name(parent));
                        let child_sub    = sub_handle_map.get(child)
                            .cloned().unwrap_or_else(|| format!("{}_sub_handle", sanitize_name(child)));

                        writeln!(file, "    // Revoke memory {child} from {parent}")?;
                        let parent_handle = resolve_mem_handle(&mut file, &handle_map, parent, &parent_arc, &owner_arc)?;
                        writeln!(file, "    let _ = Capability::revoke(&platform, &{owner_arc}, {parent_handle}, {child_sub}).unwrap();")?;
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

                Command::Switch { core, from, to, vp_id } => {
                    let from_arc = arc_map.get(from)
                        .cloned().unwrap_or_else(|| sanitize_name(from));

                    writeln!(file, "    // Switch on core {core} from {from} to {to}")?;
                    writeln!(file, "    platform.set_current_core(Some({core}));")?;
                    match vp_id {
                        Some(vp) => {
                            let to_arc = arc_map.get(to)
                                .cloned().unwrap_or_else(|| sanitize_name(to));
                            let to_handle_var = format!("{}_handle_in_{}", sanitize_name(to), sanitize_name(from));

                            writeln!(file, "    let {to_handle_var} = {from_arc}.read().data")?;
                            writeln!(file, "        .domain_capabilities.iter().find(|(_, w)| w.upgrade().map_or(false, |a| std::sync::Arc::ptr_eq(&a, &{to_arc}))).map(|(h, _)| *h)")?;
                            writeln!(file, "        .expect(\"to-domain handle not found in from-domain's table\");")?;
                            writeln!(file, "    let _ctx = Capability::<Domain>::switch(&platform, &{from_arc}, {to_handle_var}, {vp}).unwrap().0;")?;
                        }
                        None => {
                            writeln!(file, "    let _ctx = Capability::<Domain>::switch(&platform, &{from_arc}, 0, 0).unwrap().0;")?;
                        }
                    }
                    writeln!(file, "    platform.set_current_core(None);")?;
                    writeln!(file)?;
                }

                Command::Interrupt { vector, domain, core } => {
                    let domain_arc = arc_map.get(domain)
                        .cloned().unwrap_or_else(|| sanitize_name(domain));

                    writeln!(file, "    // Route interrupt {vector} on {domain} (core {core})")?;
                    writeln!(file, "    let (_vp_delivery, _batch) = Capability::<Domain>::deliver_interrupt_vp(&platform, &{domain_arc}, {core}, {vector} as u8).unwrap();")?;
                    writeln!(file, "    // Add assertions on _vp_delivery if needed")?;
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

                Command::AcceptCapability { domain, pending_id, gpa_hint } => {
                    let domain_arc = arc_map.get(domain)
                        .cloned().unwrap_or_else(|| sanitize_name(domain));
                    let gpa_arg = match gpa_hint {
                        Some(gpa) => format!("Some(0x{:x})", gpa),
                        None => "None".to_string(),
                    };

                    writeln!(file, "    // Accept pending capability {pending_id} for {domain}")?;
                    writeln!(file, "    let (_handle, _updates) = Capability::accept_at(&platform, &{domain_arc}, {pending_id}, {gpa_arg}).unwrap();")?;
                    writeln!(file)?;
                }

                Command::RejectCapability { domain, pending_id } => {
                    let domain_arc = arc_map.get(domain)
                        .cloned().unwrap_or_else(|| sanitize_name(domain));

                    writeln!(file, "    // Reject pending capability {pending_id} for {domain}")?;
                    writeln!(file, "    Capability::reject(&platform, &{domain_arc}, {pending_id}).unwrap();")?;
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
                    writeln!(file, "    let {chan_handle_var} = Capability::get_chan(&platform, &{caller_arc}, {target_handle}).unwrap().0;")?;
                    writeln!(file, "    let {chan_var} = {caller_arc}.read().data")?;
                    writeln!(file, "        .domain_capabilities[&{chan_handle_var}].upgrade().unwrap();")?;
                    writeln!(file)?;

                    arc_map.insert(chan_name.clone(), chan_var);
                    handle_map.insert(chan_name.clone(), chan_handle_var);
                    owner_map.insert(chan_name.clone(), caller.clone());
                    is_domain.insert(chan_name.clone());
                }

                Command::GetChanSelf { domain, chan_name } => {
                    let domain_arc = arc_map.get(domain)
                        .cloned().unwrap_or_else(|| sanitize_name(domain));
                    let chan_var = format!("{}_cap", sanitize_name(chan_name));
                    let chan_handle_var = format!("{}_handle", sanitize_name(chan_name));

                    writeln!(file, "    // get-chan-self: create self-channel for {domain} as {chan_name}")?;
                    writeln!(file, "    let {chan_handle_var} = Capability::get_chan_self(&platform, &{domain_arc}).unwrap().0;")?;
                    writeln!(file, "    let {chan_var} = {domain_arc}.read().data")?;
                    writeln!(file, "        .domain_capabilities[&{chan_handle_var}].upgrade().unwrap();")?;
                    writeln!(file)?;

                    arc_map.insert(chan_name.clone(), chan_var);
                    handle_map.insert(chan_name.clone(), chan_handle_var);
                    owner_map.insert(chan_name.clone(), domain.clone());
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
                    writeln!(file, "    Capability::<Domain>::send_channel(&platform, &{caller_arc}, {chan_handle}, {recv_handle_var}, Attributes::NONE).unwrap();")?;
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
                    writeln!(file, "    let {chan_handle_var} = Capability::<Domain>::accept_channel(&platform, &{recv_arc}, {pending_id}).unwrap().0;")?;
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
                    writeln!(file, "    Capability::<Domain>::reject_channel(&platform, &{recv_arc}, {pending_id}).unwrap();")?;
                    writeln!(file)?;
                }

                Command::RegisterComm { mem, child_domain, vp_id } => {
                    let mem_owner = owner_map.get(mem)
                        .cloned().unwrap_or_default();
                    let owner_arc = arc_map.get(&mem_owner)
                        .cloned().unwrap_or_else(|| sanitize_name(&mem_owner));
                    let mem_arc = arc_map.get(mem)
                        .cloned().unwrap_or_else(|| sanitize_name(mem));
                    let child_arc = arc_map.get(child_domain)
                        .cloned().unwrap_or_else(|| sanitize_name(child_domain));
                    let mem_handle_var   = format!("{}_handle_in_owner", sanitize_name(mem));
                    let child_handle_var = format!("{}_handle_in_owner", sanitize_name(child_domain));

                    writeln!(file, "    // register-comm: register '{mem}' as COMM page for '{child_domain}' VP {vp_id}")?;
                    writeln!(file, "    let {mem_handle_var} = {owner_arc}.read().data")?;
                    writeln!(file, "        .memory_capabilities.iter().find(|(_, w)| w.upgrade().map_or(false, |a| std::sync::Arc::ptr_eq(&a, &{mem_arc}))).map(|(h, _)| *h)")?;
                    writeln!(file, "        .expect(\"mem handle not found in owner's table\");")?;
                    writeln!(file, "    let {child_handle_var} = {owner_arc}.read().data")?;
                    writeln!(file, "        .domain_capabilities.iter().find(|(_, w)| w.upgrade().map_or(false, |a| std::sync::Arc::ptr_eq(&a, &{child_arc}))).map(|(h, _)| *h)")?;
                    writeln!(file, "        .expect(\"child handle not found in owner's table\");")?;
                    writeln!(file, "    Capability::<Domain>::register_comm(&platform, &{owner_arc}, {mem_handle_var}, {child_handle_var}, {vp_id}).unwrap();")?;
                    writeln!(file)?;
                }
            }
        }

        writeln!(file, "    // Test completed successfully")?;
        writeln!(file, "}}")?;

        Ok(())
    }
}

/// Resolve the current `LocalHandle` for a memory region's capability inside
/// its (possibly new) owner's table. If `handle_map` still has a fresh entry
/// for it (region hasn't changed hands since last tracked), reuse that
/// directly. Otherwise — e.g. the region was `Send`-ed to a new owner since
/// being tracked, which clears its now-stale handle — emit an inline
/// pointer-identity lookup against the owner's table and return a fresh local
/// variable bound to the freshly resolved handle.
fn resolve_mem_handle(
    file: &mut File,
    handle_map: &std::collections::HashMap<String, String>,
    mem_name: &str,
    mem_arc: &str,
    owner_arc: &str,
) -> std::io::Result<String> {
    if let Some(h) = handle_map.get(mem_name) {
        return Ok(h.clone());
    }
    let lookup_var = format!("{}_handle_in_owner", sanitize_name(mem_name));
    writeln!(file, "    let {lookup_var} = {owner_arc}.read().data")?;
    writeln!(file, "        .memory_capabilities.iter().find(|(_, w)| w.upgrade().map_or(false, |a| std::sync::Arc::ptr_eq(&a, &{mem_arc}))).map(|(h, _)| *h)")?;
    writeln!(file, "        .expect(\"mem handle not found in owner's table\");")?;
    Ok(lookup_var)
}

/// Sanitize a name to be a valid Rust identifier
fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' })
        .collect()
}

/// Convert a rights character string (e.g. "RWX", "RW", "-") to a
/// `Rights::from_bits(…)` expression suitable for use in generated test code.
/// Mirrors `parser::parse_rights`'s character-based bit computation.
fn parse_rights_expr(rights: &str) -> String {
    let mut bits: u8 = 0;
    for c in rights.chars() {
        bits |= match c {
            'R' | 'r' => 1 << 0,
            'W' | 'w' => 1 << 1,
            'X' | 'x' => 1 << 2,
            _ => 0,
        };
    }
    format!("Rights::from_bits(0x{bits:x})")
}

/// Convert a comma/pipe-separated attributes string (e.g. "CLEAN,VITAL" or
/// "NONE") to an `Attributes::from_bits(…)` expression suitable for use in
/// generated test code. Mirrors `parser::parse_attributes`'s flag computation.
fn parse_attrs_expr(attrs: &str) -> String {
    let mut bits: u8 = 0;
    for part in attrs.split(&[',', '|'][..]) {
        bits |= match part.trim().to_uppercase().as_str() {
            "HASH"  => 1 << 0,
            "CLEAN" => 1 << 1,
            "VITAL" => 1 << 2,
            "META"  => 1 << 3,
            "COMM"  => 1 << 4,
            _       => 0,
        };
    }
    format!("Attributes::from_bits(0x{bits:x})")
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
