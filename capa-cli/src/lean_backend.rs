//! LeanBackend — implements Backend by calling the Lean executable model via C FFI.
//!
//! Gated behind the `lean-backend` cargo feature.
//! The Lean state is global (single-threaded); only one LeanBackend instance may exist.
//!
//! The Lean engine uses `CapNodeId` as its internal flat-store key (replacing Arc
//! pointers). This is NOT the same as the CLI-facing `MemCapUid`. This module
//! maintains the `CapNodeId ↔ MemCapUid` mapping, mirroring how `rust_backend.rs`
//! manages `Arc ↔ MemCapUid`.

use crate::backend::*;
use std::collections::HashMap;
use std::ffi::CStr;

// ─── C FFI declarations (from lean_ffi/lean_wrapper.c) ───

unsafe extern "C" {
    fn lean_ffi_initialize() -> i32;

    // Lifecycle
    fn lean_ffi_init(mem_size: u64, num_cores: u64) -> u32;
    fn lean_ffi_reset(num_cores: u64) -> u32;

    // Memory
    fn lean_ffi_carve(owner: u64, parent: u64, start: u64, size: u64, rights: u64) -> u32;
    fn lean_ffi_alias(owner: u64, parent: u64, start: u64, size: u64, rights: u64) -> u32;
    fn lean_ffi_send(mem: u64, receiver: u64, attrs: u64, gpa: u64, has_gpa: u64) -> u32;
    fn lean_ffi_accept(dom: u64, pending: u64, gpa: u64, has_gpa: u64) -> u32;
    fn lean_ffi_reject(dom: u64, pending: u64) -> u32;
    fn lean_ffi_revoke_mem(owner: u64, parent: u64, child: u64) -> u32;

    // Domain
    fn lean_ffi_create_domain(parent: u64, cores: u64, api: u64) -> u32;
    fn lean_ffi_seal(owner: u64, child: u64) -> u32;
    fn lean_ffi_revoke_domain(parent: u64, child: u64) -> u32;

    // Channel
    fn lean_ffi_get_chan(caller: u64, target: u64) -> u32;
    fn lean_ffi_get_chan_self(caller: u64) -> u32;
    fn lean_ffi_send_channel(caller: u64, chan: u64, receiver: u64) -> u32;
    fn lean_ffi_accept_channel(receiver: u64, pending: u64) -> u32;
    fn lean_ffi_reject_channel(receiver: u64, pending: u64) -> u32;

    // VP & Switch
    fn lean_ffi_add_vp(parent: u64, child: u64, comm: u64, vp: u64) -> u32;
    fn lean_ffi_register_comm(owner: u64, comm: u64, child: u64, vp: u64) -> u32;
    fn lean_ffi_switch_forward(target: u64, core: u64, vp: u64) -> u32;
    fn lean_ffi_switch_return(core: u64) -> u32;
    fn lean_ffi_deliver_interrupt(vector: u64, domain: u64, core: u64) -> u32;

    // Policy & Registers
    fn lean_ffi_set_policy(parent: u64, child: u64, field: u64, value: u64) -> u32;
    fn lean_ffi_get_policy(parent: u64, child: u64, field: u64) -> u32;
    fn lean_ffi_set_register(parent: u64, child: u64, vp: u64, reg: u64, value: u64) -> u32;
    fn lean_ffi_get_register(parent: u64, child: u64, vp: u64, reg: u64) -> u32;
    fn lean_ffi_set_interrupt_policy(owner: u64, child: u64, vector: u64, vis: u64) -> u32;

    // Result getters
    fn lean_ffi_get_result1() -> u64;
    fn lean_ffi_get_result2() -> u64;
    fn lean_ffi_get_result_str() -> *const std::os::raw::c_char;
    fn lean_ffi_get_error_msg() -> *const std::os::raw::c_char;

    // Update buffer
    fn lean_ffi_update_count() -> u64;
    fn lean_ffi_update_field(idx: u64, field: u64) -> u64;

    // Queries
    fn lean_ffi_list_domains() -> u32;
    fn lean_ffi_get_domain_mem_caps(dom: u64) -> u32;
    fn lean_ffi_get_domain_dom_caps(dom: u64) -> u32;
    fn lean_ffi_get_pending_caps(dom: u64) -> u32;
    fn lean_ffi_get_address_space(dom: u64) -> u32;
    fn lean_ffi_get_core_states() -> u32;
    fn lean_ffi_attest(dom: u64) -> u32;
    fn lean_ffi_num_cores() -> u64;
}

// ─── Helpers ───

/// Convert Lean error code to BackendError.
fn code_to_error(code: u32) -> BackendError {
    let msg = unsafe {
        let ptr = lean_ffi_get_error_msg();
        if ptr.is_null() {
            String::new()
        } else {
            CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    };

    match code {
        1 => BackendError::DomainRevoked,
        2 => BackendError::InvalidAccess,
        3 => BackendError::PermissionDenied,
        4 => BackendError::NotFound,
        5 => BackendError::DomainSealed,
        6 => BackendError::DomainNotSealed,
        7 => BackendError::ParentRevoked,
        8 => BackendError::RegionOverlap,
        9 => BackendError::MonotonicityViolation,
        10 => BackendError::ApiNotAllowed,
        11 => BackendError::InvalidOperation(msg),
        _ => BackendError::InvalidOperation(format!("unknown error code {}: {}", code, msg)),
    }
}

/// Check FFI result: 0 = success, otherwise error.
fn check(code: u32) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(code_to_error(code))
    }
}

fn get_result1() -> u64 {
    unsafe { lean_ffi_get_result1() }
}

fn get_result2() -> u64 {
    unsafe { lean_ffi_get_result2() }
}

fn get_result_str() -> String {
    unsafe {
        let ptr = lean_ffi_get_result_str();
        if ptr.is_null() {
            String::new()
        } else {
            CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    }
}

/// Read the HwUpdate buffer into a Vec<HwUpdate>.
fn read_updates() -> Vec<HwUpdate> {
    let count = unsafe { lean_ffi_update_count() };
    let mut updates = Vec::with_capacity(count as usize);
    for i in 0..count {
        let kind_code = unsafe { lean_ffi_update_field(i, 0) };
        let domain_id = unsafe { lean_ffi_update_field(i, 1) };
        let gpa = unsafe { lean_ffi_update_field(i, 2) };
        let hpa = unsafe { lean_ffi_update_field(i, 3) };
        let size = unsafe { lean_ffi_update_field(i, 4) };
        let rights_bits = unsafe { lean_ffi_update_field(i, 5) };

        let kind = match kind_code {
            0 => HwUpdateKind::MapMemory,
            1 => HwUpdateKind::UnmapMemory,
            2 => HwUpdateKind::ZeroMemory,
            3 => HwUpdateKind::CreateDomain,
            4 => HwUpdateKind::RevokeDomain,
            5 => HwUpdateKind::CommRegion,
            6 => HwUpdateKind::UncommRegion,
            _ => HwUpdateKind::MapMemory,
        };

        let rights = if rights_bits != 0 {
            let mut r = String::new();
            if rights_bits & 1 != 0 {
                r.push('R');
            }
            if rights_bits & 2 != 0 {
                r.push('W');
            }
            if rights_bits & 4 != 0 {
                r.push('X');
            }
            Some(r)
        } else {
            None
        };

        updates.push(HwUpdate {
            kind,
            domain_id,
            gpa,
            size,
            hpa,
            rights,
        });
    }
    updates
}

/// Map policy field name to Lean field code.
fn policy_field_code(field: &str) -> u64 {
    match field {
        "cores" => 0,
        "api-monitor" => 1,
        "default-visibility" => 2,
        "num-vps" => 3,
        "cpuid-default" => 4,
        "msr-default" => 5,
        _ => 0xFF,
    }
}

// ─── JSON parsing helpers ───

use serde_json::Value;

fn parse_json_array(json: &str) -> Vec<Value> {
    serde_json::from_str::<Vec<Value>>(json).unwrap_or_default()
}

fn json_u64(v: &Value, key: &str) -> u64 {
    v.get(key).and_then(|v| v.as_u64()).unwrap_or(0)
}

fn json_str(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn json_bool(v: &Value, key: &str) -> bool {
    v.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
}

fn json_opt_u64(v: &Value, key: &str) -> Option<u64> {
    v.get(key).and_then(|v| v.as_u64())
}

fn parse_domain_info(v: &Value) -> DomainInfoDto {
    let vps = v
        .get("vp_states")
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .map(|vp| VpStateDto {
                    vp_id: json_u64(vp, "vp_id"),
                    state: json_str(vp, "state"),
                })
                .collect()
        })
        .unwrap_or_default();

    DomainInfoDto {
        id: json_u64(v, "id"),
        status: json_str(v, "status"),
        is_channel: json_bool(v, "is_channel"),
        channel_target: json_opt_u64(v, "channel_target"),
        cores_bitmap: json_u64(v, "cores_bitmap"),
        api_flags: json_str(v, "api_flags"),
        num_vps: json_u64(v, "num_vps") as usize,
        vp_states: vps,
    }
}

fn parse_mem_cap_info(v: &Value) -> MemCapInfoDto {
    let children = v
        .get("children")
        .and_then(|a| a.as_array())
        .map(|arr| arr.iter().map(parse_mem_cap_info).collect())
        .unwrap_or_default();

    MemCapInfoDto {
        uid: json_u64(v, "uid"),
        local_handle: json_u64(v, "local_handle"),
        start: json_u64(v, "start"),
        end: json_u64(v, "end"),
        rights: json_str(v, "rights"),
        kind: json_str(v, "kind"),
        status: json_str(v, "status"),
        attributes: json_str(v, "attributes"),
        owner_id: json_u64(v, "owner_id"),
        num_children: json_u64(v, "num_children") as usize,
        children,
    }
}

// ─── LeanBackend ───

pub struct LeanBackend {
    num_cores: usize,
    /// CapNodeId (Lean engine internal) → MemCapUid (CLI-facing)
    node_to_uid: HashMap<u64, MemCapUid>,
    /// MemCapUid (CLI-facing) → CapNodeId (Lean engine internal)
    uid_to_node: HashMap<MemCapUid, u64>,
    next_uid: MemCapUid,
}

impl LeanBackend {
    pub fn new(num_cores: usize) -> Self {
        let rc = unsafe { lean_ffi_initialize() };
        if rc != 0 {
            panic!("Failed to initialize Lean runtime");
        }
        LeanBackend {
            num_cores,
            node_to_uid: HashMap::new(),
            uid_to_node: HashMap::new(),
            next_uid: 0,
        }
    }

    /// Register a CapNodeId and return its CLI-facing MemCapUid.
    fn register_node(&mut self, node_id: u64) -> MemCapUid {
        if let Some(&uid) = self.node_to_uid.get(&node_id) {
            return uid;
        }
        let uid = self.next_uid;
        self.next_uid += 1;
        self.node_to_uid.insert(node_id, uid);
        self.uid_to_node.insert(uid, node_id);
        uid
    }

    /// Resolve a CLI-facing MemCapUid to the Lean engine's CapNodeId.
    fn resolve_node(&self, uid: MemCapUid) -> Result<u64> {
        self.uid_to_node.get(&uid).copied().ok_or(BackendError::NotFound)
    }
}

impl Backend for LeanBackend {
    // === Lifecycle ===

    fn init(&mut self, size: u64) -> Result<InitResult> {
        let code = unsafe { lean_ffi_init(size, self.num_cores as u64) };
        check(code)?;
        let domain_id = get_result1();
        let root_node = get_result2();
        let mem_uid = self.register_node(root_node);
        Ok(InitResult { domain_id, mem_uid })
    }

    fn reset(&mut self, num_cores: usize) {
        self.num_cores = num_cores;
        self.node_to_uid.clear();
        self.uid_to_node.clear();
        self.next_uid = 0;
        unsafe {
            lean_ffi_reset(num_cores as u64);
        }
    }

    // === Memory Operations ===

    fn carve(
        &mut self,
        owner: DomainId,
        parent: MemCapUid,
        start: u64,
        size: u64,
        rights: u8,
    ) -> Result<(MemCapUid, Vec<HwUpdate>)> {
        let parent_node = self.resolve_node(parent)?;
        let code = unsafe { lean_ffi_carve(owner, parent_node, start, size, rights as u64) };
        check(code)?;
        let child_node = get_result1();
        let child_uid = self.register_node(child_node);
        Ok((child_uid, read_updates()))
    }

    fn alias(
        &mut self,
        owner: DomainId,
        parent: MemCapUid,
        start: u64,
        size: u64,
        rights: u8,
    ) -> Result<(MemCapUid, Vec<HwUpdate>)> {
        let parent_node = self.resolve_node(parent)?;
        let code = unsafe { lean_ffi_alias(owner, parent_node, start, size, rights as u64) };
        check(code)?;
        let child_node = get_result1();
        let child_uid = self.register_node(child_node);
        Ok((child_uid, read_updates()))
    }

    fn send(
        &mut self,
        mem: MemCapUid,
        receiver: DomainId,
        attrs: u8,
        gpa: Option<u64>,
    ) -> Result<Vec<HwUpdate>> {
        let mem_node = self.resolve_node(mem)?;
        let (gpa_val, has_gpa) = match gpa {
            Some(g) => (g, 1u64),
            None => (0, 0),
        };
        let code = unsafe { lean_ffi_send(mem_node, receiver, attrs as u64, gpa_val, has_gpa) };
        check(code)?;
        Ok(read_updates())
    }

    fn accept(
        &mut self,
        domain: DomainId,
        pending_id: u64,
        gpa: Option<u64>,
    ) -> Result<(MemCapUid, Vec<HwUpdate>)> {
        let (gpa_val, has_gpa) = match gpa {
            Some(g) => (g, 1u64),
            None => (0, 0),
        };
        let code = unsafe { lean_ffi_accept(domain, pending_id, gpa_val, has_gpa) };
        check(code)?;
        let node_id = get_result1();
        let uid = self.register_node(node_id);
        Ok((uid, read_updates()))
    }

    fn reject(&mut self, domain: DomainId, pending_id: u64) -> Result<()> {
        let code = unsafe { lean_ffi_reject(domain, pending_id) };
        check(code)
    }

    fn revoke_mem(
        &mut self,
        owner: DomainId,
        parent: MemCapUid,
        child: MemCapUid,
    ) -> Result<Vec<HwUpdate>> {
        let parent_node = self.resolve_node(parent)?;
        let child_node = self.resolve_node(child)?;
        let code = unsafe { lean_ffi_revoke_mem(owner, parent_node, child_node) };
        check(code)?;
        Ok(read_updates())
    }

    // === Domain Operations ===

    fn create_domain(
        &mut self,
        parent: DomainId,
        cores: u64,
        api: u64,
    ) -> Result<(DomainId, Vec<HwUpdate>)> {
        let code = unsafe { lean_ffi_create_domain(parent, cores, api) };
        check(code)?;
        Ok((get_result1(), read_updates()))
    }

    fn seal(&mut self, owner: DomainId, child: DomainId) -> Result<()> {
        let code = unsafe { lean_ffi_seal(owner, child) };
        check(code)
    }

    fn revoke_domain(
        &mut self,
        parent: DomainId,
        child: DomainId,
    ) -> Result<Vec<HwUpdate>> {
        let code = unsafe { lean_ffi_revoke_domain(parent, child) };
        check(code)?;
        Ok(read_updates())
    }

    // === Channel Operations ===

    fn get_chan(&mut self, caller: DomainId, target: DomainId) -> Result<DomainId> {
        let code = unsafe { lean_ffi_get_chan(caller, target) };
        check(code)?;
        Ok(get_result1())
    }

    fn get_chan_self(&mut self, caller: DomainId) -> Result<DomainId> {
        let code = unsafe { lean_ffi_get_chan_self(caller) };
        check(code)?;
        Ok(get_result1())
    }

    fn send_channel(
        &mut self,
        caller: DomainId,
        chan: DomainId,
        receiver: DomainId,
    ) -> Result<()> {
        let code = unsafe { lean_ffi_send_channel(caller, chan, receiver) };
        check(code)
    }

    fn accept_channel(
        &mut self,
        receiver: DomainId,
        pending_id: u64,
    ) -> Result<DomainId> {
        let code = unsafe { lean_ffi_accept_channel(receiver, pending_id) };
        check(code)?;
        Ok(get_result1())
    }

    fn reject_channel(&mut self, receiver: DomainId, pending_id: u64) -> Result<()> {
        let code = unsafe { lean_ffi_reject_channel(receiver, pending_id) };
        check(code)
    }

    // === VP & Switch ===

    fn add_vp(
        &mut self,
        parent: DomainId,
        child: DomainId,
        comm: MemCapUid,
        vp_id: u32,
    ) -> Result<Vec<HwUpdate>> {
        let comm_node = self.resolve_node(comm)?;
        let code = unsafe { lean_ffi_add_vp(parent, child, comm_node, vp_id as u64) };
        check(code)?;
        Ok(read_updates())
    }

    fn register_comm(
        &mut self,
        owner: DomainId,
        mem: MemCapUid,
        child: DomainId,
        vp_id: u32,
    ) -> Result<Vec<HwUpdate>> {
        let mem_node = self.resolve_node(mem)?;
        let code = unsafe { lean_ffi_register_comm(owner, mem_node, child, vp_id as u64) };
        check(code)?;
        Ok(read_updates())
    }

    fn switch_forward(
        &mut self,
        domain: DomainId,
        core: u64,
        vp_id: u64,
    ) -> Result<SwitchContextDto> {
        let code = unsafe { lean_ffi_switch_forward(domain, core, vp_id) };
        check(code)?;
        let from_domain = get_result1();
        let to_domain = get_result2();
        let result_str = get_result_str();
        // Parse "isReturn|fromVp|toVp|vector" format
        let parts: Vec<&str> = result_str.split('|').collect();
        let is_return = parts.first().map(|s| *s == "true").unwrap_or(false);
        let from_vp = parts
            .get(1)
            .and_then(|s| if s.is_empty() { None } else { s.parse::<u64>().ok() });
        let to_vp = parts
            .get(2)
            .and_then(|s| if s.is_empty() { None } else { s.parse::<u64>().ok() });
        let interrupt_return = parts
            .get(3)
            .and_then(|s| if s.is_empty() { None } else { s.parse::<u8>().ok() });
        Ok(SwitchContextDto {
            from_domain,
            to_domain,
            core_id: core,
            from_vp,
            to_vp,
            is_return,
            interrupt_return,
        })
    }

    fn switch_return(&mut self, core: u64) -> Result<SwitchContextDto> {
        let code = unsafe { lean_ffi_switch_return(core) };
        check(code)?;
        let from_domain = get_result1();
        let to_domain = get_result2();
        let result_str = get_result_str();
        // Parse "isReturn|fromVp|toVp|vector" format
        let parts: Vec<&str> = result_str.split('|').collect();
        let is_return = parts.first().map(|s| *s == "true").unwrap_or(true);
        let from_vp = parts
            .get(1)
            .and_then(|s| if s.is_empty() { None } else { s.parse::<u64>().ok() });
        let to_vp = parts
            .get(2)
            .and_then(|s| if s.is_empty() { None } else { s.parse::<u64>().ok() });
        let interrupt_return = parts
            .get(3)
            .and_then(|s| if s.is_empty() { None } else { s.parse::<u8>().ok() });
        Ok(SwitchContextDto {
            from_domain,
            to_domain,
            core_id: core,
            from_vp,
            to_vp,
            is_return,
            interrupt_return,
        })
    }

    fn deliver_interrupt(
        &mut self,
        vector: u8,
        domain: DomainId,
        core: u64,
    ) -> Result<()> {
        let code =
            unsafe { lean_ffi_deliver_interrupt(vector as u64, domain, core) };
        check(code)
    }

    // === Policy & Registers ===

    fn set_policy(
        &mut self,
        parent: DomainId,
        child: DomainId,
        field: &str,
        value: u64,
    ) -> Result<()> {
        let code =
            unsafe { lean_ffi_set_policy(parent, child, policy_field_code(field), value) };
        check(code)
    }

    fn get_policy(
        &self,
        parent: DomainId,
        child: DomainId,
        field: &str,
    ) -> Result<u64> {
        let code = unsafe { lean_ffi_get_policy(parent, child, policy_field_code(field)) };
        check(code)?;
        Ok(get_result1())
    }

    fn set_register(
        &mut self,
        parent: DomainId,
        child: DomainId,
        vp: u64,
        reg: u64,
        value: u64,
    ) -> Result<()> {
        let code = unsafe { lean_ffi_set_register(parent, child, vp, reg, value) };
        check(code)
    }

    fn get_register(
        &self,
        parent: DomainId,
        child: DomainId,
        vp: u64,
        reg: u64,
    ) -> Result<u64> {
        let code = unsafe { lean_ffi_get_register(parent, child, vp, reg) };
        check(code)?;
        Ok(get_result1())
    }

    fn set_interrupt_policy(
        &mut self,
        owner: DomainId,
        child: DomainId,
        vector: u8,
        visibility: u64,
    ) -> Result<()> {
        let code = unsafe {
            lean_ffi_set_interrupt_policy(owner, child, vector as u64, visibility)
        };
        check(code)
    }

    // === Queries ===

    fn list_domains(&self) -> Vec<DomainInfoDto> {
        let code = unsafe { lean_ffi_list_domains() };
        if code != 0 {
            return vec![];
        }
        let json = get_result_str();
        let mut result: Vec<DomainInfoDto> = parse_json_array(&json)
            .iter()
            .map(parse_domain_info)
            .collect();
        result.sort_by_key(|d| d.id);
        result
    }

    fn get_domain_mem_caps(&self, id: DomainId) -> Vec<MemCapInfoDto> {
        let code = unsafe { lean_ffi_get_domain_mem_caps(id) };
        if code != 0 {
            return vec![];
        }
        let json = get_result_str();
        parse_json_array(&json)
            .iter()
            .map(parse_mem_cap_info)
            .collect()
    }

    fn get_domain_dom_caps(&self, id: DomainId) -> Vec<DomCapInfoDto> {
        let code = unsafe { lean_ffi_get_domain_dom_caps(id) };
        if code != 0 {
            return vec![];
        }
        let json = get_result_str();
        parse_json_array(&json)
            .iter()
            .map(|v| DomCapInfoDto {
                local_handle: json_u64(v, "local_handle"),
                domain_id: json_u64(v, "domain_id"),
                is_channel: json_bool(v, "is_channel"),
            })
            .collect()
    }

    fn get_pending_caps(&self, id: DomainId) -> Vec<PendingCapDto> {
        let code = unsafe { lean_ffi_get_pending_caps(id) };
        if code != 0 {
            return vec![];
        }
        let json = get_result_str();
        parse_json_array(&json)
            .iter()
            .map(|v| PendingCapDto {
                pending_id: json_u64(v, "pending_id"),
                is_domain: json_bool(v, "is_domain"),
                sender_id: json_u64(v, "sender_id"),
                start: json_u64(v, "start"),
                end: json_u64(v, "end"),
                rights: json_str(v, "rights"),
            })
            .collect()
    }

    fn get_address_space(&self, id: DomainId) -> Vec<AddressRegionDto> {
        let code = unsafe { lean_ffi_get_address_space(id) };
        if code != 0 {
            return vec![];
        }
        let json = get_result_str();
        parse_json_array(&json)
            .iter()
            .map(|v| AddressRegionDto {
                gpa: json_u64(v, "gpa"),
                size: json_u64(v, "size"),
                rights: json_str(v, "rights"),
                hpa: json_u64(v, "hpa"),
                is_identity_mapped: json_bool(v, "is_identity_mapped"),
            })
            .collect()
    }

    fn get_core_states(&self) -> Vec<CoreStateDto> {
        let code = unsafe { lean_ffi_get_core_states() };
        if code != 0 {
            return vec![];
        }
        let json = get_result_str();
        parse_json_array(&json)
            .iter()
            .map(|v| CoreStateDto {
                core_id: json_u64(v, "core_id"),
                state: json_str(v, "state"),
                domain_id: json_opt_u64(v, "domain_id"),
                vp_id: json_opt_u64(v, "vp_id"),
            })
            .collect()
    }

    fn attest(&self, id: DomainId) -> Result<String> {
        let code = unsafe { lean_ffi_attest(id) };
        check(code)?;
        Ok(get_result_str())
    }

    fn num_cores(&self) -> usize {
        unsafe { lean_ffi_num_cores() as usize }
    }
}
