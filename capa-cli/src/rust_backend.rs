//! RustBackend — wraps the `capa-engine` library behind the [`Backend`] trait.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

use capability_engine::{
    Access, Attributes, Capability, CapaError, Domain, DomainPolicy, LocalHandle,
    MemoryRegion, MonitorAPI, Platform, PolicyIdentifier, ResourceKind, Rights, Update,
    UpdateBatch, VpRunState, attest_domain, compute_address_space,
};

use crate::backend::{
    AddressRegionDto, Backend, BackendError, CoreStateDto, DomCapInfoDto, DomainInfoDto, HwUpdate,
    HwUpdateKind, InitResult, MemCapInfoDto, PendingCapDto, SwitchContextDto, VpStateDto,
};
use crate::backend::{DomainId, MemCapUid, Result};
use crate::platform::CliPlatform;
use crate::state::{find_domain_handle, find_memory_handle};

// ─── Type aliases for readability ────────────────────────────────────────────

type CapDomain = Arc<RwLock<Capability<Domain>>>;
type CapMem = Arc<RwLock<Capability<MemoryRegion>>>;

// ─── Backend implementation ──────────────────────────────────────────────────

pub struct RustBackend {
    platform: Arc<CliPlatform>,
    /// DomainId → domain capability
    domains: HashMap<DomainId, CapDomain>,
    /// MemCapUid → memory capability
    mem_caps: HashMap<MemCapUid, CapMem>,
    /// Counter for assigning unique IDs to memory capabilities.
    next_uid: MemCapUid,
    /// Counter for engine-level capability / sub-handle IDs.
    next_cap_id: u64,
    /// Counter for synthetic channel domain IDs (channels share `data.id`
    /// in the engine, so we assign unique IDs here to avoid collisions).
    next_chan_id: DomainId,
    num_cores: usize,
}

impl RustBackend {
    pub fn new(num_cores: usize) -> Self {
        RustBackend {
            platform: Arc::new(CliPlatform::new(num_cores)),
            domains: HashMap::new(),
            mem_caps: HashMap::new(),
            next_uid: 0,
            next_cap_id: 0,
            next_chan_id: u64::MAX,
            num_cores,
        }
    }

    fn alloc_uid(&mut self) -> MemCapUid {
        let uid = self.next_uid;
        self.next_uid += 1;
        uid
    }

    fn alloc_cap_id(&mut self) -> u64 {
        let id = self.next_cap_id;
        self.next_cap_id += 1;
        id
    }

    /// Allocate a unique synthetic ID for a channel domain.
    fn alloc_chan_id(&mut self) -> DomainId {
        let id = self.next_chan_id;
        self.next_chan_id -= 1;
        id
    }

    /// Look up a domain Arc by DomainId.
    fn get_domain(&self, id: DomainId) -> Result<CapDomain> {
        self.domains.get(&id).cloned().ok_or(BackendError::NotFound)
    }

    /// Look up a memory Arc by MemCapUid.
    fn get_mem(&self, uid: MemCapUid) -> Result<CapMem> {
        self.mem_caps.get(&uid).cloned().ok_or(BackendError::NotFound)
    }

    /// Find the owning domain's handle for a memory capability.
    #[allow(dead_code)]
    fn resolve_mem_handle(&self, mem: &CapMem) -> Result<(CapDomain, LocalHandle)> {
        let owner_id = mem.read().owned.owner;
        let owner = self.get_domain(owner_id)?;
        let handle = find_memory_handle(&owner, mem).ok_or(BackendError::NotFound)?;
        Ok((owner, handle))
    }

    /// Find the parent domain's handle for a child domain.
    fn resolve_dom_handle(&self, parent_id: DomainId, child_id: DomainId) -> Result<(CapDomain, CapDomain, LocalHandle)> {
        let parent = self.get_domain(parent_id)?;
        let child = self.get_domain(child_id)?;
        let handle = find_domain_handle(&parent, &child).ok_or(BackendError::NotFound)?;
        Ok((parent, child, handle))
    }

    /// Find the MemCapUid that corresponds to an Arc pointer.
    fn uid_for_mem(&self, arc: &CapMem) -> Option<MemCapUid> {
        let ptr = Arc::as_ptr(arc);
        self.mem_caps.iter()
            .find(|(_, v)| Arc::as_ptr(v) == ptr)
            .map(|(&uid, _)| uid)
    }
}

// ─── Error conversion ────────────────────────────────────────────────────────

fn convert_error(e: CapaError) -> BackendError {
    match e {
        CapaError::DomainRevoked => BackendError::DomainRevoked,
        CapaError::InvalidAccess => BackendError::InvalidAccess,
        CapaError::PermissionDenied => BackendError::PermissionDenied,
        CapaError::NotFound => BackendError::NotFound,
        CapaError::DomainSealed => BackendError::DomainSealed,
        CapaError::DomainNotSealed => BackendError::DomainNotSealed,
        CapaError::ParentRevoked => BackendError::ParentRevoked,
        CapaError::CannotAliasCarved => BackendError::CannotAliasCarved,
        CapaError::RegionOverlap => BackendError::RegionOverlap,
        CapaError::InvalidRemapping => BackendError::InvalidRemapping,
        CapaError::AlreadyExists => BackendError::AlreadyExists,
        CapaError::MonotonicityViolation => BackendError::MonotonicityViolation,
        CapaError::ApiNotAllowed => BackendError::ApiNotAllowed,
        CapaError::TreeLocked => BackendError::TreeLocked,
        CapaError::InvalidOperation(s) => BackendError::InvalidOperation(s),
        CapaError::NotSupported => BackendError::NotSupported,
        CapaError::RegisterOutOfRange => BackendError::RegisterOutOfRange,
        CapaError::RegisterAccessDenied => BackendError::RegisterAccessDenied,
        CapaError::InvalidValue => BackendError::InvalidOperation("invalid value".into()),
        CapaError::NoMemory => BackendError::InvalidOperation("no memory".into()),
    }
}

// ─── Update conversion ──────────────────────────────────────────────────────

fn convert_updates(batch: &UpdateBatch) -> Vec<HwUpdate> {
    batch.updates().iter().filter_map(|u| Some(match u {
        Update::ChangeRights { domain, address, size, physical, rights, .. } => {
            if *rights == Rights::NONE {
                HwUpdate {
                    kind: HwUpdateKind::UnmapMemory,
                    domain_id: *domain,
                    gpa: *address,
                    size: *size,
                    hpa: *physical,
                    rights: None,
                }
            } else {
                HwUpdate {
                    kind: HwUpdateKind::MapMemory,
                    domain_id: *domain,
                    gpa: *address,
                    size: *size,
                    hpa: *physical,
                    rights: Some(format_rights_val(*rights)),
                }
            }
        }
        Update::ZeroMemory { address, size } => HwUpdate {
            kind: HwUpdateKind::ZeroMemory,
            domain_id: 0,
            gpa: *address,
            size: *size,
            hpa: *address,
            rights: None,
        },
        Update::RevokeDomain { domain, .. } => HwUpdate {
            kind: HwUpdateKind::RevokeDomain,
            domain_id: *domain,
            gpa: 0,
            size: 0,
            hpa: 0,
            rights: None,
        },
        Update::CreateDomain { domain_id, .. } => HwUpdate {
            kind: HwUpdateKind::CreateDomain,
            domain_id: *domain_id,
            gpa: 0,
            size: 0,
            hpa: 0,
            rights: None,
        },
        Update::FlushTLB { domain } => HwUpdate {
            kind: HwUpdateKind::FlushTlb,
            domain_id: *domain,
            gpa: 0,
            size: 0,
            hpa: 0,
            rights: None,
        },
        Update::CommRegion { domain_id, phys, size, .. } => HwUpdate {
            kind: HwUpdateKind::CommRegion,
            domain_id: *domain_id,
            gpa: *phys,
            size: *size,
            hpa: *phys,
            rights: None,
        },
        Update::UncommRegion { domain_id, phys, size, .. } => HwUpdate {
            kind: HwUpdateKind::UncommRegion,
            domain_id: *domain_id,
            gpa: *phys,
            size: *size,
            hpa: *phys,
            rights: None,
        },
        Update::GiveMetaMem { domain_id, start, size } => HwUpdate {
            kind: HwUpdateKind::GiveMetaMem,
            domain_id: *domain_id,
            gpa: *start,
            size: *size,
            hpa: *start,
            rights: None,
        },
        Update::PolicyChanged { domain, .. } => HwUpdate {
            kind: HwUpdateKind::PolicyChanged,
            domain_id: *domain,
            gpa: 0,
            size: 0,
            hpa: 0,
            rights: None,
        },
        // Core-keyed, not a hardware/address-space projection — the CLI
        // backend is single-core and has no notion of cross-core routing,
        // so there is nothing meaningful to display here.
        Update::Switch(_) => return None,
    })).collect()
}

fn format_rights_val(r: Rights) -> String {
    let rd = if r.has(Rights::READ) { 'R' } else { '-' };
    let wr = if r.has(Rights::WRITE) { 'W' } else { '-' };
    let ex = if r.has(Rights::EXECUTE) { 'X' } else { '-' };
    let s = format!("{}{}{}", rd, wr, ex);
    if s == "---" { "NONE".to_string() } else { s }
}

fn format_attributes_val(a: Attributes) -> String {
    let bits = a.bits();
    if bits == 0 {
        return "NONE".to_string();
    }
    let mut parts = Vec::new();
    if a.hash() { parts.push("HASH"); }
    if a.clean() { parts.push("CLEAN"); }
    if a.vital() { parts.push("VITAL"); }
    if a.meta() { parts.push("META"); }
    if a.comm() { parts.push("COMM"); }
    parts.join(",")
}

fn format_api_val(api: &MonitorAPI) -> String {
    let bits = api.bits();
    if bits == 0 { return "NONE".to_string(); }
    let flags = [
        (MonitorAPI::CREATE, "CREATE"), (MonitorAPI::SET, "SET"),
        (MonitorAPI::GET, "GET"), (MonitorAPI::SEND, "SEND"),
        (MonitorAPI::SEAL, "SEAL"), (MonitorAPI::ATTEST, "ATTEST"),
        (MonitorAPI::ENUMERATE, "ENUMERATE"), (MonitorAPI::SWITCH, "SWITCH"),
        (MonitorAPI::ALIAS, "ALIAS"), (MonitorAPI::CARVE, "CARVE"),
        (MonitorAPI::REVOKE, "REVOKE"), (MonitorAPI::GETCHAN, "GETCHAN"),
        (MonitorAPI::RECEIVE_AFTER_SEAL, "RECEIVE_AFTER_SEAL"),
    ];
    flags.iter()
        .filter(|(flag, _)| bits & flag != 0)
        .map(|(_, name)| *name)
        .collect::<Vec<_>>()
        .join(",")
}

// ─── Backend trait implementation ────────────────────────────────────────────

impl Backend for RustBackend {
    // ── Lifecycle ────────────────────────────────────────────────────────

    fn init(&mut self, size: u64) -> Result<InitResult> {
        let root_domain = Domain::new_root(self.num_cores);
        let domain_id = root_domain.id;
        let root_cap_id = self.alloc_cap_id();
        let root = Capability::new_root(0, root_cap_id, root_domain);

        let root_region = MemoryRegion::new_root(0x0, size);
        let mem_cap_id = self.alloc_cap_id();
        let mem_root = Capability::new_root(0, mem_cap_id, root_region);

        // Register memory capability with root domain.
        root.write()
            .data
            .add_memory_capability(mem_cap_id, Arc::downgrade(&mem_root));

        // Schedule root domain on all cores and mark VPs as Running.
        self.platform.register_domain(domain_id, None);
        let num_cores = self.num_cores as u64;
        for core_id in 0..num_cores {
            if let Ok(core_ref) = self.platform.get_core(core_id) {
                core_ref.set_binding(root.clone(), core_id);
            }
            let vp = root.read().data.policy.vprocessor_states.get(core_id as usize).cloned();
            if let Some(vp_arc) = vp {
                *vp_arc.run_state.write() = VpRunState::Running { core: core_id };
            }
        }

        let mem_uid = self.alloc_uid();
        self.domains.insert(domain_id, root);
        self.mem_caps.insert(mem_uid, mem_root);

        Ok(InitResult { domain_id, mem_uid })
    }

    fn reset(&mut self, num_cores: usize) {
        self.platform = Arc::new(CliPlatform::new(num_cores));
        self.domains.clear();
        self.mem_caps.clear();
        self.next_uid = 0;
        self.next_cap_id = 0;
        self.num_cores = num_cores;
    }

    // ── Memory Operations ───────────────────────────────────────────────

    fn carve(
        &mut self,
        owner: DomainId,
        parent: MemCapUid,
        start: u64,
        size: u64,
        rights: u8,
    ) -> Result<(MemCapUid, Vec<HwUpdate>)> {
        let domain = self.get_domain(owner)?;
        let mem = self.get_mem(parent)?;
        let handle = find_memory_handle(&domain, &mem).ok_or(BackendError::NotFound)?;
        let access = Access::new(start, size, Rights::from_bits(rights));

        let (child_handle, _sub, batch) =
            Capability::carve(&*self.platform, &domain, handle, access).map_err(convert_error)?;

        let child = domain.read().data.memory_capabilities
            .get(&child_handle)
            .and_then(|w| w.upgrade())
            .ok_or(BackendError::NotFound)?;

        let uid = self.alloc_uid();
        self.mem_caps.insert(uid, child);

        Ok((uid, convert_updates(&batch)))
    }

    fn alias(
        &mut self,
        owner: DomainId,
        parent: MemCapUid,
        start: u64,
        size: u64,
        rights: u8,
    ) -> Result<(MemCapUid, Vec<HwUpdate>)> {
        let domain = self.get_domain(owner)?;
        let mem = self.get_mem(parent)?;
        let handle = find_memory_handle(&domain, &mem).ok_or(BackendError::NotFound)?;
        let access = Access::new(start, size, Rights::from_bits(rights));

        let (child_handle, _sub, batch) =
            Capability::alias(&*self.platform, &domain, handle, access).map_err(convert_error)?;

        let child = domain.read().data.memory_capabilities
            .get(&child_handle)
            .and_then(|w| w.upgrade())
            .ok_or(BackendError::NotFound)?;

        let uid = self.alloc_uid();
        self.mem_caps.insert(uid, child);

        Ok((uid, convert_updates(&batch)))
    }

    fn send(
        &mut self,
        mem: MemCapUid,
        receiver: DomainId,
        attrs: u8,
        gpa: Option<u64>,
    ) -> Result<Vec<HwUpdate>> {
        let mem_arc = self.get_mem(mem)?;
        let receiver_arc = self.get_domain(receiver)?;

        let sender_id = mem_arc.read().owned.owner;
        let sender = self.get_domain(sender_id)?;
        let sender_handle = find_memory_handle(&sender, &mem_arc)
            .ok_or(BackendError::NotFound)?;

        let attrs = Attributes::from_bits(attrs);

        let recv_h = find_domain_handle(&sender, &receiver_arc)
            .ok_or(BackendError::NotFound)?;
        let batch = Capability::send_at(&*self.platform, &sender, sender_handle, recv_h, attrs, gpa)
            .map_err(convert_error)?;

        Ok(convert_updates(&batch))
    }

    fn accept(
        &mut self,
        domain: DomainId,
        pending_id: u64,
        gpa: Option<u64>,
    ) -> Result<(MemCapUid, Vec<HwUpdate>)> {
        let domain_arc = self.get_domain(domain)?;

        let (handle, batch) =
            Capability::accept_at(&*self.platform, &domain_arc, pending_id, gpa)
                .map_err(convert_error)?;

        let child = domain_arc.read().data.memory_capabilities
            .get(&handle)
            .and_then(|w| w.upgrade())
            .ok_or(BackendError::NotFound)?;

        let uid = self.uid_for_mem(&child).unwrap_or_else(|| self.alloc_uid());
        self.mem_caps.insert(uid, child);

        Ok((uid, convert_updates(&batch)))
    }

    fn reject(&mut self, domain: DomainId, pending_id: u64) -> Result<()> {
        let domain_arc = self.get_domain(domain)?;
        Capability::reject(&*self.platform, &domain_arc, pending_id)
            .map(|_batch| ())
            .map_err(convert_error)
    }

    fn revoke_mem(
        &mut self,
        owner: DomainId,
        parent: MemCapUid,
        child: MemCapUid,
    ) -> Result<Vec<HwUpdate>> {
        let owner_arc = self.get_domain(owner)?;
        let parent_arc = self.get_mem(parent)?;
        let child_arc = self.get_mem(child)?;
        let parent_handle = find_memory_handle(&owner_arc, &parent_arc)
            .ok_or(BackendError::NotFound)?;
        let child_sub = child_arc.read().sub_handle;

        let batch = Capability::revoke(&*self.platform, &owner_arc, parent_handle, child_sub)
            .map_err(convert_error)?;

        // Remove the revoked child (and any descendants) from our table.
        self.prune_stale_mem_caps();

        // Clean up revoked domains from our table.
        self.cleanup_revoked(&batch);

        Ok(convert_updates(&batch))
    }

    // ── Domain Operations ───────────────────────────────────────────────

    fn create_domain(
        &mut self,
        parent: DomainId,
        cores: u64,
        api: u64,
    ) -> Result<(DomainId, Vec<HwUpdate>)> {
        let parent_arc = self.get_domain(parent)?;
        let child_policy = DomainPolicy::new_restricted(cores, MonitorAPI::from_bits(api as u16));

        let (child_handle, _batch) =
            Capability::create(&*self.platform, &parent_arc, child_policy)
                .map_err(convert_error)?;

        let child_arc = parent_arc.read().data.domain_capabilities
            .get(&child_handle)
            .and_then(|w| w.upgrade())
            .ok_or(BackendError::NotFound)?;

        let child_id = child_arc.read().data.id;

        // Add VPs as specified by the policy.
        let num_vps = child_arc.read().data.policy.num_vprocessors;
        for _ in 0..num_vps {
            child_arc.write().data.add_vprocessor().map_err(convert_error)?;
        }

        self.domains.insert(child_id, child_arc);
        self.platform.register_domain(child_id, Some(parent));

        Ok((child_id, Vec::new()))
    }

    fn seal(&mut self, owner: DomainId, child: DomainId) -> Result<()> {
        let (owner_arc, _child_arc, handle) = self.resolve_dom_handle(owner, child)?;
        Capability::seal(&*self.platform, &owner_arc, handle)
            .map(|_batch| ())
            .map_err(convert_error)
    }

    fn revoke_domain(
        &mut self,
        parent: DomainId,
        child: DomainId,
    ) -> Result<Vec<HwUpdate>> {
        let parent_arc = self.get_domain(parent)?;
        let child_arc = self.get_domain(child)?;
        let child_handle = find_domain_handle(&parent_arc, &child_arc)
            .ok_or(BackendError::NotFound)?;

        let batch = Capability::revoke_domain(&*self.platform, &parent_arc, child_handle)
            .map_err(convert_error)?;

        self.cleanup_revoked(&batch);

        Ok(convert_updates(&batch))
    }

    // ── Channel Operations ──────────────────────────────────────────────

    fn get_chan(&mut self, caller: DomainId, target: DomainId) -> Result<DomainId> {
        let (caller_arc, _target_arc, target_handle) = self.resolve_dom_handle(caller, target)?;

        let (chan_handle, _batch) =
            Capability::get_chan(&*self.platform, &caller_arc, target_handle)
                .map_err(convert_error)?;

        let chan_ref = caller_arc.read().data.domain_capabilities[&chan_handle]
            .upgrade()
            .ok_or(BackendError::NotFound)?;

        let chan_id = self.alloc_chan_id();
        self.domains.insert(chan_id, chan_ref);

        Ok(chan_id)
    }

    fn get_chan_self(&mut self, caller: DomainId) -> Result<DomainId> {
        let caller_arc = self.get_domain(caller)?;

        let (chan_handle, _batch) = Capability::get_chan_self(&*self.platform, &caller_arc)
            .map_err(convert_error)?;

        let chan_ref = caller_arc.read().data.domain_capabilities[&chan_handle]
            .upgrade()
            .ok_or(BackendError::NotFound)?;

        let chan_id = self.alloc_chan_id();
        self.domains.insert(chan_id, chan_ref);

        Ok(chan_id)
    }

    fn send_channel(
        &mut self,
        caller: DomainId,
        chan: DomainId,
        receiver: DomainId,
    ) -> Result<()> {
        let caller_arc = self.get_domain(caller)?;
        let chan_arc = self.get_domain(chan)?;
        let receiver_arc = self.get_domain(receiver)?;

        let chan_handle = find_domain_handle(&caller_arc, &chan_arc)
            .ok_or(BackendError::NotFound)?;
        let recv_handle = find_domain_handle(&caller_arc, &receiver_arc)
            .ok_or(BackendError::NotFound)?;

        Capability::<Domain>::send_channel(
            &*self.platform, &caller_arc, chan_handle, recv_handle, Attributes::NONE,
        )
        .map(|_batch| ())
        .map_err(convert_error)
    }

    fn accept_channel(
        &mut self,
        receiver: DomainId,
        pending_id: u64,
    ) -> Result<DomainId> {
        let receiver_arc = self.get_domain(receiver)?;

        let (new_handle, _batch) =
            Capability::<Domain>::accept_channel(&*self.platform, &receiver_arc, pending_id)
                .map_err(convert_error)?;

        let chan_ref = receiver_arc.read().data.domain_capabilities[&new_handle]
            .upgrade()
            .ok_or(BackendError::NotFound)?;

        let chan_id = self.alloc_chan_id();
        self.domains.insert(chan_id, chan_ref);

        Ok(chan_id)
    }

    fn reject_channel(&mut self, receiver: DomainId, pending_id: u64) -> Result<()> {
        let receiver_arc = self.get_domain(receiver)?;
        Capability::<Domain>::reject_channel(&*self.platform, &receiver_arc, pending_id)
            .map(|_batch| ())
            .map_err(convert_error)
    }

    // ── VP & Switch ─────────────────────────────────────────────────────

    fn add_vp(
        &mut self,
        _parent: DomainId,
        child: DomainId,
        _comm: MemCapUid,
        _vp_id: u32,
    ) -> Result<Vec<HwUpdate>> {
        let child_arc = self.get_domain(child)?;
        child_arc.write().data.add_vprocessor().map_err(convert_error)?;
        Ok(Vec::new())
    }

    fn register_comm(
        &mut self,
        owner: DomainId,
        mem: MemCapUid,
        child: DomainId,
        vp_id: u32,
    ) -> Result<Vec<HwUpdate>> {
        let owner_arc = self.get_domain(owner)?;
        let mem_arc = self.get_mem(mem)?;
        let child_arc = self.get_domain(child)?;

        let mem_handle = find_memory_handle(&owner_arc, &mem_arc)
            .ok_or(BackendError::NotFound)?;
        let child_handle = find_domain_handle(&owner_arc, &child_arc)
            .ok_or(BackendError::NotFound)?;

        let batch =
            Capability::<Domain>::register_comm(&*self.platform, &owner_arc, mem_handle, child_handle, vp_id)
                .map_err(convert_error)?;

        Ok(convert_updates(&batch))
    }

    fn switch_forward(
        &mut self,
        domain: DomainId,
        core: u64,
        vp_id: u64,
    ) -> Result<SwitchContextDto> {
        let core_ref = self.platform.get_core(core).map_err(convert_error)?;

        let from_id = core_ref.current_domain().ok_or_else(|| {
            BackendError::InvalidOperation("Core is idle".to_string())
        })?;

        let from_ref = self.get_domain(from_id)?;
        let to_ref = self.get_domain(domain)?;
        let to_handle = find_domain_handle(&from_ref, &to_ref)
            .ok_or(BackendError::NotFound)?;

        self.platform.set_current_core(Some(core));

        let (ctx, _batch) = Capability::<Domain>::switch(
            self.platform.as_ref(), &from_ref, to_handle, vp_id,
        )
        .map_err(convert_error)?;

        self.platform.set_current_core(None);

        Ok(SwitchContextDto {
            from_domain: ctx
                .from_domain
                .as_ref()
                .expect("forward switch always names a source domain")
                .read()
                .data
                .id,
            to_domain: ctx.to_domain.read().data.id,
            core_id: ctx.core_id,
            from_vp: ctx.from_vp_id,
            to_vp: ctx.to_vp_id,
            is_return: ctx.is_return,
            interrupt_return: ctx.interrupt_return,
        })
    }

    fn switch_return(&mut self, core: u64) -> Result<SwitchContextDto> {
        let core_ref = self.platform.get_core(core).map_err(convert_error)?;

        let from_id = core_ref.current_domain().ok_or_else(|| {
            BackendError::InvalidOperation("Core is idle".to_string())
        })?;

        let from_ref = self.get_domain(from_id)?;

        self.platform.set_current_core(Some(core));

        let (ctx, _batch) = Capability::<Domain>::switch(
            self.platform.as_ref(), &from_ref, 0, 0,
        )
        .map_err(convert_error)?;

        self.platform.set_current_core(None);

        Ok(SwitchContextDto {
            from_domain: ctx
                .from_domain
                .as_ref()
                .expect("return switch always names a source domain")
                .read()
                .data
                .id,
            to_domain: ctx.to_domain.read().data.id,
            core_id: ctx.core_id,
            from_vp: ctx.from_vp_id,
            to_vp: ctx.to_vp_id,
            is_return: ctx.is_return,
            interrupt_return: ctx.interrupt_return,
        })
    }

    fn deliver_interrupt(
        &mut self,
        vector: u8,
        domain: DomainId,
        core: u64,
    ) -> Result<()> {
        let domain_arc = self.get_domain(domain)?;

        // `deliver_interrupt_vp` already rebinds the core to the handler
        // domain internally (`core_ctx.set_binding(...)`) when the handler
        // differs from `domain` — no separate platform-side fixup needed.
        let vp_delivery = Capability::<Domain>::deliver_interrupt_vp(
            self.platform.as_ref(), &domain_arc, core, vector,
        );

        vp_delivery.map(|_| ()).map_err(convert_error)
    }

    // ── Policy & Registers ──────────────────────────────────────────────

    fn set_policy(
        &mut self,
        parent: DomainId,
        child: DomainId,
        field: &str,
        value: u64,
    ) -> Result<()> {
        let (parent_arc, _child_arc, handle) = self.resolve_dom_handle(parent, child)?;
        let policy_id = parse_policy_id(field)?;
        Capability::set_policy(&*self.platform, &parent_arc, handle, policy_id, value)
            .map(|_batch| ())
            .map_err(convert_error)
    }

    fn get_policy(
        &self,
        parent: DomainId,
        child: DomainId,
        field: &str,
    ) -> Result<u64> {
        let parent_arc = self.domains.get(&parent).ok_or(BackendError::NotFound)?;
        let child_arc = self.domains.get(&child).ok_or(BackendError::NotFound)?;
        let handle = find_domain_handle(parent_arc, child_arc)
            .ok_or(BackendError::NotFound)?;
        let policy_id = parse_policy_id(field)?;
        Capability::get_policy(&*self.platform, parent_arc, handle, policy_id)
            .map(|(v, _)| v)
            .map_err(convert_error)
    }

    fn set_register(
        &mut self,
        parent: DomainId,
        child: DomainId,
        vp: u64,
        reg: u64,
        value: u64,
    ) -> Result<()> {
        let (parent_arc, _child_arc, handle) = self.resolve_dom_handle(parent, child)?;
        Capability::set_register(&*self.platform, &parent_arc, handle, vp, reg, value)
            .map(|_batch| ())
            .map_err(convert_error)
    }

    fn get_register(
        &self,
        parent: DomainId,
        child: DomainId,
        vp: u64,
        reg: u64,
    ) -> Result<u64> {
        let parent_arc = self.domains.get(&parent).ok_or(BackendError::NotFound)?;
        let child_arc = self.domains.get(&child).ok_or(BackendError::NotFound)?;
        let handle = find_domain_handle(parent_arc, child_arc)
            .ok_or(BackendError::NotFound)?;
        Capability::get_register(&*self.platform, parent_arc, handle, vp, reg)
            .map(|(v, _)| v)
            .map_err(convert_error)
    }

    fn set_interrupt_policy(
        &mut self,
        owner: DomainId,
        child: DomainId,
        vector: u8,
        visibility: u64,
    ) -> Result<()> {
        let (owner_arc, _child_arc, handle) = self.resolve_dom_handle(owner, child)?;
        Capability::set_policy(
            &*self.platform,
            &owner_arc,
            handle,
            PolicyIdentifier::VectorVisibility(vector),
            visibility,
        )
        .map(|_batch| ())
        .map_err(convert_error)
    }

    // ── Queries ─────────────────────────────────────────────────────────

    fn list_domains(&self) -> Vec<DomainInfoDto> {
        let mut result = Vec::new();
        for (&id, dom_arc) in &self.domains {
            let d = dom_arc.read();
            let is_channel = d.is_channel();
            let channel_target = d.channel_target.as_ref()
                .and_then(|w| w.upgrade())
                .map(|t| t.read().data.id);

            let vp_states: Vec<VpStateDto> = d.data.policy.vprocessor_states.iter()
                .map(|vp| {
                    let state = vp.run_state.read();
                    VpStateDto {
                        vp_id: vp.id,
                        state: format!("{:?}", *state),
                    }
                })
                .collect();

            result.push(DomainInfoDto {
                id,
                status: format!("{:?}", d.data.status),
                is_channel,
                channel_target,
                cores_bitmap: d.data.policy.cores,
                api_flags: format_api_val(&d.data.policy.api),
                num_vps: d.data.policy.num_vprocessors,
                vp_states,
            });
        }
        result.sort_by_key(|d| d.id);
        result
    }

    fn get_domain_mem_caps(&self, id: DomainId) -> Vec<MemCapInfoDto> {
        let dom_arc = match self.domains.get(&id) {
            Some(d) => d,
            None => return Vec::new(),
        };
        let d = dom_arc.read();
        let mut result = Vec::new();

        for (&local_handle, weak) in &d.data.memory_capabilities {
            if let Some(mem_arc) = weak.upgrade() {
                if let Some(dto) = self.build_mem_info(&mem_arc, local_handle) {
                    result.push(dto);
                }
            }
        }
        result.sort_by_key(|m| m.start);
        result
    }

    fn get_domain_dom_caps(&self, id: DomainId) -> Vec<DomCapInfoDto> {
        let dom_arc = match self.domains.get(&id) {
            Some(d) => d,
            None => return Vec::new(),
        };
        let d = dom_arc.read();
        let mut result = Vec::new();

        for (&local_handle, weak) in &d.data.domain_capabilities {
            if let Some(child_arc) = weak.upgrade() {
                let child = child_arc.read();
                result.push(DomCapInfoDto {
                    local_handle,
                    domain_id: child.data.id,
                    is_channel: child_arc.read().is_channel(),
                });
            }
        }
        result.sort_by_key(|d| d.local_handle);
        result
    }

    fn get_pending_caps(&self, id: DomainId) -> Vec<PendingCapDto> {
        let dom_arc = match self.domains.get(&id) {
            Some(d) => d,
            None => return Vec::new(),
        };
        let d = dom_arc.read();
        let mut result = Vec::new();

        for (&pending_id, pending) in &d.data.pending_capabilities {
            let (start, end, rights) = if let Some(mem_ref) = pending.cap.upgrade() {
                let m = mem_ref.read();
                (m.data.access.start, m.data.access.end(), format_rights_val(m.data.access.rights))
            } else {
                (0, 0, "?".to_string())
            };
            result.push(PendingCapDto {
                pending_id,
                is_domain: false,
                sender_id: pending.sender_domain_id,
                start,
                end,
                rights,
            });
        }

        for (&pending_id, pending) in &d.data.pending_domain_capabilities {
            let (start, end) = if let Some(dom_ref) = pending.cap.upgrade() {
                let dom = dom_ref.read();
                (dom.data.id, 0)
            } else {
                (0, 0)
            };
            result.push(PendingCapDto {
                pending_id,
                is_domain: true,
                sender_id: pending.sender_domain_id,
                start,
                end,
                rights: String::new(),
            });
        }

        result.sort_by_key(|p| p.pending_id);
        result
    }

    fn get_address_space(&self, id: DomainId) -> Vec<AddressRegionDto> {
        let dom_arc = match self.domains.get(&id) {
            Some(d) => d,
            None => return Vec::new(),
        };

        let view = compute_address_space(dom_arc);
        view.regions.iter().map(|r| {
            let gpa = r.access.start;
            let hpa = r.access.start; // identity-mapped in CLI
            AddressRegionDto {
                gpa,
                size: r.access.size,
                rights: format_rights_val(r.access.rights),
                hpa,
                is_identity_mapped: gpa == hpa,
            }
        }).collect()
    }

    fn get_core_states(&self) -> Vec<CoreStateDto> {
        let mut result = Vec::new();
        for i in 0..self.num_cores as u64 {
            if let Ok(core_ref) = self.platform.get_core(i) {
                let (state_str, domain_id) = match core_ref.current_domain() {
                    Some(id) => ("Running".to_string(), Some(id)),
                    None => ("Idle".to_string(), None),
                };
                let vp_id = core_ref.current_vp();
                result.push(CoreStateDto {
                    core_id: i,
                    state: state_str,
                    domain_id,
                    vp_id,
                });
            }
        }
        result
    }

    fn attest(&self, id: DomainId) -> Result<String> {
        let dom_arc = self.domains.get(&id).ok_or(BackendError::NotFound)?;

        // Sealed domains must have ATTEST permission.
        {
            let d = dom_arc.read();
            if d.data.is_sealed() && !d.data.policy.api.attest() {
                return Err(BackendError::PermissionDenied);
            }
        }

        let report = attest_domain(dom_arc);
        Ok(report.report)
    }

    fn num_cores(&self) -> usize {
        self.num_cores
    }
}

// ─── Private helpers ─────────────────────────────────────────────────────────

impl RustBackend {
    /// Build a MemCapInfoDto for a memory capability, including its children.
    fn build_mem_info(&self, mem_arc: &CapMem, local_handle: u64) -> Option<MemCapInfoDto> {
        let m = mem_arc.read();
        let uid = self.uid_for_mem(mem_arc).unwrap_or(u64::MAX);

        let children: Vec<MemCapInfoDto> = m.children.iter()
            .filter_map(|child_arc| {
                // Find local handle for the child in the owner's table.
                let owner_id = child_arc.read().owned.owner;
                if let Some(owner_arc) = self.domains.get(&owner_id) {
                    let h = find_memory_handle(owner_arc, child_arc).unwrap_or(u64::MAX);
                    self.build_mem_info(child_arc, h)
                } else {
                    None
                }
            })
            .collect();

        Some(MemCapInfoDto {
            uid,
            local_handle,
            start: m.data.access.start,
            end: m.data.access.end(),
            rights: format_rights_val(m.data.access.rights),
            kind: format!("{:?}", m.data.kind),
            status: format!("{:?}", m.data.status),
            attributes: format_attributes_val(m.owned.attributes),
            owner_id: m.owned.owner,
            num_children: m.children.len(),
            children,
        })
    }

    /// Remove revoked domains and their memory capabilities from our tables.
    fn cleanup_revoked(&mut self, batch: &UpdateBatch) {
        let revoked_domains: Vec<DomainId> = batch.updates().iter()
            .filter_map(|u| if let Update::RevokeDomain { domain, .. } = u { Some(*domain) } else { None })
            .collect();

        for domain_id in revoked_domains {
            self.domains.remove(&domain_id);
            // Remove memory capabilities owned by the revoked domain.
            let to_remove: Vec<MemCapUid> = self.mem_caps.iter()
                .filter(|(_, m)| m.read().owned.owner == domain_id)
                .map(|(&uid, _)| uid)
                .collect();
            for uid in to_remove {
                self.mem_caps.remove(&uid);
            }
        }
    }

    /// Remove mem_caps entries whose underlying capability tree node has been
    /// dropped (no children in any parent's children list). After revoke_child
    /// drops the subtree Arcs, the only remaining strong ref is in this table.
    /// A cap is stale if it has no parent (was removed from the tree).
    fn prune_stale_mem_caps(&mut self) {
        let stale: Vec<MemCapUid> = self.mem_caps.iter()
            .filter(|(_, arc)| {
                let cap = arc.read();
                // A revoked cap's parent link still exists, but the cap was
                // removed from the parent's children list. Detect this: if
                // the cap has a parent but the parent's children no longer
                // contain this cap, it's been revoked.
                cap.parent.upgrade().map_or(false, |parent| {
                    let p = parent.read();
                    !p.children.iter().any(|c| Arc::ptr_eq(c, arc))
                })
            })
            .map(|(&uid, _)| uid)
            .collect();
        for uid in stale {
            self.mem_caps.remove(&uid);
        }
    }
}

// ─── Policy identifier parsing ───────────────────────────────────────────────

fn parse_policy_id(s: &str) -> Result<PolicyIdentifier> {
    if s.eq_ignore_ascii_case("cores") {
        return Ok(PolicyIdentifier::Cores);
    }
    if s.eq_ignore_ascii_case("api-monitor") {
        return Ok(PolicyIdentifier::ApiMonitor);
    }
    if s.eq_ignore_ascii_case("default-visibility") {
        return Ok(PolicyIdentifier::DefaultInterruptVisibility);
    }
    if let Some(rest) = s.strip_prefix("vector-visibility:") {
        let v = rest.parse::<u8>().map_err(|_|
            BackendError::InvalidOperation(format!("Invalid vector: {}", rest)))?;
        return Ok(PolicyIdentifier::VectorVisibility(v));
    }
    if let Some(rest) = s.strip_prefix("vector-read:") {
        let (vec_str, word) = parse_vector_word(rest)?;
        let v = vec_str.parse::<u8>().map_err(|_|
            BackendError::InvalidOperation(format!("Invalid vector: {}", vec_str)))?;
        return Ok(PolicyIdentifier::VectorRegReadSet(v, word));
    }
    if let Some(rest) = s.strip_prefix("vector-write:") {
        let (vec_str, word) = parse_vector_word(rest)?;
        let v = vec_str.parse::<u8>().map_err(|_|
            BackendError::InvalidOperation(format!("Invalid vector: {}", vec_str)))?;
        return Ok(PolicyIdentifier::VectorRegWriteSet(v, word));
    }
    // Interposition: cpuid-default, msr-default
    if s.eq_ignore_ascii_case("cpuid-default") {
        return Ok(PolicyIdentifier::ProcFeatureDefault(ResourceKind::Cpuid));
    }
    if s.eq_ignore_ascii_case("msr-default") {
        return Ok(PolicyIdentifier::ProcFeatureDefault(ResourceKind::Msr));
    }
    // Interposition: cpuid-range:<start>-<end>, msr-range:<start>-<end>
    // CPUID ranges cover all subleaves (0..0xFFFFFFFF).
    if let Some(rest) = s.strip_prefix("cpuid-range:") {
        let (start, end) = parse_range_pair(rest)?;
        return Ok(PolicyIdentifier::ProcFeatureRange(
            ResourceKind::Cpuid, start, 0, end, u32::MAX,
        ));
    }
    if let Some(rest) = s.strip_prefix("msr-range:") {
        let (start, end) = parse_range_pair(rest)?;
        return Ok(PolicyIdentifier::ProcFeatureRange(ResourceKind::Msr, start, 0, end, 0));
    }
    // Interposition: cpuid-emulate:<leaf>.<subleaf>:<word>, msr-emulate:<addr>:<word>
    // For CPUID, subleaf defaults to 0 if omitted.
    if let Some(rest) = s.strip_prefix("cpuid-emulate:") {
        let (key_str, word) = parse_cpuid_emulate_pair(rest)?;
        let (leaf, subleaf) = parse_leaf_subleaf(key_str)?;
        return Ok(PolicyIdentifier::ProcFeatureEmulate(ResourceKind::Cpuid, leaf, subleaf, word));
    }
    if let Some(rest) = s.strip_prefix("msr-emulate:") {
        let (key, word) = parse_emulate_pair(rest)?;
        return Ok(PolicyIdentifier::ProcFeatureEmulate(ResourceKind::Msr, key, 0, word));
    }
    // Exit policy: exit-default-trap, exit-reason-trap:<reason>,
    // exit-read:<reason>:<word>, exit-write:<reason>:<word>
    if s.eq_ignore_ascii_case("exit-default-trap") {
        return Ok(PolicyIdentifier::DefaultExitTrap);
    }
    if let Some(rest) = s.strip_prefix("exit-reason-trap:") {
        let reason = rest.parse::<u32>().map_err(|_|
            BackendError::InvalidOperation(format!("Invalid exit reason: {}", rest)))?;
        return Ok(PolicyIdentifier::ExitReasonTrap(reason));
    }
    if let Some(rest) = s.strip_prefix("exit-read:") {
        let (reason_str, word) = parse_exit_reason_word(rest)?;
        let reason = reason_str.parse::<u32>().map_err(|_|
            BackendError::InvalidOperation(format!("Invalid exit reason: {}", reason_str)))?;
        return Ok(PolicyIdentifier::ExitReasonRegReadSet(reason, word));
    }
    if let Some(rest) = s.strip_prefix("exit-write:") {
        let (reason_str, word) = parse_exit_reason_word(rest)?;
        let reason = reason_str.parse::<u32>().map_err(|_|
            BackendError::InvalidOperation(format!("Invalid exit reason: {}", reason_str)))?;
        return Ok(PolicyIdentifier::ExitReasonRegWriteSet(reason, word));
    }
    Err(BackendError::InvalidOperation(format!("Unknown policy: '{}'", s)))
}

fn parse_vector_word(s: &str) -> Result<(&str, u8)> {
    if let Some((vec_part, word_part)) = s.split_once(':') {
        let w = word_part.parse::<u8>().map_err(|_|
            BackendError::InvalidOperation(format!("Invalid word index: {}", word_part)))?;
        if w >= 3 {
            return Err(BackendError::InvalidOperation(
                format!("Word index must be 0..2, got {}", w),
            ));
        }
        Ok((vec_part, w))
    } else {
        Ok((s, 0))
    }
}

/// Parse "reason:word" for exit policy reg read/write set.
fn parse_exit_reason_word(s: &str) -> Result<(&str, u8)> {
    if let Some((reason_part, word_part)) = s.split_once(':') {
        let w = word_part.parse::<u8>().map_err(|_|
            BackendError::InvalidOperation(format!("Invalid word index: {}", word_part)))?;
        if w >= 3 {
            return Err(BackendError::InvalidOperation(
                format!("Word index must be 0..2, got {}", w),
            ));
        }
        Ok((reason_part, w))
    } else {
        Ok((s, 0))
    }
}

/// Parse "start-end" into two u32s (hex with 0x prefix or decimal).
fn parse_range_pair(s: &str) -> Result<(u32, u32)> {
    let (a, b) = s.split_once('-').ok_or_else(|| {
        BackendError::InvalidOperation(format!("Expected start-end, got '{}'", s))
    })?;
    let start = parse_u32_flex(a)?;
    let end = parse_u32_flex(b)?;
    Ok((start, end))
}

/// Parse "key:word" into (u32, u8).
fn parse_emulate_pair(s: &str) -> Result<(u32, u8)> {
    let (key_str, word_str) = s.split_once(':').ok_or_else(|| {
        BackendError::InvalidOperation(format!("Expected key:word, got '{}'", s))
    })?;
    let key = parse_u32_flex(key_str)?;
    let word = word_str.parse::<u8>().map_err(|_| {
        BackendError::InvalidOperation(format!("Invalid word index: {}", word_str))
    })?;
    Ok((key, word))
}

/// Parse "leaf.subleaf" or just "leaf" (subleaf defaults to 0).
fn parse_leaf_subleaf(s: &str) -> Result<(u32, u32)> {
    if let Some((leaf_str, sub_str)) = s.split_once('.') {
        let leaf = parse_u32_flex(leaf_str)?;
        let sub = parse_u32_flex(sub_str)?;
        Ok((leaf, sub))
    } else {
        let leaf = parse_u32_flex(s)?;
        Ok((leaf, 0))
    }
}

/// Parse "key_with_dots:word" — splits on the LAST ':' so leaf.subleaf works.
fn parse_cpuid_emulate_pair(s: &str) -> Result<(&str, u8)> {
    let (key_str, word_str) = s.rsplit_once(':').ok_or_else(|| {
        BackendError::InvalidOperation(format!("Expected key:word, got '{}'", s))
    })?;
    let word = word_str.parse::<u8>().map_err(|_| {
        BackendError::InvalidOperation(format!("Invalid word index: {}", word_str))
    })?;
    Ok((key_str, word))
}

/// Parse a u32 from hex (0x...) or decimal.
fn parse_u32_flex(s: &str) -> Result<u32> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
    } else {
        s.parse::<u32>()
    }
    .map_err(|_| BackendError::InvalidOperation(format!("Invalid u32: '{}'", s)))
}
