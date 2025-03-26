use std::collections::{HashMap, VecDeque};

use crate::capability::{CapaError, CapaRef};
use crate::memory_region::MemoryRegion;
use bitflags::bitflags;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

bitflags! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub struct MonitorAPI: u16 {
        const CREATE    = 0b001;
        const SET       = 0b010;
        const GET       = 0b100;
        const SEND      = 0b1000;
        const SEAL      = 0b10000;
        const ATTEST    = 0b100000;
        const ENUMERATE = 0b1000000;
        const SWITCH    = 0b10000000;
        const CARVE     = 0b100000000;
        const ALIAS     = 0b1000000000;
        const REVOKE    = 0b10000000000;
        const GETCHAN   = 0b100000000000;
        const RECEIVE   = 0b1000000000000;
    }
}

bitflags! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub struct VectorVisibility: u8 {
        const ALLOWED = 0b1;
        const VISIBLE = 0b10;
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Status {
    Unsealed,
    Sealed,
}

pub struct Policies {
    pub cores: u64,
    pub api: MonitorAPI,
    pub interrupts: InterruptPolicy,
}

impl Policies {
    pub fn new(cores: u64, api: MonitorAPI, interrupts: InterruptPolicy) -> Self {
        Policies {
            cores,
            api,
            interrupts,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct VectorPolicy {
    pub visibility: VectorVisibility,
    pub read_set: u64,
    pub write_set: u64,
}

pub const NB_INTERRUPTS: usize = 256;

pub struct InterruptPolicy {
    pub vectors: [VectorPolicy; NB_INTERRUPTS],
}

impl InterruptPolicy {
    pub fn default_none() -> Self {
        InterruptPolicy {
            vectors: [VectorPolicy {
                visibility: VectorVisibility::empty(),
                read_set: !(0 as u64),
                write_set: !(0 as u64),
            }; 256],
        }
    }
    pub fn default_all() -> Self {
        InterruptPolicy {
            vectors: [VectorPolicy {
                visibility: VectorVisibility::all(),
                read_set: 0,
                write_set: 0,
            }; 256],
        }
    }
}

/// For the moment define a handle
pub type LocalCapa = u64;

/// The structure to manipulate capabilities.
pub enum CapaWrapper {
    Region(CapaRef<MemoryRegion>),
    Domain(CapaRef<Domain>),
}

impl CapaWrapper {
    pub fn as_domain(&self) -> Result<CapaRef<Domain>, CapaError> {
        if let CapaWrapper::Domain(d) = self {
            return Ok(d.clone());
        }
        return Err(CapaError::WrongCapaType);
    }
    pub fn as_region(&self) -> Result<CapaRef<MemoryRegion>, CapaError> {
        if let CapaWrapper::Region(r) = self {
            return Ok(r.clone());
        }
        return Err(CapaError::WrongCapaType);
    }
}

pub struct CapabilityStore {
    pub capabilities: HashMap<LocalCapa, CapaWrapper>,
    pub next_handle: LocalCapa,
    pub free_handles: VecDeque<LocalCapa>,
}

impl CapabilityStore {
    pub fn new() -> Self {
        CapabilityStore {
            capabilities: HashMap::new(),
            next_handle: 1,
            free_handles: VecDeque::new(),
        }
    }
    pub fn install_capability(&mut self, cap: CapaWrapper) -> LocalCapa {
        let handle = if let Some(recycled) = self.free_handles.pop_front() {
            recycled
        } else {
            let h = self.next_handle;
            self.next_handle += 1;
            h
        };
        self.capabilities.insert(handle, cap);
        handle
    }
    pub fn remove(&mut self, handle: &LocalCapa) -> Result<CapaWrapper, CapaError> {
        if let Some(cap) = self.capabilities.remove(handle) {
            self.free_handles.push_back(*handle);
            return Ok(cap);
        }
        Err(CapaError::InvalidLocalCapa)
    }

    pub fn get(&self, handle: &LocalCapa) -> Result<&CapaWrapper, CapaError> {
        self.capabilities
            .get(handle)
            .ok_or(CapaError::InvalidLocalCapa)
    }
}

pub struct Domain {
    pub id: u64,
    pub status: Status,
    pub capabilities: CapabilityStore,
    pub policies: Policies,
}

impl PartialEq for Domain {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Domain {
    pub fn new(policies: Policies) -> Self {
        Domain {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            status: Status::Unsealed,
            capabilities: CapabilityStore::new(),
            policies,
        }
    }
    pub fn is_sealed(&self) -> bool {
        return self.status == Status::Sealed;
    }
    pub fn install(&mut self, capa: CapaWrapper) -> LocalCapa {
        self.capabilities.install_capability(capa)
    }

    pub fn remove(&mut self, capa: LocalCapa) -> Result<CapaWrapper, CapaError> {
        self.capabilities.remove(&capa)
    }

    pub fn is_domain(&self, capa: LocalCapa) -> Result<bool, CapaError> {
        if let CapaWrapper::Domain(_) = self.capabilities.get(&capa)? {
            return Ok(true);
        }
        Ok(false)
    }

    pub fn is_region(&self, capa: LocalCapa) -> Result<bool, CapaError> {
        if let CapaWrapper::Region(_) = self.capabilities.get(&capa)? {
            return Ok(true);
        }
        return Ok(false);
    }

    pub fn operation_allowed(&self, apicall: MonitorAPI) -> bool {
        self.policies.api.contains(apicall)
    }
}
