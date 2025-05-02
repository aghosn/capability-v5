use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use crate::capability::{CapaRef, Capability, Ownership};

use crate::domain::{
    CapaWrapper, CapabilityStore, InterruptPolicy, Policies, VectorPolicy, VectorVisibility,
};
use crate::memory_region::{Access, Attributes, RegionKind, Remapped, Rights, Status as MStatus};
use crate::{
    capability::CapaError,
    domain::{Domain, LocalCapa, MonitorAPI, Status},
    memory_region::MemoryRegion,
};

pub enum ParserChild {
    Carve(String),
    Alias(String),
}

pub struct Parser {
    pub regions: HashMap<String, CapaRef<MemoryRegion>>,
    pub owner: HashMap<String, String>,
    pub parent_children: HashMap<String, Vec<String>>,
    pub domains: HashMap<String, CapaRef<Domain>>,
    pub indicies: HashMap<String, LocalCapa>,
}

impl Parser {
    pub fn new() -> Self {
        Self {
            regions: HashMap::new(),
            owner: HashMap::new(),
            parent_children: HashMap::new(),
            domains: HashMap::new(),
            indicies: HashMap::new(),
        }
    }

    pub fn find_end(lines: &[&str], start: usize) -> usize {
        let mut j = start + 1;
        while j < lines.len() && lines[j].starts_with("|") && !lines[j].starts_with("|indices:") {
            j += 1;
        }
        return j;
    }

    pub fn parse_indicies(&mut self, line: &str) -> Result<(), CapaError> {
        if !line.starts_with("|indices: ") {
            return Err(CapaError::ParserCapability);
        }

        let line = line.trim_start_matches("|indices: ");
        line.split_whitespace().for_each(|e| {
            let sp: Vec<&str> = e.split("->").collect();
            if sp.len() != 2 {
                panic!("Invalid length {}", sp.len());
            }
            self.indicies.insert(
                sp[1].to_string(),
                LocalCapa::from_str_radix(sp[0], 10).unwrap(),
            );
        });
        Ok(())
    }

    pub fn parse_domain(&mut self, lines: &[&str]) -> Result<(), CapaError> {
        if lines.len() < 4 {
            return Err(CapaError::ParserDomain);
        }
        // Should be tdX = STATUS domain(CAPAS)
        let header: Vec<&str> = lines[0].split_whitespace().collect();
        let name = header[0].trim();
        let status = Status::from_string(header[2].to_string())?;
        let capabilities: Vec<&str> = {
            let start = header[3].find('(').ok_or(CapaError::ParserDomain)?;
            let end = start
                + header[3][start..]
                    .find(")")
                    .ok_or(CapaError::InvalidValue)?;
            header[3][start + 1..end]
                .split(",")
                .filter(|s| s.len() > 0)
                .collect()
        };
        // Add the children now so it's done.
        for c in capabilities {
            self.owner.insert(c.to_string(), name.to_string());
            if !c.starts_with("td") {
                continue;
            }
            self.parent_children
                .entry(name.to_string())
                .or_insert_with(Vec::new)
                .push(c.to_string());
        }

        // Now parse the next lines.
        if !lines[1].starts_with("|cores: 0x") {
            return Err(CapaError::ParserDomain);
        }
        let cores = {
            let mask = lines[1].trim_start_matches("|cores: 0x");
            u64::from_str_radix(mask, 16).map_err(|_| CapaError::ParserDomain)?
        };
        let api = MonitorAPI::from_string(lines[2].to_string())?;

        // Parse the interrupt policies.
        let mut inter_policy: InterruptPolicy = InterruptPolicy::default_none();

        for l in lines[3..].iter() {
            if !l.starts_with("|vec") {
                break;
            }
            inter_policy.parse_one(l.to_string())?;
        }
        let domain = Domain {
            id: 0,
            status,
            capabilities: CapabilityStore::new(),
            policies: Policies::new(cores, api, inter_policy),
        };
        // Add the domain.
        self.domains.insert(
            name.to_string(),
            CapaRef::new(RefCell::new(Capability::<Domain>::new(domain))),
        );
        Ok(())
    }

    pub fn parse_rights(input: &str) -> Result<Rights, CapaError> {
        let mut rights = Rights::empty();
        if input.contains("R") {
            rights |= Rights::READ;
        }
        if input.contains("W") {
            rights |= Rights::WRITE;
        }
        if input.contains("W") {
            rights |= Rights::EXECUTE;
        }
        Ok(rights)
    }

    pub fn parse_remapped(input: &str) -> Result<Remapped, CapaError> {
        if input.trim().contains("Identity") {
            return Ok(Remapped::Identity);
        }
        if !input.contains("Remapped") {
            return Err(CapaError::ParserRegion);
        }
        let mut trimmed = input.trim().trim_start_matches("Remapped(0x");
        trimmed = &trimmed[0..trimmed.len() - 1];
        let addr = u64::from_str_radix(trimmed, 16).map_err(|_| CapaError::ParserRegion)?;
        Ok(Remapped::Remapped(addr))
    }

    pub fn parse_region_child(input: &str) -> Result<(String, CapaRef<MemoryRegion>), CapaError> {
        let kind = if input.starts_with("| Alias") {
            RegionKind::Alias
        } else if input.starts_with("| Carve") {
            RegionKind::Carve
        } else {
            return Err(CapaError::ParserRegion);
        };
        let splitted: Vec<&str> = input.split_whitespace().collect();
        if splitted.len() != 9 {
            return Err(CapaError::ParserRegion);
        }

        let start = u64::from_str_radix(splitted[3].trim_start_matches("0x"), 16)
            .map_err(|_| CapaError::ParserRegion)?;
        let end = u64::from_str_radix(splitted[4].trim_start_matches("0x"), 16)
            .map_err(|_| CapaError::ParserRegion)?;
        if end <= start {
            return Err(CapaError::InvalidValue);
        }
        let rights = Self::parse_rights(splitted[6])?;
        let access = Access::new(start, end - start, rights);
        let name = splitted.last().ok_or(CapaError::ParserRegion)?;
        if !name.starts_with("r") {
            return Err(CapaError::ParserRegion);
        }
        Ok((
            name.to_string(),
            CapaRef::new(RefCell::new(Capability::<MemoryRegion>::new(
                MemoryRegion {
                    kind,
                    status: MStatus::Exclusive,
                    access,
                    attributes: Attributes::empty(),
                    remapped: Remapped::Identity,
                },
            ))),
        ))
    }

    pub fn parse_region(&mut self, input: &[&str]) -> Result<(), CapaError> {
        if input.len() == 0 || !input[0].starts_with("r") {
            return Err(CapaError::ParserDomain);
        }
        let header: Vec<&str> = input[0].split_whitespace().collect();
        if header.len() != 9 {
            return Err(CapaError::ParserRegion);
        }
        let name = header[0];
        let status = if header[2].to_lowercase().contains("exclusive") {
            MStatus::Exclusive
        } else if header[2].to_lowercase().contains("aliased") {
            MStatus::Aliased
        } else {
            return Err(CapaError::ParserRegion);
        };
        let start = u64::from_str_radix(header[3].trim().trim_start_matches("0x"), 16)
            .map_err(|_| CapaError::ParserRegion)?;
        let end = u64::from_str_radix(header[4].trim().trim_start_matches("0x"), 16)
            .map_err(|_| CapaError::ParserRegion)?;
        if end <= start {
            return Err(CapaError::InvalidValue);
        }
        let rights = Self::parse_rights(header[6])?;

        let access: Access = Access::new(start, end - start, rights);

        let remapped = Self::parse_remapped(header[8])?;

        let kind = if status == MStatus::Exclusive {
            RegionKind::Carve
        } else {
            RegionKind::Alias
        };

        let region = self
            .regions
            .entry(name.to_string())
            .or_insert(CapaRef::new(RefCell::new(Capability::<MemoryRegion>::new(
                MemoryRegion {
                    kind,
                    status,
                    access,
                    attributes: Attributes::empty(),
                    remapped,
                },
            ))));
        // Make sure we set what might be missing, i.e., the status, remapped, and attributes.
        region.borrow_mut().data.status = status;
        region.borrow_mut().data.remapped = remapped;
        //region.attributes = ???;

        // Now parse the children and populate the map.
        for i in 1..input.len() {
            let (cname, child) = Self::parse_region_child(input[i])?;
            if self.regions.contains_key(&cname) {
                let entry = self
                    .regions
                    .get_mut(&cname)
                    .ok_or(CapaError::ParserRegion)?;
                entry.borrow_mut().data.kind = child.borrow_mut().data.kind;
            } else {
                self.regions.insert(cname.clone(), child);
            }
            self.parent_children
                .entry(name.to_string())
                .or_insert_with(Vec::new)
                .push(cname.clone());
        }

        Ok(())
    }

    pub fn parse_attestation(&mut self, attestation: String) -> Result<(), CapaError> {
        let lines: Vec<&str> = attestation.lines().collect();
        self.parse_attestation_internal(&lines)
    }

    fn parse_attestation_internal(&mut self, lines: &Vec<&str>) -> Result<(), CapaError> {
        let mut i: usize = 0;
        while i < lines.len() {
            if lines[i].starts_with("td") {
                let end = Self::find_end(lines, i);
                self.parse_domain(&lines[i..end])?;
                i = end;
            } else if lines[i].starts_with("r") {
                let end = Self::find_end(lines, i);
                self.parse_region(&lines[i..end])?;
                i = end;
            } else if lines[i].starts_with("|indices:") {
                self.parse_indicies(lines[i])?;
                i += 1;
            } else {
                break;
            }
        }
        // Now create the tree for the capabilities.
        for (k, v) in self.parent_children.iter() {
            if k.starts_with("td") {
                let parent = self.domains.get(k).ok_or(CapaError::ParserCapability)?;
                for c in v.iter() {
                    if !self.domains.contains_key(c) {
                        continue;
                    }
                    let child = self.domains.get(c).unwrap();
                    parent.borrow_mut().children.push(child.clone());
                    child.borrow_mut().parent = Rc::downgrade(parent);
                }
            } else if k.starts_with("r") {
                let parent = self.regions.get(k).ok_or(CapaError::ParserCapability)?;
                for c in v.iter() {
                    if !self.regions.contains_key(c) {
                        continue;
                    }
                    let child = self.regions.get(c).unwrap();
                    parent.borrow_mut().children.push(child.clone());
                    child.borrow_mut().parent = Rc::downgrade(parent);
                }
            }
        }
        let td0 = self.domains.get("td0").ok_or(CapaError::ParserDomain)?;
        // Now use the indicies to set ownership.
        for (k, v) in self.indicies.iter() {
            let capa_wrapper = if k.starts_with("td") {
                let dom = self.domains.get(k).ok_or(CapaError::ParserDomain)?;
                dom.borrow_mut().owned = Ownership::new(Rc::downgrade(td0), *v);
                CapaWrapper::Domain(dom.clone())
            } else {
                let reg = self.regions.get(k).ok_or(CapaError::ParserRegion)?;
                reg.borrow_mut().owned = Ownership::new(Rc::downgrade(td0), *v);
                CapaWrapper::Region(reg.clone())
            };

            td0.borrow_mut()
                .data
                .capabilities
                .capabilities
                .insert(*v, capa_wrapper);
        }

        // Should setup the rest of the domains too?
        for (capa, owner) in self.owner.iter() {
            if owner.contains("td0") {
                // We already did it
                continue;
            }
            let dom_owner = self
                .domains
                .get(owner)
                .ok_or(CapaError::InvalidValue)
                .unwrap();

            let wrapper = if capa.starts_with("td") {
                let dom = self
                    .domains
                    .get(capa)
                    .ok_or(CapaError::InvalidValue)
                    .unwrap();
                CapaWrapper::Domain(dom.clone())
            } else {
                println!("About to get {} from {:?} ", capa, self.owner);
                let reg = self
                    .regions
                    .get(capa)
                    .ok_or(CapaError::InvalidValue)
                    .unwrap();
                CapaWrapper::Region(reg.clone())
            };
            dom_owner.borrow_mut().data.install(wrapper);
        }
        Ok(())
    }
}

// —————————————————————— Unmarshall specific elements —————————————————————— //
pub trait Unmarshall {
    type Output;
    fn from_string(input: String) -> Result<Self::Output, CapaError>;
}

impl Unmarshall for Status {
    type Output = Status;
    fn from_string(input: String) -> Result<Self::Output, CapaError> {
        match input.trim().to_lowercase().as_str() {
            "sealed" => Ok(crate::domain::Status::Sealed),
            "unsealed" => Ok(crate::domain::Status::Unsealed),
            _ => return Err(CapaError::ParserStatus),
        }
    }
}

impl Unmarshall for MonitorAPI {
    type Output = MonitorAPI;
    fn from_string(input: String) -> Result<Self::Output, CapaError> {
        let value = input.trim_start_matches("|mon.api: 0x");
        let raw = u64::from_str_radix(value, 16).map_err(|_| CapaError::ParserMonitor)?;
        MonitorAPI::from_bits(raw as u16).ok_or(CapaError::ParserMonitor)
    }
}

impl InterruptPolicy {
    pub fn parse_one(&mut self, l: String) -> Result<(), CapaError> {
        if !l.starts_with("|vec") {
            return Err(CapaError::InvalidValue);
        }
        let prefix = l.strip_prefix("|vec").ok_or(CapaError::InvalidValue)?;
        let parts: Vec<&str> = prefix.split(',').collect();
        if parts.len() != 3 {
            return Err(CapaError::InvalidValue);
        }

        let tmp: Vec<&str> = parts[0].split(':').collect();
        let (range, visi) = (tmp[0].trim_start_matches("|vec"), tmp[1]);
        // We have the start and end vector.
        let (vs, ve) = if let Some((start, end)) = range.split_once('-') {
            (
                usize::from_str_radix(start, 10).map_err(|_| CapaError::InvalidValue)?,
                usize::from_str_radix(end, 10).map_err(|_| CapaError::InvalidValue)?,
            )
        } else {
            let value = usize::from_str_radix(range, 10).map_err(|_| CapaError::InvalidValue)?;
            (value, value)
        };

        let visibility = match visi.trim().to_lowercase().as_str() {
            "allowed|visible" => VectorVisibility::all(),
            "allowed" => VectorVisibility::ALLOWED,
            "visible" => VectorVisibility::VISIBLE,
            "not reported" => VectorVisibility::empty(),
            _ => return Err(CapaError::InvalidValue),
        };

        let read = u64::from_str_radix(parts[1].trim_start_matches(" r: 0x"), 16)
            .map_err(|_| CapaError::InvalidValue)
            .unwrap();
        let write = u64::from_str_radix(parts[2].trim_start_matches(" w: 0x"), 16)
            .map_err(|_| CapaError::InvalidValue)
            .unwrap();

        // Now set the values
        for j in vs..=ve {
            self.vectors[j] = VectorPolicy {
                visibility,
                read_set: read,
                write_set: write,
            };
        }
        Ok(())
    }
}
