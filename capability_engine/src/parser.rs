use std::collections::HashMap;

use crate::display::Unmarshall;

use crate::domain::{CapabilityStore, InterruptPolicy, Policies};
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
    pub regions: HashMap<String, MemoryRegion>,
    pub owner: HashMap<String, String>,
    pub parent_children: HashMap<String, Vec<String>>,
    pub domains: HashMap<String, Domain>,
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
        while j < lines.len() && lines[j].starts_with("|") {
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
            self.indicies
                .insert(
                    sp[1].to_string(),
                    LocalCapa::from_str_radix(sp[0], 10).unwrap(),
                )
                .ok_or(CapaError::ParserCapability)
                .unwrap();
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
        let status = if header[2].to_lowercase().contains("sealed") {
            Status::Sealed
        } else if header[2].to_lowercase().contains("unsealed") {
            Status::Unsealed
        } else {
            return Err(CapaError::ParserDomain);
        };
        let capabilities: Vec<&str> = {
            let start = header[3].find('(').ok_or(CapaError::ParserDomain)?;
            let end = start
                + header[3][start..]
                    .find(")")
                    .ok_or(CapaError::InvalidValue)?;
            header[3][start + 1..end].split(",").collect()
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
        // Add the domain.
        self.domains.insert(
            name.to_string(),
            Domain {
                id: 0,
                status,
                capabilities: CapabilityStore::new(),
                policies: Policies::new(cores, api, inter_policy),
            },
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
        if input.trim().to_lowercase().contains("Identity") {
            return Ok(Remapped::Identity);
        }
        if !input.to_lowercase().contains("Remapped") {
            return Err(CapaError::ParserRegion);
        }
        let mut trimmed = input.trim().trim_start_matches("Remapped(");
        trimmed = &trimmed[0..trimmed.len() - 1];
        let addr = u64::from_str_radix(trimmed, 16).map_err(|_| CapaError::ParserRegion)?;
        Ok(Remapped::Remapped(addr))
    }

    pub fn parse_region_child(input: &str) -> Result<(String, MemoryRegion), CapaError> {
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
        let start = u64::from_str_radix(splitted[4].trim_start_matches("0x"), 16)
            .map_err(|_| CapaError::ParserRegion)?;
        let size = u64::from_str_radix(splitted[5].trim_start_matches("0x"), 16)
            .map_err(|_| CapaError::ParserRegion)?;
        let rights = Self::parse_rights(splitted[7])?;
        let access = Access::new(start, size, rights);
        let name = splitted.last().ok_or(CapaError::ParserRegion)?;
        if !name.starts_with("r") {
            return Err(CapaError::ParserRegion);
        }
        Ok((
            name.to_string(),
            MemoryRegion {
                kind,
                status: MStatus::Exclusive,
                access,
                attributes: Attributes::empty(),
                remapped: Remapped::Identity,
            },
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
        let size = u64::from_str_radix(header[4].trim().trim_start_matches("0x"), 16)
            .map_err(|_| CapaError::ParserRegion)?;
        let rights = Self::parse_rights(header[6])?;

        let access: Access = Access::new(start, size, rights);

        let remapped = Self::parse_remapped(header[8])?;

        let kind = if status == MStatus::Exclusive {
            RegionKind::Carve
        } else {
            RegionKind::Alias
        };

        let region = self
            .regions
            .entry(name.to_string())
            .or_insert(MemoryRegion {
                kind,
                status,
                access,
                attributes: Attributes::empty(),
                remapped,
            });
        // Make sure we set what might be missing, i.e., the status, remapped, and attributes.
        region.status = status;
        region.remapped = remapped;
        //region.attributes = ???;

        // Now parse the children and populate the map.
        for i in 1..input.len() {
            let (cname, child) = Self::parse_region_child(input[i])?;
            let entry = self.regions.entry(cname.clone()).or_insert(child.clone());
            entry.kind = child.kind;
            self.parent_children
                .entry(name.to_string())
                .or_insert_with(Vec::new)
                .push(cname.clone());
        }

        Ok(())
    }

    pub fn parse_attestation(&mut self, lines: &[&str]) -> Result<(), CapaError> {
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
            } else if lines[i].starts_with("|indicies:") {
                self.parse_indicies(lines[i])?;
                i += 1;
            }
        }
        // Now create the capabilities.
        todo!()
    }
}
