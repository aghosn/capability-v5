use crate::capability::*;
use crate::domain::{
    CapaWrapper, CapabilityStore, Domain, InterruptPolicy, MonitorAPI, Policies, Status,
    VectorPolicy, VectorVisibility, NB_INTERRUPTS,
};
use crate::memory_region::{Access, MemoryRegion, Remapped, Rights, ViewRegion};
use core::fmt;
use std::cell::RefCell;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::rc::Rc;

pub trait PrintWithNames<T> {
    fn fmt_with_names(
        &self,
        f: &mut fmt::Formatter,
        names: &mut HashMap<CapaKey<T>, usize>,
        prefix: String,
        next_id: &mut usize,
        full: bool,
    ) -> fmt::Result;
}

impl fmt::Display for Rights {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.contains(Rights::READ) {
            write!(f, "R")?;
        } else {
            write!(f, "_")?;
        }
        if self.contains(Rights::WRITE) {
            write!(f, "W")?;
        } else {
            write!(f, "_")?;
        }
        if self.contains(Rights::EXECUTE) {
            write!(f, "X")?;
        } else {
            write!(f, "_")?;
        }
        Ok(())
    }
}

impl fmt::Display for Remapped {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Remapped::Identity => write!(f, "Identity")?,
            Remapped::Remapped(x) => write!(f, "Remapped({:#x})", x)?,
        }
        Ok(())
    }
}

impl fmt::Display for Access {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:#x} {:#x} with {}",
            self.start,
            self.end(),
            self.rights
        )
    }
}

impl PrintWithNames<MemoryRegion> for Capability<MemoryRegion> {
    fn fmt_with_names(
        &self,
        f: &mut fmt::Formatter,
        names: &mut HashMap<CapaKey<MemoryRegion>, usize>,
        prefix: String,
        next_id: &mut usize,
        full: bool,
    ) -> fmt::Result {
        let region = &self.data;

        // Print the main region
        write!(
            f,
            "{:?} {} mapped {}",
            region.status, region.access, region.remapped
        )?;

        // Skip over the children.
        if !full {
            return Ok(());
        }
        // Print children recursively
        if !self.children.is_empty() {
            for (_, child) in self.children.iter().enumerate() {
                let name = if names.contains_key(&CapaKey(child.clone())) {
                    *names.get(&CapaKey(child.clone())).unwrap()
                } else {
                    // Generate a new name.
                    let name = *next_id;
                    *next_id += 1;
                    names.insert(CapaKey(child.clone()), name);
                    name
                };
                let child_borrowed = child.borrow();
                write!(
                    f,
                    "\n| {:?} at {} for {}{}",
                    child_borrowed.data.kind, child_borrowed.data.access, prefix, name
                )?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for Capability<MemoryRegion> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut next_id = 0;
        let prefix: String = String::from(".");
        let mut names: HashMap<CapaKey<MemoryRegion>, usize> = HashMap::new();
        self.fmt_with_names(f, &mut names, prefix, &mut next_id, true)
    }
}

impl fmt::Display for ViewRegion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} mapped {}", self.access, self.remap)
    }
}

// Identity wrapper
#[derive(Clone)]
pub struct CapaKey<T>(pub CapaRef<T>);

impl<T> PartialEq for CapaKey<T> {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

impl<T> Eq for CapaKey<T> {}

impl<T> Hash for CapaKey<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let ptr: *const RefCell<Capability<T>> = Rc::as_ptr(&self.0);
        ptr.hash(state);
    }
}

impl Capability<Domain> {
    pub fn print_header(
        &self,
        f: &mut fmt::Formatter,
        names_td: &mut HashMap<CapaKey<Domain>, usize>,
        next_td: &mut usize,
        names_regions: &mut HashMap<CapaKey<MemoryRegion>, usize>,
        next_region: &mut usize,
    ) -> fmt::Result {
        write!(f, "{:?} domain(", self.data.status)?;
        let mut as_sorted_vector: Vec<_> = self.data.capabilities.capabilities.iter().collect();
        as_sorted_vector.sort_by_key(|(id, _)| *id);
        let mut regions: Vec<_> = self
            .data
            .capabilities
            .capabilities
            .iter()
            .filter_map(|(_, x)| match x {
                CapaWrapper::Region(r) => {
                    if !names_regions.contains_key(&CapaKey(r.clone())) {
                        names_regions.insert(CapaKey(r.clone()), *next_region);
                        *next_region += 1;
                    }
                    Some(r)
                }
                _ => None,
            })
            .collect();
        regions.sort_by_key(|c| *names_regions.get(&CapaKey((*c).clone())).unwrap());

        // Now build strings from those
        self.fmt_with_names(f, names_td, String::from("td"), next_td, true)?;

        if as_sorted_vector.len() != 0
            && as_sorted_vector.len() != regions.len()
            && regions.len() != 0
        {
            write!(f, ",")?;
        }
        // Print the regions.
        let mut region_print: Vec<String> = Vec::new();
        for r in regions {
            let r_name = names_regions.get(&CapaKey(r.clone())).unwrap();
            region_print.push(format!("r{}", r_name));
        }
        writeln!(f, "{})", region_print.join(","))?;
        // Print policies
        write!(f, "{}", self.data.policies)
    }
}

impl PrintWithNames<Domain> for Capability<Domain> {
    fn fmt_with_names(
        &self,
        f: &mut fmt::Formatter,
        names: &mut HashMap<CapaKey<Domain>, usize>,
        prefix: String,
        next_id: &mut usize,
        _full: bool,
    ) -> fmt::Result {
        let as_sorted_vector: Vec<_> = self.data.capabilities.capabilities.iter().collect();
        let tds: Vec<_> = as_sorted_vector
            .iter()
            .filter(|(_, x)| matches!(x, CapaWrapper::Domain(_)))
            .collect();

        // Insert names for the "tds" domains into the HashMap
        for (_, wrapper) in &tds {
            if let CapaWrapper::Domain(ref d) = wrapper {
                // Only insert if the key does not exist
                if !names.contains_key(&CapaKey(d.clone())) {
                    names.insert(CapaKey(d.clone()), *next_id);
                    *next_id += 1;
                }
            }
        }

        // Now build strings only for the domains that are in `names`
        let tds_display: Vec<String> = tds
            .iter()
            .filter_map(|(_, wrapper)| {
                if let CapaWrapper::Domain(ref d) = wrapper {
                    // Get the name from `names` based on the domain
                    let name = names.get(&CapaKey(d.clone())).unwrap();
                    Some(format!("{}{}", prefix, *name))
                } else {
                    None
                }
            })
            .collect();

        // Print the names
        write!(f, "{}", tds_display.join(","))
    }
}

impl fmt::Display for Capability<Domain> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "td0 = ")?;
        let mut as_sorted_vector: Vec<_> = self.data.capabilities.capabilities.iter().collect();
        let mut names_region: HashMap<CapaKey<MemoryRegion>, usize> = HashMap::new();
        let mut names_td: HashMap<CapaKey<Domain>, usize> = HashMap::new();
        as_sorted_vector.sort_by_key(|(id, _)| *id);
        // Assign names to domain capabilities
        let mut next_td: usize = 1;
        let mut next_region: usize = 0;

        // Keep actual capabilities separate
        let mut tds: Vec<_> = self.children.iter().collect();

        let mut regions: Vec<_> = as_sorted_vector
            .iter()
            .filter_map(|(_, x)| match x {
                CapaWrapper::Region(r) => {
                    // Let generate names now.
                    names_region.insert(CapaKey(r.clone()), next_region);
                    next_region += 1;
                    Some(r)
                }
                _ => None,
            })
            .collect();

        // Sort the regions by name.
        regions.sort_by_key(|c| names_region.get(&CapaKey((*c).clone())).unwrap());

        // Give names to children regions first.
        for r in &regions {
            let reg = &r.borrow();
            for c in &reg.children {
                if !names_region.contains_key(&CapaKey(c.clone())) {
                    names_region.insert(CapaKey(c.clone()), next_region);
                    next_region += 1;
                }
            }
        }

        // Now we can go through the header of the current capa.
        self.print_header(
            f,
            &mut names_td,
            &mut next_td,
            &mut names_region,
            &mut next_region,
        )?;

        tds.sort_by_key(|td| {
            if !names_td.contains_key(&CapaKey((*td).clone())) {
                names_td.insert(CapaKey((*td).clone()), next_td);
                next_td += 1;
            }
            *names_td.get(&CapaKey((*td).clone())).unwrap()
        });
        for td in tds {
            write!(f, "td{} = ", names_td.get(&CapaKey(td.clone())).unwrap())?;
            td.borrow().print_header(
                f,
                &mut names_td,
                &mut next_td,
                &mut names_region,
                &mut next_region,
            )?;
        }

        // Print the regions.
        let mut regions_sorted: Vec<(CapaRef<MemoryRegion>, usize)> = names_region
            .iter()
            .map(|(k, v)| (k.0.clone(), *v))
            .collect();

        // Now we can sort without borrowing names_region
        regions_sorted.sort_by_key(|(_, v)| *v);

        // Filter the regions to be printed.
        let mut region_set: HashMap<CapaKey<MemoryRegion>, bool> = HashMap::new();
        for r in regions {
            region_set.insert(CapaKey(r.clone()), true);
            for c in &r.borrow().children {
                // If we do not own the child region anymore.
                if !region_set.contains_key(&CapaKey(c.clone())) {
                    region_set.insert(CapaKey(c.clone()), false);
                }
            }
        }

        // Now iterate and print
        for (key, name) in regions_sorted {
            if !region_set.contains_key(&CapaKey(key.clone())) {
                continue;
            }
            write!(f, "r{} = ", name)?;
            let full = *region_set.get(&CapaKey(key.clone())).unwrap();
            let capa = key.borrow(); // no conflict anymore
            capa.fmt_with_names(
                f,
                &mut names_region,
                String::from("r"),
                &mut next_region,
                full,
            )?;
            write!(f, "\n")?;
        }

        Ok(())
    }
}

impl fmt::Display for Policies {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "|cores: {:#x}", self.cores)?;
        writeln!(f, "|mon.api: {:#x}", self.api.bits())?;
        write!(f, "{}", self.interrupts)
    }
}

impl fmt::Display for InterruptPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut start = 0;
        let mut vector = &self.vectors[0];

        for i in 1..NB_INTERRUPTS {
            if &self.vectors[i] == vector {
                continue;
            }

            // Print the range [start, i - 1] and the associated policy
            if start == i - 1 {
                writeln!(f, "|vec{}: {}", start, vector)?;
            } else {
                writeln!(f, "|vec{}-{}: {}", start, i - 1, vector)?;
            }

            // Update start and vector for the next range
            start = i;
            vector = &self.vectors[i];
        }

        // Print the final range
        if start == NB_INTERRUPTS - 1 {
            writeln!(f, "|vec{}: {}", start, vector)?;
        } else {
            writeln!(f, "|vec{}-{}: {}", start, NB_INTERRUPTS - 1, vector)?;
        }

        Ok(())
    }
}

impl fmt::Display for VectorPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}, r: {:#x}, w: {:#x}",
            self.visibility, self.read_set, self.write_set
        )
    }
}

impl fmt::Display for VectorVisibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.bits() {
            0 => write!(f, "NOT REPORTED"),
            1 => write!(f, "ALLOWED"),
            2 => write!(f, "VISIBLE"),
            3 => write!(f, "ALLOWED|VISIBLE"),
            _ => write!(f, "INVALID({:#b})", self.bits()),
        }
    }
}

// ——————————————————————————————— Unmarshall ——————————————————————————————— //

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

impl Unmarshall for Domain {
    type Output = Domain;

    //TODO: cut that down into smaller bits.
    fn from_string(input: String) -> Result<Domain, CapaError> {
        let lines: Vec<&str> = input.lines().collect();
        if lines.len() < 4 {
            return Err(CapaError::InvalidValue);
        }

        // Parse the status
        let status = {
            let first: Vec<&str> = lines
                .get(0)
                .ok_or(CapaError::InvalidValue)?
                .split_whitespace()
                .filter(|x| {
                    x.to_lowercase().contains("sealed") || x.to_lowercase().contains("unsealed")
                })
                .collect();
            Status::from_string(first.get(0).ok_or(CapaError::ParserStatus)?.to_string())?
        };
        // Parse the cores.
        let cores = {
            let mask = lines
                .get(1)
                .ok_or(CapaError::InvalidValue)?
                .trim_start_matches("|cores: 0x");
            u64::from_str_radix(mask, 16).map_err(|_| CapaError::InvalidValue)?
        };

        // Parse the API calls.
        let api =
            MonitorAPI::from_string(lines.get(2).ok_or(CapaError::InvalidValue)?.to_string())?;

        // Parse the interrupt policies.
        let mut inter_policy: InterruptPolicy = InterruptPolicy::default_none();

        for l in lines.iter().skip(3) {
            if !l.starts_with("|vec") {
                break;
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
                let value =
                    usize::from_str_radix(parts[0], 10).map_err(|_| CapaError::InvalidValue)?;
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
                inter_policy.vectors[j] = VectorPolicy {
                    visibility,
                    read_set: read,
                    write_set: write,
                };
            }
        }
        Ok(Domain {
            id: 0,
            status,
            capabilities: CapabilityStore::new(),
            policies: Policies::new(cores, api, inter_policy),
        })
    }
}
