use crate::core::capability::*;
use crate::core::domain::{
    CapaWrapper, Domain, InterruptPolicy, Policies, VectorPolicy, VectorVisibility, NB_INTERRUPTS,
};
use crate::core::memory_region::{Access, MemoryRegion, Remapped, Rights, ViewRegion};
use core::fmt;
use std::collections::HashMap;

use super::capakey::CapaKey;
use super::memory_region::Attributes;

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
            self.rights,
        )
    }
}

impl fmt::Display for Attributes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.contains(Attributes::HASH) {
            write!(f, "H")?;
        }
        if self.contains(Attributes::CLEAN) {
            write!(f, "C")?;
        }
        if self.contains(Attributes::VITAL) {
            write!(f, "V")?;
        }
        Ok(())
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
        // Print the attributes is any
        if !region.attributes.is_empty() {
            write!(f, " {}", region.attributes)?;
        }

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

        // Print the local indices
        if as_sorted_vector.len() != 0 {
            write!(f, "|indices:")?;
            for (key, capa) in as_sorted_vector {
                match capa {
                    CapaWrapper::Region(r) => {
                        let name = names_region.get(&CapaKey(r.clone())).unwrap();
                        write!(f, " {}->r{}", key, name)?;
                    }
                    CapaWrapper::Domain(d) => {
                        let name = names_td.get(&CapaKey(d.clone())).unwrap();
                        write!(f, " {}->td{}", key, name)?;
                    }
                }
            }

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
