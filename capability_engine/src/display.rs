use crate::capability::*;
use crate::domain::{
    CapaWrapper, Domain, InterruptPolicy, Policies, VectorPolicy, VectorVisibility, NB_INTERRUPTS,
};
use crate::memory_region::{Access, MemoryRegion, Remapped, Rights, ViewRegion};
use core::fmt;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::rc::Rc;

pub trait PrintWithNames<T> {
    fn fmt_with_names(
        &self,
        f: &mut fmt::Formatter,
        names: &mut HashMap<CapaKey<T>, String>,
        prefix: String,
        next_id: &mut usize,
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
        names: &mut HashMap<CapaKey<MemoryRegion>, String>,
        prefix: String,
        next_id: &mut usize,
    ) -> fmt::Result {
        let region = &self.data;

        // Print the main region
        write!(
            f,
            "{:?} {} mapped {}",
            region.status, region.access, region.remapped
        )?;

        // Print children recursively
        if !self.children.is_empty() {
            for (_, child) in self.children.iter().enumerate() {
                let name = if names.contains_key(&CapaKey(child.clone())) {
                    names.get(&CapaKey(child.clone())).unwrap().clone()
                } else {
                    // Generate a new name.
                    let name = format!("{}{}", prefix, *next_id);
                    *next_id += 1;
                    names.insert(CapaKey(child.clone()), name.clone());
                    name
                };
                let child_borrowed = child.borrow();
                write!(
                    f,
                    "\n| {:?} at {} for {}",
                    child_borrowed.data.kind, child_borrowed.data.access, name
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
        let mut names: HashMap<CapaKey<MemoryRegion>, String> = HashMap::new();
        self.fmt_with_names(f, &mut names, prefix, &mut next_id)
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
        names_td: &mut HashMap<CapaKey<Domain>, String>,
        next_td: &mut usize,
        names_regions: &mut HashMap<CapaKey<MemoryRegion>, String>,
        next_region: &mut usize,
    ) -> fmt::Result {
        write!(f, "{:?} domain(", self.data.status)?;
        let mut as_sorted_vector: Vec<_> = self.data.capabilities.capabilities.iter().collect();
        as_sorted_vector.sort_by_key(|(id, _)| *id);
        let regions: Vec<_> = as_sorted_vector
            .iter()
            .filter(|(_, x)| matches!(x, CapaWrapper::Region(_)))
            .collect();

        // Now build strings from those
        self.fmt_with_names(f, names_td, String::from("td"), next_td)?;

        if as_sorted_vector.len() != 0 && as_sorted_vector.len() != regions.len() {
            write!(f, ",")?;
        }
        // Print the regions.
        let mut region_print: Vec<String> = Vec::new();
        for r in regions {
            if let (_, CapaWrapper::Region(reg)) = r {
                if !names_regions.contains_key(&CapaKey(reg.clone())) {
                    names_regions.insert(CapaKey(reg.clone()), format!("r{}", *next_region));
                    *next_region += 1;
                }
                region_print.push(names_regions.get(&CapaKey(reg.clone())).unwrap().clone());
            }
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
        names: &mut HashMap<CapaKey<Domain>, String>,
        prefix: String,
        next_id: &mut usize,
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
                    names.insert(CapaKey(d.clone()), format!("{}{}", prefix, *next_id));
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
                    names.get(&CapaKey(d.clone())).cloned()
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
        let mut names_region: HashMap<CapaKey<MemoryRegion>, String> = HashMap::new();
        let mut names_td: HashMap<CapaKey<Domain>, String> = HashMap::new();
        as_sorted_vector.sort_by_key(|(id, _)| *id);

        // Keep actual capabilities separate
        let tds: Vec<_> = as_sorted_vector
            .iter()
            .filter(|(_, x)| matches!(x, CapaWrapper::Domain(_)))
            .collect();

        let regions: Vec<_> = as_sorted_vector
            .iter()
            .filter(|(_, x)| matches!(x, CapaWrapper::Region(_)))
            .collect();

        // Assign names to domain capabilities
        let mut next_td: usize = 1;
        let mut next_region: usize = 0;

        self.print_header(
            f,
            &mut names_td,
            &mut next_td,
            &mut names_region,
            &mut next_region,
        )?;

        // Print the domains.
        for td in tds {
            if let (_, CapaWrapper::Domain(d)) = td {
                if !names_td.contains_key(&CapaKey(d.clone())) {
                    names_td.insert(CapaKey(d.clone()), format!("td{}", next_td));
                    next_td += 1;
                }
                write!(f, "{} = ", names_td.get(&CapaKey(d.clone())).unwrap())?;
                d.borrow().print_header(
                    f,
                    &mut names_td,
                    &mut next_td,
                    &mut names_region,
                    &mut next_region,
                )?;
            }
        }
        // Print the regions.
        let mut sorted: Vec<(CapaRef<MemoryRegion>, String)> = names_region
            .iter()
            .map(|(k, v)| (k.0.clone(), v.clone()))
            .collect();

        // Now we can sort without borrowing names_region
        sorted.sort_by_key(|(_, v)| {
            v.strip_prefix('r')
                .and_then(|n| n.parse::<u32>().ok())
                .unwrap_or(0)
        });

        // Filter the regions to be printed.
        let mut region_set: HashSet<CapaKey<MemoryRegion>> = HashSet::new();
        for r in regions {
            if let (_, CapaWrapper::Region(reg)) = r {
                region_set.insert(CapaKey(reg.clone()));
                for c in &reg.borrow().children {
                    region_set.insert(CapaKey(c.clone()));
                }
            }
        }

        // Now iterate and print
        for (key, name) in sorted {
            if !region_set.contains(&CapaKey(key.clone())) {
                continue;
            }
            write!(f, "{} = ", name)?;
            let capa = key.borrow(); // no conflict anymore
            capa.fmt_with_names(f, &mut names_region, String::from("r"), &mut next_region)?;
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
