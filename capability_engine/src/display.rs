use crate::capability::*;
use crate::domain::{
    CapaWrapper, Domain, InterruptPolicy, Policies, VectorPolicy, VectorVisibility, NB_INTERRUPTS,
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

impl fmt::Display for Capability<Domain> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} = {:?} domain(", self.data.id, self.data.status)?;
        let mut as_sorted_vector: Vec<_> = self.data.capabilities.capabilities.iter().collect();
        let mut names_region: HashMap<CapaKey<MemoryRegion>, String> = HashMap::new();
        let mut names_domains: HashMap<CapaKey<Domain>, String> = HashMap::new();
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
        let mut td_idx = 0;
        for (_, wrapper) in &tds {
            if let CapaWrapper::Domain(ref d) = wrapper {
                names_domains.insert(CapaKey(d.clone()), format!("td{}", td_idx));
                td_idx += 1;
            }
        }

        // Assign names to region capabilities
        let mut region_idx = 0;
        for (_, wrapper) in &regions {
            if let CapaWrapper::Region(ref r) = wrapper {
                names_region.insert(CapaKey(r.clone()), format!("r{}", region_idx));
                region_idx += 1;
            }
        }

        // Now build strings from those
        let tds_display: Vec<String> = names_domains.iter().map(|(_, name)| name.clone()).collect();
        // Print them
        write!(f, "{}", tds_display.join(","))?;

        let regions_display: Vec<String> =
            names_region.iter().map(|(_, name)| name.clone()).collect();
        if !tds_display.is_empty() && !regions_display.is_empty() {
            write!(f, ",")?;
        }
        write!(f, "{}", regions_display.join(","))?;
        writeln!(f, ")")?;

        // Print policies
        write!(f, "{}", self.data.policies)?;

        // TODO print the domains.

        //Now start printing the regions.
        if !names_region.is_empty() {
            let mut regions_sorted: Vec<_> = names_region.iter().collect();
            regions_sorted.sort_by_key(|(_, name)| *name);

            let regions_formatted: Vec<String> = regions_sorted
                .iter()
                .map(|(key, name)| format!("{} = {}", name, key.0.borrow()))
                .collect();

            writeln!(f, "{}", regions_formatted.join("\n"))?;
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
                writeln!(f, "|vec{}–{}: {}", start, i - 1, vector)?;
            }

            // Update start and vector for the next range
            start = i;
            vector = &self.vectors[i];
        }

        // Print the final range
        if start == NB_INTERRUPTS - 1 {
            writeln!(f, "vec{}: {}", start, vector)?;
        } else {
            writeln!(f, "vec{}–{}: {}", start, NB_INTERRUPTS - 1, vector)?;
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
