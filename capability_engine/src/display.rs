use crate::capability::*;
use crate::domain::{CapaWrapper, Domain};
use crate::memory_region::{Access, MemoryRegion, Remapped, Rights, ViewRegion};
use core::fmt;
use std::cell::RefCell;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::rc::Rc;

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

impl fmt::Display for Capability<MemoryRegion> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let region = &self.data;

        // Print the main region
        write!(
            f,
            "{:?} {} mapped {}",
            region.status, region.access, region.remapped
        )?;

        // Print children recursively
        if !self.children.is_empty() {
            for (i, child) in self.children.iter().enumerate() {
                let child_borrowed = child.borrow();
                write!(
                    f,
                    "\n| {:?} at {} for .{}",
                    child_borrowed.data.kind, child_borrowed.data.access, i
                )?;
            }
        }
        Ok(())
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
        write!(f, "{} = domain(", self.data.id)?;
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
        write!(f, ")")?;

        //TODO: Now start printing the regions.

        Ok(())
    }
}
