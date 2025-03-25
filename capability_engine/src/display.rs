// display_impl.rs
use crate::{Access, Capability, MemoryRegion, Rights};
use core::fmt;

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
            "{:?} {} mapped {:?}",
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
