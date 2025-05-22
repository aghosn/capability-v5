use std::collections::{HashMap, HashSet};

use super::{
    capability::{CapaError, WeakRef},
    capakey::WeakKey,
    coalesced::CoalescedView,
    domain::Domain,
};

// Encodes the updates of memory operations.
pub enum Update {
    // Zero-out a region.
    Clean { start: u64, size: u64 },
    // Revoke the domain
    Revoke { dom: WeakRef<Domain> },
    // Change in memory mappings for a domain.
    ChangeMemory { dom: WeakRef<Domain> },
}

//TODO: implement this.
pub enum CoreUpdate {}

// This structure maintains updates during an operation and attempts to keep them compact.
pub struct OperationUpdate {
    pub to_clean: Vec<Update>,
    pub to_revoke: HashSet<WeakKey<Domain>>,
    pub to_change: HashSet<WeakKey<Domain>>,
    pub snap: HashMap<WeakKey<Domain>, CoalescedView>,
}

// TODO: We'll have to see what we do about it.
impl OperationUpdate {
    pub fn new() -> Self {
        Self {
            to_clean: Vec::new(),
            to_revoke: HashSet::new(),
            to_change: HashSet::new(),
            snap: HashMap::new(),
        }
    }

    // Add all updates
    pub fn add_all(&mut self, updates: Vec<Update>) {
        for u in updates {
            self.add(u);
        }
    }

    // Add an update.
    pub fn add(&mut self, update: Update) {
        match update {
            Update::Clean { start: _, size: _ } => {
                self.to_clean.push(update);
            }
            Update::Revoke { ref dom } => {
                self.to_change.remove(&WeakKey(dom.clone()));
                self.to_change.insert(WeakKey(dom.clone()));
            }
            Update::ChangeMemory { ref dom } => {
                if !self.to_revoke.contains(&WeakKey(dom.clone())) {
                    self.to_change.insert(WeakKey(dom.clone()));
                }
            }
        }
    }

    // Compute the views for all the domains that are affected.
    pub fn snapshot(&mut self) -> Result<(), CapaError> {
        //TODO: we might change this.
        for d in &self.to_change {
            let weak = &d.0;
            if let Some(domain) = weak.clone().upgrade() {
                let coal = CoalescedView::from_regions(domain.borrow().view()?)?;
                self.snap.insert(WeakKey(weak.clone()), coal);
            }
        }
        //TODO we will need to do the cleaning + switch due to revoke
        Ok(())
    }

    pub fn compute(&mut self) -> Result<(), CapaError> {
        //TODO: I'll have to think about the most efficient change.
        /*for (d, v) in self.snap.iter() {
            if let Some(dom) = &d.0.upgrade() {
                let view = CoalescedView::from_regions(dom.borrow().view()?)?;
                let (add, remove) = v.diff(view);
            }
        }*/
        Ok(())
    }
}
