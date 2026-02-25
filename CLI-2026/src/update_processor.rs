//! Process capability engine updates in the CLI

use capability_engine::*;
use colored::*;
use std::collections::HashSet;
use std::sync::Arc;
use parking_lot::RwLock;

use crate::state::CliState;

/// Walk up the parent chain of a domain capability and return the ID of the
/// first ancestor that is NOT in `revoked_domains`. Returns `None` if there
/// is no such ancestor (i.e. the root itself was revoked).
fn find_non_revoked_ancestor(
    domain_ref: &Arc<RwLock<Capability<Domain>>>,
    revoked_domains: &HashSet<u64>,
) -> Option<u64> {
    let parent = domain_ref.read().get_parent()?;
    let parent_id = parent.read().data.id;
    if revoked_domains.contains(&parent_id) {
        find_non_revoked_ancestor(&parent, revoked_domains)
    } else {
        Some(parent_id)
    }
}

/// Process an UpdateBatch returned from a capability operation
pub fn process_updates(state: &mut CliState, updates: &UpdateBatch) {
    if updates.is_empty() {
        return;
    }

    let mut revoked_domains = HashSet::new();
    let mut revoked_memories = HashSet::new();

    // First pass: identify what needs to be revoked
    for update in updates.updates() {
        match update {
            Update::RevokeDomain { domain } => {
                revoked_domains.insert(*domain);
            }
            _ => {
                // Other updates (Map, Unmap, ZeroMemory) are informational in CLI
                // In a real system, these would be applied to the MMU
            }
        }
    }

    // Second pass: update cores that were running a revoked domain
    if !revoked_domains.is_empty() {
        let num_cores = state.num_cores as u64;
        for core_id in 0..num_cores {
            if let Ok(core_ref) = state.switch_manager.get_core(core_id) {
                if let Some(running_id) = core_ref.current_domain() {
                    if revoked_domains.contains(&running_id) {
                        // Walk up the parent chain to find the first non-revoked ancestor.
                        let domain_arc = state
                            .get_domain_name(running_id)
                            .and_then(|n| state.domains.get(n))
                            .cloned();

                        let new_state = if let Some(arc) = domain_arc {
                            match find_non_revoked_ancestor(&arc, &revoked_domains) {
                                Some(ancestor_id) => {
                                    let name = state
                                        .get_domain_name(ancestor_id)
                                        .unwrap_or("unknown")
                                        .to_string();
                                    println!(
                                        "    {} Core {} domain revoked, returning to ancestor '{}' (ID: {})",
                                        "→".bright_blue(),
                                        core_id,
                                        name.bright_white(),
                                        ancestor_id
                                    );
                                    CoreState::Running(ancestor_id)
                                }
                                None => {
                                    println!(
                                        "    {} Core {} domain revoked with no surviving ancestor, core is now idle",
                                        "→".bright_blue(),
                                        core_id
                                    );
                                    CoreState::Idle
                                }
                            }
                        } else {
                            CoreState::Idle
                        };

                        *core_ref.state.write() = new_state;
                    }
                }
            }
        }
    }

    // Third pass: remove revoked domains and their owned capabilities
    if !revoked_domains.is_empty() {
        println!(
            "{}Processing {} domain revocation(s)...",
            "  ".bright_black(),
            revoked_domains.len()
        );

        for domain_id in &revoked_domains {
            // Find domain name
            let domain_name = state.get_domain_name(*domain_id).map(|s| s.to_string());

            if let Some(name) = &domain_name {
                // Mark domain as revoked
                if let Some(domain_ref) = state.domains.get(name) {
                    domain_ref.write().data.revoke();
                }

                // Find all memory capabilities owned by this domain
                let owned_mems: Vec<String> = state
                    .memories
                    .iter()
                    .filter_map(|(mem_name, mem_ref)| {
                        let mem = mem_ref.read();
                        if mem.owned.owner == *domain_id {
                            Some(mem_name.clone())
                        } else {
                            None
                        }
                    })
                    .collect();

                // Mark them for removal
                for mem_name in owned_mems {
                    revoked_memories.insert(mem_name);
                }
            }
        }

        // Remove revoked domains from state
        for domain_id in &revoked_domains {
            if let Some(name) = state.get_domain_name(*domain_id) {
                let name_clone = name.to_string();
                state.domains.remove(&name_clone);
                println!(
                    "    {} Removed domain '{}' (ID: {})",
                    "✗".bright_red(),
                    name_clone.bright_white(),
                    domain_id
                );
            }
        }

        // Remove revoked memory capabilities from state and their parent's children list
        for mem_name in &revoked_memories {
            if let Some(mem_ref) = state.memories.remove(mem_name) {
                let mem = mem_ref.read();

                // Remove from parent's children list
                if let Some(parent_ref) = mem.get_parent() {
                    let child_handle = mem.owned.handle;
                    drop(mem); // Release read lock before acquiring write lock on parent
                    parent_ref.write().remove_child(child_handle);
                } else {
                    drop(mem);
                }

                // Get a fresh read to print info
                let mem = mem_ref.read();
                println!(
                    "    {} Removed memory capability '{}' {} (owner: {})",
                    "✗".bright_red(),
                    mem_name.bright_white(),
                    mem.data.access,
                    mem.owned.owner
                );
            }
        }
    }

    // Report other update types (informational)
    let mut map_count = 0;
    let mut unmap_count = 0;
    let mut zero_count = 0;

    for update in updates.updates() {
        match update {
            Update::Map { .. } => map_count += 1,
            Update::Unmap { .. } => unmap_count += 1,
            Update::ZeroMemory { .. } => zero_count += 1,
            Update::RevokeDomain { .. } => {}, // Already handled
            _ => {},
        }
    }

    if map_count > 0 || unmap_count > 0 || zero_count > 0 {
        let mut parts = Vec::new();
        if map_count > 0 {
            parts.push(format!("{} map(s)", map_count));
        }
        if unmap_count > 0 {
            parts.push(format!("{} unmap(s)", unmap_count));
        }
        if zero_count > 0 {
            parts.push(format!("{} zero operation(s)", zero_count));
        }
        println!(
            "  {} MMU updates: {}",
            "ℹ".bright_blue(),
            parts.join(", ")
        );
    }
}
