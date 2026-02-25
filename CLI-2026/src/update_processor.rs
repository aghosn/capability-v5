//! Process capability engine updates in the CLI

use capability_engine::*;
use colored::*;
use std::collections::HashSet;

use crate::state::CliState;

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

    // Second pass: remove revoked domains and their owned capabilities
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
