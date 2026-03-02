//! Process capability engine updates in the CLI

use capability_engine::{Update, UpdateBatch};
use std::collections::HashSet;

use crate::state::CliState;

/// Process an UpdateBatch returned from a capability operation.
/// Core state management is now handled by CliPlatform::on_domain_revoked (called by execute()).
/// This function only performs CliState HashMap cleanup.
pub fn process_updates(state: &mut CliState, updates: &UpdateBatch) {
    // 1. Collect revoked domain IDs from RevokeDomain updates
    let revoked_domains: HashSet<u64> = updates.updates().iter()
        .filter_map(|u| if let Update::RevokeDomain { domain, .. } = u { Some(*domain) } else { None })
        .collect();

    // 2. Remove revoked domains from state and clean up their memory capabilities
    if !revoked_domains.is_empty() {
        println!("  Processing {} domain revocation(s)...", revoked_domains.len());
        for &domain_id in &revoked_domains {
            if let Some(name) = state.get_domain_name(domain_id).map(|s| s.to_string()) {
                // Remove owned memory capabilities
                let owned_mems: Vec<String> = state.memories.iter()
                    .filter_map(|(n, m)| if m.read().owned.owner == domain_id { Some(n.clone()) } else { None })
                    .collect();
                for mem_name in owned_mems {
                    state.memories.remove(&mem_name);
                    println!("    ✗ Removed memory capability '{}'", mem_name);
                }
                state.domains.remove(&name);
                println!("    ✗ Removed domain '{}' (ID: {})", name, domain_id);
            }
        }
    }

    // 3. Print MMU update summary
    let (mut maps, mut unmaps, mut zeros) = (0, 0, 0);
    for update in updates.updates() {
        match update {
            Update::ChangeRights { rights, .. } if *rights == capability_engine::Rights::NONE => unmaps += 1,
            Update::ChangeRights { .. } => maps += 1,
            Update::ZeroMemory { .. } => zeros += 1,
            _ => {}
        }
    }
    if maps + unmaps + zeros > 0 {
        println!("  ℹ MMU updates: {} map(s), {} unmap(s), {} zero(s)", maps, unmaps, zeros);
    }
}
