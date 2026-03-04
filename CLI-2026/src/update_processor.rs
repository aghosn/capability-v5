//! Process capability engine updates in the CLI

use capability_engine::{Update, UpdateBatch};
use std::collections::HashSet;

use crate::state::CliState;

/// Process an UpdateBatch returned from a capability operation.
///
/// The capability engine now generates all platform-level updates (ChangeRights,
/// ZeroMemory, RevokeDomain) including memory restore on domain revocation.
/// This function only cleans up the CLI's named-entry bookkeeping.
pub fn process_updates(state: &mut CliState, updates: &UpdateBatch) {
    let revoked_domains: HashSet<u64> = updates.updates().iter()
        .filter_map(|u| if let Update::RevokeDomain { domain, .. } = u { Some(*domain) } else { None })
        .collect();

    if !revoked_domains.is_empty() {
        println!("  Processing {} domain revocation(s)...", revoked_domains.len());
        for &domain_id in &revoked_domains {
            if let Some(name) = state.domain_id_to_name.remove(&domain_id) {
                // Remove owned memory capabilities from CLI state
                let owned_mems: Vec<String> = state.memories.iter()
                    .filter_map(|(n, m)| if m.read().owned.owner == domain_id { Some(n.clone()) } else { None })
                    .collect();
                for mem_name in &owned_mems {
                    state.memories.remove(mem_name);
                    println!("    ✗ Removed memory capability '{}'", mem_name);
                }
                state.domains.remove(&name);
                println!("    ✗ Removed domain '{}' (ID: {})", name, domain_id);
            }
        }
    }

    // Print MMU update summary
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
