//! Process capability engine updates in the CLI

use crate::backend::{HwUpdate, HwUpdateKind};
use crate::state::CliState;

/// Process HwUpdates returned from a backend operation.
///
/// Cleans up CLI bookkeeping (name maps) on domain revocations and prints
/// a summary of MMU-level updates.
pub fn process_updates(state: &mut CliState, updates: &[HwUpdate]) {
    let revoked_domains: Vec<u64> = updates
        .iter()
        .filter(|u| u.kind == HwUpdateKind::RevokeDomain)
        .map(|u| u.domain_id)
        .collect();

    if !revoked_domains.is_empty() {
        println!(
            "  Processing {} domain revocation(s)...",
            revoked_domains.len()
        );
        for &domain_id in &revoked_domains {
            if let Some(name) = state.domain_id_to_name.remove(&domain_id) {
                // Remove owned memory capabilities from CLI state
                let mut owned_mems: Vec<String> = state
                    .mem_names
                    .iter()
                    .filter(|(_, uid)| state.mem_owners.get(uid) == Some(&domain_id))
                    .map(|(n, _)| n.clone())
                    .collect();
                owned_mems.sort();
                for mem_name in &owned_mems {
                    if let Some(uid) = state.mem_names.remove(mem_name) {
                        state.mem_owners.remove(&uid);
                        println!("    − Removed memory capability '{}'", mem_name);
                    }
                }
                state.domain_names.remove(&name);
                state.domain_parents.remove(&domain_id);
                println!("    − Removed domain '{}' (ID: {})", name, domain_id);
            }
        }
    }

    // Print MMU update summary
    let (mut maps, mut unmaps, mut zeros, mut comms, mut uncomms) = (0, 0, 0, 0, 0);
    for update in updates {
        match update.kind {
            HwUpdateKind::UnmapMemory => unmaps += 1,
            HwUpdateKind::MapMemory => maps += 1,
            HwUpdateKind::ZeroMemory => zeros += 1,
            HwUpdateKind::CommRegion => comms += 1,
            HwUpdateKind::UncommRegion => uncomms += 1,
            _ => {}
        }
    }
    if maps + unmaps + zeros > 0 {
        println!(
            "  ℹ MMU updates: {} map(s), {} unmap(s), {} zero(s)",
            maps, unmaps, zeros
        );
    }
    if comms > 0 {
        println!("  ℹ COMM: {} page(s) registered with monitor", comms);
    }
    if uncomms > 0 {
        println!("  ℹ COMM: {} page(s) unregistered from monitor", uncomms);
    }
}
