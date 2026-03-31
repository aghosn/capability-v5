//! Information commands routed through the Backend trait.
//!
//! All data comes from Backend query methods (list_domains, get_domain_mem_caps,
//! get_address_space, get_core_states, attest) — no direct capability_engine access.

use colored::*;
use std::collections::{HashMap, HashSet};

use crate::backend::{DomainId, MemCapInfoDto, MemCapUid};
use crate::session::Command;
use crate::state::CliState;

/// Generate attestation report for domain
pub fn cmd_attest(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.len() != 1 {
        return Err("Usage: attest <domain>".to_string());
    }

    let domain_name = args[0];
    let domain_id = *state
        .domain_names
        .get(domain_name)
        .ok_or_else(|| format!("Domain '{}' not found", domain_name))?;

    let report = state
        .backend
        .attest(domain_id)
        .map_err(|e| format!("Failed to attest: {}", e))?;

    state.session.add_command(Command::Attest {
        domain: domain_name.to_string(),
    });

    println!("\n{}", "Attestation Report:".bright_cyan().bold());
    println!("{}", report);

    Ok(())
}

/// Show address space view for domain
pub fn cmd_view(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.len() != 1 {
        return Err("Usage: view <domain>".to_string());
    }

    let domain_name = args[0];
    let domain_id = *state
        .domain_names
        .get(domain_name)
        .ok_or_else(|| format!("Domain '{}' not found", domain_name))?;

    let regions = state.backend.get_address_space(domain_id);

    state.session.add_command(Command::View {
        domain: domain_name.to_string(),
    });

    println!("\n{}", "Address Space View:".bright_cyan().bold());
    if regions.is_empty() {
        println!("  (empty)");
    } else {
        for r in &regions {
            let tag = if r.is_identity_mapped {
                " (identity)".dimmed().to_string()
            } else {
                String::new()
            };
            println!(
                "  GPA {:#x}..{:#x} → HPA {:#x} {}{}",
                r.gpa,
                r.gpa + r.size,
                r.hpa,
                r.rights,
                tag
            );
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Memory tree visualization (DTO-based)
// ─────────────────────────────────────────────────────────────────────────────

/// Memory region node for hierarchical tree visualization
#[derive(Debug, Clone)]
struct MemoryNode {
    name: String,
    start: u64,
    end: u64,
    kind: String,
    is_meta: bool,
    children: Vec<MemoryNode>,
    owner_name: String,
}

/// Build a reverse map from MemCapUid → user-assigned name
fn build_uid_to_name(state: &CliState) -> HashMap<MemCapUid, String> {
    state.mem_names.iter().map(|(n, &uid)| (uid, n.clone())).collect()
}

/// Convert a MemCapInfoDto to a MemoryNode, recursively including children.
fn dto_to_node(
    dto: &MemCapInfoDto,
    uid_to_name: &HashMap<MemCapUid, String>,
    id_to_name: &HashMap<DomainId, String>,
) -> MemoryNode {
    let name = uid_to_name
        .get(&dto.uid)
        .cloned()
        .unwrap_or_else(|| format!("uid:{}", dto.uid));

    let owner_name = id_to_name
        .get(&dto.owner_id)
        .cloned()
        .unwrap_or_else(|| format!("DOM{}", dto.owner_id));

    let is_meta = dto.attributes.contains("META");

    let children: Vec<MemoryNode> = dto
        .children
        .iter()
        .map(|c| dto_to_node(c, uid_to_name, id_to_name))
        .collect();

    MemoryNode {
        name,
        start: dto.start,
        end: dto.end,
        kind: dto.kind.clone(),
        is_meta,
        children,
        owner_name,
    }
}

/// Collect all MemCapInfoDtos from all domains and find root-level ones.
fn collect_root_mem_nodes(state: &CliState) -> Vec<MemoryNode> {
    let uid_to_name = build_uid_to_name(state);
    let domains = state.backend.list_domains();

    // Collect all top-level mem cap DTOs across all domains.
    let mut all_dtos: Vec<MemCapInfoDto> = Vec::new();
    for d in &domains {
        all_dtos.extend(state.backend.get_domain_mem_caps(d.id));
    }

    // Collect all UIDs that appear as children of other DTOs.
    let mut child_uids: HashSet<MemCapUid> = HashSet::new();
    fn collect_child_uids(dto: &MemCapInfoDto, set: &mut HashSet<MemCapUid>) {
        for child in &dto.children {
            set.insert(child.uid);
            collect_child_uids(child, set);
        }
    }
    for dto in &all_dtos {
        collect_child_uids(dto, &mut child_uids);
    }

    // Deduplicate by uid — keep the first occurrence.
    let mut seen: HashSet<MemCapUid> = HashSet::new();
    let mut root_dtos: Vec<&MemCapInfoDto> = Vec::new();
    for dto in &all_dtos {
        if !child_uids.contains(&dto.uid) && seen.insert(dto.uid) {
            root_dtos.push(dto);
        }
    }

    let mut nodes: Vec<MemoryNode> = root_dtos
        .iter()
        .map(|dto| dto_to_node(dto, &uid_to_name, &state.domain_id_to_name))
        .collect();
    nodes.sort_by_key(|n| n.start);
    nodes
}

/// Convert a physical address to bar position
fn addr_to_bar_pos(addr: u64, total_size: u64, bar_width: usize) -> usize {
    ((addr as f64 / total_size as f64) * bar_width as f64) as usize
}

const NAME_COLUMN_WIDTH: usize = 20;

fn draw_memory_bar(
    node: &MemoryNode,
    total_size: u64,
    carved_bar_ranges: &[(usize, usize)],
) {
    let bar_width = 40;
    let bar_start = addr_to_bar_pos(node.start, total_size, bar_width);
    let bar_end = addr_to_bar_pos(node.end, total_size, bar_width);
    let bar_size = (bar_end - bar_start).max(1);

    let (bar_char, color_fn): (char, fn(&str) -> colored::ColoredString) = if node.is_meta {
        ('█', |s| s.bright_purple())
    } else {
        match node.kind.as_str() {
            "Alias" => ('▓', |s| s.bright_yellow()),
            _ => ('█', |s| s.bright_cyan()),
        }
    };

    let display_name = if node.name.len() > NAME_COLUMN_WIDTH {
        format!("{}...", &node.name[..NAME_COLUMN_WIDTH - 3])
    } else {
        node.name.clone()
    };

    print!(
        "{:<width$} ",
        display_name.bright_white(),
        width = NAME_COLUMN_WIDTH
    );

    for _ in 0..bar_start {
        print!(" ");
    }

    for i in 0..bar_size {
        let bar_pos = bar_start + i;
        let is_carved = carved_bar_ranges
            .iter()
            .any(|(s, e)| bar_pos >= *s && bar_pos < *e);
        if is_carved {
            print!("{}", color_fn("░"));
        } else {
            print!("{}", color_fn(&bar_char.to_string()));
        }
    }

    for _ in (bar_start + bar_size)..bar_width {
        print!(" ");
    }

    println!(
        "  [0x{:x}..0x{:x}) {}",
        node.start,
        node.end,
        node.owner_name.bright_magenta()
    );
}

fn display_memory_tree(nodes: &[MemoryNode], total_size: u64) {
    let bar_width = 40;
    for node in nodes {
        let carved_bar_ranges: Vec<(usize, usize)> = node
            .children
            .iter()
            .filter(|c| c.kind != "Alias")
            .map(|c| {
                let start_pos = addr_to_bar_pos(c.start, total_size, bar_width);
                let end_pos = addr_to_bar_pos(c.end, total_size, bar_width);
                let end_pos = if end_pos == start_pos {
                    start_pos + 1
                } else {
                    end_pos
                };
                (start_pos, end_pos)
            })
            .collect();

        draw_memory_bar(node, total_size, &carved_bar_ranges);

        if !node.children.is_empty() {
            display_memory_tree(&node.children, total_size);
        }
    }
}

fn display_physical_address_space(state: &CliState) {
    let roots = collect_root_mem_nodes(state);
    if roots.is_empty() {
        println!("  (no memory allocated)");
        return;
    }

    fn max_end(nodes: &[MemoryNode]) -> u64 {
        nodes
            .iter()
            .map(|n| {
                let child_max = max_end(&n.children);
                n.end.max(child_max)
            })
            .max()
            .unwrap_or(0)
    }

    let total_size = max_end(&roots);

    println!();
    println!("  Memory Hierarchy (horizontal bars show address ranges):");
    println!("  {}", "─".repeat(70));

    display_memory_tree(&roots, total_size);

    println!();
    println!(
        "  Legend: {} = Carved, {} = Aliased, {} = Meta, {} = Carved portion in parent",
        "█".bright_cyan(),
        "▓".bright_yellow(),
        "█".bright_purple(),
        "░".bright_cyan()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// mem-usage (simplified — uses DTOs instead of internal struct sizes)
// ─────────────────────────────────────────────────────────────────────────────

pub fn cmd_mem_usage(state: &mut CliState) -> std::result::Result<(), String> {
    let domains = state.backend.list_domains();

    println!(
        "\n{}",
        "Memory Usage Report (object counts):".bright_cyan().bold()
    );
    println!("{}", "─".repeat(72));

    println!(
        "\n{} {} total",
        "Domains:".bright_yellow().bold(),
        domains.len()
    );
    if domains.is_empty() {
        println!("  (none)");
    } else {
        println!(
            "  {:<16} {:>4}  {:<10}  {:>6}  {:>8}  {:>8}  {:>8}",
            "Name", "ID", "Status", "#VPs", "#MemCaps", "#DomCaps", "#Pending"
        );
        println!("  {}", "─".repeat(72));
        for d in &domains {
            let name = state
                .get_domain_name(d.id)
                .unwrap_or("?")
                .to_string();
            let mem_caps = state.backend.get_domain_mem_caps(d.id);
            let dom_caps = state.backend.get_domain_dom_caps(d.id);
            let pending = state.backend.get_pending_caps(d.id);
            println!(
                "  {:<16} {:>4}  {:<10}  {:>6}  {:>8}  {:>8}  {:>8}",
                name,
                d.id,
                d.status,
                d.num_vps,
                mem_caps.len(),
                dom_caps.len(),
                pending.len()
            );
        }
    }

    // Memory regions summary
    let uid_to_name = build_uid_to_name(state);
    let mut all_mem_info: HashMap<MemCapUid, MemCapInfoDto> = HashMap::new();
    for d in &domains {
        for mc in state.backend.get_domain_mem_caps(d.id) {
            fn collect(dto: &MemCapInfoDto, map: &mut HashMap<MemCapUid, MemCapInfoDto>) {
                map.entry(dto.uid).or_insert_with(|| dto.clone());
                for c in &dto.children {
                    collect(c, map);
                }
            }
            collect(&mc, &mut all_mem_info);
        }
    }

    println!(
        "\n{} {} total",
        "Memory Regions:".bright_yellow().bold(),
        all_mem_info.len()
    );
    if all_mem_info.is_empty() {
        println!("  (none)");
    } else {
        println!(
            "  {:<16}  {:<6}  {:<28}  {:>9}",
            "Name", "Kind", "Range", "#Children"
        );
        println!("  {}", "─".repeat(64));
        let mut sorted: Vec<_> = all_mem_info.values().collect();
        sorted.sort_by_key(|m| m.start);
        for m in sorted {
            let name = uid_to_name
                .get(&m.uid)
                .cloned()
                .unwrap_or_else(|| format!("uid:{}", m.uid));
            println!(
                "  {:<16}  {:<6}  [{:#010x}..{:#010x})  {:>9}",
                name, m.kind, m.start, m.end, m.num_children
            );
        }
    }
    println!();

    Ok(())
}

/// List all domains and memory regions with active core status
pub fn cmd_list(state: &mut CliState) -> std::result::Result<(), String> {
    // Show active domains per core
    println!("\n{}", "Active Domains per Core:".bright_cyan().bold());
    let core_states = state.backend.get_core_states();
    for cs in &core_states {
        match cs.domain_id {
            Some(id) => {
                let domain_name = state.get_domain_name(id).unwrap_or("unknown");
                println!(
                    "  {} Core {}: {} (ID: {})",
                    "✓".bright_green(),
                    cs.core_id,
                    domain_name.bright_white(),
                    id
                );
            }
            None => {
                println!(
                    "  {} Core {}: {}",
                    "○".bright_black(),
                    cs.core_id,
                    "idle".bright_black()
                );
            }
        }
    }

    println!("\n{}", "Domains:".bright_cyan().bold());
    let domains = state.backend.list_domains();
    if domains.is_empty() {
        println!("  (none)");
    } else {
        for d in &domains {
            let name = state
                .get_domain_name(d.id)
                .unwrap_or("?")
                .to_string();
            if d.is_channel {
                let target_name = d
                    .channel_target
                    .and_then(|t| state.get_domain_name(t))
                    .unwrap_or("unknown");
                println!(
                    "  {} {} (Channel → Domain ID: {}, status: {})",
                    "•".bright_yellow(),
                    name.bright_white(),
                    d.channel_target.map_or(0, |t| t),
                    d.status
                );
                let _ = target_name; // used above implicitly
            } else {
                println!(
                    "  {} {} (ID: {}, status: {})",
                    "•".bright_yellow(),
                    name.bright_white(),
                    d.id,
                    d.status
                );
            }

            // Show pending capabilities
            let pending = state.backend.get_pending_caps(d.id);
            if !pending.is_empty() {
                println!(
                    "    {} Pending capabilities ({}):",
                    "⏸".bright_yellow(),
                    pending.len()
                );
                for p in &pending {
                    if p.is_domain {
                        println!(
                            "      [ID: {}] Channel (sender: {})",
                            p.pending_id, p.sender_id
                        );
                    } else {
                        println!(
                            "      [ID: {}] Memory [0x{:x}..0x{:x}) {} (sender: {})",
                            p.pending_id, p.start, p.end, p.rights, p.sender_id
                        );
                    }
                }
            }
        }
    }

    println!("\n{}", "Memory Regions:".bright_cyan().bold());
    if state.mem_names.is_empty() {
        println!("  (none)");
    } else {
        // Build uid → info map from all domains
        let all_domains = state.backend.list_domains();
        let mut mem_info_map: HashMap<MemCapUid, MemCapInfoDto> = HashMap::new();
        for d in &all_domains {
            for mc in state.backend.get_domain_mem_caps(d.id) {
                fn collect(dto: &MemCapInfoDto, map: &mut HashMap<MemCapUid, MemCapInfoDto>) {
                    map.entry(dto.uid).or_insert_with(|| dto.clone());
                    for c in &dto.children {
                        collect(c, map);
                    }
                }
                collect(&mc, &mut mem_info_map);
            }
        }

        let mut sorted_mems: Vec<_> = state.mem_names.iter().collect();
        sorted_mems.sort_by_key(|(_, uid)| **uid);

        for (name, uid) in &sorted_mems {
            if let Some(info) = mem_info_map.get(uid) {
                let owner_name = state
                    .get_domain_name(info.owner_id)
                    .unwrap_or("?");
                println!(
                    "  {} {} [0x{:x}..0x{:x}) {} (kind: {}, owner: {}, attrs: {}, children: {})",
                    "•".bright_yellow(),
                    name.bright_white(),
                    info.start,
                    info.end,
                    info.rights,
                    info.kind,
                    owner_name,
                    info.attributes,
                    info.num_children
                );
            }
        }
    }

    println!("\n{}", "Physical Address Space:".bright_cyan().bold());
    display_physical_address_space(state);

    println!();
    Ok(())
}
