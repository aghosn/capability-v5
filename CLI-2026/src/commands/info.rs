//! Information commands: attest, view, list, mem-usage

use capability_engine::*;
use capability_engine::domain::PendingCapability;
use colored::*;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::session::Command;
use crate::state::CliState;

/// Generate attestation report for domain
pub fn cmd_attest(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.len() != 1 {
        return Err("Usage: attest <domain>".to_string());
    }

    let domain_name = args[0];
    let domain = state
        .domains
        .get(domain_name)
        .ok_or_else(|| format!("Domain '{}' not found", domain_name))?;

    // Sealed domains must have ATTEST permission to produce an attestation report.
    {
        let d = domain.read();
        if d.data.is_sealed() && !d.data.policy.api.attest() {
            return Err(format!(
                "Domain '{}' does not have ATTEST permission",
                domain_name
            ));
        }
    }

    let attestation = attest_domain(domain);

    // Record command
    state.session.add_command(Command::Attest {
        domain: domain_name.to_string(),
    });

    println!("\n{}", "Attestation Report:".bright_cyan().bold());
    println!("{}", attestation.report);

    Ok(())
}

/// Show address space view for domain
pub fn cmd_view(state: &mut CliState, args: &[&str]) -> std::result::Result<(), String> {
    if args.len() != 1 {
        return Err("Usage: view <domain>".to_string());
    }

    let domain_name = args[0];
    let domain = state
        .domains
        .get(domain_name)
        .ok_or_else(|| format!("Domain '{}' not found", domain_name))?;

    let view = compute_address_space(domain);

    // Record command
    state.session.add_command(Command::View {
        domain: domain_name.to_string(),
    });

    println!("\n{}", "Address Space View:".bright_cyan().bold());
    println!("{}", view);

    Ok(())
}

/// Memory region node for hierarchical tree visualization
#[derive(Debug, Clone)]
struct MemoryNode {
    name: String,
    start: u64,
    end: u64,
    kind: RegionKind,
    status: RegionStatus,
    children: Vec<MemoryNode>,
    owner_name: String,
}

/// Build hierarchical memory tree from state
fn build_memory_tree(state: &CliState) -> Vec<MemoryNode> {
    let mut roots = Vec::new();
    let all_names: HashSet<String> = state.memories.keys().cloned().collect();
    let mut child_names: HashSet<String> = HashSet::new();

    // Build parent -> children mapping based on address containment
    let mut parent_children: HashMap<String, Vec<String>> = HashMap::new();

    for (parent_name, parent_mem) in &state.memories {
        let p = parent_mem.read();
        let parent_start = p.data.access.start;
        let parent_end = p.data.access.end();

        for (child_name, child_mem) in &state.memories {
            if child_name == parent_name {
                continue;
            }
            let c = child_mem.read();
            let child_start = c.data.access.start;
            let child_end = c.data.access.end();

            // Check if child is within parent's range and is actually a child
            if child_start >= parent_start && child_end <= parent_end && p.children.len() > 0 {
                // Verify by Arc pointer identity to avoid false matches when two regions
                // share the same address range (e.g., a carve and an alias at identical ranges)
                let child_ptr = Arc::as_ptr(child_mem);
                let is_child = p.children.iter().any(|child_ref| {
                    Arc::as_ptr(child_ref) == child_ptr
                });

                if is_child {
                    parent_children.entry(parent_name.clone())
                        .or_insert_with(Vec::new)
                        .push(child_name.clone());
                    child_names.insert(child_name.clone());
                }
            }
        }
    }

    // Build nodes recursively, starting from roots
    fn build_node(name: &str, state: &CliState, parent_children: &HashMap<String, Vec<String>>) -> Option<MemoryNode> {
        let mem = state.memories.get(name)?;
        let m = mem.read();

        let owner_name = state.get_domain_name(m.owned.owner)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("DOM{}", m.owned.owner));

        let mut children_nodes = Vec::new();

        // Get children from the map
        if let Some(children) = parent_children.get(name) {
            for child_name in children {
                if let Some(child_node) = build_node(child_name, state, parent_children) {
                    children_nodes.push(child_node);
                }
            }
        }

        children_nodes.sort_by_key(|n| n.start);

        Some(MemoryNode {
            name: name.to_string(),
            start: m.data.access.start,
            end: m.data.access.end(),
            kind: m.data.kind.clone(),
            status: m.data.status,
            children: children_nodes,
            owner_name,
        })
    }

    // Get root nodes (those not in child_names)
    for name in all_names.difference(&child_names) {
        if let Some(node) = build_node(name, state, &parent_children) {
            roots.push(node);
        }
    }

    roots.sort_by_key(|n| n.start);
    roots
}

/// Convert a physical address to bar position
fn addr_to_bar_pos(addr: u64, total_size: u64, bar_width: usize) -> usize {
    ((addr as f64 / total_size as f64) * bar_width as f64) as usize
}

/// Maximum width for capability names in the first column.
/// Adjust this value to control the layout of the address space display.
const NAME_COLUMN_WIDTH: usize = 20;

/// Draw a horizontal bar representing a memory region
fn draw_memory_bar(node: &MemoryNode, _depth: usize, total_size: u64, carved_bar_ranges: &[(usize, usize)]) {
    let bar_width = 40;

    // Calculate bar position and width based on actual address ranges
    let bar_start = addr_to_bar_pos(node.start, total_size, bar_width);
    let bar_end = addr_to_bar_pos(node.end, total_size, bar_width);
    let bar_size = (bar_end - bar_start).max(1);

    // Choose color based on kind and status:
    //   Carve + Exclusive => cyan, Carve + Aliased (carved from alias) => green, Alias => yellow
    let (bar_char, color_fn): (char, fn(&str) -> colored::ColoredString) = match (node.kind, node.status) {
        (RegionKind::Carve, RegionStatus::Exclusive) => ('█', |s| s.bright_cyan()),
        (RegionKind::Carve, RegionStatus::Aliased)   => ('█', |s| s.bright_green()),
        (RegionKind::Alias, _)                       => ('▓', |s| s.bright_yellow()),
    };

    // Truncate name if too long, ensuring it fits within NAME_COLUMN_WIDTH
    let display_name = if node.name.len() > NAME_COLUMN_WIDTH {
        format!("{}...", &node.name[..NAME_COLUMN_WIDTH - 3])
    } else {
        node.name.clone()
    };

    // Print name with fixed width, left-aligned and padded
    print!("{:<width$} ", display_name.bright_white(), width = NAME_COLUMN_WIDTH);

    // Add leading spaces to align bar by physical address
    for _ in 0..bar_start {
        print!(" ");
    }

    // Draw the bar itself
    for i in 0..bar_size {
        let bar_pos = bar_start + i;
        // Use pre-computed bar positions for carved ranges to guarantee alignment
        let is_carved = carved_bar_ranges.iter().any(|(s, e)| bar_pos >= *s && bar_pos < *e);

        if is_carved {
            print!("{}", color_fn("░"));  // Greyed out for carved portion
        } else {
            print!("{}", color_fn(&bar_char.to_string()));  // Full color for available portion
        }
    }

    // Add trailing spaces to fill the bar width and ensure alignment
    for _ in (bar_start + bar_size)..bar_width {
        print!(" ");
    }

    // Show address range and owner
    println!("  {} {} [0x{:x}..0x{:x}) owner:{}",
        format!("{:?}", node.kind).bright_black(),
        format!("{:?}", node.status).bright_black(),
        node.start, node.end, node.owner_name.bright_magenta());
}

/// Display memory tree hierarchically with horizontal bars
fn display_memory_tree(nodes: &[MemoryNode], depth: usize, total_size: u64) {
    let bar_width = 40;
    for node in nodes {
        // Pre-compute bar positions for carved children so they align exactly with child bars
        // Grey out ALL carved regions in the parent display
        let carved_bar_ranges: Vec<(usize, usize)> = node.children.iter()
            .filter(|c| matches!(c.kind, RegionKind::Carve))
            .map(|c| {
                let start_pos = addr_to_bar_pos(c.start, total_size, bar_width);
                let end_pos = addr_to_bar_pos(c.end, total_size, bar_width);
                // Ensure carved regions occupy at least 1 character in the display
                let end_pos = if end_pos == start_pos { start_pos + 1 } else { end_pos };
                (start_pos, end_pos)
            })
            .collect();

        draw_memory_bar(node, depth, total_size, &carved_bar_ranges);

        // Recursively display children
        if !node.children.is_empty() {
            display_memory_tree(&node.children, depth + 1, total_size);
        }
    }
}

/// Display physical address space visualization inspired by Figure 3
fn display_physical_address_space(state: &CliState) {
    if state.memories.is_empty() {
        println!("  (no memory allocated)");
        return;
    }

    let tree = build_memory_tree(state);

    if tree.is_empty() {
        println!("  (no memory allocated)");
        return;
    }

    // Find total address space size for visualization
    let max_end = state.memories.values()
        .map(|m| m.read().data.access.end())
        .max()
        .unwrap_or(0);

    println!();
    println!("  Memory Hierarchy (horizontal bars show address ranges):");
    println!("  {}", "─".repeat(70));

    display_memory_tree(&tree, 0, max_end);

    println!();
    println!("  Legend: {} = Carved (exclusive), {} = Carved (from alias), {} = Aliased, {} = Carved portion in parent",
        "█".bright_cyan(), "█".bright_green(), "▓".bright_yellow(), "░".bright_cyan());
}

/// Compute logical memory footprint (bytes) of a single domain capability node.
///
/// Counts the fixed inline struct size plus all heap-allocated payloads.
/// Child pointers in `children` are counted (the pointer storage), but the child
/// objects themselves are NOT — they appear as their own entries when the caller
/// iterates over `state.domains`.
fn domain_logical_bytes(cap: &Capability<Domain>) -> usize {
    let mut bytes = std::mem::size_of::<Capability<Domain>>();

    // children Vec heap buffer: one CapabilityRef<Domain> pointer per child
    bytes += cap.children.len() * std::mem::size_of::<CapabilityRef<Domain>>();

    // memory_capabilities BTreeMap: key + value per entry
    bytes += cap.data.memory_capabilities.len()
        * (std::mem::size_of::<LocalHandle>() + std::mem::size_of::<CapabilityWeak<MemoryRegion>>());

    // domain_capabilities BTreeMap: key + value per entry
    bytes += cap.data.domain_capabilities.len()
        * (std::mem::size_of::<LocalHandle>() + std::mem::size_of::<CapabilityWeak<Domain>>());

    // pending_capabilities BTreeMap: key + value per entry
    bytes += cap.data.pending_capabilities.len()
        * (std::mem::size_of::<u64>() + std::mem::size_of::<PendingCapability>());

    // interrupt policy overrides BTreeMap: key + value per entry
    bytes += cap.data.policy.interrupts.overrides.len()
        * (std::mem::size_of::<u8>() + std::mem::size_of::<VectorPolicy>());

    // vprocessor_states Vec: each VProcessorState struct + its heap contents
    for vp in &cap.data.policy.vprocessor_states {
        bytes += std::mem::size_of::<VProcessorState>();
        // platform_data Vec payload
        bytes += vp.platform_data.len();
    }

    bytes
}

/// Compute logical memory footprint (bytes) of a single memory capability node.
fn memory_logical_bytes(cap: &Capability<MemoryRegion>) -> usize {
    let mut bytes = std::mem::size_of::<Capability<MemoryRegion>>();

    // children Vec heap buffer: one CapabilityRef<MemoryRegion> pointer per child
    bytes += cap.children.len() * std::mem::size_of::<CapabilityRef<MemoryRegion>>();

    bytes
}

/// Report logical memory usage of all capability engine objects
pub fn cmd_mem_usage(state: &mut CliState) -> std::result::Result<(), String> {
    struct DomainRow {
        name: String,
        id: u64,
        status: DomainStatus,
        num_children: usize,
        num_mem_caps: usize,
        num_domain_caps: usize,
        num_pending: usize,
        num_irq_overrides: usize,
        bytes: usize,
    }

    let mut domain_rows: Vec<DomainRow> = state
        .domains
        .iter()
        .map(|(name, arc)| {
            let cap = arc.read();
            DomainRow {
                name: name.clone(),
                id: cap.data.id,
                status: cap.data.status,
                num_children: cap.children.len(),
                num_mem_caps: cap.data.memory_capabilities.len(),
                num_domain_caps: cap.data.domain_capabilities.len(),
                num_pending: cap.data.pending_capabilities.len(),
                num_irq_overrides: cap.data.policy.interrupts.overrides.len(),
                bytes: domain_logical_bytes(&cap),
            }
        })
        .collect();
    domain_rows.sort_by_key(|r| r.id);

    struct MemRow {
        name: String,
        kind: RegionKind,
        start: u64,
        end: u64,
        num_children: usize,
        bytes: usize,
    }

    let mut mem_rows: Vec<MemRow> = state
        .memories
        .iter()
        .map(|(name, arc)| {
            let cap = arc.read();
            MemRow {
                name: name.clone(),
                kind: cap.data.kind,
                start: cap.data.access.start,
                end: cap.data.access.end(),
                num_children: cap.children.len(),
                bytes: memory_logical_bytes(&cap),
            }
        })
        .collect();
    mem_rows.sort_by_key(|r| r.start);

    let total_domain_bytes: usize = domain_rows.iter().map(|r| r.bytes).sum();
    let total_mem_bytes: usize = mem_rows.iter().map(|r| r.bytes).sum();
    let grand_total = total_domain_bytes + total_mem_bytes;

    println!("\n{}", "Memory Usage Report (logical sizes):".bright_cyan().bold());
    println!("{}", "─".repeat(72));

    // Domains section
    println!(
        "\n{} {} total, {} bytes",
        "Domains:".bright_yellow().bold(),
        domain_rows.len(),
        total_domain_bytes
    );
    if domain_rows.is_empty() {
        println!("  (none)");
    } else {
        println!(
            "  {:<16} {:>4}  {:<10}  {:>9}  {:>8}  {:>8}  {:>8}  {:>6}  {:>8}",
            "Name", "ID", "Status", "#Children", "#MemCaps", "#DomCaps", "#Pending", "#IRQs", "Bytes"
        );
        println!("  {}", "─".repeat(80));
        for r in &domain_rows {
            println!(
                "  {:<16} {:>4}  {:<10}  {:>9}  {:>8}  {:>8}  {:>8}  {:>6}  {:>8}",
                r.name,
                r.id,
                format!("{:?}", r.status),
                r.num_children,
                r.num_mem_caps,
                r.num_domain_caps,
                r.num_pending,
                r.num_irq_overrides,
                r.bytes
            );
        }
    }

    // Memory regions section
    println!(
        "\n{} {} total, {} bytes",
        "Memory Regions:".bright_yellow().bold(),
        mem_rows.len(),
        total_mem_bytes
    );
    if mem_rows.is_empty() {
        println!("  (none)");
    } else {
        println!(
            "  {:<16}  {:<6}  {:<28}  {:>9}  {:>8}",
            "Name", "Kind", "Range", "#Children", "Bytes"
        );
        println!("  {}", "─".repeat(72));
        for r in &mem_rows {
            println!(
                "  {:<16}  {:<6}  [{:#010x}..{:#010x})  {:>9}  {:>8}",
                r.name,
                format!("{:?}", r.kind),
                r.start,
                r.end,
                r.num_children,
                r.bytes
            );
        }
    }

    // Summary
    println!("\n{}", "Summary:".bright_yellow().bold());
    println!("  {:<22}  {:>8} bytes", "Domains:", total_domain_bytes);
    println!("  {:<22}  {:>8} bytes", "Memory regions:", total_mem_bytes);
    println!("  {}", "─".repeat(36));
    println!("  {:<22}  {:>8} bytes", "Total:", grand_total);
    println!();
    println!(
        "{}",
        "Note: logical sizes only; excludes allocator overhead, Arc ref-counts, and RwLock state."
            .bright_black()
    );
    println!();

    Ok(())
}

/// List all domains and memory regions with active core status
pub fn cmd_list(state: &mut CliState) -> std::result::Result<(), String> {
    // Show active domains per core
    println!("\n{}", "Active Domains per Core:".bright_cyan().bold());
    for core_id in 0..state.num_cores {
        if let Ok(core_ref) = state.platform.get_core(core_id as u64) {
            let core_state = core_ref.state.read();
            match *core_state {
                CoreState::Running(domain_id) => {
                    let domain_name = state
                        .get_domain_name(domain_id)
                        .unwrap_or("unknown");
                    println!(
                        "  {} Core {}: {} (ID: {})",
                        "✓".bright_green(),
                        core_id,
                        domain_name.bright_white(),
                        domain_id
                    );
                }
                CoreState::Idle => {
                    println!("  {} Core {}: {}", "○".bright_black(), core_id, "idle".bright_black());
                }
            }
        }
    }

    println!("\n{}", "Domains:".bright_cyan().bold());
    if state.domains.is_empty() {
        println!("  (none)");
    } else {
        for (name, domain) in &state.domains {
            let d = domain.read();
            if d.is_channel() {
                // Resolve channel target to show the actual domain it points to
                if let Some(target) = d.channel_target.as_ref().and_then(|w| w.upgrade()) {
                    let target = target.read();
                    println!(
                        "  {} {} (Channel → Domain ID: {}, status: {:?})",
                        "•".bright_yellow(),
                        name.bright_white(),
                        target.data.id,
                        target.data.status
                    );
                } else {
                    println!(
                        "  {} {} (Channel, target unavailable)",
                        "•".bright_yellow(),
                        name.bright_white(),
                    );
                }
            } else {
                println!(
                    "  {} {} (ID: {}, status: {:?})",
                    "•".bright_yellow(),
                    name.bright_white(),
                    d.data.id,
                    d.data.status
                );
            }
            let pending_ids = d.data.get_pending_ids();
            if !pending_ids.is_empty() {
                println!("    {} Pending capabilities ({}):", "⏸".bright_yellow(), pending_ids.len());
                for pending_id in pending_ids {
                    if let Some(pending_cap) = d.data.pending_capabilities.get(&pending_id) {
                        if let Some(m) = pending_cap.cap.upgrade() {
                            let m = m.read();
                            println!(
                                "      [ID: {}] Memory [0x{:x}..0x{:x}) {} (sender: {})",
                                pending_id, m.data.access.start, m.data.access.end(), m.data.access.rights,
                                pending_cap.sender_domain_id
                            );
                        }
                    }
                }
            }
        }
    }

    println!("\n{}", "Memory Regions:".bright_cyan().bold());
    if state.memories.is_empty() {
        println!("  (none)");
    } else {
        for (name, mem) in &state.memories {
            let m = mem.read();
            println!(
                "  {} {} {} (kind: {:?}, owner: {}, sub_handle: {}, attrs: {}, children: {})",
                "•".bright_yellow(),
                name.bright_white(),
                m.data.access,
                m.data.kind,
                m.owned.owner,
                m.sub_handle,
                m.owned.attributes,
                m.children.len()
            );
        }
    }

    println!("\n{}", "Physical Address Space:".bright_cyan().bold());
    display_physical_address_space(state);

    println!();
    Ok(())
}
