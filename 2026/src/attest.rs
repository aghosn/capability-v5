//! Attestation support for capability trees and domains.
//!
//! The entry point is [`attest_domain`].  Internally it uses a recursive
//! helper (`attest_with_context`) that carries a name-assignment context
//! (`AttestContext`) down the capability tree so that every capability is
//! named exactly once and the same name is reused whenever the same capability
//! appears again (e.g., a carved child visible from both its parent memory cap
//! and the domain that received it).
//!
//! **Lock discipline.**  Each capability's read lock is held only for a brief
//! snapshot of its fields (cloning `Arc` refs and scalar data); all locks are
//! released before any recursive call.  Nested reads (domain → memory →
//! carved child) are always read-only and follow the child-before-parent
//! ordering used by mutation operations, so no deadlock can arise.

use crate::capability::{CapabilityRef, CapabilityWeak, LocalHandle};
use crate::domain::{Domain, DomainPolicy, DomainStatus, InterruptVisibility};
use crate::memory::MemoryRegion;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

// ─── Public types ─────────────────────────────────────────────────────────────

/// Attestation report for a domain capability tree.
#[derive(Debug, Clone)]
pub struct AttestationReport {
    /// Domain being attested.
    pub domain_id: u64,
    /// Textual representation of the domain and its capabilities.
    pub report: String,
    /// Signature over the report (filled by platform-specific signing).
    pub signature: Option<Vec<u8>>,
}

impl AttestationReport {
    pub fn new(domain_id: u64, report: String) -> Self {
        AttestationReport { domain_id, report, signature: None }
    }

    pub fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = Some(signature);
        self
    }
}

// ─── Name-assignment context ──────────────────────────────────────────────────

/// Carried through the recursive attestation, mapping each `Arc` pointer
/// (stable identity of the capability's heap allocation) to a human-readable
/// name: `dN` for ordinary domain capabilities, `chN` for channel
/// capabilities, `mN` for memory region capabilities.
struct AttestContext {
    domain_names: BTreeMap<usize, String>,
    memory_names: BTreeMap<usize, String>,
    domain_counter: usize,
    memory_counter: usize,
    channel_counter: usize,
}

impl AttestContext {
    fn new() -> Self {
        AttestContext {
            domain_names: BTreeMap::new(),
            memory_names: BTreeMap::new(),
            domain_counter: 0,
            memory_counter: 0,
            channel_counter: 0,
        }
    }

    fn domain_key(r: &CapabilityRef<Domain>) -> usize {
        Arc::as_ptr(r) as usize
    }

    fn memory_key(r: &CapabilityRef<MemoryRegion>) -> usize {
        Arc::as_ptr(r) as usize
    }

    /// Assign a name if not yet named; return a reference to the stored name.
    fn name_domain(&mut self, r: &CapabilityRef<Domain>, is_channel: bool) -> &str {
        let key = Self::domain_key(r);
        if !self.domain_names.contains_key(&key) {
            let name = if is_channel {
                let n = self.channel_counter;
                self.channel_counter += 1;
                format!("ch{n}")
            } else {
                let n = self.domain_counter;
                self.domain_counter += 1;
                format!("d{n}")
            };
            self.domain_names.insert(key, name);
        }
        self.domain_names[&key].as_str()
    }

    fn name_memory(&mut self, r: &CapabilityRef<MemoryRegion>) -> &str {
        let key = Self::memory_key(r);
        if !self.memory_names.contains_key(&key) {
            let n = self.memory_counter;
            self.memory_counter += 1;
            self.memory_names.insert(key, format!("m{n}"));
        }
        self.memory_names[&key].as_str()
    }

    fn get_domain_name(&self, r: &CapabilityRef<Domain>) -> &str {
        self.domain_names
            .get(&Self::domain_key(r))
            .map(|s| s.as_str())
            .unwrap_or("?")
    }

    fn get_memory_name(&self, r: &CapabilityRef<MemoryRegion>) -> &str {
        self.memory_names
            .get(&Self::memory_key(r))
            .map(|s| s.as_str())
            .unwrap_or("?")
    }
}

// ─── Memory-subtree pre-naming ────────────────────────────────────────────────

/// Recursively assign names to all carved/aliased children of `mem_ref`.
///
/// Called before emitting the `| carved/aliased … for mN` lines so that the
/// child name is always available when it is first referenced, even if the
/// child is owned by a domain that has not yet been visited.
///
/// **Lock discipline:** `mem_ref` read lock is held only for the brief
/// snapshot of its children; released before recursing.
fn name_memory_children(ctx: &mut AttestContext, mem_ref: &CapabilityRef<MemoryRegion>) {
    let children: Vec<CapabilityRef<MemoryRegion>> = {
        let cap = mem_ref.read();
        cap.children.iter().cloned().collect()
    };
    // Lock released.
    for child_ref in children {
        ctx.name_memory(&child_ref);
        name_memory_children(ctx, &child_ref);
    }
}

// ─── Snapshot helper ──────────────────────────────────────────────────────────

/// All data captured from a domain capability under a single brief read lock.
/// Cloning `Arc`/`Weak` refs just adjusts reference counts — no capability
/// data is copied, and the lock is released before any further processing.
struct DomainSnapshot {
    is_channel: bool,
    channel_target_weak: Option<CapabilityWeak<Domain>>,
    id: u64,
    status: DomainStatus,
    policy: DomainPolicy,
    /// Number of children in the capability tree (for the "Children:" line).
    children_len: usize,
    /// Weak ref to the parent capability (used to print the parent domain ID).
    parent_weak: CapabilityWeak<Domain>,
    /// Owned domain capabilities in handle order.
    domain_caps: Vec<(LocalHandle, CapabilityWeak<Domain>)>,
    /// Owned memory capabilities in handle order.
    mem_caps: Vec<(LocalHandle, CapabilityWeak<MemoryRegion>)>,
    /// Strong refs to child capability nodes in the tree (for recursion).
    child_refs: Vec<CapabilityRef<Domain>>,
}

impl DomainSnapshot {
    fn take(cap_ref: &CapabilityRef<Domain>) -> Self {
        let cap = cap_ref.read();
        DomainSnapshot {
            is_channel: cap.is_channel(),
            channel_target_weak: cap.channel_target.clone(),
            id: cap.data.id,
            status: cap.data.status,
            policy: cap.data.policy.clone(),
            children_len: cap.children.len(),
            parent_weak: cap.parent.clone(),
            domain_caps: cap
                .data
                .domain_capabilities
                .iter()
                .map(|(h, w)| (*h, w.clone()))
                .collect(),
            mem_caps: cap
                .data
                .memory_capabilities
                .iter()
                .map(|(h, w)| (*h, w.clone()))
                .collect(),
            child_refs: cap.children.iter().cloned().collect(),
        }
    }
}

// ─── Recursive attestation ────────────────────────────────────────────────────

/// Emit the full attestation for `cap_ref` and all of its descendants into a
/// returned `String`.  Names are assigned into `ctx` on first encounter and
/// reused on subsequent encounters.
///
/// **Precondition:** `cap_ref` has already been named in `ctx` by the caller.
///
/// `expand_children` controls whether child domains are recursed into and
/// given their own full section.  The root domain is called with
/// `expand_children = true`; children are called with `expand_children = false`
/// so that grandchildren are named and referenced but never fully printed.
/// This matches the paper's semantics: an attestation shows the attested
/// domain and its directly-owned domains in full, but goes no deeper.
///
/// **Lock discipline:** `DomainSnapshot::take` holds the read lock for one
/// brief scope and releases it before any further work.  All subsequent
/// reads (memory data, parent ID, child domain data) are independent
/// short-lived read locks with no domain lock held concurrently.
fn attest_with_context(
    cap_ref: &CapabilityRef<Domain>,
    ctx: &mut AttestContext,
    expand_children: bool,
) -> String {
    // ── 1. Snapshot ─────────────────────────────────────────────────────────
    let snap = DomainSnapshot::take(cap_ref);
    // Domain read lock released.

    // ── 2. Channel caps: compact single-line entry, no recursion ────────────
    if snap.is_channel {
        let own_name = ctx.get_domain_name(cap_ref);
        let line = if let Some(target_ref) =
            snap.channel_target_weak.as_ref().and_then(|w| w.upgrade())
        {
            let target_name = ctx.get_domain_name(&target_ref);
            format!("{own_name} = Channel → {target_name}\n")
        } else {
            format!("{own_name} = Channel (target unavailable)\n")
        };
        return line;
    }

    // ── 3. Upgrade memory weak refs ──────────────────────────────────────────
    let mem_refs: Vec<(LocalHandle, CapabilityRef<MemoryRegion>)> = snap
        .mem_caps
        .iter()
        .filter_map(|(h, w)| w.upgrade().map(|r| (*h, r)))
        .collect();

    // ── 4. Name owned memory caps (so they appear in the header) ────────────
    for (_, mem_ref) in &mem_refs {
        ctx.name_memory(mem_ref);
    }

    // ── 5. Name child domains (so they appear in the header) ─────────────────
    for child_ref in &snap.child_refs {
        let is_ch = child_ref.read().is_channel();
        ctx.name_domain(child_ref, is_ch);
    }

    // ── 6. Pre-name carved/aliased children of owned memory ──────────────────
    //    This ensures the "| carved … for mN" name is already in ctx when we
    //    emit the memory section, even if mN is owned by a child domain.
    for (_, mem_ref) in &mem_refs {
        name_memory_children(ctx, mem_ref);
    }

    // ── 7. Format this domain's section ─────────────────────────────────────
    let mut out = String::new();

    // Summary header.
    let domain_name = ctx.get_domain_name(cap_ref);
    let mut summary: Vec<String> = Vec::new();
    for (_, weak) in &snap.domain_caps {
        if let Some(r) = weak.upgrade() {
            summary.push(format!("{}", ctx.get_domain_name(&r)));
        }
    }
    for (_, mem_ref) in &mem_refs {
        summary.push(format!("{}", ctx.get_memory_name(mem_ref)));
    }
    if summary.is_empty() {
        out.push_str(&format!("{domain_name} = {:?} domain()\n", snap.status));
    } else {
        out.push_str(&format!(
            "{domain_name} = {:?} domain({})\n",
            snap.status,
            summary.join(", ")
        ));
    }

    // Core fields.
    out.push_str(&format!("Domain ID: {}\n", snap.id));
    out.push_str(&format!("Status: {:?}\n", snap.status));
    out.push_str(&format!("Cores: {:#b}\n", snap.policy.cores));

    // API.
    out.push_str("API:\n");
    out.push_str(&format!("  CREATE: {}\n", snap.policy.api.create()));
    out.push_str(&format!("  SET: {}\n", snap.policy.api.set_perm()));
    out.push_str(&format!("  GET: {}\n", snap.policy.api.get()));
    out.push_str(&format!("  SEND: {}\n", snap.policy.api.send()));
    out.push_str(&format!("  SEAL: {}\n", snap.policy.api.seal()));
    out.push_str(&format!("  ATTEST: {}\n", snap.policy.api.attest()));
    out.push_str(&format!("  ENUMERATE: {}\n", snap.policy.api.enumerate()));
    out.push_str(&format!("  SWITCH: {}\n", snap.policy.api.switch()));
    out.push_str(&format!("  ALIAS: {}\n", snap.policy.api.alias()));
    out.push_str(&format!("  CARVE: {}\n", snap.policy.api.carve()));
    out.push_str(&format!("  REVOKE: {}\n", snap.policy.api.revoke()));
    out.push_str(&format!("  GETCHAN: {}\n", snap.policy.api.getchan()));
    out.push_str(&format!(
        "  RECEIVE_AFTER_SEAL: {}\n",
        snap.policy.api.receive_after_seal()
    ));

    // Interrupts.
    out.push_str("Interrupts:\n");
    let irq = &snap.policy.interrupts;
    let vis_str = |v: &InterruptVisibility| match v {
        InterruptVisibility::Deliver => "Deliver",
        InterruptVisibility::Report => "Report",
        InterruptVisibility::NotReport => "NotReport",
    };
    out.push_str(&format!(
        "  Default: visibility={}, read={:x}, write={:x}\n",
        vis_str(&irq.default.visibility),
        irq.default.read_set,
        irq.default.write_set,
    ));
    if irq.overrides.is_empty() {
        out.push_str("  Overrides: (none)\n");
    } else {
        out.push_str("  Overrides:\n");
        for (vector, policy) in &irq.overrides {
            out.push_str(&format!(
                "    Vector {:#04x}: visibility={}, read={:x}, write={:x}\n",
                vector,
                vis_str(&policy.visibility),
                policy.read_set,
                policy.write_set,
            ));
        }
    }

    // Children / parent.
    out.push_str(&format!("Children: {}\n", snap.children_len));
    if let Some(parent_ref) = snap.parent_weak.upgrade() {
        // Brief independent read of the parent cap (no domain lock held).
        let parent_id = parent_ref.read().data.id;
        out.push_str(&format!("Parent Domain ID: {parent_id}\n"));
    } else {
        out.push_str("Parent: None (root domain)\n");
    }

    // Owned domain capabilities.
    out.push_str("\nOwned Domain Capabilities:\n");
    if snap.domain_caps.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for (handle, weak) in &snap.domain_caps {
            if let Some(child_ref) = weak.upgrade() {
                let child_name = ctx.get_domain_name(&child_ref);
                // Brief read to detect channel and resolve target name.
                let child_cap = child_ref.read();
                if child_cap.is_channel() {
                    if let Some(target) =
                        child_cap.channel_target.as_ref().and_then(|w| w.upgrade())
                    {
                        let target_name = ctx.get_domain_name(&target);
                        out.push_str(&format!(
                            "  Handle {handle}: {child_name} = Channel → {target_name}\n"
                        ));
                    } else {
                        out.push_str(&format!(
                            "  Handle {handle}: {child_name} = Channel (target unavailable)\n"
                        ));
                    }
                } else {
                    out.push_str(&format!("  Handle {handle}: {child_name}\n"));
                }
            }
        }
    }

    // Owned memory capabilities.
    out.push_str("\nOwned Memory Capabilities:\n");
    if mem_refs.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for (handle, mem_ref) in &mem_refs {
            let mem_name = ctx.get_memory_name(mem_ref);

            // Snapshot all memory data we need, then release the lock before
            // any further reads.  This avoids holding mem_ref.read() while
            // acquiring cap_ref.read() for the GPA lookup: mutations such as
            // revoke_domain may hold cap_ref.write() (domain) before acquiring
            // mem_ref.write() (memory), so taking those locks in the opposite
            // order here would create an ABBA deadlock risk.
            #[allow(unused_variables)]
            let (access_str, kind_str, attrs_str, hpa, child_refs_snap) = {
                let mem = mem_ref.read();
                (
                    format!("{}", mem.data.access),
                    format!("{:?}", mem.data.kind),
                    format!("{}", mem.owned.attributes),
                    mem.data.access.start,
                    mem.children.iter().cloned().collect::<Vec<_>>(),
                )
            };
            // mem_ref read lock released.

            out.push_str(&format!(
                "  Handle {handle}: {mem_name} = {access_str} (kind: {kind_str}, attrs: {attrs_str})\n"
            ));

            // GPA lookup: brief independent read of the domain cap.
            // No mem lock is held at this point.
            #[cfg(feature = "address_translation")]
            {
                let gpa_opt = cap_ref.read().data.address_map.find_gpa_for_hpa(hpa, 1);
                if let Some(gpa) = gpa_opt {
                    if gpa != hpa {
                        out.push_str(&format!("    GPA: {:#x} (HPA {:#x})\n", gpa, hpa));
                    } else {
                        out.push_str(&format!("    GPA: {:#x} (identity)\n", gpa));
                    }
                }
            }

            for child_ref in &child_refs_snap {
                let child_name = ctx.get_memory_name(child_ref);
                let child = child_ref.read();
                let op = match child.data.kind {
                    crate::memory::RegionKind::Carve => "carved",
                    crate::memory::RegionKind::Alias => "aliased",
                };
                out.push_str(&format!(
                    "    | {op} at {:#x} size {:#x} {} for {child_name}\n",
                    child.data.access.start,
                    child.data.access.size,
                    child.data.access.rights
                ));
            }
        }
    }

    // GPA address space (requires a brief re-read of the domain cap since
    // address_map lives on Domain.data, which was not cloned into the snapshot).
    #[cfg(feature = "address_translation")]
    {
        out.push_str("\nGPA Address Space:\n");
        let cap = cap_ref.read();
        let entries = cap.data.address_map.entries();
        if entries.is_empty() {
            out.push_str("  (empty)\n");
        } else {
            for (gpa, entry) in entries {
                match entry {
                    crate::translation::MapEntry::Mapped(m) => {
                        out.push_str(&format!(
                            "  GPA {:#x}..{:#x} → HPA {:#x} {} {}\n",
                            gpa,
                            gpa + m.size,
                            m.hpa_start,
                            m.rights,
                            if *gpa == m.hpa_start { "(identity)" } else { "" }
                        ));
                    }
                    crate::translation::MapEntry::Blocked { hpa_start, size } => {
                        out.push_str(&format!(
                            "  GPA {:#x}..{:#x} → BLOCKED (HPA {:#x})\n",
                            gpa,
                            gpa + size,
                            hpa_start
                        ));
                    }
                }
            }
        }
    }

    // ── 8. Recurse into child domains (one level only) ───────────────────────
    // Children are expanded only when the caller permits it.  This enforces
    // the attestation depth limit: the attested domain and its directly-owned
    // child domains are shown in full; grandchildren are only referenced by
    // name within their parent's "Owned Domain Capabilities" section.
    if expand_children {
        for child_ref in &snap.child_refs {
            out.push('\n');
            out.push_str(&attest_with_context(child_ref, ctx, false));
        }
    }

    out
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Generate a named attestation report for a domain (or channel) capability.
///
/// The attested domain is named `d0`; its child domains are named `d1`, `d2`,
/// … in DFS pre-order (children named before recursing).  Channel capabilities
/// are named `chN`.  Memory region capabilities are named `mN` in the order
/// they are first encountered.  The same name is used wherever the same
/// capability appears (e.g., a carved child is named once and cross-referenced
/// on the `| carved … for mN` line of its parent memory cap).
///
/// If `domain_ref` is itself a channel the target domain is attested and the
/// report is prefixed with `Channel: true` / `Target Domain ID:` headers.
pub fn attest_domain(domain_ref: &CapabilityRef<Domain>) -> AttestationReport {
    // Resolve channel indirection.
    let (effective_ref, is_channel) = {
        let r = domain_ref.read();
        if r.is_channel() {
            let target = r.channel_target.as_ref().and_then(|w| w.upgrade());
            drop(r);
            (target.unwrap_or_else(|| domain_ref.clone()), true)
        } else {
            drop(r);
            (domain_ref.clone(), false)
        }
    };

    let domain_id = effective_ref.read().data.id;

    // Initialise context and name the root domain first so it receives `d0`.
    let mut ctx = AttestContext::new();
    ctx.name_domain(&effective_ref, false); // effective_ref is always a non-channel

    let mut report = String::new();
    if is_channel {
        report.push_str("Channel: true\n");
        report.push_str(&format!("Target Domain ID: {domain_id}\n\n"));
    }
    report.push_str(&attest_with_context(&effective_ref, &mut ctx, true));

    AttestationReport::new(domain_id, report)
}

/// Generate an attestation report for a standalone memory region capability.
pub fn attest_memory_region(region_ref: &CapabilityRef<MemoryRegion>) -> String {
    let region = region_ref.read();
    let mut report = format!("Memory Region:\n");
    report.push_str(&format!("  Owner: {}\n", region.owned.owner));
    report.push_str(&format!("  Handle: {}\n", region.sub_handle));
    report.push_str(&format!("  Kind: {:?}\n", region.data.kind));
    report.push_str(&format!("  Status: {:?}\n", region.data.status));
    report.push_str(&format!("  Access: {}\n", region.data.access));
    report.push_str(&format!("  Attributes: {}\n", region.owned.attributes));

    if region.owned.attributes.hash() {
        if let Some(hash) = &region.data.content_hash {
            report.push_str(&format!("  Content Hash: {:?}\n", hash));
        }
    }

    report.push_str(&format!("  Children: {}\n", region.children.len()));

    if let Some(parent) = region.get_parent() {
        let parent_read = parent.read();
        report.push_str(&format!("  Parent: {}\n", parent_read.data.access));
    } else {
        report.push_str("  Parent: None (root region)\n");
    }

    report
}

/// Enumerate all domain IDs in a domain's subtree (DFS pre-order).
pub fn enumerate_domain_tree(domain_ref: &CapabilityRef<Domain>) -> Vec<u64> {
    let mut domain_ids = Vec::new();
    enumerate_domain_recursive(domain_ref, &mut domain_ids);
    domain_ids
}

fn enumerate_domain_recursive(domain_ref: &CapabilityRef<Domain>, ids: &mut Vec<u64>) {
    let domain = domain_ref.read();
    ids.push(domain.data.id);
    for child_ref in &domain.children {
        enumerate_domain_recursive(child_ref, ids);
    }
}
