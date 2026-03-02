//! Attestation support for capability trees and domains

use crate::capability::CapabilityRef;
use crate::domain::{Domain, InterruptVisibility};
use crate::memory::MemoryRegion;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// Attestation report for a domain capability tree
#[derive(Debug, Clone)]
pub struct AttestationReport {
    /// Domain being attested
    pub domain_id: u64,
    /// Textual representation of the domain and its capabilities
    pub report: String,
    /// Signature over the report (to be filled by platform-specific signing)
    pub signature: Option<Vec<u8>>,
}

impl AttestationReport {
    /// Create a new attestation report
    pub fn new(domain_id: u64, report: String) -> Self {
        AttestationReport {
            domain_id,
            report,
            signature: None,
        }
    }

    /// Set the signature
    pub fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = Some(signature);
        self
    }
}

/// Generate an attestation report for a domain
pub fn attest_domain(domain_ref: &CapabilityRef<Domain>) -> AttestationReport {
    let domain = domain_ref.read();
    let mut report = format!("Domain ID: {}\n", domain.data.id);
    report.push_str(&format!("Status: {:?}\n", domain.data.status));
    report.push_str(&format!("Cores: {:#b}\n", domain.data.policy.cores));
    report.push_str("API:\n");
    report.push_str(&format!("  CREATE: {}\n", domain.data.policy.api.create()));
    report.push_str(&format!("  SET: {}\n", domain.data.policy.api.set_perm()));
    report.push_str(&format!("  GET: {}\n", domain.data.policy.api.get()));
    report.push_str(&format!("  SEND: {}\n", domain.data.policy.api.send()));
    report.push_str(&format!("  SEAL: {}\n", domain.data.policy.api.seal()));
    report.push_str(&format!("  ATTEST: {}\n", domain.data.policy.api.attest()));
    report.push_str(&format!(
        "  ENUMERATE: {}\n",
        domain.data.policy.api.enumerate()
    ));
    report.push_str(&format!("  SWITCH: {}\n", domain.data.policy.api.switch()));
    report.push_str(&format!("  ALIAS: {}\n", domain.data.policy.api.alias()));
    report.push_str(&format!("  CARVE: {}\n", domain.data.policy.api.carve()));
    report.push_str(&format!("  REVOKE: {}\n", domain.data.policy.api.revoke()));
    report.push_str(&format!(
        "  GETCHAN: {}\n",
        domain.data.policy.api.getchan()
    ));
    report.push_str(&format!(
        "  RECEIVE_AFTER_SEAL: {}\n",
        domain.data.policy.api.receive_after_seal()
    ));

    // Interrupt configuration
    report.push_str("Interrupts:\n");
    let irq = &domain.data.policy.interrupts;
    let default_vis = match irq.default.visibility {
        InterruptVisibility::Deliver => "Deliver",
        InterruptVisibility::Report => "Report",
        InterruptVisibility::NotReport => "NotReport",
    };
    report.push_str(&format!(
        "  Default: visibility={}, read_set={:#018x}, write_set={:#018x}\n",
        default_vis, irq.default.read_set, irq.default.write_set
    ));
    if irq.overrides.is_empty() {
        report.push_str("  Overrides: (none)\n");
    } else {
        report.push_str("  Overrides:\n");
        for (vector, policy) in &irq.overrides {
            let vis = match policy.visibility {
                InterruptVisibility::Deliver => "Deliver",
                InterruptVisibility::Report => "Report",
                InterruptVisibility::NotReport => "NotReport",
            };
            report.push_str(&format!(
                "    Vector {:#04x}: visibility={}, read_set={:#018x}, write_set={:#018x}\n",
                vector, vis, policy.read_set, policy.write_set
            ));
        }
    }

    report.push_str(&format!("Children: {}\n", domain.children.len()));

    // Include parent info if exists
    if let Some(parent) = domain.get_parent() {
        let parent_read = parent.read();
        report.push_str(&format!("Parent Domain ID: {}\n", parent_read.data.id));
    } else {
        report.push_str("Parent: None (root domain)\n");
    }

    // List owned domain capabilities
    report.push_str("\nOwned Domain Capabilities:\n");
    if domain.data.domain_capabilities.is_empty() {
        report.push_str("  (none)\n");
    } else {
        for (handle, weak_ref) in &domain.data.domain_capabilities {
            if let Some(child_domain_ref) = weak_ref.upgrade() {
                let child = child_domain_ref.read();
                report.push_str(&format!(
                    "  Handle {}: Domain {} (status: {:?})\n",
                    handle, child.data.id, child.data.status
                ));
            }
        }
    }

    // List owned memory capabilities with their children
    report.push_str("\nOwned Memory Capabilities:\n");
    if domain.data.memory_capabilities.is_empty() {
        report.push_str("  (none)\n");
    } else {
        for (handle, weak_ref) in &domain.data.memory_capabilities {
            if let Some(mem_ref) = weak_ref.upgrade() {
                let mem = mem_ref.read();
                report.push_str(&format!(
                    "  Handle {}: {} (kind: {:?}, attrs: {})\n",
                    handle, mem.data.access, mem.data.kind, mem.owned.attributes
                ));

                // Show direct children
                if !mem.children.is_empty() {
                    for child_ref in &mem.children {
                        let child = child_ref.read();
                        let operation = match child.data.kind {
                            crate::memory::RegionKind::Carve => "carved",
                            crate::memory::RegionKind::Alias => "aliased",
                        };
                        report.push_str(&format!(
                            "    | {} at {:#x} size {:#x} {}\n",
                            operation,
                            child.data.access.start,
                            child.data.access.size,
                            child.data.access.rights
                        ));
                    }
                }
            }
        }
    }

    AttestationReport::new(domain.data.id, report)
}

/// Generate an attestation report for a memory region capability tree
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

    // Include parent info if exists
    if let Some(parent) = region.get_parent() {
        let parent_read = parent.read();
        report.push_str(&format!("  Parent: {}\n", parent_read.data.access));
    } else {
        report.push_str("  Parent: None (root region)\n");
    }

    report
}

/// Enumerate all capabilities in a domain's subtree
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
