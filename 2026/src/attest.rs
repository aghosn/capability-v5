//! Attestation support for capability trees and domains

use crate::capability::CapabilityRef;
use crate::domain::Domain;
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
    report.push_str(&format!(
        "Cores: {:#b}\n",
        domain.data.policy.cores
    ));
    report.push_str("API:\n");
    report.push_str(&format!("  CREATE: {}\n", domain.data.policy.api.create()));
    report.push_str(&format!("  SET: {}\n", domain.data.policy.api.set_perm()));
    report.push_str(&format!("  GET: {}\n", domain.data.policy.api.get()));
    report.push_str(&format!("  SEND: {}\n", domain.data.policy.api.send()));
    report.push_str(&format!("  SEAL: {}\n", domain.data.policy.api.seal()));
    report.push_str(&format!("  ATTEST: {}\n", domain.data.policy.api.attest()));
    report.push_str(&format!("  ENUMERATE: {}\n", domain.data.policy.api.enumerate()));
    report.push_str(&format!("  SWITCH: {}\n", domain.data.policy.api.switch()));
    report.push_str(&format!("  ALIAS: {}\n", domain.data.policy.api.alias()));
    report.push_str(&format!("  CARVE: {}\n", domain.data.policy.api.carve()));
    report.push_str(&format!("  REVOKE: {}\n", domain.data.policy.api.revoke()));
    report.push_str(&format!("  GETCHAN: {}\n", domain.data.policy.api.getchan()));

    report.push_str(&format!(
        "Children: {}\n",
        domain.children.len()
    ));

    // Include parent info if exists
    if let Some(parent) = domain.get_parent() {
        let parent_read = parent.read();
        report.push_str(&format!("Parent Domain ID: {}\n", parent_read.data.id));
    } else {
        report.push_str("Parent: None (root domain)\n");
    }

    AttestationReport::new(domain.data.id, report)
}

/// Generate an attestation report for a memory region capability tree
pub fn attest_memory_region(region_ref: &CapabilityRef<MemoryRegion>) -> String {
    let region = region_ref.read();
    let mut report = format!("Memory Region:\n");
    report.push_str(&format!("  Owner: {}\n", region.owned.owner));
    report.push_str(&format!("  Handle: {}\n", region.owned.handle));
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
