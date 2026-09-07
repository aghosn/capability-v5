//! Attestation support for capability trees and domains.
//!
//! The entry point is [`build_structured_attestation`]: it is the **single
//! source of truth** for attestation data, producing a flat, binary/structured
//! snapshot of a domain's own memory/domain capabilities.  Platform code
//! serializes it however it needs to (the capavisor's DomainComm wire format
//! via `StructuredAttestation::to_bytes`; `capa-cli` formats it into
//! human-readable text for its own display purposes) — no text formatting
//! or recursive tree-walking lives in the engine itself, keeping this
//! TCB-side logic minimal.
//!
//! [`attest_memory_region`] and [`enumerate_domain_tree`] are separate,
//! narrower helpers (standalone memory-region text dump, plain domain-ID
//! subtree enumeration) unrelated to the structured-attestation duplication
//! this module used to have.
//!
//! **Lock discipline.**  Each capability's read lock is held only for a brief
//! snapshot of its fields (cloning `Arc` refs and scalar data); all locks are
//! released before any recursive call.  Nested reads (domain → memory →
//! carved child) are always read-only and follow the child-before-parent
//! ordering used by mutation operations, so no deadlock can arise.

use crate::capability::{CapabilityRef, LocalHandle};
use crate::domain::Domain;
use crate::memory::MemoryRegion;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

// ─── Structured attestation ───────────────────────────────────────────────────

/// A memory capability entry in a structured attestation.
#[derive(Debug, Clone)]
pub struct MemCapInfo {
    pub handle: LocalHandle,
    /// Guest Physical Address (where this region appears in the domain's
    /// address space).  Falls back to `hpa` when no GPA mapping exists
    /// (e.g. the root domain with identity mapping).
    pub gpa: u64,
    /// Host Physical Address (the actual physical address of the region).
    pub hpa: u64,
    pub size: u64,
    pub rights: u32,
    pub attributes: u32,
}

/// A domain capability entry in a structured attestation.
#[derive(Debug, Clone)]
pub struct DomCapInfo {
    pub handle: LocalHandle,
    pub domain_id: u64,
}

/// A GPA→HPA translation entry.
#[derive(Debug, Clone)]
pub struct PaMapInfo {
    pub gpa: u64,
    pub hpa: u64,
    pub size: u64,
}

/// Structured attestation report for a domain.
///
/// Contains all the information a domain needs to understand its own
/// capabilities and address space.  Platform code can serialize this
/// into whatever wire format is appropriate (binary for the capavisor,
/// text for the CLI, etc.).
#[derive(Debug, Clone)]
pub struct StructuredAttestation {
    pub domain_id: u64,
    pub flags: u32,
    pub num_vps: u32,
    pub api_flags: u32,
    pub mem_caps: Vec<MemCapInfo>,
    pub dom_caps: Vec<DomCapInfo>,
    pub pa_map: Vec<PaMapInfo>,
}

impl StructuredAttestation {
    /// Serialize to the binary wire format used by DomainComm.
    ///
    /// Layout: `[header (40B)] [MemCapEntry * N] [DomCapEntry * N] [PaMapEntry * N]`
    ///
    /// The header and entry types match `themis-abi::domcomm` exactly.
    pub fn to_bytes(&self) -> Vec<u8> {
        // Header: 40 bytes (10 × u32/u64 fields, see AttestReport in domcomm.rs)
        let hdr_size = 40usize;
        let mem_entry_size = 40usize; // handle(8) + gpa(8) + size(8) + rights(4) + attr(4) + hpa(8)
        let dom_entry_size = 16usize; // handle(8) + domain_id(8)
        let pa_entry_size = 24usize;  // gpa(8) + hpa(8) + size(8)

        let total = hdr_size
            + self.mem_caps.len() * mem_entry_size
            + self.dom_caps.len() * dom_entry_size
            + self.pa_map.len() * pa_entry_size;

        let mut buf = Vec::with_capacity(total);

        // Header fields (little-endian)
        buf.extend_from_slice(&self.domain_id.to_le_bytes());       // 0..8
        buf.extend_from_slice(&self.flags.to_le_bytes());           // 8..12
        buf.extend_from_slice(&self.num_vps.to_le_bytes());         // 12..16
        buf.extend_from_slice(&self.api_flags.to_le_bytes());       // 16..20
        buf.extend_from_slice(&(self.mem_caps.len() as u32).to_le_bytes()); // 20..24
        buf.extend_from_slice(&(self.dom_caps.len() as u32).to_le_bytes()); // 24..28
        buf.extend_from_slice(&(self.pa_map.len() as u32).to_le_bytes());   // 28..32
        buf.extend_from_slice(&0u16.to_le_bytes());                 // chunk_index 32..34
        buf.extend_from_slice(&1u16.to_le_bytes());                 // total_chunks 34..36
        buf.extend_from_slice(&0u32.to_le_bytes());                 // reserved 36..40

        // MemCapEntry[]
        for m in &self.mem_caps {
            buf.extend_from_slice(&(m.handle as u64).to_le_bytes());
            buf.extend_from_slice(&m.gpa.to_le_bytes());
            buf.extend_from_slice(&m.size.to_le_bytes());
            buf.extend_from_slice(&m.rights.to_le_bytes());
            buf.extend_from_slice(&m.attributes.to_le_bytes());
            buf.extend_from_slice(&m.hpa.to_le_bytes());
        }

        // DomCapEntry[]
        for d in &self.dom_caps {
            buf.extend_from_slice(&(d.handle as u64).to_le_bytes());
            buf.extend_from_slice(&d.domain_id.to_le_bytes());
        }

        // PaMapEntry[]
        for p in &self.pa_map {
            buf.extend_from_slice(&p.gpa.to_le_bytes());
            buf.extend_from_slice(&p.hpa.to_le_bytes());
            buf.extend_from_slice(&p.size.to_le_bytes());
        }

        buf
    }
}

/// Build a structured attestation for the given domain.
///
/// This is the **single source of truth** for attestation data.  The
/// capavisor serializes it with [`StructuredAttestation::to_bytes()`];
/// the CLI can format it however it likes.
pub fn build_structured_attestation(
    domain_ref: &CapabilityRef<Domain>,
) -> StructuredAttestation {
    let domain = domain_ref.read();
    let domain_id = domain.data.id;
    let num_vps = domain.data.policy.num_vprocessors as u32;
    let api_flags = domain.data.policy.api.bits() as u32;
    let flags = if domain.data.is_sealed() { 1u32 } else { 0u32 };

    // Memory capabilities with proper GPA lookup.
    let mem_caps: Vec<MemCapInfo> = domain
        .data
        .memory_capabilities
        .iter()
        .filter_map(|(handle, weak)| {
            let cap_ref = weak.upgrade()?;
            let c = cap_ref.read();
            let hpa = c.data.access.start;
            #[cfg(feature = "address_translation")]
            let gpa = domain.data.mapped_gpas.get(handle).copied().unwrap_or(hpa);
            #[cfg(not(feature = "address_translation"))]
            let gpa = hpa;
            Some(MemCapInfo {
                handle: *handle,
                gpa,
                hpa,
                size: c.data.access.size,
                rights: c.data.access.rights.bits() as u32,
                attributes: c.owned.attributes.bits() as u32,
            })
        })
        .collect();

    // Domain capabilities.
    let dom_caps: Vec<DomCapInfo> = domain
        .data
        .domain_capabilities
        .iter()
        .filter_map(|(handle, weak)| {
            let cap_ref = weak.upgrade()?;
            let c = cap_ref.read();
            Some(DomCapInfo {
                handle: *handle,
                domain_id: c.data.id,
            })
        })
        .collect();

    // PA map: non-META, non-COMM memory capabilities.
    let meta_bit = crate::memory::Attributes::META as u32;
    let comm_bit = crate::memory::Attributes::COMM as u32;
    let pa_map: Vec<PaMapInfo> = mem_caps
        .iter()
        .filter(|m| m.attributes & meta_bit == 0)
        .filter(|m| m.attributes & comm_bit == 0)
        .filter(|m| m.size > 0)
        .map(|m| PaMapInfo {
            gpa: m.gpa,
            hpa: m.hpa,
            size: m.size,
        })
        .collect();

    drop(domain);

    StructuredAttestation {
        domain_id,
        flags,
        num_vps,
        api_flags,
        mem_caps,
        dom_caps,
        pa_map,
    }
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
