//! Phase 2c: capability engine + EPT setup for dom0.

extern crate alloc;
use alloc::vec::Vec;

use crate::serial_println;

use super::{CapaState, PlatformInfo};

// ── Phase 2c: Capability engine + EPT ────────────────────────────────────── //

/// Phase P2c: initialise the capability engine for dom0.
///
/// Receives the already-bootstrapped `ThemisPlatform` (domain 0 registered, full
/// META pool given).  Builds the capability tree and drives `UpdateBatch`es of
/// `ChangeRights` to map dom0's memory into the EPT.
///
/// # Bootstrap inversion
///
/// During normal operation the capability engine drives hardware state: a
/// capability is created first, then `ChangeRights` propagates it to the EPT.
/// Bootstrap inverts this order — hardware structures (VMXON, META allocator, EPT
/// root) are set up before the capability records exist.  The end result must be
/// strictly equivalent: every region accessible to dom0 in the EPT has exactly
/// one corresponding capability record, and every capability record has exactly
/// one EPT mapping.  Any divergence is a security bug.
///
/// # Capability forest
///
/// dom0's memory capability tree is a **forest** of independent roots, one per
/// disjoint physical region:
/// - one root per `dom0_owned` RAM region
/// - one root per passthrough region (MMIO / ACPI / NVS)
/// - one META-flagged root for the META pool
///
/// There is no single root that covers all memory.  Attestation must walk every
/// root; delegation produces sub-capabilities bounded by a single root's extent;
/// revocation only affects the subtree of the revoked root.
pub fn capa(info: &PlatformInfo, platform: crate::platform::ThemisPlatform) -> CapaState {
    use alloc::sync::Arc;
    use capability_engine::{
        Attributes, Capability, Domain as CapaDomain, DomainId, MemoryRegion, Rights, UpdateBatch,
    };

    const ROOT_ID: DomainId = 0;

    serial_println!();
    serial_println!("=== P2c: capability engine init ===");

    // ── Root domain capability ─────────────────────────────────────────── //

    let root_domain = Capability::new_root(ROOT_ID, 0, CapaDomain::new_root(info.num_cores));

    // ── Memory capabilities ────────────────────────────────────────────── //

    let mut mem_caps: Vec<capability_engine::CapabilityRef<MemoryRegion>> = Vec::new();
    let meta_caps;
    let comm_root_handle: u64;
    let self_domain_cap_handle: u64;
    {
        let mut dom = root_domain.write();
        let mut sub = 1u64;

        for region in &info.partition.dom0_owned[..info.partition.dom0_owned_count] {
            if region.length == 0 {
                continue;
            }
            let mem_cap = Capability::new_root(
                ROOT_ID,
                sub,
                MemoryRegion::new_root(region.base, region.length),
            );
            dom.data
                .add_memory_capability(sub, Arc::downgrade(&mem_cap));
            serial_println!(
                "  mem cap #{}: {:#x}+{:#x} ({} KiB)",
                sub,
                region.base,
                region.length,
                region.length / 1024,
            );
            mem_caps.push(mem_cap);
            sub += 1;
        }

        // ── Passthrough capabilities (MMIO / ACPI / NVS) ─────────────────── //
        //
        // Every non-RAM region mapped in dom0's EPT must have a corresponding
        // capability record so that the capability state fully reflects what
        // dom0 can access.  Without these, attestation would be blind to all
        // device MMIO and firmware table regions.
        //
        // These are regular (non-META) capabilities — MMIO regions ARE mapped
        // in the EPT and are therefore visible to dom0, unlike META pages.
        for region in &info.passthrough_regions {
            if region.length == 0 {
                continue;
            }
            let mem_cap = Capability::new_root(
                ROOT_ID,
                sub,
                MemoryRegion::new_root(region.base, region.length),
            );
            dom.data
                .add_memory_capability(sub, Arc::downgrade(&mem_cap));
            serial_println!(
                "  passthrough cap #{}: {:#x}+{:#x} ({} KiB)",
                sub,
                region.base,
                region.length,
                region.length / 1024,
            );
            mem_caps.push(mem_cap);
            sub += 1;
        }

        // ── META capabilities ─────────────────────────────────────────────── //
        //
        // The META regions were already handed to the platform allocator in
        // bootstrap_give_meta().  Here we create the matching capability
        // records so that dom0's capability state reflects ownership of those
        // pages.  One META-flagged MemoryRegion capability per physical META region.
        let mut meta_caps_local: Vec<capability_engine::CapabilityRef<MemoryRegion>> = Vec::new();
        for i in 0..info.partition.meta_count {
            let r = &info.partition.meta_regions[i];
            let cap = Capability::new_root(ROOT_ID, sub, MemoryRegion::new_root(r.base, r.length));
            {
                let mut c = cap.write();
                c.owned.attributes = Attributes::from_bits(Attributes::META).canonicalize();
            }
            dom.data.add_memory_capability(sub, Arc::downgrade(&cap));
            serial_println!(
                "  meta cap #{}: [{:#011x}..{:#011x})  {} KiB  {} pages",
                sub,
                r.base,
                r.base + r.length,
                r.length / 1024,
                r.length / 4096,
            );
            meta_caps_local.push(cap);
            sub += 1;
        }
        meta_caps = meta_caps_local;

        // ── COMM root capability ──────────────────────────────────────────── //
        //
        // The COMM region is a contiguous block carved out during partition().
        // We create a root capability as the tree anchor; the actual COMM
        // capability will be obtained by carving from this root (see below).
        let cr = &info.partition.comm_region;
        let comm_root =
            Capability::new_root(ROOT_ID, sub, MemoryRegion::new_root(cr.base, cr.length));
        comm_root_handle = sub;
        dom.data
            .add_memory_capability(sub, Arc::downgrade(&comm_root));
        serial_println!(
            "  comm root cap #{}: {:#x}+{:#x} ({} KiB)",
            sub,
            cr.base,
            cr.length,
            cr.length / 1024,
        );
        // Keep the Arc alive past this block so CARVE can find it.
        mem_caps.push(comm_root);
        sub += 1;

        // ── Self-referencing domain capability ────────────────────────────── //
        //
        // dom0 needs a domain capability pointing to itself so that
        // register_comm() can resolve the child_domain_handle.  For dom0's
        // DomainComm, target_domain_id == owner_id (self-referential).
        self_domain_cap_handle = sub;
        dom.data
            .add_domain_capability(self_domain_cap_handle, Arc::downgrade(&root_domain));
        serial_println!("  self domain cap #{}: dom0 → dom0", sub);
        // sub += 1; // not needed — last handle allocation in this block
    }

    // ── Build EPT via UpdateBatch ──────────────────────────────────────── //
    //
    // Emit one ChangeRights per dom0-owned region (identity GPA = HPA, RWX).
    // execute() calls apply_update() for each entry; ThemisPlatform lazily
    // allocates the EPT root page from the META pool on the first call.

    let batch = {
        let mut b = UpdateBatch::new();
        for region in &info.partition.dom0_owned[..info.partition.dom0_owned_count] {
            if region.length == 0 {
                continue;
            }
            b.add_change_rights(
                ROOT_ID,
                region.base, // GPA (identity)
                region.length,
                region.base, // HPA
                Rights::RWX,
                false,
            );
        }
        // COMM region is also identity-mapped — dom0 needs read/write access.
        let cr = &info.partition.comm_region;
        b.add_change_rights(ROOT_ID, cr.base, cr.length, cr.base, Rights::RW, false);
        b
    };

    capability_engine::execute(&platform, false, || Ok(((), batch)))
        .expect("P2c: capability engine execute failed");

    let eptp = platform
        .slat(ROOT_ID)
        .expect("P2c: EPT root not allocated after execute");

    serial_println!(
        "  EPT built for dom0: {} RAM regions, EPTP = {:#x}",
        info.partition.dom0_owned_count,
        eptp,
    );

    // ── EPT passthrough: map non-RAM regions for device/ACPI access ───────── //
    //
    // RESERVED + FRAMEBUFFER regions are device MMIO (PCI BARs, LAPIC, IOAPIC,
    // HPET, etc.) and are mapped UC by map_range_typed() via UncacheableRanges.
    // ACPI_RECLAIMABLE + ACPI_NVS are normal DRAM (WB) holding firmware tables.
    // BOOTLOADER_RECLAIMABLE and KERNEL_AND_MODULES are NOT mapped — capavisor
    // memory is invisible to dom0 at the hardware level.
    let passthrough_batch = {
        let mut b = UpdateBatch::new();
        for region in &info.passthrough_regions {
            if region.length == 0 {
                continue;
            }
            b.add_change_rights(
                ROOT_ID,
                region.base, // GPA (identity)
                region.length,
                region.base, // HPA
                Rights::RW,  // no execute for MMIO/firmware regions
                false,
            );
        }
        b
    };

    capability_engine::execute(&platform, false, || Ok(((), passthrough_batch)))
        .expect("P2c: passthrough EPT execute failed");

    serial_println!(
        "  EPT passthrough: {} non-RAM regions mapped (ACPI/NVS/MMIO)",
        info.passthrough_regions.len(),
    );

    // ── COMM capability: CARVE + REGISTER_COMM ────────────────────────────── //
    //
    // The COMM root capability is the tree anchor.  We carve a child covering
    // the entire region so it satisfies register_comm's "must be a Carve"
    // precondition.  Then register_comm binds it as dom0's DomainComm page
    // (target_domain == self, vp_id = 0 by convention for domain-level COMM).
    let _comm_child_handle = {
        use capability_engine::Access;
        let cr = &info.partition.comm_region;
        let access = Access::new(cr.base, cr.length, Rights::RW);

        let ((child_handle, _sub_handle), carve_batch) =
            capability_engine::execute(&platform, false, || {
                Capability::carve(&root_domain, comm_root_handle, access)
                    .map(|(h, s, batch)| ((h, s), batch))
            })
            .expect("P2c: COMM carve failed");

        serial_println!(
            "  COMM carve: child handle {} from root {}",
            child_handle,
            comm_root_handle,
        );

        let _ = carve_batch; // EPT already mapped in the RAM batch above.

        // register_comm: bind to dom0 itself (self-referential DomainComm).
        capability_engine::execute(&platform, false, || {
            Capability::register_comm(
                &root_domain,
                child_handle,
                self_domain_cap_handle,
                0, // vp_id 0 = domain-level COMM
            )
            .map(|batch| ((), batch))
        })
        .expect("P2c: COMM register failed");

        serial_println!(
            "  COMM registered: handle {} → dom0 DomainComm at {:#x}",
            child_handle,
            cr.base,
        );
        child_handle
    };

    // NOTE: attestation is now on-demand — the thhv driver requests it via
    // ATTEST_SELF hypercall at module_init, so we no longer pre-populate the
    // DomainComm RX ring here.

    serial_println!("=== P2c: done ===");

    CapaState {
        platform,
        root_domain,
        mem_caps,
        meta_caps,
    }
}
