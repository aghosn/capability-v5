//! ThemisPlatform construction: register dom0 and seed the META pool.

extern crate alloc;
use alloc::vec::Vec;

use crate::serial_println;

use super::PlatformInfo;

// ── ThemisPlatform init ───────────────────────────────────────────────────── //

/// Create and bootstrap `ThemisPlatform` for dom0.
///
/// Registers domain 0 and hands it the **full** META pool.  All subsequent
/// allocations (VMXON, VMCS, VAPIC, EPT page-table pages) come from this single
/// pool via `ThemisPlatform::alloc_meta_frame()` or the EPT walker.
///
/// Must be called before `vmx()`.
pub fn init_themis(info: &PlatformInfo) -> crate::platform::ThemisPlatform {
    use crate::platform::ThemisPlatform;
    use capability_engine::DomainId;

    const ROOT_ID: DomainId = 0;

    let mut platform =
        ThemisPlatform::new(alloc::sync::Arc::clone(&info.uc_ranges), info.num_cores);
    platform.arch.set_lapic_ids(info.cpu_lapic_ids.clone());
    platform.bootstrap_register_domain(ROOT_ID, None, info.hhdm_offset);

    // Map META regions into HHDM and give them to the platform.
    for i in 0..info.partition.meta_count {
        let r = info.partition.meta_regions[i];
        crate::mem::map_phys_range(r.base, r.length, info.hhdm_offset);
        platform.bootstrap_give_meta(ROOT_ID, r);
    }

    serial_println!(
        "ThemisPlatform: META pool {} KiB across {} region(s):",
        info.partition.meta_regions[..info.partition.meta_count]
            .iter()
            .map(|r| r.length)
            .sum::<u64>()
            / 1024,
        info.partition.meta_count
    );
    for i in 0..info.partition.meta_count {
        let r = &info.partition.meta_regions[i];
        serial_println!(
            "  [{:#011x}..{:#011x})  {} KiB",
            r.base,
            r.base + r.length,
            r.length / 1024
        );
    }
    serial_println!(
        "  breakdown: {} arch-fixed + {} page-table + {} IOMMU pages",
        info.partition.meta_breakdown.arch_fixed_pages,
        info.partition.meta_breakdown.pt_pages,
        info.partition.meta_breakdown.iommu_pages,
    );

    // ── IRT allocation for VT-d interrupt remapping (intr-p3b) ───────────── //
    //
    // One 4 KiB page per IR-capable DRHD unit, allocated from the META pool.
    // Pages are machine-global hardware tables written by the IOMMU; they are
    // never visible to any domain (absent from EPT like all META pages).
    //
    // We must map each DRHD's MMIO region before accessing its registers:
    // Limine only HHDM-maps usable RAM; IOMMU MMIO holes need explicit mapping.
    // IRTA_REG is written here; GCMD.SIRTP/IRE are issued in intr-p3c.
    if info.acpi.has_dmar {
        // VT-d spec §10.4.28: IRTA_REG layout
        //   bits[63:12]  IRT physical base (4 KiB-aligned)
        //   bits[11]     Extended Interrupt Mode (X2APIC); 0 for now
        //   bits[3:0]    Size = log2(entries) - 1; 0 = 256 entries (minimum)
        const IRTA_REG_OFFSET: usize = 0xB8;
        const IRTA_SIZE_256: u64 = 0;
        // CAP register (offset 0x08): bit 16 = IR capable.
        const CAP_OFFSET: usize = 0x08;
        const CAP_IR_BIT: u64 = 1 << 16;
        // ECAP register (offset 0x10): bit 3 = IR.
        const ECAP_OFFSET: usize = 0x10;
        const ECAP_IR_BIT: u64 = 1 << 3;

        let mut units = info.acpi.drhd_units.clone();
        for unit in units.iter_mut() {
            // Map the DRHD MMIO register page before any register access.
            crate::mem::map_phys_range(unit.register_base, 0x1000, info.hhdm_offset);

            // Read CAP/ECAP now that the page is mapped.
            let reg_virt = (unit.register_base + info.hhdm_offset) as *const u64;
            let cap = unsafe { reg_virt.add(CAP_OFFSET / 8).read_volatile() };
            let ecap = unsafe { reg_virt.add(ECAP_OFFSET / 8).read_volatile() };
            unit.ir_supported = (cap & CAP_IR_BIT != 0) || (ecap & ECAP_IR_BIT != 0);

            if !unit.ir_supported {
                serial_println!(
                    "  DRHD seg={} base={:#x}: IR not supported (cap={:#x} ecap={:#x}) — skipping",
                    unit.segment,
                    unit.register_base,
                    cap,
                    ecap,
                );
                continue;
            }

            let irt_phys = platform.alloc_meta_frame(ROOT_ID);
            unit.irt_phys = irt_phys;

            // Write IRTA_REG: base | size_encoding (EIM=0, 256 entries).
            let irta_virt =
                (unit.register_base + info.hhdm_offset + IRTA_REG_OFFSET as u64) as *mut u64;
            unsafe { core::ptr::write_volatile(irta_virt, irt_phys | IRTA_SIZE_256) };

            serial_println!(
                "  DRHD seg={} base={:#x}: cap={:#x} ecap={:#x} IRT @ {:#x} IRTA_REG written",
                unit.segment,
                unit.register_base,
                cap,
                ecap,
                irt_phys,
            );
        }
        *platform.arch.drhd_units_mut() = units;
    }

    // ── Enable VT-d interrupt remapping (intr-p3c) ───────────────────────── //
    //
    // For each IR-capable DRHD unit, issue GCMD.SIRTP (latch the IRTA_REG
    // pointer written in intr-p3b) then GCMD.IRE (enable interrupt remapping).
    //
    // CFI=1: Compatibility Format Interrupts are allowed to pass through the
    // IOMMU unchanged.  This means dom0's existing I/O APIC RTEs (which Linux
    // programs in the standard compatibility format) continue to work without
    // any reprogramming.  All IRTEs start with P=0 (not present), so no remapped
    // interrupt is active until intr-p3g programs one for a child domain.
    //
    // VT-d spec §10.4.8 GCMD / §10.4.9 GSTS register layout:
    //   Bit[25] IRE  / IRES  — Interrupt Remapping Enable / Status
    //   Bit[24] SIRTP/ IRTPS — Set IRT Pointer / IRT Pointer Set Status
    //   Bit[23] CFI  / CFIS  — Compat Format Interrupt / Status
    //
    // Note: each GCMD bit is a one-shot command; write one bit at a time and
    // wait for the corresponding GSTS status bit before proceeding.
    for unit in platform.arch.drhd_units().iter() {
        if unit.irt_phys == 0 {
            continue;
        }

        const GCMD_OFFSET: u64 = 0x18;
        const GSTS_OFFSET: u64 = 0x1C;
        const SIRTP: u32 = 1 << 24;
        const CFI: u32 = 1 << 23;
        const IRE: u32 = 1 << 25;
        const IRTPS: u32 = 1 << 24;
        const CFIS: u32 = 1 << 23;
        const IRES: u32 = 1 << 25;
        const POLL_LIMIT: usize = 100_000;

        let base = unit.register_base + info.hhdm_offset;
        let gcmd = (base + GCMD_OFFSET) as *mut u32;
        let gsts = (base + GSTS_OFFSET) as *const u32;

        // Step 1: SIRTP — latch IRTA_REG into hardware.
        unsafe { gcmd.write_volatile(SIRTP) };
        let ok = (0..POLL_LIMIT).any(|_| {
            core::hint::spin_loop();
            (unsafe { gsts.read_volatile() } & IRTPS) != 0
        });
        if !ok {
            serial_println!(
                "WARN: VT-d DRHD {:#x}: IRTPS timeout — skipping IRE",
                unit.register_base
            );
            continue;
        }

        // Step 2: CFI — let compat-format interrupts (dom0) pass through.
        unsafe { gcmd.write_volatile(CFI) };
        let ok = (0..POLL_LIMIT).any(|_| {
            core::hint::spin_loop();
            (unsafe { gsts.read_volatile() } & CFIS) != 0
        });
        if !ok {
            serial_println!("WARN: VT-d DRHD {:#x}: CFIS timeout", unit.register_base);
        }

        // Step 3: IRE — enable interrupt remapping.
        unsafe { gcmd.write_volatile(IRE) };
        let ok = (0..POLL_LIMIT).any(|_| {
            core::hint::spin_loop();
            (unsafe { gsts.read_volatile() } & IRES) != 0
        });
        if !ok {
            serial_println!(
                "WARN: VT-d DRHD {:#x}: IRES timeout — IR may not be active",
                unit.register_base
            );
        } else {
            serial_println!(
                "  DRHD {:#x}: IR enabled (CFI=1, all IRTEs P=0)",
                unit.register_base
            );
        }
    }

    // ── P4b: VT-d root table + context table allocation ──────────────────── //
    //
    // For each DRHD unit:
    //   1. Allocate one META page → root table (256 × 16-byte entries).
    //   2. For each bus in the matching ECAM segment: allocate one META page
    //      → context table (256 × 16-byte entries).
    //   3. Fill every context entry as passthrough (TT=10b) for dom0.
    //   4. Fill root entries to point at their context table pages.
    //   5. Write RTADDR_REG and issue GCMD.SRTP.
    //
    // P4c (TE=1) follows immediately after all DRHD units are initialised.
    //
    // Context entry layout (VT-d spec §9.3, legacy mode 128-bit):
    //   Low  u64: bit[0]=P, bits[3:2]=TT, bits[63:12]=SLPTPTR (ignored for passthrough)
    //   High u64: bits[2:0]=AW (1=39-bit/3-level, 2=48-bit/4-level), bits[23:8]=DID
    //   Passthrough: low=0x9 (P=1 | TT=2<<2=8), high=(DID=1)<<8 | AW (read from CAP.SAGAW)
    // Root entry layout (VT-d spec §9.2):
    //   Low  u64: bit[0]=P, bits[63:12]=CTP (context table phys >> 12)
    //   High u64: 0 (reserved)
    {
        const RTADDR_REG_OFFSET: u64 = 0x20;
        const CAP_OFFSET: u64 = 0x08;
        const ECAP_OFFSET: u64 = 0x10;
        const CCMD_OFFSET: u64 = 0x28;
        const GCMD_OFFSET: u64 = 0x18;
        const GSTS_OFFSET: u64 = 0x1C;
        const GCMD_SRTP: u32 = 1 << 30;
        const GSTS_RTPS: u32 = 1 << 30;
        const POLL_LIMIT: usize = 100_000;

        // CTX_LOW is fixed: P=1 (bit[0]), TT=pass-through=2<<2=8 (bits[3:2]).
        // CTX_HIGH is computed per-DRHD from CAP.SAGAW (bits[12:8]).
        const CTX_LOW: u64 = 0x9;

        let hhdm = info.hhdm_offset;

        for i in 0..platform.arch.drhd_units().len() {
            let (segment, _flags, reg_base) = {
                let u = &platform.arch.drhd_units()[i];
                (u.segment, u.flags, u.register_base)
            };

            let base = reg_base + hhdm;

            // Read CAP.SAGAW (bits[12:8]) to pick the highest supported AW.
            // AW=1 → 39-bit/3-level; AW=2 → 48-bit/4-level.
            let cap = unsafe { ((base + CAP_OFFSET) as *const u64).read_volatile() };
            let sagaw = (cap >> 8) & 0x1f;
            let aw = (u64::BITS - 1 - sagaw.leading_zeros()) as u64;
            let ctx_high: u64 = (1u64 << 8) | aw; // DID=1, AW

            // Allocate root table page and zero it (256 entries × 16 bytes = 4 KiB).
            let root_phys = platform.alloc_meta_frame(ROOT_ID);
            let root_virt = (root_phys + hhdm) as *mut u64;
            unsafe { core::ptr::write_bytes(root_virt as *mut u8, 0, 4096) };

            // Find ECAM regions for this unit's segment (all buses, regardless
            // of INCLUDE_PCI_ALL — an absent root entry causes a DMA fault).
            let ecam_regions: Vec<crate::arch::acpi::EcamRegion> = info
                .acpi
                .ecam_regions
                .iter()
                .filter(|r| r.segment == segment)
                .cloned()
                .collect();

            let mut ctx_tables: Vec<(u8, u64)> = Vec::new();
            for region in &ecam_regions {
                for bus in region.start_bus..=region.end_bus {
                    // Allocate context table page for this bus.
                    let ctx_phys = platform.alloc_meta_frame(ROOT_ID);
                    let ctx_virt = (ctx_phys + hhdm) as *mut u64;

                    // Fill all 256 context entries as passthrough.
                    // VT-d spec: write high word first, then low word with P=1,
                    // to prevent the IOMMU reading a half-written present entry.
                    unsafe {
                        for j in 0usize..256 {
                            let entry = ctx_virt.add(j * 2); // each entry = 2 × u64
                            entry.add(1).write_volatile(ctx_high); // high first
                            entry.write_volatile(CTX_LOW); // low + P=1 last
                        }
                    }

                    // Point root table entry for this bus at the context table.
                    unsafe {
                        let root_entry = root_virt.add(bus as usize * 2);
                        root_entry.add(1).write_volatile(0); // high = reserved
                        root_entry.write_volatile(ctx_phys | 0x1); // P=1, CTP
                    }

                    ctx_tables.push((bus, ctx_phys));
                }
            }

            let rtaddr = (base + RTADDR_REG_OFFSET) as *mut u64;
            let gcmd = (base + GCMD_OFFSET) as *mut u32;
            let gsts = (base + GSTS_OFFSET) as *const u32;
            let ccmd = (base + CCMD_OFFSET) as *mut u64;

            // RTADDR_REG: bits[63:12] = root_phys, bits[11:10] = 00 (legacy mode)
            unsafe { rtaddr.write_volatile(root_phys) };
            unsafe { gcmd.write_volatile(GCMD_SRTP) };
            let ok = (0..POLL_LIMIT).any(|_| {
                core::hint::spin_loop();
                (unsafe { gsts.read_volatile() } & GSTS_RTPS) != 0
            });
            if !ok {
                serial_println!(
                    "WARN: VT-d DRHD {:#x}: RTPS timeout",
                    platform.arch.drhd_units()[i].register_base
                );
            }

            // VT-d spec §10.2.1: global context-cache invalidation required
            // after SRTP before enabling translation.
            // CCMD_REG[63]=ICC, bits[62:61]=CIRG: 01=global (bit[61]).
            unsafe { ccmd.write_volatile((1u64 << 63) | (1u64 << 61)) };
            let ok = (0..POLL_LIMIT).any(|_| {
                core::hint::spin_loop();
                (unsafe { ccmd.read_volatile() } & (1u64 << 63)) == 0
            });
            if !ok {
                serial_println!(
                    "WARN: VT-d DRHD {:#x}: context-cache invalidation timeout",
                    platform.arch.drhd_units()[i].register_base
                );
            }

            // VT-d spec §10.2.2: global IOTLB invalidation.
            // IOTLB_REG is at ECAP.IRO*16 + 8; ECAP bits[9:8] = IRO.
            let ecap = unsafe { ((base + ECAP_OFFSET) as *const u64).read_volatile() };
            let iro = ((ecap >> 8) & 0x3f) as u64; // bits[13:8] per spec
            let iotlb_reg = (base + iro * 16 + 8) as *mut u64;
            // IVA_REG: bit[63]=IVT, bits[61:60]=IIRG: 01=global, bit[4]=DR, bit[3]=DW.
            unsafe {
                iotlb_reg.write_volatile((1u64 << 63) | (1u64 << 60) | (1u64 << 4) | (1u64 << 3))
            };
            let ok = (0..POLL_LIMIT).any(|_| {
                core::hint::spin_loop();
                (unsafe { iotlb_reg.read_volatile() } & (1u64 << 63)) == 0
            });
            if !ok {
                serial_println!(
                    "WARN: VT-d DRHD {:#x}: IOTLB invalidation timeout",
                    platform.arch.drhd_units()[i].register_base
                );
            }

            serial_println!(
                "  DRHD seg={} base={:#x}: root @ {:#x}, {} ctx tables, AW={}, cache flushed",
                segment,
                platform.arch.drhd_units()[i].register_base,
                root_phys,
                ctx_tables.len(),
                aw
            );
            platform.arch.drhd_units_mut()[i].root_phys = root_phys;
            platform.arch.drhd_units_mut()[i].aw = aw;
            platform.arch.drhd_units_mut()[i].ctx_tables = ctx_tables;
        }
    }

    // ── P4c: Enable VT-d DMA translation ─────────────────────────────────── //
    //
    // After RTADDR is latched (SRTP done), set GCMD.TE=1 per DRHD to activate
    // DMA translation.  All PCIe DMA goes through the IOMMU from this point;
    // dom0 devices use passthrough context entries (no address remapping).
    {
        const GCMD_OFFSET: u64 = 0x18;
        const GSTS_OFFSET: u64 = 0x1C;
        const GCMD_TE: u32 = 1 << 31;
        const GSTS_TES: u32 = 1 << 31;
        const POLL_LIMIT: usize = 100_000;
        let hhdm = info.hhdm_offset;

        for unit in platform.arch.drhd_units().iter() {
            if unit.root_phys == 0 {
                continue;
            }
            let base = unit.register_base + hhdm;
            let gcmd = (base + GCMD_OFFSET) as *mut u32;
            let gsts = (base + GSTS_OFFSET) as *const u32;

            unsafe { gcmd.write_volatile(GCMD_TE) };
            let ok = (0..POLL_LIMIT).any(|_| {
                core::hint::spin_loop();
                (unsafe { gsts.read_volatile() } & GSTS_TES) != 0
            });
            if !ok {
                serial_println!(
                    "WARN: VT-d DRHD {:#x}: TES timeout — DMA translation may not be active",
                    unit.register_base
                );
            } else {
                serial_println!(
                    "  DRHD {:#x}: DMA translation enabled (passthrough for dom0)",
                    unit.register_base
                );
            }
        }
    }

    // ── DomainComm header init for dom0 ──────────────────────────────────── //
    //
    // The COMM region was reserved during partition() (separate from META).
    // Write the DomainComm header and ring metadata.  Identity mapping:
    // base HPA == GPA for dom0.  The binary attestation message is written
    // later in capa() after the capability engine is initialized.
    {
        let cr = &info.partition.comm_region;
        let nr_pages = (cr.length / 4096) as u32;

        // Ensure the pages are HHDM-mapped so init_domcomm can write to them.
        crate::mem::map_phys_range(cr.base, cr.length, info.hhdm_offset);

        // Dom0 uses identity mapping: base HPA == GPA.
        platform.bootstrap_init_domcomm(ROOT_ID, cr.base, cr.base, nr_pages);

        // Set CPUID statics for the vmexit handler.
        crate::arch::vmexit::DOMCOMM_GPA.store(cr.base, core::sync::atomic::Ordering::Relaxed);
        crate::arch::vmexit::DOMCOMM_PAGES.store(nr_pages, core::sync::atomic::Ordering::Relaxed);

        serial_println!(
            "  DomainComm: {} pages at {:#x} (e820 reserved, CPUID 0x40000002)",
            nr_pages,
            cr.base,
        );
    }

    platform
}
