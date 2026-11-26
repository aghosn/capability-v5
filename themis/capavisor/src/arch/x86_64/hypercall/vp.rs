//! x86-64 implementation of `THEMIS_ADD_VP`.
//!
//! `allocate_vp` (the platform's half of `Capability::add_vp`) allocates
//! VMCS/VAPIC/PID META frames, sets up the VMCS, and creates an
//! `InactiveVcpu` for the new child VP. It runs *inside* the capa-engine's
//! own locked `add_vp` closure (via `Platform::allocate_vp`), so a failure
//! here aborts the whole operation atomically — no manual rollback is
//! needed on the capavisor side. It uses `vmptrst`/`vmptrld` to save and
//! restore whatever VMCS happens to be current on this core around the
//! VMWRITE dance needed to initialize the new VMCS — this is pure
//! core-local hardware register state, unrelated to any domain, so it
//! needs no input from the caller.

use capability_engine::{Capability, CapabilityRef, CapaError, Domain, DomainId, MsrPolicy};

use crate::hypercall::HypercallResult;
use crate::platform::ThemisPlatform;
use crate::serial_println;
use crate::vcpu::InactiveVcpu;

/// ADD_VP (0x14): add a virtual processor to a child domain.
///
/// The caller must have already CARVE'd a COMM page and SENT VP META pages
/// to the child domain. All platform-side hardware allocation happens
/// inside `Capability::add_vp` via [`allocate_vp`]; this function just
/// invokes it and translates the result.
///
/// IN:  RDI = child_domain_handle, RSI = comm_cap_handle, RDX = vp_index
/// OUT: RDI = vp_index on success
pub(super) fn do_add_vp(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    child_domain_handle: u64,
    comm_cap_handle: u64,
) -> HypercallResult {
    match Capability::add_vp(platform, caller, child_domain_handle, comm_cap_handle) {
        Ok((vp_id, _batch)) => HypercallResult::success_1(vp_id as u64),
        Err(e) => HypercallResult::from(e),
    }
}

/// Platform half of `Capability::<Domain>::add_vp` — see
/// [`capability_engine::Platform::allocate_vp`].
///
/// Allocates hardware VP state (VMCS/VAPIC/PID/MSR bitmap, ...) for
/// `(domain_id, vp_id)` and stores it directly in the domain's
/// `PlatformDomain`. Called by the capa-engine from inside `add_vp`'s own
/// locked closure — a returned `Err` aborts the whole operation before any
/// capability-tree mutation is left in place.
pub fn allocate_vp(
    platform: &ThemisPlatform,
    domain_id: DomainId,
    vp_id: u32,
    msrs: &MsrPolicy,
) -> capability_engine::Result<()> {
    use x86::bits64::vmx as vmx_ops;
    use x86::msr;

    let arc = platform.domain_arc(domain_id).ok_or(CapaError::NotFound)?;

    // Seven private META pages: VMCS, VAPIC, PID, MSR save/restore list,
    // MSR bitmap, and two I/O bitmaps. PID suballocation could save one page.
    let (
        vmcs_phys,
        vapic_phys,
        pid_phys,
        msr_list_phys,
        msr_bitmap_phys,
        io_bitmap_a_phys,
        io_bitmap_b_phys,
    );
    {
        let mut pd = arc.lock();
        let pages_needed = 7;
        if pd.meta.free_pages() < pages_needed as u64 {
            serial_println!(
                "[ADD_VP] not enough META pages: need {} have {}",
                pages_needed,
                pd.meta.free_pages()
            );
            return Err(CapaError::NoMemory);
        }
        vmcs_phys = pd.meta.alloc_frame();
        vapic_phys = pd.meta.alloc_frame();
        pid_phys = pd.meta.alloc_frame();
        msr_list_phys = pd.meta.alloc_frame();
        msr_bitmap_phys = pd.meta.alloc_frame();
        io_bitmap_a_phys = pd.meta.alloc_frame();
        io_bitmap_b_phys = pd.meta.alloc_frame();
        pd.arch.set_vp_bitmaps(
            vp_id as usize,
            [msr_bitmap_phys, io_bitmap_a_phys, io_bitmap_b_phys],
        );
    }

    // Zero the PID (64 bytes at offset 0 of the PID page; must be clean before VMENTRY).
    // PIR[255:0] = 0, ON=0, SN=0 — no pending virtual interrupts, no IPI in flight.
    let hhdm = platform.hhdm_offset();
    unsafe {
        core::ptr::write_bytes((pid_phys + hhdm) as *mut u8, 0, 64);
        // Pre-populate the VMENTRY-MSR-LOAD / VMEXIT-MSR-STORE list with the
        // fixed SYSCALL_MSRS entries; hardware handles save/restore across
        // VMEXITs from this VP's VMCS.
        let _ = crate::arch::x86_64::vmcs::msr_lists::init(msr_list_phys, hhdm);
    }

    // Initialize the VAPIC page with sane LAPIC defaults so that
    // APIC_REGISTER_VIRT + VID reads correct values from the start.
    unsafe {
        let vapic = (vapic_phys + hhdm) as *mut u32;
        // Hardware x2APIC reads use the full ID; xAPIC MMIO is parent-emulated.
        vapic.add(0x020 / 4).write_volatile(vp_id);
        // APIC_VER (0x030): version 0x14 (common), 6 LVT entries (MaxLvt=5)
        vapic.add(0x030 / 4).write_volatile(0x0005_0014);
        // DFR (0x0E0): flat model
        vapic.add(0x0E0 / 4).write_volatile(0xFFFF_FFFF);
        // SVR (0x0F0): APIC software-enabled, spurious vector 0xFF
        vapic.add(0x0F0 / 4).write_volatile(0x0000_01FF);
        // LVT entries: masked by default (bit 16 = mask)
        vapic.add(0x320 / 4).write_volatile(0x0001_0000); // LVT Timer
        vapic.add(0x330 / 4).write_volatile(0x0001_0000); // LVT Thermal
        vapic.add(0x340 / 4).write_volatile(0x0001_0000); // LVT PerfMon
        vapic.add(0x350 / 4).write_volatile(0x0001_0000); // LVT LINT0
        vapic.add(0x360 / 4).write_volatile(0x0001_0000); // LVT LINT1
        vapic.add(0x370 / 4).write_volatile(0x0001_0000); // LVT Error
                                                          // Timer DCR (0x3E0): divide by 1
        vapic.add(0x3E0 / 4).write_volatile(0x0000_000B);
    }

    // Fail closed until the engine's effective VP policy is projected.
    unsafe {
        core::ptr::write_bytes((io_bitmap_a_phys + hhdm) as *mut u8, 0xff, 4096);
        core::ptr::write_bytes((io_bitmap_b_phys + hhdm) as *mut u8, 0xff, 4096);
    }

    // Initialize MSR bitmap as a pure projection of the child's MsrPolicy.
    //
    // Invariant: bitmap ⊇ policy. Every MSR whose policy resolves to
    // `Trap` or `Emulate` traps via this bitmap; `Native` MSRs run
    // without exit. The capability engine validates every trapped access
    // (A1) before any side effect; if the bitmap were more permissive
    // than the policy, the engine would never see those accesses and
    // policy enforcement would be silently bypassed.
    //
    // Layout (Intel SDM Vol 3C §24.6.9):
    //   bytes    0-1023: RDMSR bitmap for MSRs 0x0–0x1FFF
    //   bytes 1024-2047: RDMSR bitmap for MSRs 0xC0000000–0xC0001FFF
    //   bytes 2048-3071: WRMSR bitmap for MSRs 0x0–0x1FFF
    //   bytes 3072-4095: WRMSR bitmap for MSRs 0xC0000000–0xC0001FFF
    if msr_bitmap_phys != 0 {
        // SAFETY: `msr_bitmap_phys` is a freshly-allocated 4 KiB META
        // frame for this child's MSR bitmap; the VMCS that will reference
        // it has not been loaded on any core yet.
        unsafe {
            crate::arch::x86_64::msr_bitmap::populate_from_policy(msr_bitmap_phys, hhdm, msrs);
        }
        serial_println!(
            "  MSR bitmap: {:#x} (default={:?}, {} overrides)",
            msr_bitmap_phys,
            msrs.default,
            msrs.overrides.len(),
        );
    }

    // ── Write VMCS revision ID, set up VMCS, create InactiveVcpu ──
    let rev_id = (unsafe { msr::rdmsr(msr::IA32_VMX_BASIC) } & 0x7FFF_FFFF) as u32;

    // Write revision ID into the VMCS page header.
    let vmcs_virt = (vmcs_phys + hhdm) as *mut u32;
    unsafe { vmcs_virt.write_volatile(rev_id) };

    // Get child EPT pointer — allocate an empty root if none exists yet.
    // SET_GUEST_MEMORY is deferred until just before run(); the VMCS needs
    // a valid EPTP now, and ChangeRights will populate the EPT later.
    let eptp = {
        let mut pd = arc.lock();
        pd.ensure_ept();
        pd.arch.ept().unwrap().eptp()
    };

    // Allocate a unique VPID.
    let vpid = platform.next_vpid();

    // Set up child VMCS with intercept-heavy controls + Posted Interrupts.
    // VMWRITE only ever targets the *current* VMCS, so we must temporarily
    // make the child's VMCS current. Save whatever was current on this core
    // beforehand (pure core-local hardware state, unrelated to any domain)
    // and restore it once done.
    unsafe {
        let saved_vmcs = vmx_ops::vmptrst().expect("ADD_VP: vmptrst failed");
        crate::arch::vmcs::setup_child_vmcs(
            vmcs_phys,
            vapic_phys,
            msr_bitmap_phys,
            msr_list_phys,
            hhdm,
            pid_phys,
            io_bitmap_a_phys,
            io_bitmap_b_phys,
            eptp,
            vpid,
        );
        // Deactivate child VMCS (save state to memory).
        vmx_ops::vmclear(vmcs_phys).expect("ADD_VP: child vmclear failed");
        // Restore whatever VMCS was current before we started.
        vmx_ops::vmptrld(saved_vmcs).expect("ADD_VP: vmptrld restore failed");
    }

    // Create InactiveVcpu and store in the child's PlatformDomain.
    let vcpu = InactiveVcpu::new(vmcs_phys, vapic_phys, msr_bitmap_phys, pid_phys, vpid);
    platform.bootstrap_store_vcpu(domain_id, vp_id as usize, vcpu);

    Ok(())
}
