//! x86-64 implementation of `THEMIS_ADD_VP`.
//!
//! Allocates VMCS/VAPIC/PID META frames, sets up the VMCS, and creates an
//! `InactiveVcpu` for the new child VP. Uses raw VMX intrinsics (`vmclear`,
//! `vmptrld`) to swap the calling parent's VMCS off the current core while
//! the child's VMCS is being configured, then restores the parent's VMCS
//! before returning.

extern crate alloc;

use capability_engine::{Capability, CapabilityRef, Domain, DomainId};
use themis_abi::errors;

use crate::hypercall::{try_domain, HypercallResult};
use crate::platform::ThemisPlatform;
use crate::serial_println;
use crate::vcpu::InactiveVcpu;

/// ADD_VP (0x14): add a virtual processor to a child domain.
///
/// The caller must have already CARVE'd a COMM page and SENT VP META pages
/// to the child domain.  This operation:
///   1. Allocates VMCS + VAPIC (+ MSR bitmap on first VP) from META pool.
///   2. Calls `Capability::add_vp` in the capa engine (creates VProcessorState,
///      binds COMM page).
///   3. Sets up the VMCS and creates an InactiveVcpu.
///   4. On capa engine failure, returns allocated META pages to the pool.
///
/// IN:  RDI = child_domain_handle, RSI = comm_cap_handle, RDX = vp_index
/// OUT: RDI = vp_index on success
pub(super) fn do_add_vp(
    platform: &ThemisPlatform,
    caller: &CapabilityRef<Domain>,
    child_domain_handle: u64,
    comm_cap_handle: u64,
    caller_vmcs_phys: u64,
) -> HypercallResult {
    use x86::bits64::vmx as vmx_ops;
    use x86::msr;

    // ── Step 0: resolve child domain_id from handle (read-only) ──
    // Keep `child_ref` alive — we read its MsrPolicy below to populate
    // the MSR bitmap as a faithful projection of the per-domain policy.
    let (child_domain_id, child_ref): (DomainId, _) = {
        let r = caller.read();
        let child_weak = match r.data.get_domain_capability(child_domain_handle) {
            Some(w) => w.clone(),
            None => return HypercallResult::error(errors::ERR_NOTFOUND),
        };
        drop(r);
        let child_ref = match child_weak.upgrade() {
            Some(c) => c,
            None => return HypercallResult::error(errors::ERR_NOTFOUND),
        };
        let id = child_ref.read().data.id;
        (id, child_ref)
    };

    // ── Step 1: pre-allocate VMCS + VAPIC + PID from child's META pool ──
    //
    // Per-VP META page layout (current):
    //   Page 0 (4 KB): VMCS — Intel requires a full 4 KB page.
    //   Page 1 (4 KB): VAPIC — Virtual-APIC page; hardware maps the xAPIC
    //     register space here.  xAPIC registers occupy offsets 0x000–0x3FF
    //     (1 KB); offsets 0x400–0xFFF (3 KB) are architecturally reserved
    //     and never accessed by hardware or the guest APIC emulation.
    //   Page 2 (4 KB): PID — Posted-Interrupt Descriptor; only 64 bytes are
    //     used (PIR bitmap + ON/SN/NV/NDST fields; Intel SDM Vol 3C §29.6).
    //
    // Optimization opportunity (TODO): sub-allocate the PID from the
    // VAPIC page at offset 0x400 (naturally 64-byte aligned, in the unused
    // upper 3 KB).  This would reduce per-VP META consumption from 3 pages
    // to 2 pages, matching the original THHV_META_PAGES_PER_VP=2 budget.
    // Requires computing pid_phys = vapic_phys + 0x400 instead of
    // allocating a separate frame, and reverting THHV_META_PAGES_PER_VP to 2.
    let arc = try_domain!(platform, child_domain_id);

    let (
        vmcs_phys,
        vapic_phys,
        pid_phys,
        msr_bitmap_phys,
        apic_access_phys,
        io_bitmap_a_phys,
        io_bitmap_b_phys,
        first_vp,
        pd_vp_count,
    );
    {
        let mut pd = arc.lock();
        pd_vp_count = pd.arch.vps().len(); // VP index for this new VP
                                           // Check if this is the first VP (need extra pages for MSR + IO bitmaps).
        first_vp = pd.arch.msr_bitmap_phys() == 0;
        // Per VP: VMCS + VAPIC + PID (+ MSR bitmap + 2 IO bitmaps if first VP).
        // apic_access_phys comes from the ChangeRights mapping of GPA 0xFEE00000,
        // established during THHV_SEND_SHARED_META — not allocated from META.
        // THHV_META_PAGES_SHARED (4: MSR bitmap + IO bitmaps + EPT root) +
        // THHV_META_PAGES_PER_VP (3) = 7 total for first VP.
        let pages_needed = if first_vp { 6 } else { 3 };
        if pd.meta.free_pages() < pages_needed as u64 {
            serial_println!(
                "[ADD_VP] not enough META pages: need {} have {}",
                pages_needed,
                pd.meta.free_pages()
            );
            return HypercallResult::error(errors::ERR_NOMEM);
        }
        vmcs_phys = pd.meta.alloc_frame();
        vapic_phys = pd.meta.alloc_frame();
        pid_phys = pd.meta.alloc_frame();
        if first_vp {
            let msr_phys = pd.meta.alloc_frame();
            pd.arch.set_msr_bitmap_phys(msr_phys);
            let io_a_phys = pd.meta.alloc_frame();
            pd.arch.set_io_bitmap_a_phys(io_a_phys);
            let io_b_phys = pd.meta.alloc_frame();
            pd.arch.set_io_bitmap_b_phys(io_b_phys);
        }
        msr_bitmap_phys = pd.arch.msr_bitmap_phys();
        io_bitmap_a_phys = pd.arch.io_bitmap_a_phys();
        io_bitmap_b_phys = pd.arch.io_bitmap_b_phys();
        // apic_access_phys was recorded by apply_update when thhv mapped the
        // APIC-access sentinel page at GPA 0xFEE00000 via THHV_SEND_SHARED_META.
        apic_access_phys = pd.arch.apic_access_phys();
    }

    // Zero the PID (64 bytes at offset 0 of the PID page; must be clean before VMENTRY).
    // PIR[255:0] = 0, ON=0, SN=0 — no pending virtual interrupts, no IPI in flight.
    let hhdm = platform.hhdm_offset();
    unsafe {
        core::ptr::write_bytes((pid_phys + hhdm) as *mut u8, 0, 64);
    }

    // Initialize the VAPIC page with sane LAPIC defaults so that
    // APIC_REGISTER_VIRT + VID reads correct values from the start.
    unsafe {
        let vapic = (vapic_phys + hhdm) as *mut u32;
        // APIC_ID (0x020): physical APIC ID in bits [31:24] (xAPIC format)
        vapic
            .add(0x020 / 4)
            .write_volatile((pd_vp_count as u32) << 24);
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

    // Initialize IO bitmaps: zero (pass-through) then set bits for device ports
    // that CHV needs to emulate.
    // IO bitmap A covers ports 0x0000-0x7FFF (bit N = port N).
    // IO bitmap B covers ports 0x8000-0xFFFF. Only bitmap A is used here.
    if first_vp && io_bitmap_a_phys != 0 {
        unsafe {
            // Zero both pages: all ports pass-through by default.
            core::ptr::write_bytes((io_bitmap_a_phys + hhdm) as *mut u8, 0, 4096);
            core::ptr::write_bytes((io_bitmap_b_phys + hhdm) as *mut u8, 0, 4096);

            let bitmap_a = (io_bitmap_a_phys + hhdm) as *mut u8;

            // Helper: set bit for port N → byte N/8, bit N%8.
            macro_rules! trap_port {
                ($port:expr) => {
                    let byte = $port / 8;
                    let bit = $port % 8;
                    let old = bitmap_a.add(byte).read_volatile();
                    bitmap_a.add(byte).write_volatile(old | (1u8 << bit));
                };
            }

            // Serial COM1: 0x3F8-0x3FF (UART emulation for dom1 console)
            for p in 0x3F8u16..=0x3FF {
                trap_port!(p as usize);
            }

            // NOTE: PIT (0x40-0x43), i8042 (0x60,0x64), PM-timer (0x608) intentionally
            // NOT trapped — CHV's emulated PIT can't deliver IRQ0 back to dom1, so
            // trapping these causes dom1 to lose its scheduler tick and hang at 0x30.
            // Dom1 accesses dom0's hardware directly for these; the CHV timer (0xEC)
            // provides the LAPIC timer tick independently.
        }
        serial_println!(
            "  IO bitmaps: A={:#x} B={:#x} (serial 0x3F8-0x3FF trapped)",
            io_bitmap_a_phys,
            io_bitmap_b_phys,
        );
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
    if first_vp && msr_bitmap_phys != 0 {
        let policy_summary = {
            let guard = child_ref.read();
            let p = &guard.data.policy.msrs;
            (p.default, p.overrides.len())
        };
        // SAFETY: `msr_bitmap_phys` is a freshly-allocated 4 KiB META
        // frame for this child's MSR bitmap; the VMCS that will reference
        // it has not been loaded on any core yet.
        unsafe {
            let guard = child_ref.read();
            crate::arch::x86_64::msr_bitmap::populate_from_policy(
                msr_bitmap_phys,
                hhdm,
                &guard.data.policy.msrs,
            );
        }
        serial_println!(
            "  MSR bitmap: {:#x} (default={:?}, {} overrides)",
            msr_bitmap_phys,
            policy_summary.0,
            policy_summary.1,
        );
    }

    // ── Step 2: call into capa engine ──
    let result = Capability::add_vp(platform, caller, child_domain_handle, comm_cap_handle);

    match result {
        Err(e) => {
            // Rollback: return allocated pages to META pool.
            let mut pd = arc.lock();
            pd.meta.free_frame(vmcs_phys);
            pd.meta.free_frame(vapic_phys);
            pd.meta.free_frame(pid_phys);
            if first_vp {
                pd.meta.free_frame(msr_bitmap_phys);
                pd.arch.set_msr_bitmap_phys(0);
                pd.meta.free_frame(io_bitmap_a_phys);
                pd.meta.free_frame(io_bitmap_b_phys);
                pd.arch.set_io_bitmap_a_phys(0);
                pd.arch.set_io_bitmap_b_phys(0);
                // apic_access_phys is not from META — do not free it.
            }
            serial_println!("[ADD_VP] capa engine error, META rolled back");
            HypercallResult::from(e)
        }
        Ok((vp_id, _batch)) => {
            // ── Step 3: write VMCS revision ID, set up VMCS, create InactiveVcpu ──
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
            // Clobbers VMPTRLD — restored below.
            unsafe {
                crate::arch::vmcs::setup_child_vmcs(
                    vmcs_phys,
                    vapic_phys,
                    msr_bitmap_phys,
                    pid_phys,
                    apic_access_phys,
                    io_bitmap_a_phys,
                    io_bitmap_b_phys,
                    eptp,
                    vpid,
                );
                // Deactivate child VMCS (save state to memory).
                vmx_ops::vmclear(vmcs_phys).expect("ADD_VP: child vmclear failed");
                // Restore caller's VMCS.
                vmx_ops::vmptrld(caller_vmcs_phys).expect("ADD_VP: parent vmptrld restore failed");
            }

            // Create InactiveVcpu and store in the child's PlatformDomain.
            let vcpu = InactiveVcpu::new(vmcs_phys, vapic_phys, msr_bitmap_phys, pid_phys, vpid);
            platform.bootstrap_store_vcpu(child_domain_id, vp_id as usize, vcpu);

            HypercallResult::success_1(vp_id as u64)
        }
    }
}
