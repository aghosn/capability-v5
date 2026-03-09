//! VT-x (VMX) CPU feature detection and VMXON enable.

use x86::controlregs::{self, Cr4};
use x86::msr;

// ── CPU feature detection ───────────────────────────────────────────────── //

/// Hardware virtualisation features detected via CPUID and MSRs.
#[derive(Debug, Clone)]
pub struct CpuFeatures {
    /// VMX (VT-x) supported.
    pub vmx: bool,
    /// x2APIC supported.
    pub x2apic: bool,
    /// VMCS revision ID from IA32_VMX_BASIC.
    pub vmcs_revision_id: u32,
    /// VMXON / VMCS region size in bytes.
    pub vmx_region_size: u32,
    /// True physical address width (from CPUID 0x80000008).
    pub phys_addr_bits: u8,

    // APICv sub-features (all must be true for full APICv).
    /// APIC-register virtualisation (secondary proc-based bit 8).
    pub apic_register_virt: bool,
    /// Virtual-interrupt delivery (secondary proc-based bit 9).
    pub virtual_intr_delivery: bool,
    /// Process posted interrupts (pin-based bit 7).
    pub posted_interrupts: bool,

    /// VT-d (IOMMU) detected via DMAR table (passed in, not CPUID).
    pub vtd: bool,
}

impl CpuFeatures {
    /// True if full APICv is available (all three sub-features).
    pub fn has_apicv(&self) -> bool {
        self.apic_register_virt && self.virtual_intr_delivery && self.posted_interrupts
    }
}

/// Detect CPU virtualisation features via CPUID and MSRs.
///
/// `has_dmar` is passed from ACPI parsing (VT-d presence).
pub fn detect_features(has_dmar: bool) -> CpuFeatures {
    // CPUID.01H: ECX
    let cpuid1 = core::arch::x86_64::__cpuid(1);
    let vmx = (cpuid1.ecx >> 5) & 1 != 0;    // ECX[5] = VMX
    let x2apic = (cpuid1.ecx >> 21) & 1 != 0; // ECX[21] = x2APIC

    // Physical address width from CPUID.80000008H
    let cpuid_pa = core::arch::x86_64::__cpuid(0x80000008);
    let phys_addr_bits = (cpuid_pa.eax & 0xFF) as u8;

    let mut features = CpuFeatures {
        vmx,
        x2apic,
        vmcs_revision_id: 0,
        vmx_region_size: 0,
        phys_addr_bits,
        apic_register_virt: false,
        virtual_intr_delivery: false,
        posted_interrupts: false,
        vtd: has_dmar,
    };

    if !vmx {
        return features;
    }

    // IA32_VMX_BASIC: revision ID (bits 30:0) and region size (bits 44:32).
    let vmx_basic = unsafe { msr::rdmsr(msr::IA32_VMX_BASIC) };
    features.vmcs_revision_id = (vmx_basic & 0x7FFF_FFFF) as u32;
    features.vmx_region_size = ((vmx_basic >> 32) & 0x1FFF) as u32;
    if features.vmx_region_size == 0 {
        features.vmx_region_size = 4096; // default
    }

    // Check IA32_FEATURE_CONTROL: lock bit (0) and VMX-outside-SMX (2).
    let feat_ctrl = unsafe { msr::rdmsr(msr::IA32_FEATURE_CONTROL) };
    let locked = feat_ctrl & 0x1 != 0;
    let vmx_outside_smx = feat_ctrl & 0x4 != 0;
    if locked && !vmx_outside_smx {
        // VMX is locked out by firmware — cannot proceed.
        features.vmx = false;
        return features;
    }

    // If not locked, set lock + VMX-outside-SMX.
    if !locked {
        unsafe {
            msr::wrmsr(msr::IA32_FEATURE_CONTROL, feat_ctrl | 0x5);
        }
    }

    // ── APICv detection via VMX capability MSRs ──────────────────────── //

    // Check if secondary proc-based controls are available.
    let procbased_ctls = unsafe { msr::rdmsr(msr::IA32_VMX_PROCBASED_CTLS) };
    let secondary_allowed = (procbased_ctls >> 32) & (1 << 31) != 0; // bit 31 of allowed-1

    if secondary_allowed {
        let procbased_ctls2 = unsafe { msr::rdmsr(msr::IA32_VMX_PROCBASED_CTLS2) };
        let allowed1 = (procbased_ctls2 >> 32) as u32;
        features.apic_register_virt = allowed1 & (1 << 8) != 0;
        features.virtual_intr_delivery = allowed1 & (1 << 9) != 0;
    }

    // Posted interrupts: pin-based controls bit 7.
    let pinbased_ctls = unsafe { msr::rdmsr(msr::IA32_VMX_PINBASED_CTLS) };
    let pin_allowed1 = (pinbased_ctls >> 32) as u32;
    features.posted_interrupts = pin_allowed1 & (1 << 7) != 0;

    features
}

// ── VMXON ───────────────────────────────────────────────────────────────── //

/// Enable VMX operation on the current core.
///
/// Sets CR4.VMXE, adjusts CR0/CR4 for VMX fixed bits, and executes VMXON.
///
/// `vmxon_region_phys` must point to a 4 KiB-aligned, zeroed page with the
/// VMCS revision ID written at offset 0.
pub fn enable_vmx_on_core(vmxon_region_phys: u64) -> Result<(), &'static str> {
    // Set CR4.VMXE (bit 13).
    unsafe {
        let cr4 = controlregs::cr4();
        controlregs::cr4_write(cr4 | Cr4::CR4_ENABLE_VMX);
    }

    // Adjust CR0 and CR4 to satisfy VMX fixed bits.
    adjust_control_registers();

    // Execute VMXON.
    unsafe {
        x86::bits64::vmx::vmxon(vmxon_region_phys)
            .map_err(|_| "VMXON failed")
    }
}

// ── INVEPT / INVVPID ────────────────────────────────────────────────────── //

/// INVEPT type: invalidate mappings for a single EPTP value.
pub const INVEPT_SINGLE_CONTEXT: u64 = 1;
/// INVEPT type: invalidate all EPT-derived mappings across all EPTPs.
pub const INVEPT_GLOBAL: u64 = 2;

/// Execute INVEPT (Invalidate EPT-Derived Entries).
///
/// `inv_type` selects single-context (1) or global (2).
/// For single-context, `eptp` must be the 64-bit EPTP value (root | flags).
///
/// # Safety
/// Must be called in VMX root mode on a core that has executed VMXON.
#[inline]
pub unsafe fn invept(inv_type: u64, eptp: u64) {
    // INVEPT descriptor: 128 bits — EPTP in [63:0], reserved zeros in [127:64].
    let descriptor: [u64; 2] = [eptp, 0];
    core::arch::asm!(
        "invept {inv_type}, [{desc}]",
        inv_type = in(reg) inv_type,
        desc = in(reg) descriptor.as_ptr(),
        options(nostack, preserves_flags),
    );
}

/// INVVPID type: invalidate all mappings for a single VPID.
pub const INVVPID_SINGLE_CONTEXT: u64 = 1;
/// INVVPID type: invalidate all VPID-tagged mappings except VPID 0.
pub const INVVPID_ALL_CONTEXT: u64 = 2;

/// Execute INVVPID (Invalidate VPID-Tagged TLB Entries).
///
/// # Safety
/// Must be called in VMX root mode on a core that has executed VMXON.
#[inline]
pub unsafe fn invvpid(inv_type: u64, vpid: u16) {
    // INVVPID descriptor: 128 bits — VPID in [15:0], rest zero.
    let descriptor: [u64; 2] = [vpid as u64, 0];
    core::arch::asm!(
        "invvpid {inv_type}, [{desc}]",
        inv_type = in(reg) inv_type,
        desc = in(reg) descriptor.as_ptr(),
        options(nostack, preserves_flags),
    );
}

/// Adjust CR0 and CR4 so that all VMX-required fixed bits are set/cleared.
fn adjust_control_registers() {
    unsafe {
        // CR0: bits in FIXED0 must be 1, bits not in FIXED1 must be 0.
        let cr0_fixed0 = msr::rdmsr(msr::IA32_VMX_CR0_FIXED0);
        let cr0_fixed1 = msr::rdmsr(msr::IA32_VMX_CR0_FIXED1);
        let mut cr0 = controlregs::cr0().bits() as u64;
        cr0 |= cr0_fixed0;     // Set required bits
        cr0 &= cr0_fixed1;     // Clear disallowed bits
        controlregs::cr0_write(controlregs::Cr0::from_bits_truncate(cr0 as usize));

        // CR4: same treatment.
        let cr4_fixed0 = msr::rdmsr(msr::IA32_VMX_CR4_FIXED0);
        let cr4_fixed1 = msr::rdmsr(msr::IA32_VMX_CR4_FIXED1);
        let mut cr4 = controlregs::cr4().bits() as u64;
        cr4 |= cr4_fixed0;
        cr4 &= cr4_fixed1;
        controlregs::cr4_write(Cr4::from_bits_truncate(cr4 as usize));
    }
}
