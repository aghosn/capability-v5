//! Domain representation.
//!
//! A domain is the unit of isolation in Themis.  Hardware VP structures
//! (VMXON, VMCS, VAPIC) are allocated from the domain's META pool, which
//! lives entirely inside `ThemisPlatform`.  This struct just tracks the
//! physical addresses that were allocated for this domain.

extern crate alloc;
use alloc::vec::Vec;

/// Opaque domain identifier.
pub type DomainId = u64;

/// Tracking struct for a domain's allocated hardware-VP page addresses.
///
/// The actual frame allocator lives in `ThemisPlatform::PlatformDomain::meta`.
/// Allocation is done via `ThemisPlatform::alloc_meta_frame()`.
pub struct Domain {
    pub id: DomainId,
    /// HHDM offset — needed to write revision IDs into freshly-allocated pages.
    pub hhdm_offset: u64,
    /// Physical addresses of VMXON regions, one per physical core.
    pub vmxon_regions: Vec<u64>,
    /// Physical addresses of VMCS pages, one per VP.
    pub vmcs_regions: Vec<u64>,
    /// Physical addresses of VAPIC pages, one per VP.
    pub vapic_regions: Vec<u64>,
    /// I/O bitmap pages (shared by all VPs).
    /// A = ports 0x0000–0x7FFF, B = ports 0x8000–0xFFFF.
    pub io_bitmap_a: u64,
    pub io_bitmap_b: u64,
    /// MSR bitmap page (shared by all VPs).
    /// All-zeros = no MSR intercepts.
    pub msr_bitmap: u64,
}

impl Domain {
    pub fn new(id: DomainId, hhdm_offset: u64) -> Self {
        Self {
            id,
            hhdm_offset,
            vmxon_regions: Vec::new(),
            vmcs_regions: Vec::new(),
            vapic_regions: Vec::new(),
            io_bitmap_a: 0,
            io_bitmap_b: 0,
            msr_bitmap: 0,
        }
    }

    /// Allocate `num_cores` VMXON pages from `platform` and record them.
    ///
    /// Each page is already zeroed by the allocator; this writes the VMCS
    /// revision ID at offset 0.
    pub fn alloc_vmxon_regions(
        &mut self,
        platform: &crate::platform::ThemisPlatform,
        num_cores: usize,
        vmcs_revision_id: u32,
    ) {
        self.vmxon_regions.reserve(num_cores);
        for _ in 0..num_cores {
            let phys = platform.alloc_meta_frame(self.id);
            let virt = (phys + self.hhdm_offset) as *mut u32;
            unsafe { virt.write_volatile(vmcs_revision_id & 0x7FFF_FFFF) };
            self.vmxon_regions.push(phys);
        }
    }

    /// Allocate `num_vps` VMCS pages from `platform` and record them.
    pub fn alloc_vmcs_regions(
        &mut self,
        platform: &crate::platform::ThemisPlatform,
        num_vps: usize,
        vmcs_revision_id: u32,
    ) {
        self.vmcs_regions.reserve(num_vps);
        for _ in 0..num_vps {
            let phys = platform.alloc_meta_frame(self.id);
            let virt = (phys + self.hhdm_offset) as *mut u32;
            unsafe { virt.write_volatile(vmcs_revision_id & 0x7FFF_FFFF) };
            self.vmcs_regions.push(phys);
        }
    }

    /// Allocate `num_vps` VAPIC pages from `platform` and record them.
    pub fn alloc_vapic_regions(
        &mut self,
        platform: &crate::platform::ThemisPlatform,
        num_vps: usize,
    ) {
        self.vapic_regions.reserve(num_vps);
        for _ in 0..num_vps {
            // alloc_meta_frame already returns a zeroed page.
            self.vapic_regions.push(platform.alloc_meta_frame(self.id));
        }
    }

    /// Allocate I/O bitmap pages and set bits for reset/shutdown ports.
    ///
    /// A zeroed bitmap = all ports pass through.  We set bits only for
    /// ports that trigger machine reset/shutdown so the VMEXIT handler
    /// can log them instead of letting QEMU silently exit.
    pub fn alloc_io_bitmaps(
        &mut self,
        platform: &crate::platform::ThemisPlatform,
    ) {
        self.io_bitmap_a = platform.alloc_meta_frame(self.id);
        self.io_bitmap_b = platform.alloc_meta_frame(self.id);

        // Set intercepted port bits in bitmap A (ports 0x0000–0x7FFF).
        let bitmap_a_ptr = (self.io_bitmap_a + self.hhdm_offset) as *mut u8;
        unsafe {
            // Port 0x64 — keyboard controller (cmd 0xFE = reset)
            let byte = bitmap_a_ptr.add(0x64 / 8);
            byte.write_volatile(byte.read_volatile() | (1 << (0x64 % 8)));
            // Port 0xCF9 — reset control register
            let byte = bitmap_a_ptr.add(0xCF9 / 8);
            byte.write_volatile(byte.read_volatile() | (1 << (0xCF9 % 8)));
            // Port 0x604 — PIIX4 ACPI power management (PM1a_CNT)
            let byte = bitmap_a_ptr.add(0x604 / 8);
            byte.write_volatile(byte.read_volatile() | (1 << (0x604 % 8)));
        }
    }

    /// Allocate the MSR bitmap page from META (shared by all VPs).
    ///
    /// A zeroed page means no MSR intercepts — all RDMSR/WRMSR pass through
    /// to hardware.  alloc_meta_frame already returns a zeroed page.
    pub fn alloc_msr_bitmap(
        &mut self,
        platform: &crate::platform::ThemisPlatform,
    ) {
        self.msr_bitmap = platform.alloc_meta_frame(self.id);
    }

    pub fn vmxon_phys(&self, core_index: usize) -> u64 { self.vmxon_regions[core_index] }
    pub fn vmcs_phys(&self, vp_index: usize)   -> u64 { self.vmcs_regions[vp_index] }
    pub fn vapic_phys(&self, vp_index: usize)  -> u64 { self.vapic_regions[vp_index] }
    pub fn msr_bitmap_phys(&self)              -> u64 { self.msr_bitmap }
}
