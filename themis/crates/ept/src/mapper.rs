//! EPT mapper implementation.
//!
//! Ported from `vmxvmm/crates/mmu/eptmapper.rs`.  Changes from original:
//!   - External `utils` / `vmx::bitmaps` types replaced with local types.
//!   - `FrameAllocator` simplified: `&mut self`, returns `Option<u64>` (phys
//!     addr directly) instead of `Option<Frame>` with interior mutability.
//!   - `EptMapper::new` / `get_root` → `new(hhdm_offset, root_phys)` / `eptp`.
//!   - `alloc_root(allocator)` convenience constructor added.
//!   - `debug_range` (used `log::`) removed.
//!   - Redundant `root`/`offset` params removed from `unmap_range`.
//!
//! # Thread-safety invariant
//!
//! `EptMapper` and `MetaAllocator` are **NOT Sync**.  Correct use requires that
//! only one core calls `map_range` / `unmap_range` at a time for a given
//! domain.  This invariant is provided by the **capability engine's
//! update-application lock**: `execute()` serialises all `apply_update` calls
//! so that at most one initiating core runs EPT mutations at any instant.
//! No additional locking is needed inside `EptMapper`.
//!
//! # EPT provenance
//!
//! The walk/map/unmap logic is ported from `vmxvmm/crates/mmu/` (production-
//! tested, not formally verified).  The original plan calls for replacing this
//! with the formally-verified EPT from `asterinas/hyperenclave` (ASPLOS'24,
//! Rust MIR → Coq proofs); see `todo.md` Phase 5b.

use crate::addr::{GuestPhysAddr, HostPhysAddr, HostVirtAddr};
use crate::walker::{Level, WalkNext, Walker};
use crate::{EptEntryFlags, FrameAllocator};

/// Mask to extract the physical address from an EPT entry (bits 51:12).
pub const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;

/// 2 MiB huge page (L2 leaf).
pub const HUGE_PAGE_SIZE: usize = 0x200_000;
/// 1 GiB giant page (L3 leaf).
pub const GIANT_PAGE_SIZE: usize = 0x4000_0000;

/// Bits[5:3] mask for EPT leaf memory type field (Intel SDM Vol 3C §29.3.7).
pub const EPT_MEM_TYPE_MASK: u64 = 0b111 << 3;

/// EPT memory type — wraps the bits[5:3] encoding for leaf EPT entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EptMemoryType(u64);

impl EptMemoryType {
    /// Write-back (WB) — the normal type for regular RAM.
    pub const WB: Self = Self(6 << 3);
    /// Uncacheable (UC) — for MMIO or device memory.
    pub const UC: Self = Self(0 << 3);

    pub fn bits(self) -> u64 {
        self.0
    }
}

/// Non-leaf EPT entry "present" flags.
///
/// Intermediate page-table entries (PML4 → PDPT → PD) must have at minimum
/// READ | WRITE | SUPERVISOR_EXECUTE set.  USER_EXECUTE (bit 10) must be 0
/// in non-leaf entries unless the "mode-based execute control for EPT"
/// VM-execution control is 1 (Intel SDM Vol 3C Table 29-1).  We never enable
/// that control, so intermediate entries must not set bit 10.
const EPT_INTERMEDIATE: EptEntryFlags = EptEntryFlags::READ
    .union(EptEntryFlags::WRITE)
    .union(EptEntryFlags::SUPERVISOR_EXECUTE);

/// Combination of permission bits that marks a non-leaf EPT entry as "present"
/// (reader, writer, and both execute bits — the actual permissions are only
/// checked at the leaf level).
pub const EPT_PRESENT: EptEntryFlags = EptEntryFlags::READ
    .union(EptEntryFlags::WRITE)
    .union(EptEntryFlags::SUPERVISOR_EXECUTE)
    .union(EptEntryFlags::USER_EXECUTE);

/// EPTP flags: WB memory type for EPT paging structures (bits[2:0] = 6) and
/// 4-level walk length minus 1 (bits[5:3] = 3).
pub const EPT_ROOT_FLAGS: u64 = (6 << 0) | (3 << 3);

// ——————————————————————————————— EptMapper ———————————————————————————————— //

pub struct EptMapper {
    hhdm_offset: u64,
    root: u64,
    level: Level,
}

unsafe impl Walker for EptMapper {
    type PhysAddr = HostPhysAddr;
    type VirtAddr = GuestPhysAddr;

    fn translate(&self, phys_addr: Self::PhysAddr) -> HostVirtAddr {
        HostVirtAddr::new((phys_addr.as_u64() + self.hhdm_offset) as usize)
    }

    fn root(&mut self) -> (Self::PhysAddr, Level) {
        (HostPhysAddr(self.root), self.level)
    }

    fn get_phys_addr(entry: u64) -> Self::PhysAddr {
        HostPhysAddr::from_u64(entry & ADDRESS_MASK)
    }
}

impl EptMapper {
    /// Create a mapper over an existing EPT root page.
    pub fn new(hhdm_offset: u64, root_phys: u64) -> Self {
        Self {
            hhdm_offset,
            root: root_phys,
            level: Level::L4,
        }
    }

    /// Allocate a fresh EPT root (PML4) from `allocator` and return a mapper
    /// ready to use.  The root page is zeroed by the allocator.
    pub fn alloc_root(allocator: &mut impl FrameAllocator, hhdm_offset: u64) -> Self {
        let root = allocator
            .allocate_frame()
            .expect("EptMapper::alloc_root: out of frames");
        Self::new(hhdm_offset, root)
    }

    /// Allocate a fresh root at a specific `level` (L3 for 3-level / 39-bit,
    /// L4 for 4-level / 48-bit).  Used by the VT-d SLPT which reuses this
    /// mapper at the level dictated by the DRHD unit's CAP.SAGAW AW field.
    pub fn alloc_root_at_level(
        allocator: &mut impl FrameAllocator,
        hhdm_offset: u64,
        level: Level,
    ) -> Self {
        let root = allocator
            .allocate_frame()
            .expect("EptMapper::alloc_root_at_level: out of frames");
        Self { hhdm_offset, root, level }
    }

    /// Return the raw root physical address.
    ///
    /// Used as the SLPTPTR in a VT-d context entry (bits[63:12] of ctx-entry low).
    pub fn root_phys(&self) -> u64 {
        self.root
    }

    /// Return the EPT pointer (EPTP) value to write into `VMCS.EPT_POINTER`.
    ///
    /// Encodes: 4-level walk, WB memory type, accessed/dirty bits disabled.
    pub fn eptp(&self) -> u64 {
        self.root | EPT_ROOT_FLAGS
    }

    /// Map a physical range: guest-physical `gpa` → host-physical `hpa`, `size` bytes.
    ///
    /// Uses huge (2 MiB) and giant (1 GiB) pages automatically when the range
    /// is aligned and large enough.  Intermediate page-table pages are
    /// allocated from `allocator`.
    pub fn map_range(
        &mut self,
        allocator: &mut impl FrameAllocator,
        gpa: u64,
        hpa: u64,
        size: usize,
        prot: EptEntryFlags,
        mem_type: EptMemoryType,
    ) {
        let gpa_start = GuestPhysAddr(gpa);
        let gpa_end = GuestPhysAddr(gpa + size as u64);

        unsafe {
            self.walk_range(
                gpa_start,
                gpa_end,
                &mut |addr, entry, level| {
                    // Already mapped — descend into non-leaf, or skip an existing huge leaf.
                    if (*entry & EptEntryFlags::READ.bits()) != 0 {
                        if (level == Level::L3 || level == Level::L2)
                            && (*entry & EptEntryFlags::PAGE.bits()) != 0
                        {
                            return WalkNext::Leaf;
                        }
                        return WalkNext::Continue;
                    }

                    let end = gpa + size as u64;
                    let hphys = hpa + (addr.as_u64() - gpa);

                    if level == Level::L3 {
                        if addr.as_u64() % GIANT_PAGE_SIZE as u64 == 0
                            && addr.as_u64() + GIANT_PAGE_SIZE as u64 <= end
                            && hphys % GIANT_PAGE_SIZE as u64 == 0
                        {
                            *entry = hphys
                                | EptEntryFlags::PAGE.bits()
                                | prot.bits()
                                | mem_type.bits();
                            return WalkNext::Leaf;
                        }
                    }
                    if level == Level::L2 {
                        if addr.as_u64() % HUGE_PAGE_SIZE as u64 == 0
                            && addr.as_u64() + HUGE_PAGE_SIZE as u64 <= end
                            && hphys % HUGE_PAGE_SIZE as u64 == 0
                        {
                            *entry = hphys
                                | EptEntryFlags::PAGE.bits()
                                | prot.bits()
                                | mem_type.bits();
                            return WalkNext::Leaf;
                        }
                    }
                    if level == Level::L1 {
                        *entry = hphys | prot.bits() | mem_type.bits();
                        return WalkNext::Leaf;
                    }

                    // Non-leaf: allocate an intermediate page-table page.
                    // SDM: intermediate entries must not set USER_EXECUTE (bit 10).
                    let frame = allocator
                        .allocate_frame()
                        .expect("map_range: out of frames for intermediate EPT page");
                    *entry = frame | EPT_INTERMEDIATE.bits();
                    WalkNext::Continue
                },
            )
            .expect("map_range: walk failed");
        }
    }

    /// Unmap a guest-physical range, freeing any intermediate page-table pages
    /// that become entirely empty.  Huge/giant pages that partially overlap the
    /// range are split: the portions outside the range are re-mapped using the
    /// original HPA, permissions, and memory type of the huge-page entry.
    pub fn unmap_range(
        &mut self,
        allocator: &mut impl FrameAllocator,
        gpa: u64,
        size: usize,
    ) {
        let gpa_addr = GuestPhysAddr(gpa);
        let gpa_end = GuestPhysAddr(gpa + size as u64);
        let hhdm = self.hhdm_offset;
        let root_phys = self.root;

        unsafe {
            // SAFETY INVARIANT: `cleanup_range` calls `cleanup` and `callback`
            // sequentially in a single-threaded recursive walk — the two closures
            // are never invoked concurrently.  The raw pointer below is therefore
            // safe *as long as no other thread holds a reference to `allocator`*.
            //
            // Thread safety is the CALLER's responsibility: the surrounding
            // `Domain` must be held under an exclusive lock before calling
            // `unmap_range`.  `EptMapper` and `MetaAllocator` are NOT Sync.
            let alloc_raw = allocator as *mut dyn FrameAllocator;

            let mut cleanup = |page_virt: HostVirtAddr| {
                let page_phys = page_virt.as_u64() - hhdm;
                (*alloc_raw).free_frame(page_phys);
            };

            let mut callback = |addr: GuestPhysAddr, entry: &mut u64, level: Level| {
                if (*entry & EptEntryFlags::READ.bits()) == 0 {
                    return WalkNext::Leaf;
                }

                let end = gpa + size as u64;
                let mut needs_remap = false;
                let mut aligned_addr = addr.as_u64();
                let mut big_size: u64 = 0;
                // Original huge-page attributes — captured before the entry is zeroed
                // so split re-maps preserve the original HPA, permissions, and memory type.
                let mut orig_hpa: u64 = 0;
                let mut orig_prot = EptEntryFlags::empty();
                let mut orig_mem_type = EptMemoryType::WB;

                if level == Level::L3 && (*entry & EptEntryFlags::PAGE.bits()) != 0 {
                    aligned_addr = addr.as_u64() & level.mask();
                    if gpa <= aligned_addr && aligned_addr + GIANT_PAGE_SIZE as u64 <= end {
                        *entry = 0;
                        return WalkNext::Leaf;
                    }
                    // Partial overlap: capture attrs before zeroing.
                    orig_hpa = *entry & ADDRESS_MASK;
                    orig_prot = EptEntryFlags::from_bits_truncate(*entry);
                    orig_mem_type = EptMemoryType(*entry & EPT_MEM_TYPE_MASK);
                    *entry = 0;
                    needs_remap = true;
                    big_size = GIANT_PAGE_SIZE as u64;
                }
                if level == Level::L2 && (*entry & EptEntryFlags::PAGE.bits()) != 0 {
                    aligned_addr = addr.as_u64() & level.mask();
                    if gpa <= aligned_addr && aligned_addr + HUGE_PAGE_SIZE as u64 <= end {
                        *entry = 0;
                        return WalkNext::Leaf;
                    }
                    // Partial overlap: capture attrs before zeroing.
                    orig_hpa = *entry & ADDRESS_MASK;
                    orig_prot = EptEntryFlags::from_bits_truncate(*entry);
                    orig_mem_type = EptMemoryType(*entry & EPT_MEM_TYPE_MASK);
                    *entry = 0;
                    needs_remap = true;
                    big_size = HUGE_PAGE_SIZE as u64;
                }

                if needs_remap {
                    let mut sub = EptMapper::new(hhdm, root_phys);
                    // Re-map left portion [aligned_addr, gpa) using original attributes.
                    if aligned_addr < gpa {
                        sub.map_range(
                            allocator,
                            aligned_addr,
                            orig_hpa,
                            (gpa - aligned_addr) as usize,
                            orig_prot,
                            orig_mem_type,
                        );
                    }
                    // Re-map right portion [gpa+size, aligned_addr+big_size) using original attrs.
                    let tail_start = gpa + size as u64;
                    let tail_end = aligned_addr + big_size;
                    if tail_start < tail_end {
                        let right_hpa = orig_hpa + (tail_start - aligned_addr);
                        sub.map_range(
                            allocator,
                            tail_start,
                            right_hpa,
                            (tail_end - tail_start) as usize,
                            orig_prot,
                            orig_mem_type,
                        );
                    }
                    return WalkNext::Leaf;
                }

                if level == Level::L1 {
                    *entry = 0;
                    return WalkNext::Leaf;
                }
                WalkNext::Continue
            };

            self.cleanup_range(gpa_addr, gpa_end, &mut callback, &mut cleanup)
                .expect("unmap_range: walk failed");
        }
    }

    /// Release all EPT page-table pages (but not the mapped physical frames).
    pub fn free_all(mut self, allocator: &mut impl FrameAllocator) {
        let root_phys = self.root;
        let hhdm = self.hhdm_offset;

        let mut cleanup = |page_virt: HostVirtAddr| {
            let page_phys = page_virt.as_u64() - hhdm;
            allocator.free_frame(page_phys);
        };
        let mut callback = |_addr: GuestPhysAddr, entry: &mut u64, level: Level| {
            if (*entry & EptEntryFlags::READ.bits()) == 0 {
                return WalkNext::Leaf;
            }
            if level == Level::L1 || (*entry & EptEntryFlags::PAGE.bits()) != 0 {
                return WalkNext::Leaf;
            }
            WalkNext::Continue
        };

        unsafe {
            self.cleanup_range(
                GuestPhysAddr::new(0),
                GuestPhysAddr::new(usize::MAX),
                &mut callback,
                &mut cleanup,
            )
            .expect("free_all: walk failed");
        }
        allocator.free_frame(root_phys);
    }
}
