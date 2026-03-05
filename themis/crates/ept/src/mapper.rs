//! EPT mapper implementation.
//!
//! Ported from `vmxvmm/crates/mmu/eptmapper.rs`.  Changes from original:
//!   - External `utils` / `vmx::bitmaps` types replaced with local types.
//!   - `FrameAllocator` takes `&mut self` (suits our bump allocator).
//!   - `debug_range` (used `log::`) removed.
//!   - `free_all` / `unmap_range` kept but `free_frame` is a no-op by default.

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
                    // Already mapped — descend or skip huge leaf.
                    if (*entry & EPT_PRESENT.bits()) != 0 {
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
                        if addr.as_u64() + GIANT_PAGE_SIZE as u64 <= end
                            && hphys % GIANT_PAGE_SIZE as u64 == 0
                        {
                            *entry = hphys
                                | EptEntryFlags::PAGE.bits()
                                | prot.bits()
                                | mem_type.bits()
                                | (1 << 7);
                            return WalkNext::Leaf;
                        }
                    }
                    if level == Level::L2 {
                        if addr.as_u64() + HUGE_PAGE_SIZE as u64 <= end
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
                    let frame = allocator
                        .allocate_frame()
                        .expect("map_range: out of frames for intermediate EPT page");
                    *entry = frame | EPT_PRESENT.bits();
                    WalkNext::Continue
                },
            )
            .expect("map_range: walk failed");
        }
    }

    /// Unmap a guest-physical range, freeing any intermediate page-table pages
    /// that become entirely empty.  Huge/giant pages that partially overlap the
    /// range are split and the non-removed portions are re-mapped.
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
            // cleanup only frees intermediate page-table frames; free_frame is
            // a no-op for bump allocators.  To avoid a borrow-conflict between
            // the two closures, we use a raw pointer for cleanup's free call.
            let alloc_raw = allocator as *mut dyn FrameAllocator;

            let mut cleanup = |page_virt: HostVirtAddr| {
                let page_phys = page_virt.as_u64() - hhdm;
                (*alloc_raw).free_frame(page_phys);
            };

            let mut callback = |addr: GuestPhysAddr, entry: &mut u64, level: Level| {
                if (*entry & EPT_PRESENT.bits()) == 0 {
                    return WalkNext::Leaf;
                }

                let end = gpa + size as u64;
                let mut needs_remap = false;
                let mut aligned_addr = addr.as_u64();
                let mut big_size: u64 = 0;

                if level == Level::L3 && (*entry & EptEntryFlags::PAGE.bits()) != 0 {
                    aligned_addr = addr.as_u64() & level.mask();
                    if gpa <= aligned_addr && aligned_addr + GIANT_PAGE_SIZE as u64 <= end {
                        *entry = 0;
                        return WalkNext::Leaf;
                    }
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
                    *entry = 0;
                    needs_remap = true;
                    big_size = HUGE_PAGE_SIZE as u64;
                }

                if needs_remap {
                    let mut sub = EptMapper::new(hhdm, root_phys);
                    let default_prot = EptEntryFlags::READ
                        | EptEntryFlags::WRITE
                        | EptEntryFlags::USER_EXECUTE
                        | EptEntryFlags::SUPERVISOR_EXECUTE;
                    if aligned_addr < gpa {
                        sub.map_range(
                            allocator,
                            aligned_addr,
                            aligned_addr,
                            (gpa - aligned_addr) as usize,
                            default_prot,
                            EptMemoryType::WB,
                        );
                    }
                    let tail_start = gpa + size as u64;
                    let tail_end = aligned_addr + big_size;
                    if tail_start < tail_end {
                        sub.map_range(
                            allocator,
                            tail_start,
                            tail_start,
                            (tail_end - tail_start) as usize,
                            default_prot,
                            EptMemoryType::WB,
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
            if (*entry & EPT_PRESENT.bits()) == 0 {
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
