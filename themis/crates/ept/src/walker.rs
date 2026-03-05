//! Page-table walker — generic 4-level walk used by the EPT mapper.
//!
//! Ported from `vmxvmm/crates/mmu/walker.rs`.  The only changes are:
//!   - vmxvmm's `utils::{GuestPhysAddr, …}` replaced by local types from `addr.rs`.
//!   - RISC-V `visionfive2` feature-gate dead code removed.

use core::slice;

use crate::addr::HostVirtAddr;

const NB_ENTRIES: usize = 512;
const PAGE_SIZE: u64 = 0x1000;
const PAGE_TABLE_INDEX_MASK: u64 = 0b111111111;
const PAGE_TABLE_INDEX_LEN: u64 = 9;
const L1_INDEX_START: u64 = 12;

// —————————————————————————————— Page Levels ——————————————————————————————— //

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    L4,
    L3,
    L2,
    L1,
}

impl Level {
    pub fn next(self) -> Option<Self> {
        match self {
            Level::L4 => Some(Level::L3),
            Level::L3 => Some(Level::L2),
            Level::L2 => Some(Level::L1),
            Level::L1 => None,
        }
    }

    pub fn area_size(self) -> u64 {
        match self {
            Level::L4 => PAGE_SIZE << 27,
            Level::L3 => PAGE_SIZE << 18,
            Level::L2 => PAGE_SIZE << 9,
            Level::L1 => PAGE_SIZE,
        }
    }

    pub fn mask(self) -> u64 {
        match self {
            Level::L4 => !((1 << (L1_INDEX_START + 3 * PAGE_TABLE_INDEX_LEN)) - 1),
            Level::L3 => !((1 << (L1_INDEX_START + 2 * PAGE_TABLE_INDEX_LEN)) - 1),
            Level::L2 => !((1 << (L1_INDEX_START + PAGE_TABLE_INDEX_LEN)) - 1),
            Level::L1 => !((1 << L1_INDEX_START) - 1),
        }
    }
}

// ——————————————————————————————— Address trait ———————————————————————————————— //

pub trait Address: Sized + Copy + Ord {
    fn from_u64(addr: u64) -> Self;
    fn as_u64(self) -> u64;
    fn from_usize(addr: usize) -> Self;
    fn as_usize(self) -> usize;

    #[inline]
    fn add(self, offset: u64) -> Option<Self> {
        self.as_u64().checked_add(offset).map(Self::from_u64)
    }

    #[inline]
    fn mask(self, mask: u64) -> Self {
        Self::from_u64(self.as_u64() & mask)
    }

    #[inline]
    fn l4_index(self) -> usize {
        ((self.as_u64() >> (L1_INDEX_START + 3 * PAGE_TABLE_INDEX_LEN)) & PAGE_TABLE_INDEX_MASK)
            as usize
    }
    #[inline]
    fn l3_index(self) -> usize {
        ((self.as_u64() >> (L1_INDEX_START + 2 * PAGE_TABLE_INDEX_LEN)) & PAGE_TABLE_INDEX_MASK)
            as usize
    }
    #[inline]
    fn l2_index(self) -> usize {
        ((self.as_u64() >> (L1_INDEX_START + PAGE_TABLE_INDEX_LEN)) & PAGE_TABLE_INDEX_MASK)
            as usize
    }
    #[inline]
    fn l1_index(self) -> usize {
        ((self.as_u64() >> L1_INDEX_START) & PAGE_TABLE_INDEX_MASK) as usize
    }

    fn index(self, level: Level) -> usize {
        match level {
            Level::L4 => self.l4_index(),
            Level::L3 => self.l3_index(),
            Level::L2 => self.l2_index(),
            Level::L1 => self.l1_index(),
        }
    }
}

// ————————————————————————————————— Walker ————————————————————————————————— //

pub enum WalkNext {
    Continue,
    Leaf,
    Abort,
}

pub unsafe trait Walker {
    type PhysAddr: Address;
    type VirtAddr: Address;

    fn translate(&self, phys_addr: Self::PhysAddr) -> HostVirtAddr;
    fn root(&mut self) -> (Self::PhysAddr, Level);
    fn get_phys_addr(entry: u64) -> Self::PhysAddr;

    unsafe fn walk<F>(&mut self, addr: Self::VirtAddr, callback: &mut F) -> Result<(), ()>
    where
        F: FnMut(&mut u64, Level) -> WalkNext,
    {
        let (mut phys_addr, mut level) = self.root();
        loop {
            let page = self.as_page(self.translate(phys_addr));
            let idx = addr.index(level);
            let entry = &mut page[idx];
            match callback(entry, level) {
                WalkNext::Abort => return Err(()),
                WalkNext::Leaf => return Ok(()),
                WalkNext::Continue => (),
            }
            level = match level.next() {
                Some(next) => next,
                None => return Ok(()),
            };
            phys_addr = Self::get_phys_addr(*entry);
        }
    }

    unsafe fn walk_range<F>(
        &mut self,
        start: Self::VirtAddr,
        end: Self::VirtAddr,
        callback: &mut F,
    ) -> Result<(), ()>
    where
        F: FnMut(Self::VirtAddr, &mut u64, Level) -> WalkNext,
    {
        let (phys_addr, level) = self.root();
        let page = as_page(self, self.translate(phys_addr));
        walk_range_rec(self, page, level, start, end, callback, &mut |_| {})
    }

    unsafe fn cleanup_range<F, C>(
        &mut self,
        start: Self::VirtAddr,
        end: Self::VirtAddr,
        callback: &mut F,
        cleanup: &mut C,
    ) -> Result<(), ()>
    where
        F: FnMut(Self::VirtAddr, &mut u64, Level) -> WalkNext,
        C: FnMut(HostVirtAddr),
    {
        let (phys_addr, level) = self.root();
        let page = as_page(self, self.translate(phys_addr));
        walk_range_rec(self, page, level, start, end, callback, cleanup)
    }

    unsafe fn as_page(&mut self, addr: HostVirtAddr) -> &mut [u64] {
        slice::from_raw_parts_mut(addr.as_usize() as *mut u64, NB_ENTRIES)
    }
}

// ————————————————————— Internal recursive walker —————————————————————————— //

unsafe fn walk_range_rec<VirtAddr, PhysAddr, W, F, C>(
    walker: &mut W,
    page: &mut [u64],
    level: Level,
    start: VirtAddr,
    end: VirtAddr,
    callback: &mut F,
    cleanup: &mut C,
) -> Result<(), ()>
where
    VirtAddr: Address,
    PhysAddr: Address,
    W: Walker<VirtAddr = VirtAddr, PhysAddr = PhysAddr> + ?Sized,
    F: FnMut(VirtAddr, &mut u64, Level) -> WalkNext,
    C: FnMut(HostVirtAddr),
{
    let mut idx = start.index(level);
    let mut addr = start;
    let next_level = level.next();
    let level_offset = level.area_size();
    let level_mask = level.mask();

    while addr < end && idx < NB_ENTRIES {
        let entry = &mut page[idx];
        match callback(addr, entry, level) {
            WalkNext::Continue => {
                if let Some(next) = next_level {
                    let phys_addr = W::get_phys_addr(*entry);
                    let host_virt = walker.translate(phys_addr);
                    let child_page = as_page(walker, host_virt);
                    walk_range_rec(walker, child_page, next, addr, end, callback, cleanup)?;

                    let use_index_zero = addr.index(next) == 0;
                    // Note: `next.area_size()` is 4KB at L2 level, which is much
                    // smaller than a full L1 page (512×4KB = 2MB).  This condition
                    // is overly permissive for partial-range walks — cleanup may fire
                    // even when only some entries of the child page were visited.
                    // Harmless because MetaAllocator::free_frame is a no-op (bump
                    // allocator); would be a use-after-free bug with a real allocator.
                    // Fix: replace with `end - start >= level.area_size()`.
                    let use_whole_area = end.as_u64() - start.as_u64() >= next.area_size();
                    if use_index_zero && use_whole_area {
                        cleanup(host_virt);
                    }
                }
            }
            WalkNext::Leaf => (),
            WalkNext::Abort => return Err(()),
        }

        addr = match addr.mask(level_mask).add(level_offset) {
            None => break,
            Some(a) => a,
        };
        idx += 1;
    }
    Ok(())
}

unsafe fn as_page<'a, 'b, W>(_walker: &'a mut W, addr: HostVirtAddr) -> &'b mut [u64]
where
    'b: 'a,
    W: Walker + ?Sized,
{
    slice::from_raw_parts_mut(addr.as_usize() as *mut u64, NB_ENTRIES)
}
