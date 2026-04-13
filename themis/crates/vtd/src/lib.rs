//! Intel VT-d IOMMU driver.
//!
//! Ported from `vmxvmm/crates/vtd` with the vmxvmm-specific type dependencies
//! (`mmu::FrameAllocator`, `vmx::HostPhysAddr`, `vmx::HostVirtAddr`) replaced
//! by local definitions.  All hardware-interaction logic is unchanged.
//!
//! The `FrameAllocator` trait and `PhysFrame` type defined here will be
//! implemented by `capavisor::memory::FrameAllocator` once that module exists
//! (Phase 1c).

#![no_std]

use core::{ptr, slice};

use bitflags::bitflags;

// ── Address types ────────────────────────────────────────────────────────── //

/// A host physical address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PhysAddr(u64);

impl PhysAddr {
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }
    pub const fn as_u64(self) -> u64 {
        self.0
    }
    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }
}

/// A host virtual address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct VirtAddr(usize);

impl VirtAddr {
    pub const fn new(addr: usize) -> Self {
        Self(addr)
    }
    pub const fn as_usize(self) -> usize {
        self.0
    }
}

// ── Frame allocator trait ────────────────────────────────────────────────── //

/// A 4 KiB physical frame with its corresponding virtual address (via the
/// HHDM).  Returned by `FrameAllocator::allocate_frame`.
pub struct PhysFrame {
    pub phys_addr: PhysAddr,
    /// Virtual address of the frame (HHDM mapping).
    pub virt_addr: usize,
}

impl PhysFrame {
    /// Zero the frame contents and return self for chaining.
    pub fn zeroed(self) -> Self {
        unsafe { ptr::write_bytes(self.virt_addr as *mut u8, 0, 4096) };
        self
    }
}

/// Minimal frame-allocation interface required by the VT-d driver.
///
/// Implemented by `capavisor::memory::FrameAllocator` (Phase 1c).
pub trait FrameAllocator {
    fn allocate_frame(&self) -> Option<PhysFrame>;
}

// ── Device identifier ────────────────────────────────────────────────────── //

/// PCI bus:device.function identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct DeviceId {
    pub bus: u8,
    pub dev_fun: u8,
}

// ── Root / context table entries ─────────────────────────────────────────── //

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct RootEntry {
    pub entry: u64,
    pub reserved: u64,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct ContextEntry {
    pub lower: u64,
    pub upper: u64,
}

// ── I/O MMU register access ──────────────────────────────────────────────── //

/// Helper for accessing VT-d DRHD unit MMIO registers.
pub struct Iommu {
    addr: *mut u8,
}

// SAFETY: the MMIO region is shared across cores but all accesses are
// volatile and serialised by the caller.
unsafe impl Send for Iommu {}

macro_rules! ro_reg {
    ($t:ty, $addr:expr, $get:ident) => {
        pub fn $get(&self) -> $t {
            unsafe { ptr::read_volatile(self.addr.offset($addr) as *mut $t) }
        }
    };
    ($t:ty, $addr:expr, $get:ident, $bitflag:ident) => {
        pub fn $get(&self) -> $bitflag {
            let raw = unsafe { ptr::read_volatile(self.addr.offset($addr) as *mut $t) };
            $bitflag::from_bits_retain(raw)
        }
    };
}

macro_rules! wo_reg {
    ($t:ty, $addr:expr, $set:ident) => {
        pub fn $set(&mut self, val: $t) {
            unsafe { ptr::write_volatile(self.addr.offset($addr) as *mut $t, val) }
        }
    };
}

macro_rules! rw_reg {
    ($t:ty, $addr:expr, $get:ident, $set:ident) => {
        ro_reg!($t, $addr, $get);
        wo_reg!($t, $addr, $set);
    };
    ($t:ty, $addr:expr, $get:ident, $set:ident, $bitflag:ident) => {
        ro_reg!($t, $addr, $get, $bitflag);
        wo_reg!($t, $addr, $set);
    };
}

/// Command bits that have an effect when written as 1 (one-shot semantics).
const ONE_SHOOT_COMMAND_BITS: Command = Command::SET_ROOT_PTR
    .union(Command::WRITE_FLUSH_BUFFER)
    .union(Command::SET_INT_REMAP_PTR);

impl Iommu {
    /// # Safety
    /// `addr` must be the MMIO virtual address of a VT-d DRHD unit, valid
    /// for the lifetime of this `Iommu` instance.
    pub const unsafe fn new(addr: VirtAddr) -> Self {
        Self {
            addr: addr.as_usize() as *mut u8,
        }
    }

    pub fn set_addr(&mut self, addr: usize) {
        self.addr = addr as *mut u8;
    }
    pub fn get_addr(&self) -> *mut u8 {
        self.addr
    }

    pub fn update_root_table_addr(&mut self) {
        self.execute_oneshoot_command(Command::SET_ROOT_PTR);
    }

    pub fn enable_translation(&mut self) {
        self.execute_toggle_command(Command::TRANSLATION_ENABLE, true);
    }

    pub fn iter_fault(&mut self) -> FaultIterator<'_> {
        let capability = self.get_capability().bits();
        let fault_reg_offset = ((capability >> 24) & 0b1111111111) * 16;
        let fault_reg_start = unsafe { self.addr.offset(fault_reg_offset as isize) };
        let nb_regs = ((capability >> 40) & 0b11111111) + 1;

        let fault_status = self.get_fault_status();
        let fault_idx = if fault_status.contains(FaultStatus::PRIMARY_PENDING_FAULT) {
            (fault_status.bits() >> 8) & 0b11111111
        } else {
            0
        };

        FaultIterator {
            fault_reg_start,
            nb_regs: nb_regs as usize,
            idx: fault_idx as usize,
            iommu: self,
        }
    }

    fn execute_oneshoot_command(&mut self, cmd: Command) {
        let status = self.get_global_status() & !ONE_SHOOT_COMMAND_BITS;
        self.set_global_command((status | cmd).bits());
        self.wait_on_global_status(cmd, true);
    }

    fn execute_toggle_command(&mut self, cmd: Command, enable: bool) {
        let status = self.get_global_status();
        let new_status = if enable {
            status & !ONE_SHOOT_COMMAND_BITS | cmd
        } else {
            status & !ONE_SHOOT_COMMAND_BITS & !cmd
        };
        self.set_global_command(new_status.bits());
        self.wait_on_global_status(cmd, enable);
    }

    fn wait_on_global_status(&self, cmd: Command, set: bool) {
        loop {
            let status = self.get_global_status();
            if set && status.contains(cmd) {
                return;
            }
            if !set && !status.intersects(cmd) {
                return;
            }
            core::arch::x86_64::_mm_pause();
        }
    }

    ro_reg!(u32, 0x000, get_version);
    ro_reg!(u64, 0x008, get_capability, Capability);
    ro_reg!(u64, 0x010, get_extended_capability, ExtendedCapability);
    wo_reg!(u32, 0x018, set_global_command);
    ro_reg!(u32, 0x01C, get_global_status, Command);
    rw_reg!(u64, 0x020, get_root_table_addr, set_root_table_addr);
    rw_reg!(u64, 0x028, get_context_command, set_context_command);
    rw_reg!(u32, 0x034, get_fault_status, set_fault_status, FaultStatus);
    rw_reg!(u32, 0x038, get_fault_event_control, set_fault_event_control);
    rw_reg!(u32, 0x03C, get_fault_event_data, set_fault_event_data);
    rw_reg!(u32, 0x040, get_fault_event_addr, set_fault_event_addr);
    rw_reg!(
        u32,
        0x044,
        get_fault_event_upper_addr,
        set_fault_event_upper_addr
    );
    rw_reg!(
        u32,
        0x064,
        get_protect_memory_enable,
        set_protect_memory_enable
    );
    rw_reg!(
        u32,
        0x068,
        get_protect_low_memory_base,
        set_protect_low_memory_base
    );
    rw_reg!(
        u32,
        0x06C,
        get_protect_low_memory_limit,
        set_protect_low_memory_limit
    );
    rw_reg!(
        u64,
        0x070,
        get_protect_high_memory_base,
        set_protect_high_memory_base
    );
    rw_reg!(
        u64,
        0x078,
        get_protect_high_memory_limit,
        set_protect_high_memory_limit
    );
    rw_reg!(
        u64,
        0x0B8,
        get_interrupt_remapping_table_addr,
        set_interrupt_remapping_table_addr
    );
    ro_reg!(u64, 0x100, get_mttr_capability);
}

// ── Fault iterator ───────────────────────────────────────────────────────── //

pub struct FaultInfo {
    pub addr: u64,
    pub record: FaultRecording,
}

pub struct FaultIterator<'iommu> {
    fault_reg_start: *mut u8,
    nb_regs: usize,
    idx: usize,
    iommu: &'iommu mut Iommu,
}

impl<'iommu> Iterator for FaultIterator<'iommu> {
    type Item = FaultInfo;

    fn next(&mut self) -> Option<Self::Item> {
        let (low, high) = unsafe {
            let ptr_low = self.fault_reg_start.offset((self.idx * 16) as isize) as *mut u64;
            let ptr_high = ptr_low.offset(1);

            let low = ptr::read_volatile(ptr_low);
            let high = FaultRecording::from_bits_retain(ptr::read_volatile(ptr_high));

            if high.contains(FaultRecording::FAULT) {
                ptr::write_volatile(ptr_high, high.bits()); // clear by writing 1
            } else {
                let fs = self.iommu.get_fault_status().bits();
                self.iommu.set_fault_status(fs);
                return None;
            }
            (low, high)
        };

        self.idx += 1;
        if self.idx >= self.nb_regs {
            self.idx = 0;
        }

        Some(FaultInfo {
            addr: low,
            record: high,
        })
    }
}

// ── Context table setup helper ───────────────────────────────────────────── //

/// Allocate and populate a root + context table that maps every device on
/// every bus to the second-level page table rooted at `iopt_root`.
///
/// Returns the physical address of the root table (write to VT-d Root Table
/// Address Register).
pub fn setup_iommu_context(iopt_root: PhysAddr, allocator: &impl FrameAllocator) -> PhysAddr {
    let ctx_frame = allocator
        .allocate_frame()
        .expect("VT-d context frame")
        .zeroed();
    let root_frame = allocator
        .allocate_frame()
        .expect("VT-d root frame")
        .zeroed();

    let ctx_entry = ContextEntry {
        upper: 0b010,                       // 4-level second-stage PT
        lower: iopt_root.as_u64() | 0b0001, // present
    };
    let root_entry = RootEntry {
        reserved: 0,
        entry: ctx_frame.phys_addr.as_u64() | 0b1, // present
    };

    unsafe {
        let ctx_array = slice::from_raw_parts_mut(ctx_frame.virt_addr as *mut ContextEntry, 256);
        let root_array = slice::from_raw_parts_mut(root_frame.virt_addr as *mut RootEntry, 256);
        for e in ctx_array {
            *e = ctx_entry;
        }
        for e in root_array {
            *e = root_entry;
        }
    }

    root_frame.phys_addr
}

// ── Bitflags ─────────────────────────────────────────────────────────────── //

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Capability: u64 {
        const NB_DOMAINS              = 0b111;
        const WRITE_BUFFER_FLUSH      = 1 << 4;
        const PROTECTED_LOW_MEMORY    = 1 << 5;
        const PROTECTED_HIGH_MEMORY   = 1 << 6;
        const CACHING_MODE            = 1 << 7;
        const PT_39_BITS              = 1 << 9;
        const PT_48_BITS              = 1 << 10;
        const PT_57_BITS              = 1 << 11;
        const MAXIMUM_GUEST_WIDTH     = 0b111111 << 16;
        const ZERO_LENGTH_READ        = 1 << 22;
        const FAULT_RECORDING_REG     = 0b1111111111 << 24;
        const SECOND_STAGE_2MB        = 1 << 34;
        const SECOND_STAGE_1GB        = 1 << 35;
        const PAGE_SELECTIVE_INVAL    = 1 << 39;
        const NB_FAULT_RECORDING_REG  = 0b11111111 << 40;
        const MAX_ADDR_MASK_VALUE     = 0b111111 << 48;
        const WRITE_DRAINING          = 1 << 54;
        const READ_DRAINING           = 1 << 55;
        const F_STAGE_1GB             = 1 << 56;
        const POSTED_INTERRUPT        = 1 << 59;
        const F_STAGE_5LVL            = 1 << 60;
        const ENHANCED_CMD_SUPPORT    = 1 << 61;
        const ENHANCED_SET8INT_REMAP  = 1 << 62;
        const ENHANCED_SET8ROOT_TABLE = 1 << 63;
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ExtendedCapability: u64 {
        const PAGE_WALK_COHERENCY       = 1 << 0;
        const QUEUED_INVALIDATION       = 1 << 1;
        const DEVICE_TLB_SUPPORT        = 1 << 2;
        const INT_REMAP_SUPPORT         = 1 << 3;
        const EXTENDED_INT_MODE         = 1 << 4;
        const PASS_THROUGH              = 1 << 6;
        const SNOOP_CONTROL             = 1 << 7;
        const IOTLB_REG_OFFSET          = 0b1111111111 << 8;
        const MAX_HANDLE_MASK_VAL       = 0b1111 << 20;
        const MEMORY_TYPE_SUPPORT       = 1 << 25;
        const NESTED_TRANSLATION        = 1 << 26;
        const PAGE_REQUEST              = 1 << 29;
        const EXECUTE_REQUEST           = 1 << 30;
        const SUPERVISOR_REQUEST        = 1 << 31;
        const NO_WRITE_FLAG             = 1 << 33;
        const EXTENDED_ACCESS_FLAG      = 1 << 34;
        const PROCESS_ASID_SIZE         = 0b11111 << 35;
        const PROCESS_ASID              = 1 << 40;
        const DEVICE_TLB_INVAL_THROTTLE = 1 << 41;
        const PAGE_REQUEST_DRAIN        = 1 << 42;
        const SCALABLE_MODE_SUPPORT     = 1 << 43;
        const VIRTUAL_CMD_SUPPORT       = 1 << 44;
        const S_STAGE_ACCESS_DIRTY      = 1 << 45;
        const S_STAGE_TRANSLATION       = 1 << 46;
        const SCALABLE_MODE_COHERENCY   = 1 << 48;
        const RID_PASID                 = 1 << 49;
        const PERF_MONITORING           = 1 << 51;
        const ABORT_DMA_MODE            = 1 << 52;
        const RID_PRIV                  = 1 << 53;
        const STOP_MARKER_SUPPORT       = 1 << 58;
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Command: u32 {
        const COMPATIBILITY_FORMAT_INT = 1 << 23;
        const SET_INT_REMAP_PTR        = 1 << 24;
        const INT_REMAP_ENABLE         = 1 << 25;
        const QUEUED_INVALIDATION      = 1 << 26;
        const WRITE_FLUSH_BUFFER       = 1 << 27;
        const SET_ROOT_PTR             = 1 << 30;
        const TRANSLATION_ENABLE       = 1 << 31;
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct FaultStatus: u32 {
        const PRIMARY_FAULT_OVERFLOW        = 1 << 0;
        const PRIMARY_PENDING_FAULT         = 1 << 1;
        const INVALIDATION_QUEUE_ERROR      = 1 << 4;
        const INVALIDATION_COMPLETION_ERROR = 1 << 5;
        const INVALIDATION_TIME_OUT_ERROR   = 1 << 6;
        const FAULT_RECORD_INDEX            = 0b11111111 << 8;
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct FaultRecording: u64 {
        const SOURCE_ID           = 0b111111111111111;
        const T2                  = 1 << 28;
        const PRIVILEGE_MODE_REQ  = 1 << 29;
        const EXEC_ACCESS_REQUEST = 1 << 30;
        const PASID_PRESENT       = 1 << 31;
        const FAULT_REASON        = 0b11111111 << 32;
        const PASID               = 0b11111111111111111111 << 40;
        const ADDRESS_TYPE        = 0b11 << 60;
        const T1                  = 1 << 62;
        const FAULT               = 1 << 63;
    }
}

impl FaultRecording {
    pub fn reason(self) -> u8 {
        ((self.bits() >> 32) & 0b11111111) as u8
    }
}
