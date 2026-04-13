//! Minimal GDT + per-core TSS for VMX host state.
//!
//! Intel SDM Vol.3C §26.2.3 requires that the host-state TR selector in the
//! VMCS must be non-null. Limine does **not** load a TR, so after Limine hands
//! off control `str` returns 0, which would cause VMLAUNCH error 8 ("VM entry
//! with invalid host-state field(s)").
//!
//! This module sets up a minimal owned GDT (null + code64 + data + per-core
//! TSS) and loads it with `lgdt`/`ltr` before the VMCS is written.
//!
//! # GDT layout
//!
//! | Index          | Selector          | Contents                     |
//! |----------------|-------------------|------------------------------|
//! | 0              | 0x0000 (null)     | null descriptor              |
//! | 1              | 0x0008            | 64-bit code (L=1, P=1, DPL=0)|
//! | 2              | 0x0010            | 64-bit data (P=1, DPL=0)     |
//! | 3 + 2·n        | 0x0018 + 0x10·n   | TSS available (low qword)    |
//! | 4 + 2·n        | —                 | TSS available (high qword)   |
//!
//! Selectors 0x0008 and 0x0010 mirror the Limine layout so existing segment
//! register values remain valid after `lgdt`.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::platform::MAX_CORES;

// ── 64-bit Task State Segment ─────────────────────────────────────────────── //

/// Minimal 64-bit TSS (104 bytes = 0x68).  `iomap_base` points past the end
/// of the struct, which disables the I/O permission bitmap.
#[repr(C, packed)]
pub struct Tss64 {
    _reserved0: u32,
    rsp0: u64,
    rsp1: u64,
    rsp2: u64,
    _reserved1: u64,
    ist1: u64,
    ist2: u64,
    ist3: u64,
    ist4: u64,
    ist5: u64,
    ist6: u64,
    ist7: u64,
    _reserved2: u64,
    _reserved3: u16,
    /// Offset of I/O permission bitmap from TSS base.  Setting this to
    /// `sizeof(Tss64)` disables the bitmap for this task.
    pub iomap_base: u16,
}

const fn empty_tss() -> Tss64 {
    Tss64 {
        _reserved0: 0,
        rsp0: 0,
        rsp1: 0,
        rsp2: 0,
        _reserved1: 0,
        ist1: 0,
        ist2: 0,
        ist3: 0,
        ist4: 0,
        ist5: 0,
        ist6: 0,
        ist7: 0,
        _reserved2: 0,
        _reserved3: 0,
        iomap_base: core::mem::size_of::<Tss64>() as u16,
    }
}

// ── GDT ──────────────────────────────────────────────────────────────────── //

/// Number of u64 slots in the GDT:
///   1 null + 1 code64 + 1 data + 2 × MAX_CORES TSS entries.
const GDT_FIXED: usize = 3;
const GDT_SIZE: usize = GDT_FIXED + 2 * MAX_CORES;

/// 64-bit code segment: G=1, L=1, P=1, DPL=0, type=0x9B (exec/read/accessed).
const CODE64: u64 = 0x00af9b000000ffff;

/// 64-bit data segment: G=1, P=1, DPL=0, type=0x93 (read/write/accessed).
const DATA64: u64 = 0x00af93000000ffff;

// SAFETY: GDT and TSS_ARRAY are mutable statics because they must be
// written once during init() (BSP-only, guarded by GDT_INITIALIZED CAS)
// and then read by every core via load_for_core()/gdtr_base()/tss_base().
// After init() completes, no further mutations occur — all subsequent
// accesses are read-only pointer/address computations.  We use
// addr_of!/addr_of_mut! at each access site to avoid creating Rust
// references to mutable statics (which would be instant UB under
// Stacked Borrows).
static mut GDT: [u64; GDT_SIZE] = [0u64; GDT_SIZE];
static mut TSS_ARRAY: [Tss64; MAX_CORES] = [const { empty_tss() }; MAX_CORES];

static GDT_INITIALIZED: AtomicBool = AtomicBool::new(false);

// ── Public API ────────────────────────────────────────────────────────────── //

/// Populate GDT and TSS entries (BSP only, idempotent).
///
/// Must be called before [`load_for_core`].
pub fn init() {
    if GDT_INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return; // already initialized
    }

    unsafe {
        let gdt = core::ptr::addr_of_mut!(GDT);
        let tss = core::ptr::addr_of!(TSS_ARRAY);
        (*gdt)[0] = 0; // null
        (*gdt)[1] = CODE64; // selector 0x08 — code64
        (*gdt)[2] = DATA64; // selector 0x10 — data

        for i in 0..MAX_CORES {
            let (lo, hi) = make_tss_descriptor(&(*tss)[i]);
            (*gdt)[GDT_FIXED + 2 * i] = lo;
            (*gdt)[GDT_FIXED + 2 * i + 1] = hi;
        }
    }
}

/// Load the GDT (`lgdt`) and task register (`ltr`) for `cpu_id`.
///
/// After this call `str` returns [`tss_selector`]`(cpu_id)`.
///
/// # Safety
/// [`init`] must have been called first.
pub fn load_for_core(cpu_id: usize) {
    assert!(
        cpu_id < MAX_CORES,
        "gdt::load_for_core: cpu_id out of range"
    );

    let gdt_base = core::ptr::addr_of!(GDT) as u64;
    let gdt_limit = (core::mem::size_of::<[u64; GDT_SIZE]>() - 1) as u16;
    let tss_sel = tss_selector(cpu_id);

    // 10-byte pseudo-descriptor: 2-byte limit followed by 8-byte base.
    let gdtr: [u8; 10] = {
        let mut b = [0u8; 10];
        b[0..2].copy_from_slice(&gdt_limit.to_le_bytes());
        b[2..10].copy_from_slice(&gdt_base.to_le_bytes());
        b
    };

    // lgdt then ltr.  In 64-bit mode the TSS type must be 0x9 (available)
    // before ltr; it becomes 0xB (busy) after.
    unsafe {
        core::arch::asm!(
            "lgdt [{gdt}]",
            "ltr  {tss:x}",
            gdt = in(reg) gdtr.as_ptr(),
            tss = in(reg) tss_sel,
            options(nostack),
        );
    }
}

/// Return the TSS selector for `cpu_id`.
///
/// The selector is `0x0018 + cpu_id * 0x10` (RPL=0, TI=0).
#[inline]
pub fn tss_selector(cpu_id: usize) -> u16 {
    (0x18 + cpu_id * 0x10) as u16
}

/// Return the base address of the TSS for `cpu_id`.
#[inline]
pub fn tss_base(cpu_id: usize) -> u64 {
    assert!(cpu_id < MAX_CORES);
    unsafe { core::ptr::addr_of!(TSS_ARRAY).cast::<Tss64>().add(cpu_id) as u64 }
}

/// Return a reference to the GDT base and limit suitable for writing to
/// `HOST_GDTR_BASE` in the VMCS.
#[inline]
pub fn gdtr_base() -> u64 {
    core::ptr::addr_of!(GDT) as u64
}

// ── Internal helpers ──────────────────────────────────────────────────────── //

/// Encode a 64-bit TSS descriptor into two consecutive GDT qwords.
///
/// GDT system descriptor layout (two 8-byte entries):
///
/// Qword 0 (low):
/// ```
/// bits[15: 0] = limit[15:0]
/// bits[39:16] = base[23:0]
/// bits[43:40] = type = 9 (64-bit TSS, available)
/// bit [44]    = S=0  (system descriptor)
/// bits[46:45] = DPL=0
/// bit [47]    = P=1  (present)
/// bits[51:48] = limit[19:16]
/// bits[55:52] = 0    (AVL, L, D/B, G all zero for TSS)
/// bits[63:56] = base[31:24]
/// ```
///
/// Qword 1 (high):
/// ```
/// bits[31: 0] = base[63:32]
/// bits[63:32] = 0  (reserved)
/// ```
fn make_tss_descriptor(tss: &Tss64) -> (u64, u64) {
    let base = tss as *const Tss64 as u64;
    let limit = (core::mem::size_of::<Tss64>() - 1) as u64; // 0x67

    let access: u64 = 0x89; // P=1, DPL=0, S=0, type=9 (64-bit TSS available)

    let lo = (limit & 0xFFFF)              // limit[15:0]
        | ((base & 0xFF_FFFF) << 16)       // base[23:0]
        | (access << 40)                   // access byte
        | (((limit >> 16) & 0xF) << 48)   // limit[19:16]
        | (((base >> 24) & 0xFF) << 56); // base[31:24]

    let hi = (base >> 32) & 0xFFFF_FFFF; // base[63:32]

    (lo, hi)
}
