//! Posted-Interrupt Descriptor (PID) — Intel SDM Vol 3C §29.6.
//!
//! 64-byte, 64-byte-aligned hardware structure used by VT-x posted
//! interrupts.  Layout:
//!
//! ```text
//!   bytes  0..32   PIR  — 256-bit Posted-Interrupt Requests bitmap
//!                         (one bit per interrupt vector 0..=255)
//!   byte  32  b0   ON   — Outstanding Notification (set by poster;
//!                         cleared by hardware after processing PIR)
//!   byte  32  b1   SN   — Suppress Notification (set while vCPU is
//!                         scheduled off to elide notification IPIs)
//!   byte  33       NV   — Notification Vector (8 bits)
//!   bytes 40..44   NDST — Notification Destination (APIC ID of the
//!                         physical CPU currently running this vCPU)
//! ```
//!
//! The PID is pointed to by the child VMCS via the field encoded as
//! `x86::vmx::vmcs::control::POSTED_INTERRUPT_DESC_ADDR_FULL`.
//!
//! All mutating accessors are `unsafe`: the caller must provide a valid
//! physical address of an existing PID page accessible via the HHDM
//! identity map.  The methods are no-ops when `self.is_null()` (the
//! capavisor uses `phys == 0` to represent "no PID" — e.g. for dom0).

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

const PIR_OFFSET: usize = 0;
const ON_OFFSET: usize = 32;
const NDST_OFFSET: usize = 40;

/// Typed handle to a Posted-Interrupt Descriptor.
///
/// Holds the physical address of the descriptor and the HHDM offset used
/// to dereference it.  Cheap to copy; carries no allocations.
#[derive(Clone, Copy)]
pub struct PidPage {
    phys: u64,
    hhdm: u64,
}

#[allow(dead_code)] // accessors form the typed surface; some may be unused.
impl PidPage {
    #[inline]
    pub const fn new(phys: u64, hhdm: u64) -> Self {
        Self { phys, hhdm }
    }

    /// `true` if this handle does not refer to a real PID page (e.g. dom0).
    #[inline]
    pub const fn is_null(self) -> bool {
        self.phys == 0
    }

    #[inline]
    fn virt(self, offset: usize) -> usize {
        (self.phys + self.hhdm) as usize + offset
    }

    /// Set bit `vector` in the PIR bitmap.
    ///
    /// PIR is 4 × `u64` starting at byte 0.  Uses an atomic OR so concurrent
    /// posters are race-free.
    ///
    /// # Safety
    /// `self.phys` must point to a 64-byte aligned PID page reachable via the
    /// HHDM at offset `self.hhdm`.
    #[inline]
    pub unsafe fn set_pir(self, vector: u8) {
        let word = (vector / 64) as usize;
        let bit = vector % 64;
        let pir = self.virt(PIR_OFFSET) as *const AtomicU64;
        unsafe { (*pir.add(word)).fetch_or(1u64 << bit, Ordering::Release) };
    }

    /// Atomically set the Outstanding-Notification (ON) bit.
    ///
    /// Returns `true` if ON was already set (another poster beat us — no
    /// notification IPI needed); `false` if this call was the first setter
    /// (caller must send the notification IPI).
    ///
    /// # Safety
    /// Same as [`set_pir`].
    #[inline]
    pub unsafe fn test_and_set_on(self) -> bool {
        let on = self.virt(ON_OFFSET) as *const AtomicU32;
        let prev = unsafe { (*on).fetch_or(1, Ordering::AcqRel) };
        prev & 1 != 0
    }

    /// Write the NDST field to `lapic_id`.  No-op when `self.is_null()`.
    ///
    /// # Safety
    /// Same as [`set_pir`].  Caller must ensure no concurrent reader is
    /// racing on NDST (typically called only when the vCPU is migrating
    /// between cores under a lock).
    #[inline]
    pub unsafe fn set_ndst(self, lapic_id: u32) {
        if self.is_null() {
            return;
        }
        let ndst = self.virt(NDST_OFFSET) as *mut u32;
        unsafe { core::ptr::write_volatile(ndst, lapic_id) };
    }

    /// Read the current NDST field.
    ///
    /// # Safety
    /// Same as [`set_pir`].
    #[inline]
    pub unsafe fn read_ndst(self) -> u32 {
        let ndst = self.virt(NDST_OFFSET) as *const u32;
        unsafe { core::ptr::read_volatile(ndst) }
    }
}
