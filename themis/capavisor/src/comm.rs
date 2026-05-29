//! Typed wrapper around the VP COMM page.
//!
//! The COMM page (`VpCommPage`) is the shared-memory ABI between a parent VMM
//! (e.g. dom0/CHV) and capavisor for one child VP.  It carries:
//!
//! - **Register area**: per-register values, addressed by `VpRegister`, with a
//!   dirty-bit mask so the parent can request specific register writes on the
//!   next SWITCH.
//! - **Intercept message area** (offset `VP_COMM_INTERCEPT_OFFSET`): a slim
//!   metadata blob describing the most recent exit (reason, qualification,
//!   instruction bytes, etc.).
//!
//! All access goes through `VpCommView`: it concentrates the one unsafe
//! pointer cast (`(comm_hpa + hhdm) as *mut VpCommPage`) and exposes typed
//! operations.  Callers must not synthesize their own pointer to the page.

use alloc::vec::Vec;

use themis_abi::regs::{
    InterceptMessage, VpCommPage, VpRegister, ALL_VP_REGISTERS, VP_COMM_INTERCEPT_OFFSET,
};

use crate::vcpu::ActiveVcpu;

/// Mutable view over a VP COMM page mapped at the capavisor's HHDM offset.
///
/// Use [`VpCommView::map`] to obtain one for a child VP's COMM HPA.  The view
/// borrows the page for as long as the wrapper is live; do not construct two
/// concurrent views over the same `comm_hpa`.
pub struct VpCommView<'a> {
    page: &'a mut VpCommPage,
}

impl<'a> VpCommView<'a> {
    /// Map the COMM page identified by `comm_hpa` (raw physical address) via the
    /// capavisor's HHDM offset.  Returns `None` if `comm_hpa == 0` (no COMM page
    /// registered for this VP).
    ///
    /// # Safety
    /// `comm_hpa` must be the COMM page HPA previously registered for this VP
    /// via `THHV_CREATE_VP`, and no other `VpCommView` may be live over the
    /// same address for the duration of the borrow.
    pub unsafe fn map(comm_hpa: u64, hhdm: u64) -> Option<Self> {
        if comm_hpa == 0 {
            return None;
        }
        let page = unsafe { &mut *((comm_hpa + hhdm) as *mut VpCommPage) };
        Some(Self { page })
    }

    /// Atomically snapshot-and-clear the COMM page's dirty mask, returning the
    /// list of `(reg, value)` pairs that the parent has dirty-marked for the
    /// next SWITCH.
    ///
    /// Clearing the dirty bits before returning prevents infinite replay if a
    /// subsequent operation (e.g. `set_register`) would re-mark them.
    pub fn take_dirty(&mut self) -> Vec<(VpRegister, u64)> {
        let dirty = [
            self.page.dirty_mask[0],
            self.page.dirty_mask[1],
            self.page.dirty_mask[2],
        ];
        if dirty.iter().all(|w| *w == 0) {
            return Vec::new();
        }
        for i in 0..3 {
            self.page.dirty_mask[i] &= !dirty[i];
        }
        let mut out = Vec::new();
        for reg in ALL_VP_REGISTERS {
            let (w, b) = VpCommPage::mask_bit(*reg);
            if dirty[w] & (1 << b) == 0 {
                continue;
            }
            out.push((*reg, self.page.read_reg(*reg)));
        }
        out
    }

    /// Copy the VP registers selected by `is_set(reg)` from `vcpu` into the
    /// COMM page register area.  Used by the child-exit and interrupt-forward
    /// paths to publish the read-policy-selected register subset to the parent.
    pub fn copy_regs_from_vcpu<F>(&mut self, vcpu: &mut ActiveVcpu, is_set: F)
    where
        F: Fn(VpRegister) -> bool,
    {
        for reg in ALL_VP_REGISTERS {
            if !is_set(*reg) {
                continue;
            }
            let val = if let Some(gpr) = crate::hypercall::vp_reg_to_gpr(*reg) {
                vcpu.reg(gpr)
            } else if let Some(field) = crate::hypercall::vp_reg_to_vmcs_field(*reg) {
                vcpu.try_get(field).unwrap_or(0)
            } else {
                continue;
            };
            self.page.write_reg(*reg, val);
        }
    }

    /// Write the slim intercept message at the standard offset
    /// (`VP_COMM_INTERCEPT_OFFSET`).  The write is volatile so the parent
    /// observes the full message atomically on its next read.
    pub fn write_intercept(&mut self, msg: &InterceptMessage) {
        let base = self.page as *mut VpCommPage as *mut u8;
        let dst = unsafe { base.add(VP_COMM_INTERCEPT_OFFSET) } as *mut InterceptMessage;
        unsafe { core::ptr::write_volatile(dst, *msg) };
    }
}
