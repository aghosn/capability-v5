//! APIC-access exit handler + write-instruction decoder.
//!
//! Emulates remaining APIC accesses not handled by APIC_REGISTER_VIRT/VID
//! hardware acceleration: data reads, EOI side-effects (clear ISR top bit),
//! and decoded MOV writes from MMIO `writel()`.

use x86::vmx::vmcs;

use crate::arch::x86_64::vmexit_decode::{ApicAccessType, ExitQualification};
use crate::serial_println;
use crate::vcpu::{ActiveVcpu, Reg};
use crate::arch::x86_64::vcpu_ext::ActiveVcpuExt;

use super::{APIC_REG_EOI, APIC_REG_ISR_BASE};

/// Handle an APIC-access VM exit (exit reason 44).
///
/// Triggered when the guest accesses the APIC-access page (GPA 0xFEE00000)
/// while VIRTUALIZE_APIC_ACCESSES is set.  With APIC_REGISTER_VIRT=1 and
/// VID=1, most register reads and EOI/TPR writes are handled by hardware
/// without an exit.  This handler sees the remaining accesses (e.g. ICR
/// writes for IPI delivery, non-standard register accesses).
///
/// Current policy: emulate read accesses from the VAPIC page; log and
/// advance RIP for write accesses.  ICR-based IPI emulation can be added
/// here when multi-VP child domains are needed.
///
/// Exit qualification bit layout (SDM Vol 3C §27.2.1 Table 27-6):
///   bits[11:0] — access offset within the 4 KB APIC-access page
///   bits[15:12] — access type: 0=data-read, 1=data-write, 2=instr-fetch,
///                              3=read-during-event-delivery, 10=GPA-read
pub(super) fn handle_apic_access_exit(vcpu: &mut ActiveVcpu, platform: &crate::platform::ThemisPlatform) {
    let info = ExitQualification(vcpu.get(vmcs::ro::EXIT_QUALIFICATION)).apic();
    let offset = match info.offset {
        Some(off) => off,
        None => {
            // GPA-mode access — nothing meaningful to do, advance RIP.
            vcpu.next_rip();
            return;
        }
    };

    let hhdm = platform.hhdm_offset();

    let vapic_phys = vcpu.vapic_phys();
    let vapic_virt = (vapic_phys + hhdm) as *mut u32;

    match info.access {
        ApicAccessType::DataRead | ApicAccessType::EventDeliveryLinear => {
            // Data read or read during event delivery: return VAPIC page value.
            let word_idx = offset / 4;
            let val = unsafe { vapic_virt.add(word_idx).read_volatile() };
            vcpu.set_reg(Reg::Rax, val as u64);
        }
        ApicAccessType::DataWrite => {
            // Data write: decode instruction to find source register value,
            // then mirror into VAPIC page.
            let val = decode_apic_write_value(vcpu, platform).unwrap_or(vcpu.reg(Reg::Rax) as u32);

            if offset == APIC_REG_EOI {
                // EOI: clear the highest-priority bit in the ISR (In-Service
                // Register, offsets 0x100-0x170 = 8 × 32-bit words = 256 bits).
                // Scan from highest word (0x170) down to lowest (0x100).
                for w in (0..8).rev() {
                    let isr_idx = (APIC_REG_ISR_BASE / 4) + w; // word index in VAPIC page
                    let isr_val = unsafe { vapic_virt.add(isr_idx).read_volatile() };
                    if isr_val != 0 {
                        let bit = 31 - isr_val.leading_zeros();
                        unsafe {
                            vapic_virt
                                .add(isr_idx)
                                .write_volatile(isr_val & !(1 << bit));
                        }
                        break;
                    }
                }
            } else {
                let word_idx = offset / 4;
                unsafe { vapic_virt.add(word_idx).write_volatile(val) };
            }
        }
        _ => {
            serial_println!(
                "[APIC_ACCESS] unhandled access type {:?} offset={:#x} — advancing RIP",
                info.access,
                offset
            );
        }
    }
    vcpu.next_rip();
}

/// Decode the faulting MOV instruction at guest RIP to extract the 32-bit
/// value being written for an APIC-access write exit.
///
/// Handles the common `mov [mem], reg32` (opcode 0x89) and
/// `mov [mem], imm32` (opcode 0xC7 /0) patterns emitted by `writel()`.
/// Returns `None` if the instruction can't be decoded.
pub(super) fn decode_apic_write_value(
    vcpu: &mut ActiveVcpu,
    platform: &crate::platform::ThemisPlatform,
) -> Option<u32> {
    use crate::arch::x86_64::page_walk::{ept_gpa_to_hpa, guest_gva_to_gpa};

    let hhdm = platform.hhdm_offset();
    let guest_rip = vcpu.rip();
    let guest_cr3 = vcpu.get(vmcs::guest::CR3);
    let ept_root = vcpu.get(x86::vmx::vmcs::control::EPTP_FULL);

    let insn_gpa = guest_gva_to_gpa(ept_root, hhdm, guest_cr3, guest_rip)?;
    let insn_hpa = ept_gpa_to_hpa(ept_root, hhdm, insn_gpa)?;
    let insn_ptr = (insn_hpa + hhdm) as *const u8;
    let avail = core::cmp::min(16, 0x1000 - (insn_hpa & 0xFFF) as usize);
    let mut buf = [0u8; 16];
    unsafe { core::ptr::copy_nonoverlapping(insn_ptr, buf.as_mut_ptr(), avail) };

    // Skip prefixes: REX (0x40-0x4F), operand-size (0x66), address-size (0x67)
    let mut i = 0;
    let mut rex: u8 = 0;
    while i < avail {
        match buf[i] {
            0x40..=0x4F => {
                rex = buf[i];
                i += 1;
            }
            0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3 | 0x2E | 0x3E | 0x26 | 0x64 | 0x65 | 0x36 => {
                i += 1;
            }
            _ => break,
        }
    }
    if i >= avail {
        return None;
    }

    let opcode = buf[i];
    i += 1;
    if i >= avail {
        return None;
    }

    match opcode {
        0x89 => {
            // MOV r/m32, r32: source register in ModRM reg field (bits 5:3)
            let modrm = buf[i];
            let reg_idx = ((modrm >> 3) & 0x7) | (if rex & 0x4 != 0 { 0x8 } else { 0 });
            let val = match reg_idx {
                0 => vcpu.reg(Reg::Rax),
                1 => vcpu.reg(Reg::Rcx),
                2 => vcpu.reg(Reg::Rdx),
                3 => vcpu.reg(Reg::Rbx),
                4 => return None, // RSP — not a valid APIC write source
                5 => vcpu.reg(Reg::Rbp),
                6 => vcpu.reg(Reg::Rsi),
                7 => vcpu.reg(Reg::Rdi),
                8 => vcpu.reg(Reg::R8),
                9 => vcpu.reg(Reg::R9),
                10 => vcpu.reg(Reg::R10),
                11 => vcpu.reg(Reg::R11),
                12 => vcpu.reg(Reg::R12),
                13 => vcpu.reg(Reg::R13),
                14 => vcpu.reg(Reg::R14),
                15 => vcpu.reg(Reg::R15),
                _ => return None,
            };
            Some(val as u32)
        }
        0xC7 => {
            // MOV r/m32, imm32: immediate follows ModRM (+SIB+disp)
            let modrm = buf[i];
            i += 1;
            let md = modrm >> 6;
            let rm = modrm & 0x7;
            // Skip SIB byte if present
            if md != 3 && rm == 4 {
                i += 1;
            }
            // Skip displacement
            match md {
                0 => {
                    if rm == 5 {
                        i += 4;
                    }
                }
                1 => {
                    i += 1;
                }
                2 => {
                    i += 4;
                }
                _ => {}
            }
            if i + 4 > avail {
                return None;
            }
            let imm = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
            Some(imm)
        }
        _ => None,
    }
}
