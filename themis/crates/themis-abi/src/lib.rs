//! Themis hypercall ABI — shared between the capavisor and guest software.
//!
//! This crate is `no_std` so it can be linked into the bare-metal capavisor,
//! a Linux kernel module (`themis-vmm.ko`), and userspace VMMs alike.
//!
//! # Register convention (System V AMD64-style)
//!
//! ```text
//! IN:   RAX = opcode
//!       RDI = arg0,  RSI = arg1,  RDX = arg2,  RCX = arg3,  R8 = arg4
//!
//! OUT:  RAX = error code (0 = SUCCESS, see `errors` module)
//!       RDI = result0,  RSI = result1,  RDX = result2
//! ```

#![no_std]

// ── Hypercall opcodes (RAX) ──────────────────────────────────────────────── //

pub mod opcodes {
    /// Carve an exclusive sub-region from a parent memory capability.
    /// IN:  RDI = parent_handle, RSI = start, RDX = size, RCX = rights
    /// OUT: RDI = new_handle, RSI = sub_handle
    pub const THEMIS_CARVE: u64 = 0x01;

    /// Alias a shared sub-region from a parent memory capability.
    /// IN:  RDI = parent_handle, RSI = start, RDX = size, RCX = rights
    /// OUT: RDI = new_handle, RSI = sub_handle
    pub const THEMIS_ALIAS: u64 = 0x02;

    /// Send a capability to a receiver domain or channel.
    /// IN: RDI = cap_handle, RSI = receiver_handle, RDX = attributes.
    /// RCX = memory GPA hint (u64::MAX = none; required for endpoints).
    pub const THEMIS_SEND: u64 = 0x03;

    /// Accept a pending capability, independent of its type.
    /// IN:  RDI = pending_id
    /// OUT: RDI = new_handle
    pub const THEMIS_ACCEPT: u64 = 0x04;

    /// Reject a pending capability, independent of its type.
    /// IN:  RDI = pending_id
    pub const THEMIS_REJECT: u64 = 0x05;

    /// Create a new child domain.
    /// IN:  RDI = cores_bitmask, RSI = api_flags, RDX = num_vps
    /// OUT: RDI = domain_handle
    pub const THEMIS_CREATE_DOMAIN: u64 = 0x06;

    /// Seal a domain (transition Unsealed → Sealed).
    /// IN:  RDI = domain_handle
    pub const THEMIS_SEAL: u64 = 0x07;

    /// Revoke a tree child. RDI = parent_handle (u64::MAX = self domain),
    /// RSI = child_sub_handle. RSI = 0 revokes the owned child domain
    /// named by RDI directly; this does not destroy a held endpoint.
    pub const THEMIS_REVOKE: u64 = 0x08;

    // 0x09 retired: child-domain destruction uses REVOKE(handle, 0).

    /// Switch to a target domain's VP (or return to caller).
    /// IN:  RDI = target_domain_handle (0 = return), RSI = target_vp_id
    pub const THEMIS_SWITCH: u64 = 0x0A;

    /// Get a channel capability to a domain.
    /// IN:  RDI = domain_handle (0 = self-channel, for receiving from children)
    /// OUT: RDI = channel_handle
    pub const THEMIS_GET_CHAN: u64 = 0x0B;

    /// Attest the current domain (self-attestation).
    /// OUT: RDI = hash_lo, RSI = hash_hi  (first 16 bytes of SHA-256)
    pub const THEMIS_ATTEST_SELF: u64 = 0x0C;

    /// Attest another domain (remote attestation).
    /// IN:  RDI = domain_handle
    /// OUT: RDI = hash_lo, RSI = hash_hi
    pub const THEMIS_ATTEST: u64 = 0x0D;

    /// Read a VP register from a child domain.
    /// IN:  RDI = domain_handle, RSI = vp_id, RDX = register_id
    /// OUT: RDI = value
    pub const THEMIS_GET_REG: u64 = 0x0E;

    /// Write a VP register of a child domain.
    /// IN:  RDI = domain_handle, RSI = vp_id, RDX = register_id, RCX = value
    pub const THEMIS_SET_REG: u64 = 0x0F;

    /// Assign a PCI device to a domain.
    /// IN:  RDI = domain_handle, RSI = pci_bdf
    pub const THEMIS_ASSIGN_DEVICE: u64 = 0x12;

    /// Release a PCI device from its assigned domain, returning it to dom0 passthrough.
    /// IN:  RDI = pci_bdf
    pub const THEMIS_RELEASE_DEVICE: u64 = 0x1a;

    /// Find a pending offer, independent of type.
    /// IN: RDI = inclusive starting pending ID (0 for first).
    /// OUT: RDI = pending ID, RSI = found (0 or 1).
    /// Continue with the previous returned ID + 1.
    pub const THEMIS_ENUMERATE: u64 = 0x13;

    /// Add a virtual processor to a child domain.
    /// IN:  RDI = child_domain_handle, RSI = comm_cap_handle, RDX = vp_index
    pub const THEMIS_ADD_VP: u64 = 0x14;

    // 0x15–0x17 retired: address registration and global notification vector.

    /// Register a COMM page owned by the caller, bound to a child VP.
    /// IN:  RDI = mem_cap_handle, RSI = child_domain_handle, RDX = vp_id
    ///
    /// SELF_CAPABILITY + vp_id=u32::MAX registers the caller's own DomainComm
    /// backing. Initial child DomainComm pages use SEND with COMM instead.
    pub const THEMIS_REGISTER_COMM: u64 = 0x18;

    /// Notify the capavisor to process the caller's DomainComm TX ring.
    /// IN:  (no arguments)
    /// A GROW request completes synchronously: RDI = new backing page count,
    /// RSI = new power-of-two byte capacity. Failure does not adopt its pages.
    /// The caller prepares local mappings and serializes all ring access across
    /// this exchange. Requires CPUID DOMCOMM_SYNC_GROW.
    pub const THEMIS_DOMCOMM_NOTIFY: u64 = 0x19;

    /// Inject a virtual interrupt into a VP of a child domain.
    /// IN:  RDI = child_domain_handle, RSI = vp_id, RDX = vector (0–255)
    /// The VP must be stopped (not currently running via SWITCH).
    pub const THEMIS_INJECT_INTERRUPT: u64 = 0x1b;

    /// Debug print: emit a serial trace message from any domain.
    /// IN:  RDI = 64-bit value to print.  No capability check needed.
    pub const THEMIS_DBG_PRINT: u64 = 0x1c;

    /// Toggle runtime debug logging.
    /// IN:  RDI = 1 (enable) or 0 (disable).  No capability check needed.
    pub const THEMIS_TOGGLE_DEBUG: u64 = 0x1d;

    /// Read a TPM PCR value (capavisor-mediated, read-only).
    /// IN:  RDI = pcr_index
    /// OUT: signed attestation report delivered via DomainComm RX ring;
    ///      RDI = report size in bytes (0 if TPM not available)
    pub const THEMIS_READ_PCR: u64 = 0x1e;

    /// Remap a memory capability at a new GPA within the caller's address space.
    /// IN:  RDI = cap_handle (local handle of the capability to remap)
    ///      RSI = new_gpa (target GPA; must not overlap other mapped regions)
    /// OUT: RAX = error code (0 on success)
    pub const THEMIS_MAP_SELF: u64 = 0x1f;

    // 0x20/0x21 retired: endpoint ownership uses SEND/ACCEPT.

    /// Unified policy-setting hypercall — maps directly to
    /// `Capability::set_policy(&caller, child_handle, PolicyIdentifier, value)`.
    ///
    /// IN:  RDI = child_domain_handle
    ///      RSI = policy selector (kind plus optional VP index; see `policy_kind`)
    ///      RDX = key (vector for interrupt variants, exit_reason for exit variants, 0 otherwise)
    ///      RCX = sub_key (word_index for register bitmap variants, 0 otherwise)
    ///      R8  = value
    pub const THEMIS_SET_POLICY: u64 = 0x22;

    // 0x23 retired: address-matching doorbell invocation.

    /// Create an immutable doorbell for self or an owned unsealed child.
    /// IN: RDI = child handle (u64::MAX = self), RSI = vector,
    /// RDX = kind (0 = Sync, 1 = Async), RCX = VP (0 for Sync).
    /// OUT: RDI = holder-local capability handle, RSI = recipient-tree port.
    pub const THEMIS_CREATE_DOORBELL: u64 = 0x24;

    /// Notify through a held doorbell capability.
    /// IN: RDI = capability handle, RSI = opaque value.
    /// Sync also returns the donated CPU through interrupt unwind.
    pub const THEMIS_NOTIFY: u64 = 0x25;
}

/// Synthetic exit reasons (high bit set to distinguish from VMX hardware exits).
pub mod synthetic_exits {
    // 0x8000_0001 is reserved (retired address-matched doorbell exit).

    /// Parent's callee (a descendant domain) was revoked.  The capavisor
    /// walked the caller chain, found this domain as the first non-revoked
    /// ancestor of the running doomed VP, and switched execution back here.
    /// The parent's SWITCH VMCALL sees this in rdi and observes that its
    /// callee is gone; the callee handle in its capability tree is also
    /// no longer valid.
    pub const THEMIS_EXIT_CALLEE_REVOKED: u32 = 0x8000_0002;

    /// Child voluntarily returned its donated CPU via SWITCH(0).
    pub const THEMIS_EXIT_YIELD: u32 = 0x8000_0003;
}

/// Maximum number of VPs that may be created in a single Themis domain.
///
/// This is the cap enforced by the capavisor; thhv's partition-create
/// ioctl rejects larger requests with `-EINVAL`, and the cloud-hypervisor
/// Themis backend advertises the same value via `Hypervisor::get_max_vcpus`.
/// Mirrored as `THHV_MAX_VPS_PER_DOMAIN` in `<thhv/inc/thhv.h>`; the two
/// definitions must agree.
pub const MAX_VPS_PER_DOMAIN: u32 = 256;

/// Policy-kind discriminants for `THEMIS_SET_POLICY`.
///
/// Each constant maps 1:1 to a `PolicyIdentifier` variant in the capability engine.
pub mod policy_kind {
    pub const CORES: u64 = 0;
    pub const API_MONITOR: u64 = 1;
    pub const DEFAULT_INTR_VISIBILITY: u64 = 2;
    pub const VECTOR_VISIBILITY: u64 = 3;
    pub const VECTOR_REG_READ_SET: u64 = 4;
    pub const VECTOR_REG_WRITE_SET: u64 = 5;
    pub const DEFAULT_EXIT_TRAP: u64 = 6;
    pub const EXIT_REASON_TRAP: u64 = 7;
    pub const EXIT_REASON_REG_READ_SET: u64 = 8;
    pub const EXIT_REASON_REG_WRITE_SET: u64 = 9;

    // CPUID interposition (ResourceKind::Cpuid)
    pub const CPUID_DEFAULT: u64 = 10;
    pub const CPUID_RANGE: u64 = 11;
    pub const CPUID_EMULATE: u64 = 12;

    // MSR interposition (ResourceKind::Msr)
    pub const MSR_DEFAULT: u64 = 13;
    pub const MSR_RANGE: u64 = 14;
    pub const MSR_EMULATE: u64 = 15;

    /// Per-vector explicit-injection permission (`THEMIS_INJECT_INTERRUPT`),
    /// independent of `VECTOR_VISIBILITY`. See `VectorPolicy::injectable`.
    pub const VECTOR_INJECTABLE: u64 = 16;
    pub const DEFAULT_INTR_REG_READ_SET: u64 = 17;
    pub const DEFAULT_INTR_REG_WRITE_SET: u64 = 18;
    pub const DEFAULT_EXIT_REG_READ_SET: u64 = 19;
    pub const DEFAULT_EXIT_REG_WRITE_SET: u64 = 20;
    pub const DEFAULT_VECTOR_INJECTABLE: u64 = 21;
    /// Emulate inclusive ranges: key=start, sub_key=end, value=packed result word.
    /// CPUID endpoints pack `(leaf << 32) | subleaf`; MSR endpoints are u32.
    /// Selector bit 16 selects result word 0/1, independently of VP scope.
    pub const CPUID_EMULATE_RANGE: u64 = 22;
    pub const MSR_EMULATE_RANGE: u64 = 23;
    const EMULATE_WORD_BIT: u64 = 1 << 16;

    /// On a VP-scoped category default, restore domain-default inheritance.
    pub const INHERIT: u64 = u64::MAX;

    /// The low word selects the existing policy kind. The high word is zero
    /// for domain defaults, or VP index + 1. Capability handles stay full-width.
    pub fn for_vp(kind: u64, vp_index: u32) -> Option<u64> {
        let (_, vp, _) = decode(kind)?;
        if vp.is_some() || vp_index >= super::MAX_VPS_PER_DOMAIN {
            return None;
        }
        Some(kind | ((u64::from(vp_index) + 1) << 32))
    }

    pub fn with_emulate_word(selector: u64, word: u8) -> Option<u64> {
        let (kind, _, _) = decode(selector)?;
        if !matches!(kind, CPUID_EMULATE_RANGE | MSR_EMULATE_RANGE) || word > 1 {
            return None;
        }
        Some((selector & !EMULATE_WORD_BIT) | (u64::from(word) << 16))
    }

    pub fn decode(selector: u64) -> Option<(u64, Option<u32>, u8)> {
        let kind = selector & u64::from(u32::MAX) & !EMULATE_WORD_BIT;
        let word = u8::from(selector & EMULATE_WORD_BIT != 0);
        let vp = selector >> 32;
        if kind > MSR_EMULATE_RANGE
            || vp > u64::from(super::MAX_VPS_PER_DOMAIN)
            || (word != 0 && !matches!(kind, CPUID_EMULATE_RANGE | MSR_EMULATE_RANGE))
        {
            return None;
        }
        Some((
            kind,
            if vp == 0 { None } else { Some((vp - 1) as u32) },
            word,
        ))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn policy_selection_preserves_kind_and_optional_vp() {
            for kind in 0..=MSR_EMULATE_RANGE {
                assert_eq!(decode(kind), Some((kind, None, 0)));
                for vp in [0, super::super::MAX_VPS_PER_DOMAIN - 1] {
                    assert_eq!(decode(for_vp(kind, vp).unwrap()), Some((kind, Some(vp), 0)));
                }
            }
            assert_eq!(for_vp(MSR_EMULATE_RANGE + 1, 0), None);
            assert_eq!(
                for_vp(CPUID_EMULATE, super::super::MAX_VPS_PER_DOMAIN),
                None
            );
            assert_eq!(decode(u64::MAX), None);
            assert_eq!(decode((257 << 32) | CPUID_DEFAULT), None);
        }

        #[test]
        fn emulate_word_and_vp_selection_are_independent_and_strict() {
            for kind in [CPUID_EMULATE_RANGE, MSR_EMULATE_RANGE] {
                for word in 0..2 {
                    let selector = with_emulate_word(kind, word).unwrap();
                    assert_eq!(decode(selector), Some((kind, None, word)));
                    let scoped = for_vp(selector, 255).unwrap();
                    assert_eq!(decode(scoped), Some((kind, Some(255), word)));
                    assert_eq!(
                        with_emulate_word(for_vp(kind, 255).unwrap(), word),
                        Some(scoped)
                    );
                }
                assert_eq!(with_emulate_word(kind, 2), None);
                assert_eq!(decode(kind | (1 << 17)), None);
            }
            assert_eq!(with_emulate_word(CPUID_EMULATE, 1), None);
            assert_eq!(decode(CPUID_EMULATE | EMULATE_WORD_BIT), None);
            assert_eq!(for_vp(for_vp(CPUID_EMULATE_RANGE, 0).unwrap(), 1), None);
        }
    }
}

// ── REGISTER_COMM vp_id sentinel ──────────────────────────────────────────── //

// ── Hypercall return codes (RAX on return) ───────────────────────────────── //

pub mod errors {
    pub const SUCCESS: u64 = 0;
    pub const ERR_INVALID: u64 = 1;
    pub const ERR_NOPERM: u64 = 2;
    pub const ERR_NOMEM: u64 = 3;
    pub const ERR_BADSTATE: u64 = 4;
    pub const ERR_NOTFOUND: u64 = 5;
    pub const ERR_BUSY: u64 = 6;
    /// Child VP was preempted by a physical interrupt; caller should retry SWITCH.
    pub const ERR_RETRY: u64 = 7;
    /// TX ring message sequence mismatch (concurrent attestation race).
    pub const ERR_RACE: u64 = 8;
    pub const ERR_UNIMPL: u64 = u64::MAX;
}

// ── VP register profile ───────────────────────────────────────────────────── //
//
// `VpGpRegs`, `VpSregs`, `SegmentReg`, `DescriptorTableReg`, and `VpRegister`
// are defined in the `regs` submodule and re-exported here for convenience.

pub mod regs;

pub mod vmx_exit_reasons;

pub mod domcomm;

pub mod pv;

// ── Themis hypervisor CPUID discovery ──────────────────────────────────────── //
//
// These constants define the CPUID leaf layout for discovering the Themis
// hypervisor and its features.  Used by both Eunomia (bare-metal guest) and
// Linux CoCo support (kernel driver) to detect and interact with Themis.

pub mod cpuid {
    /// Base leaf: signature + max supported leaf.
    /// EAX = max leaf (currently 0x40000004).
    /// EBX:ECX:EDX = "ThemisCapa  " (12-byte signature).
    pub const LEAF_BASE: u32 = 0x4000_0000;

    /// Feature flags leaf.
    /// EAX = feature bitmap (see `feature_bits` below).
    pub const LEAF_FEATURES: u32 = 0x4000_0001;

    /// Bits returned in EAX of `LEAF_FEATURES`.  Each bit advertises one
    /// optional capability of the capavisor; guests MUST check the bit
    /// before using the associated mechanism.  New bits MUST be appended;
    /// existing bits MUST NOT be repurposed.
    pub mod feature_bits {
        /// Capavisor supports the sync-switch scheduling model.  Always
        /// set in the current build — kept as a stable bit for guests
        /// that want to assert it.
        pub const FEATURE_SYNC_SWITCH: u32 = 1 << 0;

        // Bit 1 is reserved (retired address-matched doorbell VMCALL).

        /// Capavisor advertises hardware x2APIC virtualization support
        /// to children — VIRTUALIZE_X2APIC_MODE (bit 4), APIC_REGISTER_VIRT
        /// (bit 8) and Virtual-Interrupt-Delivery (bit 9) are all settable
        /// in `IA32_VMX_PROCBASED_CTLS2`.  When this bit is clear the
        /// nested host (typically KVM-as-L0) does not expose the controls,
        /// and parents (CHV) must keep children in xAPIC mode — pushing
        /// x2APIC MSR ranges or `IA32_APIC_BASE.EXTD` would let the guest
        /// switch to x2APIC ops while hardware delivers no virtualization,
        /// causing `#GP` on RDMSR of any x2APIC register.
        pub const FEATURE_X2APIC_VIRT: u32 = 1 << 2;

        /// Immutable doorbell capabilities with CREATE_DOORBELL (0x24)
        /// and NOTIFY (0x25), using ordinary capability ownership operations.
        pub const FEATURE_CAPABILITY_DOORBELLS: u32 = 1 << 3;
    }

    /// DomainComm discovery (alias for domcomm::CPUID_DOMCOMM_LEAF).
    /// EAX:EBX = base GPA (lo:hi), ECX = size in pages.
    pub const LEAF_DOMCOMM: u32 = 0x4000_0002;
    /// EDX feature bits on DomainComm discovery. Subleaf N+1 locates page N.
    pub const DOMCOMM_PAGE_LIST: u32 = 1 << 0;
    /// GROW completion is returned by DOMCOMM_NOTIFY in RDI/RSI (pages/capacity).
    pub const DOMCOMM_SYNC_GROW: u32 = 1 << 1;

    /// Capacity limits.
    /// EAX = max VPs, EBX = max partitions, ECX = max memory regions.
    pub const LEAF_LIMITS: u32 = 0x4000_0003;

    /// ivshmem device discovery (per-device subleaf).
    /// Subleaf N describes ivshmem device N.
    /// EAX = BAR0 GPA (32-bit MMIO, doorbell registers).
    /// EBX = total number of ivshmem devices.
    /// ECX = BAR2 GPA low 32 bits (shared data region).
    /// EDX = BAR2 GPA high 32 bits.
    pub const LEAF_IVSHMEM: u32 = 0x4000_0004;

    /// PV descriptor locator: EAX:EBX = GPA low:high, ECX = bytes, EDX = version.
    pub const LEAF_PV: u32 = 0x4000_0005;
    /// Native current-VP identity: EAX = VP index, EBX/ECX = 0, EDX = PV version.
    pub const PV_SUBLEAF_IDENTITY: u32 = 1;

    /// Expected signature bytes in EBX:ECX:EDX of LEAF_BASE.
    pub const SIG_EBX: u32 = u32::from_le_bytes(*b"Them");
    pub const SIG_ECX: u32 = u32::from_le_bytes(*b"isCa");
    pub const SIG_EDX: u32 = u32::from_le_bytes(*b"pa  ");

    /// Check CPUID leaf 0x40000000 for the Themis signature.
    /// Returns `true` if the hypervisor identifies as Themis.
    ///
    #[cfg(target_arch = "x86_64")]
    pub fn is_themis() -> bool {
        let result = core::arch::x86_64::__cpuid(LEAF_BASE);
        result.ebx == SIG_EBX && result.ecx == SIG_ECX && result.edx == SIG_EDX
    }
}

pub use regs::{DescriptorTableReg, SegmentReg, VpCommPage, VpGpRegs, VpRegister, VpSregs};

// ── META VP-state page layout (Phase 10) ────────────────────────────────── //
//
// Placed here so both capavisor and the themis-vmm.ko driver share the exact
// same struct layout without a copy.  Defined as a raw layout constant for
// now; a full `#[repr(C)] struct VpStateMeta` will replace this in Phase 10.
//
// Offset 0x000 – 0x0BF: GP registers + RIP/RSP/RFLAGS/CR0/CR3/CR4/EFER
// Offset 0x0C0 – 0x0C7: exit_reason (u32) + exit_qualification (u64)
// Offset 0x0C8 – 0x0CB: dirty bitmask (atomic u32)
// Offset 0x0CC – 0x0CF: status flags (PENDING_IRQ | RESUME_WITH_IRQ | RESUME_NO_IRQ)
// Offset 0x100 – 0x13F: PostedInterruptDescriptor (64 B, 64 B-aligned)
// Remainder: reserved / zero

pub mod meta {
    pub const DIRTY_GPR: u32 = 1 << 0;
    pub const DIRTY_CR: u32 = 1 << 1;
    pub const DIRTY_RIP: u32 = 1 << 2;
    pub const DIRTY_RSP: u32 = 1 << 3;

    pub const STATUS_PENDING_IRQ: u32 = 1 << 0;
    pub const STATUS_RESUME_WITH_IRQ: u32 = 1 << 1;
    pub const STATUS_RESUME_NO_IRQ: u32 = 1 << 2;

    /// Byte offset of the PostedInterruptDescriptor within VpStateMeta page.
    pub const PI_DESC_OFFSET: usize = 0x100;
    /// Size of a VpStateMeta page.
    pub const META_PAGE_SIZE: usize = 4096;
}
