/* SPDX-License-Identifier: GPL-2.0 */
/*
 * thhv.h — UAPI header for the thhv kernel module.
 *
 * Exposes /dev/thhv with an ioctl ABI compatible with Microsoft's THHV driver,
 * backed by Themis capability operations (VMCALLs).
 *
 * Three-level fd hierarchy:
 *   /dev/thhv       (device fd)   — THHV_CREATE_PARTITION, THHV_CHECK_EXTENSION
 *     └─ partition fd             — THHV_CREATE_VP, THHV_SET_GUEST_MEMORY, ...
 *          └─ vp fd               — THHV_RUN_VP, THHV_GET/SET_VP_STATE, mmap()
 */

#ifndef _THHV_H
#define _THHV_H

#include <linux/types.h>
#include <linux/ioctl.h>
#include <linux/poll.h>

/* ── THHV ioctl magic ──────────────────────────────────────────────────────── */

#define THHV_IOCTL_MAGIC  0xB8

/* ── CPUID detection ───────────────────────────────────────────────────────── */

#define THHV_CPUID_LEAF       0x40000000
#define THHV_CPUID_MAX_LEAF   0x40000003
#define THHV_CPUID_FEAT_LEAF  0x40000001
#define THHV_CPUID_DOMCOMM_LEAF 0x40000002  /* DomainComm discovery (EAX:EBX=GPA, ECX=nr_pages) */
#define THHV_CPUID_CAP_LEAF   0x40000003

/* Expected vendor string: "ThemisCapa" in EBX:ECX:EDX (little-endian u32s). */
#define THHV_SIG_EBX  0x6d656854  /* "Them" */
#define THHV_SIG_ECX  0x61437369  /* "isCa" */
#define THHV_SIG_EDX  0x20206170  /* "pa  " */

/* Feature flags (leaf 0x40000001, EAX). */
#define THHV_FEAT_SYNC_SCHED   (1U << 0)
#define THHV_FEAT_ASYNC_SCHED  (1U << 1)
#define THHV_FEAT_META_PAGES   (1U << 2)
#define THHV_FEAT_THEMIC       (1U << 3)
#define THHV_FEAT_DEVICE_ASSIGN (1U << 4)

/* ── Scheduling policy (Themis extension to create_partition) ──────────────── */

#define THHV_SCHED_SYNC   0
#define THHV_SCHED_ASYNC  1

/* META pages the capavisor needs per VP (VMCS + VAPIC). */
#define THHV_META_PAGES_PER_VP  3

/* ── Themis hypercall opcodes (RAX) ────────────────────────────────────────── */

#define THEMIS_HC_CARVE              0x01
#define THEMIS_HC_ALIAS              0x02
#define THEMIS_HC_SEND               0x03
#define THEMIS_HC_ACCEPT             0x04
#define THEMIS_HC_REJECT             0x05
#define THEMIS_HC_CREATE_DOMAIN      0x06
#define THEMIS_HC_SEAL               0x07
#define THEMIS_HC_REVOKE_MEM         0x08
#define THEMIS_HC_REVOKE_DOMAIN      0x09
#define THEMIS_HC_SWITCH             0x0A
#define THEMIS_HC_GET_CHAN            0x0B
#define THEMIS_HC_ATTEST_SELF        0x0C
#define THEMIS_HC_ATTEST             0x0D
#define THEMIS_HC_GET_REG            0x0E
#define THEMIS_HC_SET_REG            0x0F
#define THEMIS_HC_SET_INTR_POLICY    0x10
#define THEMIS_HC_SET_DEF_INTR_POLICY 0x11
#define THEMIS_HC_ASSIGN_DEVICE      0x12
#define THEMIS_HC_ENUMERATE          0x13
#define THEMIS_HC_ADD_VP             0x14
#define THEMIS_HC_REGISTER_DOORBELL  0x15
#define THEMIS_HC_UNREGISTER_DOORBELL 0x16
#define THEMIS_HC_SET_THEMIC_VECTOR  0x17
#define THEMIS_HC_REGISTER_COMM      0x18
#define THEMIS_HC_INJECT_INTERRUPT   0x1b

/* ── Themis hypercall opcodes (RAX in) ─────────────────────────────────────── */

#define THEMIS_OP_CARVE               0x01
#define THEMIS_OP_ALIAS               0x02
#define THEMIS_OP_SEND                0x03
#define THEMIS_OP_ACCEPT              0x04
#define THEMIS_OP_REJECT              0x05
#define THEMIS_OP_CREATE_DOMAIN       0x06
#define THEMIS_OP_SEAL                0x07
#define THEMIS_OP_REVOKE_MEM          0x08
#define THEMIS_OP_REVOKE_DOMAIN       0x09
#define THEMIS_OP_SWITCH              0x0A
#define THEMIS_OP_GET_CHAN             0x0B
#define THEMIS_OP_ATTEST_SELF         0x0C
#define THEMIS_OP_ATTEST              0x0D
#define THEMIS_OP_GET_REG             0x0E
#define THEMIS_OP_SET_REG             0x0F
#define THEMIS_OP_SET_INTR_POLICY     0x10
#define THEMIS_OP_SET_DEF_INTR_POLICY 0x11
#define THEMIS_OP_ASSIGN_DEVICE       0x12
#define THEMIS_OP_ENUMERATE           0x13
#define THEMIS_OP_ADD_VP              0x14
#define THEMIS_OP_REGISTER_DOORBELL   0x15
#define THEMIS_OP_UNREGISTER_DOORBELL 0x16
#define THEMIS_OP_SET_THEMIC_VECTOR   0x17
#define THEMIS_OP_REGISTER_COMM       0x18
#define THEMIS_OP_DOMCOMM_NOTIFY     0x19
#define THEMIS_OP_INJECT_INTERRUPT   0x1b

/* ── Themis hypercall return codes (RAX) ───────────────────────────────────── */

#define THEMIS_SUCCESS       0
#define THEMIS_ERR_INVALID   1
#define THEMIS_ERR_NOPERM    2
#define THEMIS_ERR_NOMEM     3
#define THEMIS_ERR_BADSTATE  4
#define THEMIS_ERR_NOTFOUND  5
#define THEMIS_ERR_BUSY      6
/* Child VP was preempted by a physical interrupt; caller should retry SWITCH. */
#define THEMIS_ERR_RETRY     7
#define THEMIS_ERR_UNIMPL    (~0ULL)

/*
 * Raw VMCALL primitive — 5 inputs, 3 outputs.
 *
 * Register convention (matches themis_abi):
 *   IN:  RAX = opcode, RDI = a0, RSI = a1, RDX = a2, RCX = a3, R8 = a4
 *   OUT: RAX = status,  RDI = r0, RSI = r1, RDX = r2
 */
static inline u64 __themis_vmcall(u64 opcode,
				  u64 a0, u64 a1, u64 a2, u64 a3, u64 a4,
				  u64 *r0, u64 *r1, u64 *r2)
{
	u64 status, o0, o1, o2;

	register u64 _a4 asm("r8") = a4;

	asm volatile("vmcall"
		: "=a"(status), "=D"(o0), "=S"(o1), "=d"(o2)
		: "a"(opcode), "D"(a0), "S"(a1), "d"(a2),
		  "c"(a3), "r"(_a4)
		: "r9", "r10", "r11", "memory", "cc"
	);

	if (r0) *r0 = o0;
	if (r1) *r1 = o1;
	if (r2) *r2 = o2;
	return status;
}

/* Map Themis return code to negative errno. */
static inline int __themis_to_errno(u64 status)
{
	switch (status) {
	case THEMIS_SUCCESS:      return 0;
	case THEMIS_ERR_INVALID:  return -EINVAL;
	case THEMIS_ERR_NOPERM:   return -EPERM;
	case THEMIS_ERR_NOMEM:    return -ENOMEM;
	case THEMIS_ERR_BADSTATE: return -EBUSY;
	case THEMIS_ERR_NOTFOUND: return -ENOENT;
	case THEMIS_ERR_RETRY:    return -EAGAIN;
	case THEMIS_ERR_UNIMPL:   return -ENOSYS;
	default:                  return -EIO;
	}
}

/* ── UAPI structures ──────────────────────────────────────────────────────── */

struct thhv_create_partition {
	__u64 cores_mask;     /* Allowed physical cores (bitmap); ~0 = all */
	__u64 api_flags;      /* Allowed monitor API calls (MonitorAPI bits); ~0 = all */
	__u32 sched_policy;   /* THHV_SCHED_SYNC or THHV_SCHED_ASYNC */
	__u32 num_vps;        /* Number of VPs to allocate */
};

struct thhv_create_vp {
	__u32 vp_index;
	__u32 rsvd;
	__u64 meta_uaddr;     /* Userspace VA of META pages (query size first) */
	__u64 meta_size;      /* Size in bytes (must be PAGE_SIZE * META_PAGES_PER_VP) */
	__u64 comm_uaddr;     /* Userspace VA of COMM page (PAGE_SIZE) */
};

/* Guest physical address of the LAPIC MMIO window.  The capavisor maps the
 * apic_access page here so VIRTUALIZE_APIC_ACCESSES fires APIC_ACCESS exits
 * instead of EPT violations for child-domain LAPIC accesses.
 */
#define THHV_LAPIC_GPA	0xFEE00000ULL

struct thhv_initialize_partition {
	__u64 meta_uaddr;          /* Userspace VA of shared META pages */
	__u64 meta_size;           /* Size in bytes (must be PAGE_SIZE * META_PAGES_SHARED) */
	__u64 apic_access_uaddr;   /* Userspace VA of APIC-access sentinel page (PAGE_SIZE) */
	__u64 apic_access_size;    /* Must be PAGE_SIZE */
};

struct thhv_set_guest_memory {
	__u64 guest_pfn;       /* GPA >> 12 */
	__u64 userspace_addr;  /* Host VA (page-aligned) */
	__u64 size;            /* bytes (page-aligned) */
	__u32 flags;           /* THHV_MEM_F_* bitmask */
	__u32 rights;          /* THHV_MEM_R_* bitmask (R/W/X) */
	__u64 attrs;           /* THHV_MEM_A_* bitmask (HASH/CLEAN/VITAL/META) */
};

/* flags — operation type */
#define THHV_MEM_F_UNMAP     (1U << 0)  /* Unmap (revoke) instead of map */
#define THHV_MEM_F_ALIAS     (1U << 1)  /* Alias (shared) instead of carve (exclusive) */

/* rights — access permissions on the capability */
#define THHV_MEM_R_READ      (1U << 0)
#define THHV_MEM_R_WRITE     (1U << 1)
#define THHV_MEM_R_EXEC      (1U << 2)

/* attrs — capability attributes (set on SEND) */
#define THHV_MEM_A_HASH      (1U << 0)  /* Content is hashed/verified */
#define THHV_MEM_A_CLEAN     (1U << 1)  /* Zeroed on revocation */
#define THHV_MEM_A_VITAL     (1U << 2)  /* Revocation kills the domain */
#define THHV_MEM_A_META      (1U << 3)  /* Capavisor internal allocator (implies CLEAN+VITAL) */

struct thhv_reg_name_value {
	__u64 name;            /* VpRegister discriminant (THHV_VP_REG_*) */
	__u64 value;
};

struct thhv_vp_registers {
	__u32 count;
	__u32 rsvd;
	__u64 regs;            /* Userspace pointer to count × thhv_reg_name_value */
};

#define THHV_MAX_VP_REGS  128

/* ── VpRegister name constants (discriminants from themis-abi) ──────────────── */

/* General-purpose registers (0x00–0x0E) */
#define THHV_VP_REG_RAX       0x00
#define THHV_VP_REG_RBX       0x01
#define THHV_VP_REG_RCX       0x02
#define THHV_VP_REG_RDX       0x03
#define THHV_VP_REG_RSI       0x04
#define THHV_VP_REG_RDI       0x05
#define THHV_VP_REG_RBP       0x06
#define THHV_VP_REG_R8        0x07
#define THHV_VP_REG_R9        0x08
#define THHV_VP_REG_R10       0x09
#define THHV_VP_REG_R11       0x0A
#define THHV_VP_REG_R12       0x0B
#define THHV_VP_REG_R13       0x0C
#define THHV_VP_REG_R14       0x0D
#define THHV_VP_REG_R15       0x0E

/* Stack / instruction / flags (0x10–0x12) */
#define THHV_VP_REG_RSP       0x10
#define THHV_VP_REG_RIP       0x11
#define THHV_VP_REG_RFLAGS    0x12

/* Control registers (0x20–0x24) */
#define THHV_VP_REG_CR0       0x20
#define THHV_VP_REG_CR3       0x21
#define THHV_VP_REG_CR4       0x22
#define THHV_VP_REG_EFER      0x23
#define THHV_VP_REG_DR7       0x24

/* Segment selectors (0x30–0x37) */
#define THHV_VP_REG_CS_SEL    0x30
#define THHV_VP_REG_DS_SEL    0x31
#define THHV_VP_REG_ES_SEL    0x32
#define THHV_VP_REG_FS_SEL    0x33
#define THHV_VP_REG_GS_SEL    0x34
#define THHV_VP_REG_SS_SEL    0x35
#define THHV_VP_REG_TR_SEL    0x36
#define THHV_VP_REG_LDTR_SEL  0x37

/* Segment bases (0x40–0x47) */
#define THHV_VP_REG_CS_BASE   0x40
#define THHV_VP_REG_DS_BASE   0x41
#define THHV_VP_REG_ES_BASE   0x42
#define THHV_VP_REG_FS_BASE   0x43
#define THHV_VP_REG_GS_BASE   0x44
#define THHV_VP_REG_SS_BASE   0x45
#define THHV_VP_REG_TR_BASE   0x46
#define THHV_VP_REG_LDTR_BASE 0x47

/* Segment limits (0x50–0x57) */
#define THHV_VP_REG_CS_LIM    0x50
#define THHV_VP_REG_DS_LIM    0x51
#define THHV_VP_REG_ES_LIM    0x52
#define THHV_VP_REG_FS_LIM    0x53
#define THHV_VP_REG_GS_LIM    0x54
#define THHV_VP_REG_SS_LIM    0x55
#define THHV_VP_REG_TR_LIM    0x56
#define THHV_VP_REG_LDTR_LIM  0x57

/* Segment access rights (0x60–0x67) */
#define THHV_VP_REG_CS_AR     0x60
#define THHV_VP_REG_DS_AR     0x61
#define THHV_VP_REG_ES_AR     0x62
#define THHV_VP_REG_FS_AR     0x63
#define THHV_VP_REG_GS_AR     0x64
#define THHV_VP_REG_SS_AR     0x65
#define THHV_VP_REG_TR_AR     0x66
#define THHV_VP_REG_LDTR_AR   0x67

/* Descriptor table registers (0x70–0x73) */
#define THHV_VP_REG_GDTR_BASE  0x70
#define THHV_VP_REG_GDTR_LIM   0x71
#define THHV_VP_REG_IDTR_BASE  0x72
#define THHV_VP_REG_IDTR_LIM   0x73

/* SYSENTER MSRs (0x80–0x82) */
#define THHV_VP_REG_SYSENTER_CS  0x80
#define THHV_VP_REG_SYSENTER_ESP 0x81
#define THHV_VP_REG_SYSENTER_EIP 0x82

/* FS/GS/KernelGS MSRs (0x90–0x92) */
#define THHV_VP_REG_FS_BASE_MSR     0x90
#define THHV_VP_REG_GS_BASE_MSR     0x91
#define THHV_VP_REG_KERNEL_GS_BASE  0x92

/* APIC (0xA0–0xA2) */
#define THHV_VP_REG_APIC_BASE  0xA0
#define THHV_VP_REG_TPR        0xA1
#define THHV_VP_REG_PPR        0xA2

/* VMCS state (0xB0–0xB2) */
#define THHV_VP_REG_ACTIVITY_STATE         0xB0
#define THHV_VP_REG_INTERRUPTIBILITY_STATE 0xB1
#define THHV_VP_REG_PAT                   0xB2

/*
 * VP COMM page — shared between driver and capavisor for bulk register transfer.
 *
 * Layout must match themis-abi VpCommPage exactly (4096 bytes, #[repr(C)]).
 * The driver writes register values + sets dirty_mask bits; the capavisor
 * validates and applies them at SWITCH time.
 */
#define VP_COMM_MASK_WORDS  3

struct thhv_vp_comm_page {
	__u64 dirty_mask[VP_COMM_MASK_WORDS];     /* offset   0 */
	__u64 allowed_mask[VP_COMM_MASK_WORDS];   /* offset  24 */
	__u8  _hdr_pad[16];                       /* offset  48 */
	/* GPRs (offset 64) */
	__u64 rax, rbx, rcx, rdx, rsi, rdi, rbp;
	__u64 r8, r9, r10, r11, r12, r13, r14, r15;
	/* RSP / RIP / RFLAGS (offset 184) */
	__u64 rsp, rip, rflags;
	/* Control regs (offset 208) */
	__u64 cr0, cr3, cr4, efer, dr7;
	/* Segment selectors (offset 248) */
	__u16 cs_sel, ds_sel, es_sel, fs_sel, gs_sel, ss_sel, tr_sel, ldtr_sel;
	/* Segment bases (offset 264) */
	__u64 cs_base, ds_base, es_base, fs_base, gs_base, ss_base, tr_base, ldtr_base;
	/* Segment limits (offset 328) */
	__u32 cs_limit, ds_limit, es_limit, fs_limit, gs_limit, ss_limit, tr_limit, ldtr_limit;
	/* Segment access rights (offset 360) */
	__u32 cs_ar, ds_ar, es_ar, fs_ar, gs_ar, ss_ar, tr_ar, ldtr_ar;
	/* GDTR (offset 392) */
	__u64 gdtr_base;
	__u16 gdtr_limit;
	__u8  _gdtr_pad[6];
	/* IDTR (offset 408) */
	__u64 idtr_base;
	__u16 idtr_limit;
	__u8  _idtr_pad[6];
	/* SYSENTER (offset 424) */
	__u64 sysenter_cs, sysenter_esp, sysenter_eip;
	/* FS/GS MSRs (offset 448) */
	__u64 fs_base_msr, gs_base_msr, kernel_gs_base;
	/* APIC (offset 472) */
	__u64 apic_base, tpr, ppr;
	/* Activity (offset 496) */
	__u32 activity_state, interruptibility_state;
	__u64 pat;
	/* Padding to 4096 */
	__u8  _pad[3584];
} __packed;

/*
 * Set a dirty bit for register 'reg' (THHV_VP_REG_*) in the COMM page.
 */
static inline void thhv_comm_mark_dirty(struct thhv_vp_comm_page *comm, unsigned int reg)
{
	unsigned int word = reg / 64;
	unsigned int bit  = reg % 64;

	comm->dirty_mask[word] |= (1ULL << bit);
}

/*
 * Write a u64 register value to the COMM page field for 'reg' and mark dirty.
 * For selectors (u16) and limits/access-rights (u32), the caller writes
 * the value zero-extended to u64; the capavisor truncates on read.
 */
void thhv_comm_set_reg(struct thhv_vp_comm_page *comm, unsigned int reg, __u64 val);

/* ── ThemIC — Themis Message Interface for Cloud-Hypervisor ─────────────────── */
/*
 * ThemIC is the capability-aware notification system.  Three shared pages
 * per child VP carry structured messages between capavisor and parent:
 *   - Message Page (4 KiB): 16 × 256-byte channel slots
 *   - Event Flag Page (4 KiB): pending-bit bitmap per channel
 *   - Doorbell Table (4 KiB): GPA/datamatch fast-path entries
 *
 * A fourth page type — Domain Management Page — carries domain-wide
 * messages (attestation, PA map) not tied to a child VP.
 *
 * See 2026/docs/design/mshv_themis/mshv_themis.md §4 for full design.
 */

#define THEMIC_NUM_CHANNELS       16
#define THEMIC_MSG_SLOT_SIZE      256   /* bytes per slot */
#define THEMIC_MAX_DOORBELLS      128

/* Channel indices (slots in the message page). */
#define THEMIC_CHAN_INTERCEPT      0     /* VP exit / intercept messages */
#define THEMIC_CHAN_DOORBELL       1     /* Doorbell event notifications */
#define THEMIC_CHAN_IRQ_ACK        2     /* Interrupt injection acks */
/* 3–15 reserved */

/* Message types (in themic_message_header.message_type). */
#define THEMIC_MSG_NONE           0x0000
#define THEMIC_MSG_VP_INTERCEPT   0x0001  /* VP exit: IO, MMIO, CPUID, MSR, HLT, etc. */
#define THEMIC_MSG_DOORBELL       0x0002  /* Doorbell write detected */
#define THEMIC_MSG_IRQ_ACK        0x0003  /* Interrupt delivery acknowledged */
#define THEMIC_MSG_SHUTDOWN       0x0004  /* Domain shutdown / triple fault */

struct themic_message_header {
	__u32 message_type;           /* THEMIC_MSG_* */
	__u32 payload_size;           /* bytes of payload following header */
	__u64 sequence;               /* monotonic counter for ordering */
};

/*
 * Intercept message — written by capavisor to slot 0 on VP exit.
 * This is the canonical exit info format.  The driver copies it
 * directly into thhv_run_vp.msg_buf for userspace.
 *
 * Fields are a superset: not all are valid for every exit reason.
 * The exit_reason field carries the capavisor-translated exit reason
 * (may differ from raw VMX exit reasons).
 */
struct themic_intercept_message {
	struct themic_message_header header;
	__u32 exit_reason;            /* VMX / capavisor exit reason */
	__u32 instruction_length;
	__u64 exit_qualification;
	__u64 guest_physical_address;
	__u64 guest_rip;
	__u64 guest_rflags;
	/* I/O port intercept fields */
	__u16 port_number;
	__u8  access_size;            /* 1, 2, 4 */
	__u8  is_write;
	__u32 reserved;
	__u64 rax;                    /* I/O data */
	/* MMIO intercept fields */
	__u8  instruction_bytes[16];  /* faulting instruction for emulation */
	/* CPUID intercept fields */
	__u64 cpuid_rax, cpuid_rcx;
	/* MSR intercept fields */
	__u32 msr_number;
	__u32 rsvd2;
	__u64 msr_value;
};

struct themic_doorbell_message {
	struct themic_message_header header;
	__u32 doorbell_id;
	__u32 rsvd;
	__u64 gpa;
	__u64 value;
	__u32 size;
	__u32 rsvd2;
};

/* === Message Page === */

struct themic_message_page {
	union {
		struct {
			__u8 slot_data[THEMIC_MSG_SLOT_SIZE];
		} slots[THEMIC_NUM_CHANNELS];
	};
	/* 16 × 256 = 4096 bytes = 1 page */
};

/* === Event Flag Page === */

struct themic_event_flag_page {
	__u64 flags[THEMIC_NUM_CHANNELS];
	__u8  reserved[4096 - THEMIC_NUM_CHANNELS * 8];
};

/* === Doorbell Table === */

#define THEMIC_DOORBELL_FLAG_TRIGGER_ANY_VALUE  (1 << 0)
#define THEMIC_DOORBELL_FLAG_TRIGGER_SIZE_ANY   (1 << 1)
#define THEMIC_DOORBELL_FLAG_PIO                (1 << 2)

struct themic_doorbell_entry {
	__u64 gpa;
	__u64 datamatch;
	__u32 size;
	__u32 flags;                  /* THEMIC_DOORBELL_FLAG_* */
	__u32 doorbell_id;
	__u32 reserved;
};

struct themic_doorbell_table {
	__u32 count;
	__u32 capacity;
	struct themic_doorbell_entry entries[THEMIC_MAX_DOORBELLS];
};

/*
 * RUN_VP ioctl: on return, msg_buf contains a themic_intercept_message
 * (256 bytes = one message slot) copied from the ThemIC message page
 * slot 0 (THEMIC_CHAN_INTERCEPT).
 */
struct thhv_run_vp {
	__u8 msg_buf[THEMIC_MSG_SLOT_SIZE];
};

/* ── DomainComm — Domain-level Communication Region ─────────────────────────
 *
 * Bidirectional multi-page message ring between a domain and the capavisor.
 * Per-domain (not per-VP).  Used for attestation delivery, async VP exits,
 * interrupt events, ring growth, and capability enumeration.
 *
 * For dom0: pre-allocated by capavisor, discovered via CPUID leaf 0x40000002.
 * See thhv/docs/domain-comm-v0.2.md for the full design.
 */

#define DOMCOMM_MAGIC         0x444F4D43  /* "DOMC" */
#define DOMCOMM_VERSION_MAJOR 0
#define DOMCOMM_VERSION_MINOR 2

/* ── DomainComm message types ───────────────────────────────────────────────
 *
 * Messages never cross page boundaries.  When a message doesn't fit in the
 * remaining space of the current page, the producer writes a padding message
 * (type=0) and starts the real message at the top of the next page.
 */

/* Capavisor → Domain (RX ring) */
#define DOMCOMM_MSG_NONE          0x0000  /* padding / skip */
#define DOMCOMM_MSG_ATTEST        0x0001  /* Binary attestation report */
#define DOMCOMM_MSG_VP_EXIT       0x0002  /* Async VP exit notification */
#define DOMCOMM_MSG_IRQ_NOTIFY    0x0003  /* Interrupt delivery event */
#define DOMCOMM_MSG_DOMAIN_EVENT  0x0004  /* Child domain state change */
#define DOMCOMM_MSG_ERROR         0x0005  /* Error / backpressure signal */
#define DOMCOMM_MSG_GROW_ACK      0x0006  /* Ring growth acknowledged */
#define DOMCOMM_MSG_DOORBELL_NOTIFY 0x0007 /* Doorbell write (fast-path, child not stopped) */

/* Domain → Capavisor (TX ring) */
#define DOMCOMM_MSG_ATTEST_REQ    0x0100  /* Request (self-)attestation */
#define DOMCOMM_MSG_ACK           0x0101  /* Acknowledge RX message */
#define DOMCOMM_MSG_BULK_REG_SET  0x0102  /* Bulk register write */
#define DOMCOMM_MSG_GROW_RX       0x0103  /* Request RX ring growth */
#define DOMCOMM_MSG_GROW_TX       0x0104  /* Request TX ring growth */
#define DOMCOMM_MSG_ENUM_CAP      0x0105  /* Enumerate single capability */

/* ── DomainComm header flags ────────────────────────────────────────────── */
#define DOMCOMM_FLAG_RX_READY    (1U << 0)  /* RX ring has data */
#define DOMCOMM_FLAG_TX_READY    (1U << 1)  /* TX ring has data */

/* ── DomainComm ring metadata (embedded in header page) ─────────────────── */

struct domcomm_ring_meta {
	__u32 head;           /* Producer byte offset (mod capacity) */
	__u32 tail;           /* Consumer byte offset (mod capacity) */
	__u32 page_offset;    /* First ring page (1-based index within region) */
	__u32 page_count;     /* Number of pages backing this ring */
};

/*
 * DomainComm header — page 0 of the DomainComm region.
 *
 * All ring data (including attestation) is delivered as messages on
 * the rings.  No fixed data fields beyond metadata.
 */
struct domcomm_header {
	/* 0x000 */
	__u32 magic;                  /* DOMCOMM_MAGIC */
	__u16 version_major;
	__u16 version_minor;
	__u32 total_pages;            /* Pages in the region */
	__u32 flags;                  /* DOMCOMM_FLAG_* */

	/* 0x010 — RX ring metadata (capavisor → domain) */
	struct domcomm_ring_meta rx;

	/* 0x020 — TX ring metadata (domain → capavisor) */
	struct domcomm_ring_meta tx;

	/* 0x030 — Notification */
	__u32 notify_vector;          /* IDT vector for RX notifications */
	__u32 notify_flags;

	__u8  reserved[4096 - 0x038];
};

/* ── DomainComm message header (16 bytes, 8-byte aligned) ───────────────── */

struct domcomm_msg_header {
	__u32 message_type;           /* DOMCOMM_MSG_* */
	__u32 total_size;             /* Total incl. header (8-byte aligned) */
	__u64 sequence;               /* Monotonic counter */
};

#define DOMCOMM_MSG_HDR_SIZE   sizeof(struct domcomm_msg_header)  /* 16 */
#define DOMCOMM_MAX_PAYLOAD    (4096 - DOMCOMM_MSG_HDR_SIZE)     /* 4080 */

/* ── Binary attestation report (DOMCOMM_MSG_ATTEST payload) ─────────────── */

/* Attestation flags */
#define DOMCOMM_ATTEST_F_SEALED  (1U << 0)

/*
 * Memory capability entry — one per owned memory capability.
 * The driver uses handle + hpa_start + size for CARVE/SEND arguments.
 * The gpa_start + hpa_start pair populates the PA map for translation.
 */
struct domcomm_mem_cap_entry {
	__u64 handle;                 /* Local handle in domain's table */
	__u64 gpa_start;              /* Guest Physical Address start */
	__u64 size;                   /* Range size in bytes */
	__u32 rights;                 /* Access rights (R/W/X bitmask) */
	__u32 attributes;             /* Capability attributes (COMM, META, etc.) */
	__u64 hpa_start;              /* Host Physical Address start */
};  /* 40 bytes */

/* Domain capability entry — one per owned child domain capability. */
struct domcomm_dom_cap_entry {
	__u64 handle;                 /* Local handle in domain's table */
	__u64 domain_id;              /* Target domain ID */
};  /* 16 bytes */

/* PA map entry — one per GPA→HPA translation range. */
struct domcomm_pa_map_entry {
	__u64 gpa_start;              /* Guest Physical Address start */
	__u64 hpa_start;              /* Host Physical Address start */
	__u64 size;                   /* Range size in bytes */
};  /* 24 bytes */

/*
 * Binary attestation report header.
 *
 * Variable-length: the header is followed by three arrays packed
 * contiguously: mem_caps[], dom_caps[], pa_map[].
 *
 * Total payload size = sizeof(domcomm_attest_report)
 *                    + nr_mem_caps * sizeof(domcomm_mem_cap_entry)
 *                    + nr_dom_caps * sizeof(domcomm_dom_cap_entry)
 *                    + nr_pa_entries * sizeof(domcomm_pa_map_entry)
 *
 * If the total exceeds DOMCOMM_MAX_PAYLOAD (4080 bytes), the report
 * is split across multiple DOMCOMM_MSG_ATTEST messages.  Each chunk
 * carries a chunk_index/total_chunks pair for reassembly.
 */
struct domcomm_attest_report {
	__u64 domain_id;
	__u32 flags;                  /* DOMCOMM_ATTEST_F_* */
	__u32 num_vps;
	__u32 api_flags;              /* MonitorAPI bitmask */
	__u32 nr_mem_caps;
	__u32 nr_dom_caps;
	__u32 nr_pa_entries;
	__u16 chunk_index;            /* 0-based (0 if single message) */
	__u16 total_chunks;           /* 1 if entire report fits in one msg */
	__u32 reserved;
	/* Followed by packed arrays (when chunk_index == 0 or reassembled):
	 *   struct domcomm_mem_cap_entry  mem_caps[nr_mem_caps];
	 *   struct domcomm_dom_cap_entry  dom_caps[nr_dom_caps];
	 *   struct domcomm_pa_map_entry   pa_map[nr_pa_entries];
	 */
};

/* ── Ring growth message payloads ───────────────────────────────────────── */

/* DOMCOMM_MSG_GROW_RX / DOMCOMM_MSG_GROW_TX payload (TX ring, domain→capavisor) */
struct domcomm_grow_request {
	__u64 cap_handle;             /* CARVEd memory capability handle */
	__u64 cap_sub;                /* Capability sub-handle */
	__u32 nr_pages;               /* Number of new pages */
	__u32 reserved;
};

/* DOMCOMM_MSG_GROW_ACK payload (RX ring, capavisor→domain) */
struct domcomm_grow_ack {
	__u32 new_page_count;         /* Updated page count for the ring */
	__u32 new_capacity;           /* Updated capacity in bytes */
	__u32 status;                 /* 0 = success, nonzero = error */
	__u32 reserved;
};

/* ── Async VP exit payload (RX ring) ────────────────────────────────────── */

/* DOMCOMM_MSG_VP_EXIT payload */
struct domcomm_vp_exit {
	__u32 vp_id;
	__u32 reserved;
	struct themic_intercept_message intercept;
};

/* DOMCOMM_MSG_ERROR payload */
struct domcomm_error {
	__u32 error_code;
	__u32 reserved;
	__u64 detail;                 /* Context-dependent */
};

#define DOMCOMM_ERR_RING_FULL     1  /* Ring is full, domain should grow */
#define DOMCOMM_ERR_BAD_REQUEST   2  /* Malformed TX message */

/* DOMCOMM_MSG_ENUM_CAP payload (TX ring, request) */
struct domcomm_enum_cap_req {
	__u64 handle;                 /* Handle to enumerate */
};

/* DOMCOMM_MSG_DOORBELL_NOTIFY payload (RX ring, capavisor → domain).
 * Sent when an EPT violation matches a registered doorbell.  The child VP
 * is NOT stopped; it has already resumed.
 */
struct domcomm_doorbell_notify {
	__u32 doorbell_id;   /* matches thhv_ioeventfd_entry.doorbell_id */
	__u32 reserved;
	__u64 gpa;           /* guest physical address that was written */
	__u64 value;         /* data written by the guest */
	__u32 size;          /* write size in bytes */
	__u32 reserved2;
};

struct thhv_irqfd {
	__s32 fd;
	__u32 gsi;
	__u32 flags;
	__u32 rsvd;
};

#define THHV_IRQFD_FLAG_DEASSIGN  (1u << 0)

struct thhv_ioeventfd {
	__s32 fd;
	__u32 flags;
	__u64 addr;
	__u32 len;
	__u32 datamatch;
};

#define THHV_IOEVENTFD_FLAG_DATAMATCH  (1u << 0)  /* filter on datamatch value */
#define THHV_IOEVENTFD_FLAG_PIO        (1u << 1)  /* port I/O (not MMIO) */
#define THHV_IOEVENTFD_FLAG_DEASSIGN   (1u << 2)  /* remove existing registration */

struct thhv_msi_routing {
	__u32 nr;
	__u32 rsvd;
	/* Followed by nr × thhv_user_irq_entry (defined at impl time). */
};

struct thhv_check_extension {
	__u32 ext_id;
	__u32 rsvd;
};

/*
 * GPA → HPA translation map (derived from attestation).
 *
 * dom0 runs as a guest; page_to_pfn() yields Guest Physical Addresses.
 * The capavisor's attestation report tells dom0 how its GPAs map to real
 * Host Physical Addresses.  This map must be loaded before any memory
 * operations (CARVE/ALIAS/SEND) so the driver can translate.
 */
struct thhv_pa_map_entry {
	__u64 gpa;     /* Guest Physical Address start (page-aligned) */
	__u64 hpa;     /* Host Physical Address start (page-aligned) */
	__u64 size;    /* Range size in bytes (page-aligned) */
};

struct thhv_set_pa_map {
	__u32 nr_entries;
	__u32 rsvd;
	__u64 entries;  /* Userspace pointer to nr_entries × thhv_pa_map_entry */
};

/*
 * Generic query ioctl.  The query_type selects what information is returned.
 * New query types can be added without defining new ioctls.
 */
struct thhv_query {
	__u32 query_type;
	__u32 rsvd;
	__u64 result;         /* out */
};

/* Query types for THHV_QUERY. */
#define THHV_QUERY_META_PAGES_PER_VP     1  /* META pages needed per VP (VMCS+VAPIC) */
#define THHV_QUERY_META_PAGES_SHARED     2  /* Shared META pages per partition (MSR+IO bitmaps) */

/* Shared META page count: MSR bitmap (1) + IO bitmap A (1) + IO bitmap B (1) + EPT root (1). */
#define THHV_META_PAGES_SHARED  4

/* ── Device-level ioctls ───────────────────────────────────────────────────── */

#define THHV_CREATE_PARTITION \
	_IOWR(THHV_IOCTL_MAGIC, 0x01, struct thhv_create_partition)
#define THHV_CHECK_EXTENSION \
	_IOWR(THHV_IOCTL_MAGIC, 0x02, struct thhv_check_extension)
#define THHV_QUERY \
	_IOWR(THHV_IOCTL_MAGIC, 0x03, struct thhv_query)
#define THHV_SET_PA_MAP \
	_IOW(THHV_IOCTL_MAGIC, 0x04, struct thhv_set_pa_map)

/* ── Interrupt policy visibility values ────────────────────────────────────── */

#define THHV_INTR_VISIBILITY_DELIVER     0  /* Domain receives the interrupt directly */
#define THHV_INTR_VISIBILITY_REPORT      1  /* Interrupt forwarded up; domain notified on return */
#define THHV_INTR_VISIBILITY_NOT_REPORT  2  /* Interrupt forwarded up; domain not notified */

/* ── Interrupt policy ioctl struct ─────────────────────────────────────────── */

/*
 * Set interrupt visibility for a child domain before sealing.
 * vector: 0–254 for a specific vector, 0xFF to set the domain default.
 * visibility: THHV_INTR_VISIBILITY_*.
 */
#define THHV_INTR_POLICY_VEC_DEFAULT  0xFF

struct thhv_set_intr_policy {
	__u8 vector;      /* 0–254 for specific vector; 0xFF for domain default */
	__u8 visibility;  /* THHV_INTR_VISIBILITY_* */
	__u8 pad[6];
};

/* ── Partition-level ioctls ────────────────────────────────────────────────── */

#define THHV_INITIALIZE_PARTITION \
	_IO(THHV_IOCTL_MAGIC, 0x10)
#define THHV_CREATE_VP \
	_IOWR(THHV_IOCTL_MAGIC, 0x11, struct thhv_create_vp)
#define THHV_SET_GUEST_MEMORY \
	_IOW(THHV_IOCTL_MAGIC, 0x12, struct thhv_set_guest_memory)
#define THHV_IRQFD \
	_IOW(THHV_IOCTL_MAGIC, 0x13, struct thhv_irqfd)
#define THHV_IOEVENTFD \
	_IOW(THHV_IOCTL_MAGIC, 0x14, struct thhv_ioeventfd)
#define THHV_SET_MSI_ROUTING \
	_IOW(THHV_IOCTL_MAGIC, 0x15, struct thhv_msi_routing)
#define THHV_GET_GPAP_ACCESS_BITMAP \
	_IO(THHV_IOCTL_MAGIC, 0x16)
#define THHV_SEND_SHARED_META \
	_IOW(THHV_IOCTL_MAGIC, 0x17, struct thhv_initialize_partition)
#define THHV_SET_INTR_POLICY \
	_IOW(THHV_IOCTL_MAGIC, 0x18, struct thhv_set_intr_policy)

/* ── VP-level ioctls ───────────────────────────────────────────────────────── */

#define THHV_RUN_VP \
	_IOWR(THHV_IOCTL_MAGIC, 0x20, struct thhv_run_vp)
#define THHV_GET_VP_STATE \
	_IOWR(THHV_IOCTL_MAGIC, 0x21, struct thhv_vp_registers)
#define THHV_SET_VP_STATE \
	_IOW(THHV_IOCTL_MAGIC, 0x22, struct thhv_vp_registers)

/* ── Test ioctls (CONFIG_THHV_TEST only) ───────────────────────────────────── */

/*
 * Test commands for THHV_TEST_CMD ioctl.
 * Each command exercises a specific driver path.
 * Build with THHV_TEST=1 to enable.
 */
#define THHV_TEST_CMD_GROW_RX    1   /* Grow RX ring by arg pages */
#define THHV_TEST_CMD_GROW_TX    2   /* Grow TX ring by arg pages */
#define THHV_TEST_CMD_TX_PING    3   /* TX enqueue + notify (echo test) */

struct thhv_test_cmd {
	__u32 command;    /* THHV_TEST_CMD_* */
	__u32 arg;        /* Command-specific argument */
	__s32 result;     /* Filled on return: 0 = success, <0 = errno */
	__u32 reserved;
};

#define THHV_TEST \
	_IOWR(THHV_IOCTL_MAGIC, 0xF0, struct thhv_test_cmd)

/* ── Internal driver structures (kernel-only) ──────────────────────────────── */

#ifdef __KERNEL__

#include <linux/file.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/rbtree.h>
#include <linux/kref.h>
#include <linux/wait.h>
#include <linux/atomic.h>
#include <linux/list.h>

/* Forward declarations. */
struct thhv_partition;
struct thhv_vp;

/* Per-capability entry in the driver's local capability table (§17). */
struct thhv_cap_entry {
	struct rb_node node;         /* keyed by local_handle */
	u64 local_handle;            /* domain-local handle (from engine) */
	u64 parent_handle;           /* 0 for attestation roots */
	u64 sub_handle;              /* for REVOKE(parent, sub) */
	u64 hpa_start;
	u64 size;
};

/* Tracks a capability sent to a child domain (for revocation on teardown). */
struct thhv_sent_cap {
	struct list_head list;
	u64 parent_handle;           /* parent in OUR cap table */
	u64 sub_handle;              /* child sub-handle for REVOKE */
	u64 region_key;              /* guest_pfn of the mapping (for per-region unmap) */
};

/* Per-partition state. */

/*
 * Per-ioeventfd entry: tracks one registered doorbell and the eventfd to
 * signal when the capavisor reports a matching guest write.
 */
struct thhv_ioeventfd_entry {
	struct list_head  node;
	u64               doorbell_id;   /* returned by REGISTER_DOORBELL */
	u64               addr;          /* guest GPA registered as doorbell */
	u32               len;           /* access size (0 = any) */
	u64               datamatch;     /* match value (0 if DATAMATCH flag not set) */
	u32               flags;         /* ioctl flags */
	struct eventfd_ctx *eventfd;
	struct thhv_partition *partition;
};

/*
 * Per-irqfd entry: when the eventfd fires, inject `vector` into VP 0 of
 * the partition via INJECT_INTERRUPT.  GSI→vector mapping via MSI routing
 * is a TODO; currently the ioctl `gsi` field is passed through as the vector.
 */
struct thhv_irqfd_entry {
	struct list_head   node;
	u32                gsi;
	u32                vector;       /* MSI routing lookup result (TODO) */
	struct eventfd_ctx *eventfd;
	wait_queue_head_t  *wqh;         /* saved during poll, used on deassign */
	wait_queue_entry_t wait;
	poll_table         pt;           /* used during assign to subscribe to wqh */
	struct work_struct work;
	struct thhv_partition *partition;
	bool               deassign;
};

/* Per-partition state. */
struct thhv_partition {
	u64 domain_handle;
	u64 domain_id;
	u32 sched_policy;
	u32 num_vps;
	bool sealed;

	struct thhv_vp **vps;

	/* Shared META pages: MSR bitmap + IO bitmaps A & B.  Pinned at INITIALIZE. */
	struct page **shared_meta_pages;
	unsigned int  shared_meta_nr_pages;

	/* APIC-access sentinel page: mapped at GPA THHV_LAPIC_GPA so that
	 * VIRTUALIZE_APIC_ACCESSES fires APIC_ACCESS exits for LAPIC accesses. */
	struct page **apic_access_pages;
	unsigned int  apic_access_nr_pages;

	/* EPT META pages: kernel-allocated, sent to child for EPT page tables. */
	struct page **ept_meta_pages;
	unsigned int  ept_meta_nr_pages;

	/* Memory region tracking: guest_pfn → pinned pages (for unpin on cleanup). */
	struct {
		spinlock_t lock;
		struct rb_root regions;
	} mem;

	/* Capabilities sent to this child domain (for revocation on teardown). */
	struct {
		spinlock_t lock;
		struct list_head list;
	} sent_caps;

	/* IRQfd tracking. */
	struct {
		struct list_head list;
		struct mutex lock;
	} irqfds;

	/* IOEventFd / doorbell tracking. */
	struct {
		struct list_head list;
		struct mutex lock;
	} ioeventfds;

	struct file *file;
	struct kref refcount;
};

/* Per-VP state. */
struct thhv_vp {
	u32 vp_index;
	struct thhv_partition *partition;
	struct mutex run_lock;

	/* Async mode waitqueue. */
	wait_queue_head_t exit_wq;
	atomic_t exit_pending;

	/* Exit info buffer for userspace. */
	u8 exit_msg[256];

	/* META pages: pinned from userspace, for capavisor internal alloc. */
	struct page **meta_pages;
	unsigned int  meta_nr_pages;

	/* COMM page: pinned from userspace, shared with capavisor. */
	struct page  *comm_page;
	void         *comm_kaddr;      /* kernel mapping */
	u64           comm_phys;       /* HPA (after GPA→HPA translation) */
	u64           comm_parent_handle; /* parent cap used for CARVE */
	u64           comm_cap_handle;    /* carved child handle */
	u64           comm_cap_sub;       /* sub-handle for REVOKE(parent, sub) */
	bool          comm_registered;    /* REGISTER_COMM done */

	struct file *file;
};

/* Memory region tracking node (rb-tree, keyed by guest_pfn).
 * Tracks pinned pages for cleanup.  Capability revocation is handled
 * by the per-partition sent_caps list (see thhv_sent_cap).
 */
struct thhv_mem_region {
	struct rb_node node;
	u64 guest_pfn;
	u64 nr_pages;
	u64 userspace_addr;
	struct page **pages;   /* Pinned userspace pages */
	u32 flags;             /* THHV_MEM_F_* */
	u32 rights;            /* THHV_MEM_R_* */
	u64 attrs;             /* THHV_MEM_A_* */
};

/* HPA segment produced by GPA→HPA translation. */
struct thhv_hpa_segment {
	u64 hpa_start;
	u64 size;
};

/* ── Functions exported between translation units ──────────────────────────── */

/* thhv_hvcall.c — generic fallback */
int thhv_hcall(u64 opcode, u64 arg0, u64 arg1, u64 arg2,
		   u64 *out0, u64 *out1, u64 *out2);

/*
 * Typed C wrappers around __themis_vmcall (thhv_hvcall.c).
 * All return 0 on success, negative errno on failure.
 */
int themis_create_domain(u64 cores_mask, u64 api_flags, u64 num_vps,
				u64 *out_handle);
int themis_seal(u64 domain);
int themis_revoke_domain(u64 domain);
int themis_revoke_mem(u64 parent, u64 child_sub);
int themis_carve(u64 parent, u64 start, u64 size, u64 rights,
			u64 *out_handle, u64 *out_sub);
int themis_alias(u64 parent, u64 start, u64 size, u64 rights,
			u64 *out_handle, u64 *out_sub);
int themis_send(u64 cap, u64 receiver, u64 attrs);
int themis_send_at(u64 cap, u64 receiver, u64 attrs, u64 child_gpa);
int themis_accept(u64 pending_id, u64 *out_handle);
int themis_reject(u64 pending_id);
int themis_switch(u64 target_domain, u64 vp_id);
int themis_get_chan(u64 domain, u64 *out_handle);
int themis_attest_self(u64 *out_lo, u64 *out_hi);
int themis_attest(u64 domain, u64 *out_lo, u64 *out_hi);
int themis_get_reg(u64 domain, u64 vp_id, u64 reg, u64 *out_val);
int themis_set_reg(u64 domain, u64 vp_id, u64 reg, u64 value);
int themis_set_intr_policy(u64 domain, u64 vector, u64 policy);
int themis_set_def_intr_policy(u64 domain, u64 policy);
int themis_assign_device(u64 domain, u64 pci_bdf);
int themis_register_comm(u64 cap, u64 child_domain, u64 vp_id);
int themis_add_vp(u64 child_domain, u64 comm_cap);
int themis_domcomm_notify(void);
int themis_register_doorbell(u64 child_domain, u64 gpa, u64 size,
			     u64 datamatch, u64 flags, u64 *out_doorbell_id);
int themis_unregister_doorbell(u64 child_domain, u64 doorbell_id);
int themis_set_themic_vector(u64 vector);
int themis_inject_interrupt(u64 child_domain, u32 vp_id, u8 vector);

/* thhv_part.c */
long thhv_partition_create(struct file *dev_file, void __user *uarg);
extern const struct file_operations thhv_partition_fops;

/* thhv_ioeventfd.c */
int  thhv_ioeventfd_assign(struct thhv_partition *part, struct thhv_ioeventfd __user *uarg);
int  thhv_ioeventfd_deassign(struct thhv_partition *part, struct thhv_ioeventfd __user *uarg);
void thhv_drain_domcomm_rx(struct thhv_partition *part);

/* thhv_irqfd.c */
int  thhv_irqfd_assign(struct thhv_partition *part, struct thhv_irqfd __user *uarg);
int  thhv_irqfd_deassign(struct thhv_partition *part, struct thhv_irqfd __user *uarg);
void thhv_irqfd_release_all(struct thhv_partition *part);

/* thhv_vp.c */
long thhv_vp_create(struct thhv_partition *part, void __user *uarg);
extern const struct file_operations thhv_vp_fops;

/* thhv_translate.c — GPA→HPA translation + capability table */
int thhv_set_pa_map(void __user *uarg);
int thhv_pa_map_init_from_attestation(void);
u64 thhv_gpa_to_hpa(u64 gpa);
int thhv_translate_range(u64 gpa_start, u64 size,
			 struct thhv_hpa_segment **out_segs,
			 unsigned int *out_nr_segs);
int thhv_translate_pages(struct page **pages, unsigned long nr_pages,
			 struct thhv_hpa_segment **out_segs,
			 unsigned int *out_nr_segs);
int thhv_find_parent_handle(u64 hpa, u64 size, u64 *out_handle);
int thhv_cap_table_insert(u64 local_handle, u64 parent_handle,
			  u64 sub_handle, u64 hpa_start, u64 size);
int thhv_cap_table_remove(u64 local_handle);
void thhv_pa_map_cleanup(void);

/* CARVE + SEND META pages to a child domain (frame allocator backing). */
int thhv_send_meta_pages(struct thhv_partition *part,
			 struct page **pages, unsigned int nr_pages,
			 u64 region_key);

/* Synthetic region_key values for META caps (never valid as a guest_pfn). */
#define THHV_META_KEY_SHARED	0xFFFFFFFFFFFF0001ULL
#define THHV_META_KEY_VP(vp)	(0xFFFFFFFFFFFF1000ULL + (u64)(vp))
#define THHV_META_KEY_EPT	0xFFFFFFFFFFFF2000ULL

/*
 * DomainComm ring accessor — page-aware byte-oriented ring.
 *
 * The ring may be backed by non-contiguous pages.  Messages never cross
 * page boundaries (invariant from design doc §6).  The driver maps each
 * page independently and uses this structure for ring I/O.
 */
struct domcomm_ring {
	void __iomem **page_vas;       /* Array of per-page virtual addresses */
	unsigned int   nr_pages;       /* Number of backing pages */
	__u32         *head;           /* Pointer to head in header page */
	__u32         *tail;           /* Pointer to tail in header page */
	u32            capacity;       /* Total ring size in bytes (nr_pages * PAGE_SIZE) */
	u64            next_seq;       /* Next sequence number to use (producer) */
};

/* Global DomainComm state (one per domain = one per driver instance). */
struct domcomm_state {
	void __iomem         *base;    /* memremap'd header page */
	struct domcomm_header *hdr;    /* = base, typed access to header */
	struct domcomm_ring   rx;      /* RX ring (capavisor → domain, we consume) */
	struct domcomm_ring   tx;      /* TX ring (domain → capavisor, we produce) */
	u64                   gpa;     /* GPA of the region (from CPUID) */
	unsigned int          total_pages;
	bool                  initialized;
	u64                   self_domain_handle; /* for REGISTER_COMM self-ref */
};

/* domcomm ring helpers (thhv_domcomm.c) */
int  domcomm_init(void);
void domcomm_cleanup(void);
int  domcomm_rx_dequeue(struct domcomm_ring *ring, void *buf,
			u32 buf_size, u32 *out_type, u32 *out_payload_size);
int  domcomm_tx_enqueue(struct domcomm_ring *ring, u32 msg_type,
			const void *payload, u32 payload_size);
int  domcomm_request_grow(bool grow_rx, u32 nr_pages);

/* Global DomainComm instance. */
extern struct domcomm_state thhv_domcomm;

#endif /* __KERNEL__ */

#endif /* _THHV_H */
