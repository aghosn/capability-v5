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

/* Maximum VPs per domain.  Must equal `themis_abi::MAX_VPS_PER_DOMAIN`
 * (single source of truth on the Rust side).  Enforced both here (thhv
 * partition-create ioctl) and on the userspace VMM side (CHV
 * `Hypervisor::get_max_vcpus`). */
#define THHV_MAX_VPS_PER_DOMAIN  256u

/* Maximum GSI / interrupt vector number.  Intel x86 IDT vectors are 8-bit
 * (0..255); GSI 0 is reserved as "no vector" / invalid. */
#define THHV_MAX_GSI             255u

/* Maximum entries accepted in a single THHV_SET_PA_MAP ioctl batch.  Bounds
 * userspace's per-call work and the kernel allocation it triggers. */
#define THHV_PA_MAP_MAX_ENTRIES  4096u

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
#define THEMIS_HC_ASSIGN_DEVICE      0x12
#define THEMIS_HC_ENUMERATE          0x13
#define THEMIS_HC_ADD_VP             0x14
#define THEMIS_HC_REGISTER_DOORBELL  0x15
#define THEMIS_HC_UNREGISTER_DOORBELL 0x16
#define THEMIS_HC_SET_THEMIC_VECTOR  0x17
#define THEMIS_HC_REGISTER_COMM      0x18
#define THEMIS_HC_INJECT_INTERRUPT   0x1b
#define THEMIS_HC_READ_PCR           0x1e
#define THEMIS_HC_MAP_SELF           0x1f
#define THEMIS_HC_SEND_CHAN          0x20
#define THEMIS_HC_ACCEPT_CHAN        0x21
#define THEMIS_HC_SET_POLICY        0x22

/* ── Themis hypercall opcodes (RAX in) ─────────────────────────────────────── */

#define THEMIS_OP_CARVE               0x01
#define THEMIS_OP_ALIAS               0x02
#define THEMIS_OP_SEND                0x03
#define THEMIS_SEND_IDENTITY_MAP      ((u64)-1)
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
#define THEMIS_OP_ASSIGN_DEVICE       0x12
#define THEMIS_OP_ENUMERATE           0x13
#define THEMIS_OP_ADD_VP              0x14
#define THEMIS_OP_REGISTER_DOORBELL   0x15
#define THEMIS_OP_UNREGISTER_DOORBELL 0x16
#define THEMIS_OP_SET_THEMIC_VECTOR   0x17
#define THEMIS_OP_REGISTER_COMM       0x18
#define THEMIS_OP_DOMCOMM_NOTIFY     0x19
#define THEMIS_OP_INJECT_INTERRUPT   0x1b
#define THEMIS_OP_TOGGLE_DEBUG      0x1d
#define THEMIS_OP_READ_PCR          0x1e
#define THEMIS_OP_MAP_SELF          0x1f
#define THEMIS_OP_SEND_CHAN        0x20
#define THEMIS_OP_ACCEPT_CHAN      0x21
#define THEMIS_OP_SET_POLICY      0x22

/* ── Policy-kind discriminants for THEMIS_OP_SET_POLICY ────────────────────── */

#define THEMIS_POLICY_CORES                    0
#define THEMIS_POLICY_API_MONITOR              1
#define THEMIS_POLICY_DEFAULT_INTR_VISIBILITY  2
#define THEMIS_POLICY_VECTOR_VISIBILITY        3
#define THEMIS_POLICY_VECTOR_REG_READ_SET      4
#define THEMIS_POLICY_VECTOR_REG_WRITE_SET     5
#define THEMIS_POLICY_DEFAULT_EXIT_TRAP        6
#define THEMIS_POLICY_EXIT_REASON_TRAP         7
#define THEMIS_POLICY_EXIT_REASON_REG_READ_SET 8
#define THEMIS_POLICY_EXIT_REASON_REG_WRITE_SET 9

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
#define THEMIS_ERR_RACE      8
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
	case THEMIS_ERR_BUSY:     return -EBUSY;
	case THEMIS_ERR_RETRY:    return -EAGAIN;
	case THEMIS_ERR_RACE:     return -EAGAIN;
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

/* ── VM exit reasons (Intel SDM Vol 3C §27.9.1, Appendix C) ──────────── */
#define THHV_EXIT_REASON_CPUID		10
#define THHV_EXIT_REASON_HLT		12
#define THHV_EXIT_REASON_IO		30
#define THHV_EXIT_REASON_RDMSR		31
#define THHV_EXIT_REASON_WRMSR		32
#define THHV_EXIT_REASON_EPT_VIOLATION	48

/* ── Synthetic exit reasons (high bit set, not hardware VMX reasons) ──── */
#define THHV_EXIT_REASON_DOORBELL	0x80000001u

/* ── VP activity / MP state (Intel SDM Vol 3C §24.4.2) ───────────────── */
#define THHV_MP_STATE_RUNNABLE		0
#define THHV_MP_STATE_WAIT_FOR_SIPI	3

/* ── EPT page table level shifts (Intel SDM Vol 3D §28.5) ────────────── */
#define EPT_LEVEL_SHIFT_PML4		39  /* 512 GiB */
#define EPT_LEVEL_SHIFT_PDPT		30  /* 1 GiB */
#define EPT_LEVEL_SHIFT_PD		21  /* 2 MiB */

struct thhv_initialize_partition {
	__u64 meta_uaddr;          /* Userspace VA of shared META pages */
	__u64 meta_size;           /* Size in bytes (must be PAGE_SIZE * META_PAGES_SHARED) */
	__u64 apic_access_uaddr;   /* Userspace VA of APIC-access sentinel page (PAGE_SIZE) */
	__u64 apic_access_size;    /* Must be PAGE_SIZE */
};

/* Shared-memory rendezvous constants (used in thhv_set_guest_memory). */
#define THHV_SHMEM_PATH_MAX    256
#define THHV_SHMEM_MAX_ENTRIES  16
#define THHV_SHMEM_MODE_NONE    0  /* Not a shmem region (default) */
#define THHV_SHMEM_MODE_ALIAS   1  /* Creator keeps access */
#define THHV_SHMEM_MODE_CARVE   2  /* Creator loses access */
#define THHV_SHMEM_MODE_PLUG    3  /* Join existing region */

struct thhv_set_guest_memory {
	__u64 guest_pfn;       /* GPA >> 12 */
	__u64 userspace_addr;  /* Host VA (page-aligned) */
	__u64 size;            /* bytes (page-aligned) */
	__u32 flags;           /* THHV_MEM_F_* bitmask */
	__u32 rights;          /* THHV_MEM_R_* bitmask (R/W/X) */
	__u64 attrs;           /* THHV_MEM_A_* bitmask (HASH/CLEAN/VITAL/META) */
	/* Optional shared-memory fields (shmem_mode == 0 → not shmem). */
	__u32 shmem_mode;      /* THHV_SHMEM_MODE_* (0 = none) */
	__u32 shmem_count;     /* Nr of plug aliases (creator only) */
	char  shmem_path[THHV_SHMEM_PATH_MAX]; /* Rendezvous key */
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
#define THHV_MEM_A_COMM      (1U << 4)  /* DomainComm page (implies CLEAN) */

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
 * Read a register value from the COMM page.
 * Returns 0 for unknown register IDs.
 */
static inline __u64 thhv_comm_get_reg(const struct thhv_vp_comm_page *comm, unsigned int reg)
{
	switch (reg) {
	case THHV_VP_REG_RAX: return comm->rax;
	case THHV_VP_REG_RBX: return comm->rbx;
	case THHV_VP_REG_RCX: return comm->rcx;
	case THHV_VP_REG_RDX: return comm->rdx;
	case THHV_VP_REG_RSI: return comm->rsi;
	case THHV_VP_REG_RDI: return comm->rdi;
	case THHV_VP_REG_RBP: return comm->rbp;
	case THHV_VP_REG_R8:  return comm->r8;
	case THHV_VP_REG_R9:  return comm->r9;
	case THHV_VP_REG_R10: return comm->r10;
	case THHV_VP_REG_R11: return comm->r11;
	case THHV_VP_REG_R12: return comm->r12;
	case THHV_VP_REG_R13: return comm->r13;
	case THHV_VP_REG_R14: return comm->r14;
	case THHV_VP_REG_R15: return comm->r15;
	case THHV_VP_REG_RSP:    return comm->rsp;
	case THHV_VP_REG_RIP:    return comm->rip;
	case THHV_VP_REG_RFLAGS: return comm->rflags;
	default: return 0;
	}
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
 * Slim intercept message — written by capavisor to COMM page offset 512.
 * Contains only exit metadata; register values stay in the COMM page
 * register area (gated by ExitPolicy.read_set).  thhv reads registers
 * from there and assembles the full themic_intercept_message for CHV.
 */
struct themic_slim_intercept {
	struct themic_message_header header;
	__u32 exit_reason;
	__u32 instruction_length;
	__u64 exit_qualification;
	__u64 guest_physical_address;
	__u16 port_number;
	__u8  access_size;
	__u8  is_write;
	__u32 reserved;
	__u8  instruction_bytes[16];
};

/*
 * Full intercept message — assembled by thhv from slim + COMM page regs.
 * This is the format exposed to userspace (CHV).
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
 * Binary attestation report header (common base).
 *
 * Followed by three arrays packed contiguously: mem_caps[], dom_caps[], pa_map[].
 * When `flags & DOMCOMM_ATTEST_F_SEALED`, a `domcomm_signed_envelope` (plus
 * optional TPM blobs) follows the cap entries — see THHV_ATTEST_SELF docs.
 *
 * Common-base total size = sizeof(domcomm_attest_report)
 *                        + nr_mem_caps   * sizeof(domcomm_mem_cap_entry)
 *                        + nr_dom_caps   * sizeof(domcomm_dom_cap_entry)
 *                        + nr_pa_entries * sizeof(domcomm_pa_map_entry)
 *
 * If the total exceeds DOMCOMM_MAX_PAYLOAD (4080 bytes), the report
 * is split across multiple DOMCOMM_MSG_ATTEST messages.
 *
 * NOTE: `chunk_index` / `total_chunks` are currently dead — the capavisor
 * hardcodes (0, 1) and the kernel does not reassemble multi-chunk reports.
 * Today's reports must fit in a single 4080-byte message.
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
	__u32 vector;   /* MSI vector to inject (0 = use gsi as vector) */
	__u32 vp_index; /* Target VP for injection (default 0 = BSP) */
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

/* ── Attestation ioctls (device-level) ─────────────────────────────────────── */

/*
 * THHV_ATTEST_SELF — request a signed self-attestation from the capavisor.
 *
 * Wire format of the report delivered to dom0's DomainComm RX ring:
 *
 *   [ domcomm_attest_report (40B)  ]   ← flags |= DOMCOMM_ATTEST_F_SEALED
 *   [ mem_cap entries (40B each)   ]   \
 *   [ dom_cap entries (16B each)   ]    > common base (parsed by the
 *   [ pa_map  entries (24B each)   ]   /  unsigned path too)
 *   ─────────── signed-only tail ───────────
 *   [ domcomm_signed_envelope (168B) ]
 *   [ tpm_quote (variable)         ]   (optional, if TPM is provisioned)
 *   [ tpm_sig   (variable)         ]
 *   [ ak_pub    (variable)         ]
 *
 * The Ed25519 signature in the envelope covers
 *   SHA-256(common_base ‖ nonce ‖ user_pub_key)
 * — every byte of the common base (header + cap entries) is bound.
 *
 * Returns: report_size (bytes written to DomainComm RX ring) in result field.
 */
/*
 * THHV_ATTEST_SELF — return the calling partition's signed/unsigned
 * attestation report into a userspace-supplied buffer.
 *
 * Userspace owns the buffer (any size, kernel streams chunks into it via
 * copy_to_user as they arrive from the capavisor RX ring).  On return,
 * `report_size` is the actual number of bytes written; if it exceeds
 * `buf_len` the ioctl returns -ENOSPC and `report_size` carries the
 * full size so the caller can resize and retry.
 */
struct thhv_attest_self {
	__u8  nonce[32];         /* in: verifier-supplied nonce */
	__u8  user_pub_key[32];  /* in: verifier's public key (bound into signature) */
	__u64 buf_uaddr;         /* in: userspace VA of report buffer */
	__u64 buf_len;           /* in: capacity in bytes */
	__u64 report_size;       /* out: total bytes of report (always set) */
};

#define THHV_ATTEST_SELF \
	_IOWR(THHV_IOCTL_MAGIC, 0x05, struct thhv_attest_self)

/*
 * Signed attestation envelope (168 bytes) — appended after the common base
 * when the report is sealed.  Matches `themis_abi::domcomm::SignedEnvelope`.
 *
 * The envelope is located at byte offset
 *   40 + nr_mem_caps*40 + nr_dom_caps*16 + nr_pa_entries*24
 * in `report_buf` (i.e. immediately after the common-base entries).
 */
struct domcomm_signed_envelope {
	__u8  signature[64];     /* Ed25519 signature */
	__u8  pub_key[32];       /* capavisor Ed25519 pub key */
	__u8  nonce[32];         /* echoed nonce */
	__u8  user_pub_key[32];  /* echoed user pub key */
	__u16 tpm_quote_size;
	__u16 tpm_sig_size;
	__u16 ak_pub_size;
	__u16 reserved;
};  /* 168 bytes */

/*
 * THHV_READ_PCR — read a TPM PCR value via the capavisor.
 *
 * The TPM is capavisor-exclusive (not mapped into dom0's EPT).
 * This ioctl provides read-only access to PCR values for verification.
 *
 * Returns: first 24 bytes of the PCR digest (3 × u64).
 *          Full 32-byte digest not available via register return path.
 */
struct thhv_read_pcr {
	__u32 pcr_index;     /* in: PCR index (e.g., 11) */
	__u32 rsvd;
	__u8  digest[24];    /* out: first 24 bytes of PCR SHA-256 value */
};

#define THHV_READ_PCR \
	_IOWR(THHV_IOCTL_MAGIC, 0x06, struct thhv_read_pcr)

/* Inject a virtual interrupt into a child VP's PIR (Pending Interrupt Request).
 * If the VP is halted (guest executed HLT), it is woken to process the vector. */
struct thhv_inject_interrupt {
	__u32 vp_index;
	__u8  vector;
	__u8  pad[3];
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
/*
 * Unified policy-setting ioctl — maps directly to THEMIS_OP_SET_POLICY.
 * kind: THEMIS_POLICY_* discriminant.
 * key:  vector (interrupt variants) or exit_reason (exit variants), 0 otherwise.
 * sub_key: word_index for register bitmap variants, 0 otherwise.
 * value: the policy value to set.
 */
struct thhv_set_policy {
	__u64 kind;
	__u64 key;
	__u64 sub_key;
	__u64 value;
};

#define THHV_INJECT_INTERRUPT \
	_IOW(THHV_IOCTL_MAGIC, 0x19, struct thhv_inject_interrupt)
#define THHV_SET_POLICY \
	_IOW(THHV_IOCTL_MAGIC, 0x1a, struct thhv_set_policy)

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

/* ── Debug: list HPA ranges owned (carved) by the calling partition ─────────
 *
 * Returns the list of (hpa, nr_pages) ranges that the calling partition
 * carved away from dom0 via THHV_SET_GUEST_MEMORY (i.e. exclusive — dom0 has
 * lost EPT access).  Aliased (shared) regions are NOT included.
 *
 * Userspace fills `max_entries` and `entries` (pointer to its own buffer of
 * struct thhv_debug_hpa_range).  The kernel writes up to `max_entries` and
 * sets `nr_entries` to the actual number available (which may exceed
 * `max_entries`; userspace can retry with a larger buffer).
 *
 * Coalesces adjacent pages into runs to keep the response compact.
 *
 * Behind CONFIG-style guard: refuses unless thhv was built with debug
 * support.  Intended only for the coco-attacker isolation test.
 */
struct thhv_debug_hpa_range {
	__u64 hpa;        /* Host physical address of run start (page-aligned) */
	__u64 nr_pages;   /* Number of 4 KiB pages in this run */
};

struct thhv_debug_list_hpas {
	__u64 domain_handle; /* IN:  partition (matches thhv_partition.domain_handle); 0 = all */
	__u32 max_entries;   /* IN:  capacity of `entries` */
	__u32 nr_entries;    /* OUT: total number of runs available */
	__u64 entries;       /* IN:  __u64-encoded user pointer to entries[] */
};

#define THHV_DEBUG_LIST_HPAS \
	_IOWR(THHV_IOCTL_MAGIC, 0xF1, struct thhv_debug_list_hpas)

/*
 * THHV_DEBUG_REVOKE_ALL — walk the global partitions list and issue
 * REVOKE_DOMAIN on every live partition (excluding dom0 itself, which
 * would be a suicide).  Debug-only: intended to exercise the capavisor's
 * cross-core revoke protocol from a user process pinned to a specific
 * core (typically different from the CHV vCPU thread hosting the child),
 * without having to shut CHV down.
 *
 * On success, returns the number of partitions for which the
 * REVOKE_DOMAIN hypercall was attempted.  Per-partition failures are
 * logged via dmesg but do not fail the ioctl.
 *
 * Requires CAP_SYS_ADMIN.
 */
#define THHV_DEBUG_REVOKE_ALL \
	_IO(THHV_IOCTL_MAGIC, 0xF2)


#endif /* _THHV_H */
