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

/* ── THHV ioctl magic ──────────────────────────────────────────────────────── */

#define THHV_IOCTL_MAGIC  0xB8

/* ── CPUID detection ───────────────────────────────────────────────────────── */

#define THHV_CPUID_LEAF       0x40000000
#define THHV_CPUID_MAX_LEAF   0x40000003
#define THHV_CPUID_FEAT_LEAF  0x40000001
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
#define THHV_META_PAGES_PER_VP  2

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
#define THEMIS_HC_REGISTER_VP_META   0x14
#define THEMIS_HC_REGISTER_DOORBELL  0x15
#define THEMIS_HC_REGISTER_EVENT_FLAGS 0x16
#define THEMIS_HC_REGISTER_INTR_CHAN 0x17
#define THEMIS_HC_REGISTER_COMM      0x18

/* ── Themis hypercall return codes (RAX) ───────────────────────────────────── */

#define THEMIS_SUCCESS       0
#define THEMIS_ERR_INVALID   1
#define THEMIS_ERR_NOPERM    2
#define THEMIS_ERR_NOMEM     3
#define THEMIS_ERR_BADSTATE  4
#define THEMIS_ERR_NOTFOUND  5
#define THEMIS_ERR_UNIMPL    (~0ULL)

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

struct thhv_initialize_partition {
	__u64 meta_uaddr;     /* Userspace VA of shared META pages */
	__u64 meta_size;      /* Size in bytes (must be PAGE_SIZE * META_PAGES_SHARED) */
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

struct thhv_run_vp {
	__u8 msg_buf[256];     /* THHV intercept message on return */
};

struct thhv_irqfd {
	__s32 fd;
	__u32 gsi;
	__u32 flags;
	__u32 rsvd;
};

struct thhv_ioeventfd {
	__s32 fd;
	__u32 flags;
	__u64 addr;
	__u32 len;
	__u32 datamatch;
};

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

/* Shared META page count: MSR bitmap (1) + IO bitmap A (1) + IO bitmap B (1). */
#define THHV_META_PAGES_SHARED  3

/* ── Device-level ioctls ───────────────────────────────────────────────────── */

#define THHV_CREATE_PARTITION \
	_IOWR(THHV_IOCTL_MAGIC, 0x01, struct thhv_create_partition)
#define THHV_CHECK_EXTENSION \
	_IOWR(THHV_IOCTL_MAGIC, 0x02, struct thhv_check_extension)
#define THHV_QUERY \
	_IOWR(THHV_IOCTL_MAGIC, 0x03, struct thhv_query)
#define THHV_SET_PA_MAP \
	_IOW(THHV_IOCTL_MAGIC, 0x04, struct thhv_set_pa_map)

/* ── Partition-level ioctls ────────────────────────────────────────────────── */

#define THHV_INITIALIZE_PARTITION \
	_IOW(THHV_IOCTL_MAGIC, 0x10, struct thhv_initialize_partition)
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

/* ── VP-level ioctls ───────────────────────────────────────────────────────── */

#define THHV_RUN_VP \
	_IOWR(THHV_IOCTL_MAGIC, 0x20, struct thhv_run_vp)
#define THHV_GET_VP_STATE \
	_IOWR(THHV_IOCTL_MAGIC, 0x21, struct thhv_vp_registers)
#define THHV_SET_VP_STATE \
	_IOW(THHV_IOCTL_MAGIC, 0x22, struct thhv_vp_registers)

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

	/* Memory capability tracking: guest_pfn → cap_handle. */
	struct {
		spinlock_t lock;
		struct rb_root regions;
	} mem;

	/* IRQfd tracking. */
	struct list_head irqfds;
	struct mutex irqfd_lock;

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
	u64           comm_cap_handle; /* CARVE capability handle */
	u64           comm_cap_sub;    /* CARVE capability sub-handle */
	bool          comm_registered; /* REGISTER_COMM done */

	struct file *file;
};

/* Per-capability handle (one per HPA segment within a memory region). */
struct thhv_mem_cap {
	u64 cap_handle;
	u64 cap_sub;
	u64 hpa_start;
	u64 size;
};

/* Memory region tracking node (rb-tree, keyed by guest_pfn). */
struct thhv_mem_region {
	struct rb_node node;
	u64 guest_pfn;
	u64 nr_pages;
	u64 userspace_addr;
	struct page **pages;   /* Pinned userspace pages */
	u32 flags;             /* THHV_MEM_F_* */
	u32 rights;            /* THHV_MEM_R_* */
	u64 attrs;             /* THHV_MEM_A_* */

	/* One capability per contiguous HPA segment (after GPA→HPA translation). */
	unsigned int  nr_caps;
	struct thhv_mem_cap *caps;
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
 * Typed Rust FFI wrappers (from libthemis.a, feature = "ffi").
 * All return 0 on success, negative errno on failure.
 * Prefer these over thhv_hcall() for type safety and sync with
 * the capavisor's ABI definitions.
 */
extern int themis_create_domain(u64 cores_mask, u64 api_flags, u64 num_vps,
				u64 *out_handle);
extern int themis_seal(u64 domain);
extern int themis_revoke_domain(u64 domain);
extern int themis_revoke_mem(u64 parent, u64 child_sub);
extern int themis_carve(u64 parent, u64 start, u64 size, u64 rights,
			u64 *out_handle, u64 *out_sub);
extern int themis_alias(u64 parent, u64 start, u64 size, u64 rights,
			u64 *out_handle, u64 *out_sub);
extern int themis_send(u64 cap, u64 receiver, u64 attrs);
extern int themis_accept(u64 pending_id, u64 *out_handle);
extern int themis_reject(u64 pending_id);
extern int themis_switch(u64 target_domain, u64 vp_id);
extern int themis_get_chan(u64 domain, u64 *out_handle);
extern int themis_attest_self(u64 *out_lo, u64 *out_hi);
extern int themis_attest(u64 domain, u64 *out_lo, u64 *out_hi);
extern int themis_get_reg(u64 domain, u64 vp_id, u64 reg, u64 *out_val);
extern int themis_set_reg(u64 domain, u64 vp_id, u64 reg, u64 value);
extern int themis_set_intr_policy(u64 domain, u64 vector, u64 policy);
extern int themis_set_def_intr_policy(u64 domain, u64 policy);
extern int themis_assign_device(u64 domain, u64 pci_bdf);
extern int themis_register_comm(u64 cap, u64 child_domain, u64 vp_id);

/* thhv_part.c */
long thhv_partition_create(struct file *dev_file, void __user *uarg);
extern const struct file_operations thhv_partition_fops;

/* thhv_vp.c */
long thhv_vp_create(struct thhv_partition *part, void __user *uarg);
extern const struct file_operations thhv_vp_fops;

/* thhv_translate.c — GPA→HPA address translation */
int thhv_set_pa_map(void __user *uarg);
int thhv_translate_range(u64 gpa_start, u64 size,
			 struct thhv_hpa_segment **out_segs,
			 unsigned int *out_nr_segs);
int thhv_translate_pages(struct page **pages, unsigned long nr_pages,
			 struct thhv_hpa_segment **out_segs,
			 unsigned int *out_nr_segs);
void thhv_pa_map_cleanup(void);

#endif /* __KERNEL__ */

#endif /* _THHV_H */
