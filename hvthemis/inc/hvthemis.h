/* SPDX-License-Identifier: GPL-2.0 */
/*
 * hvthemis.h — UAPI header for the hvthemis kernel module.
 *
 * Exposes /dev/mshv with an ioctl ABI compatible with Microsoft's MSHV driver,
 * backed by Themis capability operations (VMCALLs).
 *
 * Three-level fd hierarchy:
 *   /dev/mshv       (device fd)   — MSHV_CREATE_PARTITION, MSHV_CHECK_EXTENSION
 *     └─ partition fd             — MSHV_CREATE_VP, MSHV_SET_GUEST_MEMORY, ...
 *          └─ vp fd               — MSHV_RUN_VP, MSHV_GET/SET_VP_STATE, mmap()
 */

#ifndef _HVTHEMIS_H
#define _HVTHEMIS_H

#include <linux/types.h>
#include <linux/ioctl.h>

/* ── MSHV ioctl magic ──────────────────────────────────────────────────────── */

#define MSHV_IOCTL_MAGIC  0xB8

/* ── CPUID detection ───────────────────────────────────────────────────────── */

#define HVTHEMIS_CPUID_LEAF       0x40000000
#define HVTHEMIS_CPUID_MAX_LEAF   0x40000003
#define HVTHEMIS_CPUID_FEAT_LEAF  0x40000001
#define HVTHEMIS_CPUID_CAP_LEAF   0x40000003

/* Expected vendor string: "ThemisCapa" in EBX:ECX:EDX (little-endian u32s). */
#define HVTHEMIS_SIG_EBX  0x6d656854  /* "Them" */
#define HVTHEMIS_SIG_ECX  0x61437369  /* "isCa" */
#define HVTHEMIS_SIG_EDX  0x20206170  /* "pa  " */

/* Feature flags (leaf 0x40000001, EAX). */
#define HVTHEMIS_FEAT_SYNC_SCHED   (1U << 0)
#define HVTHEMIS_FEAT_ASYNC_SCHED  (1U << 1)
#define HVTHEMIS_FEAT_META_PAGES   (1U << 2)
#define HVTHEMIS_FEAT_THEMIC       (1U << 3)
#define HVTHEMIS_FEAT_DEVICE_ASSIGN (1U << 4)

/* ── Scheduling policy (Themis extension to create_partition) ──────────────── */

#define HVTHEMIS_SCHED_SYNC   0
#define HVTHEMIS_SCHED_ASYNC  1

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

struct mshv_create_partition {
	__u64 cores_mask;     /* Allowed physical cores (bitmap); ~0 = all */
	__u64 api_flags;      /* Allowed monitor API calls (MonitorAPI bits); ~0 = all */
	__u32 sched_policy;   /* HVTHEMIS_SCHED_SYNC or HVTHEMIS_SCHED_ASYNC */
	__u32 num_vps;        /* Number of VPs to allocate */
};

struct mshv_create_vp {
	__u32 vp_index;
	__u32 rsvd;
};

struct mshv_set_guest_memory {
	__u64 guest_pfn;       /* GPA >> 12 */
	__u64 userspace_addr;
	__u64 size;            /* bytes */
	__u32 flags;           /* map=0, unmap=1 */
	__u32 rsvd;
};

#define MSHV_SET_MEM_FLAG_UNMAP  1

struct mshv_vp_registers {
	__u32 count;
	__u32 rsvd;
	/* Followed by count × {name, value} pairs.
	 * For now stub — will be defined when P15d is implemented. */
};

struct mshv_run_vp {
	__u8 msg_buf[256];     /* MSHV intercept message on return */
};

struct mshv_irqfd {
	__s32 fd;
	__u32 gsi;
	__u32 flags;
	__u32 rsvd;
};

struct mshv_ioeventfd {
	__s32 fd;
	__u32 flags;
	__u64 addr;
	__u32 len;
	__u32 datamatch;
};

struct mshv_msi_routing {
	__u32 nr;
	__u32 rsvd;
	/* Followed by nr × mshv_user_irq_entry (defined at impl time). */
};

struct mshv_check_extension {
	__u32 ext_id;
	__u32 rsvd;
};

/* ── Device-level ioctls ───────────────────────────────────────────────────── */

#define MSHV_CREATE_PARTITION \
	_IOWR(MSHV_IOCTL_MAGIC, 0x01, struct mshv_create_partition)
#define MSHV_CHECK_EXTENSION \
	_IOWR(MSHV_IOCTL_MAGIC, 0x02, struct mshv_check_extension)

/* ── Partition-level ioctls ────────────────────────────────────────────────── */

#define MSHV_INITIALIZE_PARTITION \
	_IO(MSHV_IOCTL_MAGIC, 0x10)
#define MSHV_CREATE_VP \
	_IOWR(MSHV_IOCTL_MAGIC, 0x11, struct mshv_create_vp)
#define MSHV_SET_GUEST_MEMORY \
	_IOW(MSHV_IOCTL_MAGIC, 0x12, struct mshv_set_guest_memory)
#define MSHV_IRQFD \
	_IOW(MSHV_IOCTL_MAGIC, 0x13, struct mshv_irqfd)
#define MSHV_IOEVENTFD \
	_IOW(MSHV_IOCTL_MAGIC, 0x14, struct mshv_ioeventfd)
#define MSHV_SET_MSI_ROUTING \
	_IOW(MSHV_IOCTL_MAGIC, 0x15, struct mshv_msi_routing)
#define MSHV_GET_GPAP_ACCESS_BITMAP \
	_IO(MSHV_IOCTL_MAGIC, 0x16)

/* ── VP-level ioctls ───────────────────────────────────────────────────────── */

#define MSHV_RUN_VP \
	_IOWR(MSHV_IOCTL_MAGIC, 0x20, struct mshv_run_vp)
#define MSHV_GET_VP_STATE \
	_IOWR(MSHV_IOCTL_MAGIC, 0x21, struct mshv_vp_registers)
#define MSHV_SET_VP_STATE \
	_IOW(MSHV_IOCTL_MAGIC, 0x22, struct mshv_vp_registers)

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
struct hvthemis_partition;
struct hvthemis_vp;

/* Per-partition state. */
struct hvthemis_partition {
	u64 domain_handle;
	u64 domain_id;
	u32 sched_policy;
	u32 num_vps;
	bool sealed;

	struct hvthemis_vp **vps;

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
struct hvthemis_vp {
	u32 vp_index;
	struct hvthemis_partition *partition;
	struct mutex run_lock;

	/* Async mode waitqueue. */
	wait_queue_head_t exit_wq;
	atomic_t exit_pending;

	/* Exit info buffer for userspace. */
	u8 exit_msg[256];

	struct file *file;
};

/* Memory region tracking node (rb-tree). */
struct hvthemis_mem_region {
	struct rb_node node;
	u64 guest_pfn;
	u64 nr_pages;
	u64 userspace_addr;
	u64 cap_handle;
	struct page **pages;
	u8 flags;
};

/* ── Functions exported between translation units ──────────────────────────── */

/* hvthemis_hvcall.c — generic fallback */
int hvthemis_hcall(u64 opcode, u64 arg0, u64 arg1, u64 arg2,
		   u64 *out0, u64 *out1, u64 *out2);

/*
 * Typed Rust FFI wrappers (from libthemis.a, feature = "ffi").
 * All return 0 on success, negative errno on failure.
 * Prefer these over hvthemis_hcall() for type safety and sync with
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

/* hvthemis_part.c */
long hvthemis_partition_create(struct file *dev_file, void __user *uarg);
extern const struct file_operations hvthemis_partition_fops;

/* hvthemis_vp.c */
long hvthemis_vp_create(struct hvthemis_partition *part, void __user *uarg);
extern const struct file_operations hvthemis_vp_fops;

#endif /* __KERNEL__ */

#endif /* _HVTHEMIS_H */
