/* SPDX-License-Identifier: GPL-2.0 */
/*
 * thhv_internal.h — Private kernel-only definitions for the thhv driver.
 *
 * All driver-internal structs (thhv_partition, thhv_vp, …), inline helpers,
 * and the function prototypes shared between translation units live here.
 *
 * UAPI definitions (ioctl numbers, ABI structs, hypercall opcodes, …) stay
 * in <inc/thhv.h>, which userspace and kernel both consume.  This header is
 * deliberately not exposed via the public include path.
 *
 * Every .c file under src/ should `#include "thhv_internal.h"` instead of
 * `#include "thhv.h"`; the public UAPI header is pulled in transitively.
 */

#ifndef _THHV_INTERNAL_H
#define _THHV_INTERNAL_H

#include "thhv.h"

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
 * Per-irqfd entry: when the eventfd fires, inject `vector` into the
 * specified VP of the partition via INJECT_INTERRUPT.
 */
struct thhv_irqfd_entry {
	struct list_head   node;
	u32                gsi;
	u32                vector;       /* MSI routing lookup result (TODO) */
	u32                vp_index;     /* target VP for interrupt injection */
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

	/* Membership in the global partitions list (thhv_main.c).  Used by the
	 * device-level THHV_DEBUG_LIST_HPAS ioctl so any process opening
	 * /dev/thhv can enumerate carved HPAs without owning the partition fd. */
	struct list_head global_node;

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

	/* Channel capability handle: a channel pointing back to the parent
	 * (dom0), automatically created and sent to the child at domain
	 * creation.  The child accepts it to send capabilities back. */
	u64 chan_handle;

	/* Per-domain DomainComm pages: kernel-allocated, sent to child with
	 * COMM attribute so the capavisor initialises the child's DomainComm
	 * ring at seal time.  After send, the caps belong to the child; only
	 * the struct page pointers are kept for __free_page on teardown. */
#define DOMCOMM_NR_PAGES 4
#define DOMCOMM_ORDER    2  /* log2(DOMCOMM_NR_PAGES) */

	struct page **domcomm_pages;
	unsigned int  domcomm_nr_pages;
};

/* Per-VP state. */
struct thhv_vp {
	u32 vp_index;
	struct thhv_partition *partition;
	struct mutex run_lock;

	/* Async mode waitqueue. */
	wait_queue_head_t exit_wq;
	atomic_t exit_pending;

	/* MP state: software wait-for-SIPI.
	 * 0 = runnable, 3 = waiting-for-SIPI.
	 * When mp_state == 3, thhv_vp_run() blocks on sipi_wq until
	 * a SET_VP_STATE(ACTIVITY_STATE=0) transitions mp_state to 0.
	 * This mirrors KVM's in-kernel MP state management. */
	int mp_state;
	wait_queue_head_t sipi_wq;

	/* HLT blocking: when the guest executes HLT, the VP thread blocks
	 * on halt_wq until an interrupt is injected (via irqfd or IPI).
	 * This prevents busy-spinning in the CHV vCPU run loop.
	 *
	 * `halted` is atomic because it is written by the VP thread (HLT
	 * exit handler) and read/cleared by the irqfd work handler
	 * (thhv_wake_vp) which runs on a different CPU. */
	atomic_t halted;
	atomic_t pending_inject; /* counts injects since last SWITCH */
	wait_queue_head_t halt_wq;

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
int themis_send_chan(u64 chan, u64 receiver, u64 attrs);
int themis_accept_chan(u64 pending_id, u64 *out_handle);
int themis_attest_self(u32 mode, u64 offset, u64 tx_sequence,
		       u64 *out_total, u64 *out_wrote);
int themis_read_pcr(u32 pcr_index, u64 *out_r0, u64 *out_r1, u64 *out_r2);
int themis_attest(u64 domain, u64 *out_lo, u64 *out_hi);
int themis_get_reg(u64 domain, u64 vp_id, u64 reg, u64 *out_val);
int themis_set_reg(u64 domain, u64 vp_id, u64 reg, u64 value);
int themis_set_policy(u64 domain, u64 kind, u64 key, u64 sub_key, u64 value);
int themis_assign_device(u64 domain, u64 pci_bdf);
int themis_register_comm(u64 cap, u64 child_domain, u64 vp_id);
int themis_add_vp(u64 child_domain, u64 comm_cap);
int themis_map_self(u64 cap_handle, u64 new_gpa);
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
void thhv_wake_vp(struct thhv_partition *part, u32 vp_index);
extern const struct file_operations thhv_vp_fops;

/* thhv_shmem.c — capability-backed shared memory (ivshmem rendezvous) */
long thhv_shmem_handle(struct thhv_partition *part,
		       struct thhv_set_guest_memory *gm);
long thhv_shmem_create_post(struct thhv_partition *part,
			    struct thhv_set_guest_memory *gm,
			    u64 parent_handle, u64 hpa_start, u64 hpa_size);
void thhv_shmem_cleanup_partition(struct thhv_partition *part);
void thhv_shmem_init(void);
void thhv_shmem_cleanup(void);

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

/* Worst-case EPT-intermediate page count for [gpa, gpa+size) (thhv_part_mem.c). */
unsigned int thhv_ept_meta_needed(u64 gpa, u64 size);

/* THHV_SET_GUEST_MEMORY ioctl handler (thhv_part_mem.c). */
long thhv_set_guest_memory(struct thhv_partition *part, void __user *uarg);

/* THHV_DEBUG_LIST_HPAS — device-level ioctl (thhv_main.c).  Walks the global
 * partitions list registered by thhv_partitions_register.  When
 * args.domain_handle is 0, returns carved HPAs for ALL partitions; otherwise
 * filters to the matching one.  Skips THHV_MEM_F_ALIAS regions. */
long thhv_debug_list_hpas(void __user *uarg);

/* Per-partition collector used by thhv_debug_list_hpas (thhv_part_mem.c). */
void thhv_collect_carved_runs(struct thhv_partition *part,
			      struct thhv_debug_hpa_range *scratch,
			      u32 cap,
			      u32 *nr_total,
			      u64 *cur_hpa,
			      u64 *cur_pages);

/* Global partitions list (thhv_main.c) — used by thhv_debug_list_hpas. */
void thhv_partitions_register(struct thhv_partition *part);
void thhv_partitions_unregister(struct thhv_partition *part);

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
			const void *payload, u32 payload_size,
			u64 *out_sequence);
int  domcomm_request_grow(bool grow_rx, u32 nr_pages);

/* Global DomainComm instance. */
extern struct domcomm_state thhv_domcomm;

#endif /* __KERNEL__ */

#endif /* _THHV_INTERNAL_H */
