// SPDX-License-Identifier: GPL-2.0
/*
 * thhv_main.c — Module init, CPUID detection, /dev/thhv character device.
 *
 * Registers a misc device at /dev/thhv.  On open, returns a device fd whose
 * ioctls create partition fds (which in turn create VP fds).
 */

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/mm.h>
#include <asm/cpuid.h>

#include "thhv_internal.h"

#define THHV_DEV_NAME "thhv"

static DEFINE_MUTEX(attest_lock);

/* ── Global partitions list (THHV_DEBUG_LIST_HPAS) ─────────────────────────
 *
 * Each successfully-created thhv_partition links itself onto this list via
 * thhv_partitions_register, and unlinks in thhv_partitions_unregister at
 * teardown.  The list lets the device-level THHV_DEBUG_LIST_HPAS ioctl
 * enumerate carved HPAs without holding the partition fd (which is owned
 * by the VMM process, not the attacker test).
 */
static LIST_HEAD(thhv_partitions);
static DEFINE_SPINLOCK(thhv_partitions_lock);

void thhv_partitions_register(struct thhv_partition *part)
{
	spin_lock(&thhv_partitions_lock);
	list_add_tail(&part->global_node, &thhv_partitions);
	spin_unlock(&thhv_partitions_lock);
}

void thhv_partitions_unregister(struct thhv_partition *part)
{
	spin_lock(&thhv_partitions_lock);
	if (!list_empty(&part->global_node))
		list_del_init(&part->global_node);
	spin_unlock(&thhv_partitions_lock);
}

/* ── CPUID detection ───────────────────────────────────────────────────────── */

/**
 * thhv_detect - Detect Themis capavisor via CPUID leaf 0x40000000.
 *
 * Returns true if the "ThemisCapa" vendor string is present.
 */
static bool thhv_detect(void)
{
	u32 eax, ebx, ecx, edx;

	cpuid(THHV_CPUID_LEAF, &eax, &ebx, &ecx, &edx);

	if (ebx != THHV_SIG_EBX ||
	    ecx != THHV_SIG_ECX ||
	    edx != THHV_SIG_EDX) {
		pr_info("thhv: CPUID 0x40000000 vendor mismatch — not running under Themis\n");
		return false;
	}

	pr_info("thhv: detected Themis capavisor (max leaf 0x%x)\n", eax);
	return true;
}

/* ── Device-level ioctl dispatch ───────────────────────────────────────────── */

/*
 * META pages needed per VP is defined in thhv.h (THHV_META_PAGES_PER_VP).
 * Shared per-domain pages (MSR bitmap, IO bitmaps, EPT) are accounted
 * separately by userspace or via additional query types.
 */

static long thhv_dev_query(void __user *uarg)
{
	struct thhv_query q;

	if (copy_from_user(&q, uarg, sizeof(q)))
		return -EFAULT;

	switch (q.query_type) {
	case THHV_QUERY_META_PAGES_PER_VP:
		q.result = THHV_META_PAGES_PER_VP;
		break;
	case THHV_QUERY_META_PAGES_SHARED:
		q.result = THHV_META_PAGES_SHARED;
		break;
	default:
		return -EINVAL;
	}

	if (copy_to_user(uarg, &q, sizeof(q)))
		return -EFAULT;

	return 0;
}

/* ── Test infrastructure (CONFIG_THHV_TEST) ────────────────────────────────── */

#ifdef CONFIG_THHV_TEST

static long thhv_test_cmd(void __user *uarg)
{
	struct thhv_test_cmd cmd;
	int ret;

	if (copy_from_user(&cmd, uarg, sizeof(cmd)))
		return -EFAULT;

	switch (cmd.command) {
	case THHV_TEST_CMD_GROW_RX:
		pr_info("thhv: TEST grow RX by %u pages\n", cmd.arg);
		ret = domcomm_request_grow(true, cmd.arg ? cmd.arg : 1);
		break;

	case THHV_TEST_CMD_GROW_TX:
		pr_info("thhv: TEST grow TX by %u pages\n", cmd.arg);
		ret = domcomm_request_grow(false, cmd.arg ? cmd.arg : 1);
		break;

	default:
		ret = -EINVAL;
		break;
	}

	cmd.result = ret;
	if (copy_to_user(uarg, &cmd, sizeof(cmd)))
		return -EFAULT;

	return ret;
}

#endif /* CONFIG_THHV_TEST */

static long thhv_dev_ioctl(struct file *file, unsigned int cmd,
			       unsigned long arg)
{
	void __user *uarg = (void __user *)arg;

	switch (cmd) {
	case THHV_CREATE_PARTITION:
		return thhv_partition_create(file, uarg);

	case THHV_CHECK_EXTENSION:
		/* Stub: report no extensions supported yet. */
		return -ENOSYS;

	case THHV_QUERY:
		return thhv_dev_query(uarg);

	case THHV_ATTEST_SELF: {
		struct thhv_attest_self *as;
		u64 total_size = 0;
		u64 offset = 0;
		u64 wrote = 0;
		u32 rx_msg_type;
		u32 rx_chunk_size;
		u64 tx_sequence = 0;
		int is_signed = 0;
		int ret, i;

		as = kmalloc(sizeof(*as), GFP_KERNEL);
		if (!as)
			return -ENOMEM;

		if (copy_from_user(as, uarg, sizeof(*as))) {
			kfree(as);
			return -EFAULT;
		}

		for (i = 0; i < 32; i++) {
			if (as->nonce[i] != 0 || as->user_pub_key[i] != 0) {
				is_signed = 1;
				break;
			}
		}

		mutex_lock(&attest_lock);

		if (is_signed) {
			/* Signed path: enqueue AttestRequest on TX before
			 * the first hypercall — capavisor consumes it to
			 * build the signed envelope. */
			u8 req_payload[64];

			memcpy(req_payload, as->nonce, 32);
			memcpy(req_payload + 32, as->user_pub_key, 32);

			ret = domcomm_tx_enqueue(&thhv_domcomm.tx,
						DOMCOMM_MSG_ATTEST_REQ,
						req_payload, 64,
						&tx_sequence);
			if (ret)
				goto attest_unlock_err;
		}

		/* First hypercall: discover total size + enqueue first chunk. */
		ret = themis_attest_self(is_signed ? 1 : 0, 0, tx_sequence,
					 &total_size, &wrote);
		if (ret)
			goto attest_unlock_err;

		if (total_size == 0 || total_size > sizeof(as->report_buf)) {
			pr_err("thhv: ATTEST_SELF total %llu does not fit user buffer (%zu)\n",
			       total_size, sizeof(as->report_buf));
			ret = -EMSGSIZE;
			goto attest_unlock_err;
		}

		/* Reassemble chunks into the userspace buffer.  The signed
		 * path's AttestRequest is consumed by the first hypercall
		 * call only; subsequent chunk calls pass tx_sequence=0. */
		for (;;) {
			ret = domcomm_rx_dequeue(&thhv_domcomm.rx,
						 as->report_buf + offset,
						 (u32)(total_size - offset),
						 &rx_msg_type,
						 &rx_chunk_size);
			if (ret)
				goto attest_unlock_err;
			if (rx_msg_type != DOMCOMM_MSG_ATTEST) {
				ret = -EPROTO;
				goto attest_unlock_err;
			}
			offset += rx_chunk_size;
			if (offset >= total_size)
				break;
			ret = themis_attest_self(is_signed ? 1 : 0, offset, 0,
						 &total_size, &wrote);
			if (ret)
				goto attest_unlock_err;
		}

		mutex_unlock(&attest_lock);

		as->report_size = total_size;

		if (copy_to_user(uarg, as, sizeof(*as)))
			ret = -EFAULT;

		kfree(as);
		return ret;

attest_unlock_err:
		mutex_unlock(&attest_lock);
		kfree(as);
		return ret;
	}

	case THHV_READ_PCR: {
		struct thhv_read_pcr rp;
		u64 r0, r1, r2;
		int ret;

		if (copy_from_user(&rp, uarg, sizeof(rp)))
			return -EFAULT;

		ret = themis_read_pcr(rp.pcr_index, &r0, &r1, &r2);
		if (ret)
			return ret;

		memcpy(&rp.digest[0],  &r0, 8);
		memcpy(&rp.digest[8],  &r1, 8);
		memcpy(&rp.digest[16], &r2, 8);
		if (copy_to_user(uarg, &rp, sizeof(rp)))
			return -EFAULT;
		return 0;
	}

	/*
	 * THHV_SET_PA_MAP is intentionally not exposed here.
	 * The PA map should be populated automatically by the driver
	 * from the capavisor's attestation data at init time.
	 * See thhv_pa_map_init_from_attestation() in thhv_translate.c.
	 */

#ifdef CONFIG_THHV_TEST
	case THHV_TEST:
		return thhv_test_cmd(uarg);
#endif

	case THHV_DEBUG_LIST_HPAS:
		return thhv_debug_list_hpas(uarg);

	default:
		return -ENOTTY;
	}
}

/* ── THHV_DEBUG_LIST_HPAS implementation ───────────────────────────────────
 *
 * Allocates a kernel scratch buffer (cap = max_entries), iterates the global
 * partitions list under thhv_partitions_lock, and for each partition matching
 * args.domain_handle (0 = all) calls thhv_collect_carved_runs to fill
 * scratch with carved HPA runs.  After dropping the lock, copies up to
 * min(nr_total, cap) entries to userspace; nr_total reports the actual
 * number available so callers can grow their buffer and retry.
 */
long thhv_debug_list_hpas(void __user *uarg)
{
	struct thhv_debug_list_hpas args;
	struct thhv_debug_hpa_range __user *user_entries;
	struct thhv_debug_hpa_range *scratch = NULL;
	struct thhv_partition *part;
	u32 cap;
	u32 nr_total = 0;
	u64 cur_hpa = 0;
	u64 cur_pages = 0;
	long ret = 0;

	/* Debug ioctl: leaks domain physical layout — restrict to root. */
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (copy_from_user(&args, uarg, sizeof(args)))
		return -EFAULT;

	user_entries = (struct thhv_debug_hpa_range __user *)(uintptr_t)args.entries;
	if (args.max_entries && !user_entries)
		return -EINVAL;

	cap = args.max_entries;
	if (cap) {
		scratch = kvcalloc(cap, sizeof(*scratch), GFP_KERNEL);
		if (!scratch)
			return -ENOMEM;
	}

	spin_lock(&thhv_partitions_lock);
	list_for_each_entry(part, &thhv_partitions, global_node) {
		if (args.domain_handle != 0 &&
		    part->domain_handle != args.domain_handle)
			continue;
		thhv_collect_carved_runs(part, scratch, cap, &nr_total,
					 &cur_hpa, &cur_pages);
	}
	/* Flush the trailing run after iterating all partitions. */
	if (cur_pages) {
		if (nr_total < cap) {
			scratch[nr_total].hpa = cur_hpa;
			scratch[nr_total].nr_pages = cur_pages;
		}
		nr_total++;
	}
	spin_unlock(&thhv_partitions_lock);

	if (cap && nr_total) {
		u32 to_copy = min(nr_total, cap);

		if (copy_to_user(user_entries, scratch,
				 to_copy * sizeof(*scratch)))
			ret = -EFAULT;
	}
	kvfree(scratch);

	if (ret)
		return ret;

	args.nr_entries = nr_total;
	if (copy_to_user(uarg, &args, sizeof(args)))
		return -EFAULT;
	return 0;
}

/* ── Device fd file_operations ─────────────────────────────────────────────── */

static int thhv_dev_open(struct inode *inode, struct file *file)
{
	/* No per-device state needed at the device fd level. */
	return 0;
}

static int thhv_dev_release(struct inode *inode, struct file *file)
{
	return 0;
}

/* ── /dev/thhv mmap: map a host-physical page range into userspace ──────────
 *
 * Used by the coco-attacker isolation test: after THHV_DEBUG_LIST_HPAS
 * returns the HPA runs owned exclusively by a child domain, the attacker
 * mmaps those HPAs into its own address space and reads them.  An access
 * that hits a CARVE'd page faults at the EPT level → capavisor injects
 * #GP(0) → kernel SIGSEGV's the process → handler longjmps.
 *
 * `offset` parameter to mmap(2) is interpreted as the HPA (must be page-
 * aligned; mmap converts to vm_pgoff for us).  CAP_SYS_ADMIN gated: this
 * is a debug-only interface that lets root map arbitrary physical memory.
 */
static int thhv_dev_mmap(struct file *file, struct vm_area_struct *vma)
{
	unsigned long size = vma->vm_end - vma->vm_start;

	(void)file;
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff,
			    size, vma->vm_page_prot))
		return -EAGAIN;
	return 0;
}

static const struct file_operations thhv_dev_fops = {
	.owner          = THIS_MODULE,
	.open           = thhv_dev_open,
	.release        = thhv_dev_release,
	.unlocked_ioctl = thhv_dev_ioctl,
	.mmap           = thhv_dev_mmap,
};

/* ── Misc device ───────────────────────────────────────────────────────────── */

static struct miscdevice thhv_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = THHV_DEV_NAME,
	.fops  = &thhv_dev_fops,
};

/* ── Module init / exit ────────────────────────────────────────────────────── */

static int __init thhv_init(void)
{
	int ret;

	if (!thhv_detect())
		return -ENODEV;

	ret = thhv_pa_map_init_from_attestation();
	if (ret) {
		pr_err("thhv: PA map init failed (%d)\n", ret);
		return ret;
	}

	ret = misc_register(&thhv_misc);
	if (ret) {
		pr_err("thhv: failed to register /dev/%s (err %d)\n",
		       THHV_DEV_NAME, ret);
		return ret;
	}

	thhv_shmem_init();
	pr_info("thhv: /dev/%s registered\n", THHV_DEV_NAME);
	return 0;
}

static void __exit thhv_exit(void)
{
	misc_deregister(&thhv_misc);
	thhv_shmem_cleanup();
	thhv_pa_map_cleanup();
	pr_info("thhv: /dev/%s unregistered\n", THHV_DEV_NAME);
}

module_init(thhv_init);
module_exit(thhv_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Adrien Ghosn");
MODULE_DESCRIPTION("thhv — Themis capability-aware /dev/thhv driver");
