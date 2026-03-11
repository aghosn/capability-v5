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
#include <asm/cpuid.h>

#include "thhv.h"

#define THHV_DEV_NAME "thhv"

/* ── CPUID detection ───────────────────────────────────────────────────────── */

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
 * META pages needed per VP: VMCS (1) + VAPIC (1).
 * Shared per-domain pages (MSR bitmap, IO bitmaps, EPT) are accounted
 * separately by userspace or via additional query types.
 */
#define THHV_META_PAGES_PER_VP  2

static long thhv_dev_query(void __user *uarg)
{
	struct thhv_query q;

	if (copy_from_user(&q, uarg, sizeof(q)))
		return -EFAULT;

	switch (q.query_type) {
	case THHV_QUERY_META_PAGES_PER_VP:
		q.result = THHV_META_PAGES_PER_VP;
		break;
	default:
		return -EINVAL;
	}

	if (copy_to_user(uarg, &q, sizeof(q)))
		return -EFAULT;

	return 0;
}

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

	default:
		return -ENOTTY;
	}
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

static const struct file_operations thhv_dev_fops = {
	.owner          = THIS_MODULE,
	.open           = thhv_dev_open,
	.release        = thhv_dev_release,
	.unlocked_ioctl = thhv_dev_ioctl,
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

	ret = misc_register(&thhv_misc);
	if (ret) {
		pr_err("thhv: failed to register /dev/%s (err %d)\n",
		       THHV_DEV_NAME, ret);
		return ret;
	}

	pr_info("thhv: /dev/%s registered\n", THHV_DEV_NAME);
	return 0;
}

static void __exit thhv_exit(void)
{
	misc_deregister(&thhv_misc);
	pr_info("thhv: /dev/%s unregistered\n", THHV_DEV_NAME);
}

module_init(thhv_init);
module_exit(thhv_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Adrien Ghosn");
MODULE_DESCRIPTION("thhv — Themis capability-aware /dev/thhv driver");
