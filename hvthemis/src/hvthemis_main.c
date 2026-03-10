// SPDX-License-Identifier: GPL-2.0
/*
 * hvthemis_main.c — Module init, CPUID detection, /dev/mshv character device.
 *
 * Registers a misc device at /dev/mshv.  On open, returns a device fd whose
 * ioctls create partition fds (which in turn create VP fds).
 */

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <asm/cpuid.h>

#include "hvthemis.h"

#define HVTHEMIS_DEV_NAME "mshv"

/* ── CPUID detection ───────────────────────────────────────────────────────── */

static bool hvthemis_detect(void)
{
	u32 eax, ebx, ecx, edx;

	cpuid(HVTHEMIS_CPUID_LEAF, &eax, &ebx, &ecx, &edx);

	if (ebx != HVTHEMIS_SIG_EBX ||
	    ecx != HVTHEMIS_SIG_ECX ||
	    edx != HVTHEMIS_SIG_EDX) {
		pr_info("hvthemis: CPUID 0x40000000 vendor mismatch — not running under Themis\n");
		return false;
	}

	pr_info("hvthemis: detected Themis capavisor (max leaf 0x%x)\n", eax);
	return true;
}

/* ── Device-level ioctl dispatch ───────────────────────────────────────────── */

static long hvthemis_dev_ioctl(struct file *file, unsigned int cmd,
			       unsigned long arg)
{
	void __user *uarg = (void __user *)arg;

	switch (cmd) {
	case MSHV_CREATE_PARTITION:
		return hvthemis_partition_create(file, uarg);

	case MSHV_CHECK_EXTENSION:
		/* Stub: report no extensions supported yet. */
		return -ENOSYS;

	default:
		return -ENOTTY;
	}
}

/* ── Device fd file_operations ─────────────────────────────────────────────── */

static int hvthemis_dev_open(struct inode *inode, struct file *file)
{
	/* No per-device state needed at the device fd level. */
	return 0;
}

static int hvthemis_dev_release(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations hvthemis_dev_fops = {
	.owner          = THIS_MODULE,
	.open           = hvthemis_dev_open,
	.release        = hvthemis_dev_release,
	.unlocked_ioctl = hvthemis_dev_ioctl,
};

/* ── Misc device ───────────────────────────────────────────────────────────── */

static struct miscdevice hvthemis_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = HVTHEMIS_DEV_NAME,
	.fops  = &hvthemis_dev_fops,
};

/* ── Module init / exit ────────────────────────────────────────────────────── */

static int __init hvthemis_init(void)
{
	int ret;

	if (!hvthemis_detect())
		return -ENODEV;

	ret = misc_register(&hvthemis_misc);
	if (ret) {
		pr_err("hvthemis: failed to register /dev/%s (err %d)\n",
		       HVTHEMIS_DEV_NAME, ret);
		return ret;
	}

	pr_info("hvthemis: /dev/%s registered\n", HVTHEMIS_DEV_NAME);
	return 0;
}

static void __exit hvthemis_exit(void)
{
	misc_deregister(&hvthemis_misc);
	pr_info("hvthemis: /dev/%s unregistered\n", HVTHEMIS_DEV_NAME);
}

module_init(hvthemis_init);
module_exit(hvthemis_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Adrien Ghosn");
MODULE_DESCRIPTION("hvthemis — Themis capability-aware /dev/mshv driver");
