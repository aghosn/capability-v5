// SPDX-License-Identifier: GPL-2.0
/*
 * thhv_vp.c — VP fd lifecycle and ioctl dispatch.
 *
 * A VP fd is returned by THHV_CREATE_VP on a partition fd.
 * It wraps a single virtual processor within a Themis domain.
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/anon_inodes.h>
#include <linux/uaccess.h>

#include "thhv.h"

/* ── VP-level ioctl dispatch ───────────────────────────────────────────────── */

static long thhv_vp_get_state(struct thhv_vp *vp, void __user *uarg)
{
	struct thhv_partition *part = vp->partition;
	struct thhv_vp_registers hdr;
	struct thhv_reg_name_value *regs;
	u32 i;
	int ret;

	if (copy_from_user(&hdr, uarg, sizeof(hdr)))
		return -EFAULT;
	if (hdr.count == 0 || hdr.count > THHV_MAX_VP_REGS)
		return -EINVAL;

	regs = kmalloc_array(hdr.count, sizeof(*regs), GFP_KERNEL);
	if (!regs)
		return -ENOMEM;

	if (copy_from_user(regs, (void __user *)hdr.regs,
			   hdr.count * sizeof(*regs))) {
		ret = -EFAULT;
		goto out;
	}

	for (i = 0; i < hdr.count; i++) {
		ret = themis_get_reg(part->domain_handle, vp->vp_index,
				     regs[i].name, &regs[i].value);
		if (ret)
			goto out;
	}

	if (copy_to_user((void __user *)hdr.regs, regs,
			 hdr.count * sizeof(*regs))) {
		ret = -EFAULT;
		goto out;
	}

	ret = 0;
out:
	kfree(regs);
	return ret;
}

static long thhv_vp_set_state(struct thhv_vp *vp, void __user *uarg)
{
	struct thhv_partition *part = vp->partition;
	struct thhv_vp_registers hdr;
	struct thhv_reg_name_value *regs;
	u32 i;
	int ret;

	if (copy_from_user(&hdr, uarg, sizeof(hdr)))
		return -EFAULT;
	if (hdr.count == 0 || hdr.count > THHV_MAX_VP_REGS)
		return -EINVAL;

	regs = kmalloc_array(hdr.count, sizeof(*regs), GFP_KERNEL);
	if (!regs)
		return -ENOMEM;

	if (copy_from_user(regs, (void __user *)hdr.regs,
			   hdr.count * sizeof(*regs))) {
		ret = -EFAULT;
		goto out;
	}

	for (i = 0; i < hdr.count; i++) {
		ret = themis_set_reg(part->domain_handle, vp->vp_index,
				     regs[i].name, regs[i].value);
		if (ret)
			goto out;
	}

	ret = 0;
out:
	kfree(regs);
	return ret;
}

static long thhv_vp_ioctl(struct file *file, unsigned int cmd,
			      unsigned long arg)
{
	struct thhv_vp *vp = file->private_data;
	void __user *uarg = (void __user *)arg;

	switch (cmd) {
	case THHV_RUN_VP:
		/* TODO(P15f): VMCALL_SWITCH (sync) or START_VP + wait (async) */
		return -ENOSYS;

	case THHV_GET_VP_STATE:
		return thhv_vp_get_state(vp, uarg);

	case THHV_SET_VP_STATE:
		return thhv_vp_set_state(vp, uarg);

	default:
		return -ENOTTY;
	}
}

/* ── VP fd mmap (META page mapping) ────────────────────────────────────────── */

static int thhv_vp_mmap(struct file *file, struct vm_area_struct *vma)
{
	/* TODO(P15h): remap_pfn_range for META VP-state page */
	return -ENOSYS;
}

/* ── VP fd file_operations ─────────────────────────────────────────────────── */

static int thhv_vp_release(struct inode *inode, struct file *file)
{
	struct thhv_vp *vp = file->private_data;
	struct thhv_partition *part = vp->partition;

	/*
	 * TODO(P15d): Stop VP if running (async mode), cleanup ThemIC pages.
	 * The VP slot in part->vps[vp->vp_index] is freed here; the partition
	 * refcount is dropped when the partition fd is closed.
	 */

	part->vps[vp->vp_index] = NULL;
	kfree(vp);
	return 0;
}

const struct file_operations thhv_vp_fops = {
	.owner          = THIS_MODULE,
	.release        = thhv_vp_release,
	.unlocked_ioctl = thhv_vp_ioctl,
	.mmap           = thhv_vp_mmap,
};

/* ── THHV_CREATE_VP handler (called from partition ioctl) ──────────────────── */

long thhv_vp_create(struct thhv_partition *part, void __user *uarg)
{
	struct thhv_create_vp cv;
	struct thhv_vp *vp;
	struct file *file;
	int fd, ret;

	if (copy_from_user(&cv, uarg, sizeof(cv)))
		return -EFAULT;

	if (cv.vp_index >= part->num_vps)
		return -EINVAL;

	if (part->vps[cv.vp_index])
		return -EEXIST;

	vp = kzalloc(sizeof(*vp), GFP_KERNEL);
	if (!vp)
		return -ENOMEM;

	vp->vp_index = cv.vp_index;
	vp->partition = part;
	mutex_init(&vp->run_lock);
	init_waitqueue_head(&vp->exit_wq);
	atomic_set(&vp->exit_pending, 0);

	/*
	 * TODO(P15d): Allocate ThemIC pages, register COMM pages via
	 * VMCALL_REGISTER_COMM for this VP.
	 */

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		ret = fd;
		goto err_free_vp;
	}

	file = anon_inode_getfile("thhv-vp", &thhv_vp_fops,
				  vp, O_RDWR | O_CLOEXEC);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		goto err_put_fd;
	}

	vp->file = file;
	part->vps[cv.vp_index] = vp;
	fd_install(fd, file);
	return fd;

err_put_fd:
	put_unused_fd(fd);
err_free_vp:
	kfree(vp);
	return ret;
}
