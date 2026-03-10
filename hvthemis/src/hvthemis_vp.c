// SPDX-License-Identifier: GPL-2.0
/*
 * hvthemis_vp.c — VP fd lifecycle and ioctl dispatch.
 *
 * A VP fd is returned by MSHV_CREATE_VP on a partition fd.
 * It wraps a single virtual processor within a Themis domain.
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/anon_inodes.h>
#include <linux/uaccess.h>

#include "hvthemis.h"

/* ── VP-level ioctl dispatch ───────────────────────────────────────────────── */

static long hvthemis_vp_ioctl(struct file *file, unsigned int cmd,
			      unsigned long arg)
{
	/* struct hvthemis_vp *vp = file->private_data; */

	switch (cmd) {
	case MSHV_RUN_VP:
		/* TODO(P15f): VMCALL_SWITCH (sync) or START_VP + wait (async) */
		return -ENOSYS;

	case MSHV_GET_VP_STATE:
		/* TODO(P15d): VMCALL_GET_REG or read META page */
		return -ENOSYS;

	case MSHV_SET_VP_STATE:
		/* TODO(P15d): VMCALL_SET_REG or write META page */
		return -ENOSYS;

	default:
		return -ENOTTY;
	}
}

/* ── VP fd mmap (META page mapping) ────────────────────────────────────────── */

static int hvthemis_vp_mmap(struct file *file, struct vm_area_struct *vma)
{
	/* TODO(P15h): remap_pfn_range for META VP-state page */
	return -ENOSYS;
}

/* ── VP fd file_operations ─────────────────────────────────────────────────── */

static int hvthemis_vp_release(struct inode *inode, struct file *file)
{
	struct hvthemis_vp *vp = file->private_data;
	struct hvthemis_partition *part = vp->partition;

	/*
	 * TODO(P15d): Stop VP if running (async mode), cleanup ThemIC pages.
	 * The VP slot in part->vps[vp->vp_index] is freed here; the partition
	 * refcount is dropped when the partition fd is closed.
	 */

	part->vps[vp->vp_index] = NULL;
	kfree(vp);
	return 0;
}

const struct file_operations hvthemis_vp_fops = {
	.owner          = THIS_MODULE,
	.release        = hvthemis_vp_release,
	.unlocked_ioctl = hvthemis_vp_ioctl,
	.mmap           = hvthemis_vp_mmap,
};

/* ── MSHV_CREATE_VP handler (called from partition ioctl) ──────────────────── */

long hvthemis_vp_create(struct hvthemis_partition *part, void __user *uarg)
{
	struct mshv_create_vp cv;
	struct hvthemis_vp *vp;
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

	file = anon_inode_getfile("mshv-vp", &hvthemis_vp_fops,
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
