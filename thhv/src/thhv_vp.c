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
#include <linux/mm.h>

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

/* ── VP fd mmap (COMM page mapping) ────────────────────────────────────────── */

static int thhv_vp_mmap(struct file *file, struct vm_area_struct *vma)
{
	/* TODO(P15h): remap_pfn_range for META VP-state page */
	return -ENOSYS;
}

/* ── Page pinning helpers ──────────────────────────────────────────────────── */

static void thhv_vp_unpin_pages(struct thhv_vp *vp)
{
	unsigned int i;

	if (vp->comm_kaddr) {
		kunmap(vp->comm_page);
		vp->comm_kaddr = NULL;
	}
	if (vp->comm_page) {
		unpin_user_pages(&vp->comm_page, 1);
		vp->comm_page = NULL;
	}
	if (vp->meta_pages) {
		unpin_user_pages(vp->meta_pages, vp->meta_nr_pages);
		for (i = 0; i < vp->meta_nr_pages; i++)
			vp->meta_pages[i] = NULL;
		kfree(vp->meta_pages);
		vp->meta_pages = NULL;
		vp->meta_nr_pages = 0;
	}
}

static int thhv_vp_pin_pages(struct thhv_vp *vp,
			     u64 meta_uaddr, unsigned int meta_nr_pages,
			     u64 comm_uaddr)
{
	int ret;

	/* Pin META pages. */
	vp->meta_pages = kcalloc(meta_nr_pages, sizeof(struct page *),
				 GFP_KERNEL);
	if (!vp->meta_pages)
		return -ENOMEM;

	ret = pin_user_pages_fast(meta_uaddr, meta_nr_pages,
				  FOLL_WRITE | FOLL_LONGTERM,
				  vp->meta_pages);
	if (ret < 0)
		goto err;
	if (ret != (int)meta_nr_pages) {
		unpin_user_pages(vp->meta_pages, ret);
		ret = -EFAULT;
		goto err;
	}
	vp->meta_nr_pages = meta_nr_pages;

	/* Pin COMM page. */
	ret = pin_user_pages_fast(comm_uaddr, 1,
				  FOLL_WRITE | FOLL_LONGTERM,
				  &vp->comm_page);
	if (ret < 0)
		goto err_unpin_meta;
	if (ret != 1) {
		ret = -EFAULT;
		goto err_unpin_meta;
	}

	vp->comm_kaddr = kmap(vp->comm_page);
	vp->comm_phys = page_to_phys(vp->comm_page);

	return 0;

err_unpin_meta:
	unpin_user_pages(vp->meta_pages, vp->meta_nr_pages);
	vp->meta_nr_pages = 0;
err:
	kfree(vp->meta_pages);
	vp->meta_pages = NULL;
	return ret;
}

/* ── VP fd file_operations ─────────────────────────────────────────────────── */

static int thhv_vp_release(struct inode *inode, struct file *file)
{
	struct thhv_vp *vp = file->private_data;
	struct thhv_partition *part = vp->partition;

	/* TODO: Stop VP if running (async mode). */

	thhv_vp_unpin_pages(vp);

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
	unsigned int meta_nr;
	int fd, ret;

	if (copy_from_user(&cv, uarg, sizeof(cv)))
		return -EFAULT;

	if (cv.vp_index >= part->num_vps)
		return -EINVAL;
	if (part->vps[cv.vp_index])
		return -EEXIST;

	/* Validate META size. */
	meta_nr = THHV_META_PAGES_PER_VP;
	if (cv.meta_size != (u64)meta_nr * PAGE_SIZE)
		return -EINVAL;
	if (!cv.meta_uaddr || !cv.comm_uaddr)
		return -EINVAL;
	if (cv.meta_uaddr & ~PAGE_MASK || cv.comm_uaddr & ~PAGE_MASK)
		return -EINVAL;

	vp = kzalloc(sizeof(*vp), GFP_KERNEL);
	if (!vp)
		return -ENOMEM;

	vp->vp_index = cv.vp_index;
	vp->partition = part;
	mutex_init(&vp->run_lock);
	init_waitqueue_head(&vp->exit_wq);
	atomic_set(&vp->exit_pending, 0);

	/* Pin META + COMM pages from userspace. */
	ret = thhv_vp_pin_pages(vp, cv.meta_uaddr, meta_nr, cv.comm_uaddr);
	if (ret)
		goto err_free_vp;

	/*
	 * TODO(P15e): CARVE + SEND META pages to child domain.
	 * TODO(P15e): REGISTER_COMM for the COMM page.
	 */

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		ret = fd;
		goto err_unpin;
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
err_unpin:
	thhv_vp_unpin_pages(vp);
err_free_vp:
	kfree(vp);
	return ret;
}
