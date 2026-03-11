// SPDX-License-Identifier: GPL-2.0
/*
 * thhv_part.c — Partition fd lifecycle and ioctl dispatch.
 *
 * A partition fd is returned by THHV_CREATE_PARTITION on the device fd.
 * It wraps a Themis domain and tracks VPs, memory mappings, IRQfds, etc.
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/anon_inodes.h>
#include <linux/uaccess.h>
#include <linux/mm.h>

#include "thhv.h"

/* ── Partition cleanup ─────────────────────────────────────────────────────── */

static void thhv_partition_destroy(struct kref *ref)
{
	struct thhv_partition *part =
		container_of(ref, struct thhv_partition, refcount);
	int ret;
	u32 i;

	/* Revoke the domain in the capavisor (recursively tears down children). */
	if (part->domain_handle) {
		ret = themis_revoke_domain(part->domain_handle);
		if (ret)
			pr_warn("thhv: REVOKE_DOMAIN 0x%llx failed (%d)\n",
				part->domain_handle, ret);
	}

	if (part->vps) {
		for (i = 0; i < part->num_vps; i++)
			kfree(part->vps[i]);
		kfree(part->vps);
	}

	/* Unpin shared META pages. */
	if (part->shared_meta_pages) {
		unpin_user_pages(part->shared_meta_pages,
				 part->shared_meta_nr_pages);
		kfree(part->shared_meta_pages);
	}

	/* TODO: free mem regions rb-tree, irqfds, ioeventfds */

	kfree(part);
}

/* ── Partition-level ioctl dispatch ────────────────────────────────────────── */

static long thhv_part_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	struct thhv_partition *part = file->private_data;
	void __user *uarg = (void __user *)arg;
	int ret;

	switch (cmd) {
	case THHV_INITIALIZE_PARTITION: {
		struct thhv_initialize_partition ip;

		if (part->sealed)
			return -EBUSY;
		if (copy_from_user(&ip, uarg, sizeof(ip)))
			return -EFAULT;
		if (ip.meta_size != (u64)THHV_META_PAGES_SHARED * PAGE_SIZE)
			return -EINVAL;
		if (!ip.meta_uaddr || (ip.meta_uaddr & ~PAGE_MASK))
			return -EINVAL;

		/* Pin shared META pages (MSR bitmap + IO bitmaps). */
		part->shared_meta_pages = kcalloc(THHV_META_PAGES_SHARED,
						  sizeof(struct page *),
						  GFP_KERNEL);
		if (!part->shared_meta_pages)
			return -ENOMEM;

		ret = pin_user_pages_fast(ip.meta_uaddr, THHV_META_PAGES_SHARED,
					  FOLL_WRITE | FOLL_LONGTERM,
					  part->shared_meta_pages);
		if (ret < 0) {
			kfree(part->shared_meta_pages);
			part->shared_meta_pages = NULL;
			return ret;
		}
		if (ret != THHV_META_PAGES_SHARED) {
			unpin_user_pages(part->shared_meta_pages, ret);
			kfree(part->shared_meta_pages);
			part->shared_meta_pages = NULL;
			return -EFAULT;
		}
		part->shared_meta_nr_pages = THHV_META_PAGES_SHARED;

		/*
		 * TODO(P15e): CARVE + SEND shared META pages to child domain.
		 */

		ret = themis_seal(part->domain_handle);
		if (ret) {
			unpin_user_pages(part->shared_meta_pages,
					 part->shared_meta_nr_pages);
			kfree(part->shared_meta_pages);
			part->shared_meta_pages = NULL;
			part->shared_meta_nr_pages = 0;
			return ret;
		}
		part->sealed = true;
		pr_debug("thhv: sealed domain 0x%llx (%u shared META pages)\n",
			 part->domain_handle, part->shared_meta_nr_pages);
		return 0;
	}

	case THHV_CREATE_VP:
		return thhv_vp_create(part, uarg);

	case THHV_SET_GUEST_MEMORY:
		/* TODO(P15e): CARVE + SEND / REVOKE_MEM */
		return -ENOSYS;

	case THHV_IRQFD:
		/* TODO(P15g): eventfd → VMCALL_ASSERT_INTERRUPT */
		return -ENOSYS;

	case THHV_IOEVENTFD:
		/* TODO(P15h): VMCALL_REGISTER_DOORBELL */
		return -ENOSYS;

	case THHV_SET_MSI_ROUTING:
		/* TODO(P15g): build GSI → MSI table */
		return -ENOSYS;

	case THHV_GET_GPAP_ACCESS_BITMAP:
		/* TODO(P15e): dirty page tracking */
		return -ENOSYS;

	default:
		return -ENOTTY;
	}
}

/* ── Partition fd file_operations ──────────────────────────────────────────── */

static int thhv_part_release(struct inode *inode, struct file *file)
{
	struct thhv_partition *part = file->private_data;

	kref_put(&part->refcount, thhv_partition_destroy);
	return 0;
}

const struct file_operations thhv_partition_fops = {
	.owner          = THIS_MODULE,
	.release        = thhv_part_release,
	.unlocked_ioctl = thhv_part_ioctl,
};

/* ── THHV_CREATE_PARTITION handler (called from device ioctl) ──────────────── */

long thhv_partition_create(struct file *dev_file, void __user *uarg)
{
	struct thhv_create_partition cp;
	struct thhv_partition *part;
	struct file *file;
	int fd, ret;

	if (copy_from_user(&cp, uarg, sizeof(cp)))
		return -EFAULT;

	if (cp.sched_policy > THHV_SCHED_ASYNC)
		return -EINVAL;
	if (cp.num_vps == 0 || cp.num_vps > 256)
		return -EINVAL;

	part = kzalloc(sizeof(*part), GFP_KERNEL);
	if (!part)
		return -ENOMEM;

	kref_init(&part->refcount);
	part->sched_policy = cp.sched_policy;
	part->num_vps = cp.num_vps;
	part->sealed = false;

	spin_lock_init(&part->mem.lock);
	part->mem.regions = RB_ROOT;

	INIT_LIST_HEAD(&part->irqfds);
	mutex_init(&part->irqfd_lock);

	INIT_LIST_HEAD(&part->ioeventfds.list);
	mutex_init(&part->ioeventfds.lock);

	/* Allocate VP pointer array (populated lazily by CREATE_VP). */
	part->vps = kcalloc(cp.num_vps, sizeof(*part->vps), GFP_KERNEL);
	if (!part->vps) {
		ret = -ENOMEM;
		goto err_free_part;
	}

	/*
	 * Issue VMCALL_CREATE_DOMAIN.
	 * The capavisor intersects cores_mask/api_flags with the parent's
	 * policy, enforcing monotonicity.
	 */
	ret = themis_create_domain(cp.cores_mask, cp.api_flags, cp.num_vps,
				   &part->domain_handle);
	if (ret) {
		pr_err("thhv: CREATE_DOMAIN failed (%d)\n", ret);
		goto err_free_vps;
	}
	pr_debug("thhv: created domain handle 0x%llx (%u VPs)\n",
		 part->domain_handle, cp.num_vps);

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		ret = fd;
		goto err_revoke;
	}

	file = anon_inode_getfile("thhv-partition", &thhv_partition_fops,
				  part, O_RDWR | O_CLOEXEC);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		goto err_put_fd;
	}

	part->file = file;
	fd_install(fd, file);
	return fd;

err_put_fd:
	put_unused_fd(fd);
err_revoke:
	themis_revoke_domain(part->domain_handle);
err_free_vps:
	kfree(part->vps);
err_free_part:
	kfree(part);
	return ret;
}
