// SPDX-License-Identifier: GPL-2.0
/*
 * hvthemis_part.c — Partition fd lifecycle and ioctl dispatch.
 *
 * A partition fd is returned by MSHV_CREATE_PARTITION on the device fd.
 * It wraps a Themis domain and tracks VPs, memory mappings, IRQfds, etc.
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/anon_inodes.h>
#include <linux/uaccess.h>

#include "hvthemis.h"

/* ── Partition cleanup ─────────────────────────────────────────────────────── */

static void hvthemis_partition_destroy(struct kref *ref)
{
	struct hvthemis_partition *part =
		container_of(ref, struct hvthemis_partition, refcount);
	int ret;
	u32 i;

	/* Revoke the domain in the capavisor (recursively tears down children). */
	if (part->domain_handle) {
		ret = themis_revoke_domain(part->domain_handle);
		if (ret)
			pr_warn("hvthemis: REVOKE_DOMAIN 0x%llx failed (%d)\n",
				part->domain_handle, ret);
	}

	if (part->vps) {
		for (i = 0; i < part->num_vps; i++)
			kfree(part->vps[i]);
		kfree(part->vps);
	}

	/* TODO: free mem regions rb-tree, irqfds, ioeventfds */

	kfree(part);
}

/* ── Partition-level ioctl dispatch ────────────────────────────────────────── */

static long hvthemis_part_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	struct hvthemis_partition *part = file->private_data;
	void __user *uarg = (void __user *)arg;
	int ret;

	switch (cmd) {
	case MSHV_INITIALIZE_PARTITION:
		if (part->sealed)
			return -EBUSY;
		ret = themis_seal(part->domain_handle);
		if (ret)
			return ret;
		part->sealed = true;
		pr_debug("hvthemis: sealed domain 0x%llx\n",
			 part->domain_handle);
		return 0;

	case MSHV_CREATE_VP:
		return hvthemis_vp_create(part, uarg);

	case MSHV_SET_GUEST_MEMORY:
		/* TODO(P15e): CARVE + SEND / REVOKE_MEM */
		return -ENOSYS;

	case MSHV_IRQFD:
		/* TODO(P15g): eventfd → VMCALL_ASSERT_INTERRUPT */
		return -ENOSYS;

	case MSHV_IOEVENTFD:
		/* TODO(P15h): VMCALL_REGISTER_DOORBELL */
		return -ENOSYS;

	case MSHV_SET_MSI_ROUTING:
		/* TODO(P15g): build GSI → MSI table */
		return -ENOSYS;

	case MSHV_GET_GPAP_ACCESS_BITMAP:
		/* TODO(P15e): dirty page tracking */
		return -ENOSYS;

	default:
		return -ENOTTY;
	}
}

/* ── Partition fd file_operations ──────────────────────────────────────────── */

static int hvthemis_part_release(struct inode *inode, struct file *file)
{
	struct hvthemis_partition *part = file->private_data;

	kref_put(&part->refcount, hvthemis_partition_destroy);
	return 0;
}

const struct file_operations hvthemis_partition_fops = {
	.owner          = THIS_MODULE,
	.release        = hvthemis_part_release,
	.unlocked_ioctl = hvthemis_part_ioctl,
};

/* ── MSHV_CREATE_PARTITION handler (called from device ioctl) ──────────────── */

long hvthemis_partition_create(struct file *dev_file, void __user *uarg)
{
	struct mshv_create_partition cp;
	struct hvthemis_partition *part;
	struct file *file;
	int fd, ret;

	if (copy_from_user(&cp, uarg, sizeof(cp)))
		return -EFAULT;

	if (cp.sched_policy > HVTHEMIS_SCHED_ASYNC)
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
		pr_err("hvthemis: CREATE_DOMAIN failed (%d)\n", ret);
		goto err_free_vps;
	}
	pr_debug("hvthemis: created domain handle 0x%llx (%u VPs)\n",
		 part->domain_handle, cp.num_vps);

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		ret = fd;
		goto err_revoke;
	}

	file = anon_inode_getfile("mshv-partition", &hvthemis_partition_fops,
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
