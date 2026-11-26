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
#include <linux/eventfd.h>

#include "thhv_internal.h"

/* ── Partition cleanup ─────────────────────────────────────────────────────── */

static void thhv_partition_destroy(struct kref *ref)
{
	struct thhv_partition *part =
		container_of(ref, struct thhv_partition, refcount);
	int ret;
	u32 i;

	/* Remove from the global partitions list first so concurrent
	 * THHV_DEBUG_LIST_HPAS callers cannot observe a half-torn-down
	 * partition (its rb-tree is freed below). */
	thhv_partitions_unregister(part);

	/* Revoke the domain in the capavisor (recursively tears down children).
	 * -ENOENT means the domain was already revoked (e.g. via
	 * THHV_DEBUG_REVOKE_ALL) — silently ignore. */
	if (part->domain_handle) {
		ret = themis_revoke(part->domain_handle, 0);
		if (ret && ret != -ENOENT) {
			pr_warn("thhv: REVOKE domain=0x%llx failed (%d)\n",
				part->domain_handle, ret);
			/* The child may still use the pinned pages. */
			__module_get(THIS_MODULE);
			return;
		}
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

	/* Free whole EPT META allocations, including any rounding pages. */
	{
		struct thhv_ept_meta_allocation *allocation, *tmp;

		list_for_each_entry_safe(allocation, tmp,
					 &part->ept_meta_allocations, list) {
			list_del(&allocation->list);
			__free_pages(allocation->head, allocation->order);
			kfree(allocation);
		}
	}

	/* Free kernel-allocated DomainComm pages (compound allocation).
	 * Caps revoked via sent_caps below; only struct pages freed here. */
	if (part->domcomm_pages) {
		__free_pages(part->domcomm_pages[0], DOMCOMM_ORDER);
		kfree(part->domcomm_pages);
	}

	/* Free all memory regions (unpin pages only; caps revoked via sent_caps). */
	{
		struct rb_node *n;

		while ((n = rb_first(&part->mem.regions)) != NULL) {
			struct thhv_mem_region *r =
				container_of(n, struct thhv_mem_region, node);

			rb_erase(n, &part->mem.regions);
			if (r->pages) {
				unpin_user_pages(r->pages, r->nr_pages);
				kfree(r->pages);
			}
			kfree(r);
		}
	}

	/* Revoke all capabilities sent to this child domain. */
	{
		struct thhv_sent_cap *sc, *tmp;

		spin_lock(&part->sent_caps.lock);
		list_for_each_entry_safe(sc, tmp, &part->sent_caps.list, list) {
			int rv;

			rv = themis_revoke(sc->parent_handle, sc->sub_handle);
			if (rv)
				pr_warn("thhv: REVOKE parent=%llu sub=%llu failed (%d)\n",
					sc->parent_handle, sc->sub_handle, rv);
			list_del(&sc->list);
			kfree(sc);
		}
		spin_unlock(&part->sent_caps.lock);
	}

	/* Release all irqfd entries (removes waitqueue entries, flushes work). */
	thhv_irqfd_release_all(part);

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
	case THHV_SEND_CAP: {
		struct thhv_send_cap args;

		if (copy_from_user(&args, uarg, sizeof(args)))
			return -EFAULT;
		return themis_send(args.handle, part->domain_handle, args.attrs);
	}
	case THHV_SEND_SHARED_META: {
		struct thhv_initialize_partition ip;

		if (part->sealed)
			return -EBUSY;
		if (part->shared_meta_pages)
			return -EBUSY;  /* already sent */
		if (copy_from_user(&ip, uarg, sizeof(ip)))
			return -EFAULT;
		if (ip.meta_size != (u64)THHV_META_PAGES_SHARED * PAGE_SIZE)
			return -EINVAL;
		if (!ip.meta_uaddr || (ip.meta_uaddr & ~PAGE_MASK))
			return -EINVAL;
		if (ip.apic_access_uaddr || ip.apic_access_size)
			return -EINVAL;

		/* Pin domain-wide META pages before VP creation. */
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
		 * CARVE + SEND domain-wide META pages
		 * to child domain.  The capavisor adds them to the domain's
		 * frame allocator (GiveMetaMem update).
		 * Must be done BEFORE CREATE_VP so ADD_VP can allocate the
		 * per-VP resources from the META pool.
		 */
		ret = thhv_send_meta_pages(part, part->shared_meta_pages,
					   THHV_META_PAGES_SHARED,
					   THHV_META_KEY_SHARED);
		if (ret) {
			unpin_user_pages(part->shared_meta_pages,
					 part->shared_meta_nr_pages);
			kfree(part->shared_meta_pages);
			part->shared_meta_pages = NULL;
			part->shared_meta_nr_pages = 0;
			return ret;
		}
		pr_debug("thhv: sent %u shared META pages for domain 0x%llx\n",
			 part->shared_meta_nr_pages, part->domain_handle);

		return 0;
	}

	case THHV_SET_POLICY: {
		struct thhv_set_policy sp;

		if (part->sealed)
			return -EBUSY;
		if (copy_from_user(&sp, uarg, sizeof(sp)))
			return -EFAULT;
		return themis_set_policy(part->domain_handle,
					sp.kind, sp.key, sp.sub_key, sp.value);
	}

	case THHV_INITIALIZE_PARTITION: {
		if (part->sealed)
			return -EBUSY;
		if (!part->shared_meta_pages) {
			pr_err("thhv: shared META not sent before seal\n");
			return -EINVAL;
		}

		ret = themis_seal(part->domain_handle);
		if (ret)
			return ret;
		part->sealed = true;
		pr_debug("thhv: sealed domain 0x%llx\n",
			 part->domain_handle);
		return 0;
	}

	case THHV_CREATE_VP:
		return thhv_vp_create(part, uarg);

	case THHV_SET_GUEST_MEMORY:
		return thhv_set_guest_memory(part, uarg);

	case THHV_IRQFD: {
		struct thhv_irqfd __user *irq = uarg;
		struct thhv_irqfd args;

		if (copy_from_user(&args, irq, sizeof(args)))
			return -EFAULT;

		if (args.flags & THHV_IRQFD_FLAG_DEASSIGN)
			return thhv_irqfd_deassign(part, irq);
		return thhv_irqfd_assign(part, irq);
	}

	case THHV_SET_MSI_ROUTING:
		/* TODO(P15g): build GSI → MSI table */
		return -ENOSYS;

	case THHV_GET_GPAP_ACCESS_BITMAP:
		/* TODO(P15e): dirty page tracking */
		return -ENOSYS;

	case THHV_INJECT_INTERRUPT: {
		struct thhv_inject_interrupt ii;

		if (!part->sealed)
			return -EINVAL;
		if (copy_from_user(&ii, uarg, sizeof(ii)))
			return -EFAULT;
		if (ii.vp_index >= part->num_vps)
			return -EINVAL;
		ret = themis_inject_interrupt(part->domain_handle,
					      ii.vp_index, ii.vector);
		if (!ret)
			thhv_wake_vp(part, ii.vp_index);
		return ret;
	}

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
	if (cp.num_vps == 0 || cp.num_vps > THHV_MAX_VPS_PER_DOMAIN)
		return -EINVAL;

	part = kzalloc(sizeof(*part), GFP_KERNEL);
	if (!part)
		return -ENOMEM;

	kref_init(&part->refcount);
	part->sched_policy = cp.sched_policy;
	part->num_vps = cp.num_vps;
	part->sealed = false;

	INIT_LIST_HEAD(&part->global_node);

	spin_lock_init(&part->mem.lock);
	part->mem.regions = RB_ROOT;
	INIT_LIST_HEAD(&part->ept_meta_allocations);

	spin_lock_init(&part->sent_caps.lock);
	INIT_LIST_HEAD(&part->sent_caps.list);

	INIT_LIST_HEAD(&part->irqfds.list);
	mutex_init(&part->irqfds.lock);

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

	/*
	 * Provision a channel back to the parent: get a self-channel (handle=0
	 * means "channel pointing at myself") and send it to the child.  The
	 * child will accept it after boot and use it to send capabilities
	 * (e.g. shared bounce buffers) back to the parent.
	 */
	{
		u64 chan;

		ret = themis_get_chan(0, &chan);
		if (ret) {
			pr_err("thhv: GET_CHAN(self) failed (%d)\n", ret);
			goto err_revoke;
		}
		ret = themis_send(chan, part->domain_handle, 0);
		if (ret) {
			pr_err("thhv: SEND channel failed (%d)\n", ret);
			goto err_revoke;
		}
		part->chan_handle = chan;
		pr_debug("thhv: sent channel 0x%llx to child\n", chan);
	}

	/*
	 * Provision per-domain DomainComm pages: allocate 4 kernel pages,
	 * CARVE each from this domain's memory, and SEND to the child with the
	 * COMM attribute.  The capavisor accumulates the HPAs and
	 * initialises the child's DomainComm ring at seal time.
	 * After SEND, the caps belong to the child (identity-mapped,
	 * GPA=HPA); only the struct page pointers are kept for __free_page.
	 */
	{
		unsigned int i;
		struct page **dc_pages;
		struct page *dc_compound;

		dc_pages = kcalloc(DOMCOMM_NR_PAGES, sizeof(*dc_pages),
				   GFP_KERNEL);
		if (!dc_pages) {
			ret = -ENOMEM;
			goto err_revoke;
		}

		dc_compound = alloc_pages(GFP_KERNEL | __GFP_ZERO, DOMCOMM_ORDER);
		if (!dc_compound) {
			kfree(dc_pages);
			ret = -ENOMEM;
			goto err_revoke;
		}
		for (i = 0; i < DOMCOMM_NR_PAGES; i++)
			dc_pages[i] = dc_compound + i;
		part->domcomm_pages = dc_pages;
		part->domcomm_nr_pages = DOMCOMM_NR_PAGES;

		/* Size META for the actual child addresses, not this Linux GPA. */
		{
			unsigned int nr_dc_meta = 0;
			unsigned int j;

			for (j = 0; j < DOMCOMM_NR_PAGES; j++) {
				u64 gpa = (u64)page_to_pfn(dc_pages[j]) << PAGE_SHIFT;
				u64 hpa = thhv_gpa_to_hpa(gpa);

				if (hpa == (u64)-1) {
					ret = -EFAULT;
					goto err_free_domcomm_pages;
				}
				nr_dc_meta += thhv_ept_meta_needed(hpa, PAGE_SIZE);
			}
			ret = thhv_send_ept_meta(part, nr_dc_meta);
			if (ret)
				goto err_free_domcomm_pages;

			pr_debug("thhv: sent %u EPT META pages for domcomm\n",
				 nr_dc_meta);
		}

		/* Linux-contiguous pages need not have contiguous host backing. */
		for (i = 0; i < DOMCOMM_NR_PAGES; i++) {
			u64 gpa = (u64)page_to_pfn(dc_pages[i]) << PAGE_SHIFT;
			u64 hpa = thhv_gpa_to_hpa(gpa);
			u64 parent_handle, carved_handle, sub;
			struct thhv_sent_cap *sc;

			if (hpa == (u64)-1) {
				pr_err("thhv: domcomm block: GPA %#llx not in PA map\n",
				       gpa);
				ret = -EFAULT;
				goto err_free_domcomm;
			}

			ret = thhv_find_parent_handle(hpa, PAGE_SIZE,
						      &parent_handle);
			if (ret) {
				pr_err("thhv: domcomm block: no parent cap for HPA %#llx\n",
				       hpa);
				goto err_free_domcomm;
			}

			sc = kzalloc(sizeof(*sc), GFP_KERNEL);
			if (!sc) {
				ret = -ENOMEM;
				goto err_free_domcomm;
			}
			ret = themis_carve(parent_handle, hpa, PAGE_SIZE,
					   THHV_MEM_R_READ | THHV_MEM_R_WRITE,
					   &carved_handle, &sub);
			if (ret) {
				kfree(sc);
				pr_err("thhv: domcomm block: CARVE failed (%d)\n",
				       ret);
				goto err_free_domcomm;
			}

			ret = themis_send(carved_handle,
					  part->domain_handle,
					  THHV_MEM_A_COMM);
			if (ret) {
				kfree(sc);
				pr_err("thhv: domcomm block: SEND COMM failed (%d)\n",
				       ret);
				themis_revoke(parent_handle, sub);
				goto err_free_domcomm;
			}

			sc->parent_handle = parent_handle;
			sc->sub_handle    = sub;
			sc->region_key    = hpa >> PAGE_SHIFT;

			spin_lock(&part->sent_caps.lock);
			list_add_tail(&sc->list, &part->sent_caps.list);
			spin_unlock(&part->sent_caps.lock);
		}

		part->domcomm_pages = dc_pages;
		part->domcomm_nr_pages = DOMCOMM_NR_PAGES;
		pr_debug("thhv: provisioned %u DomainComm pages for child\n",
			 DOMCOMM_NR_PAGES);

		goto domcomm_done;
err_free_domcomm_pages:
err_free_domcomm:
		goto err_revoke;
domcomm_done:
		;
	}

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
	/* Register before fd_install so an attacker that immediately queries
	 * the global list cannot observe a usable fd whose partition is not
	 * yet enumerable. */
	thhv_partitions_register(part);
	fd_install(fd, file);
	return fd;

err_put_fd:
	put_unused_fd(fd);
err_revoke:
	kref_put(&part->refcount, thhv_partition_destroy);
	return ret;
err_free_vps:
	kfree(part->vps);
err_free_part:
	kfree(part);
	return ret;
}
