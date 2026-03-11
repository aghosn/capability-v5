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

			rv = themis_revoke_mem(sc->parent_handle, sc->sub_handle);
			if (rv)
				pr_warn("thhv: REVOKE_MEM parent=%llu sub=%llu failed (%d)\n",
					sc->parent_handle, sc->sub_handle, rv);
			list_del(&sc->list);
			kfree(sc);
		}
		spin_unlock(&part->sent_caps.lock);
	}

	/* TODO: free irqfds, ioeventfds */

	kfree(part);
}

/* ── Memory region rb-tree helpers ─────────────────────────────────────────── */

static struct thhv_mem_region *
thhv_mem_find(struct thhv_partition *part, u64 guest_pfn)
{
	struct rb_node *n = part->mem.regions.rb_node;

	while (n) {
		struct thhv_mem_region *r =
			container_of(n, struct thhv_mem_region, node);
		if (guest_pfn < r->guest_pfn)
			n = n->rb_left;
		else if (guest_pfn >= r->guest_pfn + r->nr_pages)
			n = n->rb_right;
		else
			return r;
	}
	return NULL;
}

static int thhv_mem_insert(struct thhv_partition *part,
			   struct thhv_mem_region *region)
{
	struct rb_node **link = &part->mem.regions.rb_node;
	struct rb_node *parent = NULL;

	while (*link) {
		struct thhv_mem_region *r =
			container_of(*link, struct thhv_mem_region, node);
		parent = *link;

		if (region->guest_pfn + region->nr_pages <= r->guest_pfn)
			link = &(*link)->rb_left;
		else if (region->guest_pfn >= r->guest_pfn + r->nr_pages)
			link = &(*link)->rb_right;
		else
			return -EEXIST; /* overlap */
	}

	rb_link_node(&region->node, parent, link);
	rb_insert_color(&region->node, &part->mem.regions);
	return 0;
}

/* ── THHV_SET_GUEST_MEMORY handler ─────────────────────────────────────────── */

static long thhv_set_guest_memory(struct thhv_partition *part,
				  void __user *uarg)
{
	struct thhv_set_guest_memory gm;
	struct thhv_mem_region *region;
	struct thhv_hpa_segment *segs = NULL;
	unsigned int nr_segs = 0;
	unsigned long nr_pages;
	unsigned int i;
	int ret;

	if (copy_from_user(&gm, uarg, sizeof(gm)))
		return -EFAULT;

	if (gm.size == 0 || (gm.size & ~PAGE_MASK))
		return -EINVAL;
	if (gm.userspace_addr & ~PAGE_MASK)
		return -EINVAL;

	nr_pages = gm.size >> PAGE_SHIFT;

	/* ── Unmap path ─────────────────────────────────────────────────── */
	if (gm.flags & THHV_MEM_F_UNMAP) {
		struct thhv_sent_cap *sc, *tmp;

		spin_lock(&part->mem.lock);
		region = thhv_mem_find(part, gm.guest_pfn);
		if (!region) {
			spin_unlock(&part->mem.lock);
			return -ENOENT;
		}
		rb_erase(&region->node, &part->mem.regions);
		spin_unlock(&part->mem.lock);

		/* Revoke all capabilities associated with this region. */
		spin_lock(&part->sent_caps.lock);
		list_for_each_entry_safe(sc, tmp, &part->sent_caps.list, list) {
			if (sc->region_key == gm.guest_pfn) {
				ret = themis_revoke_mem(sc->parent_handle,
						       sc->sub_handle);
				if (ret)
					pr_warn("thhv: REVOKE_MEM parent=%llu sub=%llu pfn 0x%llx failed (%d)\n",
						sc->parent_handle,
						sc->sub_handle,
						gm.guest_pfn, ret);
				list_del(&sc->list);
				kfree(sc);
			}
		}
		spin_unlock(&part->sent_caps.lock);

		if (region->pages) {
			unpin_user_pages(region->pages, region->nr_pages);
			kfree(region->pages);
		}
		kfree(region);
		return 0;
	}

	/* ── Map path ───────────────────────────────────────────────────── */

	region = kzalloc(sizeof(*region), GFP_KERNEL);
	if (!region)
		return -ENOMEM;

	region->guest_pfn = gm.guest_pfn;
	region->nr_pages = nr_pages;
	region->userspace_addr = gm.userspace_addr;
	region->flags = gm.flags;
	region->rights = gm.rights;
	region->attrs = gm.attrs;

	/* Pin userspace pages. */
	region->pages = kcalloc(nr_pages, sizeof(struct page *), GFP_KERNEL);
	if (!region->pages) {
		ret = -ENOMEM;
		goto err_free;
	}

	ret = pin_user_pages_fast(gm.userspace_addr, nr_pages,
				  FOLL_WRITE | FOLL_LONGTERM,
				  region->pages);
	if (ret < 0)
		goto err_free_pages;
	if ((unsigned long)ret != nr_pages) {
		unpin_user_pages(region->pages, ret);
		ret = -EFAULT;
		goto err_free_pages;
	}

	/*
	 * Translate pinned dom0 GPAs → real HPAs.
	 * Produces one or more contiguous HPA segments.
	 * Falls through as identity (GPA==HPA) when no PA map is loaded.
	 */
	ret = thhv_translate_pages(region->pages, nr_pages, &segs, &nr_segs);
	if (ret)
		goto err_unpin;

	/* CARVE/ALIAS + cap table insert + SEND_AT + cap table remove +
	 * sent_caps append for each HPA segment.
	 *
	 * On error, we track how many segments completed the full cycle
	 * (sent_caps) vs. how many only got as far as CARVE (cap table).
	 */
	{
		u64 child_gpa_cursor = gm.guest_pfn << PAGE_SHIFT;
		unsigned int nr_sent = 0;  /* segments fully sent */

		for (i = 0; i < nr_segs; i++) {
			u64 cap_handle, cap_sub;
			u64 parent_handle;
			struct thhv_sent_cap *sc;

			ret = thhv_find_parent_handle(segs[i].hpa_start,
						      segs[i].size,
						      &parent_handle);
			if (ret)
				goto err_revoke_partial;

			if (gm.flags & THHV_MEM_F_ALIAS)
				ret = themis_alias(parent_handle,
						   segs[i].hpa_start,
						   segs[i].size, gm.rights,
						   &cap_handle, &cap_sub);
			else
				ret = themis_carve(parent_handle,
						   segs[i].hpa_start,
						   segs[i].size, gm.rights,
						   &cap_handle, &cap_sub);
			if (ret)
				goto err_revoke_partial;

			/* Insert carved child into cap table. */
			ret = thhv_cap_table_insert(cap_handle, parent_handle,
						    cap_sub,
						    segs[i].hpa_start,
						    segs[i].size);
			if (ret) {
				themis_revoke_mem(parent_handle, cap_sub);
				goto err_revoke_partial;
			}

			/* SEND_AT to child domain. */
			ret = themis_send_at(cap_handle,
					     part->domain_handle,
					     gm.attrs,
					     child_gpa_cursor);
			if (ret) {
				/* Undo: revoke + remove from cap table. */
				themis_revoke_mem(parent_handle, cap_sub);
				thhv_cap_table_remove(cap_handle);
				goto err_revoke_partial;
			}

			/* Handle sent: remove from cap table, add to sent_caps. */
			thhv_cap_table_remove(cap_handle);

			sc = kzalloc(sizeof(*sc), GFP_KERNEL);
			if (!sc) {
				/* Cap already sent — can't undo SEND easily.
				 * Still record for cleanup even if alloc fails.
				 */
				pr_err("thhv: sent_cap alloc failed\n");
				ret = -ENOMEM;
				goto err_revoke_partial;
			}
			sc->parent_handle = parent_handle;
			sc->sub_handle    = cap_sub;
			sc->region_key    = gm.guest_pfn;

			spin_lock(&part->sent_caps.lock);
			list_add_tail(&sc->list, &part->sent_caps.list);
			spin_unlock(&part->sent_caps.lock);

			nr_sent++;
			child_gpa_cursor += segs[i].size;
		}
	}

	kfree(segs);
	segs = NULL;

	/* Insert into tracking tree. */
	spin_lock(&part->mem.lock);
	ret = thhv_mem_insert(part, region);
	spin_unlock(&part->mem.lock);
	if (ret)
		goto err_revoke_all;

	return 0;

err_revoke_all:
	/* All segments were sent — revoke via sent_caps. */
	{
		struct thhv_sent_cap *sc, *tmp;

		spin_lock(&part->sent_caps.lock);
		list_for_each_entry_safe(sc, tmp, &part->sent_caps.list, list) {
			if (sc->region_key == gm.guest_pfn) {
				themis_revoke_mem(sc->parent_handle,
						 sc->sub_handle);
				list_del(&sc->list);
				kfree(sc);
			}
		}
		spin_unlock(&part->sent_caps.lock);
	}
	goto err_free_segs;

err_revoke_partial:
	/* Already-sent segments are in sent_caps — revoke them. */
	{
		struct thhv_sent_cap *sc, *tmp;

		spin_lock(&part->sent_caps.lock);
		list_for_each_entry_safe(sc, tmp, &part->sent_caps.list, list) {
			if (sc->region_key == gm.guest_pfn) {
				themis_revoke_mem(sc->parent_handle,
						 sc->sub_handle);
				list_del(&sc->list);
				kfree(sc);
			}
		}
		spin_unlock(&part->sent_caps.lock);
	}
err_free_segs:
	kfree(segs);
err_unpin:
	unpin_user_pages(region->pages, nr_pages);
err_free_pages:
	kfree(region->pages);
err_free:
	kfree(region);
	return ret;
}

/* ── CARVE + SEND META pages to child domain ───────────────────────────────── */

/*
 * CARVE each pinned page from its parent capability and SEND to the child
 * domain with META attribute.  META pages are used by the capavisor for
 * internal allocations (VMCS, VAPIC, MSR bitmap, EPT pages).
 *
 * On success, each page's capability is tracked in part->sent_caps for
 * revocation on teardown.  region_key is set to a synthetic value to
 * distinguish META caps from normal memory mappings.
 *
 * Returns 0 on success, negative errno on failure (partial sends are
 * rolled back).
 */
int thhv_send_meta_pages(struct thhv_partition *part,
				struct page **pages, unsigned int nr_pages,
				u64 region_key)
{
	unsigned int i, nr_sent = 0;
	int ret;

	for (i = 0; i < nr_pages; i++) {
		u64 gpa, hpa, parent_handle, cap_handle, cap_sub;
		struct thhv_sent_cap *sc;

		gpa = (u64)page_to_pfn(pages[i]) << PAGE_SHIFT;
		hpa = thhv_gpa_to_hpa(gpa);
		if (hpa == (u64)-1) {
			pr_err("thhv: META page[%u] GPA 0x%llx: no HPA\n",
			       i, gpa);
			ret = -EFAULT;
			goto err_revoke;
		}

		ret = thhv_find_parent_handle(hpa, PAGE_SIZE, &parent_handle);
		if (ret) {
			pr_err("thhv: META page[%u] HPA 0x%llx: no parent cap\n",
			       i, hpa);
			goto err_revoke;
		}

		ret = themis_carve(parent_handle, hpa, PAGE_SIZE,
				   THHV_MEM_R_READ | THHV_MEM_R_WRITE,
				   &cap_handle, &cap_sub);
		if (ret) {
			pr_err("thhv: META page[%u] CARVE failed (%d)\n",
			       i, ret);
			goto err_revoke;
		}

		ret = thhv_cap_table_insert(cap_handle, parent_handle,
					    cap_sub, hpa, PAGE_SIZE);
		if (ret) {
			themis_revoke_mem(parent_handle, cap_sub);
			goto err_revoke;
		}

		ret = themis_send(cap_handle, part->domain_handle,
				  THHV_MEM_A_META);
		if (ret) {
			themis_revoke_mem(parent_handle, cap_sub);
			thhv_cap_table_remove(cap_handle);
			pr_err("thhv: META page[%u] SEND failed (%d)\n",
			       i, ret);
			goto err_revoke;
		}

		thhv_cap_table_remove(cap_handle);

		sc = kzalloc(sizeof(*sc), GFP_KERNEL);
		if (!sc) {
			ret = -ENOMEM;
			goto err_revoke;
		}
		sc->parent_handle = parent_handle;
		sc->sub_handle    = cap_sub;
		sc->region_key    = region_key;

		spin_lock(&part->sent_caps.lock);
		list_add_tail(&sc->list, &part->sent_caps.list);
		spin_unlock(&part->sent_caps.lock);

		nr_sent++;
	}

	pr_debug("thhv: sent %u META pages to domain 0x%llx (key=0x%llx)\n",
		 nr_sent, part->domain_handle, region_key);
	return 0;

err_revoke:
	/* Revoke already-sent META pages. */
	{
		struct thhv_sent_cap *sc, *tmp;

		spin_lock(&part->sent_caps.lock);
		list_for_each_entry_safe(sc, tmp, &part->sent_caps.list, list) {
			if (sc->region_key == region_key) {
				themis_revoke_mem(sc->parent_handle,
						 sc->sub_handle);
				list_del(&sc->list);
				kfree(sc);
			}
		}
		spin_unlock(&part->sent_caps.lock);
	}
	return ret;
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
		 * CARVE + SEND shared META pages (MSR bitmap + IO bitmaps)
		 * to child domain.  The capavisor adds them to the domain's
		 * frame allocator (GiveMetaMem update).
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
		return thhv_set_guest_memory(part, uarg);

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

	spin_lock_init(&part->sent_caps.lock);
	INIT_LIST_HEAD(&part->sent_caps.list);

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
