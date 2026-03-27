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

	/* Unpin APIC-access sentinel page. */
	if (part->apic_access_pages) {
		unpin_user_pages(part->apic_access_pages,
				 part->apic_access_nr_pages);
		kfree(part->apic_access_pages);
	}

	/* Free kernel-allocated EPT META pages. */
	if (part->ept_meta_pages) {
		unsigned int j;

		for (j = 0; j < part->ept_meta_nr_pages; j++)
			__free_page(part->ept_meta_pages[j]);
		kfree(part->ept_meta_pages);
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

	/* Release all irqfd entries (removes waitqueue entries, flushes work). */
	thhv_irqfd_release_all(part);

	/* Free ioeventfd entries (no unregister — domain already being torn down). */
	{
		struct thhv_ioeventfd_entry *e, *etmp;
		list_for_each_entry_safe(e, etmp, &part->ioeventfds.list, node) {
			list_del(&e->node);
			eventfd_ctx_put(e->eventfd);
			kfree(e);
		}
	}

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

/*
 * Compute worst-case number of EPT intermediate pages needed to map a
 * guest-physical region [gpa, gpa+size).  Accounts for all 4 EPT levels:
 *   PML4 root (1 page, allocated by ensure_ept on first use),
 *   PDPT entries (512 GB each), PD entries (1 GB each), PT entries (2 MB each).
 */
static unsigned int thhv_ept_meta_needed(u64 gpa, u64 size)
{
	u64 end = gpa + size - 1;
	unsigned int n = 0;

	/* EPT root (PML4): 1 page, first-time only but safe to over-allocate. */
	n += 1;
	/* PDPT pages (512 GB granularity). */
	n += (unsigned int)((end >> 39) - (gpa >> 39)) + 1;
	/* PD pages (1 GB granularity). */
	n += (unsigned int)((end >> 30) - (gpa >> 30)) + 1;
	/* PT pages (2 MB granularity). */
	n += (unsigned int)((end >> 21) - (gpa >> 21)) + 1;

	return n;
}

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

	/* Guard: GPA 0xFEE00000 is owned by capavisor for LAPIC virtualization.
	 * CHV must not map guest memory overlapping this range. */
	{
		u64 req_start = gm.guest_pfn << PAGE_SHIFT;
		u64 req_end   = req_start + gm.size;
		u64 lap_end   = THHV_LAPIC_GPA + PAGE_SIZE;

		if (req_start < lap_end && req_end > THHV_LAPIC_GPA) {
			pr_err("thhv: SET_GUEST_MEMORY GPA [0x%llx, 0x%llx) overlaps LAPIC range [0x%llx, 0x%llx)\n",
			       req_start, req_end, THHV_LAPIC_GPA, lap_end);
			return -EINVAL;
		}
	}

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

	/*
	 * Send EPT META pages to the child so the capavisor can allocate
	 * intermediate EPT page-table pages when mapping this region.
	 * Kernel-allocated pages are tracked in part->ept_meta_pages and
	 * freed on partition teardown.
	 */
	{
		u64 child_gpa = gm.guest_pfn << PAGE_SHIFT;
		unsigned int nr_ept_meta = thhv_ept_meta_needed(child_gpa,
								gm.size);
		struct page **ept_pages;
		unsigned int j;

		ept_pages = kcalloc(nr_ept_meta, sizeof(struct page *),
				    GFP_KERNEL);
		if (!ept_pages) {
			ret = -ENOMEM;
			goto err_free_segs;
		}

		for (j = 0; j < nr_ept_meta; j++) {
			ept_pages[j] = alloc_page(GFP_KERNEL | __GFP_ZERO);
			if (!ept_pages[j]) {
				while (j--)
					__free_page(ept_pages[j]);
				kfree(ept_pages);
				ret = -ENOMEM;
				goto err_free_segs;
			}
		}

		ret = thhv_send_meta_pages(part, ept_pages, nr_ept_meta,
					   THHV_META_KEY_EPT);
		if (ret) {
			for (j = 0; j < nr_ept_meta; j++)
				__free_page(ept_pages[j]);
			kfree(ept_pages);
			goto err_free_segs;
		}

		/*
		 * Accumulate EPT META pages.  If we already have some from a
		 * previous SET_GUEST_MEMORY call, grow the array.
		 */
		if (part->ept_meta_pages) {
			struct page **merged;
			unsigned int total = part->ept_meta_nr_pages + nr_ept_meta;

			merged = krealloc(part->ept_meta_pages,
					  total * sizeof(struct page *),
					  GFP_KERNEL);
			if (!merged) {
				/* Pages already sent — just leak tracking. */
				kfree(ept_pages);
				ret = -ENOMEM;
				goto err_free_segs;
			}
			memcpy(merged + part->ept_meta_nr_pages, ept_pages,
			       nr_ept_meta * sizeof(struct page *));
			kfree(ept_pages);
			part->ept_meta_pages = merged;
			part->ept_meta_nr_pages = total;
		} else {
			part->ept_meta_pages = ept_pages;
			part->ept_meta_nr_pages = nr_ept_meta;
		}

		pr_debug("thhv: sent %u EPT META pages for domain 0x%llx\n",
			 nr_ept_meta, part->domain_handle);
	}

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

			/* Insert child region into cap table. */
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
		 * Must be done BEFORE CREATE_VP so ADD_VP can allocate the
		 * MSR bitmap from the META pool.
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

		/*
		 * APIC-access sentinel page: pinned from CHV userspace, CARVEd
		 * from dom0's memory, and SEND_AT to the child domain at GPA
		 * THHV_LAPIC_GPA (0xFEE00000).  The capavisor's ChangeRights
		 * handler detects this GPA and stores the HPA as apic_access_phys
		 * for the VMCS APIC_ACCESS_ADDR field.  EPT META pages are also
		 * allocated here to back the EPT page-table entries for this GPA.
		 */
		if (!ip.apic_access_uaddr || (ip.apic_access_uaddr & ~PAGE_MASK))
			return -EINVAL;
		if (ip.apic_access_size != PAGE_SIZE)
			return -EINVAL;

		{
			u64 hpa, parent_handle, cap_handle, cap_sub;
			struct page **ept_pages;
			unsigned int nr_ept_meta, j;
			struct thhv_sent_cap *sc;

			/* Pin the APIC-access page. */
			part->apic_access_pages = kcalloc(1, sizeof(struct page *),
							  GFP_KERNEL);
			if (!part->apic_access_pages)
				return -ENOMEM;

			ret = pin_user_pages_fast(ip.apic_access_uaddr, 1,
						  FOLL_WRITE | FOLL_LONGTERM,
						  part->apic_access_pages);
			if (ret != 1) {
				kfree(part->apic_access_pages);
				part->apic_access_pages = NULL;
				return ret < 0 ? ret : -EFAULT;
			}
			part->apic_access_nr_pages = 1;

			/* Translate to HPA. */
			hpa = thhv_gpa_to_hpa(
				(u64)page_to_pfn(part->apic_access_pages[0]) << PAGE_SHIFT);
			if (hpa == (u64)-1) {
				pr_err("thhv: APIC-access page HPA translation failed\n");
				return -EFAULT;
			}

			/* Send EPT META pages for GPA THHV_LAPIC_GPA. */
			nr_ept_meta = thhv_ept_meta_needed(THHV_LAPIC_GPA, PAGE_SIZE);
			ept_pages = kcalloc(nr_ept_meta, sizeof(struct page *),
					    GFP_KERNEL);
			if (!ept_pages)
				return -ENOMEM;

			for (j = 0; j < nr_ept_meta; j++) {
				ept_pages[j] = alloc_page(GFP_KERNEL | __GFP_ZERO);
				if (!ept_pages[j]) {
					while (j--)
						__free_page(ept_pages[j]);
					kfree(ept_pages);
					return -ENOMEM;
				}
			}

			ret = thhv_send_meta_pages(part, ept_pages, nr_ept_meta,
						   THHV_META_KEY_EPT);
			if (ret) {
				for (j = 0; j < nr_ept_meta; j++)
					__free_page(ept_pages[j]);
				kfree(ept_pages);
				pr_err("thhv: APIC-access EPT META send failed (%d)\n", ret);
				return ret;
			}

			/* Accumulate EPT META pages for cleanup. */
			if (part->ept_meta_pages) {
				struct page **merged;
				unsigned int total = part->ept_meta_nr_pages + nr_ept_meta;

				merged = krealloc(part->ept_meta_pages,
						  total * sizeof(struct page *),
						  GFP_KERNEL);
				if (!merged) {
					kfree(ept_pages);
					return -ENOMEM;
				}
				memcpy(merged + part->ept_meta_nr_pages, ept_pages,
				       nr_ept_meta * sizeof(struct page *));
				kfree(ept_pages);
				part->ept_meta_pages = merged;
				part->ept_meta_nr_pages = total;
			} else {
				part->ept_meta_pages = ept_pages;
				part->ept_meta_nr_pages = nr_ept_meta;
			}

			/* CARVE the APIC-access page from dom0's memory. */
			ret = thhv_find_parent_handle(hpa, PAGE_SIZE, &parent_handle);
			if (ret) {
				pr_err("thhv: APIC-access page HPA 0x%llx: no parent cap\n", hpa);
				return ret;
			}

			ret = themis_carve(parent_handle, hpa, PAGE_SIZE,
					   THHV_MEM_R_READ | THHV_MEM_R_WRITE,
					   &cap_handle, &cap_sub);
			if (ret) {
				pr_err("thhv: APIC-access CARVE failed (%d)\n", ret);
				return ret;
			}

			ret = thhv_cap_table_insert(cap_handle, parent_handle,
						    cap_sub, hpa, PAGE_SIZE);
			if (ret) {
				themis_revoke_mem(parent_handle, cap_sub);
				return ret;
			}

			/* SEND_AT to child domain at GPA THHV_LAPIC_GPA.
			 * The capavisor ChangeRights handler records HPA as
			 * apic_access_phys when it sees address == THHV_LAPIC_GPA. */
			ret = themis_send_at(cap_handle, part->domain_handle,
					     0 /* no special attrs */,
					     THHV_LAPIC_GPA);
			if (ret) {
				themis_revoke_mem(parent_handle, cap_sub);
				thhv_cap_table_remove(cap_handle);
				pr_err("thhv: APIC-access SEND_AT failed (%d)\n", ret);
				return ret;
			}
			/* After SEND_AT the sender's cap slot is consumed; remove
			 * from cap_table so the capa engine can reuse the handle. */
			thhv_cap_table_remove(cap_handle);

			/* Track capability for revocation on teardown. */
			sc = kzalloc(sizeof(*sc), GFP_KERNEL);
			if (!sc) {
				themis_revoke_mem(parent_handle, cap_sub);
				thhv_cap_table_remove(cap_handle);
				return -ENOMEM;
			}
			sc->parent_handle = parent_handle;
			sc->sub_handle    = cap_sub;
			sc->region_key    = THHV_LAPIC_GPA >> PAGE_SHIFT;
			spin_lock(&part->sent_caps.lock);
			list_add_tail(&sc->list, &part->sent_caps.list);
			spin_unlock(&part->sent_caps.lock);

			pr_debug("thhv: APIC-access page HPA 0x%llx mapped at GPA 0x%llx for domain 0x%llx\n",
				 hpa, THHV_LAPIC_GPA, part->domain_handle);
		}
		return 0;
	}

	case THHV_SET_INTR_POLICY: {
		struct thhv_set_intr_policy ip;

		if (part->sealed)
			return -EBUSY;
		if (copy_from_user(&ip, uarg, sizeof(ip)))
			return -EFAULT;
		if (ip.visibility > THHV_INTR_VISIBILITY_NOT_REPORT)
			return -EINVAL;
		if (ip.vector == THHV_INTR_POLICY_VEC_DEFAULT)
			return themis_set_def_intr_policy(part->domain_handle,
							  ip.visibility);
		return themis_set_intr_policy(part->domain_handle,
					      ip.vector, ip.visibility);
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

	case THHV_IOEVENTFD: {
		struct thhv_ioeventfd __user *ioe = uarg;
		struct thhv_ioeventfd args;

		if (copy_from_user(&args, ioe, sizeof(args)))
			return -EFAULT;

		if (args.flags & THHV_IOEVENTFD_FLAG_DEASSIGN)
			return thhv_ioeventfd_deassign(part, ioe);
		return thhv_ioeventfd_assign(part, ioe);
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

	INIT_LIST_HEAD(&part->irqfds.list);
	mutex_init(&part->irqfds.lock);

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
