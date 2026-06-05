// SPDX-License-Identifier: GPL-2.0
/*
 * thhv_part_mem.c — Partition memory management.
 *
 * Split out of thhv_part.c.  Owns:
 *   * the per-partition rb-tree of guest memory regions (thhv_mem_*),
 *   * THHV_SET_GUEST_MEMORY (mapping host pages into the child EPT),
 *   * thhv_send_meta_pages (CARVE + SEND a batch of META pages to the
 *     child domain with run-length contiguity batching).
 *
 * thhv_part.c (partition lifecycle + ioctl dispatch) calls into this
 * file via the non-static helpers exported below.
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/mm.h>

#include "thhv_internal.h"

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
unsigned int thhv_ept_meta_needed(u64 gpa, u64 size)
{
	u64 end = gpa + size - 1;
	unsigned int n = 0;

	/* EPT root (PML4): 1 page, first-time only but safe to over-allocate. */
	n += 1;
	/* PDPT pages (512 GB granularity). */
	n += (unsigned int)((end >> EPT_LEVEL_SHIFT_PML4) - (gpa >> EPT_LEVEL_SHIFT_PML4)) + 1;
	/* PD pages (1 GB granularity). */
	n += (unsigned int)((end >> EPT_LEVEL_SHIFT_PDPT) - (gpa >> EPT_LEVEL_SHIFT_PDPT)) + 1;
	/* PT pages (2 MB granularity). */
	n += (unsigned int)((end >> EPT_LEVEL_SHIFT_PD) - (gpa >> EPT_LEVEL_SHIFT_PD)) + 1;

	return n;
}

long thhv_set_guest_memory(struct thhv_partition *part,
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

	pr_info("thhv: SET_GUEST_MEMORY gfn=0x%llx uaddr=0x%llx size=0x%llx nr_pages=%lu flags=0x%x shmem_mode=%u\n",
		gm.guest_pfn, gm.userspace_addr, gm.size, nr_pages,
		gm.flags, gm.shmem_mode);

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

	/* Pin userspace pages.
	 * For shmem regions (file-backed MAP_SHARED), skip FOLL_LONGTERM
	 * because tmpfs pages fail the longterm-pinnable check on some
	 * kernels.  The pin itself still prevents migration. */
	region->pages = kcalloc(nr_pages, sizeof(struct page *), GFP_KERNEL);
	if (!region->pages) {
		ret = -ENOMEM;
		goto err_free;
	}

	{
		unsigned int gup_flags = FOLL_WRITE;
		if (gm.shmem_mode == THHV_SHMEM_MODE_NONE)
			gup_flags |= FOLL_LONGTERM;

		ret = pin_user_pages_fast(gm.userspace_addr, nr_pages,
					  gup_flags, region->pages);
	}
	if (ret < 0) {
		pr_err("thhv: pin_user_pages_fast failed: ret=%d uaddr=0x%llx nr_pages=%lu\n",
		       ret, gm.userspace_addr, nr_pages);
		goto err_free_pages;
	}
	if ((unsigned long)ret != nr_pages) {
		pr_err("thhv: pin_user_pages_fast partial: got %d/%lu uaddr=0x%llx\n",
		       ret, nr_pages, gm.userspace_addr);
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
	if (ret) {
		pr_err("thhv: translate_pages failed: ret=%d\n", ret);
		goto err_unpin;
	}
	pr_info("thhv: translated %lu pages → %u segs, first hpa=0x%llx size=0x%llx\n",
		nr_pages, nr_segs, segs[0].hpa_start, segs[0].size);

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
		struct page *compound;
		unsigned int j, order;

		ept_pages = kcalloc(nr_ept_meta, sizeof(struct page *),
				    GFP_KERNEL);
		if (!ept_pages) {
			ret = -ENOMEM;
			goto err_free_segs;
		}

		order = get_order(nr_ept_meta * PAGE_SIZE);
		compound = alloc_pages(GFP_KERNEL | __GFP_ZERO, order);
		if (!compound) {
			kfree(ept_pages);
			ret = -ENOMEM;
			goto err_free_segs;
		}
		for (j = 0; j < nr_ept_meta; j++)
			ept_pages[j] = compound + j;

		ret = thhv_send_meta_pages(part, ept_pages, nr_ept_meta,
					   THHV_META_KEY_EPT);
		if (ret) {
			__free_pages(compound, order);
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
	 *
	 * Shmem plug: skip this loop — use pre-held alias from rendezvous.
	 * Shmem alias: create rendezvous aliases from parent, then alias+send.
	 * Shmem carve: carve from parent, create rendezvous aliases from the
	 *              carve, then send the carve.
	 */

	/* For shmem alias mode, create rendezvous aliases from the parent
	 * BEFORE the primary alias+send (parent still owns the region). */
	if (gm.shmem_mode == THHV_SHMEM_MODE_ALIAS) {
		u64 ph;
		if (nr_segs != 1) {
			pr_err("thhv: shmem requires physically contiguous region (%u segs)\n",
			       nr_segs);
			ret = -EINVAL;
			goto err_free_segs;
		}
		ret = thhv_find_parent_handle(segs[0].hpa_start,
					      segs[0].size, &ph);
		if (ret)
			goto err_free_segs;
		ret = thhv_shmem_create_post(part, &gm, ph,
					     segs[0].hpa_start,
					     segs[0].size);
		if (ret)
			goto err_free_segs;
	}

	if (gm.shmem_mode == THHV_SHMEM_MODE_PLUG) {
		/* Plug: pop pre-held alias and SEND_AT. */
		ret = thhv_shmem_handle(part, &gm);
		if (ret)
			goto err_free_segs;
	} else {
		/* Standard per-segment map loop. */
		u64 child_gpa_cursor = gm.guest_pfn << PAGE_SHIFT;
		unsigned int nr_sent = 0;

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

			/* For shmem carve, create rendezvous aliases FROM
			 * the carve (not from parent) before sending it. */
			if (gm.shmem_mode == THHV_SHMEM_MODE_CARVE) {
				ret = thhv_shmem_create_post(part, &gm,
							     cap_handle,
							     segs[i].hpa_start,
							     segs[i].size);
				if (ret) {
					themis_revoke_mem(parent_handle,
							 cap_sub);
					goto err_revoke_partial;
				}
			}

			ret = thhv_cap_table_insert(cap_handle, parent_handle,
						    cap_sub,
						    segs[i].hpa_start,
						    segs[i].size);
			if (ret) {
				themis_revoke_mem(parent_handle, cap_sub);
				goto err_revoke_partial;
			}

			ret = themis_send_at(cap_handle,
					     part->domain_handle,
					     gm.attrs,
					     child_gpa_cursor);
			if (ret) {
				themis_revoke_mem(parent_handle, cap_sub);
				thhv_cap_table_remove(cap_handle);
				goto err_revoke_partial;
			}

			thhv_cap_table_remove(cap_handle);

			sc = kzalloc(sizeof(*sc), GFP_KERNEL);
			if (!sc) {
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
 * CARVE + SEND a set of pages to the child domain with META attribute.
 * Detects physically-contiguous runs and batches them into a single
 * CARVE + SEND per run, reducing the number of capability objects.
 *
 * On success, each run's capability is tracked in part->sent_caps for
 * revocation on teardown.  region_key distinguishes META flavours.
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

	i = 0;
	while (i < nr_pages) {
		u64 run_gpa, run_hpa, parent_handle, cap_handle, cap_sub;
		struct thhv_sent_cap *sc;
		unsigned int run_len = 1;

		run_gpa = (u64)page_to_pfn(pages[i]) << PAGE_SHIFT;
		run_hpa = thhv_gpa_to_hpa(run_gpa);
		if (run_hpa == (u64)-1) {
			pr_err("thhv: META page[%u] GPA 0x%llx: no HPA\n",
			       i, run_gpa);
			ret = -EFAULT;
			goto err_revoke;
		}

		/* Extend run while pages are physically contiguous. */
		while (i + run_len < nr_pages) {
			u64 next_gpa = (u64)page_to_pfn(pages[i + run_len]) << PAGE_SHIFT;
			u64 next_hpa = thhv_gpa_to_hpa(next_gpa);

			if (next_hpa != run_hpa + (u64)run_len * PAGE_SIZE)
				break;
			run_len++;
		}

		ret = thhv_find_parent_handle(run_hpa,
					      (u64)run_len * PAGE_SIZE,
					      &parent_handle);
		if (ret) {
			pr_err("thhv: META run[%u+%u] HPA 0x%llx: no parent cap\n",
			       i, run_len, run_hpa);
			goto err_revoke;
		}

		ret = themis_carve(parent_handle, run_hpa,
				   (u64)run_len * PAGE_SIZE,
				   THHV_MEM_R_READ | THHV_MEM_R_WRITE,
				   &cap_handle, &cap_sub);
		if (ret) {
			pr_err("thhv: META run[%u+%u] CARVE failed (%d)\n",
			       i, run_len, ret);
			goto err_revoke;
		}

		ret = thhv_cap_table_insert(cap_handle, parent_handle,
					    cap_sub, run_hpa,
					    (u64)run_len * PAGE_SIZE);
		if (ret) {
			themis_revoke_mem(parent_handle, cap_sub);
			goto err_revoke;
		}

		ret = themis_send(cap_handle, part->domain_handle,
				  THHV_MEM_A_META);
		if (ret) {
			themis_revoke_mem(parent_handle, cap_sub);
			thhv_cap_table_remove(cap_handle);
			pr_err("thhv: META run[%u+%u] SEND failed (%d)\n",
			       i, run_len, ret);
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
		i += run_len;
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

