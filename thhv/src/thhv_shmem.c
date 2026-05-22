// SPDX-License-Identifier: GPL-2.0
/*
 * thhv_shmem.c — Capability-backed shared memory (ivshmem rendezvous).
 *
 * Implements the THHV_REGISTER_SHMEM ioctl for capability-backed ivshmem:
 *   - alias/carve: pin pages, create sub-cap, hold N extra aliases for pluggers
 *   - plug: look up path in rendezvous table, pop a pre-held alias, send to child
 *
 * The rendezvous table is global (protected by mutex), keyed by path string.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/mm.h>
#include "thhv.h"

/* ── Rendezvous table ──────────────────────────────────────────────────────── */

struct thhv_shmem_alias {
	u64 cap_handle;       /* Alias capability handle */
	u64 parent_handle;    /* Parent cap it was aliased from */
	u64 sub_handle;       /* Sub-handle within parent */
};

struct thhv_shmem_entry {
	char path[THHV_SHMEM_PATH_MAX];
	u64  backing_hpa;
	u64  size;
	int  mode;               /* THHV_SHMEM_MODE_ALIAS or _CARVE */
	int  total_count;
	int  remaining;
	struct thhv_shmem_alias aliases[THHV_SHMEM_MAX_ENTRIES];
	bool used;
};

static struct thhv_shmem_entry shmem_table[THHV_SHMEM_MAX_ENTRIES];
static DEFINE_MUTEX(shmem_lock);

void thhv_shmem_init(void)
{
	memset(shmem_table, 0, sizeof(shmem_table));
}

void thhv_shmem_cleanup(void)
{
	/* Aliases are revoked when the creator partition is torn down
	 * (CDT revocation cascades).  Just clear the table. */
	mutex_lock(&shmem_lock);
	memset(shmem_table, 0, sizeof(shmem_table));
	mutex_unlock(&shmem_lock);
}

static struct thhv_shmem_entry *find_entry_by_path(const char *path)
{
	int i;
	for (i = 0; i < THHV_SHMEM_MAX_ENTRIES; i++) {
		if (shmem_table[i].used &&
		    strncmp(shmem_table[i].path, path, THHV_SHMEM_PATH_MAX) == 0)
			return &shmem_table[i];
	}
	return NULL;
}

static struct thhv_shmem_entry *alloc_entry(void)
{
	int i;
	for (i = 0; i < THHV_SHMEM_MAX_ENTRIES; i++) {
		if (!shmem_table[i].used)
			return &shmem_table[i];
	}
	return NULL;
}

/* ── Creator path (alias/carve) ────────────────────────────────────────────── */

static long shmem_create(struct thhv_partition *part,
			  struct thhv_register_shmem *sm)
{
	struct thhv_shmem_entry *entry;
	struct thhv_hpa_segment *segs = NULL;
	unsigned int nr_segs = 0;
	struct page **pages = NULL;
	unsigned long nr_pages;
	u64 parent_handle;
	u64 primary_handle, primary_sub;
	unsigned int ept_meta_needed;
	struct page **ept_pages;
	struct page *compound;
	unsigned int order;
	int ret, i;

	nr_pages = sm->size >> PAGE_SHIFT;

	/* Pin userspace pages. */
	pages = kcalloc(nr_pages, sizeof(struct page *), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	ret = pin_user_pages_fast(sm->userspace_addr, nr_pages,
				  FOLL_WRITE | FOLL_LONGTERM, pages);
	if (ret < 0)
		goto err_free_pages_arr;
	if ((unsigned long)ret != nr_pages) {
		unpin_user_pages(pages, ret);
		ret = -EFAULT;
		goto err_free_pages_arr;
	}

	/* Translate to HPAs. */
	ret = thhv_translate_pages(pages, nr_pages, &segs, &nr_segs);
	if (ret)
		goto err_unpin;

	/* For simplicity, require the region to be physically contiguous
	 * (single HPA segment).  ivshmem sizes are typically small and
	 * file-backed, so this holds in practice. */
	if (nr_segs != 1) {
		pr_err("thhv: shmem region is not physically contiguous (%u segments)\n",
		       nr_segs);
		ret = -EINVAL;
		goto err_free_segs;
	}

	/* Find parent capability covering this HPA. */
	ret = thhv_find_parent_handle(segs[0].hpa_start, segs[0].size,
				      &parent_handle);
	if (ret)
		goto err_free_segs;

	/* Send EPT meta pages for the child to map this region. */
	ept_meta_needed = 8; /* Conservative: enough for any BAR2 mapping */
	ept_pages = kcalloc(ept_meta_needed, sizeof(struct page *), GFP_KERNEL);
	if (!ept_pages) {
		ret = -ENOMEM;
		goto err_free_segs;
	}
	order = get_order(ept_meta_needed * PAGE_SIZE);
	compound = alloc_pages(GFP_KERNEL | __GFP_ZERO, order);
	if (!compound) {
		kfree(ept_pages);
		ret = -ENOMEM;
		goto err_free_segs;
	}
	for (i = 0; i < (int)ept_meta_needed; i++)
		ept_pages[i] = compound + i;

	ret = thhv_send_meta_pages(part, ept_pages, ept_meta_needed,
				   THHV_META_KEY_EPT);
	if (ret) {
		__free_pages(compound, order);
		kfree(ept_pages);
		goto err_free_segs;
	}

	/* Track EPT meta pages in partition for cleanup. */
	if (part->ept_meta_pages) {
		struct page **merged;
		unsigned int total = part->ept_meta_nr_pages + ept_meta_needed;
		merged = krealloc(part->ept_meta_pages,
				  total * sizeof(struct page *), GFP_KERNEL);
		if (!merged) {
			kfree(ept_pages);
			ret = -ENOMEM;
			goto err_free_segs;
		}
		memcpy(merged + part->ept_meta_nr_pages, ept_pages,
		       ept_meta_needed * sizeof(struct page *));
		kfree(ept_pages);
		part->ept_meta_pages = merged;
		part->ept_meta_nr_pages = total;
	} else {
		part->ept_meta_pages = ept_pages;
		part->ept_meta_nr_pages = ept_meta_needed;
	}

	mutex_lock(&shmem_lock);

	/* Check for duplicate path. */
	if (find_entry_by_path(sm->path)) {
		mutex_unlock(&shmem_lock);
		ret = -EEXIST;
		goto err_free_segs;
	}

	entry = alloc_entry();
	if (!entry) {
		mutex_unlock(&shmem_lock);
		ret = -ENOSPC;
		goto err_free_segs;
	}

	/* Create primary alias/carve + N extra aliases for pluggers.
	 *
	 * For alias mode: alias once for the creator, alias N more for pluggers.
	 * For carve mode: alias N times first, then carve for the creator
	 *   (carve removes dom0 access, so aliases must be created before). */

	if (sm->mode == THHV_SHMEM_MODE_ALIAS) {
		/* Primary alias for creator's child domain. */
		ret = themis_alias(parent_handle, segs[0].hpa_start,
				   segs[0].size,
				   THHV_MEM_R_READ | THHV_MEM_R_WRITE,
				   &primary_handle, &primary_sub);
		if (ret)
			goto err_unlock;

		/* Extra aliases for pluggers. */
		for (i = 0; i < (int)sm->count; i++) {
			u64 ah, as_;
			ret = themis_alias(parent_handle, segs[0].hpa_start,
					   segs[0].size,
					   THHV_MEM_R_READ | THHV_MEM_R_WRITE,
					   &ah, &as_);
			if (ret) {
				/* Revoke what we created so far. */
				int j;
				for (j = 0; j < i; j++)
					themis_revoke_mem(parent_handle,
							 entry->aliases[j].sub_handle);
				themis_revoke_mem(parent_handle, primary_sub);
				goto err_unlock;
			}
			entry->aliases[i].cap_handle = ah;
			entry->aliases[i].parent_handle = parent_handle;
			entry->aliases[i].sub_handle = as_;
		}

		/* Send primary alias to child domain at the BAR2 GPA. */
		ret = themis_send_at(primary_handle, part->domain_handle,
				     0, sm->guest_gpa);
		if (ret) {
			int j;
			for (j = 0; j < (int)sm->count; j++)
				themis_revoke_mem(parent_handle,
						 entry->aliases[j].sub_handle);
			themis_revoke_mem(parent_handle, primary_sub);
			goto err_unlock;
		}
	} else {
		/* Carve mode: create aliases first, then carve. */
		for (i = 0; i < (int)sm->count; i++) {
			u64 ah, as_;
			ret = themis_alias(parent_handle, segs[0].hpa_start,
					   segs[0].size,
					   THHV_MEM_R_READ | THHV_MEM_R_WRITE,
					   &ah, &as_);
			if (ret) {
				int j;
				for (j = 0; j < i; j++)
					themis_revoke_mem(parent_handle,
							 entry->aliases[j].sub_handle);
				goto err_unlock;
			}
			entry->aliases[i].cap_handle = ah;
			entry->aliases[i].parent_handle = parent_handle;
			entry->aliases[i].sub_handle = as_;
		}

		/* Now carve — dom0 loses access. */
		ret = themis_carve(parent_handle, segs[0].hpa_start,
				   segs[0].size,
				   THHV_MEM_R_READ | THHV_MEM_R_WRITE,
				   &primary_handle, &primary_sub);
		if (ret) {
			int j;
			for (j = 0; j < (int)sm->count; j++)
				themis_revoke_mem(parent_handle,
						 entry->aliases[j].sub_handle);
			goto err_unlock;
		}

		/* Send carved cap to child domain at BAR2 GPA. */
		ret = themis_send_at(primary_handle, part->domain_handle,
				     0, sm->guest_gpa);
		if (ret) {
			int j;
			for (j = 0; j < (int)sm->count; j++)
				themis_revoke_mem(parent_handle,
						 entry->aliases[j].sub_handle);
			themis_revoke_mem(parent_handle, primary_sub);
			goto err_unlock;
		}
	}

	/* Register in rendezvous table. */
	strscpy(entry->path, sm->path, THHV_SHMEM_PATH_MAX);
	entry->backing_hpa = segs[0].hpa_start;
	entry->size = segs[0].size;
	entry->mode = sm->mode;
	entry->total_count = sm->count;
	entry->remaining = sm->count;
	entry->used = true;

	mutex_unlock(&shmem_lock);

	/* Track sent cap for revocation on partition teardown. */
	{
		struct thhv_sent_cap *sc;
		sc = kzalloc(sizeof(*sc), GFP_KERNEL);
		if (sc) {
			sc->parent_handle = parent_handle;
			sc->sub_handle = primary_sub;
			sc->region_key = sm->guest_gpa >> PAGE_SHIFT;
			spin_lock(&part->sent_caps.lock);
			list_add_tail(&sc->list, &part->sent_caps.list);
			spin_unlock(&part->sent_caps.lock);
		}
	}

	pr_info("thhv: registered shmem path=\"%s\" mode=%s count=%u gpa=0x%llx\n",
		sm->path,
		sm->mode == THHV_SHMEM_MODE_ALIAS ? "alias" : "carve",
		sm->count, sm->guest_gpa);

	kfree(segs);
	/* Keep pages pinned — they back the shared region. */
	kfree(pages);
	return 0;

err_unlock:
	entry->used = false;
	mutex_unlock(&shmem_lock);
err_free_segs:
	kfree(segs);
err_unpin:
	unpin_user_pages(pages, nr_pages);
err_free_pages_arr:
	kfree(pages);
	return ret;
}

/* ── Plug path ─────────────────────────────────────────────────────────────── */

static long shmem_plug(struct thhv_partition *part,
		       struct thhv_register_shmem *sm)
{
	struct thhv_shmem_entry *entry;
	struct thhv_shmem_alias *alias;
	unsigned int ept_meta_needed;
	struct page **ept_pages;
	struct page *compound;
	unsigned int order;
	int ret, i;

	/* Send EPT meta pages for the child to map this region. */
	ept_meta_needed = 8;
	ept_pages = kcalloc(ept_meta_needed, sizeof(struct page *), GFP_KERNEL);
	if (!ept_pages)
		return -ENOMEM;
	order = get_order(ept_meta_needed * PAGE_SIZE);
	compound = alloc_pages(GFP_KERNEL | __GFP_ZERO, order);
	if (!compound) {
		kfree(ept_pages);
		return -ENOMEM;
	}
	for (i = 0; i < (int)ept_meta_needed; i++)
		ept_pages[i] = compound + i;

	ret = thhv_send_meta_pages(part, ept_pages, ept_meta_needed,
				   THHV_META_KEY_EPT);
	if (ret) {
		__free_pages(compound, order);
		kfree(ept_pages);
		return ret;
	}

	/* Track EPT meta pages. */
	if (part->ept_meta_pages) {
		struct page **merged;
		unsigned int total = part->ept_meta_nr_pages + ept_meta_needed;
		merged = krealloc(part->ept_meta_pages,
				  total * sizeof(struct page *), GFP_KERNEL);
		if (!merged) {
			kfree(ept_pages);
			return -ENOMEM;
		}
		memcpy(merged + part->ept_meta_nr_pages, ept_pages,
		       ept_meta_needed * sizeof(struct page *));
		kfree(ept_pages);
		part->ept_meta_pages = merged;
		part->ept_meta_nr_pages = total;
	} else {
		part->ept_meta_pages = ept_pages;
		part->ept_meta_nr_pages = ept_meta_needed;
	}

	mutex_lock(&shmem_lock);

	entry = find_entry_by_path(sm->path);
	if (!entry) {
		mutex_unlock(&shmem_lock);
		pr_err("thhv: shmem plug: path \"%s\" not found\n", sm->path);
		return -ENOENT;
	}

	if (entry->remaining <= 0) {
		mutex_unlock(&shmem_lock);
		pr_err("thhv: shmem plug: no aliases remaining for \"%s\"\n",
		       sm->path);
		return -EAGAIN;
	}

	/* Pop the next alias. */
	alias = &entry->aliases[entry->total_count - entry->remaining];
	entry->remaining--;

	/* Send the alias to the plugging domain at its BAR2 GPA. */
	ret = themis_send_at(alias->cap_handle, part->domain_handle,
			     0, sm->guest_gpa);
	if (ret) {
		/* Put it back. */
		entry->remaining++;
		mutex_unlock(&shmem_lock);
		return ret;
	}

	mutex_unlock(&shmem_lock);

	/* Track sent cap. */
	{
		struct thhv_sent_cap *sc;
		sc = kzalloc(sizeof(*sc), GFP_KERNEL);
		if (sc) {
			sc->parent_handle = alias->parent_handle;
			sc->sub_handle = alias->sub_handle;
			sc->region_key = sm->guest_gpa >> PAGE_SHIFT;
			spin_lock(&part->sent_caps.lock);
			list_add_tail(&sc->list, &part->sent_caps.list);
			spin_unlock(&part->sent_caps.lock);
		}
	}

	pr_info("thhv: plugged shmem path=\"%s\" gpa=0x%llx (%d/%d remaining)\n",
		sm->path, sm->guest_gpa,
		entry->remaining, entry->total_count);

	return 0;
}

/* ── Ioctl entry point ─────────────────────────────────────────────────────── */

long thhv_register_shmem(struct thhv_partition *part, void __user *uarg)
{
	struct thhv_register_shmem sm;

	if (copy_from_user(&sm, uarg, sizeof(sm)))
		return -EFAULT;

	/* Null-terminate path. */
	sm.path[THHV_SHMEM_PATH_MAX - 1] = '\0';

	if (sm.size == 0 || !is_power_of_2(sm.size))
		return -EINVAL;

	switch (sm.mode) {
	case THHV_SHMEM_MODE_ALIAS:
	case THHV_SHMEM_MODE_CARVE:
		if (sm.count == 0 || sm.count > THHV_SHMEM_MAX_ENTRIES)
			return -EINVAL;
		return shmem_create(part, &sm);

	case THHV_SHMEM_MODE_PLUG:
		return shmem_plug(part, &sm);

	default:
		return -EINVAL;
	}
}

void thhv_shmem_cleanup_partition(struct thhv_partition *part)
{
	/* Sent caps are already cleaned up by the partition teardown path
	 * (thhv_partition_release → revoke all sent_caps).
	 * Rendezvous table entries persist until module unload or
	 * explicit cleanup. */
	(void)part;
}
