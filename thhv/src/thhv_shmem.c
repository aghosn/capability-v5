// SPDX-License-Identifier: GPL-2.0
/*
 * thhv_shmem.c — Capability-backed shared memory (ivshmem rendezvous).
 *
 * Called from thhv_set_guest_memory() when shmem_mode != THHV_SHMEM_MODE_NONE:
 *   - alias/carve: create extra aliases in the rendezvous table for pluggers
 *   - plug: pop a pre-held alias from the rendezvous table, send to child
 *
 * Pinning, translation, EPT meta, and the primary map are handled by the
 * caller (thhv_set_guest_memory in thhv_part.c).  This file only manages
 * the rendezvous table and extra alias bookkeeping.
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

/*
 * Register a rendezvous entry with N extra aliases for future pluggers.
 * Called AFTER the primary alias/carve + SEND_AT are done by the caller.
 *
 * @parent_handle: parent capability the region was aliased/carved from
 * @gm: the SET_GUEST_MEMORY request (has shmem_path, shmem_count, etc.)
 * @hpa_start, @hpa_size: physical address range of the region (single segment)
 */
static long shmem_create(struct thhv_partition *part,
			  struct thhv_set_guest_memory *gm,
			  u64 parent_handle, u64 hpa_start, u64 hpa_size)
{
	struct thhv_shmem_entry *entry;
	int ret, i;

	mutex_lock(&shmem_lock);

	if (find_entry_by_path(gm->shmem_path)) {
		mutex_unlock(&shmem_lock);
		return -EEXIST;
	}

	entry = alloc_entry();
	if (!entry) {
		mutex_unlock(&shmem_lock);
		return -ENOSPC;
	}

	/* Create N extra aliases for future pluggers. */
	for (i = 0; i < (int)gm->shmem_count; i++) {
		u64 ah, as_;
		ret = themis_alias(parent_handle, hpa_start, hpa_size,
				   THHV_MEM_R_READ | THHV_MEM_R_WRITE,
				   &ah, &as_);
		if (ret) {
			int j;
			for (j = 0; j < i; j++)
				themis_revoke_mem(parent_handle,
						 entry->aliases[j].sub_handle);
			entry->used = false;
			mutex_unlock(&shmem_lock);
			return ret;
		}
		entry->aliases[i].cap_handle = ah;
		entry->aliases[i].parent_handle = parent_handle;
		entry->aliases[i].sub_handle = as_;
	}

	strscpy(entry->path, gm->shmem_path, THHV_SHMEM_PATH_MAX);
	entry->backing_hpa = hpa_start;
	entry->size = hpa_size;
	entry->mode = gm->shmem_mode;
	entry->total_count = gm->shmem_count;
	entry->remaining = gm->shmem_count;
	entry->used = true;

	mutex_unlock(&shmem_lock);

	pr_info("thhv: registered shmem path=\"%s\" mode=%s count=%u gpa=0x%llx\n",
		gm->shmem_path,
		gm->shmem_mode == THHV_SHMEM_MODE_ALIAS ? "alias" : "carve",
		gm->shmem_count, gm->guest_pfn << PAGE_SHIFT);

	return 0;
}

/* ── Plug path ─────────────────────────────────────────────────────────────── */

/*
 * Pop a pre-held alias from the rendezvous table and SEND_AT to the child.
 * Called INSTEAD of the standard carve/alias + SEND_AT per-segment loop.
 * The caller has already sent EPT meta pages.
 */
static long shmem_plug(struct thhv_partition *part,
		       struct thhv_set_guest_memory *gm)
{
	struct thhv_shmem_entry *entry;
	struct thhv_shmem_alias *alias;
	int ret;

	mutex_lock(&shmem_lock);

	entry = find_entry_by_path(gm->shmem_path);
	if (!entry) {
		mutex_unlock(&shmem_lock);
		pr_err("thhv: shmem plug: path \"%s\" not found\n",
		       gm->shmem_path);
		return -ENOENT;
	}

	if (entry->remaining <= 0) {
		mutex_unlock(&shmem_lock);
		pr_err("thhv: shmem plug: no aliases remaining for \"%s\"\n",
		       gm->shmem_path);
		return -EAGAIN;
	}

	alias = &entry->aliases[entry->total_count - entry->remaining];
	entry->remaining--;

	ret = themis_send_at(alias->cap_handle, part->domain_handle,
			     gm->attrs, gm->guest_pfn << PAGE_SHIFT);
	if (ret) {
		entry->remaining++;
		mutex_unlock(&shmem_lock);
		return ret;
	}

	mutex_unlock(&shmem_lock);

	/* Track sent cap for revocation on partition teardown. */
	{
		struct thhv_sent_cap *sc;
		sc = kzalloc(sizeof(*sc), GFP_KERNEL);
		if (sc) {
			sc->parent_handle = alias->parent_handle;
			sc->sub_handle = alias->sub_handle;
			sc->region_key = gm->guest_pfn;
			spin_lock(&part->sent_caps.lock);
			list_add_tail(&sc->list, &part->sent_caps.list);
			spin_unlock(&part->sent_caps.lock);
		}
	}

	pr_info("thhv: plugged shmem path=\"%s\" gpa=0x%llx (%d/%d remaining)\n",
		gm->shmem_path, gm->guest_pfn << PAGE_SHIFT,
		entry->remaining, entry->total_count);

	return 0;
}

/* ── Entry point (called from thhv_set_guest_memory) ───────────────────────── */

long thhv_shmem_handle(struct thhv_partition *part,
		       struct thhv_set_guest_memory *gm)
{
	gm->shmem_path[THHV_SHMEM_PATH_MAX - 1] = '\0';

	switch (gm->shmem_mode) {
	case THHV_SHMEM_MODE_ALIAS:
	case THHV_SHMEM_MODE_CARVE:
		if (gm->shmem_count == 0 ||
		    gm->shmem_count > THHV_SHMEM_MAX_ENTRIES)
			return -EINVAL;
		/* Primary map is done by the caller. We just need to
		 * know the parent handle and HPA range for extra aliases.
		 * The caller will invoke us after its own map loop.
		 * We return 0 here — the actual work is deferred to
		 * thhv_shmem_create_post() called from thhv_set_guest_memory
		 * after the per-segment loop. */
		return 0;

	case THHV_SHMEM_MODE_PLUG:
		return shmem_plug(part, gm);

	default:
		return -EINVAL;
	}
}

/* Called after the per-segment alias/carve loop in thhv_set_guest_memory. */
long thhv_shmem_create_post(struct thhv_partition *part,
			    struct thhv_set_guest_memory *gm,
			    u64 parent_handle, u64 hpa_start, u64 hpa_size)
{
	return shmem_create(part, gm, parent_handle, hpa_start, hpa_size);
}

void thhv_shmem_cleanup_partition(struct thhv_partition *part)
{
	/* Sent caps are already cleaned up by the partition teardown path
	 * (thhv_partition_release → revoke all sent_caps).
	 * Rendezvous table entries persist until module unload or
	 * explicit cleanup. */
	(void)part;
}
