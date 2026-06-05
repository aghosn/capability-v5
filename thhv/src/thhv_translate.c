// SPDX-License-Identifier: GPL-2.0
/*
 * thhv_translate.c — dom0 GPA → HPA address translation.
 *
 * dom0 runs as a guest under the capavisor, so Linux page_to_pfn() yields
 * Guest Physical Addresses (GPAs), not Host Physical Addresses (HPAs).
 * CARVE/ALIAS/SEND capability operations require HPAs (addresses relative
 * to dom0's root memory capability).
 *
 * This module maintains a GPA→HPA mapping derived from the attestation
 * report that the capavisor provides to dom0 at boot.  Userspace loads
 * the map via the THHV_SET_PA_MAP ioctl before issuing any memory
 * operations.
 *
 * If no map has been loaded (e.g. during testing on bare metal), all
 * translations fall through as identity (GPA == HPA).
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/rwlock.h>
#include <linux/mm.h>
#include <linux/uaccess.h>

#include "thhv_internal.h"

/* ── Global PA map ─────────────────────────────────────────────────────────── */

static DEFINE_RWLOCK(pa_map_lock);
static struct rb_root pa_map = RB_ROOT;

struct thhv_pa_range {
	struct rb_node node;
	u64 gpa_start;   /* byte address, page-aligned */
	u64 hpa_start;   /* byte address, page-aligned */
	u64 size;        /* bytes, page-aligned */
};

/* ── Global capability table (§17 of domain-comm-v0.2.md) ────────────────── */

static DEFINE_SPINLOCK(cap_table_lock);
static struct rb_root cap_table = RB_ROOT;

/* ── rb-tree helpers ───────────────────────────────────────────────────────── */

static struct thhv_pa_range *pa_range_find(u64 gpa)
{
	struct rb_node *n = pa_map.rb_node;

	while (n) {
		struct thhv_pa_range *r =
			container_of(n, struct thhv_pa_range, node);
		if (gpa < r->gpa_start)
			n = n->rb_left;
		else if (gpa >= r->gpa_start + r->size)
			n = n->rb_right;
		else
			return r;
	}
	return NULL;
}

static int pa_range_insert(struct thhv_pa_range *range)
{
	struct rb_node **link = &pa_map.rb_node;
	struct rb_node *parent = NULL;

	while (*link) {
		struct thhv_pa_range *r =
			container_of(*link, struct thhv_pa_range, node);
		parent = *link;

		if (range->gpa_start + range->size <= r->gpa_start)
			link = &(*link)->rb_left;
		else if (range->gpa_start >= r->gpa_start + r->size)
			link = &(*link)->rb_right;
		else
			return -EEXIST;
	}

	rb_link_node(&range->node, parent, link);
	rb_insert_color(&range->node, &pa_map);
	return 0;
}

static void pa_map_clear(void)
{
	struct rb_node *n;

	while ((n = rb_first(&pa_map)) != NULL) {
		struct thhv_pa_range *r =
			container_of(n, struct thhv_pa_range, node);
		rb_erase(n, &pa_map);
		kfree(r);
	}
}

/* ── Capability table rb-tree helpers ──────────────────────────────────────── */

static struct thhv_cap_entry *cap_find_locked(u64 handle)
{
	struct rb_node *n = cap_table.rb_node;

	while (n) {
		struct thhv_cap_entry *e =
			container_of(n, struct thhv_cap_entry, node);
		if (handle < e->local_handle)
			n = n->rb_left;
		else if (handle > e->local_handle)
			n = n->rb_right;
		else
			return e;
	}
	return NULL;
}

static int cap_insert_locked(struct thhv_cap_entry *entry)
{
	struct rb_node **link = &cap_table.rb_node;
	struct rb_node *parent = NULL;

	while (*link) {
		struct thhv_cap_entry *e =
			container_of(*link, struct thhv_cap_entry, node);
		parent = *link;

		if (entry->local_handle < e->local_handle)
			link = &(*link)->rb_left;
		else if (entry->local_handle > e->local_handle)
			link = &(*link)->rb_right;
		else
			return -EEXIST;
	}

	rb_link_node(&entry->node, parent, link);
	rb_insert_color(&entry->node, &cap_table);
	return 0;
}

static void cap_table_clear(void)
{
	struct rb_node *n;

	while ((n = rb_first(&cap_table)) != NULL) {
		struct thhv_cap_entry *e =
			container_of(n, struct thhv_cap_entry, node);
		rb_erase(n, &cap_table);
		kfree(e);
	}
}

/*
 * thhv_cap_table_insert — add a capability to the global cap table.
 *
 * Called after a successful CARVE (or at init for attestation roots).
 */
int thhv_cap_table_insert(u64 local_handle, u64 parent_handle,
			  u64 sub_handle, u64 hpa_start, u64 size)
{
	struct thhv_cap_entry *e;
	int ret;

	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		return -ENOMEM;

	e->local_handle  = local_handle;
	e->parent_handle = parent_handle;
	e->sub_handle    = sub_handle;
	e->hpa_start     = hpa_start;
	e->size          = size;

	spin_lock(&cap_table_lock);
	ret = cap_insert_locked(e);
	spin_unlock(&cap_table_lock);

	if (ret)
		kfree(e);
	return ret;
}

/*
 * thhv_cap_table_remove — remove a capability from the global cap table.
 *
 * Called after SEND (handle freed by engine) or on revocation.
 * Returns 0 on success, -ENOENT if handle not found.
 */
int thhv_cap_table_remove(u64 local_handle)
{
	struct thhv_cap_entry *e;

	spin_lock(&cap_table_lock);
	e = cap_find_locked(local_handle);
	if (e)
		rb_erase(&e->node, &cap_table);
	spin_unlock(&cap_table_lock);

	if (!e)
		return -ENOENT;

	kfree(e);
	return 0;
}

/* ── THHV_SET_PA_MAP ioctl ─────────────────────────────────────────────────── */

int thhv_set_pa_map(void __user *uarg)
{
	struct thhv_set_pa_map hdr;
	struct thhv_pa_map_entry __user *entries;
	unsigned int i;
	int ret = 0;

	if (copy_from_user(&hdr, uarg, sizeof(hdr)))
		return -EFAULT;
	if (hdr.nr_entries == 0 || hdr.nr_entries > THHV_PA_MAP_MAX_ENTRIES)
		return -EINVAL;

	entries = (struct thhv_pa_map_entry __user *)(unsigned long)hdr.entries;

	write_lock(&pa_map_lock);
	pa_map_clear();

	for (i = 0; i < hdr.nr_entries; i++) {
		struct thhv_pa_map_entry e;
		struct thhv_pa_range *r;

		if (copy_from_user(&e, &entries[i], sizeof(e))) {
			ret = -EFAULT;
			goto err_clear;
		}
		if (e.size == 0 || (e.gpa & ~PAGE_MASK) ||
		    (e.hpa & ~PAGE_MASK) || (e.size & ~PAGE_MASK)) {
			ret = -EINVAL;
			goto err_clear;
		}

		r = kzalloc(sizeof(*r), GFP_ATOMIC);
		if (!r) {
			ret = -ENOMEM;
			goto err_clear;
		}
		r->gpa_start = e.gpa;
		r->hpa_start = e.hpa;
		r->size = e.size;

		ret = pa_range_insert(r);
		if (ret) {
			kfree(r);
			goto err_clear;
		}
	}

	write_unlock(&pa_map_lock);
	pr_info("thhv: loaded PA map (%u entries)\n", hdr.nr_entries);
	return 0;

err_clear:
	pa_map_clear();
	write_unlock(&pa_map_lock);
	return ret;
}

/* ── Simple GPA→HPA lookup ──────────────────────────────────────────────────── */

/*
 * thhv_gpa_to_hpa — translate a single GPA to HPA.
 *
 * Returns the HPA, or (u64)-1 if not in PA map.
 */
u64 thhv_gpa_to_hpa(u64 gpa)
{
	struct thhv_pa_range *r;
	u64 hpa;

	read_lock(&pa_map_lock);
	if (RB_EMPTY_ROOT(&pa_map)) {
		read_unlock(&pa_map_lock);
		return gpa;  /* identity passthrough */
	}

	r = pa_range_find(gpa);
	if (!r) {
		read_unlock(&pa_map_lock);
		return (u64)-1;
	}

	hpa = r->hpa_start + (gpa - r->gpa_start);
	read_unlock(&pa_map_lock);
	return hpa;
}

/* ── Translation: contiguous GPA range → HPA segments ──────────────────────── */

/*
 * thhv_translate_range — translate dom0 GPA range [gpa, gpa+size) to HPAs.
 *
 * The GPA range may span multiple PA map entries, yielding multiple
 * non-contiguous HPA segments.  Adjacent HPA segments are coalesced.
 *
 * Returns 0 on success, sets *out_segs and *out_nr_segs.
 * Caller must kfree(*out_segs).
 *
 * If no PA map is loaded, identity passthrough (HPA == GPA).
 */
int thhv_translate_range(u64 gpa_start, u64 size,
			 struct thhv_hpa_segment **out_segs,
			 unsigned int *out_nr_segs)
{
	struct thhv_hpa_segment *segs;
	unsigned int nr_segs = 0, max_segs = 16;
	u64 cursor = gpa_start;
	u64 end = gpa_start + size;

	segs = kcalloc(max_segs, sizeof(*segs), GFP_KERNEL);
	if (!segs)
		return -ENOMEM;

	read_lock(&pa_map_lock);

	/* Identity passthrough when no map loaded. */
	if (RB_EMPTY_ROOT(&pa_map)) {
		read_unlock(&pa_map_lock);
		segs[0].hpa_start = gpa_start;
		segs[0].size = size;
		*out_segs = segs;
		*out_nr_segs = 1;
		return 0;
	}

	while (cursor < end) {
		struct thhv_pa_range *r;
		u64 offset, chunk, hpa;

		r = pa_range_find(cursor);
		if (!r) {
			read_unlock(&pa_map_lock);
			pr_warn("thhv: GPA 0x%llx not in PA map\n", cursor);
			kfree(segs);
			return -ENXIO;
		}

		offset = cursor - r->gpa_start;
		chunk = min(end - cursor, r->size - offset);
		hpa = r->hpa_start + offset;

		/* Grow array if needed. */
		if (nr_segs == max_segs) {
			struct thhv_hpa_segment *tmp;

			max_segs *= 2;
			tmp = krealloc(segs, max_segs * sizeof(*segs),
				       GFP_ATOMIC);
			if (!tmp) {
				read_unlock(&pa_map_lock);
				kfree(segs);
				return -ENOMEM;
			}
			segs = tmp;
		}

		/* Coalesce with previous if contiguous in HPA space. */
		if (nr_segs > 0 &&
		    segs[nr_segs - 1].hpa_start +
		    segs[nr_segs - 1].size == hpa) {
			segs[nr_segs - 1].size += chunk;
		} else {
			segs[nr_segs].hpa_start = hpa;
			segs[nr_segs].size = chunk;
			nr_segs++;
		}

		cursor += chunk;
	}

	read_unlock(&pa_map_lock);

	*out_segs = segs;
	*out_nr_segs = nr_segs;
	return 0;
}

/* ── Translation: pinned pages → HPA segments ─────────────────────────────── */

/*
 * thhv_translate_pages — translate pinned struct page[] to HPA segments.
 *
 * Takes pages obtained from pin_user_pages_fast, extracts dom0 GPAs via
 * page_to_pfn, translates through the PA map, and returns coalesced HPA
 * segments suitable for CARVE/ALIAS calls.
 */
int thhv_translate_pages(struct page **pages, unsigned long nr_pages,
			 struct thhv_hpa_segment **out_segs,
			 unsigned int *out_nr_segs)
{
	u64 gpa_start;
	unsigned long i;
	bool contiguous = true;

	if (nr_pages == 0)
		return -EINVAL;

	/* Check if pages are contiguous in GPA space — common fast path. */
	gpa_start = (u64)page_to_pfn(pages[0]) << PAGE_SHIFT;
	for (i = 1; i < nr_pages; i++) {
		if (page_to_pfn(pages[i]) != page_to_pfn(pages[0]) + i) {
			contiguous = false;
			break;
		}
	}

	if (contiguous)
		return thhv_translate_range(gpa_start, nr_pages << PAGE_SHIFT,
					    out_segs, out_nr_segs);

	/* Slow path: per-page translation with coalescing. */
	{
		struct thhv_hpa_segment *segs;
		unsigned int nr_segs = 0, max_segs = 16;

		segs = kcalloc(max_segs, sizeof(*segs), GFP_KERNEL);
		if (!segs)
			return -ENOMEM;

		for (i = 0; i < nr_pages; i++) {
			struct thhv_hpa_segment *s;
			unsigned int ns;
			int ret;
			u64 page_gpa;

			page_gpa = (u64)page_to_pfn(pages[i]) << PAGE_SHIFT;
			ret = thhv_translate_range(page_gpa, PAGE_SIZE, &s, &ns);
			if (ret) {
				kfree(segs);
				return ret;
			}

			/* Coalesce with previous if contiguous. */
			if (nr_segs > 0 &&
			    segs[nr_segs - 1].hpa_start +
			    segs[nr_segs - 1].size == s[0].hpa_start) {
				segs[nr_segs - 1].size += PAGE_SIZE;
			} else {
				if (nr_segs == max_segs) {
					struct thhv_hpa_segment *tmp;

					max_segs *= 2;
					tmp = krealloc(segs,
						       max_segs * sizeof(*segs),
						       GFP_ATOMIC);
					if (!tmp) {
						kfree(s);
						kfree(segs);
						return -ENOMEM;
					}
					segs = tmp;
				}
				segs[nr_segs] = s[0];
				nr_segs++;
			}
			kfree(s);
		}

		*out_segs = segs;
		*out_nr_segs = nr_segs;
		return 0;
	}
}

/*
 * thhv_find_parent_handle — find an owned capability covering an HPA range.
 *
 * Searches the global capability table for an entry whose [hpa_start,
 * hpa_start+size) contains [hpa, hpa+size).  This works at any nesting
 * level because each domain's cap table is populated from its own
 * attestation report.
 *
 * Returns 0 on success and writes the handle to *out_handle.
 * Returns -ENXIO if no capability covers [hpa, hpa+size).
 */
int thhv_find_parent_handle(u64 hpa, u64 size, u64 *out_handle)
{
	struct rb_node *n;

	spin_lock(&cap_table_lock);

	for (n = rb_first(&cap_table); n; n = rb_next(n)) {
		struct thhv_cap_entry *e =
			container_of(n, struct thhv_cap_entry, node);

		if (e->hpa_start <= hpa &&
		    hpa + size <= e->hpa_start + e->size) {
			*out_handle = e->local_handle;
			spin_unlock(&cap_table_lock);
			return 0;
		}
	}

	spin_unlock(&cap_table_lock);
	pr_warn("thhv: no parent cap for HPA %#llx+%#llx\n", hpa, size);
	return -ENXIO;
}

/*
 * thhv_pa_map_init_from_attestation — populate the PA map from attestation.
 *
 * Called at module init after detecting the Themis capavisor.
 *
 * 1. Initialize DomainComm (CPUID discovery, memremap, validate header).
 * 2. Dequeue the DOMCOMM_MSG_ATTEST message from the RX ring.
 * 3. Parse the binary attestation report:
 *    - Extract mem_cap entries → store capability handles.
 *    - Extract pa_map entries → populate the GPA→HPA rb-tree.
 */
int thhv_pa_map_init_from_attestation(void)
{
	u8 *buf = NULL;
	u32 msg_type, chunk_size;
	struct domcomm_attest_report *report;
	struct domcomm_mem_cap_entry *mem_caps;
	struct domcomm_pa_map_entry *pa_entries;
	u8 *cursor;
	unsigned int i;
	int ret;
	u64 total_size = 0;
	u64 offset = 0;
	u64 wrote = 0;

	ret = domcomm_init();
	if (ret == -ENODEV) {
		pr_info("thhv: PA map init — identity passthrough (no DomainComm)\n");
		return 0;
	}
	if (ret)
		return ret;

	/* First hypercall: discover the full report size, also enqueues
	 * the first chunk on the RX ring. */
	ret = themis_attest_self(0, 0, 0, &total_size, &wrote);
	if (ret) {
		pr_err("thhv: ATTEST_SELF hypercall failed (%d)\n", ret);
		return ret;
	}
	if (total_size == 0 || total_size > (16ULL << 20)) {
		pr_err("thhv: ATTEST_SELF returned implausible total %llu\n",
		       total_size);
		return -EPROTO;
	}
	pr_info("thhv: ATTEST_SELF — %llu bytes total (first chunk %llu)\n",
		total_size, wrote);

	buf = kvzalloc(total_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	/* Dequeue chunks one at a time; re-issue ATTEST_SELF with the
	 * running offset until the whole report is reassembled. */
	for (;;) {
		ret = domcomm_rx_dequeue(&thhv_domcomm.rx,
					 buf + offset,
					 (u32)(total_size - offset),
					 &msg_type, &chunk_size);
		if (ret) {
			pr_err("thhv: ATTEST dequeue failed at offset %llu (%d)\n",
			       offset, ret);
			goto out_free;
		}
		if (msg_type != DOMCOMM_MSG_ATTEST) {
			pr_err("thhv: unexpected msg type %#x at offset %llu (expected ATTEST %#x)\n",
			       msg_type, offset, DOMCOMM_MSG_ATTEST);
			ret = -EPROTO;
			goto out_free;
		}
		offset += chunk_size;
		if (offset >= total_size)
			break;
		ret = themis_attest_self(0, offset, 0, &total_size, &wrote);
		if (ret) {
			pr_err("thhv: ATTEST_SELF chunk@%llu failed (%d)\n",
			       offset, ret);
			goto out_free;
		}
	}

	if (offset != total_size) {
		pr_err("thhv: ATTEST reassembly mismatch (%llu vs %llu)\n",
		       offset, total_size);
		ret = -EPROTO;
		goto out_free;
	}

	if (total_size < sizeof(struct domcomm_attest_report)) {
		pr_err("thhv: attestation payload too small (%llu < %zu)\n",
		       total_size, sizeof(struct domcomm_attest_report));
		ret = -EPROTO;
		goto out_free;
	}

	report = (struct domcomm_attest_report *)buf;

	pr_info("thhv: attestation: domain_id=%llu flags=%#x vps=%u "
		"mem_caps=%u dom_caps=%u pa_entries=%u\n",
		report->domain_id, report->flags, report->num_vps,
		report->nr_mem_caps, report->nr_dom_caps, report->nr_pa_entries);

	/* Validate payload size against reported counts. */
	{
		size_t expected = sizeof(struct domcomm_attest_report)
			+ (size_t)report->nr_mem_caps * sizeof(struct domcomm_mem_cap_entry)
			+ (size_t)report->nr_dom_caps * sizeof(struct domcomm_dom_cap_entry)
			+ (size_t)report->nr_pa_entries * sizeof(struct domcomm_pa_map_entry);
		if (total_size < expected) {
			pr_err("thhv: attestation payload too small for declared entries "
			       "(%llu < %zu)\n", total_size, expected);
			ret = -EPROTO;
			goto out_free;
		}
	}

	/* Insert mem_cap entries into the global capability table. */
	cursor = buf + sizeof(struct domcomm_attest_report);
	mem_caps = (struct domcomm_mem_cap_entry *)cursor;

	for (i = 0; i < report->nr_mem_caps; i++) {
		pr_info("thhv:   mem_cap[%u]: handle=%llu gpa=%#llx hpa=%#llx "
			"size=%#llx rights=%#x attr=%#x\n",
			i, mem_caps[i].handle,
			mem_caps[i].gpa_start, mem_caps[i].hpa_start,
			mem_caps[i].size, mem_caps[i].rights,
			mem_caps[i].attributes);

		ret = thhv_cap_table_insert(mem_caps[i].handle, 0,
					    0, mem_caps[i].hpa_start,
					    mem_caps[i].size);
		if (ret) {
			pr_err("thhv: cap table insert handle=%llu failed (%d)\n",
			       mem_caps[i].handle, ret);
			goto out_free;
		}
	}

	pr_info("thhv: capability table loaded (%u entries from attestation)\n",
		report->nr_mem_caps);

	/* Skip past dom_cap entries, but extract the self-domain handle. */
	cursor += (size_t)report->nr_mem_caps * sizeof(struct domcomm_mem_cap_entry);
	{
		struct domcomm_dom_cap_entry *dom_caps =
			(struct domcomm_dom_cap_entry *)cursor;

		thhv_domcomm.self_domain_handle = 0;
		for (i = 0; i < report->nr_dom_caps; i++) {
			pr_info("thhv:   dom_cap[%u]: handle=%llu domain_id=%llu\n",
				i, dom_caps[i].handle, dom_caps[i].domain_id);
			/* Self-referencing cap: domain_id == our own domain_id. */
			if (dom_caps[i].domain_id == report->domain_id)
				thhv_domcomm.self_domain_handle =
					dom_caps[i].handle;
		}

		if (thhv_domcomm.self_domain_handle)
			pr_info("thhv: self-domain handle = %llu\n",
				thhv_domcomm.self_domain_handle);
		else
			pr_warn("thhv: no self-referencing domain capability found\n");

		cursor += (size_t)report->nr_dom_caps *
			  sizeof(struct domcomm_dom_cap_entry);
	}

	/* Parse PA map entries → populate the GPA→HPA rb-tree. */
	pa_entries = (struct domcomm_pa_map_entry *)cursor;

	write_lock(&pa_map_lock);
	pa_map_clear();

	for (i = 0; i < report->nr_pa_entries; i++) {
		struct thhv_pa_range *r;

		r = kzalloc(sizeof(*r), GFP_ATOMIC);
		if (!r) {
			ret = -ENOMEM;
			pa_map_clear();
			write_unlock(&pa_map_lock);
			goto out_free;
		}

		r->gpa_start = pa_entries[i].gpa_start;
		r->hpa_start = pa_entries[i].hpa_start;
		r->size      = pa_entries[i].size;

		ret = pa_range_insert(r);
		if (ret) {
			pr_err("thhv: PA map insert failed for entry %u "
			       "(gpa=%#llx hpa=%#llx size=%#llx): %d\n",
			       i, r->gpa_start, r->hpa_start, r->size, ret);
			kfree(r);
			pa_map_clear();
			write_unlock(&pa_map_lock);
			goto out_free;
		}

		pr_info("thhv:   pa_map[%u]: gpa=%#llx → hpa=%#llx  size=%#llx (%llu MiB)\n",
			i, r->gpa_start, r->hpa_start, r->size,
			r->size / (1024 * 1024));
	}

	write_unlock(&pa_map_lock);

	pr_info("thhv: PA map loaded (%u entries from attestation)\n",
		report->nr_pa_entries);
	ret = 0;

out_free:
	kvfree(buf);
	return ret;
}

/* ── Module cleanup ────────────────────────────────────────────────────────── */

void thhv_pa_map_cleanup(void)
{
	write_lock(&pa_map_lock);
	pa_map_clear();
	write_unlock(&pa_map_lock);

	spin_lock(&cap_table_lock);
	cap_table_clear();
	spin_unlock(&cap_table_lock);

	domcomm_cleanup();
}
