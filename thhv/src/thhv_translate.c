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

#include "thhv.h"

/* ── Global PA map ─────────────────────────────────────────────────────────── */

static DEFINE_RWLOCK(pa_map_lock);
static struct rb_root pa_map = RB_ROOT;

struct thhv_pa_range {
	struct rb_node node;
	u64 gpa_start;   /* byte address, page-aligned */
	u64 hpa_start;   /* byte address, page-aligned */
	u64 size;        /* bytes, page-aligned */
};

/* ── Attestation capability table (for parent handle lookup by HPA) ──────── */

struct thhv_attest_cap {
	u64 handle;
	u64 hpa_start;
	u64 size;
};

static struct thhv_attest_cap *attest_caps;
static unsigned int            nr_attest_caps;

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

/* ── THHV_SET_PA_MAP ioctl ─────────────────────────────────────────────────── */

int thhv_set_pa_map(void __user *uarg)
{
	struct thhv_set_pa_map hdr;
	struct thhv_pa_map_entry __user *entries;
	unsigned int i;
	int ret = 0;

	if (copy_from_user(&hdr, uarg, sizeof(hdr)))
		return -EFAULT;
	if (hdr.nr_entries == 0 || hdr.nr_entries > 4096)
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
 * thhv_find_parent_handle — find the capability handle covering an HPA range.
 *
 * Searches the attestation mem_cap entries by HPA, not GPA.  This works
 * correctly at any nesting level (dom0, dom1, dom2, …) because CARVE
 * always operates on HPAs and the attestation provides HPA ranges for
 * each capability regardless of the domain's GPA mapping.
 *
 * Returns 0 on success and writes the handle to *out_handle.
 * Returns -ENXIO if no attestation capability covers [hpa, hpa+size).
 */
int thhv_find_parent_handle(u64 hpa, u64 size, u64 *out_handle)
{
	unsigned int i;

	for (i = 0; i < nr_attest_caps; i++) {
		struct thhv_attest_cap *ac = &attest_caps[i];

		if (ac->hpa_start <= hpa &&
		    hpa + size <= ac->hpa_start + ac->size) {
			*out_handle = ac->handle;
			return 0;
		}
	}

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
	u8 *buf;
	u32 msg_type, payload_size;
	struct domcomm_attest_report *report;
	struct domcomm_mem_cap_entry *mem_caps;
	struct domcomm_pa_map_entry *pa_entries;
	u8 *cursor;
	unsigned int i;
	int ret;

	ret = domcomm_init();
	if (ret == -ENODEV) {
		pr_info("thhv: PA map init — identity passthrough (no DomainComm)\n");
		return 0;
	}
	if (ret)
		return ret;

	/* Allocate buffer for the attestation message payload. */
	buf = kzalloc(DOMCOMM_MAX_PAYLOAD, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	/* Dequeue the pre-populated attestation message. */
	ret = domcomm_rx_dequeue(&thhv_domcomm.rx, buf, DOMCOMM_MAX_PAYLOAD,
				 &msg_type, &payload_size);
	if (ret) {
		pr_err("thhv: no attestation message on RX ring (%d)\n", ret);
		goto out_free;
	}

	if (msg_type != DOMCOMM_MSG_ATTEST) {
		pr_err("thhv: unexpected first message type %#x (expected ATTEST %#x)\n",
		       msg_type, DOMCOMM_MSG_ATTEST);
		ret = -EPROTO;
		goto out_free;
	}

	if (payload_size < sizeof(struct domcomm_attest_report)) {
		pr_err("thhv: attestation payload too small (%u < %zu)\n",
		       payload_size, sizeof(struct domcomm_attest_report));
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
		if (payload_size < expected) {
			pr_err("thhv: attestation payload too small for declared entries "
			       "(%u < %zu)\n", payload_size, expected);
			ret = -EPROTO;
			goto out_free;
		}
	}

	/* Store mem_cap entries for parent handle lookup (by HPA). */
	cursor = buf + sizeof(struct domcomm_attest_report);
	mem_caps = (struct domcomm_mem_cap_entry *)cursor;

	kfree(attest_caps);
	attest_caps = kcalloc(report->nr_mem_caps,
			      sizeof(struct thhv_attest_cap), GFP_KERNEL);
	if (!attest_caps) {
		ret = -ENOMEM;
		goto out_free;
	}
	nr_attest_caps = report->nr_mem_caps;

	for (i = 0; i < report->nr_mem_caps; i++) {
		attest_caps[i].handle    = mem_caps[i].handle;
		attest_caps[i].hpa_start = mem_caps[i].hpa_start;
		attest_caps[i].size      = mem_caps[i].size;

		pr_info("thhv:   mem_cap[%u]: handle=%llu gpa=%#llx hpa=%#llx "
			"size=%#llx rights=%#x attr=%#x\n",
			i, mem_caps[i].handle,
			mem_caps[i].gpa_start, mem_caps[i].hpa_start,
			mem_caps[i].size, mem_caps[i].rights,
			mem_caps[i].attributes);
	}

	/* Skip past dom_cap entries. */
	cursor += (size_t)report->nr_mem_caps * sizeof(struct domcomm_mem_cap_entry);
	cursor += (size_t)report->nr_dom_caps * sizeof(struct domcomm_dom_cap_entry);

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
	kfree(buf);
	return ret;
}

/* ── Module cleanup ────────────────────────────────────────────────────────── */

void thhv_pa_map_cleanup(void)
{
	write_lock(&pa_map_lock);
	pa_map_clear();
	write_unlock(&pa_map_lock);
	kfree(attest_caps);
	attest_caps = NULL;
	nr_attest_caps = 0;
	domcomm_cleanup();
}
