// SPDX-License-Identifier: GPL-2.0
/*
 * thhv_domcomm.c — DomainComm shared-memory ring between dom0 and capavisor.
 *
 * The capavisor pre-allocates a DomainComm region for dom0 during boot:
 *   - Marked TYPE_RESERVED in e820 so Linux won't use the pages.
 *   - Discoverable via CPUID leaf 0x40000002 (GPA in EAX:EBX, pages in ECX).
 *   - Contains a fixed header page + RX ring pages + TX ring pages.
 *   - The capavisor pre-populates the RX ring with a binary attestation
 *     report before dom0 boots.
 *
 * This module provides:
 *   domcomm_init()       — CPUID discovery, memremap, header validation
 *   domcomm_rx_dequeue() — page-aware SPSC consumer for the RX ring
 *   domcomm_tx_enqueue() — page-aware SPSC producer for the TX ring
 *   domcomm_cleanup()    — release memremap'd pages
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <asm/cpuid.h>

#include "thhv.h"

/* ── Global DomainComm instance ────────────────────────────────────────────── */

struct domcomm_state thhv_domcomm;

/* ── Ring helpers ──────────────────────────────────────────────────────────── */

/*
 * Translate a logical byte offset into (page_index, page_offset).
 * Messages never cross page boundaries, so the caller must handle
 * padding when a message doesn't fit in the remaining page space.
 */
static inline void ring_offset_to_page(const struct domcomm_ring *ring,
				       u32 byte_offset,
				       u32 *page_idx, u32 *page_off)
{
	u32 wrapped = byte_offset % ring->capacity;
	*page_idx = wrapped / PAGE_SIZE;
	*page_off = wrapped % PAGE_SIZE;
}

/*
 * Read bytes from the ring at a logical byte offset.
 * Handles page boundaries by reading up to page end, then continuing
 * on the next page.  The caller must ensure len bytes are available.
 */
static void ring_read(const struct domcomm_ring *ring,
		      u32 offset, void *dst, u32 len)
{
	u8 *out = dst;

	while (len > 0) {
		u32 pg, off, chunk;
		void *src;

		ring_offset_to_page(ring, offset, &pg, &off);
		chunk = min_t(u32, len, PAGE_SIZE - off);
		src = ring->page_vas[pg] + off;
		memcpy(out, src, chunk);

		out    += chunk;
		offset += chunk;
		len    -= chunk;
	}
}

/*
 * domcomm_rx_dequeue — consume one message from the RX ring.
 *
 * Returns 0 on success, -EAGAIN if ring is empty, -ENOSPC if message
 * is larger than buf_size.  On success, *out_type and *out_payload_size
 * are set, and the payload (without the 16-byte header) is copied to buf.
 */
int domcomm_rx_dequeue(struct domcomm_ring *ring, void *buf,
		       u32 buf_size, u32 *out_type, u32 *out_payload_size)
{
	struct domcomm_msg_header mhdr;
	u32 head, tail, avail;
	u32 pg, off, page_remain;
	u32 payload_size;

	/* Read producer head with acquire semantics. */
	head = smp_load_acquire(ring->head);
	tail = *ring->tail;

	if (head == tail)
		return -EAGAIN;

	avail = head - tail;

	/* Peek at the message header. */
	ring_read(ring, tail, &mhdr, sizeof(mhdr));

	/* Skip padding messages. */
	if (mhdr.message_type == DOMCOMM_MSG_NONE) {
		/*
		 * Padding fills the remainder of a page.  Advance tail to
		 * the start of the next page.
		 */
		ring_offset_to_page(ring, tail, &pg, &off);
		page_remain = PAGE_SIZE - off;
		smp_store_release(ring->tail, tail + page_remain);
		/* Retry: there should be a real message on the next page. */
		return domcomm_rx_dequeue(ring, buf, buf_size,
					 out_type, out_payload_size);
	}

	if (mhdr.total_size > avail) {
		pr_warn("thhv: domcomm RX: corrupt message (size %u > avail %u)\n",
			mhdr.total_size, avail);
		return -EIO;
	}

	payload_size = mhdr.total_size - sizeof(mhdr);
	if (payload_size > buf_size)
		return -ENOSPC;

	/* Read payload (skip past the header). */
	ring_read(ring, tail + sizeof(mhdr), buf, payload_size);

	*out_type = mhdr.message_type;
	*out_payload_size = payload_size;

	/* Advance tail with release semantics. */
	smp_store_release(ring->tail, tail + mhdr.total_size);
	return 0;
}

/*
 * domcomm_tx_enqueue — produce one message on the TX ring.
 *
 * Returns 0 on success, -ENOSPC if the ring is full.
 */
int domcomm_tx_enqueue(struct domcomm_ring *ring, u32 msg_type,
		       const void *payload, u32 payload_size)
{
	/* TODO(M4): implement for ring growth and capability enumeration. */
	(void)ring;
	(void)msg_type;
	(void)payload;
	(void)payload_size;
	return -ENOSYS;
}

/* ── Init / cleanup ────────────────────────────────────────────────────────── */

/*
 * Set up a domcomm_ring from the header's ring_meta + the memremap'd
 * region base.
 */
static int domcomm_ring_init(struct domcomm_ring *ring,
			     struct domcomm_ring_meta *meta,
			     struct domcomm_state *dc)
{
	u32 i;

	ring->nr_pages = meta->page_count;
	if (ring->nr_pages == 0)
		return 0;  /* ring not present (e.g. TX with 0 pages) */

	ring->page_vas = kcalloc(ring->nr_pages, sizeof(void *), GFP_KERNEL);
	if (!ring->page_vas)
		return -ENOMEM;

	for (i = 0; i < ring->nr_pages; i++) {
		u32 page_index = meta->page_offset + i;
		u64 page_gpa = dc->gpa + (u64)page_index * PAGE_SIZE;
		void __iomem *va;

		if (page_index >= dc->total_pages) {
			pr_err("thhv: domcomm ring page %u out of range (total %u)\n",
			       page_index, dc->total_pages);
			return -EINVAL;
		}

		va = memremap(page_gpa, PAGE_SIZE, MEMREMAP_WB);
		if (!va) {
			pr_err("thhv: domcomm memremap failed for page %u (GPA %#llx)\n",
			       i, page_gpa);
			return -ENOMEM;
		}
		ring->page_vas[i] = va;
	}

	ring->capacity = ring->nr_pages * PAGE_SIZE;
	ring->head = &meta->head;
	ring->tail = &meta->tail;
	ring->next_seq = 0;

	return 0;
}

static void domcomm_ring_cleanup(struct domcomm_ring *ring)
{
	u32 i;

	if (!ring->page_vas)
		return;

	for (i = 0; i < ring->nr_pages; i++) {
		if (ring->page_vas[i])
			memunmap(ring->page_vas[i]);
	}
	kfree(ring->page_vas);
	ring->page_vas = NULL;
}

/*
 * domcomm_init — discover and map the DomainComm region.
 *
 * 1. CPUID 0x40000002 → GPA (EAX:EBX) and page count (ECX).
 * 2. memremap the header page, validate magic/version.
 * 3. Set up RX and TX ring state from header metadata.
 */
int domcomm_init(void)
{
	struct domcomm_state *dc = &thhv_domcomm;
	u32 eax, ebx, ecx, edx;
	u64 gpa;
	void __iomem *base;
	struct domcomm_header *hdr;
	int ret;

	cpuid(THHV_CPUID_DOMCOMM_LEAF, &eax, &ebx, &ecx, &edx);

	gpa = ((u64)ebx << 32) | eax;
	if (gpa == 0 || ecx == 0) {
		pr_info("thhv: no DomainComm region (CPUID leaf %#x: GPA=%#llx pages=%u)\n",
			THHV_CPUID_DOMCOMM_LEAF, gpa, ecx);
		return -ENODEV;
	}

	dc->gpa = gpa;
	dc->total_pages = ecx;

	pr_info("thhv: DomainComm at GPA %#llx (%u pages = %u KiB)\n",
		gpa, ecx, ecx * 4);

	/* Map the header page. */
	base = memremap(gpa, PAGE_SIZE, MEMREMAP_WB);
	if (!base) {
		pr_err("thhv: domcomm memremap header failed (GPA %#llx)\n", gpa);
		return -ENOMEM;
	}

	dc->base = base;
	dc->hdr  = (struct domcomm_header *)base;
	hdr = dc->hdr;

	/* Validate header. */
	if (hdr->magic != DOMCOMM_MAGIC) {
		pr_err("thhv: domcomm bad magic: %#x (expected %#x)\n",
		       hdr->magic, DOMCOMM_MAGIC);
		ret = -EINVAL;
		goto err_unmap_base;
	}

	if (hdr->version_major != DOMCOMM_VERSION_MAJOR) {
		pr_err("thhv: domcomm version mismatch: %u.%u (expected %u.x)\n",
		       hdr->version_major, hdr->version_minor,
		       DOMCOMM_VERSION_MAJOR);
		ret = -EINVAL;
		goto err_unmap_base;
	}

	pr_info("thhv: domcomm v%u.%u  total_pages=%u  rx=%u pages  tx=%u pages\n",
		hdr->version_major, hdr->version_minor, hdr->total_pages,
		hdr->rx.page_count, hdr->tx.page_count);

	/* Init RX ring (we are the consumer). */
	ret = domcomm_ring_init(&dc->rx, &hdr->rx, dc);
	if (ret)
		goto err_unmap_base;

	/* Init TX ring (we are the producer). */
	ret = domcomm_ring_init(&dc->tx, &hdr->tx, dc);
	if (ret)
		goto err_cleanup_rx;

	dc->initialized = true;
	return 0;

err_cleanup_rx:
	domcomm_ring_cleanup(&dc->rx);
err_unmap_base:
	memunmap(base);
	dc->base = NULL;
	dc->hdr  = NULL;
	return ret;
}

void domcomm_cleanup(void)
{
	struct domcomm_state *dc = &thhv_domcomm;

	if (!dc->initialized)
		return;

	domcomm_ring_cleanup(&dc->tx);
	domcomm_ring_cleanup(&dc->rx);

	if (dc->base) {
		memunmap(dc->base);
		dc->base = NULL;
		dc->hdr  = NULL;
	}

	dc->initialized = false;
}
