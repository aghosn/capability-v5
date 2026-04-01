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
 * Write bytes to the ring at a logical byte offset.
 * Mirror of ring_read — handles page boundaries.
 * The caller must ensure len bytes of space are available.
 */
static void ring_write(const struct domcomm_ring *ring,
		       u32 offset, const void *src, u32 len)
{
	const u8 *in = src;

	while (len > 0) {
		u32 pg, off, chunk;
		void *dst;

		ring_offset_to_page(ring, offset, &pg, &off);
		chunk = min_t(u32, len, PAGE_SIZE - off);
		dst = ring->page_vas[pg] + off;
		memcpy(dst, in, chunk);

		in     += chunk;
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
 *
 * Protocol (SPSC, we are the sole producer):
 *   1. Check space: capacity - (head - tail) >= total_size
 *   2. Page boundary: if msg doesn't fit in remaining page, write padding
 *   3. Write payload at ring[head + hdr_size]
 *   4. Write header (type, total_size, sequence)
 *   5. wmb()
 *   6. Advance head with release semantics
 */
int domcomm_tx_enqueue(struct domcomm_ring *ring, u32 msg_type,
		       const void *payload, u32 payload_size)
{
	struct domcomm_msg_header mhdr;
	u32 total_size, head, tail, used, free_space;
	u32 pg, off, page_remain;

	total_size = ALIGN(DOMCOMM_MSG_HDR_SIZE + payload_size, 8);
	if (total_size > PAGE_SIZE) {
		pr_err("thhv: domcomm TX: message too large (%u > %lu)\n",
		       total_size, PAGE_SIZE);
		return -EMSGSIZE;
	}

	head = *ring->head;
	tail = smp_load_acquire(ring->tail);

	used = head - tail;
	free_space = ring->capacity - used;

	/* Check if we need to emit padding to reach next page boundary. */
	ring_offset_to_page(ring, head, &pg, &off);
	page_remain = PAGE_SIZE - off;

	if (page_remain < total_size) {
		/* Not enough room in this page — emit a padding message. */
		if (free_space < page_remain + total_size)
			return -ENOSPC;

		memset(&mhdr, 0, sizeof(mhdr));
		mhdr.message_type = DOMCOMM_MSG_NONE;
		mhdr.total_size   = page_remain;
		mhdr.sequence     = ring->next_seq++;

		ring_write(ring, head, &mhdr, sizeof(mhdr));
		/* Consumer skips entire padding area; no need to zero remainder. */

		smp_wmb();
		head += page_remain;
		smp_store_release(ring->head, head);
		free_space -= page_remain;
	}

	if (free_space < total_size)
		return -ENOSPC;

	/* Write payload first (before header — consumer reads header to decide). */
	if (payload_size > 0)
		ring_write(ring, head + DOMCOMM_MSG_HDR_SIZE,
			   payload, payload_size);

	/* Write header. */
	mhdr.message_type = msg_type;
	mhdr.total_size   = total_size;
	mhdr.sequence     = ring->next_seq++;
	ring_write(ring, head, &mhdr, sizeof(mhdr));

	/* Ensure payload + header are visible before advancing head. */
	smp_wmb();
	smp_store_release(ring->head, head + total_size);

	return 0;
}

/* ── Ring growth ───────────────────────────────────────────────────────────── */

/*
 * domcomm_request_grow — grow the RX or TX ring by nr_pages.
 *
 * 1. alloc_pages(order)
 * 2. GPA→HPA for each page
 * 3. Find parent cap in cap table → CARVE
 * 4. REGISTER_COMM(carved_handle, self_domain_handle, 0) → self-ref COMM
 * 5. tx_enqueue(GROW_RX or GROW_TX, {handle, sub, nr_pages})
 * 6. VMCALL DOMCOMM_NOTIFY → capavisor processes TX ring
 * 7. rx_dequeue → GROW_ACK → remap pages, extend local ring
 *
 * Returns 0 on success.
 */
int domcomm_request_grow(bool grow_rx, u32 nr_pages)
{
	struct domcomm_state *dc = &thhv_domcomm;
	struct domcomm_ring *ring = grow_rx ? &dc->rx : &dc->tx;
	struct page *pages;
	u64 gpa, hpa, parent_handle, sub;
	u64 carved_handle;
	struct domcomm_grow_request req;
	struct domcomm_grow_ack ack;
	u32 out_type, out_size;
	void __iomem **new_vas;
	u32 old_nr, i;
	int ret, order;

	if (!dc->initialized)
		return -ENODEV;

	if (dc->self_domain_handle == 0) {
		pr_err("thhv: domcomm grow: no self-domain handle\n");
		return -EINVAL;
	}

	/* Allocate physically contiguous pages. */
	order = get_order(nr_pages * PAGE_SIZE);
	pages = alloc_pages(GFP_KERNEL | __GFP_ZERO, order);
	if (!pages)
		return -ENOMEM;

	/* Translate GPA → HPA (Linux pfn is the GPA in our context). */
	gpa = page_to_pfn(pages) << PAGE_SHIFT;
	hpa = thhv_gpa_to_hpa(gpa);
	if (hpa == (u64)-1) {
		pr_err("thhv: domcomm grow: GPA %#llx not in PA map\n", gpa);
		ret = -EFAULT;
		goto err_free;
	}

	pr_info("thhv: grow[1] alloc ok: gpa=%#llx hpa=%#llx\n", gpa, hpa);

	/* Find parent capability covering this HPA range. */
	ret = thhv_find_parent_handle(hpa, nr_pages * PAGE_SIZE,
				      &parent_handle);
	if (ret) {
		pr_err("thhv: domcomm grow: no parent cap for HPA %#llx (%d)\n",
		       hpa, ret);
		goto err_free;
	}

	pr_info("thhv: grow[2] parent_handle=%llu\n", parent_handle);

	/* CARVE a new capability for the growth pages. */
	ret = themis_carve(parent_handle, hpa,
			       nr_pages * PAGE_SIZE,
			       7 /* RWX */,
			       &carved_handle, &sub);
	if (ret) {
		pr_err("thhv: domcomm grow: CARVE failed (%d)\n", ret);
		goto err_free;
	}

	pr_info("thhv: grow[3] CARVE ok: handle=%llu sub=%llu\n",
		carved_handle, sub);

	/* Insert into cap table (we own it until growth completes). */
	ret = thhv_cap_table_insert(carved_handle, parent_handle,
				    sub, hpa, nr_pages * PAGE_SIZE);
	if (ret) {
		pr_err("thhv: domcomm grow: cap table insert failed (%d)\n", ret);
		goto err_revoke;
	}

	pr_info("thhv: grow[4] cap_table_insert ok\n");

	/* REGISTER_COMM(carved_handle, self_domain_handle, 0) — self-ref. */
	ret = themis_register_comm(carved_handle,
				   dc->self_domain_handle, 0);
	if (ret) {
		pr_err("thhv: domcomm grow: REGISTER_COMM failed (%d)\n", ret);
		goto err_cap_remove;
	}

	pr_info("thhv: grow[5] REGISTER_COMM ok\n");

	/* Send GROW request on TX ring. */
	req.cap_handle = carved_handle;
	req.cap_sub    = sub;
	req.nr_pages   = nr_pages;
	req.reserved   = 0;

	ret = domcomm_tx_enqueue(&dc->tx,
				 grow_rx ? DOMCOMM_MSG_GROW_RX
					 : DOMCOMM_MSG_GROW_TX,
				 &req, sizeof(req));
	if (ret) {
		pr_err("thhv: domcomm grow: tx_enqueue failed (%d)\n", ret);
		goto err_cap_remove;
	}

	pr_info("thhv: grow[6] tx_enqueue ok, calling NOTIFY...\n");

	/* Notify capavisor to process the TX ring. */
	ret = themis_domcomm_notify();
	if (ret) {
		pr_err("thhv: domcomm grow: DOMCOMM_NOTIFY failed (%d)\n", ret);
		goto err_cap_remove;
	}

	pr_info("thhv: grow[7] NOTIFY returned, checking RX for ACK...\n");

	/* Read the GROW_ACK from RX ring. */
	ret = domcomm_rx_dequeue(&dc->rx, &ack, sizeof(ack),
				 &out_type, &out_size);
	if (ret) {
		pr_err("thhv: domcomm grow: no ACK on RX ring (%d)\n", ret);
		goto err_cap_remove;
	}
	if (out_type != DOMCOMM_MSG_GROW_ACK) {
		pr_err("thhv: domcomm grow: unexpected msg type %#x (expected GROW_ACK)\n",
		       out_type);
		ret = -EPROTO;
		goto err_cap_remove;
	}
	if (ack.status != 0) {
		pr_err("thhv: domcomm grow: ACK status=%u\n", ack.status);
		ret = -EIO;
		goto err_cap_remove;
	}

	/* Extend the local ring: remap new pages, grow page_vas array. */
	old_nr = ring->nr_pages;
	new_vas = krealloc(ring->page_vas,
			   (old_nr + nr_pages) * sizeof(void *),
			   GFP_KERNEL);
	if (!new_vas) {
		ret = -ENOMEM;
		goto err_cap_remove;
	}
	ring->page_vas = new_vas;

	for (i = 0; i < nr_pages; i++) {
		u64 page_gpa = gpa + i * PAGE_SIZE;
		void __iomem *va = memremap(page_gpa, PAGE_SIZE, MEMREMAP_WB);

		if (!va) {
			pr_err("thhv: domcomm grow: memremap page %u failed\n", i);
			break;
		}
		ring->page_vas[old_nr + i] = va;
	}
	ring->nr_pages  = old_nr + nr_pages;
	ring->capacity  = ring->nr_pages * PAGE_SIZE;

	/* Re-read head/tail pointers (capavisor may have updated page_count). */
	if (grow_rx) {
		ring->head = &dc->hdr->rx.head;
		ring->tail = &dc->hdr->rx.tail;
	} else {
		ring->head = &dc->hdr->tx.head;
		ring->tail = &dc->hdr->tx.tail;
	}

	pr_info("thhv: domcomm %s ring grown by %u pages → %u pages (%u bytes)\n",
		grow_rx ? "RX" : "TX", nr_pages, ring->nr_pages, ring->capacity);

	return 0;

err_cap_remove:
	thhv_cap_table_remove(carved_handle);
err_revoke:
	themis_revoke_mem(parent_handle, sub);
err_free:
	__free_pages(pages, order);
	return ret;
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

	/* Idempotency: already mapped (e.g. driver reload after rmmod/insmod). */
	if (dc->initialized)
		return 0;

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
