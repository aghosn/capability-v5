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
#include <asm/processor.h>

#include "thhv_internal.h"

/* ── Global DomainComm instance ────────────────────────────────────────────── */

struct domcomm_state thhv_domcomm;
DEFINE_MUTEX(thhv_domcomm_lock);

/* ── Ring helpers ──────────────────────────────────────────────────────────── */

/*
 * Translate a logical byte offset into (page_index, page_offset).
 * The logical capacity may be smaller than the allocated backing.
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
	if (avail > ring->capacity || avail < sizeof(mhdr))
		return -EIO;

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

	if (mhdr.total_size < sizeof(mhdr) || mhdr.total_size > PAGE_SIZE ||
	    mhdr.total_size > avail) {
		pr_warn("thhv: domcomm RX: corrupt message (size %u > avail %u)\n",
			mhdr.total_size, avail);
		return -EIO;
	}

	payload_size = mhdr.total_size - sizeof(mhdr);
	*out_type = mhdr.message_type;
	*out_payload_size = payload_size;
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

/* Caller holds thhv_domcomm_lock for the complete request/reply exchange. */
int domcomm_rx_dequeue_reply(struct domcomm_ring *ring, void *buf, u32 buf_size,
			     u32 expected_type, u32 *out_payload_size)
{
	struct domcomm_doorbell_event notification;
	u32 type, size;
	int ret;

	for (;;) {
		ret = domcomm_rx_dequeue(ring, buf, buf_size, &type, &size);
		if (ret == -ENOSPC && type == DOMCOMM_MSG_DOORBELL_EVENT) {
			ret = domcomm_rx_dequeue(ring, &notification, sizeof(notification),
						 &type, &size);
			if (ret)
				return ret;
			thhv_dispatch_doorbell_event(&notification, size);
			continue;
		}
		if (ret)
			return ret;
		if (type == DOMCOMM_MSG_DOORBELL_EVENT) {
			thhv_dispatch_doorbell_event(buf, size);
			continue;
		}
		if (type != expected_type)
			return -EPROTO;
		*out_payload_size = size;
		return 0;
	}
}

/*
 * domcomm_rx_discard — drop the head message without copying its payload.
 * Padding messages are transparently advanced past, same as in
 * domcomm_rx_dequeue.  Returns 0 on success, -EAGAIN if ring is empty.
 */
int domcomm_rx_discard(struct domcomm_ring *ring, u32 *out_type,
		       u32 *out_payload_size)
{
	struct domcomm_msg_header mhdr;
	u32 head, tail, avail, pg, off, page_remain;

	head = smp_load_acquire(ring->head);
	tail = *ring->tail;
	if (head == tail)
		return -EAGAIN;
	avail = head - tail;

	ring_read(ring, tail, &mhdr, sizeof(mhdr));

	if (mhdr.message_type == DOMCOMM_MSG_NONE) {
		ring_offset_to_page(ring, tail, &pg, &off);
		page_remain = PAGE_SIZE - off;
		smp_store_release(ring->tail, tail + page_remain);
		return domcomm_rx_discard(ring, out_type, out_payload_size);
	}

	if (mhdr.total_size > avail) {
		pr_warn("thhv: domcomm RX: corrupt message (size %u > avail %u)\n",
			mhdr.total_size, avail);
		return -EIO;
	}

	if (out_type)
		*out_type = mhdr.message_type;
	if (out_payload_size)
		*out_payload_size = mhdr.total_size - sizeof(mhdr);

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
		       const void *payload, u32 payload_size,
		       u64 *out_sequence)
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

	/* Return the sequence to the caller if requested. */
	if (out_sequence)
		*out_sequence = mhdr.sequence;

	/* Ensure payload + header are visible before advancing head. */
	smp_wmb();
	smp_store_release(ring->head, head + total_size);

	return 0;
}

/* ── Ring growth ───────────────────────────────────────────────────────────── */

/*
 * domcomm_request_grow — grow the RX or TX ring by nr_pages.
 *
 * Commit one independently translated page at a time. All local allocations
 * precede NOTIFY; successful completion transfers its lifetime to DomainComm.
 */
static int domcomm_request_grow_locked(bool grow_rx, u32 nr_pages)
{
	struct domcomm_state *dc = &thhv_domcomm;
	struct domcomm_ring *ring = grow_rx ? &dc->rx : &dc->tx;
	struct page *pages;
	u64 gpa, hpa, parent_handle, sub;
	u64 carved_handle;
	struct domcomm_grow_request req;
	u64 count, capacity;
	void __iomem **new_vas = NULL;
	void __iomem *va = NULL;
	u32 old_nr;
	int ret, order;

	if (!dc->initialized)
		return -ENODEV;

	if (!(dc->features & THHV_DOMCOMM_SYNC_GROW))
		return -EOPNOTSUPP;
	if (nr_pages != 1 || ring->nr_pages >= U32_MAX / PAGE_SIZE)
		return -EINVAL;

	/* Allocate physically contiguous pages. */
	order = get_order(nr_pages * PAGE_SIZE);
	pages = alloc_pages(GFP_KERNEL | __GFP_ZERO, order);
	if (!pages)
		return -ENOMEM;

	old_nr = ring->nr_pages;
	new_vas = kmalloc_array(old_nr + 1, sizeof(*new_vas), GFP_KERNEL);
	if (!new_vas) {
		ret = -ENOMEM;
		goto err_free;
	}
	memcpy(new_vas, ring->page_vas, old_nr * sizeof(*new_vas));
	va = memremap((u64)page_to_pfn(pages) << PAGE_SHIFT, PAGE_SIZE, MEMREMAP_WB);
	if (!va) {
		ret = -ENOMEM;
		goto err_free;
	}
	new_vas[old_nr] = va;

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
			       THHV_MEM_R_READ | THHV_MEM_R_WRITE,
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

	ret = themis_register_comm(carved_handle, THEMIS_CAP_SELF, U32_MAX);
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
				 &req, sizeof(req), NULL);
	if (ret) {
		pr_err("thhv: domcomm grow: tx_enqueue failed (%d)\n", ret);
		goto err_cap_remove;
	}

	pr_info("thhv: grow[6] tx_enqueue ok, calling NOTIFY...\n");

	/* Notify capavisor to process the TX ring. */
	ret = themis_domcomm_notify_grow(&count, &capacity);
	if (ret) {
		pr_err("thhv: domcomm grow: DOMCOMM_NOTIFY failed (%d)\n", ret);
		goto err_cap_remove;
	}

	/* Nothing after successful adoption allocates or frees backing pages. */
	kfree(ring->page_vas);
	ring->page_vas = new_vas;
	ring->nr_pages  = old_nr + 1;
	ring->capacity  = rounddown_pow_of_two(ring->nr_pages * PAGE_SIZE);
	dc->total_pages++;
	if (count != ring->nr_pages || capacity != ring->capacity) {
		pr_err("thhv: committed growth returned inconsistent metadata\n");
		return -EPROTO;
	}

	pr_info("thhv: domcomm %s ring grown by %u pages → %u pages (%u bytes)\n",
		grow_rx ? "RX" : "TX", nr_pages, ring->nr_pages, ring->capacity);

	return 0;

err_cap_remove:
	thhv_cap_table_remove(carved_handle);
err_revoke:
	{
		int revoke_ret = themis_revoke(parent_handle, sub);

		if (revoke_ret) {
			pr_err("thhv: growth cleanup revoke failed (%d); retaining page\n",
			       revoke_ret);
			memunmap(va);
			kfree(new_vas);
			return ret;
		}
	}
err_free:
	if (va)
		memunmap(va);
	kfree(new_vas);
	__free_pages(pages, order);
	return ret;
}

int domcomm_request_grow(bool grow_rx, u32 nr_pages)
{
	u32 i;
	int ret = 0;

	if (!nr_pages || nr_pages > 256)
		return -EINVAL;
	mutex_lock(&thhv_domcomm_lock);
	for (i = 0; i < nr_pages; i++) {
		ret = domcomm_request_grow_locked(grow_rx, 1);
		if (ret) {
			pr_err("thhv: %s growth stopped after %u/%u pages (%d)\n",
			       grow_rx ? "RX" : "TX", i, nr_pages, ret);
			break;
		}
	}
	mutex_unlock(&thhv_domcomm_lock);
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
		if (dc->features & THHV_DOMCOMM_PAGE_LIST) {
			u32 eax, ebx, ecx, edx;

			cpuid_count(THHV_CPUID_DOMCOMM_LEAF, page_index + 1,
				    &eax, &ebx, &ecx, &edx);
			if (ecx != 1)
				return -EPROTO;
			page_gpa = ((u64)ebx << 32) | eax;
		}

		va = memremap(page_gpa, PAGE_SIZE, MEMREMAP_WB);
		if (!va) {
			pr_err("thhv: domcomm memremap failed for page %u (GPA %#llx)\n",
			       i, page_gpa);
			return -ENOMEM;
		}
		ring->page_vas[i] = va;
	}

	ring->capacity = rounddown_pow_of_two(ring->nr_pages * PAGE_SIZE);
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
	ring->nr_pages = 0;
	ring->capacity = 0;
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

	cpuid_count(THHV_CPUID_DOMCOMM_LEAF, 0, &eax, &ebx, &ecx, &edx);

	gpa = ((u64)ebx << 32) | eax;
	if (gpa == 0 || ecx == 0) {
		pr_info("thhv: no DomainComm region (CPUID leaf %#x: GPA=%#llx pages=%u)\n",
			THHV_CPUID_DOMCOMM_LEAF, gpa, ecx);
		return -ENODEV;
	}

	dc->gpa = gpa;
	dc->total_pages = ecx;
	dc->features = edx;

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
		goto err_cleanup_rx;

	/* Init TX ring (we are the producer). */
	ret = domcomm_ring_init(&dc->tx, &hdr->tx, dc);
	if (ret)
		goto err_cleanup_tx;

	dc->initialized = true;
	return 0;

err_cleanup_tx:
	domcomm_ring_cleanup(&dc->tx);
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
