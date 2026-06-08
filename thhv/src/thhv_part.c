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

#include "thhv_internal.h"

/* ── Partition cleanup ─────────────────────────────────────────────────────── */

static void thhv_partition_destroy(struct kref *ref)
{
	struct thhv_partition *part =
		container_of(ref, struct thhv_partition, refcount);
	int ret;
	u32 i;

	/* Remove from the global partitions list first so concurrent
	 * THHV_DEBUG_LIST_HPAS callers cannot observe a half-torn-down
	 * partition (its rb-tree is freed below). */
	thhv_partitions_unregister(part);

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

	/* Free kernel-allocated EPT META pages.
	 * Pages may be compound (contiguous batches) — only free heads. */
	if (part->ept_meta_pages) {
		unsigned int j;

		for (j = 0; j < part->ept_meta_nr_pages; j++) {
			if (PageHead(part->ept_meta_pages[j]))
				__free_pages(part->ept_meta_pages[j],
					     compound_order(part->ept_meta_pages[j]));
			else if (!PageTail(part->ept_meta_pages[j]))
				__free_page(part->ept_meta_pages[j]);
			/* tail pages freed implicitly with their head */
		}
		kfree(part->ept_meta_pages);
	}

	/* Free kernel-allocated DomainComm pages (compound allocation).
	 * Caps revoked via sent_caps below; only struct pages freed here. */
	if (part->domcomm_pages) {
		__free_pages(part->domcomm_pages[0], DOMCOMM_ORDER);
		kfree(part->domcomm_pages);
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

			{
				unsigned int order = get_order(nr_ept_meta * PAGE_SIZE);
				struct page *compound = alloc_pages(GFP_KERNEL | __GFP_ZERO, order);
				if (!compound) {
					kfree(ept_pages);
					return -ENOMEM;
				}
				for (j = 0; j < nr_ept_meta; j++)
					ept_pages[j] = compound + j;
			}

			ret = thhv_send_meta_pages(part, ept_pages, nr_ept_meta,
						   THHV_META_KEY_EPT);
			if (ret) {
				__free_pages(ept_pages[0], get_order(nr_ept_meta * PAGE_SIZE));
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

	case THHV_SET_POLICY: {
		struct thhv_set_policy sp;

		if (part->sealed)
			return -EBUSY;
		if (copy_from_user(&sp, uarg, sizeof(sp)))
			return -EFAULT;
		return themis_set_policy(part->domain_handle,
					sp.kind, sp.key, sp.sub_key, sp.value);
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
	if (cp.num_vps == 0 || cp.num_vps > THHV_MAX_VPS_PER_DOMAIN)
		return -EINVAL;

	part = kzalloc(sizeof(*part), GFP_KERNEL);
	if (!part)
		return -ENOMEM;

	kref_init(&part->refcount);
	part->sched_policy = cp.sched_policy;
	part->num_vps = cp.num_vps;
	part->sealed = false;

	INIT_LIST_HEAD(&part->global_node);

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

	/*
	 * Provision a channel back to the parent: get a self-channel (handle=0
	 * means "channel pointing at myself") and send it to the child.  The
	 * child will accept it after boot and use it to send capabilities
	 * (e.g. shared bounce buffers) back to the parent.
	 */
	{
		u64 chan;

		ret = themis_get_chan(0, &chan);
		if (ret) {
			pr_err("thhv: GET_CHAN(self) failed (%d)\n", ret);
			goto err_revoke;
		}
		ret = themis_send_chan(chan, part->domain_handle, 0);
		if (ret) {
			pr_err("thhv: SEND_CHAN failed (%d)\n", ret);
			goto err_revoke;
		}
		part->chan_handle = chan;
		pr_debug("thhv: sent channel 0x%llx to child\n", chan);
	}

	/*
	 * Provision per-domain DomainComm pages: allocate 4 kernel pages,
	 * CARVE each from dom0's memory, and SEND to the child with the
	 * COMM attribute.  The capavisor accumulates the HPAs and
	 * initialises the child's DomainComm ring at seal time.
	 * After SEND, the caps belong to the child (identity-mapped,
	 * GPA=HPA); only the struct page pointers are kept for __free_page.
	 */
	{
		unsigned int i;
		struct page **dc_pages;
		struct page *dc_compound;

		dc_pages = kcalloc(DOMCOMM_NR_PAGES, sizeof(*dc_pages),
				   GFP_KERNEL);
		if (!dc_pages) {
			ret = -ENOMEM;
			goto err_revoke;
		}

		dc_compound = alloc_pages(GFP_KERNEL | __GFP_ZERO, DOMCOMM_ORDER);
		if (!dc_compound) {
			kfree(dc_pages);
			ret = -ENOMEM;
			goto err_revoke;
		}
		for (i = 0; i < DOMCOMM_NR_PAGES; i++)
			dc_pages[i] = dc_compound + i;

		/*
		 * Since domcomm pages are now contiguous, only one EPT META
		 * computation is needed for the whole block.
		 */
		{
			u64 dc_base_gpa = (u64)page_to_pfn(dc_compound) << PAGE_SHIFT;
			unsigned int nr_dc_meta = thhv_ept_meta_needed(
				dc_base_gpa, DOMCOMM_NR_PAGES * PAGE_SIZE);
			struct page **dc_meta;
			struct page *dc_meta_compound;
			unsigned int j;

			dc_meta = kcalloc(nr_dc_meta, sizeof(*dc_meta),
					  GFP_KERNEL);
			if (!dc_meta) {
				ret = -ENOMEM;
				goto err_free_domcomm_pages;
			}

			if (nr_dc_meta > 0) {
				unsigned int meta_order = get_order(nr_dc_meta * PAGE_SIZE);

				dc_meta_compound = alloc_pages(GFP_KERNEL | __GFP_ZERO,
							       meta_order);
				if (!dc_meta_compound) {
					kfree(dc_meta);
					ret = -ENOMEM;
					goto err_free_domcomm_pages;
				}
				for (j = 0; j < nr_dc_meta; j++)
					dc_meta[j] = dc_meta_compound + j;
			}

			ret = thhv_send_meta_pages(part, dc_meta, nr_dc_meta,
						   THHV_META_KEY_EPT);
			if (ret) {
				if (nr_dc_meta > 0)
					__free_pages(dc_meta[0],
						     get_order(nr_dc_meta * PAGE_SIZE));
				kfree(dc_meta);
				goto err_free_domcomm_pages;
			}

			/* Track META pages for teardown. */
			if (part->ept_meta_pages) {
				struct page **merged;
				unsigned int total = part->ept_meta_nr_pages +
						     nr_dc_meta;

				merged = krealloc(part->ept_meta_pages,
						  total * sizeof(struct page *),
						  GFP_KERNEL);
				if (!merged) {
					kfree(dc_meta);
					ret = -ENOMEM;
					goto err_free_domcomm_pages;
				}
				memcpy(merged + part->ept_meta_nr_pages,
				       dc_meta,
				       nr_dc_meta * sizeof(struct page *));
				kfree(dc_meta);
				part->ept_meta_pages = merged;
				part->ept_meta_nr_pages = total;
			} else {
				part->ept_meta_pages = dc_meta;
				part->ept_meta_nr_pages = nr_dc_meta;
			}

			pr_debug("thhv: sent %u EPT META pages for domcomm\n",
				 nr_dc_meta);
		}

		/* Single CARVE + SEND for the contiguous domcomm block. */
		{
			u64 gpa = (u64)page_to_pfn(dc_compound) << PAGE_SHIFT;
			u64 hpa = thhv_gpa_to_hpa(gpa);
			u64 parent_handle, carved_handle, sub;
			struct thhv_sent_cap *sc;

			if (hpa == (u64)-1) {
				pr_err("thhv: domcomm block: GPA %#llx not in PA map\n",
				       gpa);
				ret = -EFAULT;
				goto err_free_domcomm;
			}

			ret = thhv_find_parent_handle(hpa,
						      DOMCOMM_NR_PAGES * PAGE_SIZE,
						      &parent_handle);
			if (ret) {
				pr_err("thhv: domcomm block: no parent cap for HPA %#llx\n",
				       hpa);
				goto err_free_domcomm;
			}

			ret = themis_carve(parent_handle, hpa,
					   DOMCOMM_NR_PAGES * PAGE_SIZE,
					   THHV_MEM_R_READ | THHV_MEM_R_WRITE,
					   &carved_handle, &sub);
			if (ret) {
				pr_err("thhv: domcomm block: CARVE failed (%d)\n",
				       ret);
				goto err_free_domcomm;
			}

			ret = themis_send(carved_handle,
					  part->domain_handle,
					  THHV_MEM_A_COMM);
			if (ret) {
				pr_err("thhv: domcomm block: SEND COMM failed (%d)\n",
				       ret);
				themis_revoke_mem(parent_handle, sub);
				goto err_free_domcomm;
			}

			sc = kzalloc(sizeof(*sc), GFP_KERNEL);
			if (!sc) {
				pr_err("thhv: domcomm sent_cap alloc failed\n");
				ret = -ENOMEM;
				goto err_free_domcomm;
			}
			sc->parent_handle = parent_handle;
			sc->sub_handle    = sub;
			sc->region_key    = hpa >> PAGE_SHIFT;

			spin_lock(&part->sent_caps.lock);
			list_add_tail(&sc->list, &part->sent_caps.list);
			spin_unlock(&part->sent_caps.lock);
		}

		part->domcomm_pages = dc_pages;
		part->domcomm_nr_pages = DOMCOMM_NR_PAGES;
		pr_debug("thhv: provisioned %u DomainComm pages for child\n",
			 DOMCOMM_NR_PAGES);

		goto domcomm_done;
err_free_domcomm_pages:
err_free_domcomm:
		__free_pages(dc_compound, DOMCOMM_ORDER);
		kfree(dc_pages);
		goto err_revoke;
domcomm_done:
		;
	}

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
	/* Register before fd_install so an attacker that immediately queries
	 * the global list cannot observe a usable fd whose partition is not
	 * yet enumerable. */
	thhv_partitions_register(part);
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
