// SPDX-License-Identifier: GPL-2.0
/*
 * thhv_ioeventfd.c — IOEventFd / doorbell fast-path for thhv.
 *
 * Translates THHV_IOEVENTFD ioctl operations into capavisor doorbell
 * registrations (VMCALL_REGISTER_DOORBELL / VMCALL_UNREGISTER_DOORBELL).
 *
 * When the guest writes to a registered GPA, the capavisor writes a
 * DOMCOMM_MSG_DOORBELL_NOTIFY message to the parent's DomainComm RX ring
 * and resumes the child immediately (no VP stop).  The parent driver drains
 * the RX ring after each SWITCH return via thhv_drain_domcomm_rx().
 *
 * Usage (cloud-hypervisor IOEventFd):
 *   1. VMM calls THHV_IOEVENTFD(fd, addr, len, datamatch, flags=DATAMATCH)
 *   2. Driver registers doorbell with capavisor → gets doorbell_id
 *   3. Guest writes to addr → capavisor fast-path → DOORBELL_NOTIFY on RX ring
 *   4. Next time RUN_VP returns (for any reason), driver drains RX ring:
 *      DOORBELL_NOTIFY.doorbell_id → look up entry → eventfd_signal()
 *   5. VMM's virtio worker wakes up, processes the virtio queue
 */

#include <linux/eventfd.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "thhv_internal.h"

/* ── Assign ─────────────────────────────────────────────────────────────── */

int thhv_ioeventfd_assign(struct thhv_partition *part,
			  struct thhv_ioeventfd __user *uarg)
{
	struct thhv_ioeventfd args;
	struct thhv_ioeventfd_entry *entry;
	struct eventfd_ctx *ctx;
	u64 doorbell_id = 0;
	u64 db_flags = 0;
	int ret;

	if (copy_from_user(&args, uarg, sizeof(args)))
		return -EFAULT;

	if (args.fd < 0)
		return -EBADF;

	/* Validate access size: 0 = any, otherwise must be 1/2/4/8. */
	if (args.len != 0 && args.len != 1 && args.len != 2 &&
	    args.len != 4 && args.len != 8)
		return -EINVAL;

	ctx = eventfd_ctx_fdget(args.fd);
	if (IS_ERR(ctx))
		return PTR_ERR(ctx);

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		ret = -ENOMEM;
		goto err_put_ctx;
	}

	/* Build capavisor doorbell flags. */
	if (!(args.flags & THHV_IOEVENTFD_FLAG_DATAMATCH))
		db_flags |= (1u << 0);  /* THEMIC_DOORBELL_FLAG_ANY_VALUE */
	if (args.len == 0)
		db_flags |= (1u << 1);  /* THEMIC_DOORBELL_FLAG_ANY_SIZE */

	ret = themis_register_doorbell(part->domain_handle,
				       args.addr,
				       (u64)args.len,
				       (u64)args.datamatch,
				       db_flags,
				       &doorbell_id);
	if (ret) {
		pr_err("thhv: ioeventfd_assign: REGISTER_DOORBELL failed (%d)\n", ret);
		goto err_free_entry;
	}

	entry->doorbell_id = doorbell_id;
	entry->addr        = args.addr;
	entry->len         = args.len;
	entry->datamatch   = args.datamatch;
	entry->flags       = args.flags;
	entry->eventfd     = ctx;
	entry->partition   = part;
	INIT_LIST_HEAD(&entry->node);

	mutex_lock(&part->ioeventfds.lock);
	list_add_tail(&entry->node, &part->ioeventfds.list);
	mutex_unlock(&part->ioeventfds.lock);

	pr_debug("thhv: ioeventfd_assign: addr=%#llx len=%u doorbell_id=%llu\n",
		 args.addr, args.len, doorbell_id);
	return 0;

err_free_entry:
	kfree(entry);
err_put_ctx:
	eventfd_ctx_put(ctx);
	return ret;
}

/* ── Deassign ────────────────────────────────────────────────────────────── */

int thhv_ioeventfd_deassign(struct thhv_partition *part,
			    struct thhv_ioeventfd __user *uarg)
{
	struct thhv_ioeventfd args;
	struct thhv_ioeventfd_entry *entry, *tmp;
	int ret = -ENOENT;

	if (copy_from_user(&args, uarg, sizeof(args)))
		return -EFAULT;

	mutex_lock(&part->ioeventfds.lock);
	list_for_each_entry_safe(entry, tmp, &part->ioeventfds.list, node) {
		if (entry->addr != args.addr)
			continue;
		if (args.len != 0 && entry->len != args.len)
			continue;

		list_del(&entry->node);
		mutex_unlock(&part->ioeventfds.lock);

		themis_unregister_doorbell(part->domain_handle,
					   entry->doorbell_id);
		eventfd_ctx_put(entry->eventfd);
		kfree(entry);
		return 0;
	}
	mutex_unlock(&part->ioeventfds.lock);
	return ret;
}

/* ── RX ring drain ───────────────────────────────────────────────────────── */

/*
 * thhv_drain_domcomm_rx — process all pending messages on the DomainComm
 * RX ring that were enqueued while the child VP was running.
 *
 * Called after themis_switch() returns (any exit reason) to dispatch
 * asynchronous notifications:
 *   DOMCOMM_MSG_DOORBELL_NOTIFY → signal the matching ioeventfd
 *
 * Other message types are logged and skipped (they are handled elsewhere
 * or are future work).
 */
void thhv_drain_domcomm_rx(struct thhv_partition *part)
{
	struct domcomm_ring *rx = &thhv_domcomm.rx;
	u8 buf[sizeof(struct domcomm_doorbell_notify)];
	u32 msg_type, payload_size;
	int ret;

	for (;;) {
		ret = domcomm_rx_dequeue(rx, buf, sizeof(buf),
					 &msg_type, &payload_size);
		if (ret == -EAGAIN)
			break;  /* ring empty */
		if (ret == -ENOSPC) {
			/* Head message is larger than our doorbell-sized
			 * scratch buffer (e.g. a stale ATTEST chunk left
			 * behind by a failed ioctl).  Drop it without
			 * copying so the ring keeps draining instead of
			 * spamming pr_warn forever.
			 */
			u32 drop_type = 0, drop_size = 0;
			int dret = domcomm_rx_discard(rx, &drop_type,
						      &drop_size);
			if (dret < 0) {
				pr_warn_ratelimited("thhv: domcomm RX discard failed: %d\n",
						    dret);
				break;
			}
			pr_warn_ratelimited("thhv: dropped oversized RX msg type=%u size=%u\n",
					    drop_type, drop_size);
			continue;
		}
		if (ret < 0) {
			pr_warn_ratelimited("thhv: domcomm RX dequeue error: %d\n", ret);
			break;
		}

		if (msg_type == DOMCOMM_MSG_DOORBELL_NOTIFY) {
			struct domcomm_doorbell_notify *n =
				(struct domcomm_doorbell_notify *)buf;
			struct thhv_ioeventfd_entry *entry;
			bool found = false;

			pr_debug("thhv: DOORBELL_NOTIFY id=%u\n", n->doorbell_id);

			if (payload_size < sizeof(*n)) {
				pr_warn_ratelimited("thhv: DOORBELL_NOTIFY too small (%u)\n",
						    payload_size);
				continue;
			}

			/* Find the matching ioeventfd entry and signal it. */
			mutex_lock(&part->ioeventfds.lock);
			list_for_each_entry(entry, &part->ioeventfds.list, node) {
				if (entry->doorbell_id == n->doorbell_id) {
					eventfd_signal(entry->eventfd);
					found = true;
					break;
				}
			}
			if (!found)
				pr_warn_ratelimited("thhv: no ioeventfd for doorbell_id=%u\n",
						    n->doorbell_id);
			mutex_unlock(&part->ioeventfds.lock);

		} else if (msg_type != DOMCOMM_MSG_GROW_ACK) {
			/* Grow ACKs are handled synchronously in domcomm_request_grow;
			 * anything else here is unexpected in the sync path. */
			pr_debug("thhv: domcomm RX: unhandled msg_type %#x (size %u)\n",
				 msg_type, payload_size);
		}
	}
}
