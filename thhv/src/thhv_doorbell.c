// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>
#include <linux/eventfd.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "thhv_internal.h"

struct thhv_doorbell {
	struct list_head owner_node;
	struct list_head rx_node;
	u64 port;
	struct eventfd_ctx *eventfd;
};

static DEFINE_MUTEX(doorbell_lock);
static LIST_HEAD(doorbell_receivers);

static struct thhv_doorbell *find_doorbell(struct thhv_device *device, u64 port)
{
	struct thhv_doorbell *doorbell;

	list_for_each_entry(doorbell, &device->doorbells, owner_node)
		if (doorbell->port == port)
			return doorbell;
	return NULL;
}

static void free_doorbell(struct thhv_doorbell *doorbell)
{
	list_del(&doorbell->owner_node);
	list_del(&doorbell->rx_node);
	if (doorbell->eventfd)
		eventfd_ctx_put(doorbell->eventfd);
	kfree(doorbell);
}

long thhv_doorbell_create(struct thhv_device *device, void __user *uarg)
{
	struct thhv_create_doorbell args;
	struct thhv_doorbell *doorbell;
	u64 vp;
	int ret;

	if (copy_from_user(&args, uarg, sizeof(args)))
		return -EFAULT;
	if ((args.kind != THEMIS_DOORBELL_SYNC &&
	     args.kind != THEMIS_DOORBELL_ASYNC) ||
	    (args.kind == THEMIS_DOORBELL_SYNC && args.vp) ||
	    (args.kind == THEMIS_DOORBELL_ASYNC &&
	     (args.vp >= nr_cpu_ids || !cpu_online(args.vp))))
		return -EINVAL;
	doorbell = kzalloc(sizeof(*doorbell), GFP_KERNEL);
	if (!doorbell)
		return -ENOMEM;
	vp = 0;
	if (args.kind == THEMIS_DOORBELL_ASYNC) {
		ret = thhv_doorbell_target_vp(args.vp, &vp);
		if (ret) {
			kfree(doorbell);
			return ret;
		}
	}
	ret = themis_create_doorbell(THEMIS_CAP_SELF, thhv_doorbell_vector(),
				    args.kind, vp, &args.handle, &args.port);
	if (ret) {
		kfree(doorbell);
		return ret;
	}
	doorbell->port = args.port;
	args.recipient = thhv_domcomm.domain_id;
	mutex_lock(&doorbell_lock);
	list_add_tail(&doorbell->owner_node, &device->doorbells);
	list_add_tail(&doorbell->rx_node, &doorbell_receivers);
	if (copy_to_user(uarg, &args, sizeof(args))) {
		ret = themis_revoke(THEMIS_CAP_SELF, args.port);
		if (!ret)
			free_doorbell(doorbell);
		else
			pr_err("thhv: failed to revoke unpublished doorbell port=%llu (%d)\n",
			       args.port, ret);
		ret = -EFAULT;
	}
	mutex_unlock(&doorbell_lock);
	return ret;
}

long thhv_doorbell_eventfd(struct thhv_device *device, void __user *uarg)
{
	struct thhv_doorbell_eventfd args;
	struct thhv_doorbell *doorbell;
	struct eventfd_ctx *ctx = NULL, *old;
	int ret = 0;

	if (copy_from_user(&args, uarg, sizeof(args)))
		return -EFAULT;
	if (args.reserved || args.fd < -1)
		return -EINVAL;
	if (args.fd >= 0) {
		ctx = eventfd_ctx_fdget(args.fd);
		if (IS_ERR(ctx))
			return PTR_ERR(ctx);
	}
	mutex_lock(&doorbell_lock);
	doorbell = find_doorbell(device, args.port);
	if (!doorbell) {
		ret = -ENOENT;
	} else {
		old = doorbell->eventfd;
		doorbell->eventfd = ctx;
		ctx = old;
	}
	mutex_unlock(&doorbell_lock);
	if (ctx)
		eventfd_ctx_put(ctx);
	return ret;
}

long thhv_doorbell_revoke(struct thhv_device *device, void __user *uarg)
{
	struct thhv_revoke_cap args;
	struct thhv_doorbell *doorbell;
	int ret;

	if (copy_from_user(&args, uarg, sizeof(args)))
		return -EFAULT;
	mutex_lock(&doorbell_lock);
	ret = themis_revoke(args.parent, args.sub);
	if (!ret && args.parent == THEMIS_CAP_SELF) {
		doorbell = find_doorbell(device, args.sub);
		if (doorbell)
			free_doorbell(doorbell);
	}
	mutex_unlock(&doorbell_lock);
	return ret;
}

int thhv_doorbell_release(struct thhv_device *device)
{
	struct thhv_doorbell *doorbell, *next;
	int ret = 0;

	mutex_lock(&doorbell_lock);
	list_for_each_entry_safe(doorbell, next, &device->doorbells, owner_node) {
		int err = themis_revoke(THEMIS_CAP_SELF, doorbell->port);

		if (err && err != -ENOENT) {
			/* Keep the vector reserved if live authority cannot be removed. */
			pr_err("thhv: doorbell port=%llu revoke failed (%d); retaining IRQ registration\n",
			       doorbell->port, err);
			__module_get(THIS_MODULE);
			ret = err;
		}
		free_doorbell(doorbell);
	}
	mutex_unlock(&doorbell_lock);
	return ret;
}

void thhv_dispatch_doorbell_event(const void *payload, u32 payload_size)
{
	const struct domcomm_doorbell_event *event = payload;
	struct thhv_doorbell *doorbell;

	if (payload_size != sizeof(*event)) {
		pr_warn_ratelimited("thhv: malformed doorbell event (%u)\n", payload_size);
		return;
	}
	mutex_lock(&doorbell_lock);
	list_for_each_entry(doorbell, &doorbell_receivers, rx_node) {
		if (doorbell->port == event->port) {
			if (doorbell->eventfd)
				eventfd_signal(doorbell->eventfd);
			break;
		}
	}
	mutex_unlock(&doorbell_lock);
}
