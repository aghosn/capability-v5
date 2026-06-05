// SPDX-License-Identifier: GPL-2.0
/*
 * thhv_irqfd.c — IRQFd support for thhv.
 *
 * An irqfd lets a userspace VMM trigger a guest virtual interrupt by writing
 * to an eventfd.  Flow:
 *
 *   assign   → subscribe to the eventfd's poll waitqueue
 *   wakeup   → eventfd signalled → schedule workqueue item
 *   work fn  → themis_inject_interrupt(domain, vp_index, vector) VMCALL
 *   deassign → remove_wait_queue, cancel_work_sync, put ctx
 *
 * The target VP is specified at assign time via the vp_index field.
 */

#include <linux/eventfd.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>

#include "thhv_internal.h"

/* ── Work handler ────────────────────────────────────────────────────────── */

/**
 * thhv_irqfd_inject - Work handler for eventfd-triggered interrupts.
 *
 * Invoked from kernel workqueue when the eventfd signals (device
 * completion).  Issues INJECT_INTERRUPT VMCALL then wakes the target
 * VP if halted.
 */
static void thhv_irqfd_inject(struct work_struct *work)
{
struct thhv_irqfd_entry *entry =
container_of(work, struct thhv_irqfd_entry, work);
int ret;

if (READ_ONCE(entry->deassign))
return;

ret = themis_inject_interrupt(entry->partition->domain_handle,
      entry->vp_index, (u8)entry->vector);
if (ret)
pr_warn("thhv: irqfd inject ret=%d gsi=%u vec=%u vp=%u\n",
    ret, entry->gsi, entry->vector, entry->vp_index);

/* Wake the target VP if it is blocked in HLT. */
thhv_wake_vp(entry->partition, entry->vp_index);
}

/* ── Poll waitqueue wakeup (interrupt/softirq context) ───────────────────── */

/**
 * thhv_irqfd_wakeup - Poll callback for eventfd subscription.
 *
 * Called in interrupt context when the eventfd becomes readable.
 * Schedules the inject work handler on the default workqueue.
 */
static int thhv_irqfd_wakeup(wait_queue_entry_t *wait, unsigned int mode,
     int sync, void *key)
{
struct thhv_irqfd_entry *entry =
container_of(wait, struct thhv_irqfd_entry, wait);
__poll_t flags = (__poll_t)(unsigned long)key;

if ((flags & EPOLLIN) && !READ_ONCE(entry->deassign)) {
schedule_work(&entry->work);
}

return 0;
}

/* poll_table callback: saves wqh so we can call remove_wait_queue later. */
static void thhv_irqfd_ptable_queue_proc(struct file *file,
 wait_queue_head_t *wqh,
 poll_table *pt)
{
struct thhv_irqfd_entry *entry =
container_of(pt, struct thhv_irqfd_entry, pt);
entry->wqh = wqh;
add_wait_queue(wqh, &entry->wait);
}

/* ── Assign ─────────────────────────────────────────────────────────────── */

int thhv_irqfd_assign(struct thhv_partition *part,
      struct thhv_irqfd __user *uarg)
{
struct thhv_irqfd args;
struct thhv_irqfd_entry *entry;
struct eventfd_ctx *ctx;
struct file *file;
__poll_t events;

if (copy_from_user(&args, uarg, sizeof(args)))
return -EFAULT;
if (args.fd < 0)
return -EBADF;
if (args.gsi == 0 || args.gsi > THHV_MAX_GSI)
return -EINVAL;

file = fget(args.fd);
if (!file)
return -EBADF;

ctx = eventfd_ctx_fileget(file);
if (IS_ERR(ctx)) {
fput(file);
return PTR_ERR(ctx);
}

entry = kzalloc(sizeof(*entry), GFP_KERNEL);
if (!entry) {
eventfd_ctx_put(ctx);
fput(file);
return -ENOMEM;
}

entry->gsi       = args.gsi;
entry->vector    = args.vector ? args.vector : args.gsi;
entry->vp_index  = args.vp_index;
entry->eventfd   = ctx;
entry->wqh       = NULL;
entry->partition = part;
entry->deassign  = false;
INIT_LIST_HEAD(&entry->node);
INIT_WORK(&entry->work, thhv_irqfd_inject);
init_waitqueue_func_entry(&entry->wait, thhv_irqfd_wakeup);
init_poll_funcptr(&entry->pt, thhv_irqfd_ptable_queue_proc);

events = vfs_poll(file, &entry->pt);
fput(file);

if (events & EPOLLIN)
schedule_work(&entry->work);

mutex_lock(&part->irqfds.lock);
list_add_tail(&entry->node, &part->irqfds.list);
mutex_unlock(&part->irqfds.lock);

return 0;
}

/* ── Internal teardown ───────────────────────────────────────────────────── */

static void thhv_irqfd_remove(struct thhv_irqfd_entry *entry)
{
WRITE_ONCE(entry->deassign, true);
if (entry->wqh)
remove_wait_queue(entry->wqh, &entry->wait);
cancel_work_sync(&entry->work);
eventfd_ctx_put(entry->eventfd);
kfree(entry);
}

/* ── Deassign ────────────────────────────────────────────────────────────── */

int thhv_irqfd_deassign(struct thhv_partition *part,
struct thhv_irqfd __user *uarg)
{
struct thhv_irqfd args;
struct thhv_irqfd_entry *entry, *tmp;

if (copy_from_user(&args, uarg, sizeof(args)))
return -EFAULT;

mutex_lock(&part->irqfds.lock);
list_for_each_entry_safe(entry, tmp, &part->irqfds.list, node) {
if (entry->gsi != args.gsi)
continue;
list_del(&entry->node);
mutex_unlock(&part->irqfds.lock);
thhv_irqfd_remove(entry);
return 0;
}
mutex_unlock(&part->irqfds.lock);
return -ENOENT;
}

/* ── Release all (partition teardown) ───────────────────────────────────── */

void thhv_irqfd_release_all(struct thhv_partition *part)
{
struct thhv_irqfd_entry *entry, *tmp;
LIST_HEAD(to_free);

mutex_lock(&part->irqfds.lock);
list_for_each_entry_safe(entry, tmp, &part->irqfds.list, node) {
list_del(&entry->node);
list_add(&entry->node, &to_free);
}
mutex_unlock(&part->irqfds.lock);

list_for_each_entry_safe(entry, tmp, &to_free, node) {
list_del(&entry->node);
thhv_irqfd_remove(entry);
}
}
