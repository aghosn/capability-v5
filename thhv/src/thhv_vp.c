// SPDX-License-Identifier: GPL-2.0
/*
 * thhv_vp.c — VP fd lifecycle and ioctl dispatch.
 *
 * A VP fd is returned by THHV_CREATE_VP on a partition fd.
 * It wraps a single virtual processor within a Themis domain.
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/anon_inodes.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <asm/vmx.h>

#include "thhv.h"

/* ── COMM page exit info helpers ────────────────────────────────────────────── */

/*
 * Read a value from the COMM page at a given byte offset.
 * The COMM page is kernel-mapped at vp->comm_kaddr.
 */
static inline u32 comm_read32(struct thhv_vp *vp, unsigned int off)
{
	return *(volatile u32 *)((u8 *)vp->comm_kaddr + off);
}

static inline u64 comm_read64(struct thhv_vp *vp, unsigned int off)
{
	return *(volatile u64 *)((u8 *)vp->comm_kaddr + off);
}

/*
 * Map VMX exit reason to THHV_EXIT_* type.
 *
 * PROVISIONAL — The capavisor's platform abstraction will likely
 * translate raw VMX exit reasons before the parent sees them.
 * This mapper may be replaced entirely once the SWITCH handler
 * and exit delivery mechanism are designed.  Using linux/vmx.h
 * constants for now as a reference; the actual exit codes the
 * driver receives may be Themis-specific, not raw VMX reasons.
 */
static u32 vmx_reason_to_thhv_exit(u32 reason)
{
	switch (reason) {
	case EXIT_REASON_EXCEPTION_NMI:    return THHV_EXIT_EXCEPTION;
	case EXIT_REASON_EXTERNAL_INTERRUPT: return THHV_EXIT_INTR;
	case EXIT_REASON_TRIPLE_FAULT:     return THHV_EXIT_SHUTDOWN;
	case EXIT_REASON_CPUID:            return THHV_EXIT_CPUID;
	case EXIT_REASON_HLT:             return THHV_EXIT_HLT;
	case EXIT_REASON_VMCALL:          return THHV_EXIT_HYPERCALL;
	case EXIT_REASON_IO_INSTRUCTION:  return THHV_EXIT_IO;
	case EXIT_REASON_MSR_READ:        return THHV_EXIT_MSR;
	case EXIT_REASON_MSR_WRITE:       return THHV_EXIT_MSR;
	case EXIT_REASON_EPT_VIOLATION:   return THHV_EXIT_MEMORY_FAULT;
	case EXIT_REASON_EPT_MISCONFIG:   return THHV_EXIT_MEMORY_FAULT;
	default:                          return THHV_EXIT_UNKNOWN;
	}
}

/*
 * Parse the COMM page exit info into a thhv_exit_msg for userspace.
 */
static void thhv_build_exit_msg(struct thhv_vp *vp, struct thhv_exit_msg *msg)
{
	u32 vmx_reason;
	u64 exit_qual;

	memset(msg, 0, sizeof(*msg));

	vmx_reason = comm_read32(vp, THHV_COMM_EXIT_REASON_OFF);
	exit_qual  = comm_read64(vp, THHV_COMM_EXIT_QUAL_OFF);
	msg->instr_len = comm_read32(vp, THHV_COMM_EXIT_INSTR_LEN_OFF);
	msg->exit_type = vmx_reason_to_thhv_exit(vmx_reason);

	switch (msg->exit_type) {
	case THHV_EXIT_IO:
		/* Exit qual bits: [15:0] port, [2:0] size, [3] direction */
		msg->io.port = (u16)(exit_qual >> 16);
		msg->io.access_size = (exit_qual & 0x7) + 1;
		msg->io.is_write = !(exit_qual & (1 << 3));
		break;
	case THHV_EXIT_MMIO:
		msg->mmio.gpa = comm_read64(vp, THHV_COMM_EXIT_GPA_OFF);
		msg->mmio.is_write = !!(exit_qual & (1 << 1)); /* EPT write */
		break;
	case THHV_EXIT_CPUID:
		/* Leaf/subleaf come from guest RCX:RAX in COMM page regs. */
		break;
	case THHV_EXIT_MSR:
		/* MSR index in ECX, direction depends on vmx_reason (31=RD, 32=WR). */
		msg->msr.is_write = (vmx_reason == 32);
		break;
	default:
		break;
	}
}

/* ── THHV_RUN_VP handler ──────────────────────────────────────────────────── */

static long thhv_run_vp(struct thhv_vp *vp, void __user *uarg)
{
	struct thhv_partition *part = vp->partition;
	struct thhv_exit_msg msg;
	int ret;

	if (!part->sealed)
		return -EINVAL;
	if (!vp->comm_registered)
		return -EINVAL;

	if (!mutex_trylock(&vp->run_lock))
		return -EBUSY;

	if (part->sched_policy == THHV_SCHED_SYNC) {
		/*
		 * Sync mode: the calling thread's VP is "donated" to the
		 * child — we block in themis_switch() until the child
		 * exits.  On return, the capavisor has written exit info
		 * into the COMM page.
		 */
		ret = themis_switch(part->domain_handle, vp->vp_index);
		if (ret) {
			mutex_unlock(&vp->run_lock);
			return ret;
		}

		thhv_build_exit_msg(vp, &msg);

	} else {
		/*
		 * Async mode: the child VP runs on its own core.
		 * We park the calling thread until an exit event arrives.
		 *
		 * TODO: The actual async start mechanism (VMCALL or
		 * platform-specific kick) and the doorbell / eventfd
		 * notification that wakes us up are not yet designed.
		 * For now, park on the waitqueue until exit_pending is
		 * set (which will be done by the exit notification path
		 * once implemented).
		 */
		ret = wait_event_interruptible(vp->exit_wq,
					       atomic_read(&vp->exit_pending));
		if (ret) {
			mutex_unlock(&vp->run_lock);
			return -EINTR;
		}

		atomic_set(&vp->exit_pending, 0);
		thhv_build_exit_msg(vp, &msg);
	}

	mutex_unlock(&vp->run_lock);

	if (copy_to_user(uarg, &msg, sizeof(msg)))
		return -EFAULT;

	return 0;
}

/* ── VP-level ioctl dispatch ───────────────────────────────────────────────── */

static long thhv_vp_get_state(struct thhv_vp *vp, void __user *uarg)
{
	struct thhv_partition *part = vp->partition;
	struct thhv_vp_registers hdr;
	struct thhv_reg_name_value *regs;
	u32 i;
	int ret;

	if (copy_from_user(&hdr, uarg, sizeof(hdr)))
		return -EFAULT;
	if (hdr.count == 0 || hdr.count > THHV_MAX_VP_REGS)
		return -EINVAL;

	regs = kmalloc_array(hdr.count, sizeof(*regs), GFP_KERNEL);
	if (!regs)
		return -ENOMEM;

	if (copy_from_user(regs, (void __user *)hdr.regs,
			   hdr.count * sizeof(*regs))) {
		ret = -EFAULT;
		goto out;
	}

	for (i = 0; i < hdr.count; i++) {
		ret = themis_get_reg(part->domain_handle, vp->vp_index,
				     regs[i].name, &regs[i].value);
		if (ret)
			goto out;
	}

	if (copy_to_user((void __user *)hdr.regs, regs,
			 hdr.count * sizeof(*regs))) {
		ret = -EFAULT;
		goto out;
	}

	ret = 0;
out:
	kfree(regs);
	return ret;
}

static long thhv_vp_set_state(struct thhv_vp *vp, void __user *uarg)
{
	struct thhv_partition *part = vp->partition;
	struct thhv_vp_registers hdr;
	struct thhv_reg_name_value *regs;
	u32 i;
	int ret;

	if (copy_from_user(&hdr, uarg, sizeof(hdr)))
		return -EFAULT;
	if (hdr.count == 0 || hdr.count > THHV_MAX_VP_REGS)
		return -EINVAL;

	regs = kmalloc_array(hdr.count, sizeof(*regs), GFP_KERNEL);
	if (!regs)
		return -ENOMEM;

	if (copy_from_user(regs, (void __user *)hdr.regs,
			   hdr.count * sizeof(*regs))) {
		ret = -EFAULT;
		goto out;
	}

	for (i = 0; i < hdr.count; i++) {
		ret = themis_set_reg(part->domain_handle, vp->vp_index,
				     regs[i].name, regs[i].value);
		if (ret)
			goto out;
	}

	ret = 0;
out:
	kfree(regs);
	return ret;
}

static long thhv_vp_ioctl(struct file *file, unsigned int cmd,
			      unsigned long arg)
{
	struct thhv_vp *vp = file->private_data;
	void __user *uarg = (void __user *)arg;

	switch (cmd) {
	case THHV_RUN_VP:
		return thhv_run_vp(vp, uarg);

	case THHV_GET_VP_STATE:
		return thhv_vp_get_state(vp, uarg);

	case THHV_SET_VP_STATE:
		return thhv_vp_set_state(vp, uarg);

	default:
		return -ENOTTY;
	}
}

/* ── VP fd mmap (COMM page mapping) ────────────────────────────────────────── */

static int thhv_vp_mmap(struct file *file, struct vm_area_struct *vma)
{
	/* TODO(P15h): remap_pfn_range for META VP-state page */
	return -ENOSYS;
}

/* ── Page pinning helpers ──────────────────────────────────────────────────── */

static void thhv_vp_unpin_pages(struct thhv_vp *vp)
{
	unsigned int i;

	/* Revoke COMM capability (unbinds in the capavisor). */
	if (vp->comm_registered) {
		themis_revoke_mem(vp->comm_cap_handle, vp->comm_cap_sub);
		vp->comm_registered = false;
	}

	if (vp->comm_kaddr) {
		kunmap(vp->comm_page);
		vp->comm_kaddr = NULL;
	}
	if (vp->comm_page) {
		unpin_user_pages(&vp->comm_page, 1);
		vp->comm_page = NULL;
	}
	if (vp->meta_pages) {
		unpin_user_pages(vp->meta_pages, vp->meta_nr_pages);
		for (i = 0; i < vp->meta_nr_pages; i++)
			vp->meta_pages[i] = NULL;
		kfree(vp->meta_pages);
		vp->meta_pages = NULL;
		vp->meta_nr_pages = 0;
	}
}

static int thhv_vp_pin_pages(struct thhv_vp *vp,
			     u64 meta_uaddr, unsigned int meta_nr_pages,
			     u64 comm_uaddr)
{
	struct thhv_hpa_segment *segs = NULL;
	unsigned int nr_segs = 0;
	int ret;

	/* Pin META pages. */
	vp->meta_pages = kcalloc(meta_nr_pages, sizeof(struct page *),
				 GFP_KERNEL);
	if (!vp->meta_pages)
		return -ENOMEM;

	ret = pin_user_pages_fast(meta_uaddr, meta_nr_pages,
				  FOLL_WRITE | FOLL_LONGTERM,
				  vp->meta_pages);
	if (ret < 0)
		goto err;
	if (ret != (int)meta_nr_pages) {
		unpin_user_pages(vp->meta_pages, ret);
		ret = -EFAULT;
		goto err;
	}
	vp->meta_nr_pages = meta_nr_pages;

	/* Pin COMM page. */
	ret = pin_user_pages_fast(comm_uaddr, 1,
				  FOLL_WRITE | FOLL_LONGTERM,
				  &vp->comm_page);
	if (ret < 0)
		goto err_unpin_meta;
	if (ret != 1) {
		ret = -EFAULT;
		goto err_unpin_meta;
	}

	vp->comm_kaddr = kmap(vp->comm_page);

	/* Translate COMM page dom0 GPA → HPA. */
	ret = thhv_translate_pages(&vp->comm_page, 1, &segs, &nr_segs);
	if (ret)
		goto err_unmap_comm;
	vp->comm_phys = segs[0].hpa_start;
	kfree(segs);

	return 0;

err_unmap_comm:
	kunmap(vp->comm_page);
	vp->comm_kaddr = NULL;
	unpin_user_pages(&vp->comm_page, 1);
	vp->comm_page = NULL;
err_unpin_meta:
	unpin_user_pages(vp->meta_pages, vp->meta_nr_pages);
	vp->meta_nr_pages = 0;
err:
	kfree(vp->meta_pages);
	vp->meta_pages = NULL;
	return ret;
}

/* ── VP fd file_operations ─────────────────────────────────────────────────── */

static int thhv_vp_release(struct inode *inode, struct file *file)
{
	struct thhv_vp *vp = file->private_data;
	struct thhv_partition *part = vp->partition;

	/* TODO: Stop VP if running (async mode). */

	thhv_vp_unpin_pages(vp);

	part->vps[vp->vp_index] = NULL;
	kfree(vp);
	return 0;
}

const struct file_operations thhv_vp_fops = {
	.owner          = THIS_MODULE,
	.release        = thhv_vp_release,
	.unlocked_ioctl = thhv_vp_ioctl,
	.mmap           = thhv_vp_mmap,
};

/* ── THHV_CREATE_VP handler (called from partition ioctl) ──────────────────── */

long thhv_vp_create(struct thhv_partition *part, void __user *uarg)
{
	struct thhv_create_vp cv;
	struct thhv_vp *vp;
	struct file *file;
	unsigned int meta_nr;
	int fd, ret;

	if (copy_from_user(&cv, uarg, sizeof(cv)))
		return -EFAULT;

	if (cv.vp_index >= part->num_vps)
		return -EINVAL;
	if (part->vps[cv.vp_index])
		return -EEXIST;

	/* Validate META size. */
	meta_nr = THHV_META_PAGES_PER_VP;
	if (cv.meta_size != (u64)meta_nr * PAGE_SIZE)
		return -EINVAL;
	if (!cv.meta_uaddr || !cv.comm_uaddr)
		return -EINVAL;
	if (cv.meta_uaddr & ~PAGE_MASK || cv.comm_uaddr & ~PAGE_MASK)
		return -EINVAL;

	vp = kzalloc(sizeof(*vp), GFP_KERNEL);
	if (!vp)
		return -ENOMEM;

	vp->vp_index = cv.vp_index;
	vp->partition = part;
	mutex_init(&vp->run_lock);
	init_waitqueue_head(&vp->exit_wq);
	atomic_set(&vp->exit_pending, 0);

	/* Pin META + COMM pages from userspace. */
	ret = thhv_vp_pin_pages(vp, cv.meta_uaddr, meta_nr, cv.comm_uaddr);
	if (ret)
		goto err_free_vp;

	/*
	 * CARVE the COMM page from dom0's root capability, then
	 * REGISTER_COMM to bind it to this VP in the child domain.
	 * The capavisor marks the capability with COMM|CLEAN attributes
	 * and records the (child_domain, vp_id) binding internally.
	 */
	ret = themis_carve(0, vp->comm_phys, PAGE_SIZE,
			   THHV_MEM_R_READ | THHV_MEM_R_WRITE,
			   &vp->comm_cap_handle, &vp->comm_cap_sub);
	if (ret) {
		pr_err("thhv: CARVE COMM page HPA 0x%llx failed (%d)\n",
		       vp->comm_phys, ret);
		goto err_unpin;
	}

	ret = themis_register_comm(vp->comm_cap_handle,
				   part->domain_handle, vp->vp_index);
	if (ret) {
		pr_err("thhv: REGISTER_COMM vp %u failed (%d)\n",
		       vp->vp_index, ret);
		goto err_revoke_comm;
	}
	vp->comm_registered = true;

	/*
	 * TODO: CARVE + SEND META pages to child domain (deferred until
	 * EPT allocation from META pool is implemented in the capavisor).
	 */

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		ret = fd;
		goto err_revoke_comm;
	}

	file = anon_inode_getfile("thhv-vp", &thhv_vp_fops,
				  vp, O_RDWR | O_CLOEXEC);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		goto err_put_fd;
	}

	vp->file = file;
	part->vps[cv.vp_index] = vp;
	fd_install(fd, file);
	return fd;

err_put_fd:
	put_unused_fd(fd);
err_revoke_comm:
	if (vp->comm_registered) {
		themis_revoke_mem(vp->comm_cap_handle, vp->comm_cap_sub);
		vp->comm_registered = false;
	} else if (vp->comm_cap_handle) {
		themis_revoke_mem(vp->comm_cap_handle, vp->comm_cap_sub);
	}
err_unpin:
	thhv_vp_unpin_pages(vp);
err_free_vp:
	kfree(vp);
	return ret;
}
