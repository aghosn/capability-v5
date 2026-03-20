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

#include "thhv.h"

/* ── ThemIC intercept message reader ────────────────────────────────────────── */

/*
 * Read the ThemIC intercept message from the message page slot 0.
 * The capavisor writes a themic_intercept_message there on VP exit.
 *
 * TODO: The ThemIC message page is not yet allocated / registered
 * as a separate page.  For now this reads from the COMM page padding
 * area (offset 512+) as a transitional measure.  Once ThemIC pages
 * are wired, this reads from the actual message page slot 0.
 */
static void thhv_read_intercept_msg(struct thhv_vp *vp, void *out_buf)
{
	/* Copy the intercept slot (256 bytes) from comm page offset 512. */
	memcpy(out_buf, (u8 *)vp->comm_kaddr + 512, THEMIC_MSG_SLOT_SIZE);
}

/* ── THHV_RUN_VP handler ──────────────────────────────────────────────────── */

static long thhv_run_vp(struct thhv_vp *vp, void __user *uarg)
{
	struct thhv_partition *part = vp->partition;
	u8 msg_buf[THEMIC_MSG_SLOT_SIZE];
	int ret;

	if (!part->sealed)
		return -EINVAL;
	if (!vp->comm_registered)
		return -EINVAL;

	if (!mutex_trylock(&vp->run_lock))
		return -EBUSY;

	/* Log COMM page RIP at run time for diagnostic purposes */
	if (vp->comm_kaddr) {
		struct thhv_vp_comm_page *comm =
			(struct thhv_vp_comm_page *)vp->comm_kaddr;
		pr_info("thhv: RUN_VP vp=%u COMM->rip=0x%llx dirty_mask[0]=0x%llx\n",
			vp->vp_index, comm->rip, comm->dirty_mask[0]);
	}

	if (part->sched_policy == THHV_SCHED_SYNC) {
		/*
		 * Sync mode: the calling thread's VP is "donated" to the
		 * child — we block in themis_switch() until the child
		 * exits.  On return, the capavisor has written a
		 * themic_intercept_message to the intercept slot.
		 *
		 * If the child was preempted by a physical interrupt while
		 * running, themis_switch() returns -EAGAIN (ERR_RETRY).  We
		 * check for pending signals and retry; this is the mechanism
		 * that allows Ctrl-C / SIGINT to interrupt a running VP.
		 */
		do {
			ret = themis_switch(part->domain_handle, vp->vp_index);
			if (ret != -EAGAIN)
				break;
			if (signal_pending(current)) {
				mutex_unlock(&vp->run_lock);
				return -EINTR;
			}
		} while (true);

		if (ret) {
			mutex_unlock(&vp->run_lock);
			return ret;
		}

		thhv_read_intercept_msg(vp, msg_buf);

		/* Drain the DomainComm RX ring: signal any ioeventfds whose
		 * doorbell was hit while the child was running. */
		thhv_drain_domcomm_rx(part);

	} else {
		/*
		 * Async mode: the child VP runs on its own core.
		 * Park until an exit event arrives via the DomainComm
		 * RX ring (capavisor enqueues DOMCOMM_MSG_VP_EXIT and
		 * sends an IPI; the handler sets exit_pending and wakes us).
		 *
		 * TODO: Wire the DomainComm RX ring → IPI handler →
		 * exit_pending path.  For now, park on the waitqueue.
		 */
		ret = wait_event_interruptible(vp->exit_wq,
					       atomic_read(&vp->exit_pending));
		if (ret) {
			mutex_unlock(&vp->run_lock);
			return -EINTR;
		}

		atomic_set(&vp->exit_pending, 0);
		thhv_read_intercept_msg(vp, msg_buf);
	}

	mutex_unlock(&vp->run_lock);

	if (copy_to_user(uarg, msg_buf, THEMIC_MSG_SLOT_SIZE))
		return -EFAULT;

	return 0;
}

/* ── COMM page register write helper ────────────────────────────────────────── */

/*
 * Write a register value into the COMM page and mark its dirty bit.
 * Values are zero-extended to the natural field width by the capavisor.
 */
void thhv_comm_set_reg(struct thhv_vp_comm_page *comm, unsigned int reg, __u64 val)
{
	switch (reg) {
	/* GPRs */
	case THHV_VP_REG_RAX: comm->rax = val; break;
	case THHV_VP_REG_RBX: comm->rbx = val; break;
	case THHV_VP_REG_RCX: comm->rcx = val; break;
	case THHV_VP_REG_RDX: comm->rdx = val; break;
	case THHV_VP_REG_RSI: comm->rsi = val; break;
	case THHV_VP_REG_RDI: comm->rdi = val; break;
	case THHV_VP_REG_RBP: comm->rbp = val; break;
	case THHV_VP_REG_R8:  comm->r8  = val; break;
	case THHV_VP_REG_R9:  comm->r9  = val; break;
	case THHV_VP_REG_R10: comm->r10 = val; break;
	case THHV_VP_REG_R11: comm->r11 = val; break;
	case THHV_VP_REG_R12: comm->r12 = val; break;
	case THHV_VP_REG_R13: comm->r13 = val; break;
	case THHV_VP_REG_R14: comm->r14 = val; break;
	case THHV_VP_REG_R15: comm->r15 = val; break;
	/* RSP / RIP / RFLAGS */
	case THHV_VP_REG_RSP:    comm->rsp    = val; break;
	case THHV_VP_REG_RIP:    comm->rip    = val; break;
	case THHV_VP_REG_RFLAGS: comm->rflags = val; break;
	/* Control regs */
	case THHV_VP_REG_CR0:  comm->cr0  = val; break;
	case THHV_VP_REG_CR3:  comm->cr3  = val; break;
	case THHV_VP_REG_CR4:  comm->cr4  = val; break;
	case THHV_VP_REG_EFER: comm->efer = val; break;
	case THHV_VP_REG_DR7:  comm->dr7  = val; break;
	/* Segment selectors */
	case THHV_VP_REG_CS_SEL:   comm->cs_sel   = (__u16)val; break;
	case THHV_VP_REG_DS_SEL:   comm->ds_sel   = (__u16)val; break;
	case THHV_VP_REG_ES_SEL:   comm->es_sel   = (__u16)val; break;
	case THHV_VP_REG_FS_SEL:   comm->fs_sel   = (__u16)val; break;
	case THHV_VP_REG_GS_SEL:   comm->gs_sel   = (__u16)val; break;
	case THHV_VP_REG_SS_SEL:   comm->ss_sel   = (__u16)val; break;
	case THHV_VP_REG_TR_SEL:   comm->tr_sel   = (__u16)val; break;
	case THHV_VP_REG_LDTR_SEL: comm->ldtr_sel = (__u16)val; break;
	/* Segment bases */
	case THHV_VP_REG_CS_BASE:   comm->cs_base   = val; break;
	case THHV_VP_REG_DS_BASE:   comm->ds_base   = val; break;
	case THHV_VP_REG_ES_BASE:   comm->es_base   = val; break;
	case THHV_VP_REG_FS_BASE:   comm->fs_base   = val; break;
	case THHV_VP_REG_GS_BASE:   comm->gs_base   = val; break;
	case THHV_VP_REG_SS_BASE:   comm->ss_base   = val; break;
	case THHV_VP_REG_TR_BASE:   comm->tr_base   = val; break;
	case THHV_VP_REG_LDTR_BASE: comm->ldtr_base = val; break;
	/* Segment limits */
	case THHV_VP_REG_CS_LIM:   comm->cs_limit   = (__u32)val; break;
	case THHV_VP_REG_DS_LIM:   comm->ds_limit   = (__u32)val; break;
	case THHV_VP_REG_ES_LIM:   comm->es_limit   = (__u32)val; break;
	case THHV_VP_REG_FS_LIM:   comm->fs_limit   = (__u32)val; break;
	case THHV_VP_REG_GS_LIM:   comm->gs_limit   = (__u32)val; break;
	case THHV_VP_REG_SS_LIM:   comm->ss_limit   = (__u32)val; break;
	case THHV_VP_REG_TR_LIM:   comm->tr_limit   = (__u32)val; break;
	case THHV_VP_REG_LDTR_LIM: comm->ldtr_limit = (__u32)val; break;
	/* Segment access rights */
	case THHV_VP_REG_CS_AR:   comm->cs_ar   = (__u32)val; break;
	case THHV_VP_REG_DS_AR:   comm->ds_ar   = (__u32)val; break;
	case THHV_VP_REG_ES_AR:   comm->es_ar   = (__u32)val; break;
	case THHV_VP_REG_FS_AR:   comm->fs_ar   = (__u32)val; break;
	case THHV_VP_REG_GS_AR:   comm->gs_ar   = (__u32)val; break;
	case THHV_VP_REG_SS_AR:   comm->ss_ar   = (__u32)val; break;
	case THHV_VP_REG_TR_AR:   comm->tr_ar   = (__u32)val; break;
	case THHV_VP_REG_LDTR_AR: comm->ldtr_ar = (__u32)val; break;
	/* Descriptor tables */
	case THHV_VP_REG_GDTR_BASE: comm->gdtr_base  = val; break;
	case THHV_VP_REG_GDTR_LIM:  comm->gdtr_limit = (__u16)val; break;
	case THHV_VP_REG_IDTR_BASE: comm->idtr_base  = val; break;
	case THHV_VP_REG_IDTR_LIM:  comm->idtr_limit = (__u16)val; break;
	/* SYSENTER */
	case THHV_VP_REG_SYSENTER_CS:  comm->sysenter_cs  = val; break;
	case THHV_VP_REG_SYSENTER_ESP: comm->sysenter_esp = val; break;
	case THHV_VP_REG_SYSENTER_EIP: comm->sysenter_eip = val; break;
	/* Segment MSRs */
	case THHV_VP_REG_FS_BASE_MSR:    comm->fs_base_msr    = val; break;
	case THHV_VP_REG_GS_BASE_MSR:    comm->gs_base_msr    = val; break;
	case THHV_VP_REG_KERNEL_GS_BASE: comm->kernel_gs_base = val; break;
	/* APIC */
	case THHV_VP_REG_APIC_BASE: comm->apic_base = val; break;
	case THHV_VP_REG_TPR:       comm->tpr       = val; break;
	case THHV_VP_REG_PPR:       comm->ppr       = val; break;
	/* Activity / interruptibility / PAT */
	case THHV_VP_REG_ACTIVITY_STATE:         comm->activity_state         = (__u32)val; break;
	case THHV_VP_REG_INTERRUPTIBILITY_STATE: comm->interruptibility_state = (__u32)val; break;
	case THHV_VP_REG_PAT:                    comm->pat                    = val; break;
	default:
		pr_warn("thhv: unknown VP register %u\n", reg);
		return;
	}
	thhv_comm_mark_dirty(comm, reg);
}

/* ── VP state get/set ──────────────────────────────────────────────────────── */

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
	struct thhv_vp_comm_page *comm;
	u32 i;
	int ret;

	if (!vp->comm_kaddr) {
		pr_err("thhv: set_state: COMM page not mapped\n");
		return -EINVAL;
	}

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

	/* Write all register values into the COMM page + set dirty bits.
	 * The capavisor will validate and apply them at SWITCH time. */
	comm = (struct thhv_vp_comm_page *)vp->comm_kaddr;
	for (i = 0; i < hdr.count; i++) {
		if (regs[i].name == THHV_VP_REG_RIP)
			pr_info("thhv: SET_VP_STATE vp=%u RIP=0x%llx\n",
				vp->vp_index, regs[i].value);
		thhv_comm_set_reg(comm, (unsigned int)regs[i].name, regs[i].value);
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
		themis_revoke_mem(vp->comm_parent_handle, vp->comm_cap_sub);
		thhv_cap_table_remove(vp->comm_cap_handle);
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
	 * CARVE the COMM page from the parent capability, then
	 * REGISTER_COMM to bind it to this VP in the child domain.
	 * The COMM cap stays owned by us (not SEND'd), so it remains
	 * in the global cap table until VP teardown.
	 */
	{
		u64 parent_handle;

		ret = thhv_find_parent_handle(vp->comm_phys, PAGE_SIZE,
					      &parent_handle);
		if (ret) {
			pr_err("thhv: no parent cap for COMM HPA 0x%llx\n",
			       vp->comm_phys);
			goto err_unpin;
		}

		vp->comm_parent_handle = parent_handle;
		ret = themis_carve(parent_handle, vp->comm_phys, PAGE_SIZE,
				   THHV_MEM_R_READ | THHV_MEM_R_WRITE,
				   &vp->comm_cap_handle, &vp->comm_cap_sub);
		if (ret) {
			pr_err("thhv: CARVE COMM page HPA 0x%llx failed (%d)\n",
			       vp->comm_phys, ret);
			goto err_unpin;
		}

		/* Track the carved COMM cap in the global cap table. */
		ret = thhv_cap_table_insert(vp->comm_cap_handle,
					    parent_handle,
					    vp->comm_cap_sub,
					    vp->comm_phys, PAGE_SIZE);
		if (ret) {
			themis_revoke_mem(parent_handle, vp->comm_cap_sub);
			goto err_unpin;
		}
	}

	/*
	 * CARVE + SEND per-VP META pages (VMCS + VAPIC) to child domain.
	 * Must be done BEFORE ADD_VP so the capavisor can allocate VMCS/VAPIC.
	 */
	ret = thhv_send_meta_pages(part, vp->meta_pages, vp->meta_nr_pages,
				   THHV_META_KEY_VP(cv.vp_index));
	if (ret) {
		pr_err("thhv: SEND META for VP %u failed (%d)\n",
		       cv.vp_index, ret);
		goto err_revoke_comm;
	}

	/*
	 * ADD_VP: creates VProcessorState in the capa engine, binds COMM page,
	 * allocates VMCS + VAPIC from META pool, and sets up the VMCS.
	 */
	ret = themis_add_vp(part->domain_handle, vp->comm_cap_handle);
	if (ret) {
		pr_err("thhv: ADD_VP vp %u failed (%d)\n",
		       vp->vp_index, ret);
		goto err_revoke_comm;
	}
	vp->comm_registered = true;

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
	if (vp->comm_registered || vp->comm_cap_handle) {
		themis_revoke_mem(vp->comm_parent_handle, vp->comm_cap_sub);
		thhv_cap_table_remove(vp->comm_cap_handle);
		vp->comm_registered = false;
	}
err_unpin:
	thhv_vp_unpin_pages(vp);
err_free_vp:
	kfree(vp);
	return ret;
}
