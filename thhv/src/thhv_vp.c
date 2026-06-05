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
#include <linux/delay.h>

#include "thhv_internal.h"

/* ── ThemIC intercept message reader ────────────────────────────────────────── */

/*
 * Read the slim intercept from COMM page offset 512 and assemble the
 * full themic_intercept_message by pulling registers from the COMM page
 * register area (which the capavisor filters via ExitPolicy.read_set).
 *
 * This ensures the only path for register exposure is read_set — the
 * intercept message itself carries no register values.
 */
static void thhv_read_intercept_msg(struct thhv_vp *vp,
				    struct themic_intercept_message *msg)
{
	struct themic_slim_intercept slim;
	const struct thhv_vp_comm_page *comm =
		(const struct thhv_vp_comm_page *)vp->comm_kaddr;

	memset(msg, 0, sizeof(*msg));

	/* Read slim intercept from COMM page offset 512. */
	memcpy(&slim, (u8 *)vp->comm_kaddr + 512, sizeof(slim));

	/* Copy exit metadata. */
	msg->header              = slim.header;
	msg->exit_reason         = slim.exit_reason;
	msg->instruction_length  = slim.instruction_length;
	msg->exit_qualification  = slim.exit_qualification;
	msg->guest_physical_address = slim.guest_physical_address;
	msg->port_number         = slim.port_number;
	msg->access_size         = slim.access_size;
	msg->is_write            = slim.is_write;
	memcpy(msg->instruction_bytes, slim.instruction_bytes, 16);

	/* Always populate RIP and RFLAGS (needed for logging/emulation). */
	msg->guest_rip    = thhv_comm_get_reg(comm, THHV_VP_REG_RIP);
	msg->guest_rflags = thhv_comm_get_reg(comm, THHV_VP_REG_RFLAGS);

	/* Populate exit-type-specific register fields. */
	switch (slim.exit_reason) {
	case THHV_EXIT_REASON_IO:
		msg->rax = thhv_comm_get_reg(comm, THHV_VP_REG_RAX);
		break;
	case THHV_EXIT_REASON_CPUID:
		msg->cpuid_rax = thhv_comm_get_reg(comm, THHV_VP_REG_RAX);
		msg->cpuid_rcx = thhv_comm_get_reg(comm, THHV_VP_REG_RCX);
		break;
	case THHV_EXIT_REASON_RDMSR:
		msg->msr_number = (u32)thhv_comm_get_reg(comm, THHV_VP_REG_RCX);
		break;
	case THHV_EXIT_REASON_WRMSR: {
		__u64 rax = thhv_comm_get_reg(comm, THHV_VP_REG_RAX);
		__u64 rdx = thhv_comm_get_reg(comm, THHV_VP_REG_RDX);
		msg->msr_number = (u32)thhv_comm_get_reg(comm, THHV_VP_REG_RCX);
		msg->msr_value  = ((rdx & 0xFFFFFFFF) << 32) | (rax & 0xFFFFFFFF);
		break;
	}
	default:
		break;
	}
}

/* ── THHV_RUN_VP handler ──────────────────────────────────────────────────── */

/**
 * thhv_run_vp - Execute a child VP via the capavisor SWITCH hypercall.
 * @vp:   VP to run
 * @uarg: Userspace pointer to intercept message buffer (THEMIC_MSG_SLOT_SIZE bytes)
 *
 * Sync mode: blocks in themis_switch() until the child exits.  On HLT exit,
 * blocks on halt_wq until an interrupt is injected, then retries SWITCH.
 * Async mode: waits on exit_wq for the capavisor to signal exit_pending.
 *
 * Returns 0 on success (intercept message copied to @uarg), negative errno on error.
 */

static long thhv_run_vp(struct thhv_vp *vp, void __user *uarg)
{
	struct thhv_partition *part = vp->partition;
	/* The userspace ABI is a fixed THEMIC_MSG_SLOT_SIZE (256) byte buffer;
	 * the live layout is struct themic_intercept_message. Use a union so
	 * the kernel works with a typed struct and userspace still gets the
	 * full slot-sized buffer via copy_to_user. */
	union {
		struct themic_intercept_message msg;
		u8 raw[THEMIC_MSG_SLOT_SIZE];
	} slot = {0};
	int ret;

	if (!part->sealed)
		return -EINVAL;
	if (!vp->comm_registered)
		return -EINVAL;

	if (!mutex_trylock(&vp->run_lock))
		return -EBUSY;

	/* Block if this VP is in wait-for-SIPI state (mp_state == THHV_MP_STATE_WAIT_FOR_SIPI).
	 * The BSP will send INIT+SIPI via CHV → SET_VP_STATE(ACTIVITY_STATE=0)
	 * which transitions mp_state to 0 and wakes us. */
	if (vp->mp_state == THHV_MP_STATE_WAIT_FOR_SIPI) {
		ret = wait_event_interruptible(vp->sipi_wq, vp->mp_state != THHV_MP_STATE_WAIT_FOR_SIPI);
		if (ret) {
			mutex_unlock(&vp->run_lock);
			return ret;
		}
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
retry_switch:
		do {
			ret = themis_switch(part->domain_handle, vp->vp_index);
			if (ret != -EAGAIN)
				break;
			/* Drain DomainComm RX on every ERR_RETRY iteration.
			 * Doorbells hit via the capavisor fast-path queue
			 * notifications here; if we don't drain between
			 * SWITCH retries the child may deadlock waiting for
			 * a completion interrupt whose doorbell was never
			 * forwarded to CHV. */
			thhv_drain_domcomm_rx(part);
			if (signal_pending(current)) {
				mutex_unlock(&vp->run_lock);
				return -EINTR;
			}
			/* Force a scheduling point so dom0 can service
			 * timers, network, and SSH even when the child
			 * is interrupt-heavy.  usleep_range() puts this
			 * thread to sleep for ~50-100µs, which is long
			 * enough for the scheduler to run other tasks
			 * but short enough not to hurt throughput. */
			usleep_range(50, 100);
		} while (true);
		if (ret) {
			mutex_unlock(&vp->run_lock);
			return ret;
		}

		thhv_read_intercept_msg(vp, &slot.msg);

		/* HLT exit: guest is idle, waiting for an interrupt.
		 * Block here until an interrupt is injected (via irqfd
		 * or THHV_INJECT_INTERRUPT), then retry the SWITCH so
		 * the capavisor can inject the pending PIR vector and
		 * re-enter the child.  This prevents busy-spinning. */
		if (slot.msg.exit_reason == THHV_EXIT_REASON_HLT) {
			atomic_set(&vp->halted, 1);
			smp_mb(); /* pair with smp_mb in thhv_wake_vp */
			/* Check if an inject arrived during the race
			 * window between reading HLT and setting halted. */
			if (atomic_read(&vp->pending_inject) > 0) {
				atomic_set(&vp->halted, 0);
				atomic_set(&vp->pending_inject, 0);
				goto retry_switch;
			}
			thhv_drain_domcomm_rx(part);
			ret = wait_event_interruptible(vp->halt_wq,
				!atomic_read(&vp->halted) || signal_pending(current));
			atomic_set(&vp->halted, 0);
			if (signal_pending(current)) {
				mutex_unlock(&vp->run_lock);
				return -EINTR;
			}
			atomic_set(&vp->pending_inject, 0);
			goto retry_switch;
		}

		/* DOORBELL exit: child rang a doorbell via VMCALL.
		 * The capavisor already enqueued a DOORBELL_NOTIFY
		 * on our DomainComm RX ring.  Drain it (signals
		 * matching ioeventfds) and forward to userspace
		 * so CHV can log the event. */
		if (slot.msg.exit_reason == THHV_EXIT_REASON_DOORBELL) {
			thhv_drain_domcomm_rx(part);
		}

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
		 * DomainComm RX → IPI: not yet implemented (see todo.md §Future work).
		 * For now, park on the waitqueue.
		 */
		ret = wait_event_interruptible(vp->exit_wq,
					       atomic_read(&vp->exit_pending));
		if (ret) {
			mutex_unlock(&vp->run_lock);
			return -EINTR;
		}

		atomic_set(&vp->exit_pending, 0);
		thhv_read_intercept_msg(vp, &slot.msg);
	}

	mutex_unlock(&vp->run_lock);

	if (copy_to_user(uarg, slot.raw, THEMIC_MSG_SLOT_SIZE))
		return -EFAULT;

	return 0;
}

/* ── Wake a halted VP after interrupt injection ────────────────────────────── */

/**
 * thhv_wake_vp - Wake a halted VP after interrupt injection.
 * @part:     Partition containing the VP
 * @vp_index: VP index within the partition
 *
 * Called from irqfd work handler and THHV_INJECT_INTERRUPT ioctl.
 * Uses atomic pending_inject counter to prevent lost-wakeup race
 * with the HLT exit handler in thhv_run_vp().
 */
void thhv_wake_vp(struct thhv_partition *part, u32 vp_index)
{
	struct thhv_vp *vp;

	if (vp_index >= part->num_vps)
		return;
	vp = part->vps[vp_index];
	if (!vp)
		return;
	/* Increment pending counter so the HLT path can detect injects
	 * that arrived between reading EXIT_REASON_HLT and blocking. */
	atomic_inc(&vp->pending_inject);
	smp_mb(); /* ensure pending_inject is visible before checking halted */
	if (atomic_read(&vp->halted)) {
		atomic_set(&vp->halted, 0);
		wake_up_interruptible(&vp->halt_wq);
	}
}

/* ── COMM page register write helper ────────────────────────────────────────── */

/**
 * thhv_comm_set_reg - Write a VP register to the COMM page.
 * @comm:  Kernel-mapped COMM page
 * @reg:   Register identifier (THHV_VP_REG_*)
 * @value: Value to write
 *
 * Stages register updates in the COMM page for the capavisor to apply
 * to the VMCS at the next SWITCH.  Sets the corresponding dirty bit.
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
	 * The capavisor will validate and apply them at SWITCH time.
	 *
	 * Special case: ACTIVITY_STATE manages the software wait-for-SIPI
	 * mechanism.  Value 3 blocks future VP_RUN calls; value 0 unblocks
	 * and wakes any sleeping thread.
	 *
	 * Guard against duplicate SIPI: if ACTIVITY_STATE=0 arrives while
	 * the VP is already running (mp_state != 3), the entire batch is
	 * silently dropped — the AP has already booted from the first SIPI
	 * and writing SIPI state to the COMM page would reset it. */

	/* Pre-scan for ACTIVITY_STATE=0 on an already-running VP. */
	for (i = 0; i < hdr.count; i++) {
		if (regs[i].name == THHV_VP_REG_ACTIVITY_STATE &&
		    regs[i].value == 0 && vp->mp_state != THHV_MP_STATE_WAIT_FOR_SIPI) {
			pr_debug("thhv: vp %u: ignoring duplicate SIPI "
				 "(mp_state=%d, already running)\n",
				 vp->vp_index, vp->mp_state);
			ret = 0;
			goto out;
		}
	}

	comm = (struct thhv_vp_comm_page *)vp->comm_kaddr;
	for (i = 0; i < hdr.count; i++) {
		if (regs[i].name == THHV_VP_REG_ACTIVITY_STATE) {
			if (regs[i].value == THHV_MP_STATE_WAIT_FOR_SIPI) {
				vp->mp_state = THHV_MP_STATE_WAIT_FOR_SIPI;
				/* Don't write to COMM page — we handle
				 * the wait in thhv_vp_run(), not in the
				 * capavisor VMCS. */
			} else {
				if (vp->mp_state == THHV_MP_STATE_WAIT_FOR_SIPI) {
					vp->mp_state = THHV_MP_STATE_RUNNABLE;
					wake_up_interruptible(&vp->sipi_wq);
				}
				/* Write ACTIVITY_STATE=0 to COMM page so
				 * capavisor applies it to the VMCS. */
				thhv_comm_set_reg(comm, (unsigned int)regs[i].name,
						  regs[i].value);
			}
			continue;
		}
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
	/* META VP-state page mmap: not yet implemented (see todo.md §Future work) */
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

	/* Async VP stop: not yet implemented (see todo.md §Future work) */

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

/**
 * thhv_vp_create - Create a new VP in a partition.
 * @part:  Target partition (must not be sealed)
 * @uarg:  Userspace pointer to thhv_create_vp struct
 *
 * Pins the COMM page from userspace, allocates META pages, then issues
 * CARVE + SEND + ADD_VP hypercalls to register the VP with the capavisor.
 * The VP starts in RUNNABLE state (mp_state = 0); CHV sets WAIT_FOR_SIPI
 * for APs via SET_VP_STATE after creation.
 *
 * Returns 0 on success, negative errno on error.
 */
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
	vp->mp_state = THHV_MP_STATE_RUNNABLE;
	init_waitqueue_head(&vp->sipi_wq);
	atomic_set(&vp->halted, 0);
	init_waitqueue_head(&vp->halt_wq);

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
