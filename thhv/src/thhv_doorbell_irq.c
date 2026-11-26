// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/workqueue.h>
#include <asm/hw_irq.h>
#include <asm/irqdomain.h>
#include <asm/processor.h>

#include "thhv_internal.h"

static struct irq_domain *doorbell_domain;
static struct fwnode_handle *doorbell_fwnode;
static unsigned int doorbell_vector;
static int *doorbell_irqs;
static u32 *doorbell_vps;
#ifdef CONFIG_THHV_TEST
static DEFINE_PER_CPU(unsigned long, doorbell_count);
static DECLARE_WAIT_QUEUE_HEAD(doorbell_wait);
#endif

static void doorbell_rx_work(struct work_struct *work);
static DECLARE_WORK(doorbell_work, doorbell_rx_work);

static void doorbell_rx_work(struct work_struct *work)
{
	thhv_drain_domcomm_rx(NULL);
}

static irqreturn_t doorbell_interrupt(int irq, void *data)
{
#ifdef CONFIG_THHV_TEST
	this_cpu_inc(doorbell_count);
	wake_up(&doorbell_wait);
#endif
	schedule_work(&doorbell_work);
	return IRQ_HANDLED;
}

/* VM-entry injection does not put this vector in the physical LAPIC ISR. */
static void doorbell_irq_noop(struct irq_data *data)
{
}

static struct irq_chip doorbell_chip = {
	.name = "themis-doorbell",
	.irq_ack = doorbell_irq_noop,
	.irq_mask = doorbell_irq_noop,
	.irq_unmask = doorbell_irq_noop,
	.irq_set_affinity = irq_chip_set_affinity_parent,
};

static int doorbell_irq_alloc(struct irq_domain *domain, unsigned int irq,
			      unsigned int count, void *arg)
{
	unsigned int i;
	int ret;

	ret = irq_domain_alloc_irqs_parent(domain, irq, count, arg);
	if (ret)
		return ret;
	for (i = 0; i < count; i++) {
		irq_domain_set_info(domain, irq + i, irq + i, &doorbell_chip,
				    NULL, handle_edge_irq, NULL, NULL);
		irqd_set_affinity_on_activate(irq_get_irq_data(irq + i));
	}
	return 0;
}

static void doorbell_irq_free(struct irq_domain *domain, unsigned int irq,
			      unsigned int count)
{
	irq_domain_free_irqs_parent(domain, irq, count);
}

static const struct irq_domain_ops doorbell_domain_ops = {
	.alloc = doorbell_irq_alloc,
	.free = doorbell_irq_free,
};

static int allocate_on_cpu(unsigned int cpu, unsigned int *vector)
{
	struct irq_alloc_info info = { .mask = cpumask_of(cpu) };
	struct irq_cfg *cfg;
	int irq, ret;

	irq = irq_domain_alloc_irqs(doorbell_domain, 1, NUMA_NO_NODE, &info);
	if (irq < 0)
		return irq;
	ret = irq_set_affinity(irq, cpumask_of(cpu));
	if (ret)
		goto fail;
	cfg = irqd_cfg(irq_get_irq_data(irq));
	if (!cfg || cfg->vector < FIRST_EXTERNAL_VECTOR ||
	    cfg->vector >= FIRST_SYSTEM_VECTOR) {
		ret = -EINVAL;
		goto fail;
	}
	*vector = cfg->vector;
	return irq;
fail:
	irq_dispose_mapping(irq);
	return ret;
}

/*
 * The x86 allocator chooses one CPU per IRQ, but vector numbers are local
 * to CPUs. Retain one ordinary allocation per CPU with a common number;
 * no vector table or IDT is modified by this driver.
 */
static int allocate_common_vector(void)
{
	int (*allocated)[NR_VECTORS];
	unsigned int cpu, first, candidate, vector;
	int irq, ret = -ENOSPC;
	bool common;

	allocated = kcalloc(nr_cpu_ids, sizeof(*allocated), GFP_KERNEL);
	if (!allocated)
		return -ENOMEM;
	first = cpumask_first(cpu_online_mask);
	for (;;) {
		irq = allocate_on_cpu(first, &candidate);
		if (irq < 0) {
			ret = irq;
			break;
		}
		allocated[first][candidate] = irq;
		common = true;
		for_each_online_cpu(cpu) {
			while (!allocated[cpu][candidate]) {
				irq = allocate_on_cpu(cpu, &vector);
				if (irq < 0) {
					if (irq != -ENOSPC) {
						ret = irq;
						goto out;
					}
					common = false;
					break;
				}
				allocated[cpu][vector] = irq;
			}
			if (!common)
				break;
		}
		if (common) {
			doorbell_vector = candidate;
			for_each_online_cpu(cpu) {
				doorbell_irqs[cpu] = allocated[cpu][candidate];
				allocated[cpu][candidate] = 0;
			}
			ret = 0;
			break;
		}
	}
out:
	for_each_online_cpu(cpu)
		for (vector = 0; vector < NR_VECTORS; vector++)
			if (allocated[cpu][vector])
				irq_dispose_mapping(allocated[cpu][vector]);
	kfree(allocated);
	return ret;
}

unsigned int thhv_doorbell_vector(void)
{
	return doorbell_vector;
}

static void discover_vp(void *unused)
{
	u32 eax, ebx, ecx, edx;

	cpuid_count(0x40000005, 1, &eax, &ebx, &ecx, &edx);
	doorbell_vps[smp_processor_id()] =
		edx == 1 && eax < THHV_MAX_VPS_PER_DOMAIN ? eax : U32_MAX;
}

int thhv_doorbell_target_vp(unsigned int cpu, u64 *vp)
{
	if (cpu >= nr_cpu_ids || !cpu_online(cpu))
		return -EINVAL;
	*vp = doorbell_vps[cpu];
	return 0;
}

#ifdef CONFIG_THHV_TEST
int thhv_test_doorbell_irq(unsigned int cpu)
{
	unsigned long before;
	u64 handle, port, vp;
	int ret, revoke_ret;

	if (cpu >= nr_cpu_ids || !cpu_online(cpu))
		return -EINVAL;
	before = READ_ONCE(per_cpu(doorbell_count, cpu));
	ret = thhv_doorbell_target_vp(cpu, &vp);
	if (ret)
		return ret;
	ret = themis_create_doorbell(THEMIS_CAP_SELF, doorbell_vector,
		THEMIS_DOORBELL_ASYNC, vp, &handle, &port);
	if (ret)
		return ret;
	ret = themis_notify(handle, 0x7468656d6973ULL);
	if (!ret && !wait_event_timeout(doorbell_wait,
		READ_ONCE(per_cpu(doorbell_count, cpu)) != before, 5 * HZ))
		ret = -ETIMEDOUT;
	revoke_ret = themis_revoke(THEMIS_CAP_SELF, port);
	if (revoke_ret) {
		pr_err("thhv: IRQ probe doorbell revoke failed (%d)\n", revoke_ret);
		__module_get(THIS_MODULE);
		if (!ret)
			ret = revoke_ret;
	}
	pr_info("thhv: doorbell IRQ probe cpu=%u vector=%u result=%d\n",
		cpu, doorbell_vector, ret);
	return ret;
}
#endif

int thhv_doorbell_irq_init(void)
{
	unsigned int cpu;
	int ret;

	/* Fixed capability vectors must not migrate or disappear while live. */
	cpu_hotplug_disable();
	doorbell_irqs = kcalloc(nr_cpu_ids, sizeof(*doorbell_irqs), GFP_KERNEL);
	if (!doorbell_irqs) {
		ret = -ENOMEM;
		goto enable_hotplug;
	}
	doorbell_vps = kmalloc_array(nr_cpu_ids, sizeof(*doorbell_vps), GFP_KERNEL);
	if (!doorbell_vps) {
		ret = -ENOMEM;
		goto free_irqs;
	}
	on_each_cpu(discover_vp, NULL, 1);
	for_each_online_cpu(cpu) {
		unsigned int other;

		if (doorbell_vps[cpu] == U32_MAX) {
			pr_err("thhv: native VP identity unavailable on CPU %u\n", cpu);
			ret = -EPROTO;
			goto free_irqs;
		}
		for_each_online_cpu(other) {
			if (other < cpu && doorbell_vps[other] == doorbell_vps[cpu]) {
				pr_err("thhv: duplicate native VP identity on CPUs %u/%u\n", other, cpu);
				ret = -EPROTO;
				goto free_irqs;
			}
		}
	}
	doorbell_fwnode = irq_domain_alloc_named_fwnode("themis-doorbell");
	if (!doorbell_fwnode) {
		ret = -ENOMEM;
		goto free_irqs;
	}
	doorbell_domain = irq_domain_create_hierarchy(x86_vector_domain, 0, 0,
		doorbell_fwnode, &doorbell_domain_ops, NULL);
	if (!doorbell_domain) {
		ret = -ENOMEM;
		goto free_fwnode;
	}
	ret = allocate_common_vector();
	if (ret)
		goto remove_domain;
	for_each_online_cpu(cpu) {
		irq_set_status_flags(doorbell_irqs[cpu], IRQ_NO_BALANCING);
		ret = request_irq(doorbell_irqs[cpu], doorbell_interrupt,
			IRQF_NOBALANCING | IRQF_NO_THREAD, "themis-doorbell",
			&doorbell_irqs[cpu]);
		if (ret)
			goto free_handlers;
	}
	pr_info("thhv: doorbell vector %u registered on %u CPUs\n",
		doorbell_vector, num_online_cpus());
	return 0;

free_handlers:
	for_each_online_cpu(cpu) {
		if (irq_has_action(doorbell_irqs[cpu]))
			free_irq(doorbell_irqs[cpu], &doorbell_irqs[cpu]);
		irq_dispose_mapping(doorbell_irqs[cpu]);
	}
remove_domain:
	irq_domain_remove(doorbell_domain);
free_fwnode:
	irq_domain_free_fwnode(doorbell_fwnode);
free_irqs:
	kfree(doorbell_vps);
	doorbell_vps = NULL;
	kfree(doorbell_irqs);
	doorbell_irqs = NULL;
enable_hotplug:
	cpu_hotplug_enable();
	return ret;
}

static long drain_cpu_interrupts(void *unused)
{
	u32 eax, ebx, ecx, edx;

	/*
	 * Run in process context with IF set. The monitor drains this VP's
	 * software PIR before re-entry, including interrupt-window retries.
	 * All senders must have been revoked before reaching this point.
	 */
	cpuid(THHV_CPUID_LEAF, &eax, &ebx, &ecx, &edx);
	return 0;
}

void thhv_doorbell_irq_cleanup(void)
{
	unsigned int cpu;

	for_each_online_cpu(cpu)
		work_on_cpu(cpu, drain_cpu_interrupts, NULL);
	for_each_online_cpu(cpu) {
		free_irq(doorbell_irqs[cpu], &doorbell_irqs[cpu]);
		irq_dispose_mapping(doorbell_irqs[cpu]);
	}
	cancel_work_sync(&doorbell_work);
	irq_domain_remove(doorbell_domain);
	irq_domain_free_fwnode(doorbell_fwnode);
	kfree(doorbell_irqs);
	doorbell_irqs = NULL;
	doorbell_vector = 0;
	kfree(doorbell_vps);
	doorbell_vps = NULL;
	cpu_hotplug_enable();
}
