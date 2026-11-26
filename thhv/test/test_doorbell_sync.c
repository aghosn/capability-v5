// SPDX-License-Identifier: GPL-2.0
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "thhv.h"

extern const char guest_start[], guest_end[];

/* Discover the sealed-domain offer rather than guessing a local handle. */
__asm__(
	".pushsection .rodata\n"
	".code32\n"
	"guest_start:\n"
	"movl $0x13, %eax\n"       /* ENUMERATE(0) */
	"xorl %edi, %edi\n"
	"vmcall\n"
	"testl %eax, %eax\n"
	"jnz 1f\n"
	"cmpl $1, %esi\n"
	"jne 1f\n"
	"movl $4, %eax\n"          /* ACCEPT(pending_id) */
	"vmcall\n"
	"testl %eax, %eax\n"
	"jnz 1f\n"
	"movl $0x25, %eax\n"       /* NOTIFY(accepted_handle, 7) */
	"movl $7, %esi\n"
	"vmcall\n"
	"testl %eax, %eax\n"
	"jnz 1f\n"
	"movl $0x51, %eax\n"
	"jmp 2f\n"
	"1: movl $0xee, %eax\n"
	"2: cpuid\n"              /* Observable exit after resumption. */
	"jmp 2b\n"
	"guest_end:\n"
	".code64\n"
	".popsection\n"
);

static void check(int success, const char *what)
{
	if (!success) {
		perror(what);
		exit(1);
	}
}

static void *pages(unsigned int count)
{
	void *p = mmap(NULL, count * 4096UL, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);

	check(p != MAP_FAILED, "mmap");
	memset(p, 0, count * 4096UL);
	return p;
}

int main(void)
{
	int device = open("/dev/thhv", O_RDWR);
	struct thhv_create_partition create = {
		.cores_mask = ~0ULL, .api_flags = ~0ULL,
		.sched_policy = THHV_SCHED_SYNC, .num_vps = 1,
	};
	struct thhv_create_doorbell doorbell = { .kind = THEMIS_DOORBELL_SYNC };
	struct thhv_doorbell_eventfd subscription;
	struct thhv_send_cap send;
	struct thhv_initialize_partition meta;
	struct thhv_set_guest_memory memory;
	struct thhv_create_vp create_vp;
	struct thhv_vp_registers state;
	struct thhv_run_vp run = { 0 };
	struct thhv_reg_name_value regs[] = {
		{ .name = THHV_VP_REG_RIP, .value = 0x1000 },
		{ .name = THHV_VP_REG_RFLAGS, .value = 2 },
		{ .name = THHV_VP_REG_CR0, .value = 0x31 },
		{ .name = THHV_VP_REG_CR3, .value = 0 },
		{ .name = THHV_VP_REG_CR4, .value = 0 },
		{ .name = THHV_VP_REG_EFER, .value = 0 },
		{ .name = THHV_VP_REG_CS_SEL, .value = 8 },
		{ .name = THHV_VP_REG_CS_BASE, .value = 0 },
		{ .name = THHV_VP_REG_CS_LIM, .value = 0xffffffff },
		{ .name = THHV_VP_REG_CS_AR, .value = 0xc09b },
	};
	void *shared = pages(THHV_META_PAGES_SHARED);
	void *vp_meta = pages(THHV_META_PAGES_PER_VP);
	void *comm = pages(1), *code = pages(1);
	uint64_t count;
	int partition, vp, event, ret;

	check(device >= 0, "open driver");
	partition = ioctl(device, THHV_CREATE_PARTITION, &create);
	check(partition >= 0, "create child");
	meta = (struct thhv_initialize_partition) {
		.meta_uaddr = (uintptr_t)shared,
		.meta_size = THHV_META_PAGES_SHARED * 4096UL,
	};
	check(ioctl(partition, THHV_SEND_SHARED_META, &meta) == 0, "send shared META");
	check((uintptr_t)guest_end - (uintptr_t)guest_start <= 4096, "guest code size");
	memcpy(code, guest_start, (uintptr_t)guest_end - (uintptr_t)guest_start);
	memory = (struct thhv_set_guest_memory) {
		.guest_pfn = 1, .userspace_addr = (uintptr_t)code, .size = 4096,
		.rights = THHV_MEM_R_READ | THHV_MEM_R_WRITE | THHV_MEM_R_EXEC,
	};
	check(ioctl(partition, THHV_SET_GUEST_MEMORY, &memory) == 0, "map guest code");
	create_vp = (struct thhv_create_vp) {
		.vp_index = 0, .meta_uaddr = (uintptr_t)vp_meta,
		.meta_size = THHV_META_PAGES_PER_VP * 4096UL, .comm_uaddr = (uintptr_t)comm,
	};
	vp = ioctl(partition, THHV_CREATE_VP, &create_vp);
	check(vp >= 0, "create VP");
	state = (struct thhv_vp_registers) {
		.count = sizeof(regs) / sizeof(regs[0]), .regs = (uintptr_t)regs,
	};
	check(ioctl(vp, THHV_SET_VP_STATE, &state) == 0, "set protected-mode entry");
	for (int word = 0; word < 3; word++) {
		struct thhv_set_policy policy = {
			.kind = THEMIS_POLICY_EXIT_REASON_REG_READ_SET,
			.key = THHV_EXIT_REASON_CPUID, .sub_key = word, .value = ~0ULL,
		};

		check(ioctl(partition, THHV_SET_POLICY, &policy) == 0, "set test exit mask");
	}
	check(ioctl(device, THHV_CREATE_DOORBELL, &doorbell) == 0, "create Sync");
	event = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	check(event >= 0, "eventfd");
	subscription = (struct thhv_doorbell_eventfd) { .port = doorbell.port, .fd = event };
	check(ioctl(device, THHV_DOORBELL_EVENTFD, &subscription) == 0, "subscribe");
	check(ioctl(partition, THHV_INITIALIZE_PARTITION) == 0, "seal child");
	send = (struct thhv_send_cap) { .handle = doorbell.handle };
	check(ioctl(partition, THHV_SEND_CAP, &send) == 0, "offer to sealed child");
	do {
		ret = ioctl(vp, THHV_RUN_VP, &run);
	} while (ret < 0 && errno == EAGAIN);
	check(ret == 0, "run notify and resume");
	check(((struct themic_intercept_message *)run.msg_buf)->exit_reason ==
	      THHV_EXIT_REASON_CPUID, "guest reached post-notify exit");
	regs[0] = (struct thhv_reg_name_value) { .name = THHV_VP_REG_RAX };
	state.count = 1;
	check(ioctl(vp, THHV_GET_VP_STATE, &state) == 0, "read guest result");
	check(regs[0].value == 0x51, "guest ENUMERATE/ACCEPT/NOTIFY all succeeded");
	check(read(event, &count, sizeof(count)) == sizeof(count) && count == 1,
	      "Sync produced exactly one eventfd signal");
	close(vp);
	close(partition);
	close(device);
	close(event);
	munmap(shared, THHV_META_PAGES_SHARED * 4096UL);
	munmap(vp_meta, THHV_META_PAGES_PER_VP * 4096UL);
	munmap(comm, 4096);
	munmap(code, 4096);
	puts("PASS: child discovers, accepts, notifies Sync and resumes successfully");
	return 0;
}
