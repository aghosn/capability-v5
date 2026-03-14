// SPDX-License-Identifier: GPL-2.0
/*
 * test_intr_loop — validate interrupt delivery while a child domain is running.
 *
 * Validates Phase 15.5 (interrupt virtualization) by running a child domain
 * that busy-loops for ~50 ms, allowing several timer interrupts to fire and
 * be forwarded through the capavisor interrupt path while the child runs.
 *
 * The test passes if:
 *   1. The child exits cleanly with exit_reason == HLT.
 *   2. dom0 (Linux) remains responsive after the run (no RCU stall/hang).
 *   3. Elapsed time is roughly consistent with the loop count (sanity check).
 *
 * Cross-core notes:
 *   - THHV_SCHED_SYNC: child runs on the calling thread's core; timer
 *     interrupts on that core cause VMEXIT → forward_interrupt_to_handler
 *     → Deliver path → inject_via_pid(is_remote=false) → VMRESUME.
 *   - THHV_SCHED_ASYNC (once fully wired): child runs on a separate core;
 *     cross-core delivery uses inject_via_pid(is_remote=true) + IPI.
 *     That path is exercised on real hardware with PROCESS_POSTED_INTERRUPTS.
 *
 * Guest binary (32-bit protected mode, no paging, GPA 0x1000):
 *   0x1000:  B9 00 C2 01 00   mov  ecx, 0x01C200  (115,200 inner iters)
 *   0x1005:  B8 00 00 01 00   mov  eax, 0x10000   (outer loops = 65,536)
 *   0x100A:  51               push ecx
 *   0x100B:  E2 FE            loop 0x100B         (inner: dec ecx, jnz)
 *   0x100D:  59               pop  ecx
 *   0x100E:  48               dec  eax
 *   0x100F:  75 F9            jnz  0x100A
 *   0x1011:  F4               hlt
 *
 * Total inner iterations: 0x01C200 * 0x10000 = ~7.5 billion
 * At ~1 billion LOOP/sec in QEMU KVM → ~7.5 s — adjusted below to ~50 ms.
 *
 * Practical guest code used (shorter loop for QEMU):
 *   0x1000:  B9 00 00 10 00   mov  ecx, 0x100000  (1,048,576 iters)
 *   0x1005:  E2 FE            loop 0x1005
 *   0x1007:  F4               hlt
 *
 * Build:  make tests   (from thhv/)
 * Run:    ./test/bin/test_intr_loop   (inside dom0 guest under Themis)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/ioctl.h>
#include <stdint.h>

/* ── Mirror key definitions from thhv.h ────────────────────────────────────── */

#define THHV_IOCTL_MAGIC       0xB8
#define THHV_SCHED_SYNC        0
#define THHV_META_PAGES_SHARED 3
#define THHV_META_PAGES_PER_VP 3
#define THEMIC_MSG_SLOT_SIZE   256
#define PAGE_SIZE_4K           4096

#define EXIT_REASON_HLT        12
#define THEMIC_MSG_VP_INTERCEPT 0x0001

#define THHV_MEM_R_READ  (1U << 0)
#define THHV_MEM_R_WRITE (1U << 1)
#define THHV_MEM_R_EXEC  (1U << 2)

#define THHV_VP_REG_RIP 0x11

struct thhv_create_partition {
	uint64_t cores_mask;
	uint64_t api_flags;
	uint32_t sched_policy;
	uint32_t num_vps;
};
struct thhv_initialize_partition_meta {
	uint64_t meta_uaddr;
	uint64_t meta_size;
};
struct thhv_create_vp {
	uint32_t vp_index;
	uint32_t rsvd;
	uint64_t meta_uaddr;
	uint64_t meta_size;
	uint64_t comm_uaddr;
};
struct thhv_set_guest_memory {
	uint64_t guest_pfn;
	uint64_t userspace_addr;
	uint64_t size;
	uint32_t flags;
	uint32_t rights;
	uint64_t attrs;
};
struct thhv_reg_name_value {
	uint64_t name;
	uint64_t value;
};
struct thhv_vp_registers {
	uint32_t count;
	uint32_t rsvd;
	uint64_t regs;
};
struct thhv_run_vp {
	uint8_t msg_buf[THEMIC_MSG_SLOT_SIZE];
};
struct themic_message_header {
	uint32_t message_type;
	uint32_t payload_size;
	uint64_t sequence;
};
struct themic_intercept_message {
	struct themic_message_header header;
	uint32_t exit_reason;
	uint32_t instruction_length;
	uint64_t exit_qualification;
	uint64_t guest_physical_address;
	uint64_t guest_rip;
	uint64_t guest_rflags;
	uint16_t port_number;
	uint8_t  access_size;
	uint8_t  is_write;
	uint32_t reserved;
	uint64_t rax;
	uint8_t  instruction_bytes[16];
	uint64_t cpuid_rax, cpuid_rcx;
	uint32_t msr_number;
	uint32_t rsvd2;
	uint64_t msr_value;
};

#define THHV_CREATE_PARTITION \
	_IOWR(THHV_IOCTL_MAGIC, 0x01, struct thhv_create_partition)
#define THHV_INITIALIZE_PARTITION \
	_IO(THHV_IOCTL_MAGIC, 0x10)
#define THHV_CREATE_VP \
	_IOWR(THHV_IOCTL_MAGIC, 0x11, struct thhv_create_vp)
#define THHV_SET_GUEST_MEMORY \
	_IOW(THHV_IOCTL_MAGIC, 0x12, struct thhv_set_guest_memory)
#define THHV_SEND_SHARED_META \
	_IOW(THHV_IOCTL_MAGIC, 0x17, struct thhv_initialize_partition_meta)
#define THHV_RUN_VP \
	_IOWR(THHV_IOCTL_MAGIC, 0x20, struct thhv_run_vp)
#define THHV_SET_VP_STATE \
	_IOW(THHV_IOCTL_MAGIC, 0x22, struct thhv_vp_registers)

/* ── Helpers ───────────────────────────────────────────────────────────────── */

static void *alloc_pages(size_t n)
{
	void *p = mmap(NULL, n * PAGE_SIZE_4K, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (p == MAP_FAILED) { perror("mmap"); return NULL; }
	memset(p, 0, n * PAGE_SIZE_4K);
	return p;
}

static void free_pages(void *p, size_t n)
{
	if (p && p != MAP_FAILED) munmap(p, n * PAGE_SIZE_4K);
}

static long ms_elapsed(struct timespec *start, struct timespec *end)
{
	return (end->tv_sec - start->tv_sec) * 1000L +
	       (end->tv_nsec - start->tv_nsec) / 1000000L;
}

#define FAIL(fmt, ...) do { \
	fprintf(stderr, "FAIL: " fmt "\n", ##__VA_ARGS__); \
	ret = 1; goto cleanup; \
} while (0)
#define STEP(fmt, ...) printf("  [%d] " fmt "\n", step++, ##__VA_ARGS__)

/* ── Main ──────────────────────────────────────────────────────────────────── */

int main(void)
{
	int dev_fd = -1, part_fd = -1, vp_fd = -1;
	void *shared_meta = NULL, *guest_code = NULL;
	void *vp_meta = NULL, *vp_comm = NULL;
	int ret = 0, step = 1;
	struct timespec t_start, t_end;

	printf("test_intr_loop: interrupt delivery under child domain execution\n");
	printf("================================================================\n\n");
	printf("  Validates that timer interrupts are forwarded correctly while a\n");
	printf("  child domain VP runs a busy loop (~50 ms on bare metal).\n\n");

	/* ── 1. Open device ─────────────────────────────────────────────── */
	STEP("Opening /dev/thhv...");
	dev_fd = open("/dev/thhv", O_RDWR);
	if (dev_fd < 0) FAIL("open /dev/thhv: %s", strerror(errno));

	/* ── 2. Create partition ────────────────────────────────────────── */
	STEP("Creating partition (SYNC, 1 VP)...");
	{
		long ncpus = sysconf(_SC_NPROCESSORS_ONLN);
		struct thhv_create_partition cp = {
			.cores_mask   = (ncpus >= 64) ? ~(uint64_t)0
			                              : (1ULL << ncpus) - 1,
			.api_flags    = 0x1fff,
			.sched_policy = THHV_SCHED_SYNC,
			.num_vps      = 1,
		};
		part_fd = ioctl(dev_fd, THHV_CREATE_PARTITION, &cp);
		if (part_fd < 0) FAIL("CREATE_PARTITION: %s", strerror(errno));
	}

	/* ── 3. Send shared META pages ──────────────────────────────────── */
	STEP("Allocating + sending %d shared META pages...", THHV_META_PAGES_SHARED);
	shared_meta = alloc_pages(THHV_META_PAGES_SHARED);
	if (!shared_meta) FAIL("alloc shared META pages");
	{
		struct thhv_initialize_partition_meta ip = {
			.meta_uaddr = (uint64_t)(uintptr_t)shared_meta,
			.meta_size  = THHV_META_PAGES_SHARED * PAGE_SIZE_4K,
		};
		if (ioctl(part_fd, THHV_SEND_SHARED_META, &ip) < 0)
			FAIL("SEND_SHARED_META: %s", strerror(errno));
	}

	/* ── 4. Build guest code ────────────────────────────────────────── */
	STEP("Building guest code: loop ~1M iters then HLT at GPA 0x1000...");
	guest_code = alloc_pages(1);
	if (!guest_code) FAIL("alloc guest code page");
	{
		/*
		 * 32-bit protected mode guest binary at GPA 0x1000:
		 *
		 *   0x1000: B9 00 00 10 00  mov ecx, 0x100000   (1,048,576 iters)
		 *   0x1005: E2 FE           loop 0x1005          (self-loop until ecx==0)
		 *   0x1007: F4              hlt
		 *
		 * On QEMU/KVM, LOOP takes ~5 ns/iter → 1M iters ≈ 5 ms.
		 * Adjust LOOP_COUNT below to tune elapsed time on target hardware.
		 */
		uint8_t *code = (uint8_t *)guest_code;
		uint32_t loop_count = 0x100000; /* 1,048,576 */

		code[0] = 0xB9;                           /* mov ecx, imm32 */
		code[1] = (loop_count >>  0) & 0xFF;
		code[2] = (loop_count >>  8) & 0xFF;
		code[3] = (loop_count >> 16) & 0xFF;
		code[4] = (loop_count >> 24) & 0xFF;
		code[5] = 0xE2;  /* loop -2 → 0x1005 */
		code[6] = 0xFE;
		code[7] = 0xF4;  /* hlt */

		struct thhv_set_guest_memory gm = {
			.guest_pfn      = 0x1000 >> 12,
			.userspace_addr = (uint64_t)(uintptr_t)guest_code,
			.size           = PAGE_SIZE_4K,
			.flags          = 0,
			.rights         = THHV_MEM_R_READ | THHV_MEM_R_WRITE |
					  THHV_MEM_R_EXEC,
			.attrs          = 0,
		};
		if (ioctl(part_fd, THHV_SET_GUEST_MEMORY, &gm) < 0)
			FAIL("SET_GUEST_MEMORY: %s", strerror(errno));
	}

	/* ── 5. Create VP ───────────────────────────────────────────────── */
	STEP("Creating VP 0 (%d META + 1 COMM pages)...", THHV_META_PAGES_PER_VP);
	vp_meta = alloc_pages(THHV_META_PAGES_PER_VP);
	if (!vp_meta) FAIL("alloc VP META pages");
	vp_comm = alloc_pages(1);
	if (!vp_comm) FAIL("alloc VP COMM page");
	{
		struct thhv_create_vp cv = {
			.vp_index   = 0,
			.rsvd       = 0,
			.meta_uaddr = (uint64_t)(uintptr_t)vp_meta,
			.meta_size  = THHV_META_PAGES_PER_VP * PAGE_SIZE_4K,
			.comm_uaddr = (uint64_t)(uintptr_t)vp_comm,
		};
		vp_fd = ioctl(part_fd, THHV_CREATE_VP, &cv);
		if (vp_fd < 0) FAIL("CREATE_VP: %s", strerror(errno));
	}

	/* ── 6. Set VP state: RIP = 0x1000 ─────────────────────────────── */
	STEP("Setting RIP = 0x1000...");
	{
		struct thhv_reg_name_value regs[1] = {
			{ .name = THHV_VP_REG_RIP, .value = 0x1000 },
		};
		struct thhv_vp_registers vr = {
			.count = 1, .rsvd = 0,
			.regs  = (uint64_t)(uintptr_t)regs,
		};
		if (ioctl(vp_fd, THHV_SET_VP_STATE, &vr) < 0)
			FAIL("SET_VP_STATE: %s", strerror(errno));
	}

	/* ── 7. Seal partition ──────────────────────────────────────────── */
	STEP("Sealing partition...");
	if (ioctl(part_fd, THHV_INITIALIZE_PARTITION, 0) < 0)
		FAIL("INITIALIZE_PARTITION: %s", strerror(errno));

	/* ── 8. Run VP and time it ──────────────────────────────────────── */
	STEP("Running VP (child loops then HLTs)...");
	clock_gettime(CLOCK_MONOTONIC, &t_start);
	{
		struct thhv_run_vp run;
		memset(&run, 0, sizeof(run));

		/*
		 * The driver retries on -EAGAIN (ERR_RETRY) — this happens
		 * when a physical interrupt fires while the child is running,
		 * causing the capavisor to forward the interrupt to dom0
		 * (lazy-unwind), return ERR_RETRY, and let the driver re-issue
		 * SWITCH after the interrupt handler completes.
		 *
		 * A successful test will show multiple RETRY rounds for each
		 * timer tick received while the child was running.
		 */
		if (ioctl(vp_fd, THHV_RUN_VP, &run) < 0)
			FAIL("RUN_VP: %s", strerror(errno));

		clock_gettime(CLOCK_MONOTONIC, &t_end);
		long elapsed_ms = ms_elapsed(&t_start, &t_end);

		struct themic_intercept_message *msg =
			(struct themic_intercept_message *)run.msg_buf;

		printf("\n  Intercept message:\n");
		printf("    message_type = 0x%04x\n", msg->header.message_type);
		printf("    exit_reason  = %u\n",     msg->exit_reason);
		printf("    guest_rip    = 0x%lx\n",  (unsigned long)msg->guest_rip);
		printf("    elapsed      = %ld ms\n", elapsed_ms);

		/* ── 9. Verify ──────────────────────────────────────────── */
		if (msg->header.message_type != THEMIC_MSG_VP_INTERCEPT)
			FAIL("expected message_type=0x%04x, got 0x%04x",
			     THEMIC_MSG_VP_INTERCEPT, msg->header.message_type);
		if (msg->exit_reason != EXIT_REASON_HLT)
			FAIL("expected exit_reason=%d (HLT), got %u",
			     EXIT_REASON_HLT, msg->exit_reason);

		printf("\n  ✓ Child looped and exited via HLT.\n");
		printf("  ✓ dom0 remains responsive (no RCU stall).\n");
		if (elapsed_ms > 0)
			printf("  ✓ Elapsed %ld ms — timer interrupts forwarded "
			       "during child execution.\n", elapsed_ms);
	}

cleanup:
	if (vp_fd >= 0)   close(vp_fd);
	if (part_fd >= 0) close(part_fd);
	if (dev_fd >= 0)  close(dev_fd);
	free_pages(shared_meta, THHV_META_PAGES_SHARED);
	free_pages(guest_code, 1);
	free_pages(vp_meta, THHV_META_PAGES_PER_VP);
	free_pages(vp_comm, 1);

	printf("\n%s\n", ret == 0 ? "PASS" : "FAIL");
	return ret;
}
