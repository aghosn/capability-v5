// SPDX-License-Identifier: GPL-2.0
/*
 * test_child_hlt — end-to-end test: create a child domain that executes HLT.
 *
 * Flow:
 *   1. Open /dev/thhv
 *   2. CREATE_PARTITION (sync, 1 VP)
 *   3. SEND_SHARED_META (3 pages: MSR bitmap + IO bitmaps)
 *   4. SET_GUEST_MEMORY (1 page at GPA 0x1000 containing HLT instruction)
 *   5. CREATE_VP (2 META pages + 1 COMM page)
 *   6. SET_VP_STATE (RIP = 0x1000)
 *   7. INITIALIZE_PARTITION (seal)
 *   8. RUN_VP → driver parks halted VP; interrupt the wait with SIGALRM
 *   9. Verify the COMM intercept is HLT and RUN_VP returned EINTR
 *
 * The child guest runs in 32-bit protected mode (unrestricted guest), no
 * paging, and executes a single HLT instruction at GPA 0x1000.  The
 * capavisor has HLT_EXITING enabled for child domains, so the HLT causes
 * a VMEXIT which is forwarded back to the parent via the intercept message
 * in the VP COMM page.
 *
 * Build:  make tests   (from thhv/)
 * Run:    ./test/bin/test_child_hlt   (inside dom0 guest under Themis)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/ioctl.h>
#include <stdint.h>
#include <signal.h>

/* ── Constants ─────────────────────────────────────────────────────────────── */

#include "thhv.h"

#define PAGE_SIZE_4K           4096

/* Exit reasons (Intel SDM Vol 3C Appendix C). */

/* ── Helpers ───────────────────────────────────────────────────────────────── */

static volatile sig_atomic_t timed_out;

static void timeout_handler(int signal)
{
	(void)signal;
	timed_out = 1;
}

static void *alloc_pages(size_t n)
{
	void *p = mmap(NULL, n * PAGE_SIZE_4K,
		       PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
		       -1, 0);
	if (p == MAP_FAILED) {
		perror("mmap");
		return NULL;
	}
	memset(p, 0, n * PAGE_SIZE_4K);
	return p;
}

static void free_pages(void *p, size_t n)
{
	if (p && p != MAP_FAILED)
		munmap(p, n * PAGE_SIZE_4K);
}

#define FAIL(fmt, ...) do { \
	fprintf(stderr, "FAIL: " fmt "\n", ##__VA_ARGS__); \
	ret = 1; \
	goto cleanup; \
} while (0)

#define STEP(fmt, ...) printf("  [%d] " fmt "\n", step++, ##__VA_ARGS__)

/* ── Main ──────────────────────────────────────────────────────────────────── */

int main(void)
{
	int dev_fd = -1, part_fd = -1, vp_fd = -1;
	void *shared_meta = NULL;
	void *guest_code = NULL;
	void *vp_meta = NULL;
	void *vp_comm = NULL;
	int ret = 0, step = 1;

	printf("test_child_hlt: end-to-end child domain HLT test\n");
	printf("=================================================\n\n");

	/* ── 1. Open device ─────────────────────────────────────────────── */
	STEP("Opening /dev/thhv...");
	dev_fd = open("/dev/thhv", O_RDWR);
	if (dev_fd < 0)
		FAIL("open /dev/thhv: %s", strerror(errno));

	/* ── 2. Create partition ────────────────────────────────────────── */
	STEP("Creating partition (sync, 1 VP)...");
	{
		struct thhv_create_partition cp = {
			.cores_mask   = (sysconf(_SC_NPROCESSORS_ONLN) >= 64)
		                ? ~(uint64_t)0
		                : (1ULL << sysconf(_SC_NPROCESSORS_ONLN)) - 1,
			.api_flags    = 0x1fff,/* all API flags */
			.sched_policy = THHV_SCHED_SYNC,
			.num_vps      = 1,
		};
		part_fd = ioctl(dev_fd, THHV_CREATE_PARTITION, &cp);
		if (part_fd < 0)
			FAIL("CREATE_PARTITION: %s", strerror(errno));
	}

	/* ── 3. Send shared META pages ──────────────────────────────────── */
	STEP("Allocating + sending %d shared META pages...",
	     THHV_META_PAGES_SHARED);
	shared_meta = alloc_pages(THHV_META_PAGES_SHARED);
	if (!shared_meta)
		FAIL("alloc shared META pages");
	{
		struct thhv_initialize_partition ip = {
			.meta_uaddr = (uint64_t)(uintptr_t)shared_meta,
			.meta_size  = THHV_META_PAGES_SHARED * PAGE_SIZE_4K,
		};
		if (ioctl(part_fd, THHV_SEND_SHARED_META, &ip) < 0)
			FAIL("SEND_SHARED_META: %s", strerror(errno));
	}

	/* ── 4. Map guest code page ─────────────────────────────────────── */
	STEP("Mapping guest code page at GPA 0x1000...");
	guest_code = alloc_pages(1);
	if (!guest_code)
		FAIL("alloc guest code page");
	/*
	 * Guest binary: a single HLT instruction (0xF4).
	 * The child starts in 32-bit protected mode at RIP=0x1000
	 * with the EPT mapping this page to GPA 0x1000.
	 */
	((uint8_t *)guest_code)[0] = 0xF4;  /* HLT */
	{
		struct thhv_set_guest_memory gm = {
			.guest_pfn      = 0x1000 >> 12,  /* GPA 0x1000 → PFN 1 */
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
	STEP("Creating VP 0 (%d META + 1 COMM pages)...",
	     THHV_META_PAGES_PER_VP);
	vp_meta = alloc_pages(THHV_META_PAGES_PER_VP);
	if (!vp_meta)
		FAIL("alloc VP META pages");
	vp_comm = alloc_pages(1);
	if (!vp_comm)
		FAIL("alloc VP COMM page");
	{
		struct thhv_create_vp cv = {
			.vp_index  = 0,
			.rsvd      = 0,
			.meta_uaddr = (uint64_t)(uintptr_t)vp_meta,
			.meta_size  = THHV_META_PAGES_PER_VP * PAGE_SIZE_4K,
			.comm_uaddr = (uint64_t)(uintptr_t)vp_comm,
		};
		vp_fd = ioctl(part_fd, THHV_CREATE_VP, &cv);
		if (vp_fd < 0)
			FAIL("CREATE_VP: %s", strerror(errno));
	}

	/* ── 6. Set VP state: RIP = 0x1000 ──────────────────────────────── */
	STEP("Setting RIP = 0x1000...");
	{
		struct thhv_reg_name_value regs[1] = {
			{ .name = THHV_VP_REG_RIP, .value = 0x1000 },
		};
		struct thhv_vp_registers vr = {
			.count = 1,
			.rsvd  = 0,
			.regs  = (uint64_t)(uintptr_t)regs,
		};
		if (ioctl(vp_fd, THHV_SET_VP_STATE, &vr) < 0)
			FAIL("SET_VP_STATE: %s", strerror(errno));
	}

	/* ── 7. Seal (initialize) partition ─────────────────────────────── */
	STEP("Sealing partition...");
	if (ioctl(part_fd, THHV_INITIALIZE_PARTITION, 0) < 0)
		FAIL("INITIALIZE_PARTITION: %s", strerror(errno));

	/* ── 8. Run VP ──────────────────────────────────────────────────── */
	STEP("Running VP (expecting interruptible HLT wait)...");
	{
		struct thhv_run_vp run;
		struct sigaction action = { .sa_handler = timeout_handler };
		int result, run_errno;

		sigemptyset(&action.sa_mask);
		if (sigaction(SIGALRM, &action, NULL) < 0)
			FAIL("sigaction: %s", strerror(errno));
		memset(&run, 0, sizeof(run));
		alarm(3);
		do {
			result = ioctl(vp_fd, THHV_RUN_VP, &run);
			run_errno = errno;
		} while (result < 0 && run_errno == EAGAIN && !timed_out);
		alarm(0);
		if (result != -1 || run_errno != EINTR || !timed_out)
			FAIL("expected interrupted HLT wait, result=%d errno=%d",
			     result, run_errno);

		/* HLT is consumed by the driver; its intercept remains in COMM. */
		struct themic_slim_intercept *msg =
			(struct themic_slim_intercept *)((uint8_t *)vp_comm + 512);

		printf("\n  Intercept message:\n");
		printf("    message_type    = 0x%04x\n", msg->header.message_type);
		printf("    exit_reason     = %u\n", msg->exit_reason);
		printf("    instruction_len = %u\n", msg->instruction_length);
		printf("    guest_rip       = 0x%lx\n",
		       (unsigned long)thhv_comm_get_reg(vp_comm, THHV_VP_REG_RIP));
		printf("    guest_rflags    = 0x%lx\n",
		       (unsigned long)thhv_comm_get_reg(vp_comm, THHV_VP_REG_RFLAGS));
		printf("    exit_qual       = 0x%lx\n",
		       (unsigned long)msg->exit_qualification);

		/* ── 9. Verify ──────────────────────────────────────────── */
		if (msg->header.message_type != THEMIC_MSG_VP_INTERCEPT)
			FAIL("expected message_type 0x%04x, got 0x%04x",
			     THEMIC_MSG_VP_INTERCEPT, msg->header.message_type);
		if (msg->exit_reason != THHV_EXIT_REASON_HLT)
			FAIL("expected exit_reason %d (HLT), got %u",
			     THHV_EXIT_REASON_HLT, msg->exit_reason);
	}

	printf("\n  Child HLT recorded; driver wait interrupted correctly.\n");

cleanup:
	if (vp_fd >= 0)
		close(vp_fd);
	if (part_fd >= 0)
		close(part_fd);
	if (dev_fd >= 0)
		close(dev_fd);
	free_pages(shared_meta, THHV_META_PAGES_SHARED);
	free_pages(guest_code, 1);
	free_pages(vp_meta, THHV_META_PAGES_PER_VP);
	free_pages(vp_comm, 1);

	printf("\n%s\n", ret == 0 ? "PASS" : "FAIL");
	return ret;
}
