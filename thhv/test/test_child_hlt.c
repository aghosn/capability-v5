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
 *   8. RUN_VP → block until child exits
 *   9. Verify exit_reason == 12 (HLT)
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

/* ── Constants ─────────────────────────────────────────────────────────────── */

#define THHV_IOCTL_MAGIC       0xB8
#define THHV_SCHED_SYNC        0
#define THHV_META_PAGES_SHARED 3
#define THHV_META_PAGES_PER_VP 3
#define THEMIC_MSG_SLOT_SIZE   256
#define PAGE_SIZE_4K           4096

/* Exit reasons (Intel SDM Vol 3C Appendix C). */
#define EXIT_REASON_HLT        12

/* ThemIC message types. */
#define THEMIC_MSG_VP_INTERCEPT 0x0001

/* Memory mapping rights. */
#define THHV_MEM_R_READ  (1U << 0)
#define THHV_MEM_R_WRITE (1U << 1)
#define THHV_MEM_R_EXEC  (1U << 2)

/* VP register discriminants (from thhv.h VpRegister). */
#define THHV_VP_REG_RIP 0x11

/* ── Ioctl structures ─────────────────────────────────────────────────────── */

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
	uint64_t regs;  /* pointer to array of thhv_reg_name_value */
};

struct thhv_run_vp {
	uint8_t msg_buf[THEMIC_MSG_SLOT_SIZE];
};

/* Intercept message header (matches capavisor ThemicMessageHeader). */
struct themic_message_header {
	uint32_t message_type;
	uint32_t payload_size;
	uint64_t sequence;
};

/* Intercept message (matches capavisor InterceptMessage, 120 bytes). */
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

/* ── Ioctl numbers ─────────────────────────────────────────────────────────── */

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
		struct thhv_initialize_partition_meta ip = {
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
	STEP("Running VP (expecting HLT exit)...");
	{
		struct thhv_run_vp run;
		memset(&run, 0, sizeof(run));
		if (ioctl(vp_fd, THHV_RUN_VP, &run) < 0)
			FAIL("RUN_VP: %s", strerror(errno));

		/* Parse the intercept message. */
		struct themic_intercept_message *msg =
			(struct themic_intercept_message *)run.msg_buf;

		printf("\n  Intercept message:\n");
		printf("    message_type    = 0x%04x\n", msg->header.message_type);
		printf("    exit_reason     = %u\n", msg->exit_reason);
		printf("    instruction_len = %u\n", msg->instruction_length);
		printf("    guest_rip       = 0x%lx\n",
		       (unsigned long)msg->guest_rip);
		printf("    guest_rflags    = 0x%lx\n",
		       (unsigned long)msg->guest_rflags);
		printf("    exit_qual       = 0x%lx\n",
		       (unsigned long)msg->exit_qualification);

		/* ── 9. Verify ──────────────────────────────────────────── */
		if (msg->header.message_type != THEMIC_MSG_VP_INTERCEPT)
			FAIL("expected message_type 0x%04x, got 0x%04x",
			     THEMIC_MSG_VP_INTERCEPT, msg->header.message_type);
		if (msg->exit_reason != EXIT_REASON_HLT)
			FAIL("expected exit_reason %d (HLT), got %u",
			     EXIT_REASON_HLT, msg->exit_reason);
	}

	printf("\n  ✓ Child executed HLT and exited correctly.\n");

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
