// SPDX-License-Identifier: GPL-2.0
/*
 * test_coco_attacker — dom0 user program that probes every carved HPA in the
 * system and reports any successful load as a confidentiality LEAK.
 *
 * Pairs with the eunomia-coco-illegal-access workload running in dom1.
 *
 * Flow:
 *   1. open /dev/thhv
 *   2. ioctl(THHV_DEBUG_LIST_HPAS) with max_entries=0 to size, allocate, retry
 *   3. for each (hpa, nr_pages) run:
 *        mmap(NULL, nr_pages * 4096, PROT_READ, MAP_SHARED, thhv_fd, hpa)
 *        for every other page in the run:
 *            probe a single u64 read under sigsetjmp/SIGSEGV handler
 *            faulted -> good; success -> LEAK
 *   4. print summary; exit 0 iff probed > 0 and leaks == 0
 *
 * The mmap path uses thhv's debug mmap fop (offset = HPA); the page tables it
 * installs point straight at the carved HPAs, so EPT_VIOLATION is the only
 * thing that can stop the load.  capavisor injects #GP(0) on CPL=3
 * EPT_VIOLATION, which Linux converts to SIGSEGV.
 *
 * Build:  make tests   (from thhv/)
 * Run:    sudo ./test/bin/test_coco_attacker     (needs CAP_SYS_ADMIN)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>
#include <inttypes.h>
#include <linux/ioctl.h>

/* Local copies of UAPI bits we need (thhv.h pulls in kernel-only helpers). */
#define THHV_IOCTL_MAGIC 0xB8

struct thhv_debug_hpa_range {
	uint64_t hpa;
	uint64_t nr_pages;
};

struct thhv_debug_list_hpas {
	uint64_t domain_handle;
	uint32_t max_entries;
	uint32_t nr_entries;
	uint64_t entries;
};

#define THHV_DEBUG_LIST_HPAS \
	_IOWR(THHV_IOCTL_MAGIC, 0xF1, struct thhv_debug_list_hpas)

#define PAGE_SIZE 4096UL

/* SIGSEGV recovery: jump back to the probe site. */
static sigjmp_buf g_probe_env;
static volatile sig_atomic_t g_in_probe = 0;

static void sigsegv_handler(int sig, siginfo_t *info, void *ctx)
{
	(void)sig;
	(void)info;
	(void)ctx;
	if (g_in_probe) {
		/* Async-signal-safe: just jump back. */
		siglongjmp(g_probe_env, 1);
	}
	/* Unexpected SIGSEGV outside probe — abort hard. */
	_exit(2);
}

static int install_handler(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = sigsegv_handler;
	sa.sa_flags = SA_SIGINFO | SA_NODEFER;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGSEGV, &sa, NULL) < 0) {
		perror("sigaction(SIGSEGV)");
		return -1;
	}
	/* #GP from kernel re-injection arrives to userland as SIGSEGV on x86_64
	 * (force_sig(SIGSEGV) inside do_general_protection).  We still also
	 * trap SIGBUS to be safe. */
	if (sigaction(SIGBUS, &sa, NULL) < 0) {
		perror("sigaction(SIGBUS)");
		return -1;
	}
	return 0;
}

/* Returns: 0 on fault (good), 1 on success-load (LEAK), value via *out. */
static int probe_one(volatile uint64_t *va, uint64_t *out)
{
	uint64_t v = 0;
	int result;

	if (sigsetjmp(g_probe_env, 1) == 0) {
		g_in_probe = 1;
		v = *va;          /* the only allowed faulting site */
		g_in_probe = 0;
		*out = v;
		result = 1;       /* loaded — LEAK */
	} else {
		g_in_probe = 0;
		result = 0;       /* faulted — good */
	}
	return result;
}

/* Two-step ioctl: size first, then fetch. */
static struct thhv_debug_hpa_range *fetch_runs(int fd, uint32_t *out_n)
{
	struct thhv_debug_list_hpas q;
	struct thhv_debug_hpa_range *buf;
	uint32_t cap;

	memset(&q, 0, sizeof(q));
	q.domain_handle = 0;       /* 0 = all partitions */
	q.max_entries   = 0;
	q.entries       = 0;
	if (ioctl(fd, THHV_DEBUG_LIST_HPAS, &q) < 0) {
		perror("ioctl(THHV_DEBUG_LIST_HPAS) sizing");
		return NULL;
	}
	if (q.nr_entries == 0) {
		fprintf(stderr, "no carved runs reported — is dom1 up?\n");
		*out_n = 0;
		return NULL;
	}

	/* Re-fetch with some headroom in case more partitions appear meanwhile. */
	cap = q.nr_entries + 16;
	buf = calloc(cap, sizeof(*buf));
	if (!buf) {
		perror("calloc");
		return NULL;
	}

	memset(&q, 0, sizeof(q));
	q.domain_handle = 0;
	q.max_entries   = cap;
	q.entries       = (uintptr_t)buf;
	if (ioctl(fd, THHV_DEBUG_LIST_HPAS, &q) < 0) {
		perror("ioctl(THHV_DEBUG_LIST_HPAS) fetch");
		free(buf);
		return NULL;
	}

	*out_n = q.nr_entries < cap ? q.nr_entries : cap;
	return buf;
}

int main(int argc, char **argv)
{
	int fd, opt;
	uint32_t n_runs = 0;
	struct thhv_debug_hpa_range *runs = NULL;
	uint64_t probed = 0, faulted = 0, leaks = 0;
	int verbose = 0;
	/* Probe stride: 1 = every page, 2 = every other page, ... */
	uint64_t stride = 2;
	/* Hard cap: bail after this many probes total (0 = unlimited). */
	uint64_t max_probes = 64;
	/* Wait up to N seconds for at least one carved run to appear. */
	unsigned wait_secs = 0;

	while ((opt = getopt(argc, argv, "vs:w:n:")) != -1) {
		switch (opt) {
		case 'v':
			verbose = 1;
			break;
		case 's':
			stride = strtoull(optarg, NULL, 0);
			if (stride == 0) stride = 1;
			break;
		case 'w':
			wait_secs = (unsigned)strtoul(optarg, NULL, 0);
			break;
		case 'n':
			max_probes = strtoull(optarg, NULL, 0);
			break;
		default:
			fprintf(stderr,
				"usage: %s [-v] [-s stride] [-w wait_secs] [-n max_probes]\n",
				argv[0]);
			return 1;
		}
	}

	if (install_handler() < 0)
		return 1;

	fd = open("/dev/thhv", O_RDWR);
	if (fd < 0) {
		perror("open(/dev/thhv)");
		return 1;
	}

	/* Optionally poll until dom1 has carved its RAM. */
	{
		unsigned waited_ms = 0;
		unsigned limit_ms = wait_secs * 1000;
		while (1) {
			struct thhv_debug_list_hpas q;
			memset(&q, 0, sizeof(q));
			if (ioctl(fd, THHV_DEBUG_LIST_HPAS, &q) < 0) {
				perror("ioctl(THHV_DEBUG_LIST_HPAS) probe");
				close(fd);
				return 1;
			}
			if (q.nr_entries > 0)
				break;
			if (waited_ms >= limit_ms) {
				fprintf(stderr,
					"no carved runs after %u s — is dom1 up?\n",
					wait_secs);
				close(fd);
				return 6;
			}
			usleep(200000);  /* 200 ms */
			waited_ms += 200;
		}
	}

	runs = fetch_runs(fd, &n_runs);
	if (!runs) {
		close(fd);
		return 1;
	}

	printf("coco-attacker: %u carved run(s), stride=%" PRIu64 "\n",
	       n_runs, stride);

	for (uint32_t i = 0; i < n_runs; i++) {
		uint64_t hpa = runs[i].hpa;
		uint64_t np  = runs[i].nr_pages;
		size_t len   = (size_t)np * PAGE_SIZE;
		void *map;

		if (verbose)
			printf("  [%u] hpa=%#018" PRIx64 " pages=%" PRIu64 "\n",
			       i, hpa, np);

		map = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, (off_t)hpa);
		if (map == MAP_FAILED) {
			fprintf(stderr, "  mmap(hpa=%#" PRIx64 ", len=%zu) failed: %s\n",
				hpa, len, strerror(errno));
			continue;
		}

		for (uint64_t p = 0; p < np; p += stride) {
			volatile uint64_t *va =
				(volatile uint64_t *)((uintptr_t)map + p * PAGE_SIZE);
			uint64_t got = 0;
			int loaded = probe_one(va, &got);
			probed++;
			if (loaded) {
				leaks++;
				if (leaks <= 16) {
					printf("  LEAK hpa=%#018" PRIx64 " page=%" PRIu64
					       " val=%#018" PRIx64 "\n",
					       hpa + p * PAGE_SIZE, p, got);
				}
			} else {
				faulted++;
			}
			if (max_probes && probed >= max_probes)
				break;
		}

		munmap(map, len);
		if (max_probes && probed >= max_probes) {
			printf("coco-attacker: reached probe cap (%" PRIu64
			       "); stopping early\n", max_probes);
			break;
		}
	}

	free(runs);
	close(fd);

	printf("coco-attacker: probed=%" PRIu64 " faulted=%" PRIu64
	       " leaks=%" PRIu64 "\n", probed, faulted, leaks);

	if (probed == 0) {
		fprintf(stderr, "FAIL: no probes performed\n");
		return 3;
	}
	if (leaks != 0) {
		fprintf(stderr, "FAIL: %" PRIu64 " leak(s) detected\n", leaks);
		return 4;
	}
	if (faulted != probed) {
		fprintf(stderr,
			"FAIL: %" PRIu64 "/%" PRIu64 " did not fault and did not load\n",
			probed - faulted, probed);
		return 5;
	}
	printf("PASS: every probed page faulted; isolation holds\n");
	return 0;
}
