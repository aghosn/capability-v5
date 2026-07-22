// SPDX-License-Identifier: GPL-2.0
/*
 * test_debug_revoke_all — issue THHV_DEBUG_REVOKE_ALL on /dev/thhv.
 *
 * Debug helper that walks the thhv global partitions list and fires
 * REVOKE_DOMAIN on every registered child partition (dom0 itself is
 * never in the list).  Intended to exercise the capavisor cross-core
 * revoke path from a user process pinned to a specific dom0 core
 * (typically different from the CHV vCPU thread hosting the child).
 *
 * Usage:
 *   sudo taskset -c <core> ./test_debug_revoke_all
 *
 * Exits 0 on success, prints the number of partitions revoked.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/ioctl.h>

/* Local UAPI copy (thhv.h pulls in kernel-only helpers we don't need). */
#define THHV_IOCTL_MAGIC 0xB8
#define THHV_DEBUG_REVOKE_ALL _IO(THHV_IOCTL_MAGIC, 0xF2)

int main(int argc, char **argv)
{
	int fd, rc;

	(void)argc;
	(void)argv;

	fd = open("/dev/thhv", O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "open(/dev/thhv): %s\n", strerror(errno));
		return 1;
	}

	rc = ioctl(fd, THHV_DEBUG_REVOKE_ALL);
	if (rc < 0) {
		fprintf(stderr, "THHV_DEBUG_REVOKE_ALL: %s\n", strerror(errno));
		close(fd);
		return 1;
	}

	printf("THHV_DEBUG_REVOKE_ALL: %d partition(s) revoked\n", rc);
	close(fd);
	return 0;
}
