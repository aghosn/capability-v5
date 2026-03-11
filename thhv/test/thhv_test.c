// SPDX-License-Identifier: GPL-2.0
/*
 * thhv_test — userspace test tool for the thhv driver.
 *
 * Build: gcc -o thhv_test thhv_test.c
 * Usage: ./thhv_test <command> [args...]
 *
 * Commands:
 *   grow_rx [pages]    Grow RX ring (default 1 page)
 *   grow_tx [pages]    Grow TX ring (default 1 page)
 *
 * Requires: driver built with THHV_TEST=1
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/ioctl.h>
#include <stdint.h>

/* Mirror the ioctl definitions from thhv.h */
#define THHV_IOCTL_MAGIC  0xB8

#define THHV_TEST_CMD_GROW_RX    1
#define THHV_TEST_CMD_GROW_TX    2
#define THHV_TEST_CMD_TX_PING    3

struct thhv_test_cmd {
	uint32_t command;
	uint32_t arg;
	int32_t  result;
	uint32_t reserved;
};

#define THHV_TEST \
	_IOWR(THHV_IOCTL_MAGIC, 0xF0, struct thhv_test_cmd)

static int run_test(int fd, uint32_t command, uint32_t arg, const char *name)
{
	struct thhv_test_cmd cmd = {
		.command = command,
		.arg = arg,
		.result = 0,
		.reserved = 0,
	};
	int ret;

	printf("  %-20s arg=%u ... ", name, arg);
	fflush(stdout);

	ret = ioctl(fd, THHV_TEST, &cmd);
	if (ret < 0) {
		printf("FAIL (ioctl: %s, result=%d)\n", strerror(errno), cmd.result);
		return -1;
	}

	if (cmd.result != 0) {
		printf("FAIL (result=%d)\n", cmd.result);
		return -1;
	}

	printf("OK\n");
	return 0;
}

int main(int argc, char *argv[])
{
	int fd, ret = 0;
	uint32_t pages;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <grow_rx|grow_tx> [pages]\n", argv[0]);
		return 1;
	}

	fd = open("/dev/thhv", O_RDWR);
	if (fd < 0) {
		perror("open /dev/thhv");
		return 1;
	}

	pages = (argc >= 3) ? (uint32_t)atoi(argv[2]) : 1;

	printf("thhv test suite\n");
	printf("===============\n");

	if (strcmp(argv[1], "grow_rx") == 0) {
		ret = run_test(fd, THHV_TEST_CMD_GROW_RX, pages, "grow_rx");
	} else if (strcmp(argv[1], "grow_tx") == 0) {
		ret = run_test(fd, THHV_TEST_CMD_GROW_TX, pages, "grow_tx");
	} else if (strcmp(argv[1], "all") == 0) {
		printf("Running all tests...\n");
		ret |= run_test(fd, THHV_TEST_CMD_GROW_RX, 1, "grow_rx");
		ret |= run_test(fd, THHV_TEST_CMD_GROW_TX, 1, "grow_tx");
	} else {
		fprintf(stderr, "Unknown command: %s\n", argv[1]);
		ret = 1;
	}

	close(fd);

	printf("\n%s\n", ret == 0 ? "ALL PASSED" : "SOME FAILED");
	return ret;
}
