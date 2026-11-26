// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "thhv.h"

int main(int argc, char **argv)
{
	long cpus = sysconf(_SC_NPROCESSORS_ONLN);
	int fd, cpu, repeats = 4;

	if (argc == 2) {
		char *end;
		long value = strtol(argv[1], &end, 10);

		if (*end || value < 1 || value > 10000)
			return 2;
		repeats = value;
	} else if (argc != 1) {
		return 2;
	}
	fd = open("/dev/thhv", O_RDWR);
	if (fd < 0) {
		perror("open /dev/thhv");
		return 1;
	}
	for (int round = 0; round < repeats; round++) {
		for (cpu = 0; cpu < cpus; cpu++) {
			struct thhv_test_cmd cmd = {
				.command = THHV_TEST_CMD_DOORBELL_IRQ,
				.arg = cpu,
			};

			if (ioctl(fd, THHV_TEST, &cmd) < 0 || cmd.result) {
				fprintf(stderr, "doorbell round=%d cpu=%d: errno=%d result=%d\n",
					round, cpu, errno, cmd.result);
				close(fd);
				return 1;
			}
		}
	}
	printf("PASS: %d rounds across %ld CPUs\n", repeats, cpus);
	close(fd);
	return 0;
}
