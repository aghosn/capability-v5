// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "thhv.h"

static void check(int success, const char *what)
{
	if (!success) {
		fprintf(stderr, "FAIL: %s (errno=%d)\n", what, errno);
		exit(1);
	}
}

static void attest(int fd)
{
	void *buffer = malloc(1 << 20);
	struct thhv_attest_self args = {
		.buf_uaddr = (uintptr_t)buffer,
		.buf_len = 1 << 20,
	};

	check(buffer != NULL, "allocate attestation buffer");
	check(ioctl(fd, THHV_ATTEST_SELF, &args) == 0, "attest with queued events");
	free(buffer);
}

static void expect_event(int fd, int present)
{
	struct pollfd pollfd = { .fd = fd, .events = POLLIN };
	uint64_t count;
	int ret = poll(&pollfd, 1, present ? 5000 : 100);

	check(ret == (present ? 1 : 0), "eventfd readiness");
	if (present)
		check(read(fd, &count, sizeof(count)) == sizeof(count) && count == 1,
		      "one eventfd signal");
}

static int pending_close(void)
{
	long cpus = sysconf(_SC_NPROCESSORS_ONLN);
	int other = open("/dev/thhv", O_RDWR);

	check(other >= 0 && cpus > 0, "open driver for close test");
	for (int round = 0; round < 16; round++) {
		int fd = open("/dev/thhv", O_RDWR);

		check(fd >= 0, "open endpoint owner");
		for (long cpu = 0; cpu < cpus; cpu++) {
			struct thhv_create_doorbell doorbell = {
				.kind = THEMIS_DOORBELL_ASYNC, .vp = cpu,
			};
			struct thhv_notify notify;

			check(ioctl(fd, THHV_CREATE_DOORBELL, &doorbell) == 0,
			      "create before immediate close");
			notify.handle = doorbell.handle;
			notify.value = round;
			check(ioctl(fd, THHV_NOTIFY, &notify) == 0,
			      "post before immediate close");
		}
		check(close(fd) == 0, "immediate owner close");
	}
	close(other);
	puts("PASS: close after pending notifications");
	return 0;
}

int main(int argc, char **argv)
{
	int check_growth = argc == 2 && !strcmp(argv[1], "--grow");

	if (argc == 2 && !strcmp(argv[1], "--pending-close"))
		return pending_close();
	if (argc != 1 && !check_growth)
		return 2;
	long cpus = sysconf(_SC_NPROCESSORS_ONLN);
	int fd = open("/dev/thhv", O_RDWR);
	int other = open("/dev/thhv", O_RDWR);
	int event = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);

	check(fd >= 0 && other >= 0 && event >= 0, "open driver and eventfd");
	check(cpus > 0, "online CPU count");
	for (long cpu = 0; cpu < cpus; cpu++) {
		struct thhv_create_doorbell doorbell = {
			.kind = THEMIS_DOORBELL_ASYNC,
			.vp = cpu,
		};
		struct thhv_doorbell_eventfd subscription = { .fd = event };
		struct thhv_notify notify;
		struct thhv_revoke_cap revoke = { .parent = THEMIS_CAP_SELF };

		check(ioctl(fd, THHV_CREATE_DOORBELL, &doorbell) == 0, "create Async");
		subscription.port = doorbell.port;
		errno = 0;
		check(ioctl(other, THHV_DOORBELL_EVENTFD, &subscription) < 0 &&
		      errno == ENOENT, "subscription belongs to owning device fd");
		check(ioctl(fd, THHV_DOORBELL_EVENTFD, &subscription) == 0, "subscribe");
		notify.handle = doorbell.handle;
		notify.value = 0x7468656d69730000ULL + cpu;
		for (int round = 0; round < 4; round++) {
			struct thhv_test_cmd grow = {
				.command = round & 1 ? THHV_TEST_CMD_GROW_TX : THHV_TEST_CMD_GROW_RX,
				.arg = 1,
			};

			check(ioctl(fd, THHV_NOTIFY, &notify) == 0, "notify Async");
			if (cpu == 0 && check_growth)
				check(ioctl(fd, THHV_TEST, &grow) == 0 && grow.result == 0,
				      "grow with pending notification");
			attest(fd);
			expect_event(event, 1);
		}
		subscription.fd = -1;
		check(ioctl(fd, THHV_DOORBELL_EVENTFD, &subscription) == 0, "detach");
		check(ioctl(fd, THHV_NOTIFY, &notify) == 0, "notify while detached");
		attest(fd);
		expect_event(event, 0);
		subscription.fd = event;
		check(ioctl(fd, THHV_DOORBELL_EVENTFD, &subscription) == 0, "reattach");
		check(ioctl(fd, THHV_NOTIFY, &notify) == 0, "notify after reattach");
		expect_event(event, 1);
		revoke.sub = doorbell.port;
		check(ioctl(fd, THHV_REVOKE_CAP, &revoke) == 0, "revoke recipient port");
		check(ioctl(fd, THHV_NOTIFY, &notify) < 0, "stale handle rejected");
		expect_event(event, 0);
		printf("PASS: Async CPU %ld, subscription and revoke\n", cpu);
	}
	{
		struct thhv_create_partition args = {
			.cores_mask = ~0ULL, .api_flags = ~0ULL,
			.sched_policy = THHV_SCHED_SYNC, .num_vps = 1,
		};
		struct thhv_create_doorbell doorbell = { .kind = THEMIS_DOORBELL_SYNC };
		struct thhv_send_cap send;
		struct thhv_notify notify;
		struct thhv_revoke_cap revoke = { .parent = THEMIS_CAP_SELF };
		int partition = ioctl(fd, THHV_CREATE_PARTITION, &args);

		check(partition >= 0, "create child using generic channel SEND");
		check(ioctl(fd, THHV_CREATE_DOORBELL, &doorbell) == 0, "create for transfer");
		send.handle = doorbell.handle;
		send.attrs = 0;
		check(ioctl(partition, THHV_SEND_CAP, &send) == 0, "generic SEND to child");
		notify.handle = doorbell.handle;
		notify.value = 1;
		check(ioctl(fd, THHV_NOTIFY, &notify) < 0, "sender loses invocation handle");
		revoke.sub = doorbell.port;
		check(ioctl(fd, THHV_REVOKE_CAP, &revoke) == 0, "recipient revokes sent endpoint");
		check(close(partition) == 0, "destroy child using generic REVOKE");
		puts("PASS: shared ownership VMCALLs and recipient reclaim");
	}
	{
		struct thhv_create_doorbell doorbell = { .kind = THEMIS_DOORBELL_SYNC };
		struct thhv_notify notify;
		struct thhv_doorbell_eventfd subscription = { .fd = event };

		check(ioctl(fd, THHV_CREATE_DOORBELL, &doorbell) == 0, "create Sync");
		subscription.port = doorbell.port;
		check(ioctl(fd, THHV_DOORBELL_EVENTFD, &subscription) == 0, "subscribe Sync");
		notify.handle = doorbell.handle;
		notify.value = 1;
		check(ioctl(fd, THHV_NOTIFY, &notify) < 0, "Sync rejects absent caller chain");
		attest(fd);
		expect_event(event, 0);
		check(close(fd) == 0, "close revokes endpoint");
		check(ioctl(other, THHV_NOTIFY, &notify) < 0, "closed owner leaves no authority");
	}
	close(other);
	close(event);
	puts("PASS: public doorbell ioctls and eventfd delivery");
	return 0;
}
