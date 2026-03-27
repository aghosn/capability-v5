/*
 * toggle-debug.c — Toggle capavisor runtime debug logging.
 *
 * Usage: sudo ./toggle-debug [1|0]
 *   1 = enable, 0 = disable (default: enable)
 *
 * Performs a raw VMCALL with opcode 0x1d (THEMIS_TOGGLE_DEBUG).
 * Must be run as root inside dom0.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define THEMIS_OP_TOGGLE_DEBUG 0x1d

static inline uint64_t themis_vmcall(uint64_t opcode, uint64_t a0)
{
	uint64_t status;
	__asm__ __volatile__(
		"vmcall"
		: "=a"(status)
		: "a"(opcode), "D"(a0), "S"((uint64_t)0),
		  "d"((uint64_t)0), "c"((uint64_t)0)
		: "r8", "memory"
	);
	return status;
}

int main(int argc, char **argv)
{
	uint64_t enable = 1;
	if (argc > 1)
		enable = (uint64_t)atoi(argv[1]);

	uint64_t ret = themis_vmcall(THEMIS_OP_TOGGLE_DEBUG, enable);
	printf("THEMIS_TOGGLE_DEBUG(%lu) returned %lu\n", enable, ret);
	return (int)ret;
}
