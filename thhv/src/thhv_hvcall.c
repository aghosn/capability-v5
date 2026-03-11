// SPDX-License-Identifier: GPL-2.0
/*
 * thhv_hvcall.c — Thin C shims around libthemis FFI functions.
 *
 * The actual VMCALL inline assembly lives in the Rust crate
 * `themis/crates/libthemis` (compiled as libthemis.a with feature "ffi").
 * This file provides the C-visible wrappers that the rest of the driver
 * calls, forwarding directly to the Rust FFI symbols.
 *
 * Why not call the Rust FFI functions directly from the driver?
 * We could — but this thin C wrapper lets us add kernel-specific
 * diagnostics (pr_debug, tracepoints) without touching libthemis.
 */

#include <linux/module.h>
#include "thhv.h"

/*
 * Extern declarations for the Rust FFI symbols (from libthemis.a).
 * These are defined in themis/crates/libthemis/src/ffi.rs and compiled
 * as #[no_mangle] pub extern "C" functions.
 */
extern int themis_create_domain(u64 cores_mask, u64 api_flags, u64 num_vps,
				u64 *out_handle);
extern int themis_seal(u64 domain);
extern int themis_revoke_domain(u64 domain);
extern int themis_revoke_mem(u64 parent, u64 child_sub);
extern int themis_carve(u64 parent, u64 start, u64 size, u64 rights,
			u64 *out_handle, u64 *out_sub);
extern int themis_send(u64 cap, u64 receiver, u64 attrs);
extern int themis_switch(u64 target_domain, u64 vp_id);
extern int themis_get_reg(u64 domain, u64 vp_id, u64 reg, u64 *out_val);
extern int themis_set_reg(u64 domain, u64 vp_id, u64 reg, u64 value);
extern int themis_register_comm(u64 cap, u64 child_domain, u64 vp_id);

/*
 * thhv_hcall() — General-purpose VMCALL wrapper.
 *
 * This is a fallback for opcodes that don't have dedicated FFI wrappers.
 * It issues a raw VMCALL using inline assembly (same convention as
 * libthemis but duplicated here for cases where we need to call an
 * opcode not yet exposed by libthemis's FFI surface).
 */
int thhv_hcall(u64 opcode, u64 arg0, u64 arg1, u64 arg2,
		   u64 *out0, u64 *out1, u64 *out2)
{
	u64 status, o0, o1, o2;

	asm volatile(
		"vmcall"
		: "=a"(status), "=D"(o0), "=S"(o1), "=d"(o2)
		: "a"(opcode), "D"(arg0), "S"(arg1), "d"(arg2)
		: "memory", "cc"
	);

	if (out0)
		*out0 = o0;
	if (out1)
		*out1 = o1;
	if (out2)
		*out2 = o2;

	switch (status) {
	case THEMIS_SUCCESS:     return 0;
	case THEMIS_ERR_INVALID: return -EINVAL;
	case THEMIS_ERR_NOPERM:  return -EPERM;
	case THEMIS_ERR_NOMEM:   return -ENOMEM;
	case THEMIS_ERR_BADSTATE:return -EBUSY;
	case THEMIS_ERR_NOTFOUND:return -ENOENT;
	case THEMIS_ERR_UNIMPL:  return -ENOSYS;
	default:                 return -EIO;
	}
}

