// SPDX-License-Identifier: GPL-2.0
/*
 * thhv_hvcall.c — Themis hypercall wrappers (pure C, no Rust dependency).
 *
 * All functions use __themis_vmcall() from thhv.h which issues the VMCALL
 * instruction with the correct register convention.  Error mapping uses
 * __themis_to_errno().
 */

#include <linux/module.h>
#include "thhv.h"

/* ── Generic fallback (for opcodes without dedicated wrappers) ─────────── */

int thhv_hcall(u64 opcode, u64 arg0, u64 arg1, u64 arg2,
		   u64 *out0, u64 *out1, u64 *out2)
{
	u64 status = __themis_vmcall(opcode, arg0, arg1, arg2, 0, 0,
				     out0, out1, out2);
	return __themis_to_errno(status);
}

/* ── Memory capability operations ──────────────────────────────────────── */

int themis_carve(u64 parent, u64 start, u64 size, u64 rights,
		 u64 *out_handle, u64 *out_sub)
{
	u64 status = __themis_vmcall(THEMIS_OP_CARVE,
				     parent, start, size, rights, 0,
				     out_handle, out_sub, NULL);
	return __themis_to_errno(status);
}

int themis_alias(u64 parent, u64 start, u64 size, u64 rights,
		 u64 *out_handle, u64 *out_sub)
{
	u64 status = __themis_vmcall(THEMIS_OP_ALIAS,
				     parent, start, size, rights, 0,
				     out_handle, out_sub, NULL);
	return __themis_to_errno(status);
}

int themis_send(u64 cap, u64 receiver, u64 attrs)
{
	u64 status = __themis_vmcall(THEMIS_OP_SEND,
				     cap, receiver, attrs, 0, 0,
				     NULL, NULL, NULL);
	return __themis_to_errno(status);
}

int themis_send_at(u64 cap, u64 receiver, u64 attrs, u64 child_gpa)
{
	u64 status = __themis_vmcall(THEMIS_OP_SEND,
				     cap, receiver, attrs, child_gpa, 0,
				     NULL, NULL, NULL);
	return __themis_to_errno(status);
}

int themis_accept(u64 pending_id, u64 *out_handle)
{
	u64 status = __themis_vmcall(THEMIS_OP_ACCEPT,
				     pending_id, 0, 0, 0, 0,
				     out_handle, NULL, NULL);
	return __themis_to_errno(status);
}

int themis_reject(u64 pending_id)
{
	u64 status = __themis_vmcall(THEMIS_OP_REJECT,
				     pending_id, 0, 0, 0, 0,
				     NULL, NULL, NULL);
	return __themis_to_errno(status);
}

int themis_revoke_mem(u64 parent, u64 child_sub)
{
	u64 status = __themis_vmcall(THEMIS_OP_REVOKE_MEM,
				     parent, child_sub, 0, 0, 0,
				     NULL, NULL, NULL);
	return __themis_to_errno(status);
}

/* ── Domain operations ─────────────────────────────────────────────────── */

int themis_create_domain(u64 cores_mask, u64 api_flags, u64 num_vps,
			 u64 *out_handle)
{
	u64 status = __themis_vmcall(THEMIS_OP_CREATE_DOMAIN,
				     cores_mask, api_flags, num_vps, 0, 0,
				     out_handle, NULL, NULL);
	return __themis_to_errno(status);
}

int themis_seal(u64 domain)
{
	u64 status = __themis_vmcall(THEMIS_OP_SEAL,
				     domain, 0, 0, 0, 0,
				     NULL, NULL, NULL);
	return __themis_to_errno(status);
}

int themis_revoke_domain(u64 domain)
{
	u64 status = __themis_vmcall(THEMIS_OP_REVOKE_DOMAIN,
				     domain, 0, 0, 0, 0,
				     NULL, NULL, NULL);
	return __themis_to_errno(status);
}

int themis_switch(u64 target_domain, u64 vp_id)
{
	u64 status = __themis_vmcall(THEMIS_OP_SWITCH,
				     target_domain, vp_id, 0, 0, 0,
				     NULL, NULL, NULL);
	return __themis_to_errno(status);
}

/* ── Attestation ───────────────────────────────────────────────────────── */

int themis_get_chan(u64 domain, u64 *out_handle)
{
	u64 status = __themis_vmcall(THEMIS_OP_GET_CHAN,
				     domain, 0, 0, 0, 0,
				     out_handle, NULL, NULL);
	return __themis_to_errno(status);
}

int themis_attest_self(u64 *out_lo, u64 *out_hi)
{
	u64 status = __themis_vmcall(THEMIS_OP_ATTEST_SELF,
				     0, 0, 0, 0, 0,
				     out_lo, out_hi, NULL);
	return __themis_to_errno(status);
}

int themis_attest(u64 domain, u64 *out_lo, u64 *out_hi)
{
	u64 status = __themis_vmcall(THEMIS_OP_ATTEST,
				     domain, 0, 0, 0, 0,
				     out_lo, out_hi, NULL);
	return __themis_to_errno(status);
}

/* ── VP register access ────────────────────────────────────────────────── */

int themis_get_reg(u64 domain, u64 vp_id, u64 reg, u64 *out_val)
{
	u64 status = __themis_vmcall(THEMIS_OP_GET_REG,
				     domain, vp_id, reg, 0, 0,
				     out_val, NULL, NULL);
	return __themis_to_errno(status);
}

int themis_set_reg(u64 domain, u64 vp_id, u64 reg, u64 value)
{
	u64 status = __themis_vmcall(THEMIS_OP_SET_REG,
				     domain, vp_id, reg, value, 0,
				     NULL, NULL, NULL);
	return __themis_to_errno(status);
}

/* ── Interrupt / device assignment ─────────────────────────────────────── */

int themis_set_intr_policy(u64 domain, u64 vector, u64 policy)
{
	u64 status = __themis_vmcall(THEMIS_OP_SET_INTR_POLICY,
				     domain, vector, policy, 0, 0,
				     NULL, NULL, NULL);
	return __themis_to_errno(status);
}

int themis_set_def_intr_policy(u64 domain, u64 policy)
{
	u64 status = __themis_vmcall(THEMIS_OP_SET_DEF_INTR_POLICY,
				     domain, policy, 0, 0, 0,
				     NULL, NULL, NULL);
	return __themis_to_errno(status);
}

int themis_assign_device(u64 domain, u64 pci_bdf)
{
	u64 status = __themis_vmcall(THEMIS_OP_ASSIGN_DEVICE,
				     domain, pci_bdf, 0, 0, 0,
				     NULL, NULL, NULL);
	return __themis_to_errno(status);
}

/* ── DomainComm registration ──────────────────────────────────────────── */

int themis_register_comm(u64 cap, u64 child_domain, u64 vp_id)
{
	u64 status = __themis_vmcall(THEMIS_OP_REGISTER_COMM,
				     cap, child_domain, vp_id, 0, 0,
				     NULL, NULL, NULL);
	return __themis_to_errno(status);
}

/* ── Add VP ──────────────────────────────────────────────────────────── */

int themis_add_vp(u64 child_domain, u64 comm_cap)
{
	u64 rdi;
	u64 status = __themis_vmcall(THEMIS_OP_ADD_VP,
				     child_domain, comm_cap, 0, 0, 0,
				     &rdi, NULL, NULL);
	return __themis_to_errno(status);
}

/* ── DomainComm TX ring notification ─────────────────────────────────── */

int themis_domcomm_notify(void)
{
	u64 status = __themis_vmcall(THEMIS_OP_DOMCOMM_NOTIFY,
				     0, 0, 0, 0, 0,
				     NULL, NULL, NULL);
	return __themis_to_errno(status);
}
