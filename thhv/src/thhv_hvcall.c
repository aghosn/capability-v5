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

/**
 * themis_send - Send a memory capability to a child domain.
 * @cap:           Capability to send
 * @receiver:      Child domain handle
 * @attrs:         Send attributes / rights
 *
 * Uses THEMIS_SEND_IDENTITY_MAP as the GPA hint (identity mapping).
 */
int themis_send(u64 cap, u64 receiver, u64 attrs)
{
	u64 status = __themis_vmcall(THEMIS_OP_SEND,
				     cap, receiver, attrs,
				     THEMIS_SEND_IDENTITY_MAP, 0,
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

int themis_attest_self(u64 nonce_0, u64 nonce_1, u64 nonce_2, u64 nonce_3,
		       u64 *out_size)
{
	u64 status = __themis_vmcall(THEMIS_OP_ATTEST_SELF,
				     nonce_0, nonce_1, nonce_2, nonce_3, 0,
				     out_size, NULL, NULL);
	return __themis_to_errno(status);
}

int themis_attest_self_signed(u64 tx_sequence, u64 *out_size)
{
	u64 status = __themis_vmcall(THEMIS_OP_ATTEST_SELF,
				     1,            /* arg0 = signed mode flag */
				     tx_sequence,  /* arg1 = TX ring msg sequence */
				     0, 0, 0,
				     out_size, NULL, NULL);
	return __themis_to_errno(status);
}

int themis_read_pcr(u32 pcr_index, u64 *out_r0, u64 *out_r1, u64 *out_r2)
{
	u64 status = __themis_vmcall(THEMIS_OP_READ_PCR,
				     (u64)pcr_index, 0, 0, 0, 0,
				     out_r0, out_r1, out_r2);
	return __themis_to_errno(status);
}

int themis_map_self(u64 cap_handle, u64 new_gpa)
{
	u64 status = __themis_vmcall(THEMIS_OP_MAP_SELF,
				     cap_handle, new_gpa, 0, 0, 0,
				     NULL, NULL, NULL);
	return __themis_to_errno(status);
}

int themis_set_exit_policy(u64 child_domain, u64 exit_reason, u64 trap)
{
	u64 status = __themis_vmcall(THEMIS_OP_SET_EXIT_POLICY,
				     child_domain, exit_reason, trap, 0, 0,
				     NULL, NULL, NULL);
	return __themis_to_errno(status);
}

int themis_set_def_exit_policy(u64 child_domain, u64 trap)
{
	u64 status = __themis_vmcall(THEMIS_OP_SET_DEF_EXIT_POLICY,
				     child_domain, trap, 0, 0, 0,
				     NULL, NULL, NULL);
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

int themis_set_policy(u64 domain, u64 kind, u64 key, u64 sub_key, u64 value)
{
	u64 status = __themis_vmcall(THEMIS_OP_SET_POLICY,
				     domain, kind, key, sub_key, value,
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

/* ── ThemIC doorbell registration ────────────────────────────────────── */

int themis_register_doorbell(u64 child_domain, u64 gpa, u64 size,
     u64 datamatch, u64 flags, u64 *out_doorbell_id)
{
u64 status = __themis_vmcall(THEMIS_OP_REGISTER_DOORBELL,
     child_domain, gpa, size, datamatch, flags,
     out_doorbell_id, NULL, NULL);
return __themis_to_errno(status);
}

int themis_unregister_doorbell(u64 child_domain, u64 doorbell_id)
{
u64 status = __themis_vmcall(THEMIS_OP_UNREGISTER_DOORBELL,
     child_domain, doorbell_id, 0, 0, 0,
     NULL, NULL, NULL);
return __themis_to_errno(status);
}

int themis_set_themic_vector(u64 vector)
{
u64 status = __themis_vmcall(THEMIS_OP_SET_THEMIC_VECTOR,
     vector, 0, 0, 0, 0,
     NULL, NULL, NULL);
return __themis_to_errno(status);
}

int themis_inject_interrupt(u64 child_domain, u32 vp_id, u8 vector)
{
u64 status = __themis_vmcall(THEMIS_OP_INJECT_INTERRUPT,
     child_domain, (u64)vp_id, (u64)vector, 0, 0,
     NULL, NULL, NULL);
return __themis_to_errno(status);
}
