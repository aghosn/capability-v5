// Thin C wrapper around Lean @[export] functions.
// Handles IO result unwrapping: Lean IO functions return lean_object*
// (IO result); we extract the value and free the result here.

#include "lean_wrapper.h"
#include <lean/lean.h>
#include <string.h>

// Lean runtime initialization (declared in libleanrt)
extern void lean_initialize_runtime_module(void);

// ── Lean @[export] function declarations ──

extern lean_object* lean_exec_init(uint64_t, uint64_t);
extern lean_object* lean_exec_reset(uint64_t);
extern lean_object* lean_exec_carve(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
extern lean_object* lean_exec_alias(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
extern lean_object* lean_exec_send(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
extern lean_object* lean_exec_accept(uint64_t, uint64_t, uint64_t, uint64_t);
extern lean_object* lean_exec_reject(uint64_t, uint64_t);
extern lean_object* lean_exec_revoke_mem(uint64_t, uint64_t, uint64_t);
extern lean_object* lean_exec_create_domain(uint64_t, uint64_t, uint64_t);
extern lean_object* lean_exec_seal(uint64_t, uint64_t);
extern lean_object* lean_exec_revoke_domain(uint64_t, uint64_t);
extern lean_object* lean_exec_get_chan(uint64_t, uint64_t);
extern lean_object* lean_exec_send_channel(uint64_t, uint64_t, uint64_t);
extern lean_object* lean_exec_accept_channel(uint64_t, uint64_t);
extern lean_object* lean_exec_reject_channel(uint64_t, uint64_t);
extern lean_object* lean_exec_add_vp(uint64_t, uint64_t, uint64_t, uint64_t);
extern lean_object* lean_exec_register_comm(uint64_t, uint64_t, uint64_t, uint64_t);
extern lean_object* lean_exec_switch_forward(uint64_t, uint64_t, uint64_t);
extern lean_object* lean_exec_switch_return(uint64_t);
extern lean_object* lean_exec_deliver_interrupt(uint64_t, uint64_t, uint64_t);
extern lean_object* lean_exec_set_policy(uint64_t, uint64_t, uint64_t, uint64_t);
extern lean_object* lean_exec_get_policy(uint64_t, uint64_t, uint64_t);
extern lean_object* lean_exec_set_register(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
extern lean_object* lean_exec_get_register(uint64_t, uint64_t, uint64_t, uint64_t);
extern lean_object* lean_exec_set_interrupt_policy(uint64_t, uint64_t, uint64_t, uint64_t);
extern lean_object* lean_exec_get_result1(void);
extern lean_object* lean_exec_get_result2(void);
extern lean_object* lean_exec_get_result_str(void);
extern lean_object* lean_exec_get_error_msg(void);
extern lean_object* lean_exec_update_count(void);
extern lean_object* lean_exec_update_field(uint64_t, uint64_t);
extern lean_object* lean_exec_list_domains(void);
extern lean_object* lean_exec_get_domain_mem_caps(uint64_t);
extern lean_object* lean_exec_get_domain_dom_caps(uint64_t);
extern lean_object* lean_exec_get_pending_caps(uint64_t);
extern lean_object* lean_exec_get_address_space(uint64_t);
extern lean_object* lean_exec_get_core_states(void);
extern lean_object* lean_exec_attest(uint64_t);
extern lean_object* lean_exec_num_cores(void);

// Module initializer
extern lean_object* initialize_LeanExec_LeanExec_FFI(uint8_t);

// ── Helpers ──

// Extract UInt32 from IO result, free the result.
static uint32_t extract_u32(lean_object* r) {
    if (lean_io_result_is_ok(r)) {
        uint32_t val = lean_unbox_uint32(lean_io_result_get_value(r));
        lean_dec_ref(r);
        return val;
    }
    lean_dec_ref(r);
    return 0xFFFF;
}

// Extract UInt64 from IO result, free the result.
static uint64_t extract_u64(lean_object* r) {
    if (lean_io_result_is_ok(r)) {
        uint64_t val = lean_unbox_uint64(lean_io_result_get_value(r));
        lean_dec_ref(r);
        return val;
    }
    lean_dec_ref(r);
    return 0;
}

// Extract String from IO result into static buffer, free the result.
#define STR_BUF_SIZE 262144
static char g_str_buf[STR_BUF_SIZE];

static const char* extract_str(lean_object* r) {
    if (lean_io_result_is_ok(r)) {
        b_lean_obj_res val = lean_io_result_get_value(r);
        const char* s = lean_string_cstr(val);
        size_t len = strlen(s);
        if (len >= STR_BUF_SIZE) len = STR_BUF_SIZE - 1;
        memcpy(g_str_buf, s, len);
        g_str_buf[len] = '\0';
        lean_dec_ref(r);
        return g_str_buf;
    }
    lean_dec_ref(r);
    g_str_buf[0] = '\0';
    return g_str_buf;
}

// ── Initialization ──

static int g_initialized = 0;

int lean_ffi_initialize(void) {
    if (g_initialized) return 0;

    lean_initialize_runtime_module();

    lean_object* res = initialize_LeanExec_LeanExec_FFI(1);
    if (lean_io_result_is_error(res)) {
        lean_dec_ref(res);
        return -1;
    }
    lean_dec_ref(res);

    g_initialized = 1;
    return 0;
}

// ── Lifecycle ──

uint32_t lean_ffi_init(uint64_t mem_size, uint64_t num_cores) {
    return extract_u32(lean_exec_init(mem_size, num_cores));
}

uint32_t lean_ffi_reset(uint64_t num_cores) {
    return extract_u32(lean_exec_reset(num_cores));
}

// ── Memory operations ──

uint32_t lean_ffi_carve(uint64_t owner, uint64_t parent_uid,
                        uint64_t start, uint64_t size, uint64_t rights) {
    return extract_u32(lean_exec_carve(owner, parent_uid, start, size, rights));
}

uint32_t lean_ffi_alias(uint64_t owner, uint64_t parent_uid,
                        uint64_t start, uint64_t size, uint64_t rights) {
    return extract_u32(lean_exec_alias(owner, parent_uid, start, size, rights));
}

uint32_t lean_ffi_send(uint64_t mem_uid, uint64_t receiver,
                       uint64_t attrs, uint64_t gpa_val, uint64_t has_gpa) {
    return extract_u32(lean_exec_send(mem_uid, receiver, attrs, gpa_val, has_gpa));
}

uint32_t lean_ffi_accept(uint64_t dom_id, uint64_t pending_id,
                         uint64_t gpa_val, uint64_t has_gpa) {
    return extract_u32(lean_exec_accept(dom_id, pending_id, gpa_val, has_gpa));
}

uint32_t lean_ffi_reject(uint64_t dom_id, uint64_t pending_id) {
    return extract_u32(lean_exec_reject(dom_id, pending_id));
}

uint32_t lean_ffi_revoke_mem(uint64_t owner, uint64_t parent_uid,
                             uint64_t child_uid) {
    return extract_u32(lean_exec_revoke_mem(owner, parent_uid, child_uid));
}

// ── Domain operations ──

uint32_t lean_ffi_create_domain(uint64_t parent_id, uint64_t cores, uint64_t api) {
    return extract_u32(lean_exec_create_domain(parent_id, cores, api));
}

uint32_t lean_ffi_seal(uint64_t owner, uint64_t child_id) {
    return extract_u32(lean_exec_seal(owner, child_id));
}

uint32_t lean_ffi_revoke_domain(uint64_t parent_id, uint64_t child_id) {
    return extract_u32(lean_exec_revoke_domain(parent_id, child_id));
}

// ── Channel operations ──

uint32_t lean_ffi_get_chan(uint64_t caller, uint64_t target) {
    return extract_u32(lean_exec_get_chan(caller, target));
}

uint32_t lean_ffi_send_channel(uint64_t caller, uint64_t chan_id,
                               uint64_t receiver) {
    return extract_u32(lean_exec_send_channel(caller, chan_id, receiver));
}

uint32_t lean_ffi_accept_channel(uint64_t receiver, uint64_t pending_id) {
    return extract_u32(lean_exec_accept_channel(receiver, pending_id));
}

uint32_t lean_ffi_reject_channel(uint64_t receiver, uint64_t pending_id) {
    return extract_u32(lean_exec_reject_channel(receiver, pending_id));
}

// ── VP & Switch ──

uint32_t lean_ffi_add_vp(uint64_t parent, uint64_t child,
                         uint64_t comm_uid, uint64_t vp_id) {
    return extract_u32(lean_exec_add_vp(parent, child, comm_uid, vp_id));
}

uint32_t lean_ffi_register_comm(uint64_t owner, uint64_t comm_uid,
                                uint64_t child, uint64_t vp_id) {
    return extract_u32(lean_exec_register_comm(owner, comm_uid, child, vp_id));
}

uint32_t lean_ffi_switch_forward(uint64_t target_dom, uint64_t core, uint64_t vp) {
    return extract_u32(lean_exec_switch_forward(target_dom, core, vp));
}

uint32_t lean_ffi_switch_return(uint64_t core) {
    return extract_u32(lean_exec_switch_return(core));
}

uint32_t lean_ffi_deliver_interrupt(uint64_t vector, uint64_t domain,
                                    uint64_t core) {
    return extract_u32(lean_exec_deliver_interrupt(vector, domain, core));
}

// ── Policy & Registers ──

uint32_t lean_ffi_set_policy(uint64_t parent, uint64_t child,
                             uint64_t field_code, uint64_t value) {
    return extract_u32(lean_exec_set_policy(parent, child, field_code, value));
}

uint32_t lean_ffi_get_policy(uint64_t parent, uint64_t child,
                             uint64_t field_code) {
    return extract_u32(lean_exec_get_policy(parent, child, field_code));
}

uint32_t lean_ffi_set_register(uint64_t parent, uint64_t child,
                               uint64_t vp, uint64_t reg, uint64_t value) {
    return extract_u32(lean_exec_set_register(parent, child, vp, reg, value));
}

uint32_t lean_ffi_get_register(uint64_t parent, uint64_t child,
                               uint64_t vp, uint64_t reg) {
    return extract_u32(lean_exec_get_register(parent, child, vp, reg));
}

uint32_t lean_ffi_set_interrupt_policy(uint64_t owner, uint64_t child,
                                       uint64_t vector, uint64_t visibility) {
    return extract_u32(lean_exec_set_interrupt_policy(owner, child,
                                                      vector, visibility));
}

// ── Result getters ──

uint64_t lean_ffi_get_result1(void) {
    return extract_u64(lean_exec_get_result1());
}

uint64_t lean_ffi_get_result2(void) {
    return extract_u64(lean_exec_get_result2());
}

const char* lean_ffi_get_result_str(void) {
    return extract_str(lean_exec_get_result_str());
}

const char* lean_ffi_get_error_msg(void) {
    return extract_str(lean_exec_get_error_msg());
}

// ── Update buffer ──

uint64_t lean_ffi_update_count(void) {
    return extract_u64(lean_exec_update_count());
}

uint64_t lean_ffi_update_field(uint64_t idx, uint64_t field_idx) {
    return extract_u64(lean_exec_update_field(idx, field_idx));
}

// ── Queries ──

uint32_t lean_ffi_list_domains(void) {
    return extract_u32(lean_exec_list_domains());
}

uint32_t lean_ffi_get_domain_mem_caps(uint64_t dom_id) {
    return extract_u32(lean_exec_get_domain_mem_caps(dom_id));
}

uint32_t lean_ffi_get_domain_dom_caps(uint64_t dom_id) {
    return extract_u32(lean_exec_get_domain_dom_caps(dom_id));
}

uint32_t lean_ffi_get_pending_caps(uint64_t dom_id) {
    return extract_u32(lean_exec_get_pending_caps(dom_id));
}

uint32_t lean_ffi_get_address_space(uint64_t dom_id) {
    return extract_u32(lean_exec_get_address_space(dom_id));
}

uint32_t lean_ffi_get_core_states(void) {
    return extract_u32(lean_exec_get_core_states());
}

uint32_t lean_ffi_attest(uint64_t dom_id) {
    return extract_u32(lean_exec_attest(dom_id));
}

uint64_t lean_ffi_num_cores(void) {
    return extract_u64(lean_exec_num_cores());
}
