// Thin C wrapper around Lean @[export] functions.
// Handles IO result unwrapping so Rust only sees plain C types.

#ifndef LEAN_FFI_WRAPPER_H
#define LEAN_FFI_WRAPPER_H

#include <stdint.h>

// Must be called before any other lean_ffi_* function.
// Returns 0 on success, -1 on failure.
int lean_ffi_initialize(void);

// --- Lifecycle ---
uint32_t lean_ffi_init(uint64_t mem_size, uint64_t num_cores);
uint32_t lean_ffi_reset(uint64_t num_cores);

// --- Memory operations ---
uint32_t lean_ffi_carve(uint64_t owner, uint64_t parent_uid,
                        uint64_t start, uint64_t size, uint64_t rights);
uint32_t lean_ffi_alias(uint64_t owner, uint64_t parent_uid,
                        uint64_t start, uint64_t size, uint64_t rights);
uint32_t lean_ffi_send(uint64_t mem_uid, uint64_t receiver,
                       uint64_t attrs, uint64_t gpa_val, uint64_t has_gpa);
uint32_t lean_ffi_accept(uint64_t dom_id, uint64_t pending_id,
                         uint64_t gpa_val, uint64_t has_gpa);
uint32_t lean_ffi_reject(uint64_t dom_id, uint64_t pending_id);
uint32_t lean_ffi_revoke_mem(uint64_t owner, uint64_t parent_uid,
                             uint64_t child_uid);

// --- Domain operations ---
uint32_t lean_ffi_create_domain(uint64_t parent_id, uint64_t cores, uint64_t api);
uint32_t lean_ffi_seal(uint64_t owner, uint64_t child_id);
uint32_t lean_ffi_revoke_domain(uint64_t parent_id, uint64_t child_id);

// --- Channel operations ---
uint32_t lean_ffi_get_chan(uint64_t caller, uint64_t target);
uint32_t lean_ffi_get_chan_self(uint64_t caller);
uint32_t lean_ffi_send_channel(uint64_t caller, uint64_t chan_id,
                               uint64_t receiver);
uint32_t lean_ffi_accept_channel(uint64_t receiver, uint64_t pending_id);
uint32_t lean_ffi_reject_channel(uint64_t receiver, uint64_t pending_id);

// --- VP & Switch ---
uint32_t lean_ffi_add_vp(uint64_t parent, uint64_t child,
                         uint64_t comm_uid, uint64_t vp_id);
uint32_t lean_ffi_register_comm(uint64_t owner, uint64_t comm_uid,
                                uint64_t child, uint64_t vp_id);
uint32_t lean_ffi_switch_forward(uint64_t target_dom, uint64_t core, uint64_t vp);
uint32_t lean_ffi_switch_return(uint64_t core);
uint32_t lean_ffi_deliver_interrupt(uint64_t vector, uint64_t domain,
                                    uint64_t core);

// --- Policy & Registers ---
uint32_t lean_ffi_set_policy(uint64_t parent, uint64_t child,
                             uint64_t field_code, uint64_t value);
uint32_t lean_ffi_get_policy(uint64_t parent, uint64_t child,
                             uint64_t field_code);
uint32_t lean_ffi_set_register(uint64_t parent, uint64_t child,
                               uint64_t vp, uint64_t reg, uint64_t value);
uint32_t lean_ffi_get_register(uint64_t parent, uint64_t child,
                               uint64_t vp, uint64_t reg);
uint32_t lean_ffi_set_interrupt_policy(uint64_t owner, uint64_t child,
                                       uint64_t vector, uint64_t visibility);

// --- Result getters ---
uint64_t lean_ffi_get_result1(void);
uint64_t lean_ffi_get_result2(void);
// Returns pointer to internal buffer — valid until next call.
const char* lean_ffi_get_result_str(void);
const char* lean_ffi_get_error_msg(void);

// --- Update buffer access ---
uint64_t lean_ffi_update_count(void);
uint64_t lean_ffi_update_field(uint64_t idx, uint64_t field_idx);

// --- Queries (results via get_result_str) ---
uint32_t lean_ffi_list_domains(void);
uint32_t lean_ffi_get_domain_mem_caps(uint64_t dom_id);
uint32_t lean_ffi_get_domain_dom_caps(uint64_t dom_id);
uint32_t lean_ffi_get_pending_caps(uint64_t dom_id);
uint32_t lean_ffi_get_address_space(uint64_t dom_id);
uint32_t lean_ffi_get_core_states(void);
uint32_t lean_ffi_attest(uint64_t dom_id);
uint64_t lean_ffi_num_cores(void);

#endif // LEAN_FFI_WRAPPER_H
