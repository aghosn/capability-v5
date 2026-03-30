//! Command dispatcher and module organization

pub mod domain;
pub mod memory;
pub mod info;
pub mod execution;
pub mod session_cmd;
pub mod tutos;

use crate::state::CliState;

/// Dispatch a command to the appropriate handler
pub fn dispatch(state: &mut CliState, cmd: &str, args: &[&str]) -> std::result::Result<(), String> {
    match cmd {
        // Domain commands
        "init" => domain::cmd_init(state, args),
        "create-domain" => domain::cmd_create_domain(state, args),
        "seal" => domain::cmd_seal(state, args),
        "revoke" => domain::cmd_revoke(state, args),
        "set-interrupt-policy" => domain::cmd_set_interrupt_policy(state, args),
        "set-default-interrupt-policy" => domain::cmd_set_default_interrupt_policy(state, args),
        "set-policy" => domain::cmd_set_policy(state, args),
        "get-policy" => domain::cmd_get_policy(state, args),
        "set-register" => domain::cmd_set_register(state, args),
        "get-register" => domain::cmd_get_register(state, args),
        "enumerate-pending" => domain::cmd_enumerate_pending(state, args),
        "accept-capability" => domain::cmd_accept_capability(state, args),
        "reject-capability" => domain::cmd_reject_capability(state, args),
        "get-chan"          => domain::cmd_get_chan(state, args),
        "accept-channel"    => domain::cmd_accept_channel(state, args),
        "reject-channel"    => domain::cmd_reject_channel(state, args),

        // Memory commands
        "carve" => memory::cmd_carve(state, args),
        "alias" => memory::cmd_alias(state, args),
        "send" => memory::cmd_send(state, args),
        "register-comm" => memory::cmd_register_comm(state, args),

        // Information commands
        "attest" => info::cmd_attest(state, args),
        "view" => info::cmd_view(state, args),
        "list" => info::cmd_list(state),
        "mem-usage" => info::cmd_mem_usage(state),

        // Execution commands
        "switch" => execution::cmd_switch(state, args),
        "interrupt" => execution::cmd_interrupt(state, args),

        // Session commands
        "save-session" => session_cmd::cmd_save_session(state, args),
        "export-as-unit-test" => session_cmd::cmd_export_as_unit_test(state, args),
        "clear-session" => session_cmd::cmd_clear_session(state),
        "reset" => session_cmd::cmd_reset(state),
        "load" => session_cmd::cmd_load(state, args),
        "auto-list" => session_cmd::cmd_toggle_auto_list(state, args),

        // Tutorial command
        "tutos" => tutos::cmd_tutos(state, args),

        // Unknown command
        _ => Err(format!("Unknown command: {}", cmd)),
    }
}
