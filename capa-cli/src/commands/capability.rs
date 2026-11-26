use crate::{parser::parse_number, session::Command, state::CliState};
use capability_engine::DoorbellKind;

fn domain(state: &CliState, name: &str) -> Result<u64, String> {
    state.domain_names.get(name).copied().ok_or_else(|| format!("Unknown domain: {name}"))
}

pub fn dispatch(state: &mut CliState, cmd: &str, args: &[&str]) -> Result<(), String> {
    let result = match (cmd, args) {
        ("create-doorbell", [caller, recipient, vector, mode, rest @ ..]) => {
            let caller = domain(state, caller)?;
            let child = if *recipient == "self" { None } else { Some(domain(state, recipient)?) };
            let vector = u8::try_from(parse_number(vector)?).map_err(|_| "Invalid vector")?;
            let kind = match (*mode, rest) {
                ("sync", []) => DoorbellKind::Sync,
                ("async", [vp]) => DoorbellKind::Async { vp_id: parse_number(vp)? },
                _ => return Err("Use sync, or async <vp>".into()),
            };
            state.backend.create_doorbell(caller, child, vector, kind)
                .map(|(handle, port)| format!("Created doorbell handle={handle} port={port}"))
        }
        ("send-capability", [caller, handle, receiver]) => {
            let caller = domain(state, caller)?;
            let receiver = domain(state, receiver)?;
            state.backend.send_capability(caller, parse_number(handle)?, receiver)
                .map(|_| "Capability sent".into())
        }
        ("accept", [receiver, pending]) => {
            let receiver = domain(state, receiver)?;
            state.backend.accept_handle(receiver, parse_number(pending)?)
                .map(|handle| format!("Accepted capability handle={handle}"))
        }
        ("revoke", [caller, parent, sub]) => {
            let caller = domain(state, caller)?;
            let parent = if *parent == "self" { None } else { Some(parse_number(parent)?) };
            state.backend.revoke_child(caller, parent, parse_number(sub)?)
                .map(|_| "Capability revoked and destroyed".into())
        }
        ("notify", [caller, core, handle, value]) => {
            let caller = domain(state, caller)?;
            state.backend.notify(caller, parse_number(core)?, parse_number(handle)?, parse_number(value)?)
                .map(|context| match context {
                    Some(ctx) => format!("Sync delivered; resumed domain={} vp={}",
                        ctx.to_domain, ctx.to_vp.expect("Sync has a target VP")),
                    None => "Async delivered; sender continues".into(),
                })
        }
        ("doorbells", [recipient]) => {
            let recipient = domain(state, recipient)?;
            state.backend.doorbells(recipient)
        }
        _ => return Err(concat!(
            "Usage: create-doorbell <caller> <self|child> <vector> <sync|async vp>\n",
            "send-capability <caller> <handle> <receiver> | accept <receiver> <pending>\n",
            "revoke <caller> <self|parent_handle> <child_port>\n",
            "notify <caller> <core> <handle> <value> | doorbells <domain>"
        ).into()),
    };
    let output = result.map_err(|error| error.to_string())?;
    println!("{output}");
    state.session.add_command(Command::CapabilityCommand {
        text: format!("{cmd} {}", args.join(" ")),
    });
    Ok(())
}
