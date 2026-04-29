//! xtask — thin dispatcher from `cargo <task>` to `scripts/<task>.sh`.
//!
//! Usage (via cargo aliases defined in .cargo/config.toml):
//!   cargo iso            →  bash scripts/build-iso.sh
//!   cargo themis         →  bash scripts/run-qemu.sh
//!   cargo themis-debug   →  bash scripts/themis-debug.sh
//!   cargo gdb            →  bash scripts/gdb.sh
//!   cargo build-kernel  →  bash scripts/build-kernel.sh
//!   cargo fetch-dom0     →  bash scripts/fetch-dom0.sh
//!
//! Direct usage:
//!   cargo run -p xtask -- <task> [extra args...]
//!
//! All environment variables are forwarded to the script unchanged,
//! so knobs like QEMU_MEM, PROFILE, FORCE etc. work as documented.

use std::path::PathBuf;
use std::process::Command;

#[cfg(unix)]
use std::os::unix::process::CommandExt;

fn main() {
    // The first argument after `--` is the task name.
    let task = match std::env::args().nth(1) {
        Some(t) => t,
        None => {
            eprintln!("usage: cargo run -p xtask -- <task> [args...]");
            eprintln!("tasks: iso | run-qemu | themis-debug | gdb | fetch-dom0 | run-dom0 | setup-limine | resize-disk | aarch64-iso | aarch64-themis | aarch64-direct | fetch-aarch64-kernel | fetch-aarch64-dom0 | build-kernel");
            std::process::exit(1);
        }
    };

    // xtask lives at <workspace>/xtask/; workspace root is one level up.
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has no parent directory")
        .to_owned();

    // Map task name → script filename (hyphens allowed in task names).
    let script_name = format!("{}.sh", task);
    let script = workspace.join("scripts").join(&script_name);

    if !script.exists() {
        eprintln!(
            "error: no script for task '{}' (expected {})",
            task,
            script.display()
        );
        eprintln!("available tasks: iso | run-qemu | themis-debug | gdb | fetch-dom0 | run-dom0 | setup-limine | resize-disk | aarch64-iso | aarch64-themis | aarch64-direct | fetch-aarch64-kernel | fetch-aarch64-dom0 | build-kernel");
        std::process::exit(1);
    }

    // Forward any extra arguments after the task name to the script.
    let extra: Vec<String> = std::env::args().skip(2).collect();

    // Replace this process with bash — gives the script (and QEMU) direct
    // terminal access, which is required for interactive serial consoles.
    let err = Command::new("bash")
        .arg(&script)
        .args(&extra)
        .current_dir(&workspace)
        .exec();

    // exec() only returns on failure
    panic!("failed to exec {}: {err}", script.display());
}
