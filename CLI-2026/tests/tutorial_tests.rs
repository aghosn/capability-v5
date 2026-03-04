//! Integration tests for CLI tutorials.
//!
//! Each test loads the corresponding tutorial file from `tutos/` through the
//! CLI's `load` command and asserts that no command fails.  Commands that are
//! intentionally expected to fail must be preceded by a `# EXPECT_FAIL` line
//! in the tutorial file; `cmd_load` will run them and assert they return an
//! error — if they unexpectedly succeed, that is treated as a failure.
//!
//! Run with:  cargo test

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Return the path to the compiled binary.
fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_capability-cli"))
}

/// Return the absolute path to a tutorial file given its filename (e.g. "01-basic-carve.txt").
fn tuto(name: &str) -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("tutos").join(name)
}

/// Run the CLI with `load <tuto>` piped on stdin.
/// Returns an error string listing every `✗` failure line, or `Ok(())` if clean.
fn run_tuto(name: &str) -> Result<(), String> {
    let bin = binary_path();
    let path = tuto(name);

    let mut child = Command::new(&bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("Failed to spawn {}: {}", bin.display(), e));

    // Send the `load` command followed by a newline so the REPL processes it.
    let stdin = child.stdin.as_mut().expect("Failed to open stdin");
    writeln!(stdin, "load {}", path.display()).expect("Failed to write to stdin");
    drop(child.stdin.take()); // close stdin so the REPL sees EOF and exits

    let output = child.wait_with_output().expect("Failed to wait on child");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Collect lines that start with the failure indicator.
    let failures: Vec<&str> = stdout
        .lines()
        .filter(|l| l.contains('✗'))
        .collect();

    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "Tutorial {} had {} unexpected failure(s):\n{}",
            name,
            failures.len(),
            failures.join("\n")
        ))
    }
}

// ── Individual tutorial tests ───────────────────────────────────────────────

#[test]
fn tutorial_01_basic_carve() {
    run_tuto("01-basic-carve.txt").unwrap();
}

#[test]
fn tutorial_02_basic_alias() {
    run_tuto("02-basic-alias.txt").unwrap();
}

#[test]
fn tutorial_03_basic_send() {
    run_tuto("03-basic-send.txt").unwrap();
}

#[test]
fn tutorial_04_basic_switch() {
    run_tuto("04-basic-switch.txt").unwrap();
}

#[test]
fn tutorial_05_basic_interrupts() {
    run_tuto("05-basic-interrupts.txt").unwrap();
}

#[test]
fn tutorial_06_cvm_virtio() {
    run_tuto("06-cvm-virtio.txt").unwrap();
}

#[test]
fn tutorial_07_nested_enclave() {
    run_tuto("07-nested-enclave.txt").unwrap();
}

#[test]
fn tutorial_08_sandbox() {
    run_tuto("08-sandbox.txt").unwrap();
}

#[test]
fn tutorial_09_encapsulation() {
    run_tuto("09-encapsulation.txt").unwrap();
}

#[test]
fn tutorial_10_pending_capabilities() {
    run_tuto("10-pending-capabilities.txt").unwrap();
}

#[test]
fn tutorial_11_sibling_attestation() {
    run_tuto("11-sibling-attestation.txt").unwrap();
}

#[test]
fn tutorial_12_meta_regions() {
    run_tuto("12-meta-regions.txt").unwrap();
}

#[test]
fn tutorial_13_driver_channels() {
    run_tuto("13-driver-channels.txt").unwrap();
}
