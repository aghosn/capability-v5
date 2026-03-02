//! Integration tests for CLI tutorials.
//!
//! Each test loads a fixture file from `tests/fixtures/` through the CLI's
//! `load` command and asserts that no command fails.  Expected-failure commands
//! (e.g., sending to a sealed domain without RECEIVE_AFTER_SEAL) are stripped
//! from the fixture files; only the commands that *should* succeed are present.
//!
//! Run with:  cargo test

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Return the path to the compiled binary.
fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_capability-cli"))
}

/// Return the absolute path to a fixture file given its base name (e.g. "04").
fn fixture(name: &str) -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("tests").join("fixtures").join(format!("{}.txt", name))
}

/// Run the CLI with `load <fixture>` piped on stdin.
/// Returns an error string listing every `✗` failure line, or `Ok(())` if clean.
fn run_fixture(name: &str) -> Result<(), String> {
    let bin = binary_path();
    let fix = fixture(name);

    let mut child = Command::new(&bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("Failed to spawn {}: {}", bin.display(), e));

    // Send the `load` command followed by a newline so the REPL processes it.
    let stdin = child.stdin.as_mut().expect("Failed to open stdin");
    writeln!(stdin, "load {}", fix.display()).expect("Failed to write to stdin");
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
    run_fixture("01").unwrap();
}

#[test]
fn tutorial_02_basic_alias() {
    run_fixture("02").unwrap();
}

#[test]
fn tutorial_03_basic_send() {
    run_fixture("03").unwrap();
}

#[test]
fn tutorial_04_basic_switch() {
    run_fixture("04").unwrap();
}

#[test]
fn tutorial_05_basic_interrupts() {
    run_fixture("05").unwrap();
}

#[test]
fn tutorial_06_cvm_virtio() {
    run_fixture("06").unwrap();
}

#[test]
fn tutorial_07_nested_enclave() {
    run_fixture("07").unwrap();
}

#[test]
fn tutorial_08_sandbox() {
    // Fixture omits the two expected-failure commands:
    //   • send extra_mem sandbox1   (sealed without RECEIVE_AFTER_SEAL)
    //   • attest sandbox1           (no ATTEST permission)
    run_fixture("08").unwrap();
}

#[test]
fn tutorial_10_pending_capabilities() {
    // Fixture omits the expected-failure command:
    //   • send extra1 strict   (sealed without RECEIVE_AFTER_SEAL)
    run_fixture("10").unwrap();
}
