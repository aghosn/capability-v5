use std::process::Command;

fn main() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let cli_dir = std::path::Path::new(manifest_dir).parent().unwrap();
    let script = cli_dir.join("scripts/diff-test.sh");
    let status = Command::new("bash")
        .arg(&script)
        .status()
        .expect("failed to run diff-test.sh");
    std::process::exit(status.code().unwrap_or(1));
}
