fn main() {
    // Tell cargo to re-run this script only when the linker script changes.
    println!("cargo:rerun-if-changed=linker.ld");

    // Emit an absolute path so the linker finds it regardless of the working
    // directory from which `cargo build` is invoked.
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg=-T{manifest}/linker.ld");
}
