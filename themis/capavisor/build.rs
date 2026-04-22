fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let direct_boot = std::env::var("CARGO_FEATURE_DIRECT_BOOT").is_ok();

    let linker_script = match arch.as_str() {
        "aarch64" if direct_boot => "linker-aarch64-direct.ld",
        "aarch64" => "linker-aarch64.ld",
        _ => "linker.ld",
    };

    println!("cargo:rerun-if-changed={linker_script}");
    println!("cargo:rustc-link-arg=-T{manifest}/{linker_script}");
}
