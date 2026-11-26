fn main() {
    let linker = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../linker.ld");
    println!("cargo:rerun-if-changed={}", linker.display());
    println!("cargo:rustc-link-arg=-T{}", linker.display());
}
