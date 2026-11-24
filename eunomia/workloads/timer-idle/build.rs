fn main() {
    let eunomia = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../linker.ld");
    println!("cargo:rerun-if-changed={}", eunomia.display());
    println!("cargo:rustc-link-arg=-T{}", eunomia.display());
}
