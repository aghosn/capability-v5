// Build script for capa-cli.
// When the `lean-backend` feature is enabled, compiles the C FFI wrapper
// and links against the Lean-compiled object files + Lean runtime.

#[cfg(feature = "lean-backend")]
use std::path::{Path, PathBuf};

fn main() {
    #[cfg(feature = "lean-backend")]
    build_lean_ffi();
}

#[cfg(feature = "lean-backend")]
fn build_lean_ffi() {

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let repo_root = Path::new(&manifest_dir).parent().unwrap();

    // Find Lean toolchain
    let home = std::env::var("HOME").unwrap();
    let lean_toolchain = find_lean_toolchain(&home, repo_root);
    let lean_include = lean_toolchain.join("include");
    let lean_lib = lean_toolchain.join("lib");
    let lean_lib_lean = lean_lib.join("lean");

    // Collect Lean-compiled object files (excluding Main.c.o.export to avoid
    // duplicate `main` symbols)
    let lean_exec_build = repo_root.join("lean-exec/.lake/build/ir");
    let lean_proof_build = repo_root.join("lean/.lake/build/ir");

    let mut objects: Vec<PathBuf> = Vec::new();

    // lean-exec objects
    collect_objects(&lean_exec_build, &mut objects);
    // ThemisCapa proof model objects
    collect_objects(&lean_proof_build, &mut objects);

    // Filter out Main.c.o.export files (they contain main())
    objects.retain(|p| {
        let fname = p.file_name().unwrap().to_str().unwrap();
        fname != "Main.c.o.export"
    });

    if objects.is_empty() {
        panic!(
            "No Lean object files found. Run `cd lean-exec && lake build` first.\n\
             Expected files in: {}",
            lean_exec_build.display()
        );
    }

    // Compile the C wrapper
    cc::Build::new()
        .file(Path::new(&manifest_dir).join("lean_ffi/lean_wrapper.c"))
        .include(&lean_include)
        .flag("-fPIC")
        .flag("-O2")
        .define("NDEBUG", None)
        .flag("-Wno-unused-parameter")
        .compile("lean_wrapper");

    // Create a static archive from all Lean objects
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let archive_path = Path::new(&out_dir).join("liblean_exec_objs.a");
    let mut ar_cmd = std::process::Command::new("ar");
    ar_cmd.arg("rcs").arg(&archive_path);
    for obj in &objects {
        ar_cmd.arg(obj);
    }
    let status = ar_cmd.status().expect("Failed to run ar");
    if !status.success() {
        panic!("ar failed to create archive");
    }

    // Link everything
    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static=lean_exec_objs");

    // Lean runtime libraries (order matters due to dependencies)
    println!(
        "cargo:rustc-link-search=native={}",
        lean_lib_lean.display()
    );
    println!("cargo:rustc-link-search=native={}", lean_lib.display());

    // Static Lean runtime libs
    println!("cargo:rustc-link-lib=static=leancpp");
    println!("cargo:rustc-link-lib=static=Lean");
    println!("cargo:rustc-link-lib=static=Std");
    println!("cargo:rustc-link-lib=static=Init");
    println!("cargo:rustc-link-lib=static=leanrt");

    // Bundled dependencies from Lean toolchain
    println!("cargo:rustc-link-lib=static=gmp");
    println!("cargo:rustc-link-lib=static=uv");
    println!("cargo:rustc-link-lib=static=unwind");

    // Lean bundles its own libc++ and libc++abi
    let libcxx = lean_lib.join("libc++.a");
    let _libcxxabi = lean_lib.join("libc++abi.a");
    if libcxx.exists() {
        println!("cargo:rustc-link-lib=static:+whole-archive=c++");
        println!("cargo:rustc-link-lib=static:+whole-archive=c++abi");
    }

    // System libraries
    println!("cargo:rustc-link-lib=dylib=pthread");
    println!("cargo:rustc-link-lib=dylib=dl");
    println!("cargo:rustc-link-lib=dylib=rt");
    println!("cargo:rustc-link-lib=dylib=m");

    // Re-run if lean objects change
    println!("cargo:rerun-if-changed=lean_ffi/lean_wrapper.c");
    println!("cargo:rerun-if-changed=lean_ffi/lean_wrapper.h");
    for obj in &objects {
        println!("cargo:rerun-if-changed={}", obj.display());
    }
}

#[cfg(feature = "lean-backend")]
fn find_lean_toolchain(home: &str, repo_root: &Path) -> PathBuf {
    // Read lean-toolchain from lean-exec/ to determine version
    let toolchain_file = repo_root.join("lean-exec/lean-toolchain");
    let version = if toolchain_file.exists() {
        let content = std::fs::read_to_string(&toolchain_file).unwrap();
        let content = content.trim();
        // Format: "leanprover/lean4:v4.29.0" or just "leanprover--lean4---v4.29.0"
        if content.contains(':') {
            let parts: Vec<&str> = content.split(':').collect();
            // "leanprover/lean4:v4.29.0" → folder "leanprover--lean4---v4.29.0"
            let org_repo = parts[0].replace('/', "--");
            let ver = parts[1];
            format!("{}---{}", org_repo, ver)
        } else {
            content.to_string()
        }
    } else {
        // Fallback: find first available toolchain
        "leanprover--lean4---v4.29.0".to_string()
    };

    let toolchain_dir = PathBuf::from(home)
        .join(".elan/toolchains")
        .join(&version);

    if !toolchain_dir.exists() {
        panic!(
            "Lean toolchain not found at: {}\n\
             Install it with: elan toolchain install {}",
            toolchain_dir.display(),
            version
        );
    }
    toolchain_dir
}

#[cfg(feature = "lean-backend")]
fn collect_objects(dir: &Path, out: &mut Vec<PathBuf>) {
    if !dir.exists() {
        return;
    }
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            collect_objects(&path, out);
        } else if path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(".c.o.export")
        {
            out.push(path);
        }
    }
}
