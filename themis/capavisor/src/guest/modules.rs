//! Module discovery from the Limine boot protocol.
//!
//! Each module loaded by Limine is described by a [`limine::file::File`].
//! [`ModuleInfo`] extracts the fields Themis cares about (base address, size,
//! identifying tag) and [`find_module`] performs a name-based lookup against the
//! `module_cmdline` tags declared in `limine.conf`.

use core::ffi::CStr;

/// Compact description of a Limine-loaded module.
#[derive(Debug, Clone, Copy)]
pub struct ModuleInfo {
    /// Physical address where the module was loaded (via HHDM, so this is
    /// already a valid virtual pointer in the capavisor address space).
    pub base: *const u8,
    /// Size of the module in bytes.
    pub size: u64,
    /// The `module_cmdline` tag (e.g. `"dom0-kernel"`).  Empty if none was set.
    pub cmdline: &'static str,
    /// The path Limine used to locate the module on disk.
    #[allow(dead_code)]
    pub path: &'static str,
}

/// Extract [`ModuleInfo`] from a Limine [`File`](limine::file::File).
///
/// The `cmdline` and `path` are converted from C strings; if they contain
/// invalid UTF-8 the raw bytes are lossily replaced (should not happen in
/// practice since both are ASCII paths/tags set in `limine.conf`).
impl ModuleInfo {
    pub fn from_limine_file(file: &'static limine::file::File) -> Self {
        Self {
            base: file.addr(),
            size: file.size(),
            cmdline: cstr_to_str(file.string()),
            path: cstr_to_str(file.path()),
        }
    }
}

/// Search a slice of modules for one whose `cmdline` matches the given `name`
/// exactly (e.g. `"dom0-kernel"`).
pub fn find_module<'a>(modules: &'a [ModuleInfo], name: &str) -> Option<&'a ModuleInfo> {
    modules.iter().find(|m| m.cmdline == name)
}

/// Convert a `&CStr` to `&str`, falling back to `"<invalid-utf8>"` on error.
fn cstr_to_str(s: &CStr) -> &str {
    s.to_str().unwrap_or("<invalid-utf8>")
}
