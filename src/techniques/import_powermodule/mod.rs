//! Import a PowerShell module into the caller's session.
//!
//! The `build.output.kind: psmodule` counterpart of `powershell_hosting`: instead
//! of running a `.ps1` in a loader's own process, the artifact is a managed
//! PowerShell **binary module** whose `OnImport` injects the embedded script into
//! the runspace that imported it — so `Import-Module .\x.dll` makes the tool's
//! functions available in the operator's `powershell.exe`. See `README.md`.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;

use super::{Capability, Category, PayloadFormat, Stability, TechniqueDef};

/// Parameters for importing a PowerShell module.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// Name of the payload in `build.payloads` to inject. Optional when the plan
    /// declares exactly one payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
}

/// Static metadata for importing a PowerShell module.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "import_powermodule",
    attck: &["T1059.001", "T1620"],
    // Measured on the lab host (2026-10-11): the module imports into a fresh
    // `powershell.exe -NoProfile` and the script's functions land in the
    // session. Not `Stable` because the `.dll` itself is on disk (README) and
    // the module is a `kind: psmodule` output, which no host matrix has covered
    // beyond PowerShell 5.1.
    stability: Stability::Experimental,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &[],
    category: Category::Execution,
    doc_path: "src/techniques/import_powermodule/README.md",
    stub_fragment: include_str!("stub_fragment.rs"),
    formats: &[PayloadFormat::Powershell],
    requires_indirect_syscalls: false,
    params_example: "technique: import_powermodule\n",
    readme: include_str!("README.md"),
    // A `kind: psmodule` build runs in the host's CLR; the fragment issues no
    // Nt* call.
    syscalls: &[],
    resolves_imports: false,
};

/// Runtime diagnostic the placeholder Rust fragment can emit.
const MESSAGES: &[(&str, &str)] = &[(
    "$MSG_PSMODULE_ONLY$",
    "import_powermodule runs only in a 'kind: psmodule' build",
)];

impl Params {
    /// Renders the placeholder Rust fragment (see `stub_fragment.rs`).
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        let mut rendered = DEF.stub_fragment.to_string();
        for (index, (placeholder, text)) in MESSAGES.iter().enumerate() {
            rendered = rendered.replace(
                placeholder,
                &strings
                    .obfuscate(text)
                    .render_stub_expr(&format!("msg_{index}")),
            );
        }
        rendered
    }
}

#[cfg(test)]
mod tests;
