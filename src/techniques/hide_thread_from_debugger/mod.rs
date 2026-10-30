//! Hide thread from debugger.
//!
//! Sets `ThreadHideFromDebugger` on the loader's main thread so it stops raising
//! debug events and an attached debugger is detached. A Preparation technique: it
//! modifies the process state and never runs the payload. See `README.md` for the
//! full write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for the thread-hiding preparation.
///
/// Deliberately parameterless: it hides the thread that runs it, which is the
/// loader's main thread — the one a debugger attaches to. Covering the loader's
/// other threads would need `OpenThread` on each, which is a different technique.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Params {}

/// Static metadata for the thread-hiding preparation.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "hide_thread_from_debugger",
    // T1622: debugger evasion.
    attck: &["T1622"],
    // Measured 2026-10-14 (Windows 11 26200): the call is accepted
    // (`STATUS_SUCCESS`; kernel32's `SetThreadInformation` refuses the class),
    // and under two debuggers the hidden thread's `int3` never reaches them
    // while the control build's does. Numbers: `docs/measurements.md`.
    stability: Stability::Stable,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &[],
    category: Category::Preparation,
    doc_path: "src/techniques/hide_thread_from_debugger/README.md",
    readme: include_str!("README.md"),
    stub_fragment: include_str!("stub_fragment.rs"),
    formats: &[],
    requires_indirect_syscalls: false,
    params_example: "technique: hide_thread_from_debugger\n",
    // Kernel32's `SetThreadInformation` rejects the class with
    // `ERROR_INVALID_PARAMETER` (measured), so the call goes through the syscall
    // layer's `NtSetInformationThread` helper.
    syscalls: &["NtSetInformationThread"],
    resolves_imports: false,
};

/// Runtime diagnostics the fragment can emit, as `(placeholder, plaintext)`
/// pairs.
///
/// `render_fragment` replaces each placeholder with code that rebuilds the
/// message at runtime, so no diagnostic text — and no technique keyword like
/// `loader` — lands in the generated stub's `.rdata`.
const MESSAGES: &[(&str, &str)] = &[(
    "$MSG_HIDE_FAILED$",
    "failed to hide the thread from the debugger",
)];

impl Params {
    /// Renders the thread-hiding stub fragment, obfuscating the diagnostic
    /// through `strings`.
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        let mut rendered = DEF.stub_fragment.to_string();
        for (index, (placeholder, text)) in MESSAGES.iter().enumerate() {
            rendered = rendered.replace(
                placeholder,
                &strings
                    .obfuscate(text)
                    .render_stub_expr(&format!("hide_msg_{index}")),
            );
        }
        rendered
    }
}

#[cfg(test)]
mod tests;
