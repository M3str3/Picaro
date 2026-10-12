//! Anti-debug.
//!
//! Detects a debugger attached to (or watching) the current process and, by
//! default, aborts the preparation so the payload never runs. A Preparation
//! technique: it never runs the payload. See `README.md` for the full write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;

use super::{Capability, Category, Stability, TechniqueDef};

/// What the technique does when a debugger is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Fail the preparation so the payload never runs (default).
    Abort,
    /// Note the detection and continue (useful while debugging the stub).
    Continue,
}

/// Parameters for the anti-debug preparation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// Behaviour on detection.
    #[serde(default = "default_action")]
    pub action: Action,
}

/// Default for [`Params::action`]: abort on detection.
pub fn default_action() -> Action {
    Action::Abort
}

impl Default for Params {
    /// Defaults to aborting on detection (see [`default_action`]).
    fn default() -> Self {
        Self {
            action: default_action(),
        }
    }
}

/// Static metadata for the anti-debug preparation.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "anti_debug",
    attck: &["T1622"],
    stability: Stability::Stable,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &[],
    category: Category::Preparation,
    doc_path: "src/techniques/anti_debug/README.md",
    readme: include_str!("README.md"),
    stub_fragment: include_str!("stub_fragment.rs"),
    formats: &[],
    requires_indirect_syscalls: false,
    params_example: "technique: anti_debug\nparams:\n  action: abort\n",
    // The debug-port / debug-object checks use NtQueryInformationProcess and the
    // hardware-breakpoint check uses NtGetContextThread, so `mode: indirect`
    // removes the IsDebuggerPresent/CheckRemoteDebuggerPresent/GetThreadContext
    // imports.
    syscalls: &["NtQueryInformationProcess", "NtGetContextThread"],
    resolves_imports: false,
};

/// Runtime diagnostics the fragment can emit, as `(placeholder, plaintext)`
/// pairs.
///
/// `render_fragment` replaces each placeholder with code that rebuilds the
/// message at runtime, so no diagnostic text — least of all a technique keyword
/// like `loader` — lands in the generated stub's `.rdata`.
const MESSAGES: &[(&str, &str)] = &[("$MSG_DEBUGGER_DETECTED$", "a debugger was detected")];

impl Params {
    /// Renders the anti-debug stub fragment, baking in whether a detection
    /// aborts the preparation.
    ///
    /// The detection error is rebuilt from `strings`'s obfuscated bytes, so no
    /// diagnostic text reaches the generated stub's `.rdata`.
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        let abort = match self.action {
            Action::Abort => "true",
            Action::Continue => "false",
        };
        let mut rendered = DEF.stub_fragment.replace("$ABORT_ON_DETECT$", abort);
        for (index, (placeholder, text)) in MESSAGES.iter().enumerate() {
            rendered = rendered.replace(
                placeholder,
                &strings
                    .obfuscate(text)
                    .render_stub_expr(&format!("anti_debug_msg_{index}")),
            );
        }
        rendered
    }
}

#[cfg(test)]
mod tests;
