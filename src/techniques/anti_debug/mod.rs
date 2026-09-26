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
    requires: &[Capability::WindowsX64],
    conflicts: &[],
    category: Category::Preparation,
    doc_path: "src/techniques/anti_debug/README.md",
    readme: include_str!("README.md"),
    stub_fragment: include_str!("stub_fragment.rs"),
    params_example: "technique: anti_debug\nparams:\n  action: abort\n",
    // The checks use IsDebuggerPresent/CheckRemoteDebuggerPresent/GetThreadContext
    // directly; routing them through NtQueryInformationProcess is a later phase.
    syscalls: &[],
    resolves_imports: false,
};

impl Params {
    /// Renders the anti-debug stub fragment, baking in whether a detection
    /// aborts the preparation.
    pub fn render_fragment(&self, _strings: &StringsConfig) -> String {
        let abort = match self.action {
            Action::Abort => "true",
            Action::Continue => "false",
        };
        DEF.stub_fragment.replace("$ABORT_ON_DETECT$", abort)
    }
}

#[cfg(test)]
mod tests;
