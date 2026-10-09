//! Sleep (control technique).
//!
//! Waits for a fixed duration between stages. A Control technique: it neither
//! modifies the process state nor runs the payload, it only paces the chain.
//! See `README.md` for the full write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for the sleep technique.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// Milliseconds to wait.
    #[serde(default = "default_ms")]
    pub ms: u64,
}

/// Default for [`Params::ms`]: one second.
pub fn default_ms() -> u64 {
    1000
}

impl Default for Params {
    fn default() -> Self {
        Self { ms: default_ms() }
    }
}

/// Static metadata for the sleep technique.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "sleep",
    // A pause is not an ATT&CK technique of its own; T1497 (Virtualization /
    // Sandbox Evasion) covers the timing-based evasion a deliberate delay is
    // usually part of. The registry requires a non-empty list.
    attck: &["T1497"],
    stability: Stability::Stable,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &[],
    category: Category::Control,
    doc_path: "src/techniques/sleep/README.md",
    stub_fragment: include_str!("stub_fragment.rs"),
    formats: &[],
    requires_indirect_syscalls: false,
    params_example: "technique: sleep\nparams:\n  ms: 1000\n",
    readme: include_str!("README.md"),
    syscalls: &[],
    resolves_imports: false,
};

impl Params {
    /// Renders the sleep fragment with the configured duration substituted.
    ///
    /// The technique holds no per-build literal, so `strings` is unused; the
    /// parameter is kept to match the other techniques' render signature.
    pub fn render_fragment(&self, _strings: &StringsConfig) -> String {
        DEF.stub_fragment.replace("$MS$", &self.ms.to_string())
    }
}

#[cfg(test)]
mod tests;
