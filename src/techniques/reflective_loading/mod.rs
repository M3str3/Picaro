//! Reflective loading.
//!
//! Maps a PE into the current process (manual mapping) and runs its entry
//! point, so the payload executes without an external target process and
//! without touching disk. See `README.md` for the full write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for reflective loading (none for now; args are a later phase).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {}

/// Static metadata for reflective loading.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "reflective_loading",
    attck: &["T1620"],
    stability: Stability::Experimental,
    requires: &[Capability::WindowsX64],
    conflicts: &["process_hollowing"],
    category: Category::Execution,
    doc_path: "src/techniques/reflective_loading/README.md",
    stub_fragment: include_str!("stub_fragment.rs"),
    params_example: "technique: reflective_loading\n",
    readme: include_str!("README.md"),
};

impl Params {
    /// Renders the reflective-loading stub fragment (no per-build parameters,
    /// so `strings` is unused here).
    pub fn render_fragment(&self, _strings: &StringsConfig) -> String {
        DEF.stub_fragment.to_string()
    }
}

#[cfg(test)]
mod tests;
