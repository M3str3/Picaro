//! <Technique name>.
//!
//! <One-line description.> See `README.md` for the full write-up.

use serde::{Deserialize, Serialize};

use super::{Capability, Stability, TechniqueDef};

/// Parameters for <technique name>.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    // TODO: add the technique's YAML parameters here, e.g.
    // #[serde(default = "default_target")]
    // pub target: String,
}

/// Static metadata for <technique name>.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "<technique_key>",
    attck: &["T0000.000"],
    stability: Stability::Experimental,
    requires: &[Capability::WindowsX64],
    conflicts: &[],
    doc_path: "src/techniques/<technique_key>/README.md",
    stub_fragment: include_str!("stub_fragment.rs"),
    params_example: "technique: <technique_key>\n",
    readme: include_str!("README.md"),
};

impl Params {
    /// Renders this technique's stub fragment for these parameters.
    pub fn render_fragment(&self) -> String {
        // TODO: substitute this technique's placeholders, e.g.
        // DEF.stub_fragment.replace("$PLACEHOLDER$", &value)
        DEF.stub_fragment.to_string()
    }
}

#[cfg(test)]
mod tests;
