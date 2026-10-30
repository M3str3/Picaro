//! Erase PE header.
//!
//! Zeroes the loader image's in-memory PE header, so a memory scanner that
//! parses PE headers to find the module sees no DOS/NT headers at the base.
//! See `README.md` for the full write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for PE-header erasure.
///
/// The technique is deliberately parameterless: the target is always the
/// loader's own image (`GetModuleHandleA(NULL)`), and both the header offsets
/// (`e_lfanew` at `0x3C`, `SizeOfHeaders` at `e_lfanew + 0x54`) are fixed by the
/// PE format. A plan cannot point it at another module — a mapped image in
/// another process needs write access the loader does not have by default, so
/// that would be a different technique.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Params {}

/// Static metadata for PE-header erasure.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "erase_pe_header",
    attck: &["T1027"],
    // Measured on Windows 11 26200 (2026-10-14): the in-memory header loses its
    // signatures while the process keeps running and a following Execution step
    // still executes.
    stability: Stability::Stable,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &["sleep_obfuscation"],
    category: Category::Preparation,
    doc_path: "src/techniques/erase_pe_header/README.md",
    stub_fragment: include_str!("stub_fragment.rs"),
    formats: &[],
    requires_indirect_syscalls: false,
    params_example: "technique: erase_pe_header\n",
    readme: include_str!("README.md"),
    // Only the page-protection change is a kernel call; `GetModuleHandleA` stays
    // a loader entry point (like `LoadLibraryA` elsewhere), so `mode: indirect`
    // removes the `VirtualProtect` import.
    syscalls: &["NtProtectVirtualMemory"],
    resolves_imports: false,
};

/// Runtime diagnostics the fragment can emit, as `(placeholder, plaintext)`
/// pairs.
///
/// `render_fragment` replaces each placeholder with code that rebuilds the
/// message at runtime, so no diagnostic text — and no technique keyword — lands
/// in the generated stub's `.rdata`.
const MESSAGES: &[(&str, &str)] = &[
    (
        "$MSG_NO_IMAGE_BASE$",
        "erase_pe_header: could not read the loader's image base",
    ),
    (
        "$MSG_BAD_SIZE_OF_HEADERS$",
        "erase_pe_header: the loader's image size of headers is invalid",
    ),
    (
        "$MSG_PROTECT_FAILED$",
        "erase_pe_header: could not make the loader's header writable",
    ),
    (
        "$MSG_RESTORE_FAILED$",
        "erase_pe_header: could not restore the loader's header protection",
    ),
];

impl Params {
    /// Renders the PE-header-erasing stub fragment.
    ///
    /// The technique has no per-build parameters, so the only substitutions are
    /// the diagnostics: each is rebuilt at runtime with the active string
    /// strategy, so no message text appears in the generated stub's strings.
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        let mut rendered = DEF.stub_fragment.to_string();
        for (index, (placeholder, text)) in MESSAGES.iter().enumerate() {
            rendered = rendered.replace(
                placeholder,
                &strings
                    .obfuscate(text)
                    .render_stub_expr(&format!("erase_pe_header_msg_{index}")),
            );
        }
        rendered
    }
}

#[cfg(test)]
mod tests;
