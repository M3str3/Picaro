//! Vectored-exception execution.
//!
//! Runs the payload from a private RX region by redirecting a breakpoint raised
//! on the loader's own thread: a vectored exception handler swaps `Rip` for the
//! payload and a small trampoline returns to the loader. See `README.md` for the
//! full write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;
use crate::plan::schema::PayloadFormat;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for VEH execution: which payload to run (the payload format and
/// export live in the payload's `build.payloads` entry).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// Name of the payload in `build.payloads` to run. Optional when the plan
    /// declares exactly one payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
}

/// Static metadata for VEH execution.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "veh_execution",
    // T1106: the payload is entered from a system exception dispatch, not from
    // a dedicated thread. T1620: it runs from an in-process private allocation.
    attck: &["T1106", "T1620"],
    // The handler rewrites the AMD64 `CONTEXT`, and the trampoline is x64
    // assembly; the x86 form (a `ret N` emulation and a 32-bit context) is
    // future work.
    stability: Stability::Experimental,
    requires: &[Capability::WindowsX64],
    conflicts: &[],
    category: Category::Execution,
    doc_path: "src/techniques/veh_execution/README.md",
    stub_fragment: include_str!("stub_fragment.rs"),
    formats: &[super::PayloadFormat::Shellcode],
    requires_indirect_syscalls: false,
    params_example: "technique: veh_execution\n",
    readme: include_str!("README.md"),
    // The payload and its execution stack are allocated and the payload is
    // flipped to RX through the syscall layer.
    syscalls: &["NtAllocateVirtualMemory", "NtProtectVirtualMemory"],
    // Raw shellcode has no import table to resolve.
    resolves_imports: false,
};

/// Runtime diagnostics the fragment can emit, as `(placeholder, plaintext)`
/// pairs.
///
/// `render_fragment_for` replaces each placeholder with code that rebuilds the
/// message at runtime, so no diagnostic text — and no technique keyword — lands
/// in the generated stub's `.rdata`.
const MESSAGES: &[(&str, &str)] = &[
    ("$MSG_EMPTY$", "the payload is empty"),
    (
        "$MSG_ALLOC_FAILED$",
        "could not allocate the payload region",
    ),
    (
        "$MSG_PROTECT_FAILED$",
        "could not make the payload executable",
    ),
    (
        "$MSG_STACK_FAILED$",
        "could not allocate the execution stack",
    ),
    (
        "$MSG_HANDLER_FAILED$",
        "could not register the vectored exception handler",
    ),
    (
        "$MSG_NEVER_RAN$",
        "the vectored handler never entered the payload",
    ),
];

impl Params {
    /// Renders the VEH-execution stub fragment for these parameters.
    ///
    /// Every diagnostic is rebuilt from `strings`'s obfuscated bytes, and the
    /// payload-format guard is resolved here: the technique runs raw shellcode,
    /// so a `pe`/`dll`/`dotnet` payload gets a fragment that fails with a clear
    /// message instead of jumping into a file header.
    pub fn render_fragment_for(
        &self,
        strings: &StringsConfig,
        format: PayloadFormat,
        _export: Option<&str>,
    ) -> String {
        let unsupported_format = format!(
            "the veh_execution technique runs raw shellcode payloads only (this payload's format is '{}')",
            format.label()
        );

        // The trampoline and the trigger are global assembly symbols; two
        // `veh_execution` steps in one stub must not collide, so each render
        // gets a unique suffix.
        let suffix = rand::random::<u32>();
        let return_symbol = format!("veh_payload_return_{suffix:08x}");
        let trigger_symbol = format!("veh_trigger_{suffix:08x}");

        let mut rendered = DEF.stub_fragment.to_string();
        for (index, (placeholder, text)) in MESSAGES.iter().enumerate() {
            rendered = rendered.replace(
                placeholder,
                &strings
                    .obfuscate(text)
                    .render_stub_expr(&format!("veh_msg_{index}")),
            );
        }
        rendered
            .replace("$RETURN_SYMBOL$", &return_symbol)
            .replace("$TRIGGER_SYMBOL$", &trigger_symbol)
            .replace(
                "$SUPPORTED_FORMAT$",
                if format == PayloadFormat::Shellcode {
                    "true"
                } else {
                    "false"
                },
            )
            .replace(
                "$MSG_UNSUPPORTED_FORMAT$",
                &strings
                    .obfuscate(&unsupported_format)
                    .render_stub_expr("veh_unsupported"),
            )
    }
}

#[cfg(test)]
mod tests;
