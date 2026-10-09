//! Guardrail (T1480): a killswitch / gate.
//!
//! Aborts the runtime before the payload runs when a deadline has passed or a
//! run-count has been exceeded. A Preparation technique: it never runs the
//! payload, it only decides whether the chain continues. See `README.md` for
//! the full write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;

use super::{Capability, Category, Stability, TechniqueDef};

/// Parameters for the guardrail technique.
///
/// Both gates are optional; a plan that sets neither is a no-op (the gate
/// always lets the payload run), which `plan::validate::advisories` surfaces.
/// The registry is deliberately avoided (the counter is a file under the
/// per-user temporary directory instead), so `run_key` is repurposed as the
/// file name while keeping its original "value name" wording.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// ISO date (YYYY-MM-DD) after which the payload must not run. None = no date gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expire_on: Option<String>,
    /// Maximum number of times the loader may run. None = no run-count gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_runs: Option<u32>,
    /// Registry value name under `HKCU\Software\picaro` used to persist the run counter.
    #[serde(default = "default_run_key")]
    pub run_key: String,
}

/// Default for [`Params::run_key`]: the counter file name under the temporary
/// directory.
pub fn default_run_key() -> String {
    "runs".to_string()
}

impl Default for Params {
    fn default() -> Self {
        Self {
            expire_on: None,
            max_runs: None,
            run_key: default_run_key(),
        }
    }
}

/// Static metadata for the guardrail technique.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "guardrail",
    attck: &["T1480"],
    stability: Stability::Stable,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &[],
    category: Category::Preparation,
    doc_path: "src/techniques/guardrail/README.md",
    readme: include_str!("README.md"),
    stub_fragment: include_str!("stub_fragment.rs"),
    formats: &[],
    requires_indirect_syscalls: false,
    params_example: "technique: guardrail\nparams:\n  expire_on: \"2027-01-01\"\n  max_runs: 3\n",
    // The fragment uses only the standard library (clock, environment, file
    // I/O); no syscall and no payload import resolution are involved.
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
const MESSAGES: &[(&str, &str)] = &[
    ("$MSG_DATE_FAILED$", "could not read the current date"),
    (
        "$MSG_COUNTER_READ_FAILED$",
        "could not read the run counter",
    ),
    (
        "$MSG_COUNTER_WRITE_FAILED$",
        "could not write the run counter",
    ),
    ("$MSG_COUNTER_CORRUPT$", "the run counter is not a number"),
];

impl Params {
    /// Renders the guardrail stub fragment for these parameters.
    ///
    /// The per-build deadline, the counter file name and every diagnostic are
    /// emitted as code that rebuilds the value at runtime through `strings`, so
    /// none of them appears in the generated stub in cleartext.
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        let expire_on = match self.expire_on.as_deref() {
            Some(date) => format!(
                "Some({})",
                strings
                    .obfuscate(date)
                    .render_stub_expr("guardrail_expire_on")
            ),
            None => "None".to_string(),
        };
        let max_runs = match self.max_runs {
            Some(n) => format!("Some({n}u32)"),
            None => "None".to_string(),
        };
        let run_key = strings
            .obfuscate(&self.run_key)
            .render_stub_expr("guardrail_run_key");

        let mut rendered = DEF
            .stub_fragment
            .replace("$EXPIRE_ON_DEF$", &expire_on)
            .replace("$MAX_RUNS_DEF$", &max_runs)
            .replace("$RUN_KEY_DEF$", &run_key);
        for (index, (placeholder, text)) in MESSAGES.iter().enumerate() {
            rendered = rendered.replace(
                placeholder,
                &strings
                    .obfuscate(text)
                    .render_stub_expr(&format!("guardrail_msg_{index}")),
            );
        }
        rendered
    }
}

#[cfg(test)]
mod tests;
