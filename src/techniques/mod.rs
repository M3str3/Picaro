//! Technique registry.
//!
//! Every evasion/execution technique lives in its own subdirectory (e.g.
//! [`process_hollowing`]) and is registered in [`all`]. The registry is pure
//! metadata: it feeds the `packerman techniques` CLI, the `validate` CI check
//! and the stub renderer. How to add a technique is documented in
//! `src/techniques/README.md`.

pub mod patch_amsi;
pub mod process_hollowing;
pub mod reflective_loading;

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;
use crate::error::{PackerError, Result};

/// One step of the `pipeline` in the YAML config.
///
/// Internally-tagged enum: each technique carries its own parameters as extra
/// keys in the same YAML object (`technique: <name>` + the technique's fields).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "technique", rename_all = "snake_case")]
pub enum PipelineStep {
    /// Patch AmsiScanBuffer in the current process (preparation).
    PatchAmsi(patch_amsi::Params),
    /// Process hollowing: run the payload inside a suspended, legitimate
    /// process instead of on disk.
    ProcessHollowing(process_hollowing::Params),
    /// Reflective loading: map the payload into the current process and run
    /// its entry point.
    ReflectiveLoading(reflective_loading::Params),
}

impl PipelineStep {
    /// Renders the technique's stub fragment for this step's parameters.
    ///
    /// `strings` is the active string-obfuscation configuration, used to
    /// obfuscate any per-build string literal (e.g. the hollowing target). The
    /// result is injected verbatim into the generated stub (see `engine::stub`).
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        match self {
            PipelineStep::PatchAmsi(params) => params.render_fragment(strings),
            PipelineStep::ProcessHollowing(params) => params.render_fragment(strings),
            PipelineStep::ReflectiveLoading(params) => params.render_fragment(strings),
        }
    }

    /// The technique's YAML key (used by semantic validation).
    pub fn name(&self) -> &'static str {
        match self {
            PipelineStep::PatchAmsi(_) => patch_amsi::DEF.name,
            PipelineStep::ProcessHollowing(_) => process_hollowing::DEF.name,
            PipelineStep::ReflectiveLoading(_) => reflective_loading::DEF.name,
        }
    }

    /// The technique's [`Category`] (Preparation vs Execution).
    pub fn category(&self) -> Category {
        match self {
            PipelineStep::PatchAmsi(_) => Category::Preparation,
            PipelineStep::ProcessHollowing(_) => Category::Execution,
            PipelineStep::ReflectiveLoading(_) => Category::Execution,
        }
    }
}

/// Which role a technique plays in the pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// Modifies the current process state (e.g. patches AMSI) but never runs
    /// the payload.
    Preparation,
    /// Executes the decrypted payload.
    Execution,
}

impl Category {
    /// Lowercase label used by `packerman techniques list`.
    pub fn label(self) -> &'static str {
        match self {
            Category::Preparation => "preparation",
            Category::Execution => "execution",
        }
    }
}

/// Maturity of a technique.
///
/// Variants are part of the metadata vocabulary; only the ones used by the
/// currently-registered techniques are constructed.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stability {
    Stable,
    Experimental,
    Deprecated,
}

impl Stability {
    /// Lowercase label used by `packerman techniques list`.
    pub fn label(self) -> &'static str {
        match self {
            Stability::Stable => "stable",
            Stability::Experimental => "experimental",
            Stability::Deprecated => "deprecated",
        }
    }
}

/// A capability the build host must provide for a technique.
///
/// Variants are part of the metadata vocabulary; only the ones used by the
/// currently-registered techniques are constructed.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    WindowsX64,
    KernelAccess,
    AdminRequired,
}

/// Static metadata describing one technique.
///
/// No logic here — only data consumed by the `techniques` CLI, the `validate`
/// check and the stub renderer.
pub struct TechniqueDef {
    /// YAML key (`technique: <name>`).
    pub name: &'static str,
    /// MITRE ATT&CK technique IDs.
    pub attck: &'static [&'static str],
    /// Maturity.
    pub stability: Stability,
    /// Capabilities the build host must provide.
    pub requires: &'static [Capability],
    /// Names of techniques this one conflicts with.
    pub conflicts: &'static [&'static str],
    /// Pipeline role: Preparation (modifies state) or Execution (runs payload).
    pub category: Category,
    /// Path to the human-readable README (relative to the repo root).
    pub doc_path: &'static str,
    /// The technique's stub fragment source (embedded via `include_str!`).
    pub stub_fragment: &'static str,
    /// A YAML snippet (parseable as a [`PipelineStep`]) documenting the params.
    pub params_example: &'static str,
    /// The technique's README, embedded via `include_str!` for `techniques show`.
    pub readme: &'static str,
}

/// All registered techniques.
pub fn all() -> &'static [TechniqueDef] {
    &[
        process_hollowing::DEF,
        reflective_loading::DEF,
        patch_amsi::DEF,
    ]
}

/// Looks up a technique by its YAML key.
pub fn find(name: &str) -> Option<&'static TechniqueDef> {
    all().iter().find(|def| def.name == name)
}

/// Returns the [`Category`] of the technique with the given YAML key, if it is
/// registered. Used by pipeline validation.
pub fn category_of(name: &str) -> Option<Category> {
    find(name).map(|def| def.category)
}

/// Section headings every technique README must contain (see
/// `_template/README.md`).
const REQUIRED_SECTIONS: &[&str] = &[
    "## Metadata",
    "## What it does",
    "## YAML parameters",
    "## YAML example",
    "## How it works",
    "## What it evades",
    "## What detects it",
    "## Measurements",
    "## Implementation notes",
    "## References",
];

/// Renders the `packerman techniques list` output (no colors).
pub fn list() -> String {
    let mut out = String::new();
    for def in all() {
        let attck = def.attck.join(", ");
        let summary = short_description(def.readme);
        out.push_str(&format!(
            "{:<18} {:<12} {:<12} {:<12} {}\n",
            def.name,
            def.category.label(),
            def.stability.label(),
            attck,
            summary
        ));
    }
    out
}

/// Returns the README of `name` for `packerman techniques show`.
pub fn show(name: &str) -> Result<String> {
    find(name)
        .map(|def| def.readme.to_string())
        .ok_or_else(|| PackerError::Validation(format!("unknown technique '{name}'")))
}

/// Validates the registry. Returns a list of problems; empty means all good.
///
/// This is a CI helper: it reports failures as warnings without failing.
pub fn validate() -> Vec<String> {
    let mut problems = Vec::new();
    for def in all() {
        // Registered in `all()` ⇒ its `mod.rs` exists and defines a `DEF`.
        if def.name.trim().is_empty() {
            problems.push("technique with an empty name".to_string());
        }

        if def.attck.is_empty() {
            problems.push(format!("{}: 'attck' must not be empty", def.name));
        }

        if def.requires.is_empty() {
            problems.push(format!("{}: 'requires' must not be empty", def.name));
        }

        if def.conflicts.contains(&def.name) {
            problems.push(format!("{}: conflicts with itself", def.name));
        }

        // `doc_path` must point to an existing file.
        let readme_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(def.doc_path);
        if !readme_path.is_file() {
            problems.push(format!(
                "{}: doc_path does not exist: {}",
                def.name, def.doc_path
            ));
        }

        // `params_example` must parse as a pipeline step.
        if serde_yml::from_str::<PipelineStep>(def.params_example).is_err() {
            problems.push(format!("{}: params_example does not parse", def.name));
        }

        if def.stub_fragment.trim().is_empty() {
            problems.push(format!("{}: stub_fragment.rs is empty", def.name));
        }

        let mut title_seen = false;
        if let Some(first) = def.readme.lines().next() {
            title_seen = first.starts_with("# ");
        }
        if !title_seen {
            problems.push(format!("{}: README.md has no '#' title", def.name));
        }
        for section in REQUIRED_SECTIONS {
            if !def.readme.contains(section) {
                problems.push(format!(
                    "{}: README.md missing section '{section}'",
                    def.name
                ));
            }
        }

        let tests_path = tests_path(def);
        match std::fs::read_to_string(&tests_path) {
            Ok(content) if content.contains("#[test]") => {}
            Ok(_) => problems.push(format!("{}: tests.rs has no #[test]", def.name)),
            Err(_) => problems.push(format!(
                "{}: tests.rs not found at '{}'",
                def.name,
                tests_path.display()
            )),
        }
    }
    problems
}

/// The `tests.rs` path of a technique (used by `validate`).
fn tests_path(def: &TechniqueDef) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("techniques")
        .join(def.name)
        .join("tests.rs")
}

/// Extracts the one-line summary of a technique README (the first non-empty
/// line under `## What it does`).
fn short_description(readme: &str) -> &str {
    let marker = "## What it does";
    let start = readme.find(marker).map(|i| i + marker.len()).unwrap_or(0);
    for line in readme[start..].lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            return trimmed;
        }
    }
    ""
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_non_empty_and_well_formed() {
        assert!(
            !all().is_empty(),
            "at least one technique must be registered"
        );
        for def in all() {
            assert!(!def.name.is_empty(), "technique name must not be empty");
            assert!(!def.doc_path.is_empty(), "doc_path must not be empty");

            // The README referenced by doc_path must exist on disk.
            let readme_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(def.doc_path);
            assert!(
                readme_path.is_file(),
                "doc_path does not exist: {}",
                readme_path.display()
            );
        }
    }

    #[test]
    fn every_technique_has_a_parseable_yaml_example() {
        for def in all() {
            let step: PipelineStep = serde_yml::from_str(def.params_example)
                .unwrap_or_else(|e| panic!("{} params_example does not parse: {e}", def.name));
            let round_tripped = serde_yml::to_string(&step).expect("serialize PipelineStep");
            assert!(
                !round_tripped.trim().is_empty(),
                "{} params_example must serialize",
                def.name
            );
        }
    }

    #[test]
    fn find_returns_registered_technique() {
        assert!(find("process_hollowing").is_some());
        assert!(find("does_not_exist").is_none());
    }

    #[test]
    fn category_of_reports_preparation_and_execution() {
        assert_eq!(category_of("patch_amsi"), Some(Category::Preparation));
        assert_eq!(category_of("process_hollowing"), Some(Category::Execution));
        assert_eq!(category_of("reflective_loading"), Some(Category::Execution));
        assert_eq!(category_of("does_not_exist"), None);
    }

    #[test]
    fn list_includes_process_hollowing() {
        let output = list();
        assert!(
            output.contains("process_hollowing"),
            "list output: {output}"
        );
        assert!(output.contains("execution"), "list output: {output}");
        assert!(output.contains("preparation"), "list output: {output}");
    }

    #[test]
    fn show_returns_readme() {
        let readme = show("process_hollowing").expect("known technique");
        assert!(readme.contains("# Process hollowing"));
    }
}
