//! Technique registry.
//!
//! Every evasion/execution technique lives in its own subdirectory (e.g.
//! [`process_hollowing`]) and is registered in [`all`]. The registry is pure
//! metadata: it feeds the `batesian techniques` CLI, the `validate` CI check
//! and the stub renderer. How to add a technique is documented in
//! `src/techniques/README.md`.

pub mod anti_debug;
pub mod patch_amsi;
pub mod patch_etw;
pub mod process_hollowing;
pub mod reflective_loading;

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;
use crate::error::{PackerError, Result};
use crate::ui::{glyph, Palette};

/// One step of the `runtime` list in the YAML config.
///
/// Internally-tagged enum: each technique carries its own parameters as extra
/// keys in the same YAML object (`technique: <name>` + the technique's fields).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "technique", rename_all = "snake_case")]
pub enum RuntimeStep {
    /// Detect a debugger in the current process, aborting by default
    /// (preparation).
    AntiDebug(anti_debug::Params),
    /// Patch AmsiScanBuffer in the current process (preparation).
    PatchAmsi(patch_amsi::Params),
    /// Patch the ETW event-writing exports in the current process
    /// (preparation).
    PatchEtw(patch_etw::Params),
    /// Process hollowing: run the payload inside a suspended, legitimate
    /// process instead of on disk.
    ProcessHollowing(process_hollowing::Params),
    /// Reflective loading: map the payload into the current process and run
    /// its entry point.
    ReflectiveLoading(reflective_loading::Params),
}

impl RuntimeStep {
    /// Renders the technique's stub fragment for this step's parameters.
    ///
    /// `strings` is the active string-obfuscation configuration, used to
    /// obfuscate any per-build string literal (e.g. the hollowing target). The
    /// result is injected verbatim into the generated stub (see `engine::stub`).
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        match self {
            RuntimeStep::AntiDebug(params) => params.render_fragment(strings),
            RuntimeStep::PatchAmsi(params) => params.render_fragment(strings),
            RuntimeStep::PatchEtw(params) => params.render_fragment(strings),
            RuntimeStep::ProcessHollowing(params) => params.render_fragment(strings),
            RuntimeStep::ReflectiveLoading(params) => params.render_fragment(strings),
        }
    }

    /// The technique's YAML key (used by semantic validation).
    pub fn name(&self) -> &'static str {
        match self {
            RuntimeStep::AntiDebug(_) => anti_debug::DEF.name,
            RuntimeStep::PatchAmsi(_) => patch_amsi::DEF.name,
            RuntimeStep::PatchEtw(_) => patch_etw::DEF.name,
            RuntimeStep::ProcessHollowing(_) => process_hollowing::DEF.name,
            RuntimeStep::ReflectiveLoading(_) => reflective_loading::DEF.name,
        }
    }

    /// The technique's [`Category`] (Preparation vs Execution).
    pub fn category(&self) -> Category {
        match self {
            RuntimeStep::AntiDebug(_) => Category::Preparation,
            RuntimeStep::PatchAmsi(_) => Category::Preparation,
            RuntimeStep::PatchEtw(_) => Category::Preparation,
            RuntimeStep::ProcessHollowing(_) => Category::Execution,
            RuntimeStep::ReflectiveLoading(_) => Category::Execution,
        }
    }
}

/// Which role a technique plays in the pipeline.
///
/// Variant order is meaningful: it defines the sort key used by
/// [`list`] (Preparation before Execution).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Category {
    /// Modifies the current process state (e.g. patches AMSI) but never runs
    /// the payload.
    Preparation,
    /// Executes the decrypted payload.
    Execution,
}

impl Category {
    /// Lowercase label used by `batesian techniques list`.
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
///
/// Variant order is meaningful: it defines the sort key used by [`list`]
/// (Stable before Experimental before Deprecated).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stability {
    Stable,
    Experimental,
    Deprecated,
}

impl Stability {
    /// Lowercase label used by `batesian techniques list`.
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
    /// A YAML snippet (parseable as a [`RuntimeStep`]) documenting the params.
    pub params_example: &'static str,
    /// The technique's README, embedded via `include_str!` for `techniques show`.
    pub readme: &'static str,
    /// Nt* functions this technique invokes through the syscall layer when
    /// `build.stub.syscalls.mode: indirect` is active. The packer resolves only
    /// the union of the active techniques' requirements (see
    /// `engine::syscalls::required`).
    pub syscalls: &'static [&'static str],
    /// Whether the technique needs the shared payload import resolver
    /// (`engine::imports`) rendered into the stub. The resolver is emitted only
    /// when an active technique declares it, so no unused code is injected.
    pub resolves_imports: bool,
}

/// All registered techniques.
pub fn all() -> &'static [TechniqueDef] {
    &[
        process_hollowing::DEF,
        reflective_loading::DEF,
        patch_amsi::DEF,
        anti_debug::DEF,
        patch_etw::DEF,
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

/// Renders the `batesian techniques list` output.
pub fn list(ui: &Palette) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{} {} {} {} {}\n",
        // Pad before styling: applying the width to an already-colored string
        // would count the escape codes and misalign the header against the rows.
        ui.dim(format!("{:<18}", "TECHNIQUE")),
        ui.dim(format!("{:<12}", "CATEGORY")),
        ui.dim(format!("{:<12}", "STABILITY")),
        ui.dim(format!("{:<16}", "ATT&CK")),
        ui.dim("SUMMARY"),
    ));
    // Grouped by category, then maturity, then name: the listing reads as a
    // pipeline (Preparation before Execution) with the most reliable entries
    // first inside each group.
    let mut defs: Vec<&TechniqueDef> = all().iter().collect();
    defs.sort_by_key(|def| (def.category, def.stability, def.name));
    for def in defs {
        out.push_str(&format!(
            "{} {:<12} {} {:<16} {}\n",
            ui.bold(format!("{:<18}", def.name)),
            def.category.label(),
            stability_label(def, ui),
            def.attck.join(", "),
            truncate(short_description(def.readme), 70),
        ));
    }

    let executions = all()
        .iter()
        .filter(|d| d.category == Category::Execution)
        .count();
    out.push_str(&format!(
        "\n{} {}\n",
        glyph::DOT,
        ui.dim(format!(
            "{} techniques ({} preparation, {} execution)",
            all().len(),
            all().len() - executions,
            executions
        ))
    ));
    out
}

/// The technique's stability label, padded and colored by maturity.
fn stability_label(def: &TechniqueDef, ui: &Palette) -> String {
    let label = format!("{:<12}", def.stability.label());
    match def.stability {
        Stability::Stable => ui.ok(label),
        Stability::Experimental => ui.warn(label),
        Stability::Deprecated => ui.error(label),
    }
}

/// Returns the README of `name` for `batesian techniques show`.
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

        // `params_example` must parse as a runtime step.
        if serde_yml::from_str::<RuntimeStep>(def.params_example).is_err() {
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

/// Shortens a summary to at most `max` characters, appending an ellipsis.
fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
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
            let step: RuntimeStep = serde_yml::from_str(def.params_example)
                .unwrap_or_else(|e| panic!("{} params_example does not parse: {e}", def.name));
            let round_tripped = serde_yml::to_string(&step).expect("serialize RuntimeStep");
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
        let output = list(&Palette::plain());
        assert!(
            output.contains("process_hollowing"),
            "list output: {output}"
        );
        assert!(output.contains("execution"), "list output: {output}");
        assert!(output.contains("preparation"), "list output: {output}");
    }

    /// Rows are ordered by category, then stability, then technique name.
    #[test]
    fn list_is_ordered_by_category_stability_then_name() {
        let output = list(&Palette::plain());
        let names: Vec<&str> = output
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .filter(|token| find(token).is_some())
            .collect();

        let mut expected: Vec<&TechniqueDef> = all().iter().collect();
        expected.sort_by_key(|def| (def.category, def.stability, def.name));
        let expected: Vec<&str> = expected.iter().map(|def| def.name).collect();

        assert_eq!(names, expected, "list output: {output}");
    }

    /// The plain palette must not leak escape codes into the listing.
    #[test]
    fn plain_list_has_no_escape_codes() {
        let output = list(&Palette::plain());
        assert!(!output.contains('\u{1b}'), "escapes leaked: {output:?}");
    }

    /// Long summaries are truncated so the listing stays readable.
    #[test]
    fn truncates_long_summaries() {
        assert_eq!(truncate("short", 10), "short");
        let cut = truncate("0123456789abcdef", 8);
        assert_eq!(cut.chars().count(), 8);
        assert!(cut.ends_with("…"), "no ellipsis: {cut:?}");
    }

    #[test]
    fn show_returns_readme() {
        let readme = show("process_hollowing").expect("known technique");
        assert!(readme.contains("# Process hollowing"));
    }
}
