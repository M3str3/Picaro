//! Technique registry.
//!
//! Every evasion/execution technique lives in its own subdirectory (e.g.
//! [`process_hollowing`]) and is registered in [`all`]. The registry is pure
//! metadata: it feeds the `picaro techniques` CLI, the `validate` CI check
//! and the stub renderer. How to add a technique is documented in
//! `src/techniques/README.md`.

pub mod anti_debug;
pub mod bouncer;
pub mod dotnet_hosting;
pub mod early_bird;
pub mod execution_callbacks;
pub mod fibers;
pub mod living_off_the_land;
pub mod module_stomping;
pub mod patch_amsi;
pub mod patch_etw;
pub mod pe_injection;
pub mod ppid_spoofing;
pub mod process_hollowing;
pub mod reflective_loading;
pub mod sleep;
pub mod sleep_obfuscation;
pub mod unhook_ntdll;

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;
use crate::error::{PackerError, Result};
use crate::ui::{glyph, Palette};

use crate::plan::schema::{PayloadFormat, StepControl};

/// One step of the `runtime` list in the YAML plan.
///
/// A step is a technique call: the technique's `params` plus the loader's own
/// orchestration ([`StepControl`]). The two live in separate namespaces, so a
/// technique parameter can never collide with an orchestration field: the
/// technique interprets `params`, the loader reads the control fields.
///
/// ```yaml
/// runtime:
///   - technique: process_hollowing
///     params:
///       payload: implant
///       target: "C:\\Windows\\System32\\svchost.exe"
///     on_fail: continue
/// ```
///
/// `params` is optional: a technique whose parameters all have defaults (e.g.
/// `patch_amsi`) may omit it entirely.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeStep {
    /// The technique the step calls, with its `params`.
    #[serde(flatten)]
    pub technique: TechniqueKind,

    /// How the loader reacts to this step's result.
    #[serde(flatten)]
    pub control: StepControl,
}

impl RuntimeStep {
    /// Builds a step that calls `technique` with default orchestration.
    pub fn new(technique: TechniqueKind) -> Self {
        Self {
            technique,
            control: StepControl::default(),
        }
    }

    /// The technique's YAML key (used by semantic validation and the build log).
    pub fn name(&self) -> &'static str {
        self.technique.name()
    }

    /// The technique's [`Category`] (Preparation, Execution or Control).
    pub fn category(&self) -> Category {
        self.technique.category()
    }
}

/// A technique call: which technique, and the arguments it interprets.
///
/// Internally tagged enum: the step names the technique with `technique: <name>`
/// and passes its parameters under a nested `params:` mapping, so a parameter
/// can never collide with the tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "technique", rename_all = "snake_case")]
pub enum TechniqueKind {
    /// Detect a debugger in the current process, aborting by default
    /// (preparation).
    AntiDebug {
        /// Technique parameters (`action`).
        #[serde(default)]
        params: anti_debug::Params,
    },
    /// Gate the pipeline on the host environment (preparation).
    Bouncer {
        /// Technique parameters (the declared checks).
        #[serde(default)]
        params: bouncer::Params,
    },
    /// Patch AmsiScanBuffer in the current process (preparation).
    PatchAmsi {
        /// Technique parameters (none).
        #[serde(default)]
        params: patch_amsi::Params,
    },
    /// Patch the ETW event-writing exports in the current process
    /// (preparation).
    PatchEtw {
        /// Technique parameters (`full`).
        #[serde(default)]
        params: patch_etw::Params,
    },
    /// ntdll unhooking: restore the loaded ntdll's code section from a clean
    /// copy read from disk (preparation).
    UnhookNtdll {
        /// Technique parameters (none).
        #[serde(default)]
        params: unhook_ntdll::Params,
    },
    /// Process hollowing: run the payload inside a suspended, legitimate
    /// process instead of on disk.
    ProcessHollowing {
        /// Technique parameters (`payload`, `target`).
        #[serde(default)]
        params: process_hollowing::Params,
    },
    /// .NET hosting: start the CLR in the current process and load the managed
    /// payload as an assembly from memory.
    DotnetHosting {
        /// Technique parameters (`payload`).
        #[serde(default)]
        params: dotnet_hosting::Params,
    },
    /// Reflective loading: map the payload into the current process and run
    /// its entry point.
    ReflectiveLoading {
        /// Technique parameters (`payload`).
        #[serde(default)]
        params: reflective_loading::Params,
    },
    /// Callback execution: run the payload as the callback of a legitimate
    /// Windows enumeration API in the current process.
    ExecutionCallbacks {
        /// Technique parameters (`payload`).
        #[serde(default)]
        params: execution_callbacks::Params,
    },
    /// Fiber execution: run the payload on a fiber in the current process.
    Fibers {
        /// Technique parameters (`payload`).
        #[serde(default)]
        params: fibers::Params,
    },
    /// Module stomping: overwrite a legitimately loaded module's code with the
    /// payload and run it from there.
    ModuleStomping {
        /// Technique parameters (`payload`).
        #[serde(default)]
        params: module_stomping::Params,
    },
    /// Early Bird APC injection: spawn a suspended process, write the payload
    /// and queue an APC before the target runs.
    EarlyBird {
        /// Technique parameters (`payload`, `target`).
        #[serde(default)]
        params: early_bird::Params,
    },
    /// PE injection: map the payload image into a suspended process and start
    /// it at its entry point.
    PeInjection {
        /// Technique parameters (`payload`, `target`).
        #[serde(default)]
        params: pe_injection::Params,
    },
    /// Sleep obfuscation: encrypt the image region during a timer-driven
    /// sleep (preparation).
    SleepObfuscation {
        /// Technique parameters (`variant`, `sleep_ms`, `encrypt_regions`).
        #[serde(default)]
        params: sleep_obfuscation::Params,
    },
    /// Living off the land: launch a process — a signed Microsoft binary
    /// (T1218 proxy execution) or any command (control).
    LivingOffTheLand {
        /// Technique parameters (`binary`, `args`, `window`, `wait`,
        /// `timeout_s`).
        #[serde(default)]
        params: living_off_the_land::Params,
    },
    /// Wait a number of milliseconds (control).
    Sleep {
        /// Technique parameters (`ms`).
        #[serde(default)]
        params: sleep::Params,
    },
    /// Parent-process spoofing: launch a process whose recorded parent is a
    /// different, legitimate process (control).
    PpidSpoofing {
        /// Technique parameters (`binary`, `args`, `parent`, `wait`).
        #[serde(default)]
        params: ppid_spoofing::Params,
    },
}

impl TechniqueKind {
    /// Renders the technique's stub fragment for its parameters.
    ///
    /// `strings` is the active string-obfuscation configuration, used to
    /// obfuscate any per-build string literal (e.g. the hollowing target).
    /// `format` and `export` describe the payload the technique loads.
    pub fn render_fragment(
        &self,
        strings: &StringsConfig,
        format: PayloadFormat,
        export: Option<&str>,
    ) -> String {
        match self {
            TechniqueKind::AntiDebug { params } => params.render_fragment(strings),
            TechniqueKind::Bouncer { params } => params.render_fragment(strings),
            TechniqueKind::PatchAmsi { params } => params.render_fragment(strings),
            TechniqueKind::PatchEtw { params } => params.render_fragment(strings),
            TechniqueKind::DotnetHosting { params } => params.render_fragment(strings),
            TechniqueKind::ProcessHollowing { params } => {
                params.render_fragment_for(strings, format)
            }
            TechniqueKind::ReflectiveLoading { params } => {
                params.render_fragment_for(strings, format, export)
            }
            TechniqueKind::ExecutionCallbacks { params } => {
                params.render_fragment_for(strings, format, export)
            }
            TechniqueKind::Fibers { params } => params.render_fragment_for(strings, format, export),
            TechniqueKind::ModuleStomping { params } => {
                params.render_fragment_for(strings, format, export)
            }
            TechniqueKind::SleepObfuscation { params } => params.render_fragment(strings),
            TechniqueKind::UnhookNtdll { params } => params.render_fragment(strings),
            TechniqueKind::EarlyBird { params } => {
                params.render_fragment_for(strings, format, export)
            }
            TechniqueKind::PeInjection { params } => {
                params.render_fragment_for(strings, format, export)
            }
            TechniqueKind::PpidSpoofing { params } => params.render_fragment(strings),
            TechniqueKind::LivingOffTheLand { params } => params.render_fragment(strings),
            TechniqueKind::Sleep { params } => params.render_fragment(strings),
        }
    }

    /// The technique's YAML key (used by semantic validation).
    pub fn name(&self) -> &'static str {
        match self {
            TechniqueKind::AntiDebug { .. } => anti_debug::DEF.name,
            TechniqueKind::Bouncer { .. } => bouncer::DEF.name,
            TechniqueKind::PatchAmsi { .. } => patch_amsi::DEF.name,
            TechniqueKind::PatchEtw { .. } => patch_etw::DEF.name,
            TechniqueKind::DotnetHosting { .. } => dotnet_hosting::DEF.name,
            TechniqueKind::ProcessHollowing { .. } => process_hollowing::DEF.name,
            TechniqueKind::ReflectiveLoading { .. } => reflective_loading::DEF.name,
            TechniqueKind::ExecutionCallbacks { .. } => execution_callbacks::DEF.name,
            TechniqueKind::Fibers { .. } => fibers::DEF.name,
            TechniqueKind::ModuleStomping { .. } => module_stomping::DEF.name,
            TechniqueKind::EarlyBird { .. } => early_bird::DEF.name,
            TechniqueKind::PeInjection { .. } => pe_injection::DEF.name,
            TechniqueKind::PpidSpoofing { .. } => ppid_spoofing::DEF.name,
            TechniqueKind::UnhookNtdll { .. } => unhook_ntdll::DEF.name,
            TechniqueKind::SleepObfuscation { .. } => sleep_obfuscation::DEF.name,
            TechniqueKind::LivingOffTheLand { .. } => living_off_the_land::DEF.name,
            TechniqueKind::Sleep { .. } => sleep::DEF.name,
        }
    }

    /// The name of the payload this technique loads, when it loads one.
    ///
    /// Only Execution techniques run a payload; a Preparation or Control step
    /// returns `None`.
    pub fn payload_name(&self) -> Option<&str> {
        match self {
            TechniqueKind::ProcessHollowing { params } => params.payload.as_deref(),
            TechniqueKind::DotnetHosting { params } => params.payload.as_deref(),
            TechniqueKind::ReflectiveLoading { params } => params.payload.as_deref(),
            TechniqueKind::ExecutionCallbacks { params } => params.payload.as_deref(),
            TechniqueKind::Fibers { params } => params.payload.as_deref(),
            TechniqueKind::ModuleStomping { params } => params.payload.as_deref(),
            TechniqueKind::EarlyBird { params } => params.payload.as_deref(),
            TechniqueKind::PeInjection { params } => params.payload.as_deref(),
            _ => None,
        }
    }

    /// The technique's [`Category`] (Preparation, Execution or Control).
    ///
    /// Read from the technique's [`TechniqueDef`] so the registry stays the
    /// single source of truth: a technique cannot disagree with itself.
    pub fn category(&self) -> Category {
        match self {
            TechniqueKind::AntiDebug { .. } => anti_debug::DEF.category,
            TechniqueKind::Bouncer { .. } => bouncer::DEF.category,
            TechniqueKind::PatchAmsi { .. } => patch_amsi::DEF.category,
            TechniqueKind::PatchEtw { .. } => patch_etw::DEF.category,
            TechniqueKind::DotnetHosting { .. } => dotnet_hosting::DEF.category,
            TechniqueKind::ProcessHollowing { .. } => process_hollowing::DEF.category,
            TechniqueKind::ReflectiveLoading { .. } => reflective_loading::DEF.category,
            TechniqueKind::ExecutionCallbacks { .. } => execution_callbacks::DEF.category,
            TechniqueKind::Fibers { .. } => fibers::DEF.category,
            TechniqueKind::ModuleStomping { .. } => module_stomping::DEF.category,
            TechniqueKind::EarlyBird { .. } => early_bird::DEF.category,
            TechniqueKind::PeInjection { .. } => pe_injection::DEF.category,
            TechniqueKind::PpidSpoofing { .. } => ppid_spoofing::DEF.category,
            TechniqueKind::UnhookNtdll { .. } => unhook_ntdll::DEF.category,
            TechniqueKind::SleepObfuscation { .. } => sleep_obfuscation::DEF.category,
            TechniqueKind::LivingOffTheLand { .. } => living_off_the_land::DEF.category,
            TechniqueKind::Sleep { .. } => sleep::DEF.category,
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
    /// Neither prepares state nor runs the payload: it orchestrates the chain
    /// (launch a process, wait). `living_off_the_land` and `sleep`.
    Control,
}

impl Category {
    /// Lowercase label used by `picaro techniques list`.
    pub fn label(self) -> &'static str {
        match self {
            Category::Preparation => "preparation",
            Category::Execution => "execution",
            Category::Control => "control",
        }
    }
}

/// Maturity of a technique.
///
/// Variants are part of the metadata vocabulary; only the ones used by the
/// currently-registered techniques are constructed.
///
/// Variant order is meaningful: it defines the sort key used by [`list`]
/// (Stable before Experimental before Unimplemented before Deprecated).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stability {
    /// Complete and verified: a measurement baseline or passing runtime checks.
    Stable,
    /// Works, but a gap or a caveat remains (see the technique's README).
    Experimental,
    /// Registered and wired (registry arm, metadata, docs, tests) but **not
    /// finished**: either the stub fragment is a placeholder or a required part
    /// of the loader contract is missing, so it must not be shipped as-is.
    /// `plan::validate::advisories` warns when a runtime selects one.
    Unimplemented,
    /// Superseded by a better technique; kept for old plans.
    Deprecated,
}

impl Stability {
    /// Lowercase label used by `picaro techniques list`.
    pub fn label(self) -> &'static str {
        match self {
            Stability::Stable => "stable",
            Stability::Experimental => "experimental",
            Stability::Unimplemented => "unimplemented",
            Stability::Deprecated => "deprecated",
        }
    }
}

/// A capability the build host must provide for a technique.
///
/// The architecture variants (`WindowsX64` / `WindowsX86`) gate which
/// `build.output.arch` a technique can run under; `plan::validate` checks them
/// against the plan. Variants are part of the metadata vocabulary; only the ones
/// used by the currently-registered techniques are constructed.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    WindowsX64,
    WindowsX86,
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
        dotnet_hosting::DEF,
        process_hollowing::DEF,
        reflective_loading::DEF,
        execution_callbacks::DEF,
        fibers::DEF,
        module_stomping::DEF,
        early_bird::DEF,
        pe_injection::DEF,
        ppid_spoofing::DEF,
        unhook_ntdll::DEF,
        patch_amsi::DEF,
        anti_debug::DEF,
        patch_etw::DEF,
        sleep_obfuscation::DEF,
        bouncer::DEF,
        living_off_the_land::DEF,
        sleep::DEF,
    ]
}

/// Looks up a technique by its YAML key.
pub fn find(name: &str) -> Option<&'static TechniqueDef> {
    all().iter().find(|def| def.name == name)
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

/// The widest cell of a listing column, header included.
///
/// The table is measured instead of fixed: a technique name or an ATT&CK list
/// longer than the rest must not push the remaining columns of its own row out
/// of line.
fn column_width(header: &str, values: impl Iterator<Item = String>) -> usize {
    values
        .map(|value| value.chars().count())
        .chain(std::iter::once(header.chars().count()))
        .max()
        .unwrap_or(0)
}

/// Pads a cell to `width`.
///
/// The padding happens before the cell is styled: padding an already-colored
/// string would count the escape codes and misalign the row (see
/// [`stability_label`], which pads for the same reason).
fn pad(text: &str, width: usize) -> String {
    format!("{text:<width$}")
}

/// Renders the `picaro techniques list` output.
pub fn list(ui: &Palette) -> String {
    let mut out = String::new();

    // Grouped by category, then maturity, then name: the listing reads as a
    // pipeline (Preparation before Execution) with the most reliable entries
    // first inside each group.
    let mut defs: Vec<&TechniqueDef> = all().iter().collect();
    defs.sort_by_key(|def| (def.category, def.stability, def.name));

    let name_w = column_width("TECHNIQUE", defs.iter().map(|def| def.name.to_string()));
    let category_w = column_width(
        "CATEGORY",
        defs.iter().map(|def| def.category.label().to_string()),
    );
    let stability_w = column_width(
        "STABILITY",
        defs.iter().map(|def| def.stability.label().to_string()),
    );
    let attck_w = column_width("ATT&CK", defs.iter().map(|def| def.attck.join(", ")));

    out.push_str(&format!(
        "{} {} {} {} {}\n",
        ui.dim(pad("TECHNIQUE", name_w)),
        ui.dim(pad("CATEGORY", category_w)),
        ui.dim(pad("STABILITY", stability_w)),
        ui.dim(pad("ATT&CK", attck_w)),
        ui.dim("SUMMARY"),
    ));
    for def in defs {
        let name = ui.bold(pad(def.name, name_w));
        let category = pad(def.category.label(), category_w);
        let stability = stability_label(def, ui, stability_w);
        let attck = pad(&def.attck.join(", "), attck_w);
        out.push_str(&format!(
            "{name} {category} {stability} {attck} {}\n",
            truncate(summary(def), 70)
        ));
    }

    let count = |category: Category| all().iter().filter(|d| d.category == category).count();
    out.push_str(&format!(
        "\n{} {}\n",
        glyph::DOT,
        ui.dim(format!(
            "{} techniques ({} preparation, {} execution, {} control)",
            all().len(),
            count(Category::Preparation),
            count(Category::Execution),
            count(Category::Control),
        ))
    ));
    out
}

/// The technique's stability label, padded to `width` and colored by maturity.
fn stability_label(def: &TechniqueDef, ui: &Palette, width: usize) -> String {
    let label = format!(
        "{name:<width$}",
        name = def.stability.label(),
        width = width
    );
    match def.stability {
        Stability::Stable => ui.ok(label),
        Stability::Experimental => ui.warn(label),
        Stability::Unimplemented => ui.error(label),
        Stability::Deprecated => ui.error(label),
    }
}

/// Returns the README of `name` for `picaro techniques show`.
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

/// The technique's one-line summary, taken from its README.
///
/// Shared by `techniques list` and the interactive `build` wizard so both show
/// the same wording.
pub fn summary(def: &TechniqueDef) -> &str {
    short_description(def.readme)
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

    /// A long technique name or ATT&CK list must not push the rest of its row.
    ///
    /// Regression: the name column was a fixed 18 characters, so the 19-char
    /// `living_off_the_land` and `execution_callbacks` shifted the columns that
    /// follow them by one.
    #[test]
    fn list_columns_align_across_rows() {
        let output = list(&Palette::plain());
        let starts: Vec<usize> = all()
            .iter()
            .map(|def| {
                let line = output
                    .lines()
                    .find(|line| line.split_whitespace().next() == Some(def.name))
                    .unwrap_or_else(|| panic!("no row for {}: {output}", def.name));
                let last = truncate(summary(def), 70);
                line.rfind(&last)
                    .unwrap_or_else(|| panic!("no summary column in {line:?}"))
            })
            .collect();

        assert!(
            starts.windows(2).all(|pair| pair[0] == pair[1]),
            "the summary column is ragged: {starts:?}\n{output}"
        );
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
