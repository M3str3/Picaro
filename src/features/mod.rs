//! Loader-feature registry.
//!
//! A *loader feature* is stub-level configuration, not a `runtime:` step: it
//! changes how the generated stub is built or how it talks to the kernel and the
//! payload's imports, so it carries no payload and is not ordered in the
//! pipeline. The ordered preparations/executions/controls live in
//! [`crate::techniques`].
//!
//! This module is metadata-only, mirroring [`crate::techniques::TechniqueDef`]:
//! it feeds `picaro techniques list`, `picaro techniques show` and
//! `picaro techniques validate`, so the CLI and the documentation have a single
//! source of truth. The implementation stays in `crate::engine` (e.g.
//! `engine::syscalls`); here we only describe the feature.

pub mod api_resolution;
pub mod args;
pub mod strings;
pub mod syscalls;

use std::path::Path;

use crate::error::{PackerError, Result};
use crate::techniques::{
    column_width, pad, readme_title, short_description, strip_header, truncate, Capability,
    Stability,
};
use crate::ui::{glyph, markdown, Meta, Palette, Tone};

/// Where a loader feature is configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FeatureScope {
    /// Loader-wide, under `build.stub.*`: it shapes the generated stub.
    Loader,
    /// Per-payload, under `build.payloads.<name>`: the stub applies it when the
    /// payload runs.
    Payload,
}

impl FeatureScope {
    /// Lowercase label used by `picaro techniques list`.
    pub fn label(self) -> &'static str {
        match self {
            FeatureScope::Loader => "loader",
            FeatureScope::Payload => "payload",
        }
    }
}

/// Static metadata describing one loader feature.
///
/// No logic here — only data consumed by the `techniques` CLI and `validate`.
pub struct FeatureDef {
    /// Display name (also the `techniques show` selector).
    pub name: &'static str,
    /// MITRE ATT&CK technique IDs.
    pub attck: &'static [&'static str],
    /// Maturity, shared with the technique registry.
    pub stability: Stability,
    /// Capabilities the build host must provide. Empty for a portable feature.
    pub requires: &'static [Capability],
    /// Names of features/techniques this one conflicts with.
    pub conflicts: &'static [&'static str],
    /// Where the feature is configured.
    pub scope: FeatureScope,
    /// The YAML path that selects it (e.g. `build.stub.syscalls`).
    pub yaml: &'static str,
    /// Path to the human-readable README (relative to the repo root).
    pub doc_path: &'static str,
    /// The README, embedded via `include_str!` for `techniques show`.
    pub readme: &'static str,
    /// A YAML snippet documenting the feature's block.
    pub params_example: &'static str,
}

/// All registered loader features.
pub fn all() -> &'static [FeatureDef] {
    &[syscalls::DEF, api_resolution::DEF, strings::DEF, args::DEF]
}

/// Looks up a loader feature by its name.
pub fn find(name: &str) -> Option<&'static FeatureDef> {
    all().iter().find(|def| def.name == name)
}

/// Section headings every feature README must contain.
///
/// Shorter than the technique template: a feature has no pipeline contract and
/// no per-build marker, so those sections do not apply.
const REQUIRED_SECTIONS: &[&str] = &[
    "## What it does",
    "## YAML parameters",
    "## YAML example",
    "## How it works",
    "## What it evades",
    "## What detects it",
    "## Implementation notes",
    "## References",
];

/// Renders the `LOADER FEATURES` table, appended to `picaro techniques list`.
///
/// Loader features are grouped by scope (loader-wide before per-payload), then
/// maturity, then name — the same shape as the technique listing.
pub fn list(ui: &Palette) -> String {
    let mut out = String::new();

    let mut defs: Vec<&FeatureDef> = all().iter().collect();
    defs.sort_by_key(|def| (def.scope, def.stability, def.name));

    let name_w = column_width("FEATURE", defs.iter().map(|def| def.name.to_string()));
    let scope_w = column_width(
        "SCOPE",
        defs.iter().map(|def| def.scope.label().to_string()),
    );
    let stability_w = column_width(
        "STABILITY",
        defs.iter().map(|def| def.stability.label().to_string()),
    );
    let attck_w = column_width("ATT&CK", defs.iter().map(|def| def.attck.join(", ")));

    out.push_str(&ui.bold("LOADER FEATURES"));
    out.push('\n');
    out.push_str(&format!(
        "{} {} {} {} {}\n",
        ui.dim(pad("FEATURE", name_w)),
        ui.dim(pad("SCOPE", scope_w)),
        ui.dim(pad("STABILITY", stability_w)),
        ui.dim(pad("ATT&CK", attck_w)),
        ui.dim("SUMMARY"),
    ));
    for def in defs {
        let name = ui.bold(pad(def.name, name_w));
        let scope = pad(def.scope.label(), scope_w);
        let stability = stability_label(def, ui, stability_w);
        let attck = pad(&def.attck.join(", "), attck_w);
        out.push_str(&format!(
            "{name} {scope} {stability} {attck} {}\n",
            truncate(summary(def), 70)
        ));
    }

    out.push_str(&format!(
        "\n{} {}\n",
        glyph::DOT,
        ui.dim(format!(
            "{} loader features — stub configuration, not ordered in `runtime:`",
            all().len(),
        ))
    ));
    out
}

/// The feature's stability label, padded to `width` and colored by maturity.
fn stability_label(def: &FeatureDef, ui: &Palette, width: usize) -> String {
    let label = format!("{name:<width$}", name = def.stability.label());
    match def.stability {
        Stability::Stable => ui.ok(label),
        Stability::Experimental => ui.warn(label),
        Stability::Unimplemented | Stability::Deprecated => ui.error(label),
    }
}

/// The color role of a maturity (shared with [`stability_label`]).
fn stability_tone(stability: Stability) -> Tone {
    match stability {
        Stability::Stable => Tone::Ok,
        Stability::Experimental => Tone::Warn,
        Stability::Unimplemented | Stability::Deprecated => Tone::Bad,
    }
}

/// The feature's one-line summary, taken from its README.
pub fn summary(def: &FeatureDef) -> &str {
    short_description(def.readme)
}

/// The feature's README as embedded Markdown, verbatim.
pub fn readme(name: &str) -> Result<&'static str> {
    find(name)
        .map(|def| def.readme)
        .ok_or_else(|| unknown(name))
}

/// Renders `picaro techniques show <feature>`: a styled header built from the
/// feature's metadata, followed by its README rendered as Markdown.
pub fn show(name: &str, ui: &Palette) -> Result<String> {
    let def = find(name).ok_or_else(|| unknown(name))?;
    let width = crate::ui::term_width();

    let mut out = String::new();
    out.push_str(&ui.heading(readme_title(def.readme).unwrap_or(def.name)));
    out.push_str("\n\n");

    out.push_str(&ui.meta_bar(&[
        Meta {
            key: "SCOPE",
            value: def.scope.label().to_string(),
            tone: Tone::Value,
        },
        Meta {
            key: "STABILITY",
            value: def.stability.label().to_string(),
            tone: stability_tone(def.stability),
        },
        Meta {
            key: "ATT&CK",
            value: def.attck.join(", "),
            tone: Tone::Value,
        },
    ]));
    out.push('\n');

    out.push_str(&ui.field("yaml", def.yaml));
    out.push('\n');
    if !def.requires.is_empty() {
        out.push_str(&ui.field_wrapped("requires", capabilities(def.requires), width));
        out.push('\n');
    }
    if !def.conflicts.is_empty() {
        out.push_str(&ui.field_wrapped("conflicts", def.conflicts.join(", "), width));
        out.push('\n');
    }

    out.push('\n');
    out.push_str(&ui.rule(width));
    out.push_str("\n\n");

    // The styled header replaces the README's title and Metadata section.
    out.push_str(&markdown::render(&strip_header(def.readme), ui, width));

    out.push('\n');
    out.push_str(&ui.dim(format!("{} {}", glyph::DOT, def.doc_path)));
    out.push('\n');
    Ok(out)
}

/// Validates the feature registry. Returns a list of problems; empty means good.
///
/// This is a CI helper: it reports failures as warnings without failing.
pub fn validate() -> Vec<String> {
    let mut problems = Vec::new();
    for def in all() {
        if def.name.trim().is_empty() {
            problems.push("feature with an empty name".to_string());
        }

        if def.attck.is_empty() {
            problems.push(format!("{}: 'attck' must not be empty", def.name));
        }

        if def.yaml.trim().is_empty() {
            problems.push(format!("{}: 'yaml' must not be empty", def.name));
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

        if def.params_example.trim().is_empty() {
            problems.push(format!("{}: params_example must not be empty", def.name));
        }

        let title_seen = def
            .readme
            .lines()
            .next()
            .is_some_and(|first| first.starts_with("# "));
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
    }
    problems
}

/// Comma-joined capability labels for the `requires` field.
fn capabilities(requires: &[Capability]) -> String {
    requires
        .iter()
        .map(|capability| capability.label())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The error for a name that is neither a technique nor a feature.
fn unknown(name: &str) -> PackerError {
    PackerError::Validation(format!("unknown technique or loader feature '{name}'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_non_empty_and_well_formed() {
        assert!(
            !all().is_empty(),
            "at least one loader feature must be registered"
        );
        for def in all() {
            assert!(!def.name.is_empty(), "feature name must not be empty");
            assert!(!def.yaml.is_empty(), "feature yaml path must not be empty");

            let readme_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(def.doc_path);
            assert!(
                readme_path.is_file(),
                "doc_path does not exist: {}",
                readme_path.display()
            );
        }
    }

    /// Every registered feature must be reachable from the documentation: a page
    /// under `docs/features/ref/`, a link in the overview table and a nav entry
    /// in `mkdocs.yml`. Adding a feature without updating the docs is the drift
    /// this guards against.
    #[test]
    fn every_feature_is_documented() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let overview = std::fs::read_to_string(root.join("docs/features/index.md"))
            .expect("docs/features/index.md must exist");
        let nav = std::fs::read_to_string(root.join("mkdocs.yml")).expect("mkdocs.yml must exist");

        for def in all() {
            let docs_page = format!("docs/features/ref/{}.md", def.name);
            assert!(
                root.join(&docs_page).is_file(),
                "{}: missing docs page '{docs_page}'",
                def.name
            );
            assert!(
                overview.contains(&format!("(ref/{}.md)", def.name)),
                "{}: no link to the feature in docs/features/index.md",
                def.name
            );
            assert!(
                nav.contains(&format!("features/ref/{}.md", def.name)),
                "{}: no nav entry in mkdocs.yml",
                def.name
            );
        }
    }

    #[test]
    fn find_returns_a_registered_feature() {
        assert!(find("syscalls").is_some());
        assert!(find("does_not_exist").is_none());
    }

    #[test]
    fn list_includes_the_features() {
        let output = list(&Palette::plain());
        assert!(output.contains("LOADER FEATURES"), "list output: {output}");
        for def in all() {
            assert!(
                output.contains(def.name),
                "{}: missing from the listing: {output}",
                def.name
            );
        }
    }

    #[test]
    fn plain_list_has_no_escape_codes() {
        let output = list(&Palette::plain());
        assert!(!output.contains('\u{1b}'), "escapes leaked: {output:?}");
    }

    #[test]
    fn show_renders_metadata_and_readme() {
        let page = show("syscalls", &Palette::plain()).expect("known feature");
        assert!(page.contains("loader"), "page: {page}");
        assert!(page.contains("T1106"), "page: {page}");
        assert!(page.contains("build.stub.syscalls"), "page: {page}");
        assert!(page.contains("What it does"), "page: {page}");
        assert!(!page.contains("## Metadata"), "page: {page}");
        assert!(!page.contains('\u{1b}'), "escapes leaked: {page:?}");
    }

    #[test]
    fn show_pages_every_feature() {
        for def in all() {
            let page = show(def.name, &Palette::plain())
                .unwrap_or_else(|error| panic!("{}: {error}", def.name));
            assert!(!page.is_empty(), "{}: empty page", def.name);
            assert!(
                page.contains("What it does"),
                "{}: missing section: {page}",
                def.name
            );
        }
    }

    #[test]
    fn readme_is_verbatim() {
        let raw = readme("syscalls").expect("known feature");
        assert!(raw.contains("# "), "no title: {raw}");
    }

    #[test]
    fn unknown_feature_is_an_error() {
        assert!(show("does_not_exist", &Palette::plain()).is_err());
        assert!(readme("does_not_exist").is_err());
    }

    #[test]
    fn validate_reports_no_problems() {
        let problems = validate();
        assert!(problems.is_empty(), "problems: {problems:?}");
    }
}
