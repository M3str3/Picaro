//! Registry of SSN resolvers for `build.stub.syscalls.mode: indirect`.
//!
//! Each resolver is a small, self-contained module under this directory: its
//! own stub fragment, its own `ResolverDef` metadata and a README that the
//! docs site renders (see `docs/features/ref/syscalls/`). The `Resolver`
//! enum in the parent module is the YAML selector
//! (`build.stub.syscalls.resolver`); this registry is the single place that
//! maps it to an implementation and describes it for the CLI and the docs.

pub mod api_hash;
pub mod halos_gate;
pub mod hells_gate;
pub mod tartarus_gate;

use std::path::Path;

use crate::error::{PackerError, Result};
use crate::techniques::Stability;
use crate::techniques::{
    column_width, pad, readme_title, short_description, stability_label, stability_tone,
    strip_header, truncate,
};
use crate::ui::{glyph, markdown, Meta, Palette, Tone};

use super::Resolver;

/// Static metadata describing one SSN resolver.
///
/// No logic — only data, mirroring `FeatureDef`/`TechniqueDef`. The stub
/// fragment lives next to the definition (its module), and [`render_body`]
/// selects it.
pub struct ResolverDef {
    /// The YAML value of `build.stub.syscalls.resolver` (snake_case).
    pub name: &'static str,
    /// The phase the resolver landed in (`6a`/`6b`/`6c`), for the docs table.
    pub phase: &'static str,
    /// MITRE ATT&CK technique IDs.
    pub attck: &'static [&'static str],
    /// Maturity, shared with the technique/feature registries.
    pub stability: Stability,
    /// Path to the human-readable README (relative to the repo root).
    pub doc_path: &'static str,
    /// The README, embedded via `include_str!` for `techniques show` and the
    /// docs pipeline.
    pub readme: &'static str,
}

/// Every registered resolver, in build order.
const ALL: &[ResolverDef] = &[
    hells_gate::DEF,
    tartarus_gate::DEF,
    api_hash::DEF,
    halos_gate::DEF,
];

/// All registered resolvers, in build order.
pub fn all() -> &'static [ResolverDef] {
    ALL
}

/// Looks up a resolver by its YAML value.
pub fn find(name: &str) -> Option<&'static ResolverDef> {
    all().iter().find(|def| def.name == name)
}

/// The resolver's one-line summary, taken from its README.
pub fn summary(def: &ResolverDef) -> &str {
    short_description(def.readme)
}

/// The resolver's README as embedded Markdown, verbatim.
pub fn readme(name: &str) -> Result<&'static str> {
    find(name)
        .map(|def| def.readme)
        .ok_or_else(|| unknown(name))
}

/// Renders the `SYSCALL RESOLVERS` table, appended to `picaro techniques list`.
pub fn list(ui: &Palette) -> String {
    let mut out = String::new();
    let defs: Vec<&ResolverDef> = all().iter().collect();

    let name_w = column_width("RESOLVER", defs.iter().map(|def| def.name.to_string()));
    let phase_w = column_width("PHASE", defs.iter().map(|def| def.phase.to_string()));
    let stability_w = column_width(
        "STABILITY",
        defs.iter().map(|def| def.stability.label().to_string()),
    );
    let attck_w = column_width("ATT&CK", defs.iter().map(|def| def.attck.join(", ")));

    out.push_str(&ui.bold("SYSCALL RESOLVERS"));
    out.push('\n');
    out.push_str(&format!(
        "{} {} {} {} {}\n",
        ui.dim(pad("RESOLVER", name_w)),
        ui.dim(pad("PHASE", phase_w)),
        ui.dim(pad("STABILITY", stability_w)),
        ui.dim(pad("ATT&CK", attck_w)),
        ui.dim("SUMMARY"),
    ));
    for def in defs {
        out.push_str(&format!(
            "{} {} {} {} {}\n",
            ui.bold(pad(def.name, name_w)),
            pad(def.phase, phase_w),
            stability_label(def.stability, ui, stability_w),
            pad(&def.attck.join(", "), attck_w),
            truncate(summary(def), 70),
        ));
    }

    out.push_str(&format!(
        "\n{} {}\n",
        glyph::DOT,
        ui.dim(format!(
            "{} SSN resolvers for `build.stub.syscalls.resolver`",
            all().len(),
        ))
    ));
    out
}

/// Renders `picaro techniques show <resolver>`: a metadata header built from
/// the registry, followed by the resolver's README as Markdown.
pub fn show(name: &str, ui: &Palette) -> Result<String> {
    let def = find(name).ok_or_else(|| unknown(name))?;
    let width = crate::ui::term_width();

    let mut out = String::new();
    out.push_str(&ui.heading(readme_title(def.readme).unwrap_or(def.name)));
    out.push_str("\n\n");

    out.push_str(&ui.meta_bar(&[
        Meta {
            key: "PHASE",
            value: def.phase.to_string(),
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

    out.push_str(&ui.field("yaml", "build.stub.syscalls.resolver"));
    out.push('\n');

    out.push('\n');
    out.push_str(&ui.rule(width));
    out.push_str("\n\n");

    let body = strip_header(def.readme);
    out.push_str(&markdown::render(&body, ui, width));

    out.push('\n');
    out.push_str(&ui.dim(format!("{} {}", glyph::DOT, def.doc_path)));
    out.push('\n');
    Ok(out)
}

/// Validates the resolver registry and its docs pages. Returns a list of
/// problems; empty means good. This is a CI helper: it reports failures as
/// warnings without failing.
pub fn validate() -> Vec<String> {
    let mut problems = Vec::new();
    for def in all() {
        if def.name.trim().is_empty() {
            problems.push("resolver with an empty name".to_string());
        }
        if def.phase.trim().is_empty() {
            problems.push(format!("{}: 'phase' must not be empty", def.name));
        }
        if def.attck.is_empty() {
            problems.push(format!("{}: 'attck' must not be empty", def.name));
        }

        let readme_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(def.doc_path);
        if !readme_path.is_file() {
            problems.push(format!(
                "{}: doc_path does not exist: {}",
                def.name, def.doc_path
            ));
        }
        if !def.readme.starts_with("# ") {
            problems.push(format!("{}: README.md has no '#' title", def.name));
        }

        let page = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("docs/features/ref/syscalls/{}.md", def.name));
        if !page.is_file() {
            problems.push(format!(
                "{}: missing docs page 'docs/features/ref/syscalls/{}.md'",
                def.name, def.name
            ));
        }
    }
    problems
}

/// Renders the resolver body for the selected resolver.
///
/// The prebuilt `ssn_init` / `ssn_resolve` lines come from the parent module's
/// per-function loop. Every resolver shares the same placeholder set now
/// (Hell's Gate included, since its hooked-prologue fallback reads the clean
/// on-disk copy too), so the substitution lives here once.
pub(crate) fn render_body(
    resolver: Resolver,
    ssn_init: &str,
    ssn_resolve: &str,
    ntdll_def: &str,
    seed: u64,
) -> String {
    let fragment = match resolver {
        Resolver::HellsGate => hells_gate::FRAGMENT,
        Resolver::TartarusGate => tartarus_gate::FRAGMENT,
        Resolver::ApiHash => api_hash::FRAGMENT,
        Resolver::HalosGate => halos_gate::FRAGMENT,
    };
    fragment
        .replace("$SSN_INIT$", ssn_init)
        .replace("$SSN_RESOLVE$", ssn_resolve)
        .replace("$NTDLL_DEF$", ntdll_def)
        .replace("$FILE_PE_HELPERS$", super::pe_file::FILE_PE_HELPERS)
        .replace("$API_HASH_SEED$", &format!("0x{seed:016x}"))
}

/// The error for a name that is not a resolver.
fn unknown(name: &str) -> PackerError {
    PackerError::Validation(format!("unknown SSN resolver '{name}'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_well_formed() {
        assert!(
            !all().is_empty(),
            "at least one resolver must be registered"
        );
        for def in all() {
            assert!(!def.name.is_empty(), "resolver name must not be empty");
            assert!(
                !def.phase.is_empty(),
                "{}: phase must not be empty",
                def.name
            );
            assert!(
                !def.attck.is_empty(),
                "{}: attck must not be empty",
                def.name
            );
            assert!(!def.doc_path.is_empty(), "{}: doc_path empty", def.name);
            assert!(
                def.readme.starts_with("# "),
                "{}: README has no title",
                def.name
            );
            let readme_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(def.doc_path);
            assert!(
                readme_path.is_file(),
                "{}: doc_path does not exist: {}",
                def.name,
                readme_path.display()
            );
        }
    }

    /// Every registered resolver must have a docs page. The sidebar group, the
    /// overview table and the page itself are generated from this registry, so
    /// there is no per-resolver nav entry to keep in sync.
    #[test]
    fn every_resolver_is_documented() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        for def in all() {
            let page = format!("docs/features/ref/syscalls/{}.md", def.name);
            assert!(
                root.join(&page).is_file(),
                "{}: missing docs page '{page}'",
                def.name
            );
        }
    }

    #[test]
    fn find_returns_a_registered_resolver() {
        assert!(find("hells_gate").is_some());
        assert!(find("does_not_exist").is_none());
    }

    #[test]
    fn list_includes_every_resolver_without_escapes() {
        let output = list(&Palette::plain());
        assert!(
            output.contains("SYSCALL RESOLVERS"),
            "list output: {output}"
        );
        for def in all() {
            assert!(
                output.contains(def.name),
                "{}: missing from the listing: {output}",
                def.name
            );
        }
        assert!(!output.contains('\u{1b}'), "escapes leaked: {output:?}");
    }

    #[test]
    fn show_renders_metadata_and_readme() {
        let page = show("hells_gate", &Palette::plain()).expect("known resolver");
        assert!(page.contains("6a"), "page: {page}");
        assert!(page.contains("T1106"), "page: {page}");
        assert!(
            page.contains("build.stub.syscalls.resolver"),
            "page: {page}"
        );
        assert!(page.contains("What it does"), "page: {page}");
        assert!(!page.contains('\u{1b}'), "escapes leaked: {page:?}");
    }

    #[test]
    fn validate_reports_no_problems() {
        let problems = validate();
        assert!(problems.is_empty(), "problems: {problems:?}");
    }
}
