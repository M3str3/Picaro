use super::*;

/// Section headings every technique README must contain (see
/// `_template/README.md`).
///
/// The README is the prose explanation only: the technique's metadata
/// (category, stability, ATT&CK, platforms, syscalls, params, example) lives in
/// its `TechniqueDef` and is rendered from the registry by `picaro techniques
/// show` and the docs site, so a README never repeats it.
const REQUIRED_SECTIONS: &[&str] = &[
    "## What it does",
    "## How it works",
    "## Integration",
    "## What it evades",
    "## What detects it",
    "## Measurements",
    "## Implementation notes",
    "## References",
];

/// Headings that must NOT appear in a README: the same data lives in
/// [`TechniqueDef`] and is rendered from it (the docs page and `techniques
/// show`), so duplicating it in the README is the drift this split avoids.
const FORBIDDEN_SECTIONS: &[&str] = &["## Metadata", "## YAML parameters", "## YAML example"];

/// The widest cell of a listing column, header included.
///
/// The table is measured instead of fixed: a technique name or an ATT&CK list
/// longer than the rest must not push the remaining columns of its own row out
/// of line.
pub(crate) fn column_width(header: &str, values: impl Iterator<Item = String>) -> usize {
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
pub(crate) fn pad(text: &str, width: usize) -> String {
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
        let stability = stability_label(def.stability, ui, stability_w);
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

    // Legend: two dim lines. Their first token is never a technique name, so
    // the table-shape tests keep matching only real rows.
    out.push_str(&format!(
        "  {} {}  {}  {}  {}\n",
        ui.dim("stability:"),
        ui.ok(Stability::Stable.label()),
        ui.warn(Stability::Experimental.label()),
        ui.error(Stability::Unimplemented.label()),
        ui.error(Stability::Deprecated.label()),
    ));
    out.push_str(&format!(
        "  {} {}\n",
        ui.dim("show:"),
        ui.dim("picaro techniques show <name> for the full README"),
    ));

    // Loader features (`syscalls`, `api_resolution`, `strings`, `args`) are not
    // runtime steps; they are listed in their own table so the registry view is
    // complete.
    out.push('\n');
    out.push_str(&crate::features::list(ui));
    out.push('\n');
    out.push_str(&crate::engine::syscalls::resolvers::list(ui));
    out
}

/// A stability label padded to `width` and colored by maturity.
///
/// Shared by the technique and loader-feature listings.
pub(crate) fn stability_label(stability: Stability, ui: &Palette, width: usize) -> String {
    let label = format!("{name:<width$}", name = stability.label(), width = width);
    match stability {
        Stability::Stable => ui.ok(label),
        Stability::Experimental => ui.warn(label),
        Stability::Unimplemented => ui.error(label),
        Stability::Deprecated => ui.error(label),
    }
}

/// The technique's README as embedded Markdown, verbatim.
pub fn readme(name: &str) -> Result<&'static str> {
    if let Some(def) = find(name) {
        return Ok(def.readme);
    }
    // Not a technique: it may be a loader feature or an SSN resolver.
    crate::features::readme(name).or_else(|_| crate::engine::syscalls::resolvers::readme(name))
}

/// Renders `picaro techniques show <name>`: a styled header built from the
/// technique's metadata, followed by its README rendered as Markdown.
pub fn show(name: &str, ui: &Palette) -> Result<String> {
    let Some(def) = find(name) else {
        // Not a technique: it may be a loader feature (`syscalls`, `strings`, …)
        // or an SSN resolver (`hells_gate`, …).
        return crate::features::show(name, ui)
            .or_else(|_| crate::engine::syscalls::resolvers::show(name, ui));
    };
    let width = crate::ui::term_width();

    let mut out = String::new();
    out.push_str(&ui.heading(readme_title(def.readme).unwrap_or(def.name)));
    out.push_str("\n\n");

    out.push_str(&ui.meta_bar(&[
        Meta {
            key: "CATEGORY",
            value: def.category.label().to_string(),
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

    out.push_str(&ui.field("yaml key", def.name));
    out.push('\n');
    out.push_str(&ui.field_wrapped("requires", capabilities(def.requires), width));
    out.push('\n');
    if !def.conflicts.is_empty() {
        out.push_str(&ui.field_wrapped("conflicts", def.conflicts.join(", "), width));
        out.push('\n');
    }
    if !def.syscalls.is_empty() {
        out.push_str(&ui.field_wrapped("syscalls", def.syscalls.join(", "), width));
        out.push('\n');
    }
    if def.resolves_imports {
        out.push_str(&ui.field("imports", "shared resolver"));
        out.push('\n');
    }

    out.push('\n');
    out.push_str(&ui.rule(width));
    out.push_str("\n\n");

    // The styled header replaces the README's title; the README is prose-only,
    // so the registry's parameter table and example are always prepended.
    let body = format!(
        "{}{}",
        params_markdown(&[], def.params_example),
        strip_header(def.readme)
    );
    out.push_str(&markdown::render(&body, ui, width));

    out.push('\n');
    out.push_str(&ui.dim(format!("{} {}", glyph::DOT, def.doc_path)));
    out.push('\n');
    Ok(out)
}

/// The Markdown preamble `techniques show`/`features show` prepends: a parameter
/// table (when the registry declares one) followed by the copy-paste example.
///
/// Shared by both registries, so a technique and a loader feature render their
/// parameters the same way.
pub(crate) fn params_markdown(params: &[ParamDef], example: &str) -> String {
    let mut out = String::new();
    if !params.is_empty() {
        out.push_str("## Parameters\n\n");
        out.push_str("| Parameter | Type | Required | Default | Description |\n");
        out.push_str("| --- | --- | --- | --- | --- |\n");
        for param in params {
            let required = if param.required { "yes" } else { "no" };
            let default = match param.default {
                Some(value) => format!("`{value}`"),
                None => "—".to_string(),
            };
            out.push_str(&format!(
                "| `{}` | {} | {} | {} | {} |\n",
                param.key,
                param.kind.label(),
                required,
                default,
                param.description,
            ));
        }
        out.push('\n');
    }
    if !example.trim().is_empty() {
        out.push_str("## Example\n\n```yaml\n");
        out.push_str(example.trim());
        out.push_str("\n```\n\n");
    }
    out
}

/// The README's `# ` title, when it has one.
pub(crate) fn readme_title(readme: &str) -> Option<&str> {
    readme
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("# "))
}

/// The color role of a maturity (shared with [`stability_label`]).
pub(crate) fn stability_tone(stability: Stability) -> Tone {
    match stability {
        Stability::Stable => Tone::Ok,
        Stability::Experimental => Tone::Warn,
        Stability::Unimplemented | Stability::Deprecated => Tone::Bad,
    }
}

/// Comma-joined capability labels for the `requires` field.
pub(crate) fn capabilities(requires: &[Capability]) -> String {
    requires
        .iter()
        .map(|capability| capability.label())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Drops the README's leading `# ` title and its `## Metadata` section, which
/// the styled header supersedes.
pub(crate) fn strip_header(readme: &str) -> String {
    let mut out = String::new();
    let mut in_metadata = false;
    for line in readme.lines() {
        if in_metadata {
            if line.starts_with("## ") {
                in_metadata = false;
            } else {
                continue;
            }
        }
        if out.is_empty() && line.starts_with("# ") {
            continue;
        }
        if line.trim() == "## Metadata" {
            in_metadata = true;
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
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
        for section in FORBIDDEN_SECTIONS {
            if def.readme.contains(section) {
                problems.push(format!(
                    "{}: README.md must not contain '{section}' — that data is rendered from the \
                     registry (TechniqueDef); keep the README prose-only",
                    def.name
                ));
            }
        }
        if !def.readme.contains("```mermaid") {
            problems.push(format!(
                "{}: README.md has no ```mermaid diagram (the 'How it works' section should open \
                 with one)",
                def.name
            ));
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
    // Loader features and SSN resolvers live in parallel registries; validate
    // them too.
    problems.extend(crate::features::validate());
    problems.extend(crate::engine::syscalls::resolvers::validate());
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
pub(crate) fn short_description(readme: &str) -> &str {
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
pub(crate) fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}
