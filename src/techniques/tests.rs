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

/// Every registered technique must have a docs page. The site sidebar and the
/// `docs/techniques/index.md` overview table are generated from this registry
/// at assemble time (see `docs/site/scripts/assemble-docs.mjs`), so they
/// cannot drift and need no per-technique nav or overview entry.
#[test]
fn every_technique_is_documented() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for def in all() {
        let docs_page = format!("docs/techniques/ref/{}.md", def.name);
        assert!(
            root.join(&docs_page).is_file(),
            "{}: missing docs page '{docs_page}'",
            def.name
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
fn show_renders_metadata_and_readme() {
    let page = show("process_hollowing", &Palette::plain()).expect("known technique");
    assert!(page.contains("Process hollowing"), "page: {page}");
    assert!(page.contains("T1055"), "page: {page}");
    // The README body is rendered, not dumped raw.
    assert!(page.contains("What it does"), "page: {page}");
    assert!(!page.contains("## Metadata"), "page: {page}");
    assert!(!page.contains('\u{1b}'), "escapes leaked: {page:?}");
}

#[test]
fn readme_is_verbatim() {
    let raw = readme("process_hollowing").expect("known technique");
    assert!(raw.contains("# Process hollowing"));
    assert!(raw.contains("## What it does"));
}

#[test]
fn unknown_technique_is_an_error() {
    assert!(show("does_not_exist", &Palette::plain()).is_err());
    assert!(readme("does_not_exist").is_err());
}

/// Smoke test: the renderer survives every real README and keeps its
/// required section.
#[test]
fn show_pages_every_technique() {
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

/// Technique keys are matched ignoring case and underscores, so a plan is
/// free to name a step `ReflectiveLoading`, `reflectiveloading` or
/// `REFLECTIVE_loading` while the registry keeps one canonical spelling.
#[test]
fn technique_names_ignore_case_and_underscores() {
    let canonical = canonical_name("reflective_loading").expect("canonical name");
    assert_eq!(canonical, "reflective_loading");
    for alias in [
        "reflectiveloading",
        "REFLECTIVEloading",
        "ReflectiveLoading",
        "Reflective_Loading",
        "REFLECTIVE_LOADING",
    ] {
        assert_eq!(
            canonical_name(alias),
            Some("reflective_loading"),
            "{alias} must resolve to reflective_loading"
        );
        assert_eq!(find(alias).map(|def| def.name), Some("reflective_loading"));
    }
    assert_eq!(canonical_name("no_such_technique"), None);
}

/// A technique fragment must not declare a `thiserror` diagnostic: its
/// `#[error("...")]` literals reach the generated stub in cleartext.
///
/// Every diagnostic must be rebuilt at runtime through `StringsConfig` (the
/// `MESSAGES` pattern in `process_hollowing`/`fibers`/...). This is the
/// source-level counterpart of the compiled-stub guardrail
/// (`no_sensitive_literals_in_generated_stubs`), and it runs without rustc.
#[test]
fn no_fragment_declares_a_cleartext_diagnostic() {
    let fragments = all()
        .iter()
        .map(|def| (def.name, def.stub_fragment))
        .chain(std::iter::once((
            "reflective_loading (shellcode)",
            reflective_loading::SHELLCODE_FRAGMENT,
        )));
    for (name, fragment) in fragments {
        assert!(
            !fragment.contains("thiserror::Error"),
            "technique '{name}' derives a thiserror diagnostic"
        );
        assert!(
            !fragment.contains("#[error("),
            "technique '{name}' declares a cleartext `#[error(...)]` diagnostic"
        );
    }
}
