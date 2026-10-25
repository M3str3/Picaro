use super::*;

#[test]
fn package_paths_puts_a_build_in_a_plan_folder() {
    assert_eq!(
        package_paths("full-evasion", Path::new("dist/full-evasion.exe")),
        (
            PathBuf::from("dist/full-evasion"),
            PathBuf::from("dist/full-evasion/full-evasion.exe")
        )
    );
}

#[test]
fn package_paths_keeps_an_existing_plan_folder() {
    assert_eq!(
        package_paths("calc", Path::new("packed/calc/calc.exe")),
        (
            PathBuf::from("packed/calc"),
            PathBuf::from("packed/calc/calc.exe")
        )
    );
}

#[test]
fn package_paths_defaults_to_packed_for_a_bare_filename() {
    assert_eq!(
        package_paths("calc", Path::new("calc.exe")),
        (
            PathBuf::from("packed/calc"),
            PathBuf::from("packed/calc/calc.exe")
        )
    );
}

#[test]
fn package_dir_names_cannot_escape_their_parent() {
    let (package, artifact) = package_paths("../evil", Path::new("dist/loader.exe"));
    assert_eq!(package, PathBuf::from("dist/_evil"));
    assert_eq!(artifact, PathBuf::from("dist/_evil/loader.exe"));
}

#[test]
fn console_subsystem_leaves_the_source_untouched() {
    let source = "fn main() {}\n".to_string();
    assert_eq!(apply_subsystem(source.clone(), Subsystem::Console), source);
}

#[test]
fn windows_subsystem_prepends_the_attribute() {
    let source = "fn main() {}\n".to_string();
    let out = apply_subsystem(source, Subsystem::Windows);
    assert!(out.starts_with("#![windows_subsystem = \"windows\"]\n"));
    assert!(out.ends_with("fn main() {}\n"));
}

#[test]
fn an_existing_subsystem_attribute_is_not_duplicated() {
    let source = "#![windows_subsystem = \"console\"]\nfn main() {}\n".to_string();
    let out = apply_subsystem(source.clone(), Subsystem::Windows);
    assert_eq!(out, source, "a stub that sets its own subsystem wins");
}

fn proxy_config(body: &str) -> api_resolution::ApiResolutionConfig {
    let yaml: api_resolution::YamlApiResolutionPlan = serde_yml::from_str(body).expect("yaml");
    api_resolution::ApiResolutionConfig::from_yaml(Some(&yaml)).expect("valid")
}

#[test]
fn identifier_matching_rejects_substring_hits() {
    assert!(mentions_identifier(
        "OpenProcessToken()",
        "OpenProcessToken"
    ));
    assert!(!mentions_identifier("OpenProcessToken()", "OpenProcess"));
    assert!(!mentions_identifier(
        "MyOpenProcessToken",
        "OpenProcessToken"
    ));
}

#[test]
fn an_active_technique_import_exempts_its_api_from_the_proxy_audit() {
    let config = proxy_config("mode: proxy\napis: all\n");
    let bouncer = ResolvedStep {
        index: 0,
        label: "bouncer".to_string(),
        technique: TechniqueKind::Bouncer {
            params: techniques::bouncer::Params::default(),
        },
        payload: None,
        control: plan::schema::StepControl::default(),
    };

    let exempt = technique_imported_functions(&[bouncer], &config.apis);
    assert!(exempt.contains("OpenProcessToken"));
    // `OpenProcess` is not exempted by `OpenProcessToken`.
    assert!(!exempt.contains("OpenProcess"));
}

#[test]
fn no_active_technique_exempts_nothing() {
    let config = proxy_config("mode: proxy\napis: all\n");
    assert!(technique_imported_functions(&[], &config.apis).is_empty());
}

#[test]
fn short_thumbprint_keeps_the_first_16_digits() {
    assert_eq!(short_thumbprint("DEADBEEF00112233AABB"), "DEADBEEF00112233");
}

#[test]
fn scratch_dir_defaults_to_build_next_to_the_manifest() {
    let dir = scratch_dir_in(None, Path::new("/usr/src/picaro"));
    assert_eq!(dir, Path::new("/usr/src/picaro/build"));
}

#[test]
fn scratch_dir_honors_the_picaro_build_dir_override() {
    let dir = scratch_dir_in(
        Some(PathBuf::from("/tmp/picaro-build")),
        Path::new("/usr/src/picaro"),
    );
    assert_eq!(dir, Path::new("/tmp/picaro-build"));
}

#[test]
fn an_empty_scratch_override_falls_back_to_the_default() {
    let dir = scratch_dir_in(Some(PathBuf::new()), Path::new("/usr/src/picaro"));
    assert_eq!(dir, Path::new("/usr/src/picaro/build"));
}

#[test]
fn unique_scratch_dirs_differ_across_nonces() {
    let first = unique_scratch_dir_in(Path::new("/usr/src/picaro"), "1-100");
    let second = unique_scratch_dir_in(Path::new("/usr/src/picaro"), "2-200");
    assert_ne!(first, second, "each run must get its own scratch directory");
}

#[test]
fn unique_scratch_dir_lives_in_a_run_folder_under_build() {
    let dir = unique_scratch_dir_in(Path::new("/usr/src/picaro"), "42-123");
    assert_eq!(dir, Path::new("/usr/src/picaro/build/run-42-123"));
}

#[test]
fn shellcode_intermediates_keep_a_neutral_name() {
    let output: plan::schema::OutputPlan =
        serde_yml::from_str("path: dist/xenon-stage.bin\nkind: shellcode\n").expect("output plan");
    let path = intermediate_path(Path::new("/build"), &output);
    assert_eq!(path, Path::new("/build").join("out.dll"));
}

#[test]
fn dll_intermediates_follow_the_delivered_name() {
    let output: plan::schema::OutputPlan =
        serde_yml::from_str("path: dist/metrics.dll\nkind: dll\n").expect("output plan");
    let path = intermediate_path(Path::new("/build"), &output);
    assert_eq!(path, Path::new("/build").join("metrics.dll"));
}

#[test]
fn a_build_name_pins_the_scratch_dir_under_build() {
    let dir = scratch_dir_for(None, Path::new("/usr/src/picaro"), Some("debug"))
        .expect("a bare name is accepted");
    assert_eq!(dir, Path::new("/usr/src/picaro/build/debug"));
}

#[test]
fn a_build_name_stacks_on_top_of_the_picaro_build_dir_override() {
    let dir = scratch_dir_for(
        Some(PathBuf::from("/tmp/picaro-build")),
        Path::new("/usr/src/picaro"),
        Some("debug"),
    )
    .expect("a bare name is accepted");
    assert_eq!(dir, Path::new("/tmp/picaro-build/debug"));
}

#[test]
fn without_a_build_name_the_override_dir_is_kept_verbatim() {
    let dir = scratch_dir_for(
        Some(PathBuf::from("/tmp/picaro-build")),
        Path::new("/usr/src/picaro"),
        None,
    )
    .expect("no name, no error");
    assert_eq!(dir, Path::new("/tmp/picaro-build"));
}

#[test]
fn a_build_name_that_is_a_path_is_rejected() {
    for name in ["", "   ", ".", "..", "a/b", "a\\b", "C:"] {
        assert!(
            scratch_dir_for(None, Path::new("/usr/src/picaro"), Some(name)).is_err(),
            "{name:?} must be rejected as a build name"
        );
    }
}
