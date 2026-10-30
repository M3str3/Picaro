use super::*;

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
fn a_delivered_path_is_exact_and_a_directory_gets_the_default_name() {
    assert_eq!(
        resolve_delivered_path(Path::new("deliver/loader.exe"), "demo", OutputKind::Exe),
        PathBuf::from("deliver/loader.exe")
    );
    assert_eq!(
        resolve_delivered_path(Path::new("deliver/"), "demo", OutputKind::Exe),
        PathBuf::from("deliver/demo.exe")
    );
}

#[test]
fn a_build_name_that_is_a_path_is_rejected() {
    for name in ["", "   ", ".", "..", "a/b", "a\\b", "C:"] {
        assert!(
            bare_dir_component(name).is_err(),
            "{name:?} must be rejected as a build name"
        );
    }
}

#[test]
fn shellcode_intermediates_keep_a_neutral_name() {
    let path = intermediate_path(
        Path::new("/build"),
        OutputKind::Shellcode,
        "xenon-stage.bin",
    );
    assert_eq!(path, Path::new("/build").join("out.dll"));
}

#[test]
fn dll_intermediates_follow_the_delivered_name() {
    let path = intermediate_path(Path::new("/build"), OutputKind::Dll, "metrics.dll");
    assert_eq!(path, Path::new("/build").join("metrics.dll"));
}

#[test]
fn an_exe_intermediate_stays_anonymous() {
    let path = intermediate_path(Path::new("/build"), OutputKind::Exe, "metrics.exe");
    assert_eq!(path, Path::new("/build").join("out.exe"));
}
