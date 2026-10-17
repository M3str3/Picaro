//! Tests for the hide-module preparation.

use super::{Params, DEF};
use crate::audit::strings::find_sensitive_literals_in_source;
use crate::engine::obfuscation::StringsConfig;
use crate::techniques::{Category, TechniqueKind};

#[test]
fn parses_defaults() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: hide_module\n").expect("hide_module should parse");
    assert_eq!(
        step,
        TechniqueKind::HideModule {
            params: Params::default()
        }
    );
}

#[test]
fn parses_explicit_modules() {
    let step: TechniqueKind = serde_yml::from_str(
        r#"technique: hide_module
params:
  modules: ["payload.dll", "inject.dll"]
  hide_self: false
"#,
    )
    .expect("hide_module should parse");
    assert_eq!(
        step,
        TechniqueKind::HideModule {
            params: Params {
                modules: vec!["payload.dll".to_string(), "inject.dll".to_string()],
                hide_self: false,
            }
        }
    );
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "hide_module");
    assert_eq!(DEF.attck, &["T1014"]);
    assert_eq!(DEF.category, Category::Preparation);
    assert!(DEF.conflicts.is_empty());
    assert!(DEF.syscalls.is_empty());
    assert!(!DEF.stub_fragment.is_empty());
    assert!(!DEF.readme.is_empty());
}

#[test]
fn params_example_parses_as_a_runtime_step() {
    let step: TechniqueKind =
        serde_yml::from_str(DEF.params_example).expect("params_example should parse");
    assert_eq!(step.name(), "hide_module");
}

#[test]
fn fragment_has_no_forbidden_patterns() {
    for forbidden in [
        "println!",
        "eprintln!",
        "unwrap(",
        "expect(",
        "todo!",
        "unimplemented!",
        "panic!",
        "anyhow",
    ] {
        assert!(
            !DEF.stub_fragment.contains(forbidden),
            "stub_fragment.rs must not contain '{forbidden}'"
        );
    }
}

#[test]
fn render_fragment_obfuscates_literals() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params {
        modules: vec!["payload.dll".to_string()],
        hide_self: true,
    }
    .render_fragment(&strings);

    assert!(fragment.contains("fn hide_module"));
    assert!(
        !fragment.contains("payload.dll"),
        "the module name leaked in cleartext"
    );
    assert!(
        !fragment.contains('$'),
        "an unsubstituted placeholder is still in the fragment"
    );
    assert!(find_sensitive_literals_in_source(&fragment).is_empty());
}

#[test]
fn render_fragment_substitutes_hide_self() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let rendered = Params {
        modules: vec![],
        hide_self: false,
    }
    .render_fragment(&strings);

    assert!(rendered.contains("let hide_self: bool = false;"));
    assert!(rendered.contains("let modules: Vec<String> = vec![];"));
    assert!(!rendered.contains('$'));
}
