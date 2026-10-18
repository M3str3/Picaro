//! Tests for the drop technique.

use super::{Params, DEF};
use crate::audit::strings::find_sensitive_literals_in_source;
use crate::engine::obfuscation::{StringStrategy, StringsConfig};
use crate::techniques::TechniqueKind;

fn xor_strings() -> StringsConfig {
    StringsConfig::from_yaml(None).expect("default strings")
}

fn stack_strings() -> StringsConfig {
    StringsConfig {
        strategy: StringStrategy::Stack,
        key: None,
    }
}

/// The fully-populated parameter set, extracted from `DEF.params_example`.
fn full_params() -> Params {
    let step: TechniqueKind =
        serde_yml::from_str(DEF.params_example).expect("the params example must parse");
    let TechniqueKind::Drop { params } = step else {
        panic!("the params example must be a drop step");
    };
    params
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "drop");
    assert_eq!(DEF.attck, &["T1027.009"]);
    assert_eq!(DEF.category, crate::techniques::Category::Preparation);
    assert_eq!(DEF.stability, crate::techniques::Stability::Experimental);
    assert!(DEF.conflicts.is_empty());
    assert!(!DEF.stub_fragment.is_empty());
    assert!(!DEF.readme.is_empty());
}

#[test]
fn params_example_parses() {
    let params = full_params();
    assert_eq!(params.path, "TEST.docx");
    assert_eq!(params.payload.as_deref(), Some("decoy_doc"));
}

#[test]
fn params_default_to_an_empty_path() {
    let step: TechniqueKind = serde_yml::from_str("technique: drop\n").expect("drop should parse");
    let TechniqueKind::Drop { params } = step else {
        panic!("expected a drop step");
    };
    assert_eq!(params, Params::default());
    assert!(params.path.is_empty());
    assert!(params.payload.is_none());
}

#[test]
fn render_fragment_substitutes_every_placeholder() {
    let fragment = full_params().render_fragment(&xor_strings());
    assert!(
        !fragment.contains('$'),
        "an unsubstituted placeholder would break the stub"
    );
    assert!(fragment.contains("pub fn drop()"));
    assert!(fragment.contains("asset_bytes()"));
}

#[test]
fn render_fragment_obfuscates_the_path() {
    for strings in [xor_strings(), stack_strings()] {
        let fragment = full_params().render_fragment(&strings);
        let code = crate::audit::strings::strip_comments(&fragment);
        assert!(
            !code.contains("TEST.docx"),
            "the path leaked in cleartext with strategy {}",
            strings.strategy.label()
        );
    }
}

#[test]
fn rendered_fragment_has_no_sensitive_literals() {
    let fragment = full_params().render_fragment(&xor_strings());
    let leaked = find_sensitive_literals_in_source(&fragment);
    assert!(
        leaked.is_empty(),
        "the rendered fragment leaks sensitive literals: {leaked:?}"
    );
}

#[test]
fn fragment_has_no_forbidden_patterns() {
    for forbidden in [
        "println!",
        "eprintln!",
        "unwrap",
        "expect",
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
