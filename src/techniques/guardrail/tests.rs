//! Tests for the guardrail preparation.

use super::{Params, DEF};
use crate::audit::strings::find_sensitive_literals_in_source;
use crate::engine::obfuscation::StringsConfig;
use crate::techniques::{Category, Stability, TechniqueKind};

#[test]
fn parses_minimal_yaml_and_defaults_to_no_gate() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: guardrail\n").expect("guardrail should parse");
    assert_eq!(
        step,
        TechniqueKind::Guardrail {
            params: Params {
                expire_on: None,
                max_runs: None,
                run_key: "runs".to_string(),
            }
        }
    );
}

#[test]
fn parses_explicit_gates() {
    let step: TechniqueKind = serde_yml::from_str(
        "technique: guardrail\nparams:\n  expire_on: \"2027-01-01\"\n  max_runs: 3\n",
    )
    .expect("guardrail should parse");
    assert_eq!(
        step,
        TechniqueKind::Guardrail {
            params: Params {
                expire_on: Some("2027-01-01".to_string()),
                max_runs: Some(3),
                run_key: "runs".to_string(),
            }
        }
    );
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "guardrail");
    assert_eq!(DEF.attck, &["T1480"]);
    assert_eq!(DEF.category, Category::Preparation);
    assert_eq!(DEF.stability, Stability::Stable);
    assert!(DEF.conflicts.is_empty());
    assert!(DEF.syscalls.is_empty());
    assert!(!DEF.stub_fragment.is_empty());
    assert!(!DEF.readme.is_empty());
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
fn render_fragment_has_no_placeholders_or_sensitive_literals() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params {
        expire_on: Some("2027-01-01".to_string()),
        max_runs: Some(3),
        run_key: "runs".to_string(),
    }
    .render_fragment(&strings);

    assert!(fragment.contains("fn guardrail"));
    assert!(!fragment.contains('$'));
    assert!(find_sensitive_literals_in_source(&fragment).is_empty());
}
