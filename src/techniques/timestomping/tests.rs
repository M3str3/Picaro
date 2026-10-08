//! Tests for the timestomping preparation.

use super::{Params, DEF};
use crate::audit::strings::find_sensitive_literals_in_source;
use crate::engine::obfuscation::StringsConfig;
use crate::techniques::{Category, TechniqueKind};

#[test]
fn parses_minimal_yaml_with_reference_only() {
    let step: TechniqueKind = serde_yml::from_str(
        r#"technique: timestomping
params:
  reference: "C:\\Windows\\System32\\kernel32.dll"
"#,
    )
    .expect("timestomping should parse");
    assert_eq!(
        step,
        TechniqueKind::Timestomping {
            params: Params {
                target: None,
                reference: "C:\\Windows\\System32\\kernel32.dll".to_string(),
            }
        }
    );
}

#[test]
fn parses_explicit_target() {
    let step: TechniqueKind = serde_yml::from_str(
        r#"technique: timestomping
params:
  target: "C:\\Windows\\System32\\notepad.exe"
  reference: "C:\\Windows\\System32\\kernel32.dll"
"#,
    )
    .expect("timestomping should parse");
    assert_eq!(
        step,
        TechniqueKind::Timestomping {
            params: Params {
                target: Some("C:\\Windows\\System32\\notepad.exe".to_string()),
                reference: "C:\\Windows\\System32\\kernel32.dll".to_string(),
            }
        }
    );
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "timestomping");
    assert_eq!(DEF.attck, &["T1070.006"]);
    assert_eq!(DEF.category, Category::Preparation);
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
        target: None,
        reference: "C:\\Windows\\System32\\kernel32.dll".to_string(),
    }
    .render_fragment(&strings);

    assert!(fragment.contains("fn timestomping"));
    assert!(!fragment.contains('$'));
    assert!(find_sensitive_literals_in_source(&fragment).is_empty());
}

#[test]
fn render_fragment_bakes_in_the_target() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params {
        target: Some("C:\\Windows\\System32\\notepad.exe".to_string()),
        reference: "C:\\Windows\\System32\\kernel32.dll".to_string(),
    }
    .render_fragment(&strings);

    assert!(fragment.contains("let target: Option<String> = Some("));
    assert!(!fragment.contains('$'));
    assert!(find_sensitive_literals_in_source(&fragment).is_empty());
}
