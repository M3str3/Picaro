//! Tests for the sleep technique.

use super::{Params, DEF};
use crate::engine::obfuscation::StringsConfig;

#[test]
fn default_duration_is_one_second() {
    assert_eq!(Params::default().ms, 1000);
    assert_eq!(super::default_ms(), 1000);
}

#[test]
fn parses_duration_from_yaml() {
    let params: Params = serde_yml::from_str("ms: 5").expect("ms should parse");
    assert_eq!(params.ms, 5);
}

#[test]
fn empty_yaml_uses_the_default_duration() {
    let params: Params = serde_yml::from_str("{}").expect("empty mapping should parse");
    assert_eq!(params.ms, 1000);
}

#[test]
fn render_fragment_substitutes_the_duration() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params { ms: 250 }.render_fragment(&strings);

    assert!(fragment.contains("fn run_sleep"));
    assert!(
        !fragment.contains("$MS$"),
        "placeholder was not substituted"
    );
    assert!(fragment.contains("from_millis(250)"));
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "sleep");
    assert_eq!(DEF.attck, &["T1497"]);
    assert_eq!(DEF.category, crate::techniques::Category::Control);
    assert!(DEF.conflicts.is_empty());
    assert!(!DEF.stub_fragment.is_empty());
    assert!(!DEF.readme.is_empty());
}
