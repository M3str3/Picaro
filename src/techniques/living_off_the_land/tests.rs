//! Tests for the living-off-the-land technique.

use super::{Params, DEF};
use crate::engine::obfuscation::StringsConfig;
use crate::plan::schema::WindowMode;
use crate::techniques::TechniqueKind;

#[test]
fn defaults_are_a_hidden_waiting_launch() {
    let params = Params::default();
    assert!(params.binary.is_empty());
    assert!(params.args.is_empty());
    assert_eq!(params.window, WindowMode::Hidden);
    assert!(params.wait);
    assert_eq!(params.timeout_s, 0);
    assert!(super::default_wait());
}

#[test]
fn params_example_parses_as_a_runtime_step() {
    let step: TechniqueKind =
        serde_yml::from_str(DEF.params_example).expect("params_example should parse");
    assert_eq!(step.name(), "living_off_the_land");
}

#[test]
fn render_fragment_substitutes_every_placeholder() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let params = Params {
        binary: "certutil.exe".to_string(),
        args: vec!["-urlcache".to_string(), "-f".to_string()],
        timeout_s: 30,
        ..Params::default()
    };
    let fragment = params.render_fragment(&strings);

    assert!(fragment.contains("fn run_exec"));
    for placeholder in [
        "$BINARY_DEF$",
        "$ARGS_DEF$",
        "$FLAGS$",
        "$WAIT$",
        "$TIMEOUT_MS$",
    ] {
        assert!(
            !fragment.contains(placeholder),
            "placeholder {placeholder} was not substituted"
        );
    }
    assert!(
        !fragment.contains('$'),
        "an unsubstituted placeholder is still in the fragment"
    );
    assert!(fragment.contains("30000u32"));
    assert!(fragment.contains("CREATE_NO_WINDOW"));
}

#[test]
fn detached_and_limited_modes_are_rendered() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");

    let detached = Params {
        binary: "cmd.exe".to_string(),
        window: WindowMode::Normal,
        wait: false,
        ..Params::default()
    }
    .render_fragment(&strings);
    assert!(detached.contains("PROCESS_CREATION_FLAGS(0)"));
    assert!(detached.contains("if false"));

    let limited = Params {
        binary: "cmd.exe".to_string(),
        ..Params::default()
    }
    .render_fragment(&strings);
    assert!(limited.contains("0u32"));
}

#[test]
fn render_fragment_obfuscates_the_binary_and_args() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let params = Params {
        binary: "certutil.exe".to_string(),
        args: vec!["-urlcache".to_string()],
        ..Params::default()
    };
    let fragment = params.render_fragment(&strings);

    assert!(
        !fragment.contains("certutil.exe"),
        "binary leaked in cleartext"
    );
    assert!(!fragment.contains("-urlcache"), "arg leaked in cleartext");
    assert!(fragment.contains("crate::dec_xor"));
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "living_off_the_land");
    assert_eq!(DEF.attck, &["T1218", "T1105"]);
    assert_eq!(DEF.category, crate::techniques::Category::Control);
    assert!(DEF.conflicts.is_empty());
    assert!(!DEF.stub_fragment.is_empty());
    assert!(!DEF.readme.is_empty());
}
