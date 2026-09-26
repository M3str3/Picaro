//! Tests for the anti-debug preparation.

use super::{Action, Params, DEF};
use crate::audit::strings::find_sensitive_literals_in_source;
use crate::engine::obfuscation::StringsConfig;
use crate::techniques::{Category, RuntimeStep};

#[test]
fn parses_params_from_empty_yaml_and_defaults_to_abort() {
    let step: RuntimeStep =
        serde_yml::from_str("technique: anti_debug\n").expect("anti_debug should parse");
    assert_eq!(
        step,
        RuntimeStep::AntiDebug {
            params: Params {
                action: Action::Abort
            }
        }
    );
}

#[test]
fn parses_explicit_continue() {
    let step: RuntimeStep =
        serde_yml::from_str("technique: anti_debug\nparams:\n  action: continue\n")
            .expect("anti_debug should parse");
    assert_eq!(
        step,
        RuntimeStep::AntiDebug {
            params: Params {
                action: Action::Continue
            }
        }
    );
}

#[test]
fn rejects_an_unknown_action() {
    let err =
        serde_yml::from_str::<RuntimeStep>("technique: anti_debug\nparams:\n  action: nope\n")
            .expect_err("an unknown action must be rejected");
    assert!(
        err.to_string().contains("unknown variant") && err.to_string().contains("abort"),
        "unclear error: {err}"
    );
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "anti_debug");
    assert_eq!(DEF.attck, &["T1622"]);
    assert_eq!(DEF.category, Category::Preparation);
    assert!(DEF.conflicts.is_empty());
    assert_eq!(
        DEF.syscalls,
        &["NtQueryInformationProcess", "NtGetContextThread"]
    );
    assert!(!DEF.stub_fragment.is_empty());
    assert!(!DEF.readme.is_empty());
}

#[test]
fn fragment_has_no_forbidden_patterns() {
    for forbidden in [
        "println!",
        "unwrap",
        "expect",
        "todo!",
        "unimplemented!",
        "anyhow",
        "panic!",
    ] {
        assert!(
            !DEF.stub_fragment.contains(forbidden),
            "stub_fragment.rs must not contain '{forbidden}'"
        );
    }
}

#[test]
fn render_fragment_bakes_in_abort() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params {
        action: Action::Abort,
    }
    .render_fragment(&strings);

    assert!(fragment.contains("fn anti_debug"));
    assert!(fragment.contains("const ABORT_ON_DETECT: bool = true;"));
    assert!(!fragment.contains("$ABORT_ON_DETECT$"));
    assert!(find_sensitive_literals_in_source(&fragment).is_empty());
}

#[test]
fn render_fragment_bakes_in_continue() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params {
        action: Action::Continue,
    }
    .render_fragment(&strings);
    assert!(fragment.contains("const ABORT_ON_DETECT: bool = false;"));
}
