//! Tests for the ETW patch technique.

use super::{Params, DEF};
use crate::audit::strings::find_sensitive_literals_in_source;
use crate::engine::obfuscation::StringsConfig;
use crate::techniques::{Category, RuntimeStep};

#[test]
fn parses_params_from_empty_yaml_and_defaults_full_to_true() {
    let step: RuntimeStep =
        serde_yml::from_str("technique: patch_etw\n").expect("patch_etw should parse");
    assert_eq!(
        step,
        RuntimeStep::PatchEtw {
            params: Params { full: true }
        }
    );
}

#[test]
fn parses_explicit_full_false() {
    let step: RuntimeStep = serde_yml::from_str("technique: patch_etw\nparams:\n  full: false\n")
        .expect("patch_etw should parse");
    assert_eq!(
        step,
        RuntimeStep::PatchEtw {
            params: Params { full: false }
        }
    );
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "patch_etw");
    assert_eq!(DEF.attck, &["T1562.006"]);
    assert_eq!(DEF.category, Category::Preparation);
    assert!(DEF.conflicts.is_empty());
    assert_eq!(DEF.syscalls, &["NtProtectVirtualMemory"]);
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
fn render_fragment_obfuscates_literals_and_enables_full() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params { full: true }.render_fragment(&strings);

    // The entry point is present and every placeholder is substituted.
    assert!(fragment.contains("fn patch_etw"));
    assert!(fragment.contains("const PATCH_FULL: bool = true;"));
    for placeholder in [
        "$ETW_DLL_DEF$",
        "$ETW_FUNC_DEF$",
        "$ETW_FULL_FUNC_DEF$",
        "$PATCH_FULL$",
    ] {
        assert!(
            !fragment.contains(placeholder),
            "placeholder {placeholder} was not substituted"
        );
    }

    // No sensitive literal survives in code (the guardrail ignores comments,
    // which *do* name the functions).
    assert!(
        find_sensitive_literals_in_source(&fragment).is_empty(),
        "cleartext sensitive literal in the rendered fragment"
    );
    assert!(fragment.contains("crate::dec_xor"));
}

#[test]
fn render_fragment_disables_full_when_requested() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params { full: false }.render_fragment(&strings);
    assert!(fragment.contains("const PATCH_FULL: bool = false;"));
}
