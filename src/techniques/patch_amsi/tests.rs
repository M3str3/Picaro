//! Tests for the AMSI patch technique.

use super::{Params, DEF};
use crate::engine::obfuscation::StringsConfig;
use crate::techniques::PipelineStep;

#[test]
fn parses_params_from_empty_yaml() {
    let step: PipelineStep =
        serde_yml::from_str("technique: patch_amsi\n").expect("patch_amsi should parse");
    assert_eq!(step, PipelineStep::PatchAmsi(Params {}));
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "patch_amsi");
    assert_eq!(DEF.attck, &["T1562.001"]);
    assert_eq!(DEF.category, crate::techniques::Category::Preparation);
    assert!(DEF.conflicts.is_empty());
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
    let fragment = Params {}.render_fragment(&strings);

    // The entry point is present, the placeholders are substituted, and the
    // runtime byte literals must not appear in cleartext.
    assert!(fragment.contains("fn patch_amsi"));
    assert!(!fragment.contains("AMSI_DLL_DEF"));
    assert!(!fragment.contains("AMSI_FUNC_DEF"));
    assert!(!fragment.contains("b\"amsi.dll"));
    assert!(!fragment.contains("b\"AmsiScanBuffer"));
    assert!(fragment.contains("crate::dec_xor"));
}
