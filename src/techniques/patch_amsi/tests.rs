//! Tests for the AMSI patch technique.

use super::{Params, DEF};
use crate::engine::obfuscation::StringsConfig;
use crate::techniques::TechniqueKind;

#[test]
fn parses_params_from_empty_yaml_and_enables_every_variant() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: patch_amsi\n").expect("patch_amsi should parse");
    assert_eq!(
        step,
        TechniqueKind::PatchAmsi {
            params: Params {
                scan_string: true,
                open_session: true,
            }
        }
    );
}

#[test]
fn parses_explicit_variants_false() {
    let step: TechniqueKind = serde_yml::from_str(
        "technique: patch_amsi\nparams:\n  scan_string: false\n  open_session: false\n",
    )
    .expect("patch_amsi should parse");
    assert_eq!(
        step,
        TechniqueKind::PatchAmsi {
            params: Params {
                scan_string: false,
                open_session: false,
            }
        }
    );
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
    let fragment = Params::default().render_fragment(&strings);

    // The entry point is present, the placeholders are substituted, and the
    // runtime byte literals must not appear in cleartext.
    assert!(fragment.contains("fn patch_amsi"));
    assert!(fragment.contains("const PATCH_SCAN_STRING: bool = true;"));
    assert!(fragment.contains("const PATCH_OPEN_SESSION: bool = true;"));
    for placeholder in [
        "$AMSI_DLL_DEF$",
        "$AMSI_FUNC_DEF$",
        "$AMSI_SCAN_STRING_FUNC_DEF$",
        "$AMSI_OPEN_SESSION_FUNC_DEF$",
        "$PATCH_SCAN_STRING$",
        "$PATCH_OPEN_SESSION$",
    ] {
        assert!(
            !fragment.contains(placeholder),
            "placeholder {placeholder} was not substituted"
        );
    }
    assert!(!fragment.contains("b\"amsi.dll"));
    assert!(!fragment.contains("b\"AmsiScanBuffer"));
    assert!(!fragment.contains("b\"AmsiScanString"));
    assert!(!fragment.contains("b\"AmsiOpenSession"));
    assert!(fragment.contains("crate::dec_xor"));
    assert!(
        crate::audit::strings::find_sensitive_literals_in_source(&fragment).is_empty(),
        "cleartext sensitive literal in the rendered fragment"
    );
}

#[test]
fn render_fragment_disables_the_optional_variants() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params {
        scan_string: false,
        open_session: false,
    }
    .render_fragment(&strings);
    assert!(fragment.contains("const PATCH_SCAN_STRING: bool = false;"));
    assert!(fragment.contains("const PATCH_OPEN_SESSION: bool = false;"));
}
