//! Tests for the process-mitigation technique.

use super::{Params, DEF};
use crate::engine::obfuscation::StringsConfig;
use crate::techniques::TechniqueKind;

#[test]
fn parses_params_from_empty_yaml_and_enables_the_default_policies() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: process_mitigations\n").expect("should parse");
    assert_eq!(
        step,
        TechniqueKind::ProcessMitigations {
            params: Params {
                block_dlls: true,
                extension_points: true,
                win32k_filter: false,
            }
        }
    );
}

#[test]
fn parses_explicit_flags() {
    let step: TechniqueKind = serde_yml::from_str(
        "technique: process_mitigations\nparams:\n  block_dlls: false\n  extension_points: false\n  win32k_filter: true\n",
    )
    .expect("should parse");
    assert_eq!(
        step,
        TechniqueKind::ProcessMitigations {
            params: Params {
                block_dlls: false,
                extension_points: false,
                win32k_filter: true,
            }
        }
    );
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "process_mitigations");
    assert_eq!(DEF.attck, &["T1562.001"]);
    assert_eq!(DEF.category, crate::techniques::Category::Preparation);
    assert!(DEF.conflicts.is_empty());
    assert!(DEF.syscalls.is_empty());
    assert!(DEF.formats.is_empty());
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
fn render_fragment_bakes_in_the_selected_policies_and_obfuscates_literals() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params::default().render_fragment(&strings);

    assert!(fragment.contains("fn process_mitigations"));
    assert!(fragment.contains("const BLOCK_DLLS: bool = true;"));
    assert!(fragment.contains("const EXTENSION_POINTS: bool = true;"));
    assert!(fragment.contains("const WIN32K_FILTER: bool = false;"));
    for placeholder in [
        "$BLOCK_DLLS$",
        "$EXTENSION_POINTS$",
        "$WIN32K_FILTER$",
        "$MSG_BLOCK_DLLS_FAILED$",
    ] {
        assert!(
            !fragment.contains(placeholder),
            "placeholder {placeholder} was not substituted"
        );
    }
    assert!(fragment.contains("crate::tech_dbg!"));
    assert!(
        crate::audit::strings::find_sensitive_literals_in_source(&fragment).is_empty(),
        "cleartext sensitive literal in the rendered fragment"
    );
}

#[test]
fn render_fragment_bakes_in_the_alternate_selection() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params {
        block_dlls: false,
        extension_points: false,
        win32k_filter: true,
    }
    .render_fragment(&strings);
    assert!(fragment.contains("const BLOCK_DLLS: bool = false;"));
    assert!(fragment.contains("const EXTENSION_POINTS: bool = false;"));
    assert!(fragment.contains("const WIN32K_FILTER: bool = true;"));
}
