//! Tests for the image-path-spoofing technique.

use super::{Params, DEF};
use crate::engine::obfuscation::StringsConfig;
use crate::techniques::TechniqueKind;

#[test]
fn parses_the_decoy_path() {
    let step: TechniqueKind = serde_yml::from_str(
        "technique: image_path_spoofing\nparams:\n  path: 'C:\\Windows\\System32\\svchost.exe'\n",
    )
    .expect("should parse");
    let TechniqueKind::ImagePathSpoofing { params } = step else {
        panic!("expected image_path_spoofing, got {step:?}");
    };
    assert_eq!(params.path, r"C:\Windows\System32\svchost.exe");
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "image_path_spoofing");
    assert_eq!(DEF.attck, &["T1036.005"]);
    assert_eq!(DEF.category, crate::techniques::Category::Preparation);
    assert_eq!(DEF.conflicts, &["self_deletion"]);
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
fn render_fragment_obfuscates_literals() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let params = Params {
        path: r"C:\Windows\System32\svchost.exe".to_string(),
    };
    let fragment = params.render_fragment(&strings);

    assert!(fragment.contains("fn image_path_spoofing"));
    assert!(fragment.contains(
        "const IMAGE_PATH_OFFSET: usize = if cfg!(target_arch = \"x86\") { 0x38 } else { 0x60 };"
    ));
    assert!(fragment.contains(
        "const UNICODE_STRING_BUFFER_OFFSET: usize = if cfg!(target_arch = \"x86\") { 0x04 } else { 0x08 };"
    ));
    for placeholder in [
        "$SPOOF_PATH_DEF$",
        "$MSG_PEB_FAILED$",
        "$MSG_PARAMS_FAILED$",
    ] {
        assert!(
            !fragment.contains(placeholder),
            "placeholder {placeholder} was not substituted"
        );
    }
    assert!(!fragment.contains(r"C:\Windows\System32\svchost.exe"));
    assert!(fragment.contains("crate::dec_xor"));
    assert!(
        crate::audit::strings::find_sensitive_literals_in_source(&fragment).is_empty(),
        "cleartext sensitive literal in the rendered fragment"
    );
}
