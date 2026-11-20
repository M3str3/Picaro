//! Tests for process ghosting.

use super::{Params, DEF, MESSAGES};
use crate::audit::strings::find_sensitive_literals_in_source;
use crate::engine::obfuscation::{StringStrategy, StringsConfig};
use crate::plan::schema::PayloadFormat;
use crate::techniques::{Category, Stability, TechniqueKind};

/// An XOR-obfuscation config, so the rendered fragment can be checked for the
/// runtime decoder the substitutions must use.
fn xor_strings() -> StringsConfig {
    StringsConfig {
        strategy: StringStrategy::Xor,
        key: Some([0x5Au8; 32]),
    }
}

/// Every `$...$` token in a fragment, in order.
fn placeholders(fragment: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = fragment;
    while let Some(start) = rest.find('$') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('$') else {
            break;
        };
        found.push(rest[start..start + 2 + end].to_string());
        rest = &after[end + 1..];
    }
    found
}

#[test]
fn parses_params_from_empty_yaml() {
    let step: TechniqueKind = serde_yml::from_str("technique: process_ghosting\n")
        .expect("process_ghosting should parse");
    assert_eq!(
        step,
        TechniqueKind::ProcessGhosting {
            params: Params::default()
        }
    );
}

#[test]
fn parses_a_payload() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: process_ghosting\nparams:\n  payload: implant\n")
            .expect("process_ghosting with a payload should parse");
    match step {
        TechniqueKind::ProcessGhosting { params } => {
            assert_eq!(params.payload.as_deref(), Some("implant"));
        }
        other => panic!("expected process_ghosting, got {other:?}"),
    }
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "process_ghosting");
    assert_eq!(DEF.attck, &["T1055.012"]);
    assert_eq!(DEF.category, Category::Execution);
    assert_eq!(DEF.stability, Stability::Experimental);
    assert!(!DEF.requires.is_empty());
    assert!(!DEF.stub_fragment.is_empty());
    assert!(!DEF.readme.is_empty());
    // The image section and its mapping are ntdll exports called directly, not
    // helpers of the indirect syscall layer, so the technique adds nothing there.
    assert!(
        DEF.syscalls.is_empty(),
        "unexpected syscalls: {:?}",
        DEF.syscalls
    );
}

#[test]
fn def_exposes_the_execution_entry_point() {
    assert!(
        DEF.stub_fragment.contains("fn execute_payload"),
        "the fragment must define the Execution contract"
    );
}

#[test]
fn fragment_has_no_forbidden_patterns() {
    for forbidden in [
        "println!",
        "eprintln!",
        "unwrap",
        "expect",
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

/// Every `$MSG_*$` the fragment uses must have an entry in `MESSAGES`; a typo
/// there would only show up as an unsubstituted token in a generated stub.
#[test]
fn messages_cover_every_fragment_placeholder() {
    let declared: Vec<&str> = MESSAGES
        .iter()
        .map(|(placeholder, _)| *placeholder)
        .collect();
    for placeholder in placeholders(DEF.stub_fragment) {
        if placeholder.starts_with("$MSG_") {
            assert!(
                declared.contains(&placeholder.as_str()),
                "'{placeholder}' has no MESSAGES entry"
            );
        }
    }
}

#[test]
fn render_fragment_for_substitutes_every_placeholder() {
    let fragment = Params::default().render_fragment_for(&xor_strings(), PayloadFormat::Pe, None);

    assert!(fragment.contains("fn execute_payload"));
    assert!(
        placeholders(&fragment).is_empty(),
        "unsubstituted placeholder(s): {:?}",
        placeholders(&fragment)
    );
    assert!(
        find_sensitive_literals_in_source(&fragment).is_empty(),
        "cleartext literal(s) leaked: {:?}",
        find_sensitive_literals_in_source(&fragment)
    );
    // The substitutions use the configured strategy (XOR here).
    assert!(fragment.contains("crate::dec_xor"));
}

/// The fragment must keep the guards and shared helpers that make it a PE
/// mapper *and* the image-section flow that makes ghosting work: a data section
/// over a delete-pending file cannot be created (writable) nor mapped by RVA.
#[test]
fn fragment_carries_the_ghosting_contract() {
    for needed in [
        "IMAGE_DOS_SIGNATURE",
        "IMAGE_NT_SIGNATURE",
        "SetFileInformationByHandle",
        "FileDispositionInfo",
        "NtCreateSection",
        "SEC_IMAGE",
        "NtMapViewOfSection",
        "crate::patch_imports",
        "crate::resolution_policy",
    ] {
        assert!(
            DEF.stub_fragment.contains(needed),
            "the fragment is missing '{needed}'"
        );
    }
}

/// The kernel maps an image section and applies its base relocations, so the
/// fragment must not carry a relocation walk of its own: a hand-rolled walk over
/// the payload's relocation directory was the open bug in this path.
#[test]
fn the_image_section_leaves_relocations_to_the_kernel() {
    for gone in [
        "IMAGE_DIRECTORY_ENTRY_BASERELOC",
        "IMAGE_BASE_RELOCATION",
        "fix_relocations",
        "CreateFileMappingW(",
        "MapViewOfFile(",
    ] {
        assert!(
            !DEF.stub_fragment.contains(gone),
            "the fragment still contains '{gone}'"
        );
    }
}

/// The header validation runs on the *mapped* view, so every offset it derives
/// from the payload has to be checked against the image size before use.
#[test]
fn header_validation_bounds_every_offset() {
    for needed in [
        "$MSG_HEADERS_OUT_OF_BOUNDS$",
        "$MSG_IMAGE_SIZE_INVALID$",
        "$MSG_ENTRY_OUT_OF_BOUNDS$",
    ] {
        assert!(
            DEF.stub_fragment.contains(needed),
            "the fragment is missing the bound check '{needed}'"
        );
    }
}
