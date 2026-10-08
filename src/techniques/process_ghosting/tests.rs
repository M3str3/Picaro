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
    let step: TechniqueKind = serde_yml::from_str(
        "technique: process_ghosting\nparams:\n  payload: implant\n",
    )
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
    // Ghosting is Win32-only: the section/map/delete flow needs no Nt* helper.
    assert!(DEF.syscalls.is_empty(), "unexpected syscalls: {:?}", DEF.syscalls);
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
/// mapper: the signature checks, the shared import resolver and the Win32
/// section/ghosting flow.
#[test]
fn fragment_carries_the_ghosting_contract() {
    for needed in [
        "IMAGE_DOS_SIGNATURE",
        "IMAGE_NT_SIGNATURE",
        "CreateFileMappingW",
        "MapViewOfFile",
        "SetFileInformationByHandle",
        "FileDispositionInfo",
        "crate::patch_imports",
        "crate::resolution_policy",
    ] {
        assert!(
            DEF.stub_fragment.contains(needed),
            "the fragment is missing '{needed}'"
        );
    }
}
