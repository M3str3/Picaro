//! Tests for PE-header erasure.

use super::{Params, DEF, MESSAGES};
use crate::audit::strings::find_sensitive_literals_in_source;
use crate::engine::obfuscation::StringsConfig;
use crate::techniques::{Capability, Category, RuntimeStep, Stability, TechniqueKind};

/// The `$PLACEHOLDER$` tokens `source` still contains.
///
/// A rendered fragment must report none: `$` has no meaning in the stub outside
/// a macro, so a leftover token is always a substitution bug — including one
/// hidden in a comment, which is why this scans the raw source.
fn placeholders(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = source;
    while let Some(start) = rest.find('$') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('$') else { break };
        out.push(format!("${}$", &after[..end]));
        rest = &after[end + 1..];
    }
    out
}

#[test]
fn parses_from_empty_yaml() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: erase_pe_header\n").expect("erase_pe_header should parse");
    assert_eq!(
        step,
        TechniqueKind::ErasePeHeader {
            params: Params::default()
        }
    );
}

#[test]
fn parses_explicit_empty_params() {
    let step: TechniqueKind = serde_yml::from_str("technique: erase_pe_header\nparams: {}\n")
        .expect("an explicit empty params mapping should parse");
    assert_eq!(
        step,
        TechniqueKind::ErasePeHeader {
            params: Params::default()
        }
    );
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "erase_pe_header");
    assert_eq!(DEF.attck, &["T1027"]);
    assert_eq!(DEF.stability, Stability::Stable);
    assert_eq!(DEF.category, Category::Preparation);
    assert_eq!(DEF.conflicts, &["sleep_obfuscation"]);
    assert_eq!(DEF.syscalls, &["NtProtectVirtualMemory"]);
    assert!(DEF.requires.contains(&Capability::WindowsX64));
    assert!(DEF.requires.contains(&Capability::WindowsX86));
    assert!(!DEF.stub_fragment.is_empty());
    assert!(!DEF.readme.is_empty());
    assert!(
        serde_yml::from_str::<RuntimeStep>(DEF.params_example).is_ok(),
        "params_example must parse as a runtime step"
    );
}

#[test]
fn def_exposes_the_preparation_entry_point() {
    assert!(
        DEF.stub_fragment.contains("fn erase_pe_header"),
        "the fragment must define the Preparation contract"
    );
    assert!(
        DEF.stub_fragment.contains("Result<bool, String>"),
        "a Preparation returns Ok(true) to continue, Ok(false) to abort"
    );
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
fn render_fragment_substitutes_every_placeholder() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params::default().render_fragment(&strings);

    assert!(
        fragment.contains("fn erase_pe_header"),
        "the entry point is missing"
    );
    let left = placeholders(&fragment);
    assert!(left.is_empty(), "unsubstituted placeholders: {left:?}");
    assert!(
        !fragment.contains('$'),
        "an unsubstituted placeholder would break the stub"
    );
}

#[test]
fn render_fragment_obfuscates_literals() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params::default().render_fragment(&strings);

    assert!(fragment.contains("fn erase_pe_header"));
    assert!(!fragment.contains('$'), "no placeholder may survive");
    // No sensitive literal (and no technique keyword) in the rendered code.
    assert!(
        find_sensitive_literals_in_source(&fragment).is_empty(),
        "cleartext sensitive literal in the rendered fragment"
    );
    // Every diagnostic is rebuilt at runtime, not inlined.
    for (_, text) in MESSAGES {
        assert!(
            !fragment.contains(text),
            "the message '{text}' is in cleartext"
        );
    }
}

#[test]
fn every_message_placeholder_is_used() {
    for (placeholder, _) in MESSAGES {
        assert!(
            DEF.stub_fragment.contains(placeholder),
            "{placeholder} is declared but never used by the fragment"
        );
    }
}

#[test]
fn the_fragment_zeroes_the_loader_header_through_the_syscall_layer() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params::default().render_fragment(&strings);

    // The loader's own image, not a named module.
    assert!(fragment.contains("GetModuleHandleA(PCSTR::null())"));
    // The header is zeroed, not copied over.
    assert!(fragment.contains("core::ptr::write_bytes"));
    // A writable window and a restore: both through the syscall layer.
    assert_eq!(
        fragment.matches("crate::nt_protect_vm(").count(),
        2,
        "expected a writable and a restore protection change"
    );
    assert!(fragment.contains("PAGE_READWRITE.0"));
    assert!(!fragment.contains("VirtualProtect("));
    assert!(!fragment.contains("VirtualProtectEx"));
}
