//! Tests for the hide-thread-from-debugger technique.

use super::{Params, DEF};
use crate::engine::obfuscation::StringsConfig;
use crate::techniques::TechniqueKind;

#[test]
fn parses_from_empty_yaml() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: hide_thread_from_debugger\n").expect("should parse");
    assert_eq!(
        step,
        TechniqueKind::HideThreadFromDebugger {
            params: Params::default()
        }
    );
}

#[test]
fn parses_an_explicit_empty_params_block() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: hide_thread_from_debugger\nparams: {}\n")
            .expect("should parse");
    assert_eq!(
        step,
        TechniqueKind::HideThreadFromDebugger {
            params: Params::default()
        }
    );
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "hide_thread_from_debugger");
    assert_eq!(DEF.attck, &["T1622"]);
    assert_eq!(DEF.category, crate::techniques::Category::Preparation);
    assert!(DEF.conflicts.is_empty());
    // The class is not covered by kernel32's wrapper (measured), so the call is
    // routed through the syscall layer.
    assert_eq!(DEF.syscalls, &["NtSetInformationThread"]);
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

    assert!(fragment.contains("fn hide_thread_from_debugger"));
    assert!(fragment.contains("THREAD_HIDE_FROM_DEBUGGER: i32 = 0x11"));
    assert!(fragment.contains("crate::nt_set_info_thread"));
    assert!(!fragment.contains("$MSG_HIDE_FAILED$"));
    assert!(fragment.contains("crate::dec_xor"));
    assert!(
        crate::audit::strings::find_sensitive_literals_in_source(&fragment).is_empty(),
        "cleartext sensitive literal in the rendered fragment"
    );
}
