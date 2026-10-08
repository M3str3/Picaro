//! Tests for Early Bird injection.

use super::{default_target, Params, DEF, MESSAGES};
use crate::engine::obfuscation::StringsConfig;
use crate::plan::schema::PayloadFormat;
use crate::techniques::{Category, TechniqueKind};

/// Renders the fragment with the default (obfuscating) string strategy.
fn render(params: &Params) -> String {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    params.render_fragment_for(&strings, PayloadFormat::Shellcode, None)
}

#[test]
fn parses_params_from_empty_yaml() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: early_bird\n").expect("early_bird should parse");
    assert_eq!(
        step,
        TechniqueKind::EarlyBird {
            params: Params::default()
        }
    );
}

#[test]
fn defaults_the_target() {
    assert_eq!(Params::default().target, default_target());
    assert!(!default_target().is_empty());
}

#[test]
fn defaults_the_wait_to_zero() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: early_bird\n").expect("early_bird should parse");
    match step {
        TechniqueKind::EarlyBird { params } => assert_eq!(params.wait_ms, 0),
        other => panic!("expected early_bird, got {other:?}"),
    }
}

#[test]
fn parses_a_payload_and_target() {
    let step: TechniqueKind = serde_yml::from_str(
        "technique: early_bird\nparams:\n  payload: implant\n  target: \"C:\\\\x.exe\"\n  wait_ms: 2500\n",
    )
    .expect("early_bird with a payload should parse");
    match step {
        TechniqueKind::EarlyBird { params } => {
            assert_eq!(params.payload.as_deref(), Some("implant"));
            assert_eq!(params.target, r"C:\x.exe");
            assert_eq!(params.wait_ms, 2500);
        }
        other => panic!("expected early_bird, got {other:?}"),
    }
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "early_bird");
    assert_eq!(DEF.category, Category::Execution);
    assert!(!DEF.attck.is_empty());
    assert!(!DEF.requires.is_empty());
    assert!(!DEF.stub_fragment.is_empty());
    assert!(!DEF.readme.is_empty());
}

#[test]
fn def_exposes_the_execution_entry_point() {
    assert!(
        DEF.stub_fragment.contains("fn execute_payload"),
        "the fragment must define the Execution contract"
    );
}

#[test]
fn render_fragment_for_returns_the_fragment() {
    let fragment = render(&Params::default());
    assert!(fragment.contains("fn execute_payload"));
}

#[test]
fn every_placeholder_is_substituted() {
    let fragment = render(&Params::default());
    assert!(
        !fragment.contains('$'),
        "unsubstituted placeholder in the rendered fragment"
    );
    assert!(!fragment.contains("MSG_"), "a message placeholder survived");
}

#[test]
fn the_target_never_appears_in_cleartext() {
    let params = Params {
        target: r"C:\Windows\System32\svchost.exe".to_string(),
        ..Params::default()
    };
    let fragment = render(&params);
    assert!(
        !fragment.contains(&params.target),
        "the target path must be rebuilt from obfuscated bytes"
    );
}

#[test]
fn every_diagnostic_is_obfuscated() {
    let fragment = render(&Params::default());
    for (placeholder, text) in MESSAGES {
        assert!(
            !DEF.stub_fragment.contains(text),
            "cleartext diagnostic for {placeholder} in the fragment"
        );
        assert!(
            !fragment.contains(text),
            "cleartext diagnostic for {placeholder} in the rendered fragment"
        );
    }
}

#[test]
fn the_wait_bound_is_rendered_as_a_u32_literal() {
    let params = Params {
        wait_ms: 1500,
        ..Params::default()
    };
    assert!(
        render(&params).contains("1500u32"),
        "wait_ms must reach the fragment as a u32 literal"
    );

    // The syscall layer takes a `u32` timeout (`u32::MAX` = infinite), so a
    // larger YAML value is clamped instead of wrapping.
    let huge = Params {
        wait_ms: u64::MAX,
        ..Params::default()
    };
    assert!(render(&huge).contains("4294967295u32"));
}

#[test]
fn the_apc_is_queued_before_the_thread_is_resumed() {
    let fragment = render(&Params::default());
    let queue = fragment
        .find("nt_queue_apc")
        .expect("the payload must be queued as an APC");
    let resume = fragment
        .find("nt_resume_thread")
        .expect("the target's main thread must be resumed");
    assert!(
        queue < resume,
        "queueing after the resume would run the payload on an initialized target (or never)"
    );
}

#[test]
fn the_fragment_uses_the_syscall_layer() {
    let fragment = render(&Params::default());
    for helper in [
        "crate::nt_alloc_vm",
        "crate::nt_write_vm",
        "crate::nt_protect_vm",
        "crate::nt_queue_apc",
        "crate::nt_resume_thread",
        "crate::nt_wait_for_single_object",
        "crate::nt_close",
    ] {
        assert!(
            fragment.contains(helper),
            "{helper} missing from the fragment"
        );
    }
    assert!(
        fragment.contains("CreateProcessA") && fragment.contains("CREATE_SUSPENDED"),
        "the target must be spawned suspended"
    );
    assert!(
        !fragment.contains("VirtualAllocEx")
            && !fragment.contains("QueueUserAPC")
            && !fragment.contains("ResumeThread"),
        "kernel-facing calls must go through the nt_* helpers"
    );
}

#[test]
fn the_runtime_guard_rejects_a_non_shellcode_format() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let shellcode = Params::default().render_fragment_for(&strings, PayloadFormat::Shellcode, None);
    assert!(
        shellcode.contains("if !true"),
        "a shellcode payload must pass the runtime guard"
    );

    let pe = Params::default().render_fragment_for(&strings, PayloadFormat::Pe, None);
    assert!(
        pe.contains("if !false"),
        "a non-shellcode payload must fail the runtime guard"
    );
}

#[test]
fn fragment_has_no_forbidden_patterns() {
    for forbidden in [
        "anyhow",
        "static mut",
        "println!",
        "eprintln!",
        "unwrap(",
        "expect(",
        "todo!",
        "unimplemented!",
        "panic!",
    ] {
        assert!(
            !DEF.stub_fragment.contains(forbidden),
            "the fragment must not use {forbidden}"
        );
    }
}
