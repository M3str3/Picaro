//! Tests for PE injection.

use super::{default_target, Params, DEF, MESSAGES};
use crate::audit::strings::find_sensitive_literals_in_source;
use crate::engine::obfuscation::{StringStrategy, StringsConfig};
use crate::plan::schema::PayloadFormat;
use crate::techniques::{Category, TechniqueKind};

/// A plan exercising the technique, with the payload format as a parameter.
fn plan_yaml(format: &str) -> String {
    format!(
        r#"schema: 6
name: pe-injection-format
build:
  payloads:
    blob:
      source: payload.bin
      format: {format}
  output:
    path: dist/out.exe
runtime:
  - technique: pe_injection
    params:
      target: "C:\\Windows\\System32\\notepad.exe"
"#
    )
}

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
    let step: TechniqueKind =
        serde_yml::from_str("technique: pe_injection\n").expect("pe_injection should parse");
    assert_eq!(
        step,
        TechniqueKind::PeInjection {
            params: Params::default()
        }
    );
}

#[test]
fn defaults_the_target() {
    assert_eq!(Params::default().target, default_target());
    assert_eq!(Params::default().timeout_ms, 0, "0 waits forever");
}

#[test]
fn parses_a_payload_and_target() {
    let step: TechniqueKind = serde_yml::from_str(
        "technique: pe_injection\nparams:\n  payload: implant\n  target: \"C:\\\\x.exe\"\n",
    )
    .expect("pe_injection with a payload should parse");
    match step {
        TechniqueKind::PeInjection { params } => {
            assert_eq!(params.payload.as_deref(), Some("implant"));
            assert_eq!(params.target, r"C:\x.exe");
            assert_eq!(params.timeout_ms, 0);
        }
        other => panic!("expected pe_injection, got {other:?}"),
    }
}

#[test]
fn parses_a_timeout() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: pe_injection\nparams:\n  timeout_ms: 45000\n")
            .expect("pe_injection with a timeout should parse");
    match step {
        TechniqueKind::PeInjection { params } => assert_eq!(params.timeout_ms, 45_000),
        other => panic!("expected pe_injection, got {other:?}"),
    }
}

#[test]
fn params_example_parses() {
    let step: TechniqueKind =
        serde_yml::from_str(DEF.params_example).expect("params_example should parse");
    match step {
        TechniqueKind::PeInjection { params } => {
            assert!(params.target.ends_with("notepad.exe"));
            assert_eq!(params.timeout_ms, 30_000);
        }
        other => panic!("expected pe_injection, got {other:?}"),
    }
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "pe_injection");
    assert_eq!(DEF.category, Category::Execution);
    assert!(!DEF.attck.is_empty());
    assert!(!DEF.requires.is_empty());
    assert!(!DEF.stub_fragment.is_empty());
    assert!(!DEF.readme.is_empty());
    // The payload's IAT must be resolved before the target runs it: checked at
    // compile time, so clippy does not see an `assert!(true)`.
    const _: () = assert!(DEF.resolves_imports);
}

#[test]
fn def_requests_only_the_syscalls_it_issues() {
    // The payload runs on a thread of its own, so the target's own thread is
    // never resumed, suspended or read, and the image is never read back.
    for unused in [
        "NtResumeThread",
        "NtSuspendThread",
        "NtGetContextThread",
        "NtSetContextThread",
        "NtReadVirtualMemory",
        "NtUnmapViewOfSection",
    ] {
        assert!(
            !DEF.syscalls.contains(&unused),
            "pe_injection does not issue {unused}"
        );
    }
    for used in [
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtProtectVirtualMemory",
        "NtCreateThreadEx",
        "NtWaitForSingleObject",
        "NtQueryInformationProcess",
        "NtClose",
    ] {
        assert!(DEF.syscalls.contains(&used), "missing {used}");
    }
}

#[test]
fn def_exposes_the_execution_entry_point() {
    assert!(
        DEF.stub_fragment.contains("fn execute_payload"),
        "the fragment must define the Execution contract"
    );
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
    assert!(!fragment.contains("$MSG_UNIMPLEMENTED$"));
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
fn render_fragment_for_obfuscates_the_target_and_every_diagnostic() {
    let params = Params {
        payload: None,
        target: r"C:\Windows\System32\notepad.exe".to_string(),
        timeout_ms: 0,
    };
    let fragment = params.render_fragment_for(&xor_strings(), PayloadFormat::Pe, None);
    let code = crate::audit::strings::strip_comments(&fragment);

    // The target path, the dynamically resolved names and every diagnostic are
    // runtime reconstructions, so none of them is a cleartext literal. The
    // generic scan catches all of them at once (it also flags the Nt* names,
    // the Windows path prefix and `svchost`).
    assert!(
        !fragment.contains(r"C:\Windows\System32\notepad.exe"),
        "the target path leaked"
    );
    assert!(
        find_sensitive_literals_in_source(&fragment).is_empty(),
        "cleartext literal(s) leaked: {:?}",
        find_sensitive_literals_in_source(&fragment)
    );
    for (_, text) in MESSAGES {
        assert!(
            !code.contains(*text),
            "diagnostic leaked in cleartext: {text:?}"
        );
    }

    // The substitutions use the configured strategy (XOR here).
    assert!(fragment.contains("crate::dec_xor"));
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

/// The fragment must keep the guards that make it a PE mapper and not a blob
/// runner: the signature checks, the architecture backstop, the shared import
/// resolver and the thread creation through the syscall layer.
#[test]
fn fragment_carries_the_pe_guards() {
    for needed in [
        "IMAGE_DOS_SIGNATURE",
        "IMAGE_NT_SIGNATURE",
        "EXPECTED_MACHINE",
        "OPTIONAL_MAGIC_PE32PLUS",
        "crate::resolve_imports",
        "crate::nt_create_thread_ex",
        "crate::nt_alloc_vm",
    ] {
        assert!(
            DEF.stub_fragment.contains(needed),
            "the fragment is missing '{needed}'"
        );
    }
}

#[test]
fn validate_rejects_a_non_pe_payload_format() {
    let plan: crate::plan::schema::Plan =
        serde_yml::from_str(&plan_yaml("shellcode")).expect("the plan should parse");
    let error = crate::plan::validate::validate(&plan)
        .expect_err("shellcode must be rejected")
        .to_string();
    assert!(error.contains("pe_injection"), "unexpected error: {error}");
    assert!(error.contains("it runs: pe"), "unexpected error: {error}");
}

#[test]
fn validate_accepts_a_pe_payload() {
    let plan: crate::plan::schema::Plan =
        serde_yml::from_str(&plan_yaml("pe")).expect("the plan should parse");
    crate::plan::validate::validate(&plan).expect("a PE payload must validate");
}
