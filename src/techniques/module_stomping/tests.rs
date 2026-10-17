//! Tests for module stomping.

use super::{default_module, Params, DEF, MESSAGES};
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
        serde_yml::from_str("technique: module_stomping\n").expect("module_stomping should parse");
    assert_eq!(
        step,
        TechniqueKind::ModuleStomping {
            params: Params::default()
        }
    );
}

#[test]
fn parses_a_payload_name() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: module_stomping\nparams:\n  payload: implant\n")
            .expect("module_stomping with a payload should parse");
    match step {
        TechniqueKind::ModuleStomping { params } => {
            assert_eq!(params.payload.as_deref(), Some("implant"));
        }
        other => panic!("expected module_stomping, got {other:?}"),
    }
}

#[test]
fn parses_a_stomp_target() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: module_stomping\nparams:\n  module: dbghelp.dll\n")
            .expect("module_stomping with a module should parse");
    match step {
        TechniqueKind::ModuleStomping { params } => {
            assert_eq!(params.module, "dbghelp.dll");
        }
        other => panic!("expected module_stomping, got {other:?}"),
    }
}

/// A step without `params:` must behave like `Params::default()`: the serde
/// default and the `Default` impl have to agree.
#[test]
fn the_omitted_module_defaults_to_the_documented_target() {
    assert_eq!(default_module(), "wininet.dll");
    assert_eq!(Params::default().module, default_module());

    let step: TechniqueKind = serde_yml::from_str("technique: module_stomping\nparams: {}\n")
        .expect("empty params should parse");
    match step {
        TechniqueKind::ModuleStomping { params } => assert_eq!(params.module, default_module()),
        other => panic!("expected module_stomping, got {other:?}"),
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
    assert_eq!(DEF.name, "module_stomping");
    assert_eq!(DEF.category, Category::Execution);
    assert_eq!(DEF.attck, &["T1055"]);
    assert!(!DEF.requires.is_empty());
    assert!(!DEF.stub_fragment.is_empty());
    assert!(!DEF.readme.is_empty());
    // The only kernel call the fragment issues is the protection change; the
    // payload is raw shellcode, so no import resolver is needed (checked on the
    // rendered fragment below, where the constant would not fold away).
    assert_eq!(DEF.syscalls, &["NtProtectVirtualMemory"]);
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
    assert_eq!(step.name(), "module_stomping");
}

#[test]
fn render_fragment_for_returns_the_fragment() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params::default().render_fragment_for(&strings, PayloadFormat::Pe, None);
    assert!(fragment.contains("fn execute_payload"));
}

/// Every placeholder in the fragment is either the stomp target or one of the
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
/// obfuscation strategy, and neither the stomp target nor the message text may
/// survive in cleartext.
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
            "{label}: the stomp target leaked in cleartext"
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

/// The stomp: two protection changes (writable, then the loader's own), one
/// `memcpy` into the module, and a direct call — no Win32 protection call.
#[test]
fn the_fragment_stomps_through_the_syscall_layer() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params::default().render_fragment_for(&strings, PayloadFormat::Shellcode, None);

    assert_eq!(
        fragment.matches("crate::nt_protect_vm(").count(),
        2,
        "expected a writable and a restore protection change"
    );
    assert!(
        !fragment.contains("VirtualProtectEx"),
        "no direct Win32 call"
    );
    // Raw shellcode has no import table, so the shared resolver is not wired in
    // (`DEF.resolves_imports` is false).
    assert!(!fragment.contains("resolve_imports"));
    assert!(fragment.contains(
        "unsafe { ptr::copy_nonoverlapping(image.as_ptr(), section.start, payload_len) }"
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

/// Full e2e for the compiler: render + compile a module-stomping stub for both
/// syscall modes, producing a PE each time.
///
/// Marked `#[ignore]` because it requires `rustc` and the compiled
/// dependencies. Run it with `cargo test --features live-tests -- --ignored module_stomping`.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the compiled dependencies"]
fn compiles_module_stomping_stub_for_both_syscall_modes() {
    use std::path::Path;

    let plaintext: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
    let key = crate::engine::crypto::generate_key();
    let encrypted = crate::engine::crypto::encrypt_payload(&plaintext, &key).unwrap();

    let build_dir = std::env::temp_dir().join(format!("picaro_stomp_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&build_dir);
    std::fs::create_dir_all(&build_dir).unwrap();
    std::fs::write(build_dir.join("payload.bin"), &encrypted.ciphertext).unwrap();

    let template = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("engine")
            .join("templates")
            .join("main.rs.tpl"),
    )
    .unwrap();

    let deps = crate::engine::compiler::locate_stub_deps(crate::plan::schema::Arch::X64).unwrap();
    let strings = crate::engine::obfuscation::StringsConfig::from_yaml(None).unwrap();

    let cases = [
        ("none", crate::engine::syscalls::SyscallsMode::None),
        ("indirect", crate::engine::syscalls::SyscallsMode::Indirect),
    ];

    for (name, mode) in cases {
        let pipeline = vec![RuntimeStep::new(TechniqueKind::ModuleStomping {
            params: Params::default(),
        })];
        let params = crate::engine::steps::test_params(
            &pipeline,
            &encrypted,
            "payload.bin",
            PayloadFormat::Shellcode,
            None,
            false,
        );
        let stub_src = crate::engine::steps::render_builtin(
            &template,
            &params,
            &strings,
            &crate::engine::syscalls::SyscallsConfig {
                mode,
                ..Default::default()
            },
            &crate::engine::api_resolution::ApiResolutionConfig::default(),
        )
        .unwrap();
        // The appended debug prelude uses `$` as Rust macro syntax, so the
        // placeholder check runs over the template's own output.
        let body = crate::engine::debug::strip_prelude(&stub_src);
        assert!(
            !body.contains('$'),
            "{name}: an unsubstituted placeholder reached the stub"
        );

        let stub_path = build_dir.join(format!("main_{name}.rs"));
        std::fs::write(&stub_path, stub_src).unwrap();

        let out = build_dir.join(format!("out_{name}.exe"));
        crate::engine::compiler::compile_stub(
            &stub_path,
            &out,
            &deps,
            crate::engine::compiler::CompileOptions::default(),
        )
        .unwrap();
    }

    let _ = std::fs::remove_dir_all(&build_dir);
}
