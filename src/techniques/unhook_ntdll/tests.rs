//! Tests for ntdll unhooking.

use super::{Params, DEF, MESSAGES};
use crate::audit::strings::find_sensitive_literals_in_source;
use crate::engine::obfuscation::{StringsConfig, YamlStringsPlan};
use crate::plan::schema::PayloadFormat;
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
        serde_yml::from_str("technique: unhook_ntdll\n").expect("unhook_ntdll should parse");
    assert_eq!(
        step,
        TechniqueKind::UnhookNtdll {
            params: Params::default()
        }
    );
}

#[test]
fn parses_explicit_empty_params() {
    let step: TechniqueKind = serde_yml::from_str("technique: unhook_ntdll\nparams: {}\n")
        .expect("an explicit empty params mapping should parse");
    assert_eq!(
        step,
        TechniqueKind::UnhookNtdll {
            params: Params::default()
        }
    );
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "unhook_ntdll");
    assert_eq!(DEF.attck, &["T1562.001"]);
    assert_eq!(DEF.category, Category::Preparation);
    assert_eq!(DEF.stability, Stability::Stable);
    assert!(DEF.conflicts.is_empty());
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
        DEF.stub_fragment.contains("fn unhook_ntdll"),
        "the fragment must define the Preparation contract"
    );
    assert!(
        DEF.stub_fragment.contains("Result<bool, String>"),
        "a Preparation returns Ok(true) to continue, Ok(false) to abort"
    );
}

#[test]
fn fragment_has_no_forbidden_patterns() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let rendered = Params::default().render_fragment(&strings);
    for source in [DEF.stub_fragment, rendered.as_str()] {
        for forbidden in [
            "println!",
            "unwrap",
            "expect",
            "todo!",
            "unimplemented!",
            "anyhow",
            "panic!",
        ] {
            assert!(
                !source.contains(forbidden),
                "the fragment must not contain '{forbidden}'"
            );
        }
    }
}

#[test]
fn render_fragment_substitutes_every_placeholder() {
    for (name, strings) in strategies() {
        let fragment = Params::default().render_fragment(&strings);
        assert!(
            fragment.contains("fn unhook_ntdll"),
            "{name}: the entry point is missing"
        );
        let left = placeholders(&fragment);
        assert!(
            left.is_empty(),
            "{name}: unsubstituted placeholders: {left:?}"
        );
    }
}

#[test]
fn render_fragment_obfuscates_the_path_and_the_module_name() {
    for (name, strings) in strategies() {
        let fragment = Params::default().render_fragment(&strings);

        // No sensitive literal survives in code (the guardrail ignores comments,
        // which do name the module and the technique).
        assert!(
            find_sensitive_literals_in_source(&fragment).is_empty(),
            "{name}: cleartext sensitive literal in the rendered fragment"
        );
        // The path and the module name are not literal byte strings either.
        assert!(
            !fragment.contains(r"C:\Windows\System32\ntdll.dll"),
            "{name}: the clean copy's path is in cleartext"
        );
        assert!(
            !fragment.contains(r#"b"ntdll.dll""#),
            "{name}: the module name is in cleartext"
        );
        // Every diagnostic is rebuilt at runtime too.
        for (_, text) in MESSAGES {
            assert!(
                !fragment.contains(text),
                "{name}: the message '{text}' is in cleartext"
            );
        }
        // The active strategy's decoder is what rebuilds them.
        let decoded = match name {
            "xor" => fragment.contains("crate::dec_xor"),
            _ => fragment.contains("std::hint::black_box"),
        };
        assert!(
            decoded,
            "{name}: the strings must be rebuilt at runtime by the active strategy"
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
fn the_fragment_guards_the_section_size() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params::default().render_fragment(&strings);

    assert!(
        fragment.contains("if virtual_size == 0 || raw_size == 0"),
        "an empty section must be refused"
    );
    assert!(
        fragment.contains("checked_add(raw_size)"),
        "the raw range must be overflow-checked before it is compared"
    );
    assert!(
        fragment.contains("end > file.len()"),
        "a section that does not fit the file must be refused"
    );
    assert!(
        fragment.contains("copy_len: virtual_size.min(raw_size)"),
        "the copy must be bounded by both the file and the mapped section"
    );
}

#[test]
fn the_fragment_applies_the_section_relocations() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params::default().render_fragment(&strings);

    assert!(fragment.contains("fn apply_section_relocations"));
    assert!(fragment.contains("RELOC_HIGHLOW"));
    assert!(fragment.contains("RELOC_DIR64"));
    assert!(fragment.contains("wrapping_add(delta)"));
    assert!(
        fragment.contains(
            "apply_section_relocations(&file, &clean, module.0 as usize, target as *mut u8)?;"
        ),
        "the fixups must run after the copy and before the restore"
    );
}

#[test]
fn the_fragment_restores_through_the_syscall_layer() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params::default().render_fragment(&strings);

    assert_eq!(
        fragment.matches("crate::nt_protect_vm(").count(),
        2,
        "expected a writable and a restore protection change"
    );
    assert!(!fragment.contains("VirtualProtectEx"));
    assert!(!fragment.contains("VirtualProtect("));
    assert!(!fragment.contains("WriteProcessMemory"));
    assert!(fragment.contains("PAGE_EXECUTE_READWRITE.0"));
    assert!(fragment.contains("ptr::copy_nonoverlapping"));
    assert!(fragment.contains("GetModuleHandleA"));
    assert!(fragment.contains("std::fs::read"));
}

/// Full e2e for the compiler: render + compile an unhook_ntdll stub for both
/// syscall modes, producing a PE each time.
///
/// Marked `#[ignore]` because it requires `rustc` and the compiled
/// dependencies. Run it with `cargo test -- --ignored unhook_ntdll`.
#[test]
#[ignore = "requires rustc and the compiled dependencies"]
fn compiles_unhook_ntdll_stub_for_both_syscall_modes() {
    use std::path::Path;

    let plaintext: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
    let key = crate::engine::crypto::generate_key();
    let encrypted = crate::engine::crypto::encrypt_payload(&plaintext, &key).unwrap();

    let build_dir = std::env::temp_dir().join(format!("picaro_unhook_{}", std::process::id()));
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
    let strings = StringsConfig::from_yaml(None).unwrap();

    let cases = [
        ("none", crate::engine::syscalls::SyscallsMode::None),
        ("indirect", crate::engine::syscalls::SyscallsMode::Indirect),
    ];

    for (name, mode) in cases {
        let pipeline = vec![RuntimeStep::new(TechniqueKind::UnhookNtdll {
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
