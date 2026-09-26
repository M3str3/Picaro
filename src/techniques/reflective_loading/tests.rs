//! Tests for the reflective loading technique.

use super::{Params, DEF, SHELLCODE_FRAGMENT};
use crate::config::schema::PayloadFormat;
use crate::engine::obfuscation::StringsConfig;
use crate::techniques::RuntimeStep;

#[test]
fn parses_params_from_empty_yaml() {
    let step: RuntimeStep = serde_yml::from_str("technique: reflective_loading\n")
        .expect("reflective_loading should parse");
    assert_eq!(step, RuntimeStep::ReflectiveLoading { params: Params {} });
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "reflective_loading");
    assert_eq!(DEF.attck, &["T1620"]);
    assert!(!DEF.stub_fragment.is_empty());
    assert!(SHELLCODE_FRAGMENT.contains("fn run_shellcode"));
    assert!(!DEF.readme.is_empty());
}

#[test]
fn fragment_has_no_forbidden_patterns() {
    for forbidden in [
        "anyhow",
        "static mut",
        "println!",
        "unimplemented!",
        "todo!",
    ] {
        for source in [DEF.stub_fragment, SHELLCODE_FRAGMENT] {
            assert!(
                !source.contains(forbidden),
                "a stub fragment must not contain '{forbidden}'"
            );
        }
    }
}

/// The payload format selects the fragment: a PE/DLL payload gets the mapper, a
/// shellcode payload the raw-code runner.
#[test]
fn the_payload_format_selects_the_fragment() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let params = Params {};

    let pe = params.render_fragment_for(&strings, PayloadFormat::Pe, None);
    assert!(pe.contains("fn run_reflective"));
    assert!(!pe.contains("fn run_shellcode"));

    let shellcode = params.render_fragment_for(&strings, PayloadFormat::Shellcode, None);
    assert!(shellcode.contains("fn run_shellcode"));
    assert!(!shellcode.contains("fn run_reflective"));
}

/// Every rendered fragment must be free of unsubstituted `$PLACEHOLDER$`
/// tokens, and a DLL export name must not survive in cleartext.
#[test]
fn rendered_fragments_substitute_placeholders_and_obfuscate_the_export() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let params = Params {};

    for format in [
        PayloadFormat::Pe,
        PayloadFormat::Dll,
        PayloadFormat::Shellcode,
    ] {
        let fragment = params.render_fragment_for(&strings, format, None);
        assert!(
            !fragment.contains('$'),
            "an unsubstituted placeholder would break the stub ({:?})",
            format
        );
    }

    let with_export = params.render_fragment_for(&strings, PayloadFormat::Dll, Some("ExportedRun"));
    assert!(with_export.contains("Some("));
    assert!(
        !with_export.contains("\"ExportedRun\""),
        "the export name leaked in cleartext"
    );
}

/// Full e2e: render + compile a reflective-loading stub for each payload
/// format, producing a PE each time.
///
/// Marked `#[ignore]` because it requires `rustc` and the compiled
/// dependencies. Run it with `cargo test -- --ignored`.
#[test]
#[ignore = "requires rustc and the compiled dependencies"]
fn compiles_reflective_loading_stub_for_every_format() {
    use std::path::Path;

    let plaintext: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
    let key = crate::engine::crypto::generate_key();
    let encrypted = crate::engine::crypto::encrypt_payload(&plaintext, &key).unwrap();

    let build_dir = std::env::temp_dir().join(format!("batesian_refl_fmt_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&build_dir);
    std::fs::create_dir_all(&build_dir).unwrap();
    std::fs::write(build_dir.join("payload.bin"), &encrypted.ciphertext).unwrap();

    let template = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("templates")
            .join("stub")
            .join("main.rs.tpl"),
    )
    .unwrap();

    let deps = crate::engine::compiler::locate_stub_deps().unwrap();
    let strings = crate::engine::obfuscation::StringsConfig::from_yaml(None).unwrap();

    // (format, export, output name)
    let cases = [
        (PayloadFormat::Pe, None, "pe"),
        (PayloadFormat::Dll, Some("Run"), "dll"),
        (PayloadFormat::Shellcode, None, "shellcode"),
    ];

    for (format, export, name) in cases {
        let params = crate::engine::stub::StubParams {
            nonce: encrypted.nonce,
            key: encrypted.key,
            ciphertext: encrypted.ciphertext.clone(),
            plaintext_len: encrypted.plaintext_len,
            payload_format: format,
            payload_export: export.map(str::to_string),
            stub_marker: crate::engine::stub::generate_stub_marker(),
            payload_path: "payload.bin".to_string(),
            build_args: std::collections::BTreeMap::new(),
            payload_args: Vec::new(),
            args_mode: crate::engine::args::ArgsMode::Join,
        };
        let pipeline = vec![RuntimeStep::ReflectiveLoading { params: Params {} }];
        let stub_src = crate::engine::stub::render_main_rs(
            &template,
            &params,
            &pipeline,
            &strings,
            &crate::engine::syscalls::SyscallsConfig::default(),
        )
        .unwrap();
        assert!(
            !stub_src.contains('$'),
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

/// Full e2e: render + compile a reflective-loading stub, producing a PE.
///
/// Marked `#[ignore]` because it requires `rustc` and the compiled
/// dependencies. Run it with `cargo test -- --ignored`.
#[test]
#[ignore = "requires rustc and the compiled dependencies"]
fn compiles_reflective_loading_stub_to_pe() {
    use std::path::Path;

    let plaintext: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
    let key = crate::engine::crypto::generate_key();
    let encrypted = crate::engine::crypto::encrypt_payload(&plaintext, &key).unwrap();

    let build_dir = std::env::temp_dir().join(format!("batesian_refl_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&build_dir);
    std::fs::create_dir_all(&build_dir).unwrap();
    std::fs::write(build_dir.join("payload.bin"), &encrypted.ciphertext).unwrap();

    let template = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("templates")
            .join("stub")
            .join("main.rs.tpl"),
    )
    .unwrap();
    let params = crate::engine::stub::StubParams {
        nonce: encrypted.nonce,
        key: encrypted.key,
        ciphertext: encrypted.ciphertext.clone(),
        plaintext_len: encrypted.plaintext_len,
        payload_format: PayloadFormat::Pe,
        payload_export: None,
        stub_marker: crate::engine::stub::generate_stub_marker(),
        payload_path: "payload.bin".to_string(),
        build_args: std::collections::BTreeMap::new(),
        payload_args: Vec::new(),
        args_mode: crate::engine::args::ArgsMode::Join,
    };
    let pipeline = vec![RuntimeStep::ReflectiveLoading { params: Params {} }];
    let strings = crate::engine::obfuscation::StringsConfig::from_yaml(None).unwrap();
    let stub_src = crate::engine::stub::render_main_rs(
        &template,
        &params,
        &pipeline,
        &strings,
        &crate::engine::syscalls::SyscallsConfig::default(),
    )
    .unwrap();
    let stub_path = build_dir.join("main.rs");
    std::fs::write(&stub_path, stub_src).unwrap();

    let deps = crate::engine::compiler::locate_stub_deps().unwrap();
    let out = build_dir.join("out.exe");
    // `compile_stub` verifies the `MZ` header before returning.
    crate::engine::compiler::compile_stub(
        &stub_path,
        &out,
        &deps,
        crate::engine::compiler::CompileOptions::default(),
    )
    .unwrap();

    let _ = std::fs::remove_dir_all(&build_dir);
}
