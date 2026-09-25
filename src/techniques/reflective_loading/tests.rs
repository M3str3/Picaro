//! Tests for the reflective loading technique.

use super::{Params, DEF};
use crate::techniques::PipelineStep;

#[test]
fn parses_params_from_empty_yaml() {
    let step: PipelineStep = serde_yml::from_str("technique: reflective_loading\n")
        .expect("reflective_loading should parse");
    assert_eq!(step, PipelineStep::ReflectiveLoading(Params {}));
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "reflective_loading");
    assert_eq!(DEF.attck, &["T1620"]);
    assert!(!DEF.stub_fragment.is_empty());
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
        assert!(
            !DEF.stub_fragment.contains(forbidden),
            "stub_fragment.rs must not contain '{forbidden}'"
        );
    }
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

    let build_dir = std::env::temp_dir().join(format!("packerman_refl_{}", std::process::id()));
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
        stub_marker: crate::engine::stub::generate_stub_marker(),
        payload_path: "payload.bin".to_string(),
        build_args: std::collections::BTreeMap::new(),
    };
    let pipeline = vec![PipelineStep::ReflectiveLoading(Params {})];
    let strings = crate::engine::obfuscation::StringsConfig::from_yaml(None).unwrap();
    let stub_src =
        crate::engine::stub::render_main_rs(&template, &params, &pipeline, &strings).unwrap();
    let stub_path = build_dir.join("main.rs");
    std::fs::write(&stub_path, stub_src).unwrap();

    let deps = crate::engine::compiler::locate_stub_deps().unwrap();
    let out = build_dir.join("out.exe");
    // `compile_stub` verifies the `MZ` header before returning.
    crate::engine::compiler::compile_stub(&stub_path, &out, &deps).unwrap();

    let _ = std::fs::remove_dir_all(&build_dir);
}
