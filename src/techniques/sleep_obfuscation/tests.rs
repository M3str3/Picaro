//! Tests for the sleep-obfuscation technique.

use super::{EncryptRegion, Params, Variant, DEF};
use crate::engine::obfuscation::StringsConfig;
use crate::techniques::TechniqueKind;

#[test]
fn parses_params_with_defaults() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: sleep_obfuscation\n").expect("should parse");
    assert_eq!(
        step,
        TechniqueKind::SleepObfuscation {
            params: Params {
                variant: Variant::Ekko,
                sleep_ms: 5000,
                encrypt_regions: vec![EncryptRegion::Payload],
            }
        }
    );
}

#[test]
fn parses_explicit_params() {
    let step: TechniqueKind = serde_yml::from_str(
        "technique: sleep_obfuscation\nparams:\n  variant: cronos\n  sleep_ms: 1234\n  encrypt_regions: [payload, stack]\n",
    )
    .expect("should parse");
    assert_eq!(
        step,
        TechniqueKind::SleepObfuscation {
            params: Params {
                variant: Variant::Cronos,
                sleep_ms: 1234,
                encrypt_regions: vec![EncryptRegion::Payload, EncryptRegion::Stack],
            }
        }
    );
}

#[test]
fn rejects_unknown_variant() {
    let err = serde_yml::from_str::<TechniqueKind>(
        "technique: sleep_obfuscation\nparams:\n  variant: banana\n",
    )
    .expect_err("an unknown variant must fail");
    let msg = err.to_string();
    assert!(msg.contains("banana"), "unclear error: {msg}");
}

#[test]
fn rejects_unknown_encrypt_region() {
    let err = serde_yml::from_str::<TechniqueKind>(
        "technique: sleep_obfuscation\nparams:\n  encrypt_regions: [banana]\n",
    )
    .expect_err("an unknown region must fail");
    let msg = err.to_string();
    assert!(msg.contains("banana"), "unclear error: {msg}");
}

#[test]
fn parses_bare_all_region_scalar() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: sleep_obfuscation\nparams:\n  encrypt_regions: all\n")
            .expect("the bare 'all' scalar should parse");
    assert_eq!(
        step,
        TechniqueKind::SleepObfuscation {
            params: Params {
                variant: Variant::Ekko,
                sleep_ms: 5000,
                encrypt_regions: vec![EncryptRegion::All],
            }
        }
    );
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "sleep_obfuscation");
    assert_eq!(DEF.attck, &["T1027"]);
    assert_eq!(DEF.category, crate::techniques::Category::Preparation);
    assert!(DEF.conflicts.is_empty());
    assert!(!DEF.stub_fragment.is_empty());
    assert!(!DEF.readme.is_empty());
    assert!(DEF.syscalls.is_empty());
}

#[test]
fn fragment_has_no_forbidden_patterns() {
    for forbidden in [
        "println!",
        "unwrap",
        "expect",
        "panic!",
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
fn no_debug_artifacts_in_fragment() {
    for artifact in ["eprintln!", "DEBUG_STAGE", "TRACE ", "GetTickCount"] {
        assert!(
            !DEF.stub_fragment.contains(artifact),
            "stub_fragment.rs must not contain the debug artifact '{artifact}'"
        );
    }
}

#[test]
fn render_fragment_obfuscates_api_names() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params {
        variant: Variant::Ekko,
        sleep_ms: 5000,
        encrypt_regions: vec![EncryptRegion::Payload],
    }
    .render_fragment(&strings);

    // The entry point is present and every placeholder is substituted.
    assert!(fragment.contains("pub fn sleep_obfuscation"));
    assert!(fragment.contains("const SLEEP_MS: u64 = 5000;"));
    for placeholder in [
        "$KERNEL32_DLL_DEF$",
        "$NTDLL_DLL_DEF$",
        "$ADVAPI32_DLL_DEF$",
        "$CREATE_TIMER_QUEUE_DEF$",
        "$CREATE_TIMER_QUEUE_TIMER_DEF$",
        "$DELETE_TIMER_QUEUE_EX_DEF$",
        "$WAIT_FOR_SINGLE_OBJECT_DEF$",
        "$SET_EVENT_DEF$",
        "$VIRTUAL_PROTECT_DEF$",
        "$RTL_CAPTURE_CONTEXT_DEF$",
        "$NT_CONTINUE_DEF$",
        "$SYSTEM_FUNCTION_032_DEF$",
        "$SLEEP_MS$",
        "$SLEEP_KEY_DEF$",
    ] {
        assert!(
            !fragment.contains(placeholder),
            "placeholder not substituted: {placeholder}"
        );
    }

    // No resolved API/DLL name may appear as a string literal in the
    // generated source (checking the quoted form keeps the check honest: the
    // error-variant identifiers legitimately contain e.g. "VirtualProtect").
    for name in [
        "kernel32.dll",
        "ntdll.dll",
        "advapi32.dll",
        "CreateTimerQueue",
        "CreateTimerQueueTimer",
        "DeleteTimerQueueEx",
        "WaitForSingleObject",
        "SetEvent",
        "VirtualProtect",
        "RtlCaptureContext",
        "NtContinue",
        "SystemFunction032",
    ] {
        assert!(
            !fragment.contains(&format!("\"{name}\"")),
            "cleartext literal leaked: {name}"
        );
    }

    // The xor strategy routes every name through the runtime decoder.
    assert!(fragment.contains("crate::dec_xor"));
}

/// Full e2e: render + compile a `sleep_obfuscation → reflective_loading` stub,
/// producing a PE. This locks in that the fragment (which references
/// `crate::KEY_HEX` and several windows-rs types) compiles inside a generated
/// stub, not just in isolation.
///
/// Marked `#[ignore]` because it requires `rustc` and the compiled
/// dependencies. Run it with `cargo test -- --ignored`.
#[test]
#[ignore = "requires rustc and the compiled dependencies"]
fn compiles_sleep_obfuscation_stub_to_pe() {
    use std::path::Path;

    let plaintext: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
    let key = crate::engine::crypto::generate_key();
    let encrypted = crate::engine::crypto::encrypt_payload(&plaintext, &key).unwrap();

    let build_dir = std::env::temp_dir().join(format!("picaro_sleep_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&build_dir);
    std::fs::create_dir_all(&build_dir).unwrap();
    std::fs::write(build_dir.join("payload.bin"), &encrypted.ciphertext).unwrap();

    let template = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src").join("engine").join("templates")
            .join("main.rs.tpl"),
    )
    .unwrap();
    let pipeline = vec![
        crate::techniques::RuntimeStep::new(TechniqueKind::SleepObfuscation {
            params: Params {
                variant: Variant::Ekko,
                sleep_ms: 5000,
                encrypt_regions: vec![EncryptRegion::Payload],
            },
        }),
        crate::techniques::RuntimeStep::new(TechniqueKind::ReflectiveLoading {
            params: crate::techniques::reflective_loading::Params::default(),
        }),
    ];
    let strings = StringsConfig::from_yaml(None).unwrap();
    let params = crate::engine::steps::test_params(
        &pipeline,
        &encrypted,
        "payload.bin",
        crate::plan::schema::PayloadFormat::Pe,
        None,
        false,
    );
    let stub_src = crate::engine::steps::render_builtin(
        &template,
        &params,
        &strings,
        &crate::engine::syscalls::SyscallsConfig::default(),
        &crate::engine::api_resolution::ApiResolutionConfig::default(),
    )
    .unwrap();
    let stub_path = build_dir.join("main.rs");
    std::fs::write(&stub_path, stub_src).unwrap();

    let deps = crate::engine::compiler::locate_stub_deps(crate::plan::schema::Arch::X64).unwrap();
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
