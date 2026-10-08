//! Tests for fiber execution.

use super::{Params, DEF};
use crate::engine::obfuscation::StringsConfig;
use crate::plan::schema::PayloadFormat;
use crate::techniques::{Category, TechniqueKind};

/// Every message `render_fragment_for` obfuscates must not survive in the
/// rendered fragment as cleartext.
const MESSAGE_TEXTS: &[&str] = &[
    "the payload is empty",
    "could not allocate the payload region",
    "could not convert the current thread to a fiber",
    "could not create the payload fiber",
    "could not make the payload executable",
    "runs raw shellcode payloads only",
];

/// Formats the technique is rendered for, including the ones the fragment
/// refuses at runtime (the guard still has to be valid Rust).
const FORMATS: [PayloadFormat; 4] = [
    PayloadFormat::Shellcode,
    PayloadFormat::Pe,
    PayloadFormat::Dll,
    PayloadFormat::Dotnet,
];

#[test]
fn parses_params_from_empty_yaml() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: fibers\n").expect("fibers should parse");
    assert_eq!(
        step,
        TechniqueKind::Fibers {
            params: Params::default()
        }
    );
}

#[test]
fn parses_a_payload_name() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: fibers\nparams:\n  payload: implant\n")
            .expect("fibers with a payload should parse");
    match step {
        TechniqueKind::Fibers { params } => {
            assert_eq!(params.payload.as_deref(), Some("implant"));
        }
        other => panic!("expected fibers, got {other:?}"),
    }
}

#[test]
fn def_is_well_formed() {
    assert_eq!(DEF.name, "fibers");
    assert_eq!(DEF.category, Category::Execution);
    assert!(!DEF.attck.is_empty());
    assert!(!DEF.requires.is_empty());
    assert!(!DEF.stub_fragment.is_empty());
    assert!(!DEF.readme.is_empty());
}

/// ATT&CK has no fiber-specific sub-technique, so the parent `T1055` is the
/// mapping; the fragment's only kernel-facing call goes through the syscall
/// layer, and raw shellcode has no import table to resolve.
#[test]
fn def_declares_the_injection_metadata() {
    // Through the registry (a runtime lookup), so the const fields are asserted
    // as values rather than compile-time constants.
    let def = crate::techniques::find("fibers").expect("fibers must be registered");
    assert_eq!(def.attck, &["T1055"]);
    assert_eq!(
        def.syscalls,
        &["NtAllocateVirtualMemory", "NtProtectVirtualMemory"]
    );
    assert!(!def.resolves_imports, "shellcode has no imports to resolve");
    assert!(!def.conflicts.contains(&def.name));
}

#[test]
fn params_example_parses_as_a_runtime_step() {
    let step: crate::techniques::RuntimeStep =
        serde_yml::from_str(DEF.params_example).expect("params_example must parse");
    assert_eq!(step.name(), "fibers");
}

#[test]
fn def_exposes_the_execution_entry_point() {
    assert!(
        DEF.stub_fragment.contains("fn execute_payload"),
        "the fragment must define the Execution contract"
    );
}

#[test]
fn the_fragment_defines_the_execution_contract() {
    assert!(
        DEF.stub_fragment
            .contains("pub fn execute_payload(image: &mut [u8]) -> Result<i32, String>"),
        "the generated wrapper calls exactly this signature"
    );
}

#[test]
fn render_fragment_for_returns_the_fragment() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params::default().render_fragment_for(&strings, PayloadFormat::Shellcode, None);
    assert!(fragment.contains("fn execute_payload"));
}

/// Every placeholder is substituted for every payload format, including the
/// formats the fragment refuses: a left-over `$...$` token is not valid Rust and
/// would break the stub build.
#[test]
fn every_placeholder_is_substituted_for_every_format() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    for format in FORMATS {
        let fragment = Params::default().render_fragment_for(&strings, format, None);
        assert!(
            !fragment.contains('$'),
            "an unsubstituted placeholder would break the stub ({format:?})"
        );
    }
}

/// The runtime diagnostics are rebuilt from obfuscated bytes: none of the
/// message texts may appear in a rendered fragment (under either strategy).
#[test]
fn rendered_fragment_hides_every_message() {
    let xor = StringsConfig::from_yaml(None).expect("default strings");
    let stack = StringsConfig {
        strategy: crate::engine::obfuscation::StringStrategy::Stack,
        key: None,
    };

    for strings in [xor, stack] {
        for format in FORMATS {
            let fragment = Params::default().render_fragment_for(&strings, format, None);
            for text in MESSAGE_TEXTS {
                assert!(
                    !fragment.contains(text),
                    "message text leaked in cleartext ({format:?}): {text}"
                );
            }
        }
    }
}

/// The fragment only runs raw shellcode: the guard is enabled for that format
/// and disabled (with the message still substituted, as dead code) otherwise.
#[test]
fn the_format_guard_marks_shellcode_supported() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let params = Params::default();

    let shellcode = params.render_fragment_for(&strings, PayloadFormat::Shellcode, None);
    assert!(
        shellcode.contains("if !true"),
        "a shellcode payload must pass the format guard"
    );

    let pe = params.render_fragment_for(&strings, PayloadFormat::Pe, None);
    assert!(
        pe.contains("if !false"),
        "a non-shellcode payload must hit the format guard"
    );
    assert!(
        !pe.contains("format is 'pe'"),
        "the guard message must be obfuscated, not inlined"
    );
}

/// The fragment must not call the Win32 memory/thread APIs directly and must
/// leave the fiber bookkeeping visible (the technique's static signature).
#[test]
fn the_fragment_routes_kernel_memory_calls_through_the_syscall_layer() {
    for forbidden in [
        "VirtualAlloc(",
        "VirtualAllocEx(",
        "VirtualProtect(",
        "VirtualProtectEx(",
        "VirtualFree(",
        "CreateThread(",
        "CreateRemoteThread(",
        "WriteProcessMemory(",
        "ExitProcess(",
    ] {
        assert!(
            !DEF.stub_fragment.contains(forbidden),
            "a stub fragment must not call '{forbidden}' directly"
        );
    }
    assert!(
        DEF.stub_fragment.contains("crate::nt_alloc_vm("),
        "the region allocation must go through the syscall layer"
    );
    assert!(
        DEF.stub_fragment.contains("crate::nt_protect_vm("),
        "page protection must go through the syscall layer"
    );

    // The technique is *returning* by design: it schedules the loader's fiber
    // again instead of letting the fiber function return (which exits the
    // thread).
    assert!(DEF.stub_fragment.contains("SwitchToFiber("));
    assert!(DEF.stub_fragment.contains("payload_fiber"));
    assert!(DEF.stub_fragment.contains("DeleteFiber("));
    assert!(DEF.stub_fragment.contains("ConvertFiberToThread("));
}

#[test]
fn fragment_has_no_forbidden_patterns() {
    for forbidden in [
        "anyhow",
        "static mut",
        "println!",
        "unwrap(",
        "expect(",
        "todo!",
        "unimplemented!",
        "panic!",
    ] {
        assert!(
            !DEF.stub_fragment.contains(forbidden),
            "a stub fragment must not contain '{forbidden}'"
        );
    }
}

/// Renders and compiles a fibers stub for one payload format, returning the
/// generated source (before the `$`-bearing debug prelude).
///
/// Shared by the ignored compile tests, which need `rustc` and the compiled
/// dependencies and therefore only run under `cargo test -- --ignored`.
#[cfg(test)]
fn render_stub_for(format: PayloadFormat, name: &str) -> String {
    use std::path::Path;

    let plaintext: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
    let key = crate::engine::crypto::generate_key();
    let encrypted = crate::engine::crypto::encrypt_payload(&plaintext, &key).expect("encrypt");

    let build_dir =
        std::env::temp_dir().join(format!("picaro_fibers_{name}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&build_dir);
    std::fs::create_dir_all(&build_dir).expect("build dir");
    std::fs::write(build_dir.join("payload.bin"), &encrypted.ciphertext).expect("payload");

    let template = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src").join("engine").join("templates")
            .join("main.rs.tpl"),
    )
    .expect("template");

    let params = crate::engine::steps::test_params(
        &[crate::techniques::RuntimeStep::new(TechniqueKind::Fibers {
            params: Params::default(),
        })],
        &encrypted,
        "payload.bin",
        format,
        None,
        false,
    );
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let stub_src = crate::engine::steps::render_builtin(
        &template,
        &params,
        &strings,
        &crate::engine::syscalls::SyscallsConfig::default(),
        &crate::engine::api_resolution::ApiResolutionConfig::default(),
    )
    .expect("render");

    // The appended debug prelude uses `$` as Rust macro syntax, so the
    // placeholder check runs over the template's own output.
    let body = crate::engine::debug::strip_prelude(&stub_src).to_string();
    assert!(
        !body.contains('$'),
        "{name}: an unsubstituted placeholder reached the stub"
    );
    assert!(
        body.contains("fn execute_payload"),
        "{name}: the step module is missing the execution contract"
    );

    let stub_path = build_dir.join("main.rs");
    std::fs::write(&stub_path, stub_src).expect("write stub");

    let deps = crate::engine::compiler::locate_stub_deps(crate::plan::schema::Arch::X64)
        .expect("stub deps");
    let out = build_dir.join("out.exe");
    // `compile_stub` verifies the `MZ` header before returning.
    crate::engine::compiler::compile_stub(
        &stub_path,
        &out,
        &deps,
        crate::engine::compiler::CompileOptions::default(),
    )
    .expect("compile");

    let _ = std::fs::remove_dir_all(&build_dir);
    body
}

/// Full e2e: render + compile a fibers stub for a shellcode payload (the
/// supported format), producing a PE.
///
/// Marked `#[ignore]` because it requires `rustc` and the compiled
/// dependencies. Run it with `cargo test -- --ignored`.
#[test]
#[ignore = "requires rustc and the compiled dependencies"]
fn compiles_a_fibers_stub_for_shellcode() {
    render_stub_for(PayloadFormat::Shellcode, "shellcode");
}

/// The format guard is rendered for a non-shellcode payload too, so the
/// error-returning branch must compile as well (the plan should be rejected at
/// validation time; this keeps the fallback honest).
///
/// Marked `#[ignore]` because it requires `rustc` and the compiled
/// dependencies.
#[test]
#[ignore = "requires rustc and the compiled dependencies"]
fn compiles_the_format_guard_for_a_pe_payload() {
    let body = render_stub_for(PayloadFormat::Pe, "pe_guard");
    assert!(
        body.contains("if !false"),
        "the guard must be live for a non-shellcode payload"
    );
}

/// The fragment is arch-neutral (`extern "system"` is stdcall on x86, the same
/// shape `PFIBER_START_ROUTINE` uses), so the i686 stub must compile too.
///
/// Marked `#[ignore]` because it needs `rustc` and the workspace built for the
/// i686 target: `cargo build --target i686-pc-windows-msvc`.
#[test]
#[ignore = "requires rustc and the workspace built for the i686 target"]
fn compiles_a_fibers_stub_for_i686() {
    use std::path::Path;

    let plaintext: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
    let key = crate::engine::crypto::generate_key();
    let encrypted = crate::engine::crypto::encrypt_payload(&plaintext, &key).expect("encrypt");

    let build_dir = std::env::temp_dir().join(format!("picaro_fibers_i686_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&build_dir);
    std::fs::create_dir_all(&build_dir).expect("build dir");
    std::fs::write(build_dir.join("payload.bin"), &encrypted.ciphertext).expect("payload");

    let template = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src").join("engine").join("templates")
            .join("main.rs.tpl"),
    )
    .expect("template");
    let params = crate::engine::steps::test_params(
        &[crate::techniques::RuntimeStep::new(TechniqueKind::Fibers {
            params: Params::default(),
        })],
        &encrypted,
        "payload.bin",
        PayloadFormat::Shellcode,
        None,
        false,
    );
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let stub_src = crate::engine::steps::render_builtin(
        &template,
        &params,
        &strings,
        &crate::engine::syscalls::SyscallsConfig::default(),
        &crate::engine::api_resolution::ApiResolutionConfig::default(),
    )
    .expect("render");
    let stub_path = build_dir.join("main.rs");
    std::fs::write(&stub_path, stub_src).expect("write stub");

    let arch = crate::plan::schema::Arch::X86;
    let deps = crate::engine::compiler::locate_stub_deps(arch).expect("i686 stub deps");
    let out = build_dir.join("out.exe");
    crate::engine::compiler::compile_stub(
        &stub_path,
        &out,
        &deps,
        crate::engine::compiler::CompileOptions {
            arch,
            ..crate::engine::compiler::CompileOptions::default()
        },
    )
    .expect("compile");

    let info = crate::engine::pe::parse(&std::fs::read(&out).expect("read")).expect("PE32");
    assert_eq!(info.machine, crate::engine::pe::IMAGE_FILE_MACHINE_I386);
    let _ = std::fs::remove_dir_all(&build_dir);
}
