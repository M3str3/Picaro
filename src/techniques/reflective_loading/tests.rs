//! Tests for the reflective loading technique.

use super::{Params, DEF, SHELLCODE_FRAGMENT};
use crate::engine::obfuscation::StringsConfig;
use crate::plan::schema::PayloadFormat;
use crate::techniques::{RuntimeStep, TechniqueKind};
use std::process::Command;

#[test]
fn parses_params_from_empty_yaml() {
    let step: TechniqueKind = serde_yml::from_str("technique: reflective_loading\n")
        .expect("reflective_loading should parse");
    assert_eq!(
        step,
        TechniqueKind::ReflectiveLoading {
            params: Params::default()
        }
    );
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
    let params = Params::default();

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
    let params = Params::default();

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

    let build_dir = std::env::temp_dir().join(format!("picaro_refl_fmt_{}", std::process::id()));
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

    let deps = crate::engine::compiler::locate_stub_deps(crate::plan::schema::Arch::X64).unwrap();
    let strings = crate::engine::obfuscation::StringsConfig::from_yaml(None).unwrap();

    // (format, export, output name)
    let cases = [
        (PayloadFormat::Pe, None, "pe"),
        (PayloadFormat::Dll, Some("Run"), "dll"),
        (PayloadFormat::Shellcode, None, "shellcode"),
    ];

    for (format, export, name) in cases {
        let pipeline = vec![RuntimeStep::new(TechniqueKind::ReflectiveLoading {
            params: Params::default(),
        })];
        let params = crate::engine::steps::test_params(
            &pipeline,
            &encrypted,
            "payload.bin",
            format,
            export,
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

    let build_dir = std::env::temp_dir().join(format!("picaro_refl_{}", std::process::id()));
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
    let params = crate::engine::steps::test_params(
        &[RuntimeStep::new(TechniqueKind::ReflectiveLoading {
            params: Params::default(),
        })],
        &encrypted,
        "payload.bin",
        PayloadFormat::Pe,
        None,
        false,
    );
    let strings = crate::engine::obfuscation::StringsConfig::from_yaml(None).unwrap();
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

/// Builds the `api_resolution` probe payload, packs it with an indirect-syscall
/// `reflective_loading` stub and the given `apis:` selection and `unmatched`
/// policy (debug build, so the proxies emit `tech_dbg!` traces), runs it and
/// returns `(exit status, stdout, stderr)`.
fn run_proxy_case(
    name: &str,
    apis_yaml: &str,
    unmatched: &str,
) -> (std::process::ExitStatus, String, String) {
    use std::path::Path;

    let build_dir =
        std::env::temp_dir().join(format!("picaro_api_res_{}_{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&build_dir);
    std::fs::create_dir_all(&build_dir).unwrap();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    // 1. Compile the probe payload with a single `rustc`.
    let rustc = crate::engine::compiler::find_rustc().unwrap();
    let probe_exe = build_dir.join("probe.exe");
    let status = Command::new(&rustc)
        .arg(root.join("tests").join("fixtures").join("api_probe.rs"))
        .args(["-O", "-C", "strip=symbols", "-o"])
        .arg(&probe_exe)
        .status()
        .unwrap();
    assert!(status.success(), "probe compilation failed");
    let plaintext = std::fs::read(&probe_exe).unwrap();

    // 2. Encrypt it as the payload the stub embeds.
    let key = crate::engine::crypto::generate_key();
    let encrypted = crate::engine::crypto::encrypt_payload(&plaintext, &key).unwrap();
    std::fs::write(build_dir.join("payload.bin"), &encrypted.ciphertext).unwrap();

    // 3. Resolve the loader configs.
    let syscalls = crate::engine::syscalls::SyscallsConfig {
        mode: crate::engine::syscalls::SyscallsMode::Indirect,
        resolver: crate::engine::syscalls::Resolver::HellsGate,
    };
    let yaml = format!("mode: proxy\nunmatched: {unmatched}\napis:\n{apis_yaml}");
    let yaml: crate::engine::api_resolution::YamlApiResolutionPlan =
        serde_yml::from_str(&yaml).unwrap();
    let api_resolution =
        crate::engine::api_resolution::ApiResolutionConfig::from_yaml(Some(&yaml)).unwrap();

    // 4. Render (debug) and compile the stub.
    let template =
        std::fs::read_to_string(root.join("templates").join("stub").join("main.rs.tpl")).unwrap();
    let params = crate::engine::steps::test_params(
        &[RuntimeStep::new(TechniqueKind::ReflectiveLoading {
            params: Params::default(),
        })],
        &encrypted,
        "payload.bin",
        PayloadFormat::Pe,
        None,
        true,
    );
    let strings = StringsConfig::from_yaml(None).unwrap();
    let stub_src = crate::engine::steps::render_builtin(
        &template,
        &params,
        &strings,
        &syscalls,
        &api_resolution,
    )
    .unwrap();
    let stub_path = build_dir.join("main.rs");
    std::fs::write(&stub_path, stub_src).unwrap();

    let deps = crate::engine::compiler::locate_stub_deps(crate::plan::schema::Arch::X64).unwrap();
    let out = build_dir.join("out.exe");
    crate::engine::compiler::compile_stub(
        &stub_path,
        &out,
        &deps,
        crate::engine::compiler::CompileOptions::default(),
    )
    .unwrap();

    // 5. Run the artifact and capture both streams.
    let output = Command::new(&out).output().unwrap();
    let status = output.status;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let _ = std::fs::remove_dir_all(&build_dir);
    (status, stdout, stderr)
}

/// Strategy `route_to_nt` (rebuild): `kernel32!OpenProcess` is rebuilt on
/// `NtOpenProcess` and the returned handle must be valid and usable.
#[test]
#[ignore = "requires rustc and the compiled dependencies"]
fn api_resolution_rebuilds_openprocess() {
    let (_, stdout, stderr) =
        run_proxy_case("rebuild", "  - \"kernel32!OpenProcess\"\n", "forward");
    assert!(
        stderr.contains("routed to the syscall layer"),
        "no route trace:\n{stderr}"
    );
    assert!(
        !stdout.contains("open=0x0 via_handle"),
        "null handle:\n{stdout}"
    );
    assert!(
        stdout.contains("via_handle=1 bytes=[88, 77, 66, 55, 44, 33, 22, 11]"),
        "the rebuilt handle was not usable:\n{stdout}"
    );
}

/// Strategy `route_to_nt` (direct): the `ntdll!NtOpenProcess` entry routes
/// through the syscall layer.
#[test]
#[ignore = "requires rustc and the compiled dependencies"]
fn api_resolution_routes_ntopenprocess() {
    let (_, stdout, stderr) = run_proxy_case("ntopen", "  - \"ntdll!NtOpenProcess\"\n", "forward");
    assert!(
        stderr.contains("routed to the syscall layer"),
        "no route trace:\n{stderr}"
    );
    assert!(
        !stderr.contains("forwarded to the original"),
        "unexpected forward trace:\n{stderr}"
    );
    assert!(
        stdout.contains("ntopen=0x00000000 handle=0x"),
        "wrong status:\n{stdout}"
    );
    assert!(!stdout.contains("handle=0x0\n"), "null handle:\n{stdout}");
}

/// The `GetProcAddress` handler: a catalogue name gets its proxy, an ordinal is
/// forwarded to the original resolver.
#[test]
#[ignore = "requires rustc and the compiled dependencies"]
fn api_resolution_handler_returns_proxies() {
    let (_, stdout, stderr) = run_proxy_case(
        "handler",
        "  - \"kernel32!GetProcAddress\"\n  - \"kernel32!ReadProcessMemory\"\n",
        "forward",
    );
    assert!(
        stderr.contains("returned a proxy"),
        "the handler did not return a proxy:\n{stderr}"
    );
    assert!(
        stderr.contains("forwarded to the original"),
        "the ordinal was not forwarded:\n{stderr}"
    );
    assert!(
        stdout.contains("rc=1 bytes=[88, 77, 66, 55, 44, 33, 22, 11]"),
        "the dynamically resolved proxy returned wrong data:\n{stdout}"
    );
}

/// Strategy `route_to_nt` (direct): the `ntdll!Nt*` entry routes through the
/// syscall layer.
#[test]
#[ignore = "requires rustc and the compiled dependencies"]
fn api_resolution_routes_ntreadvirtualmemory() {
    let (_, stdout, stderr) =
        run_proxy_case("direct", "  - \"ntdll!NtReadVirtualMemory\"\n", "forward");
    assert!(
        stderr.contains("routed to the syscall layer"),
        "no route trace:\n{stderr}"
    );
    assert!(
        !stderr.contains("forwarded to the original"),
        "unexpected forward trace:\n{stderr}"
    );
    assert!(
        stdout.contains("API_PROBE ntrvm=0x00000000 read=8 bytes=[88, 77, 66, 55, 44, 33, 22, 11]"),
        "wrong data or status:\n{stdout}"
    );
}

/// Strategy `route_to_nt` (wrapper): `kernel32!ReadProcessMemory` is
/// re-implemented on `NtReadVirtualMemory` (NTSTATUS -> BOOL).
#[test]
#[ignore = "requires rustc and the compiled dependencies"]
fn api_resolution_wraps_readprocessmemory() {
    let (_, stdout, stderr) =
        run_proxy_case("wrapper", "  - \"kernel32!ReadProcessMemory\"\n", "forward");
    assert!(
        stderr.contains("routed to the syscall layer"),
        "no route trace:\n{stderr}"
    );
    assert!(
        !stderr.contains("forwarded to the original"),
        "unexpected forward trace:\n{stderr}"
    );
    assert!(
        stdout.contains("API_PROBE rpm=1 read=8 bytes=[88, 77, 66, 55, 44, 33, 22, 11]"),
        "wrong data:\n{stdout}"
    );
}

/// `unmatched: abort` fails the load on the first payload import outside the
/// catalogue, so the probe never runs (finding 1: the option used to be parsed
/// but ignored).
#[test]
#[ignore = "requires rustc and the compiled dependencies"]
fn api_resolution_aborts_on_unmatched() {
    // Only `NtReadVirtualMemory` is proxied, but the probe imports and uses many
    // other APIs, so the very first non-catalogue import must abort the load.
    let (status, stdout, stderr) =
        run_proxy_case("abort", "  - \"ntdll!NtReadVirtualMemory\"\n", "abort");
    assert!(
        !status.success(),
        "the load should have failed under unmatched: abort:\n{stderr}"
    );
    assert!(
        !stdout.contains("API_PROBE"),
        "the payload ran despite unmatched: abort:\n{stdout}"
    );
}
