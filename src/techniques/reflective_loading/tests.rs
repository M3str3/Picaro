//! Tests for the reflective loading technique.

use super::{Params, DEF, MESSAGES, SHELLCODE_FRAGMENT, SHELLCODE_MESSAGES};
use crate::engine::obfuscation::StringsConfig;
use crate::plan::schema::PayloadFormat;
#[cfg(feature = "live-tests")]
use crate::techniques::RuntimeStep;
use crate::techniques::TechniqueKind;
#[cfg(feature = "live-tests")]
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

/// The option is opt-in: a plan that does not mention it keeps the mapped
/// header intact.
#[test]
fn erase_header_defaults_to_off() {
    assert!(!Params::default().erase_header);

    let step: TechniqueKind = serde_yml::from_str("technique: reflective_loading\nparams: {}\n")
        .expect("an empty params mapping should parse");
    assert_eq!(
        step,
        TechniqueKind::ReflectiveLoading {
            params: Params::default()
        }
    );
}

#[test]
fn parses_erase_header_from_params() {
    let step: TechniqueKind =
        serde_yml::from_str("technique: reflective_loading\nparams:\n  erase_header: true\n")
            .expect("reflective_loading should parse");
    assert_eq!(
        step,
        TechniqueKind::ReflectiveLoading {
            params: Params {
                erase_header: true,
                ..Params::default()
            }
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
    assert!(
        serde_yml::from_str::<TechniqueKind>(DEF.params_example).is_ok(),
        "params_example must parse as a runtime step: {}",
        DEF.params_example
    );
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

/// The flag reaches the fragment as a `true`/`false` constant: off keeps the
/// mapped header, on enables the zeroing.
#[test]
fn the_rendered_fragment_carries_the_erase_header_flag() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");

    let off = Params::default().render_fragment(&strings);
    assert!(off.contains("const ERASE_HEADER: bool = false;"));
    assert!(off.contains("fn erase_mapped_header"));

    let on = Params {
        erase_header: true,
        ..Params::default()
    }
    .render_fragment(&strings);
    assert!(on.contains("const ERASE_HEADER: bool = true;"));
}

/// The zeroing writes `SizeOfHeaders` zero bytes at the mapped base, after the
/// loader's fixups and before the payload's entry point runs.
#[test]
fn erase_header_zeroes_the_mapped_header_before_the_entry_point() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params {
        erase_header: true,
        ..Params::default()
    }
    .render_fragment(&strings);

    assert!(fragment.contains("(*nt).OptionalHeader.SizeOfHeaders as usize"));
    assert!(fragment.contains("ptr::write_bytes(image_base as *mut u8, 0, size)"));
    let erase = fragment
        .find("erase_mapped_header(image_base, nt);")
        .expect("the enabled fragment must erase the mapped header");
    let entry = fragment
        .find("exe_main()")
        .expect("the mapper must call the payload's entry point");
    assert!(
        erase < entry,
        "the header must be erased before the payload's entry point runs"
    );
}

/// The decrypted buffer holds the only pristine DLL: the export may block for
/// its whole lifetime, so the loader zeroes the buffer once the export address
/// is resolved and before the export runs. Everything that reads `nt` from the
/// buffer (TLS callbacks, `DllMain`, header erasure, the export lookup) runs
/// first, and `resolve_export` returns an address in the mapped image, not the
/// buffer.
#[test]
fn the_export_path_zeroes_the_decrypted_payload_after_the_lookup() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params::default().render_fragment(&strings);

    let resolve = fragment
        .find("let address = resolve_export(image_base, nt, name)?;")
        .expect("the export path must resolve the export");
    let zero = fragment
        .find("payload.fill(0);")
        .expect("the export path must zero the decrypted payload");
    let call = fragment
        .find("call_export(address);")
        .expect("the export path must call the export");

    assert!(
        resolve < zero && zero < call,
        "the buffer must be zeroed after the export lookup and before the export runs"
    );
    assert_eq!(
        fragment.matches("payload.fill(0);").count(),
        1,
        "nothing may zero the buffer before the steps that read its headers"
    );
    assert!(
        fragment
            .replace("\r\n", "\n")
            .contains("payload: &mut [u8],"),
        "run_reflective must take the buffer mutably so it can be zeroed"
    );
}

/// A shellcode payload has no mapped image, so enabling the option changes
/// nothing in its fragment.
#[test]
fn erase_header_does_not_change_the_shellcode_fragment() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let plain = Params::default().render_fragment_for(&strings, PayloadFormat::Shellcode, None);
    let enabled = Params {
        erase_header: true,
        ..Params::default()
    }
    .render_fragment_for(&strings, PayloadFormat::Shellcode, None);
    assert_eq!(plain, enabled);
}

/// A payload that did not land at its preferred base is only fixable with base
/// relocations: without them the load has to fail instead of running with stale
/// absolute addresses, so the mapper checks for relocations *after* it knows it
/// has to move the image.
#[test]
fn the_mapper_refuses_to_run_a_relocated_image_without_relocations() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params::default().render_fragment(&strings);

    let delta_check = fragment
        .find("let delta = image_base as isize - preferred;")
        .expect("the mapper must compute the relocation delta");
    let landed = fragment
        .find("if delta == 0 {")
        .expect("landing at the preferred base skips the fixups");
    let missing = fragment
        .find("if reloc_dir.Size == 0 || reloc_dir.VirtualAddress == 0 {")
        .expect("the mapper must look for the relocation directory");
    assert!(
        delta_check < landed && landed < missing,
        "the no-relocation refusal must depend on the delta, not run before it"
    );
    let refusal = fragment[missing..]
        .find('}')
        .expect("the relocation guard must be a block");
    assert!(
        fragment[missing..missing + refusal].contains("return Err("),
        "an image that cannot be relocated must fail the load"
    );
}

/// A manually mapped image gets no static-TLS slot, and it cannot be faked: the
/// loader frees the thread's `ThreadLocalStoragePointer` array (and every entry
/// it holds) from a heap it owns when the thread exits, so an array we allocate
/// faults there — measured 2026-10-18 with a plain-exe reproducer
/// (`LdrShutdownThread` reading `array - 0x10`). The fragment therefore only
/// runs the payload's `DLL_PROCESS_ATTACH` callbacks.
#[test]
fn the_mapper_does_not_provision_static_tls() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params::default().render_fragment(&strings);

    assert!(
        !fragment.contains("TlsAlloc()"),
        "no dynamic index is taken"
    );
    assert!(
        !fragment.contains("set_tls_array"),
        "the TEB array is untouched"
    );
    assert!(
        !fragment.contains("provision_tls"),
        "nothing is provisioned"
    );
    assert!(
        fragment.contains("fn run_tls_callbacks"),
        "the payload's TLS callbacks still have to run"
    );

    let callbacks = fragment
        .find("run_tls_callbacks(image_base, nt);")
        .expect("the mapper must run the payload's callbacks");
    let entry = fragment
        .find("exe_main()")
        .expect("the mapper must call the payload's entry point");
    assert!(
        callbacks < entry,
        "the callbacks must run before the payload's entry point"
    );
}

/// The export lookup is bounds-checked against the image and refuses a
/// forwarded export, whose entry is a string inside the export directory rather
/// than code.
#[test]
fn the_export_lookup_refuses_a_forwarder() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params::default().render_fragment(&strings);

    assert!(
        // The fragment keeps the source file's line endings (CRLF on a Windows
        // checkout), so the signature is matched on a normalized copy.
        fragment.replace("\r\n", "\n").contains(
            "fn resolve_export(\n    image_base: *mut c_void,\n    nt: *const NtHeaders,\n    wanted: &str,\n) -> Result<usize, String>"
        ),
        "the lookup must report why it failed, not just miss"
    );
    assert!(
        fragment.contains("function_rva >= dir_start && function_rva < dir_end"),
        "a function RVA inside the export directory is a forwarder"
    );
    // The raw fragment, before the messages are substituted: each table and each
    // name is checked against `SizeOfImage`.
    assert!(
        DEF.stub_fragment
            .contains("ok_or_else(|| $MSG_EXPORT_OUT_OF_IMAGE$)"),
        "the export tables must be bounds-checked"
    );
}

/// The bounds the mapper relies on: the headers, the size fields, the section
/// table, each section's source and destination, and the entry point.
#[test]
fn the_mapper_bounds_checks_the_image_it_maps() {
    let strings = StringsConfig::from_yaml(None).expect("default strings");
    let fragment = Params::default().render_fragment(&strings);

    for guard in [
        // The NT headers and the section table fit in the file buffer.
        "checked_add(std::mem::size_of::<NtHeaders>())",
        "(*nt).FileHeader.NumberOfSections as usize * std::mem::size_of::<IMAGE_SECTION_HEADER>()",
        // `SizeOfHeaders` is copied into an image that has to hold it.
        "size_of_headers > size_of_image",
        // The entry point is inside the image (or zero for a DLL).
        "entry_point != 0 && entry_point >= size_of_image",
        // Both ends of a section copy, with checked arithmetic.
        "checked_add(raw_size)",
        // An executable without an entry point never jumps into its header.
        "if entry_rva == 0 {",
    ] {
        assert!(
            fragment.contains(guard),
            "the mapper dropped a bounds guard: {guard}"
        );
    }
}

/// Every message in the tables is used by its fragment, and neither table
/// repeats a token: a placeholder left in the text would reach the stub as a
/// `$TOKEN$`, and one missing from a table would never be substituted.
#[test]
fn every_message_is_used_and_unique() {
    for (messages, fragment) in [
        (MESSAGES, DEF.stub_fragment),
        (SHELLCODE_MESSAGES, SHELLCODE_FRAGMENT),
    ] {
        for (i, (placeholder, message)) in messages.iter().enumerate() {
            assert!(
                fragment.contains(placeholder),
                "'{placeholder}' is in the table but not in the fragment"
            );
            assert!(
                !message.is_empty(),
                "'{placeholder}' has no diagnostic text"
            );
            for (other, _) in &messages[..i] {
                assert_ne!(placeholder, other, "a placeholder is listed twice");
            }
        }
    }
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

/// The exact guardrail the build flow relies on: a rendered fragment -- the PE
/// mapper and the shellcode runner alike -- leaves no `$PLACEHOLDER$` token and
/// no sensitive literal in the generated source, under either obfuscation
/// strategy.
#[test]
fn rendered_fragments_have_no_placeholders_or_sensitive_literals() {
    use crate::audit::strings::find_sensitive_literals_in_source;
    use crate::engine::obfuscation::StringStrategy;

    let strategies = [
        StringsConfig::from_yaml(None).expect("default strings"),
        StringsConfig {
            strategy: StringStrategy::Stack,
            key: None,
        },
    ];

    for strings in strategies {
        for erase_header in [false, true] {
            for format in [
                PayloadFormat::Pe,
                PayloadFormat::Dll,
                PayloadFormat::Shellcode,
            ] {
                let params = Params {
                    erase_header,
                    ..Params::default()
                };
                let fragment = params.render_fragment_for(&strings, format, None);
                assert!(
                    !fragment.contains('$'),
                    "an unsubstituted placeholder would break the stub ({format:?})"
                );
                let leaked = find_sensitive_literals_in_source(&fragment);
                assert!(
                    leaked.is_empty(),
                    "the rendered fragment leaks sensitive literals ({format:?}): {leaked:?}"
                );
            }
        }
    }
}

/// Full e2e: render + compile a reflective-loading stub for each payload
/// format, producing a PE each time.
///
/// Marked `#[ignore]` because it requires `rustc` and the compiled
/// dependencies. Run it with `cargo test --features live-tests -- --ignored`.
#[test]
#[cfg(feature = "live-tests")]
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
            .join("src")
            .join("engine")
            .join("templates")
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
/// dependencies. Run it with `cargo test --features live-tests -- --ignored`.
#[test]
#[cfg(feature = "live-tests")]
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
            .join("src")
            .join("engine")
            .join("templates")
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
#[cfg(feature = "live-tests")]
fn run_proxy_case(
    name: &str,
    apis_yaml: &str,
    unmatched: &str,
) -> (std::process::ExitStatus, String, String) {
    let probe_src = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("api_probe.rs");
    run_proxy_case_with(name, &probe_src, apis_yaml, unmatched, &[])
}

/// The same, with a custom probe source and extra runtime arguments.
#[cfg(feature = "live-tests")]
fn run_proxy_case_with(
    name: &str,
    probe_src: &std::path::Path,
    apis_yaml: &str,
    unmatched: &str,
    args: &[&str],
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
        .arg(probe_src)
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
    let template = std::fs::read_to_string(
        root.join("src")
            .join("engine")
            .join("templates")
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
    let output = Command::new(&out).args(args).output().unwrap();
    let status = output.status;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let _ = std::fs::remove_dir_all(&build_dir);
    (status, stdout, stderr)
}

/// Strategy `route_to_nt` (rebuild): `kernel32!OpenProcess` is rebuilt on
/// `NtOpenProcess` and the returned handle must be valid and usable.
#[test]
#[cfg(feature = "live-tests")]
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
#[cfg(feature = "live-tests")]
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
#[cfg(feature = "live-tests")]
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
#[cfg(feature = "live-tests")]
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
#[cfg(feature = "live-tests")]
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
#[cfg(feature = "live-tests")]
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

/// `OpenProcess` rebuild fidelity: the rebuilt call must reproduce the real
/// export's error semantics (a zero access mask and a bogus pid are refused
/// with `ERROR_INVALID_PARAMETER`) and still honour the `inherit` flag.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the compiled dependencies"]
fn api_resolution_openprocess_matches_error_semantics() {
    let (_, stdout, stderr) =
        run_proxy_case("openfidelity", "  - \"kernel32!OpenProcess\"\n", "forward");
    assert!(
        stderr.contains("routed to the syscall layer"),
        "no route trace:\n{stderr}"
    );
    // The proxy's `OpenProcess` must match the real export case for case
    // (null-or-not and the error code): a zero access mask, a bogus pid, a
    // valid pid, and the `inherit` flag.
    assert!(
        stdout.contains("API_PROBE open_fidelity agree=4/4"),
        "the proxy diverged from the real OpenProcess:\n{stdout}"
    );
    // `inherit != 0` maps to `OBJ_INHERIT`; the handle is still usable.
    assert!(
        !stdout.contains("inherit=0x0 rc="),
        "the inherit flag broke OpenProcess:\n{stdout}"
    );
    assert!(
        stdout.contains("inherit=0x") && stdout.contains(" rc=1 read=8"),
        "the inherited handle was not usable:\n{stdout}"
    );
}

/// Reentrancy: the proxies must answer many concurrent callers correctly.
///
/// The probe spawns eight threads that each route `ReadProcessMemory`, rebuild
/// `OpenProcess`, and resolve `ReadProcessMemory` dynamically through the
/// `GetProcAddress` handler. All eight must see the right bytes on every path.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the compiled dependencies"]
fn api_resolution_proxies_are_reentrant() {
    let (status, stdout, stderr) = run_proxy_case_with(
        "reentrant",
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("api_probe.rs"),
        "  - \"kernel32!GetProcAddress\"\n  - \"kernel32!OpenProcess\"\n  - \"kernel32!ReadProcessMemory\"\n",
        "forward",
        &["--threads"],
    );
    assert!(status.success(), "the threaded probe failed:\n{stderr}");
    assert!(
        stdout.contains("API_PROBE threads=8 rpm=8 open=8 gpa=8"),
        "a concurrent path misbehaved:\n{stdout}\n{stderr}"
    );
}

/// A payload whose import address table spans more than one page still loads:
/// `patch_imports` protects and restores every touched page, not just one.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the compiled dependencies"]
fn api_resolution_handles_a_multi_page_iat() {
    let dir = std::env::temp_dir().join(format!("picaro_api_res_mp_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let probe = generate_multi_page_probe(&dir);

    let (status, stdout, stderr) = run_proxy_case_with(
        "multipage",
        &probe,
        "  - \"kernel32!ReadProcessMemory\"\n",
        "forward",
        &[],
    );
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        status.success(),
        "the multi-page-IAT payload failed:\n{stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("API_MULTIPAGE imports="),
        "the payload did not run:\n{stdout}\n{stderr}"
    );
}

/// A wildcard selection proxies every direct `Nt*` route: the payload's
/// `ntdll!NtClose` (and its siblings) land on the generated proxies.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the compiled dependencies"]
fn api_resolution_proxies_every_direct_nt_route() {
    let (status, stdout, stderr) = run_proxy_case_with(
        "ntwildcard",
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("api_probe.rs"),
        "  - \"ntdll:*\"\n",
        "forward",
        &[],
    );
    assert!(status.success(), "the payload failed:\n{stderr}");
    assert!(
        stdout.contains("API_PROBE ntclose=0x00000000"),
        "NtClose was not served correctly:\n{stdout}"
    );
    // The native-signature proxy helper: NtWaitForSingleObject with a zero
    // relative timeout returns STATUS_TIMEOUT (0x102).
    assert!(
        stdout.contains("API_PROBE ntwait=0x00000102"),
        "the native-signature proxy helper misbehaved:\n{stdout}"
    );
    assert!(
        stderr.contains("routed to the syscall layer"),
        "no route trace:\n{stderr}"
    );
    assert!(
        !stderr.contains("forwarded to the original"),
        "a direct route was forwarded instead of proxied:\n{stderr}"
    );
}

/// The named exports of an on-disk DLL, read from its export directory.
#[cfg(feature = "live-tests")]
fn module_export_names(dll: &str) -> Vec<String> {
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let path = std::path::Path::new(&system_root)
        .join("System32")
        .join(dll);
    let file =
        std::fs::read(&path).unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()));

    let u16_at = |o: usize| u16::from_le_bytes([file[o], file[o + 1]]);
    let u32_at = |o: usize| u32::from_le_bytes([file[o], file[o + 1], file[o + 2], file[o + 3]]);

    let e_lfanew = u32_at(0x3C) as usize;
    assert_eq!(
        u32_at(e_lfanew),
        0x0000_4550,
        "not a PE: {}",
        path.display()
    );
    let num_sections = u16_at(e_lfanew + 4 + 2) as usize;
    let opt_size = u16_at(e_lfanew + 4 + 16) as usize;
    let opt = e_lfanew + 4 + 20;
    let is_pe32plus = u16_at(opt) == 0x20b;
    let dir_off = if is_pe32plus { opt + 112 } else { opt + 96 };
    let export_rva = u32_at(dir_off);
    assert!(export_rva != 0, "no exports in {dll}");

    let section_table = opt + opt_size;
    let sections: Vec<(u32, u32, u32, u32)> = (0..num_sections)
        .map(|i| {
            let s = section_table + i * 40;
            (
                u32_at(s + 12),
                u32_at(s + 8),
                u32_at(s + 16),
                u32_at(s + 20),
            )
        })
        .collect();
    let rva_to_off = |rva: u32| -> Option<usize> {
        for &(va, vsize, raw_size, ptr) in &sections {
            let size = vsize.max(raw_size);
            if rva >= va && rva < va + size {
                return Some((ptr + (rva - va)) as usize);
            }
        }
        None
    };

    let ed = rva_to_off(export_rva).expect("export directory");
    let num_names = u32_at(ed + 24) as usize;
    let names_off = rva_to_off(u32_at(ed + 32)).expect("name pointer table");

    let mut names = Vec::with_capacity(num_names);
    for i in 0..num_names {
        let Some(off) = rva_to_off(u32_at(names_off + i * 4)) else {
            continue;
        };
        let len = file[off..].iter().position(|&b| b == 0).unwrap_or(0);
        if len == 0 {
            continue;
        }
        if let Ok(name) = std::str::from_utf8(&file[off..off + len]) {
            names.push(name.to_string());
        }
    }
    names
}

/// Whether an export name is a valid, non-keyword Rust identifier.
#[cfg(feature = "live-tests")]
fn is_usable_ident(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return false;
    }
    !matches!(
        name,
        "main"
            | "fn"
            | "type"
            | "loop"
            | "match"
            | "move"
            | "ref"
            | "box"
            | "in"
            | "as"
            | "use"
            | "mod"
            | "let"
            | "impl"
            | "trait"
            | "self"
            | "Self"
    )
}

/// Writes a probe that references real `kernel32` exports, so the payload's IAT
/// is forced past a single page (a page holds 512 x64 slots).
///
/// The export list read from disk includes entries the import library does not
/// carry, so the source is compiled once here and the unresolved `__imp_*`
/// symbols are pruned until it links; the final set is a subset, hence linkable.
#[cfg(feature = "live-tests")]
fn generate_multi_page_probe(dir: &std::path::Path) -> std::path::PathBuf {
    let mut names: Vec<String> = module_export_names("kernel32.dll")
        .into_iter()
        .filter(|name| is_usable_ident(name))
        .collect();

    let rustc = crate::engine::compiler::find_rustc().unwrap();
    let path = dir.join("multipage_probe.rs");
    let exe = dir.join("mp_probe.exe");
    for _ in 0..16 {
        std::fs::write(&path, render_multi_page_probe(&names)).expect("write generated probe");
        let output = Command::new(&rustc)
            .arg(&path)
            .args(["-O", "-C", "strip=symbols", "-o"])
            .arg(&exe)
            .output()
            .unwrap();
        if output.status.success() {
            break;
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        let missing = unresolved_imports(&stderr);
        assert!(
            !missing.is_empty(),
            "the generated multi-page probe failed to compile:\n{stderr}"
        );
        let before = names.len();
        names.retain(|name| !missing.contains(name));
        assert!(
            names.len() < before,
            "no progress pruning unresolved imports"
        );
    }

    // A subset of a linkable set is linkable; keep the count modest but past a
    // page.
    names.truncate(600);
    assert!(
        names.len() > 512,
        "need more than 512 linkable imports to cross a page, got {}",
        names.len()
    );
    std::fs::write(&path, render_multi_page_probe(&names)).expect("write generated probe");
    path
}

/// Renders a probe that imports `names` and takes each address, forcing an IAT
/// entry for every one of them.
#[cfg(feature = "live-tests")]
fn render_multi_page_probe(names: &[String]) -> String {
    let mut src = String::new();
    src.push_str("//! Generated probe: >512 imports, so the IAT spans two pages.\n\n");
    src.push_str("#[link(name = \"kernel32\")]\nextern \"system\" {\n");
    for name in names {
        src.push_str(&format!("    fn {name}();\n"));
    }
    src.push_str("}\n\nfn main() {\n");
    for name in names {
        src.push_str(&format!("    std::hint::black_box({name} as usize);\n"));
    }
    src.push_str(&format!(
        "    println!(\"API_MULTIPAGE imports={}\");\n",
        names.len()
    ));
    src.push_str("}\n");
    src
}

/// The `__imp_<Name>` symbols the linker reported as unresolved.
#[cfg(feature = "live-tests")]
fn unresolved_imports(stderr: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in stderr.lines() {
        let Some(idx) = line.find("__imp_") else {
            continue;
        };
        let name: String = line[idx + "__imp_".len()..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            names.push(name);
        }
    }
    names
}
