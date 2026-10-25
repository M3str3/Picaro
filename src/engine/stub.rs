//! Stub template substitution.
//!
//! The step renderer ([`super::steps`]) builds the values for a template's
//! `$PLACEHOLDER$` tokens; this module owns the substitution engine itself and
//! the few helpers every stub template shares. It is deliberately dumb: it does
//! not know what the placeholders mean, only that a `$NAME$` token whose name is
//! not in the value map is an error (to catch a stale template) and that the
//! legacy `{{NAME}}` delimiters are rejected with a migration hint.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use rand::RngCore;
use regex::Regex;

use super::{BuildError, Result};

/// Generates a per-build unique marker: `STUB_MARKER_<16 hex>`.
/// A random marker used by tests and out-of-tree callers.
///
/// A real build derives its marker from the master entropy (see the packer's
/// `stub_marker`), so the generated source is reproducible.
#[allow(dead_code)]
pub fn generate_stub_marker() -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("STUB_MARKER_{}", hex::encode(bytes))
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

/// Substitutes every `$NAME$` token in `template`, looking each one up in
/// `values`. An unknown token is an error, and the legacy `{{NAME}}` delimiters
/// are rejected with a migration hint.
///
/// A `$` that is not part of a `$NAME$` token (e.g. inside a string literal or a
/// macro body) is kept literally.
pub(crate) fn substitute_template(
    template: &str,
    values: &BTreeMap<String, String>,
) -> Result<String> {
    if let Some(legacy) = find_legacy_placeholder(template) {
        return Err(BuildError::InvalidTemplate(format!(
            "placeholder '{legacy}' uses the old `{{{{...}}}}` syntax; use `$...$` instead (e.g. `$STEP_MODULES$`)"
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitutes_known_placeholders_and_keeps_stray_dollars() {
        let values = BTreeMap::from([
            ("$A$".to_string(), "one".to_string()),
            ("$B$".to_string(), "two".to_string()),
        ]);
        let out = substitute_template("x=$A$ y=$B$ z=$not_a_token", &values).expect("render");
        assert_eq!(out, "x=one y=two z=$not_a_token");
    }

    #[test]
    fn a_missing_placeholder_is_an_error() {
        let values = BTreeMap::from([("$A$".to_string(), "one".to_string())]);
        let err = substitute_template("x=$B$", &values).expect_err("should fail");
        assert!(err.to_string().contains("B"), "unclear: {err}");
    }

    #[test]
    fn legacy_brace_placeholder_is_rejected_with_a_hint() {
        let values = BTreeMap::new();
        let err = substitute_template("x={{A}}", &values).expect_err("should fail");
        let msg = err.to_string();
        assert!(msg.contains("{{A}}"), "unclear: {msg}");
        assert!(msg.contains("$...$"), "the hint is missing: {msg}");
    }

    #[test]
    fn validate_custom_stub_requires_fn_main() {
        assert!(validate_custom_stub_template("fn main() {}\n").is_ok());
        assert!(validate_custom_stub_template("fn  main  ( ) {}\n").is_ok());

        let err = validate_custom_stub_template("fn not_main() {}\n").expect_err("should fail");
        assert!(err.to_string().contains("fn main"), "unclear error: {err}");
    }

    #[test]
    fn a_marker_is_a_prefixed_hex_string() {
        let marker = generate_stub_marker();
        let hex = marker.strip_prefix("STUB_MARKER_").expect("marker prefix");
        assert_eq!(hex.len(), 16);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
