//! Build-time argument substitution (`$arg.<key>$`).
//!
//! A YAML plan may reference arguments passed to
//! `picaro build plan.yaml arg0 arg1 ...` using the `$arg.<key>$` syntax.
//! Positional arguments are keyed by their 0-based index (`$arg.0$`); an
//! argument of the form `name=value` is keyed by `name` (`$arg.name$`).
//! `$stem.<key>$` is the same value with any directory and the last extension
//! stripped (so `C:\a\payload.exe` becomes `payload`), for deriving an output
//! name from an input path.
//!
//! Substitution happens *before* semantic validation and typed deserialization,
//! so a substituted value still goes through the normal type checks (a bad type
//! fails with the usual `serde` error).
//!
//! The retired schema-1 token `$build.N$` (and the older `{{build.N}}` form) is
//! rejected with a migration hint. A custom stub accesses the already-resolved
//! value with a different token, `$ARG_<key>$` (rendered by `engine::stub`), so
//! there is no collision between the two namespaces.

use std::collections::BTreeMap;

use serde_yml::Value;

use crate::error::{PackerError, Result};

/// Build-argument prefix in the YAML (the raw value).
const PREFIX: &str = "$arg.";
/// Prefix for the value's file stem (directory and last extension stripped).
const STEM_PREFIX: &str = "$stem.";

/// Parses the CLI arguments into the substitution map.
///
/// An argument matching `name=value` (with an identifier `name`) is stored
/// under `name`; every other argument is positional and is stored under its
/// 0-based position (`"0"`, `"1"`, ...). Both spaces share the same map, so a
/// custom stub's `$ARG_<key>$` sees the same values.
pub fn parse(args: &[String]) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let mut position = 0usize;
    for arg in args {
        if let Some((name, value)) = split_named(arg) {
            map.insert(name.to_string(), value.to_string());
        } else {
            map.insert(position.to_string(), arg.clone());
            position += 1;
        }
    }
    map
}

/// Splits `arg` into `(name, value)` when it is a `name=value` pair whose name
/// is an identifier. Returns `None` for positional arguments.
fn split_named(arg: &str) -> Option<(&str, &str)> {
    let (name, value) = arg.split_once('=')?;
    if is_identifier(name) {
        Some((name, value))
    } else {
        None
    }
}

/// Whether `s` is a non-empty ASCII identifier (`[A-Za-z_][A-Za-z0-9_]*`).
fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Substitutes every `$arg.<key>$` token found in `value`'s string fields.
///
/// A token whose key has no value is an error; unused arguments are ignored.
pub fn substitute(value: &mut Value, args: &BTreeMap<String, String>) -> Result<()> {
    match value {
        Value::String(s) => substitute_string(s, args)?,
        Value::Sequence(seq) => {
            for item in seq {
                substitute(item, args)?;
            }
        }
        Value::Mapping(map) => {
            for (_, v) in map.iter_mut() {
                substitute(v, args)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Replaces every `$arg.<key>$` / `$stem.<key>$` token inside `s` using `args`.
///
/// Tokens are replaced even when embedded in a larger string (e.g.
/// `"$stem.0$.hidden.exe"`). A missing key or a malformed token is a
/// [`PackerError::Validation`] error, and the retired schema-1 tokens are
/// rejected with a migration hint.
fn substitute_string(s: &mut String, args: &BTreeMap<String, String>) -> Result<()> {
    if let Some(token) = legacy_token(s) {
        return Err(PackerError::Validation(format!(
            "the plan uses the schema-1 build argument '{token}'; \
             use $arg.0$ instead (schema 3 syntax)"
        )));
    }

    let mut out = String::with_capacity(s.len());
    let mut rest: &str = s;

    // Replace the leftmost of the two prefixes first.
    while let Some((start, prefix)) = [PREFIX, STEM_PREFIX]
        .into_iter()
        .filter_map(|prefix| rest.find(prefix).map(|at| (at, prefix)))
        .min_by_key(|(at, _)| *at)
    {
        out.push_str(&rest[..start]);

        let after = &rest[start + prefix.len()..];
        let end = after.find('$').ok_or_else(|| {
            PackerError::Validation(format!("unterminated build argument placeholder in '{s}'"))
        })?;

        let key = after[..end].trim();
        if key.is_empty() {
            return Err(PackerError::Validation(format!(
                "empty build argument placeholder in '{s}'"
            )));
        }

        let arg = args.get(key).ok_or_else(|| {
            PackerError::Validation(format!(
                "the plan references '{prefix}{key}$' but no build argument '{key}' was provided"
            ))
        })?;

        if prefix == STEM_PREFIX {
            out.push_str(&file_stem(arg));
        } else {
            out.push_str(arg);
        }
        rest = &after[end + 1..];
    }

    out.push_str(rest);
    *s = out;
    Ok(())
}

/// The file stem of a path-like value: drops any directory and the last
/// extension.
///
/// Splits on both `/` and `\` so a Windows path is handled even when the packer
/// runs on Linux (Docker). A value with no extension is returned unchanged.
fn file_stem(value: &str) -> String {
    let name = value.rsplit(['/', '\\']).next().unwrap_or(value);
    match name.rsplit_once('.') {
        Some((stem, _)) if !stem.is_empty() => stem.to_string(),
        _ => name.to_string(),
    }
}

/// Returns the first schema-1 build-argument token in `s`, if any.
///
/// Recognizes both the `$build.N$` form and the older `{{build.N}}` form, so a
/// plan migrated by hand gets a clear pointer instead of silently keeping a
/// literal token.
fn legacy_token(s: &str) -> Option<String> {
    if let Some(start) = s.find("{{build.") {
        if let Some(end) = s[start..].find("}}") {
            return Some(s[start..start + end + 2].to_string());
        }
    }
    const LEGACY: &str = "$build.";
    let start = s.find(LEGACY)?;
    let tail = &s[start..];
    let end = tail[LEGACY.len()..]
        .find('$')
        .map(|i| LEGACY.len() + i + 1)
        .unwrap_or(tail.len());
    Some(tail[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("0".to_string(), "svchost.exe".to_string()),
            ("1".to_string(), "./dist/out.exe".to_string()),
            ("name".to_string(), "notepad".to_string()),
        ])
    }

    fn rendered(value: &Value) -> String {
        serde_yml::to_string(value).expect("serialize value")
    }

    #[test]
    fn parse_keys_positional_args_by_index() {
        let map = parse(&["a".to_string(), "b".to_string()]);
        assert_eq!(map.get("0").map(String::as_str), Some("a"));
        assert_eq!(map.get("1").map(String::as_str), Some("b"));
    }

    #[test]
    fn parse_keys_named_args_by_name() {
        let map = parse(&["target=svchost.exe".to_string(), "b".to_string()]);
        assert_eq!(map.get("target").map(String::as_str), Some("svchost.exe"));
        // The positional arg still counts from zero.
        assert_eq!(map.get("0").map(String::as_str), Some("b"));
    }

    #[test]
    fn parse_keeps_windows_paths_positional() {
        // A drive-letter path is not a `name=value` pair.
        let map = parse(&["C:\\Windows\\System32\\svchost.exe".to_string()]);
        assert_eq!(
            map.get("0").map(String::as_str),
            Some("C:\\Windows\\System32\\svchost.exe")
        );
    }

    #[test]
    fn substitutes_positional_tokens() {
        let mut value: Value =
            serde_yml::from_str("target: \"$arg.0$\"\noutput: \"$arg.1$\"\n").expect("yaml");

        substitute(&mut value, &args()).expect("substitute");

        let out = rendered(&value);
        assert!(out.contains("svchost.exe"), "rendered: {out}");
        assert!(out.contains("./dist/out.exe"), "rendered: {out}");
        assert!(!out.contains("$arg."), "rendered: {out}");
    }

    #[test]
    fn substitutes_named_token() {
        let mut value: Value = serde_yml::from_str("target: \"$arg.name$\"\n").expect("yaml");
        substitute(&mut value, &args()).expect("substitute");
        assert!(rendered(&value).contains("notepad"));
    }

    #[test]
    fn substitutes_token_embedded_in_a_string() {
        let mut value: Value = serde_yml::from_str("name: \"build_$arg.0$_x\"\n").expect("yaml");

        substitute(&mut value, &args()).expect("substitute");

        assert!(rendered(&value).contains("build_svchost.exe_x"));
    }

    #[test]
    fn substitutes_the_stem_token() {
        let mut value: Value =
            serde_yml::from_str("path: \"$stem.0$.hidden.exe\"\n").expect("yaml");
        substitute(&mut value, &args()).expect("substitute");
        // `svchost.exe` -> `svchost`.
        assert!(rendered(&value).contains("svchost.hidden.exe"));
    }

    #[test]
    fn stem_strips_a_directory_and_the_last_extension() {
        assert_eq!(file_stem("C:\\path\\payload.exe"), "payload");
        assert_eq!(file_stem("/work/a/payload.exe"), "payload");
        assert_eq!(file_stem("payload.exe"), "payload");
        assert_eq!(file_stem("archive.tar.gz"), "archive.tar");
        // No extension, or a dotfile: returned as the file name.
        assert_eq!(file_stem("payload"), "payload");
        assert_eq!(file_stem("C:\\x\\.hidden"), ".hidden");
    }

    #[test]
    fn missing_argument_is_an_error() {
        let mut value: Value = serde_yml::from_str("target: \"$arg.5$\"\n").expect("yaml");
        let err = substitute(&mut value, &args()).expect_err("missing key must fail");
        assert!(err.to_string().contains("$arg.5$"), "err: {err}");
        assert!(err.to_string().contains("was provided"), "err: {err}");
    }

    #[test]
    fn missing_stem_argument_is_an_error() {
        let mut value: Value = serde_yml::from_str("path: \"$stem.5$.exe\"\n").expect("yaml");
        let err = substitute(&mut value, &args()).expect_err("missing key must fail");
        assert!(err.to_string().contains("$stem.5$"), "err: {err}");
    }

    #[test]
    fn empty_key_is_an_error() {
        let mut value: Value = serde_yml::from_str("target: \"$arg.$\"\n").expect("yaml");
        let err = substitute(&mut value, &args()).expect_err("empty key must fail");
        assert!(err.to_string().contains("empty"), "err: {err}");
    }

    #[test]
    fn rejects_legacy_dollar_build_token() {
        let mut value: Value = serde_yml::from_str("target: \"$build.0$\"\n").expect("yaml");
        let err = substitute(&mut value, &args()).expect_err("legacy token must fail");
        let msg = err.to_string();
        assert!(msg.contains("schema-1 build argument"), "err: {msg}");
        assert!(msg.contains("use $arg.0$"), "err: {msg}");
    }

    #[test]
    fn rejects_legacy_brace_build_token() {
        let mut value: Value = serde_yml::from_str("target: \"{{build.0}}\"\n").expect("yaml");
        let err = substitute(&mut value, &args()).expect_err("legacy token must fail");
        let msg = err.to_string();
        assert!(msg.contains("{{build.0}}"), "err: {msg}");
        assert!(msg.contains("use $arg.0$"), "err: {msg}");
    }

    #[test]
    fn leaves_non_string_values_untouched() {
        let mut value: Value = serde_yml::from_str("schema: 3\nstrip: true\n").expect("yaml");
        substitute(&mut value, &args()).expect("substitute");

        let out = rendered(&value);
        assert!(out.contains("schema: 3"), "rendered: {out}");
        assert!(out.contains("strip: true"), "rendered: {out}");
    }
}
