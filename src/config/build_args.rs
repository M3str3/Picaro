//! Build-time argument substitution (`{{build.N}}`).
//!
//! A YAML config may reference positional arguments passed to
//! `packerman build config.yaml arg0 arg1 ...` using the `{{build.N}}` syntax
//! (`N` is a 0-based index). Substitution happens *before* semantic validation
//! and typed deserialization, so a substituted value still goes through the
//! normal type checks (a bad type fails with the usual `serde` error).

use serde_yml::Value;

use crate::error::{PackerError, Result};

/// Substitutes every `{{build.N}}` token found in `value`'s string fields.
///
/// `args` is the list of positional arguments after the config path. A token
/// whose index has no corresponding argument is an error; extra arguments are
/// silently ignored.
pub fn substitute(value: &mut Value, args: &[String]) -> Result<()> {
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

/// Replaces every `{{build.N}}` token inside `s` using `args`.
///
/// Tokens are replaced even when embedded in a larger string (e.g.
/// `"{{build.0}}_payload.exe"`). A missing index or a malformed token is a
/// [`PackerError::Validation`] error.
fn substitute_string(s: &mut String, args: &[String]) -> Result<()> {
    const PREFIX: &str = "{{build.";

    let mut out = String::with_capacity(s.len());
    let mut rest: &str = s;

    while let Some(start) = rest.find(PREFIX) {
        out.push_str(&rest[..start]);

        let after = &rest[start + PREFIX.len()..];
        let end = after.find("}}").ok_or_else(|| {
            PackerError::Validation(format!("unterminated build argument placeholder in '{s}'"))
        })?;

        let idx_str = after[..end].trim();
        let idx: usize = idx_str.parse().map_err(|_| {
            PackerError::Validation(format!("invalid build argument index '{idx_str}' in '{s}'"))
        })?;

        let arg = args.get(idx).ok_or_else(|| {
            PackerError::Validation(format!(
                "the config references '{{{{build.{idx}}}}}' but no build argument #{idx} was provided"
            ))
        })?;

        out.push_str(arg);
        rest = &after[end + 2..];
    }

    out.push_str(rest);
    *s = out;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> Vec<String> {
        vec!["svchost.exe".to_string(), "./dist/out.exe".to_string()]
    }

    fn rendered(value: &Value) -> String {
        serde_yml::to_string(value).expect("serialize value")
    }

    #[test]
    fn substitutes_positional_tokens() {
        let mut value: Value =
            serde_yml::from_str("target: \"{{build.0}}\"\noutput: \"{{build.1}}\"\n")
                .expect("yaml");

        substitute(&mut value, &args()).expect("substitute");

        let out = rendered(&value);
        assert!(out.contains("svchost.exe"), "rendered: {out}");
        assert!(out.contains("./dist/out.exe"), "rendered: {out}");
        assert!(!out.contains("{{build."), "rendered: {out}");
    }

    #[test]
    fn substitutes_token_embedded_in_a_string() {
        let mut value: Value = serde_yml::from_str("name: \"build_{{build.0}}_x\"\n")
            .expect("yaml");

        substitute(&mut value, &args()).expect("substitute");

        assert!(rendered(&value).contains("build_svchost.exe_x"));
    }

    #[test]
    fn missing_argument_is_an_error() {
        let mut value: Value = serde_yml::from_str("target: \"{{build.5}}\"\n").expect("yaml");
        let err = substitute(&mut value, &args()).expect_err("missing index must fail");
        assert!(err.to_string().contains("build.5"), "err: {err}");
    }

    #[test]
    fn invalid_index_is_an_error() {
        let mut value: Value = serde_yml::from_str("target: \"{{build.not_a_number}}\"\n")
            .expect("yaml");
        let err = substitute(&mut value, &args()).expect_err("invalid index must fail");
        assert!(err.to_string().contains("not_a_number"), "err: {err}");
    }

    #[test]
    fn leaves_non_string_values_untouched() {
        let mut value: Value = serde_yml::from_str("schema: 1\nstrip: true\n").expect("yaml");
        substitute(&mut value, &args()).expect("substitute");

        let out = rendered(&value);
        assert!(out.contains("schema: 1"), "rendered: {out}");
        assert!(out.contains("strip: true"), "rendered: {out}");
    }
}
