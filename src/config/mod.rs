//! `config` module: loading, parsing and validation of the YAML.
//!
//! Responsibilities:
//! - `schema`: `serde` structs modeling the YAML document (schema 3).
//! - `validate`: semantic validation after parsing.
//! - `build_args`: `$arg.N$` placeholder substitution from CLI args.
//! - `load_config`: single entry point that reads a file, resolves build
//!   arguments, deserializes it and validates it, returning a ready-to-use
//!   [`Config`].

pub mod build_args;
pub mod schema;
pub mod validate;

use std::collections::BTreeMap;
use std::path::Path;

use crate::error::{PackerError, Result};

pub use schema::Config;

/// Reads `path`, resolves `$arg.N$` placeholders, deserializes the YAML and
/// validates the resulting config.
///
/// `build_args` maps the CLI arguments (positional indices and `name=value`
/// pairs, see [`build_args::parse`]) to the values substituted into the YAML.
/// Each stage (read, parse, substitute, validate) returns a typed error so the
/// user gets a clear message without the program panicking.
pub fn load_config(path: &Path, build_args: &BTreeMap<String, String>) -> Result<Config> {
    let raw = std::fs::read_to_string(path).map_err(|source| PackerError::ReadConfig {
        path: path.to_path_buf(),
        source,
    })?;

    let config = parse_and_substitute(&raw, build_args, path)?;

    validate::validate(&config)?;

    Ok(config)
}

/// Parses the raw YAML into an untyped [`serde_yml::Value`], substitutes the
/// build arguments, then deserializes the result into a typed [`Config`].
///
/// Substituting on the untyped value tree (rather than on the raw string) keeps
/// quoting and escaping correct, while typed fields are still fully checked by
/// the later `serde` deserialization.
fn parse_and_substitute(
    raw: &str,
    build_args: &BTreeMap<String, String>,
    path: &Path,
) -> Result<Config> {
    let mut value: serde_yml::Value =
        serde_yml::from_str(raw).map_err(|source| PackerError::ParseConfig {
            path: path.to_path_buf(),
            source,
        })?;

    build_args::substitute(&mut value, build_args)?;

    serde_yml::from_value(value).map_err(|source| PackerError::ParseConfig {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A valid schema-3 YAML whose `process_hollowing.target` is a `$arg.0$` token.
    const ARGS_YAML: &str = r#"
schema: 4
name: args-test
build:
  payload:
    source: ./payload.exe
    crypto:
      algo: xchacha20poly1305
      key: random
  output:
    path: ./dist/out.exe
    arch: x64
    strip: true
    trim_paths: all
runtime:
  - technique: process_hollowing
    params:
      target: "$arg.0$"
"#;

    fn write_temp(name: &str, contents: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("batesian_config_tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn load_config_substitutes_build_args() {
        let path = write_temp("build_args.yaml", ARGS_YAML);
        let args = build_args::parse(&["C:\\Windows\\System32\\notepad.exe".to_string()]);

        let config = load_config(&path, &args).expect("load with build args");

        match &config.runtime[0] {
            crate::techniques::RuntimeStep::ProcessHollowing { params } => {
                assert_eq!(params.target, r"C:\Windows\System32\notepad.exe");
            }
            other => panic!("expected process_hollowing, got {other:?}"),
        }
    }

    #[test]
    fn load_config_substitutes_named_build_args() {
        let yaml = ARGS_YAML.replace("$arg.0$", "$arg.target$");
        let path = write_temp("named_args.yaml", &yaml);
        let args = build_args::parse(&["target=C:\\Windows\\System32\\notepad.exe".to_string()]);

        let config = load_config(&path, &args).expect("load with a named build arg");

        match &config.runtime[0] {
            crate::techniques::RuntimeStep::ProcessHollowing { params } => {
                assert_eq!(params.target, r"C:\Windows\System32\notepad.exe");
            }
            other => panic!("expected process_hollowing, got {other:?}"),
        }
    }
}
