//! `config` module: loading, parsing and validation of the YAML.
//!
//! Responsibilities:
//! - `schema`: `serde` structs modeling the YAML document.
//! - `validate`: semantic validation after parsing.
//! - `build_args`: `$build.N$` placeholder substitution from CLI args.
//! - `load_config`: single entry point that reads a file, resolves build
//!   arguments, deserializes it and validates it, returning a ready-to-use
//!   [`Config`].

pub mod build_args;
pub mod schema;
pub mod validate;

use std::path::Path;

use crate::error::{PackerError, Result};

pub use schema::Config;

/// Reads `path`, resolves `$build.N$` placeholders, deserializes the YAML and
/// validates the resulting config.
///
/// `build_args` are the positional CLI arguments after the config path
/// (`batesian build config.yaml arg0 arg1 ...`). Each stage (read, parse,
/// substitute, validate) returns a typed error so the user gets a clear message
/// without the program panicking.
pub fn load_config(path: &Path, build_args: &[String]) -> Result<Config> {
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
fn parse_and_substitute(raw: &str, build_args: &[String], path: &Path) -> Result<Config> {
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

    /// A valid YAML whose `process_hollowing.target` is a `$build.0$` token.
    const ARGS_YAML: &str = r#"
schema: 1
name: args-test
input:
  path: ./payload.exe
payload:
  crypto:
    algo: xchacha20poly1305
    key: random
pipeline:
  - technique: process_hollowing
    target: "$build.0$"
output:
  path: ./dist/out.exe
  arch: x64
  strip: true
  trim_paths: all
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
        let args = vec!["C:\\Windows\\System32\\notepad.exe".to_string()];

        let config = load_config(&path, &args).expect("load with build args");

        match &config.pipeline[0] {
            crate::techniques::PipelineStep::ProcessHollowing(params) => {
                assert_eq!(params.target, r"C:\Windows\System32\notepad.exe");
            }
            other => panic!("expected process_hollowing, got {other:?}"),
        }
    }
}
