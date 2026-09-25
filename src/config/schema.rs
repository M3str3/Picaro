//! `serde` structs modeling the YAML configuration document.
//!
//! Each struct maps to a block of the YAML (see `examples/configs/`).
//! The design aims to be:
//! - **Explicit**: fields are required by default (no magic values), except
//!   where `#[serde(default)]` says otherwise.
//! - **Strict**: `deny_unknown_fields` catches typos in the YAML keys.
//! - **Extensible**: the enums centralize the valid options, so adding a new
//!   technique or algorithm is a localized change.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::YamlStringsConfig;
use crate::techniques::PipelineStep;

/// Root document of the YAML.
///
/// Groups the four blocks (`input`, `payload`, `pipeline`, `output`) plus the
/// `schema` and `name` metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Schema version. Only `1` is accepted; it is validated on deserialize.
    #[serde(deserialize_with = "deserialize_schema_version")]
    pub schema: u32,

    /// Descriptive build name (identifies the generated artifact).
    pub name: String,

    /// Input block: which PE to pack.
    pub input: InputConfig,

    /// Payload block: how the input PE is encrypted/transformed.
    pub payload: PayloadConfig,

    /// Evasion/execution techniques to apply, in order.
    ///
    /// It is optional: an empty pipeline packs the payload with no extra
    /// techniques.
    #[serde(default)]
    pub pipeline: Vec<PipelineStep>,

    /// Optional custom loader stub (a Rust template). When absent, the builtin
    /// stub (`templates/stub/main.rs.tpl`) is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loader: Option<LoaderConfig>,

    /// Output block: how to produce the packed PE.
    pub output: OutputConfig,
}

/// `loader` block: a user-provided stub template.
///
/// The file is a Rust source template with `$PLACEHOLDER$` slots that the
/// packer fills (see `docs/custom-stubs.md`). It must define a `fn main()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoaderConfig {
    /// Path to the stub template (`.rs`).
    pub path: PathBuf,
}

/// `input` block: locates the input binary.
///
/// Exactly one of `path` (a local file) or `url` (a remote resource fetched in
/// memory) must be set; semantic validation enforces this in
/// [`crate::config::validate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputConfig {
    /// Local path (relative or absolute) to the PE to be packed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,

    /// Remote URL to fetch the PE from, in memory, without writing to disk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// `payload` block: describes the cryptographic transformation of the payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadConfig {
    /// Sub-block with the cryptographic configuration.
    pub crypto: CryptoConfig,

    /// Optional string-obfuscation configuration for stub literals.
    ///
    /// When absent, the packer defaults to `xor` + a random key (and warns).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strings: Option<YamlStringsConfig>,
}

/// Cryptographic configuration of the payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoConfig {
    /// Authenticated encryption algorithm.
    pub algo: CryptoAlgorithm,

    /// Source of the encryption key.
    pub key: KeySource,
}

/// Supported encryption algorithms.
///
/// `rename_all = "lowercase"` makes the YAML value `xchacha20poly1305` map to
/// this variant (and vice versa when serializing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CryptoAlgorithm {
    /// XChaCha20-Poly1305 (AEAD authenticated encryption, 24-byte nonce).
    XChaCha20Poly1305,
}

/// Source of the encryption key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeySource {
    /// Random key generated on every build.
    Random,
}

/// `output` block: defines the final artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputConfig {
    /// Output path of the packed PE.
    pub path: PathBuf,

    /// Target architecture.
    pub arch: Arch,

    /// Whether to strip the symbol table from the final binary.
    pub strip: bool,

    /// Path-remapping policy for the debug info.
    pub trim_paths: TrimPaths,
}

/// Target architectures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    /// x86-64 (PE32+).
    X64,
    /// x86 (PE32).
    X86,
}

/// Path-remapping policy for the final binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrimPaths {
    /// Remap all absolute paths.
    All,
    /// Do not remap anything.
    None,
    /// Remap only absolute paths pointing outside the project.
    Relative,
}

/// Validates the schema version during deserialization.
///
/// Gives a clear error at parse time (not later) if the user uses a schema
/// version we do not support yet.
fn deserialize_schema_version<'de, D>(deserializer: D) -> std::result::Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let version = u32::deserialize(deserializer)?;
    if version != 1 {
        return Err(serde::de::Error::custom(format!(
            "unsupported schema version: {version} (only 1 is accepted)"
        )));
    }
    Ok(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::techniques::process_hollowing::{default_target, Params};

    /// Minimal valid YAML used as a base in all tests.
    const VALID_YAML: &str = r#"
schema: 1
name: mimikatz-basic

input:
  path: ./mimikatz.exe

payload:
  crypto:
    algo: xchacha20poly1305
    key: random

pipeline:
  - technique: process_hollowing
    target: "C:\\Windows\\System32\\svchost.exe"

output:
  path: ./dist/mimikatz_packed.exe
  arch: x64
  strip: true
  trim_paths: all
"#;

    #[test]
    fn parses_valid_config() {
        let config: Config =
            serde_yml::from_str(VALID_YAML).expect("the example YAML should parse");

        assert_eq!(config.schema, 1);
        assert_eq!(config.name, "mimikatz-basic");
        assert_eq!(config.input.path, Some(PathBuf::from("./mimikatz.exe")));
        assert_eq!(config.input.url, None);
        assert_eq!(
            config.payload.crypto.algo,
            CryptoAlgorithm::XChaCha20Poly1305
        );
        assert_eq!(config.payload.crypto.key, KeySource::Random);
        assert_eq!(
            config.pipeline,
            vec![PipelineStep::ProcessHollowing(Params {
                target: r"C:\Windows\System32\svchost.exe".to_string(),
            })]
        );
        assert_eq!(
            config.output.path,
            PathBuf::from("./dist/mimikatz_packed.exe")
        );
        assert_eq!(config.output.arch, Arch::X64);
        assert!(config.output.strip);
        assert_eq!(config.output.trim_paths, TrimPaths::All);
    }

    #[test]
    fn parses_strings_block() {
        let yaml = VALID_YAML.replace(
            "payload:\n  crypto:\n    algo: xchacha20poly1305\n    key: random\n",
            "payload:\n  crypto:\n    algo: xchacha20poly1305\n    key: random\n  strings:\n    strategy: stack\n    key: random\n",
        );
        let config: Config = serde_yml::from_str(&yaml).expect("strings block should parse");
        let strings = config.payload.strings.expect("strings should be present");
        assert_eq!(strings.strategy, "stack");
        assert_eq!(strings.key, "random");
    }

    #[test]
    fn strings_block_is_optional() {
        let config: Config = serde_yml::from_str(VALID_YAML).expect("valid YAML should parse");
        assert_eq!(config.payload.strings, None);
    }

    #[test]
    fn loader_block_is_optional() {
        let config: Config = serde_yml::from_str(VALID_YAML).expect("valid YAML should parse");
        assert_eq!(config.loader, None);
    }

    #[test]
    fn parses_loader_block() {
        let yaml = VALID_YAML.replace(
            "output:\n  path: ./dist/mimikatz_packed.exe",
            "loader:\n  path: ./my_stub.rs\n\noutput:\n  path: ./dist/mimikatz_packed.exe",
        );
        let config: Config = serde_yml::from_str(&yaml).expect("loader block should parse");
        assert_eq!(
            config.loader.map(|l| l.path),
            Some(PathBuf::from("./my_stub.rs"))
        );
    }

    #[test]
    fn parses_url_input() {
        let yaml = VALID_YAML.replace(
            "input:\n  path: ./mimikatz.exe\n",
            "input:\n  url: https://example.com/mimikatz.exe\n",
        );
        let config: Config = serde_yml::from_str(&yaml).expect("a url input should parse");

        assert_eq!(config.input.path, None);
        assert_eq!(
            config.input.url.as_deref(),
            Some("https://example.com/mimikatz.exe")
        );
    }

    #[test]
    fn process_hollowing_defaults_target() {
        let yaml = VALID_YAML.replace(
            "pipeline:\n  - technique: process_hollowing\n    target: \"C:\\\\Windows\\\\System32\\\\svchost.exe\"\n",
            "pipeline:\n  - technique: process_hollowing\n",
        );
        let config: Config =
            serde_yml::from_str(&yaml).expect("process_hollowing without target should parse");
        assert_eq!(
            config.pipeline,
            vec![PipelineStep::ProcessHollowing(Params {
                target: default_target(),
            })]
        );
    }

    #[test]
    fn rejects_invalid_target_type() {
        let yaml = VALID_YAML.replace(
            "    target: \"C:\\\\Windows\\\\System32\\\\svchost.exe\"\n",
            "    target: 123\n",
        );
        assert!(
            serde_yml::from_str::<Config>(&yaml).is_err(),
            "a non-string target should fail"
        );
    }

    #[test]
    fn rejects_unsupported_schema_version() {
        let yaml = VALID_YAML.replace("schema: 1", "schema: 2");
        let err = serde_yml::from_str::<Config>(&yaml).expect_err("schema 2 should fail");
        let msg = err.to_string();
        assert!(
            msg.contains("schema version"),
            "unclear error message: {msg}"
        );
    }

    #[test]
    fn rejects_unknown_technique() {
        let yaml = VALID_YAML.replace("process_hollowing", "indirect_syscalls");
        assert!(
            serde_yml::from_str::<Config>(&yaml).is_err(),
            "an unknown technique should fail"
        );
    }

    #[test]
    fn rejects_typo_in_field_name() {
        let yaml = VALID_YAML.replace("name: mimikatz-basic", "naem: mimikatz-basic");
        assert!(
            serde_yml::from_str::<Config>(&yaml).is_err(),
            "a typo in a key should fail (deny_unknown_fields)"
        );
    }

    #[test]
    fn allows_empty_pipeline() {
        let yaml = VALID_YAML.replace(
            "pipeline:\n  - technique: process_hollowing\n    target: \"C:\\\\Windows\\\\System32\\\\svchost.exe\"\n",
            "",
        );
        let config: Config = serde_yml::from_str(&yaml).expect("an empty pipeline should be valid");
        assert!(config.pipeline.is_empty());
    }
}
