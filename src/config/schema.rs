//! `serde` structs modeling the YAML configuration document (schema 2).
//!
//! Each struct maps to a block of the YAML (see `examples/configs/`).
//! The design aims to be:
//! - **Explicit**: fields are required by default (no magic values), except
//!   where `#[serde(default)]` says otherwise.
//! - **Strict**: `deny_unknown_fields` catches typos in the YAML keys.
//! - **Extensible**: the enums centralize the valid options, so adding a new
//!   technique or algorithm is a localized change.
//!
//! Schema 2 groups everything the build needs under `build` and keeps the
//! execution-time technique list under `runtime`. See
//! `docs/migration-v1-v2.md` for the schema-1 → schema-2 mapping.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::YamlStringsConfig;
use crate::engine::syscalls::YamlSyscallsConfig;
use crate::techniques::RuntimeStep;

/// The only schema version we accept.
pub const SUPPORTED_SCHEMA: u32 = 2;

/// Migration hint shown when a config still declares `schema: 1`.
const SCHEMA_1_MIGRATION: &str = "\
schema 1 is no longer supported.
Migration:
  input.path      → build.payload.source
  payload.*       → build.payload.*, build.strings
  loader.path     → build.stub.path
  loader.syscalls → build.stub.syscalls
  output.*        → build.output.*
  pipeline        → runtime
  $build.N$       → $arg.N$
See docs/migration-v1-v2.md for details.";

/// Root document of the YAML.
///
/// Two halves: `build` (what to produce) and `runtime` (the techniques the
/// generated stub applies), plus the `schema` and `name` metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Schema version. Only `2` is accepted; it is validated on deserialize.
    #[serde(deserialize_with = "deserialize_schema_version")]
    pub schema: u32,

    /// Descriptive build name (identifies the generated artifact).
    pub name: String,

    /// Build block: payload, strings, stub and output.
    pub build: BuildConfig,

    /// Execution techniques the stub applies, in order.
    ///
    /// It is optional: an empty runtime produces a stub with no extra
    /// techniques.
    #[serde(default)]
    pub runtime: Vec<RuntimeStep>,
}

/// `build` block: everything needed to produce the packed PE.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildConfig {
    /// Payload block: where the input PE comes from and how it is encrypted.
    pub payload: PayloadConfig,

    /// Optional string-obfuscation configuration.
    ///
    /// Applies to every stub literal (template, technique fragments and anything
    /// else the packer emits), independent of the techniques. When absent, the
    /// packer defaults to `xor` + a random key (and warns).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strings: Option<YamlStringsConfig>,

    /// Stub configuration: builtin or custom, plus the syscall layer.
    #[serde(default)]
    pub stub: StubConfig,

    /// Output block: how to produce the packed PE.
    pub output: OutputConfig,
}

/// `payload` block: the input source and its cryptographic transformation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadConfig {
    /// The input PE: a local path or a URL (the packer detects the scheme).
    ///
    /// Supports `http://`, `https://` and `file://` sources; anything else is a
    /// local path. `ftp://` is recognized but not implemented.
    pub source: String,

    /// Sub-block with the cryptographic configuration.
    pub crypto: CryptoConfig,
}

/// `stub` block: the stub configuration.
///
/// `path` selects a custom stub template; `syscalls` configures how the stub
/// talks to the kernel. Both are optional: without them the builtin stub with
/// the default syscall mode is used.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StubConfig {
    /// Path to a custom stub template (`.rs`). `None` means the builtin stub.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,

    /// Syscall-layer configuration (how the stub invokes the kernel).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syscalls: Option<YamlSyscallsConfig>,
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
/// Gives a clear error at parse time (not later): a specific migration hint for
/// the retired schema 1 and a generic message for anything unknown.
fn deserialize_schema_version<'de, D>(deserializer: D) -> std::result::Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let version = u32::deserialize(deserializer)?;
    match version {
        SUPPORTED_SCHEMA => Ok(version),
        1 => Err(serde::de::Error::custom(SCHEMA_1_MIGRATION)),
        other => Err(serde::de::Error::custom(format!(
            "unsupported schema version: {other} (only {SUPPORTED_SCHEMA} is accepted)"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::techniques::process_hollowing::{default_target, Params};

    /// Minimal valid YAML used as a base in all tests.
    const VALID_YAML: &str = r#"
schema: 2
name: mimikatz-basic

build:
  payload:
    source: ./mimikatz.exe
    crypto:
      algo: xchacha20poly1305
      key: random

  output:
    path: ./dist/mimikatz_packed.exe
    arch: x64
    strip: true
    trim_paths: all

runtime:
  - technique: process_hollowing
    target: "C:\\Windows\\System32\\svchost.exe"
"#;

    #[test]
    fn parses_valid_config() {
        let config: Config =
            serde_yml::from_str(VALID_YAML).expect("the example YAML should parse");

        assert_eq!(config.schema, 2);
        assert_eq!(config.name, "mimikatz-basic");
        assert_eq!(config.build.payload.source, "./mimikatz.exe");
        assert_eq!(
            config.build.payload.crypto.algo,
            CryptoAlgorithm::XChaCha20Poly1305
        );
        assert_eq!(config.build.payload.crypto.key, KeySource::Random);
        assert_eq!(config.build.stub.path, None);
        assert_eq!(config.build.stub.syscalls, None);
        assert_eq!(
            config.runtime,
            vec![RuntimeStep::ProcessHollowing(Params {
                target: r"C:\Windows\System32\svchost.exe".to_string(),
            })]
        );
        assert_eq!(
            config.build.output.path,
            PathBuf::from("./dist/mimikatz_packed.exe")
        );
        assert_eq!(config.build.output.arch, Arch::X64);
        assert!(config.build.output.strip);
        assert_eq!(config.build.output.trim_paths, TrimPaths::All);
    }

    #[test]
    fn parses_strings_block() {
        let yaml = VALID_YAML.replace(
            "  output:\n",
            "  strings:\n    strategy: stack\n    key: random\n\n  output:\n",
        );
        let config: Config = serde_yml::from_str(&yaml).expect("strings block should parse");
        let strings = config.build.strings.expect("strings should be present");
        assert_eq!(strings.strategy, "stack");
        assert_eq!(strings.key, "random");
    }

    #[test]
    fn strings_block_is_optional() {
        let config: Config = serde_yml::from_str(VALID_YAML).expect("valid YAML should parse");
        assert_eq!(config.build.strings, None);
    }

    #[test]
    fn stub_block_is_optional_and_defaults_to_builtin() {
        let config: Config = serde_yml::from_str(VALID_YAML).expect("valid YAML should parse");
        assert_eq!(config.build.stub, StubConfig::default());
    }

    #[test]
    fn parses_stub_path_block() {
        let yaml = VALID_YAML.replace(
            "  output:\n",
            "  stub:\n    path: ./my_stub.rs\n\n  output:\n",
        );
        let config: Config = serde_yml::from_str(&yaml).expect("stub block should parse");
        assert_eq!(config.build.stub.path, Some(PathBuf::from("./my_stub.rs")));
    }

    #[test]
    fn stub_path_null_means_builtin() {
        let yaml = VALID_YAML.replace("  output:\n", "  stub:\n    path: null\n\n  output:\n");
        let config: Config = serde_yml::from_str(&yaml).expect("null path should parse");
        assert_eq!(config.build.stub.path, None);
    }

    #[test]
    fn parses_stub_syscalls_block() {
        let yaml = VALID_YAML.replace(
            "  output:\n",
            "  stub:\n    syscalls:\n      mode: indirect\n\n  output:\n",
        );
        let config: Config = serde_yml::from_str(&yaml).expect("syscalls block should parse");
        assert_eq!(config.build.stub.path, None);
        let syscalls = config
            .build
            .stub
            .syscalls
            .expect("syscalls should be present");
        assert_eq!(syscalls.mode, "indirect");
        assert_eq!(syscalls.resolver, "hells_gate");
    }

    #[test]
    fn stub_syscalls_defaults_mode_and_resolver() {
        let yaml = VALID_YAML.replace("  output:\n", "  stub:\n    syscalls: {}\n\n  output:\n");
        let config: Config = serde_yml::from_str(&yaml).expect("empty syscalls should parse");
        let syscalls = config
            .build
            .stub
            .syscalls
            .expect("syscalls should be present");
        assert_eq!(syscalls.mode, "none");
        assert_eq!(syscalls.resolver, "hells_gate");
    }

    #[test]
    fn parses_url_source() {
        let yaml = VALID_YAML.replace(
            "    source: ./mimikatz.exe\n",
            "    source: https://example.com/mimikatz.exe\n",
        );
        let config: Config = serde_yml::from_str(&yaml).expect("a url source should parse");

        assert_eq!(
            config.build.payload.source,
            "https://example.com/mimikatz.exe"
        );
    }

    #[test]
    fn process_hollowing_defaults_target() {
        let yaml = VALID_YAML.replace(
            "runtime:\n  - technique: process_hollowing\n    target: \"C:\\\\Windows\\\\System32\\\\svchost.exe\"\n",
            "runtime:\n  - technique: process_hollowing\n",
        );
        let config: Config =
            serde_yml::from_str(&yaml).expect("process_hollowing without target should parse");
        assert_eq!(
            config.runtime,
            vec![RuntimeStep::ProcessHollowing(Params {
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
    fn rejects_schema_one_with_a_migration_message() {
        let yaml = VALID_YAML.replace("schema: 2", "schema: 1");
        let err = serde_yml::from_str::<Config>(&yaml).expect_err("schema 1 should fail");
        let msg = err.to_string();
        assert!(
            msg.contains("schema 1 is no longer supported"),
            "unclear error message: {msg}"
        );
        assert!(msg.contains("build.payload.source"), "msg: {msg}");
        assert!(msg.contains("$arg.N$"), "msg: {msg}");
        assert!(msg.contains("docs/migration-v1-v2.md"), "msg: {msg}");
    }

    #[test]
    fn rejects_unknown_schema_version() {
        let yaml = VALID_YAML.replace("schema: 2", "schema: 3");
        let err = serde_yml::from_str::<Config>(&yaml).expect_err("schema 3 should fail");
        let msg = err.to_string();
        assert!(
            msg.contains("unsupported schema version"),
            "unclear error message: {msg}"
        );
    }

    #[test]
    fn rejects_schema_one_keys() {
        // A schema-1 document is rejected by the version check, not by the
        // (now unknown) top-level keys.
        let yaml = r#"
schema: 1
name: old
input:
  path: ./p.exe
payload:
  crypto:
    algo: xchacha20poly1305
    key: random
output:
  path: ./dist/o.exe
  arch: x64
  strip: true
  trim_paths: all
"#;
        let err = serde_yml::from_str::<Config>(yaml).expect_err("schema 1 should fail");
        assert!(
            err.to_string().contains("schema 1 is no longer supported"),
            "unclear error: {err}"
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
    fn rejects_legacy_top_level_input_block() {
        let yaml = VALID_YAML.replace(
            "build:\n  payload:\n    source: ./mimikatz.exe\n",
            "input:\n  path: ./mimikatz.exe\nbuild:\n  payload:\n    crypto:\n      algo: xchacha20poly1305\n      key: random\n",
        );
        assert!(
            serde_yml::from_str::<Config>(&yaml).is_err(),
            "the schema-1 `input` block should fail (deny_unknown_fields)"
        );
    }

    #[test]
    fn allows_empty_runtime() {
        let yaml = VALID_YAML.replace(
            "runtime:\n  - technique: process_hollowing\n    target: \"C:\\\\Windows\\\\System32\\\\svchost.exe\"\n",
            "",
        );
        let config: Config = serde_yml::from_str(&yaml).expect("an empty runtime should be valid");
        assert!(config.runtime.is_empty());
    }
}
