//! `serde` structs modeling the YAML configuration document (schema 3).
//!
//! Each struct maps to a block of the YAML (see `examples/configs/`).
//! The design aims to be:
//! - **Explicit**: fields are required by default (no magic values), except
//!   where `#[serde(default)]` says otherwise.
//! - **Strict**: `deny_unknown_fields` catches typos in the YAML keys.
//! - **Extensible**: the enums centralize the valid options, so adding a new
//!   technique or algorithm is a localized change.
//!
//! Schema 3 groups everything the build needs under `build` (`payload`,
//! `stub`, `output`) and keeps the execution-time technique list under
//! `runtime`. Stub-level string obfuscation lives under `build.stub.strings`.
//! See `docs/migration-v1-v3.md` (schema 1 → current) and
//! `docs/migration-v2-v3.md` (schema 2 → 3).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::engine::args::ArgsMode;
use crate::engine::obfuscation::YamlStringsConfig;
use crate::engine::syscalls::YamlSyscallsConfig;
use crate::techniques::RuntimeStep;

/// The only schema version we accept.
pub const SUPPORTED_SCHEMA: u32 = 4;

/// Migration hint shown when a config still declares `schema: 1`.
const SCHEMA_1_MIGRATION: &str = "\
schema 1 is no longer supported.
Migration:
  input.path      → build.payload.source
  payload.*       → build.payload.*
  payload.strings → build.stub.strings
  loader.path     → build.stub.path
  loader.syscalls → build.stub.syscalls
  output.*        → build.output.*
  pipeline        → runtime
  pipeline params → runtime[].params (nested)
  $build.N$       → $arg.N$
See docs/migration-v1-v3.md, then docs/migration-v3-v4.md for details.";

/// Migration hint shown when a config still declares `schema: 2`.
const SCHEMA_2_MIGRATION: &str = "\
schema 2 is no longer supported.
Migration:
  build.strings → build.stub.strings
  runtime entries now nest parameters under `params:` (schema 3 → 4)
See docs/migration-v2-v3.md (then docs/migration-v3-v4.md) for details.";

/// Migration hint shown when a config still declares `schema: 3`.
const SCHEMA_3_MIGRATION: &str = "\
schema 3 is no longer supported.
Migration: a runtime entry now nests the technique's parameters under a
`params:` mapping instead of putting them next to `technique:`.
  before (schema 3):
    - technique: process_hollowing
      target: \"C:\\\\Windows\\\\System32\\\\svchost.exe\"
  after (schema 4):
    - technique: process_hollowing
      params:
        target: \"C:\\\\Windows\\\\System32\\\\svchost.exe\"
A technique with no parameters omits `params:` entirely.
See docs/migration-v3-v4.md for details.";

/// Root document of the YAML.
///
/// Two halves: `build` (what to produce) and `runtime` (the techniques the
/// generated stub applies), plus the `schema` and `name` metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Schema version. Only `3` is accepted; it is validated on deserialize.
    #[serde(deserialize_with = "deserialize_schema_version")]
    pub schema: u32,

    /// Descriptive build name (identifies the generated artifact).
    pub name: String,

    /// Build block: payload, stub and output.
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

    /// Stub configuration: builtin or custom, the syscall layer and the
    /// string obfuscation applied to the stub's literals.
    #[serde(default)]
    pub stub: StubConfig,

    /// Output block: how to produce the packed PE.
    pub output: OutputConfig,
}

/// `payload` block: the input source and its cryptographic transformation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadConfig {
    /// The input payload: a local path or a URL (the packer detects the scheme).
    ///
    /// Supports `http://`, `https://` and `file://` sources; anything else is a
    /// local path. `ftp://` is recognized but not implemented.
    pub source: String,

    /// The input's binary format (default: `pe`).
    ///
    /// `pe` is an executable image, `dll` a library image and `shellcode` a raw
    /// code blob with no headers. The format decides how the packer validates the
    /// input and how the execution technique runs it.
    #[serde(default)]
    pub format: PayloadFormat,

    /// Exported function to invoke for `format: dll` (e.g. `Run`).
    ///
    /// Optional: without it the payload's entry point runs (`DllMain` with
    /// `DLL_PROCESS_ATTACH`), which only initializes the library. An export is
    /// the usual way to give a DLL payload real work to do. Rejected unless
    /// `format` is `dll`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export: Option<String>,

    /// Fixed arguments passed to the payload at runtime, in order.
    ///
    /// Optional: without them the stub forwards only the args the operator
    /// passes to the packed binary itself (see `args_mode`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,

    /// How `args` combine with the runtime args (default: `join`).
    #[serde(default)]
    pub args_mode: ArgsMode,

    /// Sub-block with the cryptographic configuration.
    pub crypto: CryptoConfig,

    /// Optional expected SHA-256 (hex) of the input payload.
    ///
    /// Pins a remote `http(s)://` source to a known build: a mismatch aborts
    /// before anything is encrypted. Useful to stop a URL (or a tampered local
    /// file) from silently changing what gets packed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// `stub` block: the stub configuration.
///
/// `path` selects a custom stub template; `syscalls` configures how the stub
/// talks to the kernel; `strings` configures the obfuscation applied to the
/// stub's literals. All are optional: without them the builtin stub, the
/// default syscall mode, and `xor` + a random key are used.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StubConfig {
    /// Path to a custom stub template (`.rs`). `None` means the builtin stub.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,

    /// Syscall-layer configuration (how the stub invokes the kernel).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syscalls: Option<YamlSyscallsConfig>,

    /// Optional string-obfuscation configuration.
    ///
    /// Applies to every stub literal (template, technique fragments and anything
    /// else the packer emits), independent of the techniques. When absent, the
    /// packer defaults to `xor` + a random key (and warns).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strings: Option<YamlStringsConfig>,
}

/// The binary format of the input payload.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PayloadFormat {
    /// A PE executable image (PE32+). The default.
    #[default]
    Pe,
    /// Raw shellcode: a position-independent code blob with no PE headers.
    Shellcode,
    /// A PE library image (a DLL).
    Dll,
}

impl PayloadFormat {
    /// Lowercase label used in build output and error messages.
    pub fn label(self) -> &'static str {
        match self {
            PayloadFormat::Pe => "pe",
            PayloadFormat::Shellcode => "shellcode",
            PayloadFormat::Dll => "dll",
        }
    }

    /// Whether the format carries PE headers (so the packer parses it as a PE).
    pub fn is_pe_image(self) -> bool {
        matches!(self, PayloadFormat::Pe | PayloadFormat::Dll)
    }
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

    /// Whether to write the build manifest next to the artifact (default: yes).
    ///
    /// The manifest (`<stem>.manifest.json`) records the artifact and payload
    /// hashes, the resolved config and the toolchain, for provenance.
    #[serde(default = "default_true")]
    pub manifest: bool,

    /// Optional PE resources embedded into the artifact (`output.resources`).
    ///
    /// Distinct from `manifest` above: that one is the build-provenance JSON,
    /// this one is the executable's own resources (icon, version info and the
    /// Windows application manifest) written into a `.rsrc` section.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourcesConfig>,

    /// Subsystem of the packed binary: `console` (default) or `windows` (GUI).
    ///
    /// A `windows` build hides the console window a console process would
    /// flash, which is what a normal GUI application looks like.
    #[serde(default, skip_serializing_if = "Subsystem::is_console")]
    pub subsystem: Subsystem,

    /// Optional Authenticode signing (`output.sign`).
    ///
    /// The packer signs the artifact with `signtool`, either with a self-signed
    /// lab certificate (`mode: lab`), one already in the user's store
    /// (`mode: store`) or a `.pfx` (`mode: file`). A self-signed signature is
    /// for integrity and lab verification only; it does not buy SmartScreen
    /// reputation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign: Option<SignConfig>,
}

/// Subsystem of the packed binary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Subsystem {
    /// A console application (a console window is allocated).
    #[default]
    Console,
    /// A GUI application (no console window).
    Windows,
}

impl Subsystem {
    /// Whether this is the default subsystem (used to skip it when serializing).
    pub fn is_console(&self) -> bool {
        matches!(self, Subsystem::Console)
    }

    /// Lowercase label.
    pub fn label(self) -> &'static str {
        match self {
            Subsystem::Console => "console",
            Subsystem::Windows => "windows",
        }
    }
}

/// `output.sign`: Authenticode signing of the artifact.
///
/// Every field is optional except `mode`; which of the others matter depends on
/// the mode:
///
/// - `none` — no signing (default).
/// - `lab` — use (or create) an automatic CA + code-signing chain in the
///   current user's store, matched by `subject`. When signing runs, the CA's
///   public certificate is exported next to the artifact
///   (`<stem>.ca.cer`) so it can be trusted on the lab machine; nothing is
///   added to the local trust stores.
/// - `store` — use a certificate already in the current user's store, matched by
///   `thumbprint` or `subject`.
/// - `file` — sign with a `.pfx`/`.p12` file; the password is read from the
///   environment variable named by `password_env` (never from the YAML).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignConfig {
    /// `none`, `lab`, `store` or `file`.
    #[serde(default = "default_sign_mode")]
    pub mode: String,

    /// Certificate subject to use or create (e.g. `CN=batesian lab`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,

    /// Certificate thumbprint, for `mode: store`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,

    /// Path to a `.pfx`/`.p12`, for `mode: file`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<PathBuf>,

    /// Environment variable holding the `.pfx` password, for `mode: file`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_env: Option<String>,

    /// RFC 3161 timestamp server; without it the signature expires with the
    /// certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_url: Option<String>,

    /// Explicit `signtool.exe` path, overriding PATH and the Windows SDK search.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signtool: Option<PathBuf>,
}

/// Default signing mode: no signing.
fn default_sign_mode() -> String {
    "none".to_string()
}

/// `output.resources`: the PE resources to embed into the artifact.
///
/// All fields are optional; each one that is set adds the matching resource
/// type. The resources are built programmatically (no `rc.exe`/`windres`), so
/// the build stays pure Rust and cross-platform.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourcesConfig {
    /// Path to a `.ico` file, embedded as `RT_GROUP_ICON` + `RT_ICON`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<PathBuf>,

    /// `VERSIONINFO` strings, embedded as `RT_VERSION`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_info: Option<VersionInfoConfig>,

    /// Windows application manifest (UAC/DPI), embedded as `RT_MANIFEST`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<ManifestConfig>,
}

/// `output.resources.version_info`: the strings of the `VERSIONINFO` resource.
///
/// Every field is optional; the ones present are emitted. Versions are
/// `MAJOR.MINOR.PATCH.BUILD` (1 to 4 dot-separated numbers; missing parts are
/// zero).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionInfoConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub company: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_filename: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub internal_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copyright: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_version: Option<String>,

    /// Fill the unset fields with plausible random values (company, product,
    /// description, versions, copyright) instead of leaving them out.
    ///
    /// Explicit fields always win, so this can be combined with a fixed company
    /// and a randomized version. When the lab certificate has no `subject`, the
    /// generated company is used for it too, so the artifact and the signature
    /// agree.
    #[serde(default)]
    pub randomize: bool,
}

/// `output.resources.manifest`: the Windows application manifest to embed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestConfig {
    /// Requested UAC execution level (default: `as_invoker`).
    #[serde(default)]
    pub level: ExecutionLevel,

    /// `uiAccess` attribute (default: false); needs a signed, installed app.
    #[serde(default)]
    pub ui_access: bool,

    /// Whether to declare DPI awareness (default: true).
    #[serde(default = "default_true")]
    pub dpi_aware: bool,
}

impl Default for ManifestConfig {
    fn default() -> Self {
        Self {
            level: ExecutionLevel::AsInvoker,
            ui_access: false,
            dpi_aware: true,
        }
    }
}

/// UAC execution level for the embedded application manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionLevel {
    /// Run with the caller's privileges (default).
    AsInvoker,
    /// Elevate when the user is an administrator, without prompting.
    HighestAvailable,
    /// Always prompt for elevation.
    RequireAdministrator,
}

impl Default for ExecutionLevel {
    fn default() -> Self {
        Self::AsInvoker
    }
}

impl ExecutionLevel {
    /// The XML attribute value (`asInvoker`, `highestAvailable`, ...).
    pub fn xml_value(self) -> &'static str {
        match self {
            ExecutionLevel::AsInvoker => "asInvoker",
            ExecutionLevel::HighestAvailable => "highestAvailable",
            ExecutionLevel::RequireAdministrator => "requireAdministrator",
        }
    }
}

/// `serde` default for boolean fields that default to enabled.
fn default_true() -> bool {
    true
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
    /// Rewrite every absolute build path the compiler emits (the project and the
    /// Cargo home). Best effort: source paths baked into prebuilt dependency
    /// rlibs are outside `rustc`'s control, so `strip: true` is what removes
    /// those.
    All,
    /// Leave build paths untouched.
    None,
    /// Rewrite the project's own paths to relative; absolute paths outside the
    /// project (e.g. the Cargo home) are left untouched.
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
        2 => Err(serde::de::Error::custom(SCHEMA_2_MIGRATION)),
        3 => Err(serde::de::Error::custom(SCHEMA_3_MIGRATION)),
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
schema: 4
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
    params:
      target: "C:\\Windows\\System32\\svchost.exe"
"#;

    #[test]
    fn parses_valid_config() {
        let config: Config =
            serde_yml::from_str(VALID_YAML).expect("the example YAML should parse");

        assert_eq!(config.schema, 4);
        assert_eq!(config.name, "mimikatz-basic");
        assert_eq!(config.build.payload.source, "./mimikatz.exe");
        assert_eq!(
            config.build.payload.crypto.algo,
            CryptoAlgorithm::XChaCha20Poly1305
        );
        assert_eq!(config.build.payload.crypto.key, KeySource::Random);
        assert_eq!(config.build.stub.path, None);
        assert_eq!(config.build.stub.syscalls, None);
        assert_eq!(config.build.stub.strings, None);
        assert_eq!(
            config.runtime,
            vec![RuntimeStep::ProcessHollowing {
                params: Params {
                    target: r"C:\Windows\System32\svchost.exe".to_string(),
                }
            }]
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
    fn parses_stub_strings_block() {
        let yaml = VALID_YAML.replace(
            "  output:\n",
            "  stub:\n    strings:\n      strategy: stack\n      key: random\n\n  output:\n",
        );
        let config: Config = serde_yml::from_str(&yaml).expect("stub strings block should parse");
        let strings = config
            .build
            .stub
            .strings
            .expect("strings should be present");
        assert_eq!(strings.strategy, "stack");
        assert_eq!(strings.key, "random");
    }

    #[test]
    fn parses_stub_strings_and_syscalls_together() {
        let yaml = VALID_YAML.replace(
            "  output:\n",
            "  stub:\n    syscalls:\n      mode: indirect\n    strings:\n      strategy: xor\n\n  output:\n",
        );
        let config: Config = serde_yml::from_str(&yaml).expect("stub block should parse");
        assert_eq!(
            config.build.stub.syscalls.expect("syscalls").mode,
            "indirect"
        );
        assert_eq!(config.build.stub.strings.expect("strings").strategy, "xor");
    }

    #[test]
    fn strings_block_is_optional() {
        let config: Config = serde_yml::from_str(VALID_YAML).expect("valid YAML should parse");
        assert_eq!(config.build.stub.strings, None);
    }

    #[test]
    fn rejects_strings_block_at_build_level() {
        // Schema 2's `build.strings` is no longer a valid sibling of `payload`.
        let yaml = VALID_YAML.replace(
            "  output:\n",
            "  strings:\n    strategy: xor\n\n  output:\n",
        );
        assert!(
            serde_yml::from_str::<Config>(&yaml).is_err(),
            "build.strings should be rejected (deny_unknown_fields)"
        );
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
            "  - technique: process_hollowing\n    params:\n      target: \"C:\\\\Windows\\\\System32\\\\svchost.exe\"\n",
            "  - technique: process_hollowing\n",
        );
        let config: Config =
            serde_yml::from_str(&yaml).expect("process_hollowing without target should parse");
        assert_eq!(
            config.runtime,
            vec![RuntimeStep::ProcessHollowing {
                params: Params {
                    target: default_target(),
                }
            }]
        );
    }

    #[test]
    fn payload_args_default_to_join() {
        let config: Config = serde_yml::from_str(VALID_YAML).expect("valid YAML should parse");
        assert_eq!(config.build.payload.args, None);
        assert_eq!(config.build.payload.args_mode, ArgsMode::Join);
    }

    /// Locks in the documented migration hazard: unknown keys inside a runtime
    /// entry are dropped, so a config migrated from schema 3 that leaves its
    /// parameters flat parses and silently falls back to the defaults.
    #[test]
    fn a_flat_param_is_dropped_and_the_default_applies() {
        let yaml = VALID_YAML.replace(
            "    params:\n      target: \"C:\\\\Windows\\\\System32\\\\svchost.exe\"\n",
            "    target: \"C:\\\\Windows\\\\System32\\\\notepad.exe\"\n",
        );
        let config: Config = serde_yml::from_str(&yaml).expect("a flat param still parses");
        assert_eq!(
            config.runtime,
            vec![RuntimeStep::ProcessHollowing {
                params: Params {
                    target: default_target(),
                }
            }],
            "the flat target must be dropped in favour of the default"
        );
    }

    #[test]
    fn payload_args_and_override_mode_parse() {
        let yaml = VALID_YAML.replace(
            "    source: ./mimikatz.exe\n",
            "    source: ./mimikatz.exe\n    args: [\"privilege::debug\", \"log\", \"C:\\\\temp\\\\out.log\"]\n    args_mode: override\n",
        );
        let config: Config = serde_yml::from_str(&yaml).expect("args should parse");
        assert_eq!(
            config.build.payload.args,
            Some(vec![
                "privilege::debug".to_string(),
                "log".to_string(),
                r"C:\temp\out.log".to_string(),
            ])
        );
        assert_eq!(config.build.payload.args_mode, ArgsMode::Override);
    }

    #[test]
    fn empty_payload_args_are_valid() {
        let yaml = VALID_YAML.replace(
            "    source: ./mimikatz.exe\n",
            "    source: ./mimikatz.exe\n    args: []\n",
        );
        let config: Config = serde_yml::from_str(&yaml).expect("empty args should parse");
        assert_eq!(config.build.payload.args, Some(vec![]));
        assert_eq!(config.build.payload.args_mode, ArgsMode::Join);
    }

    #[test]
    fn payload_args_keep_special_characters() {
        let yaml = VALID_YAML.replace(
            "    source: ./mimikatz.exe\n",
            "    source: ./mimikatz.exe\n    args: ['hello world', 'say \"hi\"', 'C:\\Program Files\\x']\n",
        );
        let config: Config = serde_yml::from_str(&yaml).expect("special args should parse");
        assert_eq!(
            config.build.payload.args,
            Some(vec![
                "hello world".to_string(),
                "say \"hi\"".to_string(),
                r"C:\Program Files\x".to_string(),
            ])
        );
    }

    #[test]
    fn rejects_unknown_args_mode() {
        let yaml = VALID_YAML.replace(
            "    source: ./mimikatz.exe\n",
            "    source: ./mimikatz.exe\n    args_mode: prepend\n",
        );
        assert!(
            serde_yml::from_str::<Config>(&yaml).is_err(),
            "an unknown args_mode should fail"
        );
    }

    #[test]
    fn payload_format_defaults_to_pe() {
        let config: Config = serde_yml::from_str(VALID_YAML).expect("valid YAML should parse");
        assert_eq!(config.build.payload.format, PayloadFormat::Pe);
        assert_eq!(config.build.payload.export, None);
    }

    #[test]
    fn parses_shellcode_format() {
        let yaml = VALID_YAML.replace(
            "    source: ./mimikatz.exe\n",
            "    source: ./beacon.bin\n    format: shellcode\n",
        );
        let config: Config = serde_yml::from_str(&yaml).expect("shellcode format should parse");
        assert_eq!(config.build.payload.format, PayloadFormat::Shellcode);
        assert!(!config.build.payload.format.is_pe_image());
    }

    #[test]
    fn parses_dll_format_with_export() {
        let yaml = VALID_YAML.replace(
            "    source: ./mimikatz.exe\n",
            "    source: ./payload.dll\n    format: dll\n    export: Run\n",
        );
        let config: Config = serde_yml::from_str(&yaml).expect("dll format should parse");
        assert_eq!(config.build.payload.format, PayloadFormat::Dll);
        assert_eq!(config.build.payload.export.as_deref(), Some("Run"));
        assert!(config.build.payload.format.is_pe_image());
    }

    #[test]
    fn rejects_unknown_payload_format() {
        let yaml = VALID_YAML.replace(
            "    source: ./mimikatz.exe\n",
            "    source: ./beacon.bin\n    format: vbs\n",
        );
        assert!(
            serde_yml::from_str::<Config>(&yaml).is_err(),
            "an unknown payload format should fail"
        );
    }

    #[test]
    fn rejects_invalid_target_type() {
        let yaml = VALID_YAML.replace(
            "      target: \"C:\\\\Windows\\\\System32\\\\svchost.exe\"\n",
            "      target: 123\n",
        );
        assert!(
            serde_yml::from_str::<Config>(&yaml).is_err(),
            "a non-string target should fail"
        );
    }

    #[test]
    fn rejects_schema_one_with_a_migration_message() {
        let yaml = VALID_YAML.replace("schema: 4", "schema: 1");
        let err = serde_yml::from_str::<Config>(&yaml).expect_err("schema 1 should fail");
        let msg = err.to_string();
        assert!(
            msg.contains("schema 1 is no longer supported"),
            "unclear error message: {msg}"
        );
        assert!(msg.contains("build.payload.source"), "msg: {msg}");
        assert!(msg.contains("$arg.N$"), "msg: {msg}");
        assert!(msg.contains("docs/migration-v1-v3.md"), "msg: {msg}");
    }

    #[test]
    fn rejects_schema_two_with_a_migration_message() {
        let yaml = VALID_YAML.replace("schema: 4", "schema: 2");
        let err = serde_yml::from_str::<Config>(&yaml).expect_err("schema 2 should fail");
        let msg = err.to_string();
        assert!(
            msg.contains("schema 2 is no longer supported"),
            "unclear error message: {msg}"
        );
        assert!(msg.contains("build.stub.strings"), "msg: {msg}");
        assert!(msg.contains("docs/migration-v2-v3.md"), "msg: {msg}");
    }

    #[test]
    fn rejects_schema_three_with_a_migration_message() {
        let yaml = VALID_YAML.replace("schema: 4", "schema: 3");
        let err = serde_yml::from_str::<Config>(&yaml).expect_err("schema 3 should fail");
        let msg = err.to_string();
        assert!(
            msg.contains("schema 3 is no longer supported"),
            "unclear error message: {msg}"
        );
        assert!(msg.contains("params:"), "msg: {msg}");
        assert!(msg.contains("docs/migration-v3-v4.md"), "msg: {msg}");
    }

    #[test]
    fn rejects_unknown_schema_version() {
        let yaml = VALID_YAML.replace("schema: 4", "schema: 5");
        let err = serde_yml::from_str::<Config>(&yaml).expect_err("schema 5 should fail");
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
            "runtime:\n  - technique: process_hollowing\n    params:\n      target: \"C:\\\\Windows\\\\System32\\\\svchost.exe\"\n",
            "",
        );
        let config: Config = serde_yml::from_str(&yaml).expect("an empty runtime should be valid");
        assert!(config.runtime.is_empty());
    }
}
