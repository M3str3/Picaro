//! `serde` structs modeling the YAML plan document (schema 4).
//!
//! Each struct maps to a block of the YAML (see `examples/plans/`).
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

use crate::engine::api_resolution::YamlApiResolutionPlan;
use crate::engine::args::ArgsMode;
use crate::engine::obfuscation::YamlStringsPlan;
use crate::engine::syscalls::YamlSyscallsPlan;
use crate::techniques::RuntimeStep;

/// The schema version this packer writes.
pub const SUPPORTED_SCHEMA: u32 = 5;

/// The previous schema version, still accepted: the single-payload shape.
///
/// A schema-4 document is a schema-5 document whose `build.payload`/`runtime`
/// are normalized into one stage (see [`crate::plan::stages`]), so existing
/// plans keep working unchanged.
pub const LEGACY_SCHEMA: u32 = 4;

/// Migration hint shown when a plan still declares `schema: 1`.
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

/// Migration hint shown when a plan still declares `schema: 2`.
const SCHEMA_2_MIGRATION: &str = "\
schema 2 is no longer supported.
Migration:
  build.strings → build.stub.strings
  runtime entries now nest parameters under `params:` (schema 3 → 4)
See docs/migration-v2-v3.md (then docs/migration-v3-v4.md) for details.";

/// Migration hint shown when a plan still declares `schema: 3`.
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
pub struct Plan {
    /// Schema version. Only `3` is accepted; it is validated on deserialize.
    #[serde(deserialize_with = "deserialize_schema_version")]
    pub schema: u32,

    /// Descriptive build name (identifies the generated artifact).
    pub name: String,

    /// Build block: payload, stub and output.
    pub build: BuildPlan,

    /// Execution techniques the stub applies, in order.
    ///
    /// It is optional: an empty runtime produces a stub with no extra
    /// techniques. Ignored when `stages` is non-empty (the single-payload
    /// shorthand of schema 5).
    #[serde(default)]
    pub runtime: Vec<RuntimeStep>,

    /// Ordered multi-payload chain (schema 5).
    ///
    /// Each entry is an action (`technique`, `exec` or `sleep`). When empty, the
    /// document is the single-payload shorthand and one `technique` stage is
    /// synthesized from `build.payload` + `runtime`.
    #[serde(default)]
    pub stages: Vec<StagePlan>,
}

/// `build` block: everything needed to produce the packed PE.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildPlan {
    /// Payload block: where the input PE comes from and how it is encrypted.
    ///
    /// Required for the single-payload shorthand (no `stages`); absent in a
    /// multi-stage plan, where every payload is declared inline per stage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<PayloadPlan>,

    /// Stub configuration: builtin or custom, the syscall layer and the
    /// string obfuscation applied to the stub's literals.
    #[serde(default)]
    pub stub: StubPlan,

    /// Output block: how to produce the packed PE.
    pub output: OutputPlan,
}

/// `payload` block: the input source and its cryptographic transformation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadPlan {
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
    pub crypto: CryptoPlan,

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
pub struct StubPlan {
    /// Path to a custom stub template (`.rs`). `None` means the builtin stub.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,

    /// Syscall-layer configuration (how the stub invokes the kernel).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syscalls: Option<YamlSyscallsPlan>,

    /// API-resolution configuration (how the loader resolves the payload's
    /// imports). `None` means the default (`mode: none`, no behaviour change).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_resolution: Option<YamlApiResolutionPlan>,

    /// Optional string-obfuscation configuration.
    ///
    /// Applies to every stub literal (template, technique fragments and anything
    /// else the packer emits), independent of the techniques. When absent, the
    /// packer defaults to `xor` + a random key (and warns).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strings: Option<YamlStringsPlan>,

    /// Compile the stub as a debug artifact.
    ///
    /// The techniques print what they are doing on stderr
    /// (`[+] [<technique>] <message>`) and the artifact is built without the
    /// hardening: symbols and debug info are kept, the optimizer is off and the
    /// source paths are left in place so a debugger can open the generated
    /// stub. This is a laboratory tool: a debug artifact is markedly less
    /// evasive and is never meant to be delivered. Defaults to `false`.
    #[serde(default)]
    pub debug: bool,
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
    /// A managed (.NET) assembly: a PE image whose entry point calls
    /// `mscoree.dll!_CorExeMain`. It is not mapped like a native payload; the
    /// stub hosts the CLR and loads the assembly from memory
    /// (`technique: dotnet_hosting`).
    Dotnet,
}

impl PayloadFormat {
    /// Lowercase label used in build output and error messages.
    pub fn label(self) -> &'static str {
        match self {
            PayloadFormat::Pe => "pe",
            PayloadFormat::Shellcode => "shellcode",
            PayloadFormat::Dll => "dll",
            PayloadFormat::Dotnet => "dotnet",
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
pub struct CryptoPlan {
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
pub struct OutputPlan {
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
    /// hashes, the resolved plan and the toolchain, for provenance.
    #[serde(default = "default_true")]
    pub manifest: bool,

    /// Optional PE resources embedded into the artifact (`output.resources`).
    ///
    /// Distinct from `manifest` above: that one is the build-provenance JSON,
    /// this one is the executable's own resources (icon, version info and the
    /// Windows application manifest) written into a `.rsrc` section.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourcesPlan>,

    /// Subsystem of the packed binary: `console` (default) or `windows` (GUI).
    ///
    /// A `windows` build hides the console window a console process would
    /// flash, which is what a normal GUI application looks like.
    #[serde(default, skip_serializing_if = "Subsystem::is_console")]
    pub subsystem: Subsystem,

    /// Optional Authenticode signing (`output.sign`).
    ///
    /// The packer signs the artifact, either with a self-signed lab certificate
    /// (`mode: lab`), one already in the user's store (`mode: store`, Windows
    /// only) or a `.pfx` (`mode: file`). It uses `signtool` on Windows and
    /// `osslsigncode` elsewhere, so the same plan also signs inside the Docker
    /// image. A self-signed signature is for integrity and lab verification only;
    /// it does not buy SmartScreen reputation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign: Option<SignPlan>,
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
///   `thumbprint` or `subject`. This is the *Windows* certificate store, so the
///   mode is Windows only; inside a container use `file` or `lab`.
/// - `file` — sign with a `.pfx`/`.p12` file; the password is read from the
///   environment variable named by `password_env` (never from the YAML).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignPlan {
    /// `none`, `lab`, `store` or `file`.
    #[serde(default = "default_sign_mode")]
    pub mode: String,

    /// Certificate subject to use or create (e.g. `CN=picaro lab`).
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
pub struct ResourcesPlan {
    /// Path to a `.ico` file, embedded as `RT_GROUP_ICON` + `RT_ICON`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<PathBuf>,

    /// `VERSIONINFO` strings, embedded as `RT_VERSION`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_info: Option<VersionInfoPlan>,

    /// Windows application manifest (UAC/DPI), embedded as `RT_MANIFEST`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<ManifestPlan>,
}

/// `output.resources.version_info`: the strings of the `VERSIONINFO` resource.
///
/// Every field is optional; the ones present are emitted. Versions are
/// `MAJOR.MINOR.PATCH.BUILD` (1 to 4 dot-separated numbers; missing parts are
/// zero).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionInfoPlan {
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
pub struct ManifestPlan {
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

impl Default for ManifestPlan {
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    /// x86-64 (PE32+).
    #[default]
    X64,
    /// x86 (PE32).
    X86,
}

impl Arch {
    /// Lowercase label used in messages and the build log.
    pub fn label(self) -> &'static str {
        match self {
            Arch::X64 => "x64",
            Arch::X86 => "x86",
        }
    }
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

/// One entry of the top-level `stages:` list (schema 5).
///
/// A stage is an *action*: run an embedded payload with a technique pipeline
/// (`action: technique`), launch a process such as a living-off-the-land binary
/// (`action: exec`), or wait (`action: sleep`). The list order is the order the
/// generated stub runs them in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagePlan {
    /// Optional label, used in messages and the generated stub's module names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// What the stage does (default: `technique`).
    #[serde(default)]
    pub action: StageAction,

    /// `technique`: the payload to run (inline; each stage carries its own).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<PayloadPlan>,

    /// `technique`: preparation + execution techniques, in order.
    #[serde(default)]
    pub runtime: Vec<RuntimeStep>,

    /// `exec`: the process to launch. A bare name (no path separator) is
    /// resolved against `System32` at run time; an absolute path is used as is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary: Option<String>,

    /// `exec`: arguments passed to `binary`.
    #[serde(default)]
    pub args: Vec<String>,

    /// `exec`: wait for the child and capture its exit code (default: true).
    #[serde(default = "default_true")]
    pub wait: bool,

    /// `exec`: window visibility (default: hidden).
    #[serde(default)]
    pub window: WindowMode,

    /// `exec`: seconds to wait for the child before terminating it (0 = no
    /// limit). Only meaningful with `wait: true`.
    #[serde(default)]
    pub timeout_s: u64,

    /// `sleep`: milliseconds to wait.
    #[serde(default)]
    pub sleep_ms: u64,

    /// What to do when the stage runs to completion (default: continue).
    #[serde(default)]
    pub on_success: StageOutcome,

    /// What to do when the stage fails (default: stop, i.e. propagate the
    /// error and exit 1).
    #[serde(default)]
    pub on_fail: StageFailure,

    /// Wait this long before starting the stage.
    #[serde(default)]
    pub delay_ms: u64,
}

impl StagePlan {
    /// A human label for the stage: its `name`, or `<action><index>`.
    pub fn label(&self, index: usize) -> String {
        match &self.name {
            Some(name) => name.clone(),
            None => format!("{}{index}", self.action.label()),
        }
    }
}

/// What a stage does (`stages[].action`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StageAction {
    /// Run an embedded payload with a technique pipeline (the single-payload
    /// shape, generalized).
    #[default]
    Technique,
    /// Launch a process: a living-off-the-land binary or any command (T1218).
    Exec,
    /// Wait a number of milliseconds.
    Sleep,
}

impl StageAction {
    /// Lowercase label used in messages and the build log.
    pub fn label(self) -> &'static str {
        match self {
            StageAction::Technique => "technique",
            StageAction::Exec => "exec",
            StageAction::Sleep => "sleep",
        }
    }
}

/// Window visibility for an `exec` stage.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WindowMode {
    /// No console window (`CREATE_NO_WINDOW` + `SW_HIDE`). The default.
    #[default]
    Hidden,
    /// Inherit the parent's console/window state.
    Normal,
}

/// What to do after a stage completes (`stages[].on_success`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StageOutcome {
    /// Run the next stage (default).
    #[default]
    Continue,
    /// Stop the chain, exiting with this stage's code.
    Stop,
    /// Stop the chain and exit `0` immediately.
    Exit,
}

/// What to do when a stage fails (`stages[].on_fail`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StageFailure {
    /// Propagate the failure: the stub reports it and exits `1` (default).
    #[default]
    Stop,
    /// Log the failure and run the next stage.
    Continue,
    /// Report the failure and exit `0`.
    Exit,
}

/// Validates the schema version during deserialization.
///
/// Accepts the current schema ([`SUPPORTED_SCHEMA`], 5) and the legacy 4
/// (single-payload). Gives a clear migration hint for the retired 1/2/3 and a
/// generic message for anything unknown.
fn deserialize_schema_version<'de, D>(deserializer: D) -> std::result::Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let version = u32::deserialize(deserializer)?;
    match version {
        SUPPORTED_SCHEMA | LEGACY_SCHEMA => Ok(version),
        1 => Err(serde::de::Error::custom(SCHEMA_1_MIGRATION)),
        2 => Err(serde::de::Error::custom(SCHEMA_2_MIGRATION)),
        3 => Err(serde::de::Error::custom(SCHEMA_3_MIGRATION)),
        other => Err(serde::de::Error::custom(format!(
            "unsupported schema version: {other} (schema {SUPPORTED_SCHEMA} is current; schema {LEGACY_SCHEMA} is accepted for single-payload plans)"
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
    fn parses_valid_plan() {
        let plan: Plan = serde_yml::from_str(VALID_YAML).expect("the example YAML should parse");

        assert_eq!(plan.schema, 4);
        assert_eq!(plan.name, "mimikatz-basic");
        assert_eq!(
            plan.build.payload.as_ref().unwrap().source,
            "./mimikatz.exe"
        );
        assert_eq!(
            plan.build.payload.as_ref().unwrap().crypto.algo,
            CryptoAlgorithm::XChaCha20Poly1305
        );
        assert_eq!(
            plan.build.payload.as_ref().unwrap().crypto.key,
            KeySource::Random
        );
        assert_eq!(plan.build.stub.path, None);
        assert_eq!(plan.build.stub.syscalls, None);
        assert_eq!(plan.build.stub.api_resolution, None);
        assert_eq!(plan.build.stub.strings, None);
        assert_eq!(
            plan.runtime,
            vec![RuntimeStep::ProcessHollowing {
                params: Params {
                    target: r"C:\Windows\System32\svchost.exe".to_string(),
                }
            }]
        );
        assert_eq!(
            plan.build.output.path,
            PathBuf::from("./dist/mimikatz_packed.exe")
        );
        assert_eq!(plan.build.output.arch, Arch::X64);
        assert!(plan.build.output.strip);
        assert_eq!(plan.build.output.trim_paths, TrimPaths::All);
    }

    #[test]
    fn parses_stub_strings_block() {
        let yaml = VALID_YAML.replace(
            "  output:\n",
            "  stub:\n    strings:\n      strategy: stack\n      key: random\n\n  output:\n",
        );
        let plan: Plan = serde_yml::from_str(&yaml).expect("stub strings block should parse");
        let strings = plan.build.stub.strings.expect("strings should be present");
        assert_eq!(strings.strategy, "stack");
        assert_eq!(strings.key, "random");
    }

    #[test]
    fn parses_stub_strings_and_syscalls_together() {
        let yaml = VALID_YAML.replace(
            "  output:\n",
            "  stub:\n    syscalls:\n      mode: indirect\n    strings:\n      strategy: xor\n\n  output:\n",
        );
        let plan: Plan = serde_yml::from_str(&yaml).expect("stub block should parse");
        assert_eq!(plan.build.stub.syscalls.expect("syscalls").mode, "indirect");
        assert_eq!(plan.build.stub.strings.expect("strings").strategy, "xor");
    }

    #[test]
    fn strings_block_is_optional() {
        let plan: Plan = serde_yml::from_str(VALID_YAML).expect("valid YAML should parse");
        assert_eq!(plan.build.stub.strings, None);
    }

    #[test]
    fn parses_stub_api_resolution_block() {
        let yaml = VALID_YAML.replace(
            "  output:\n",
            "  stub:\n    api_resolution:\n      mode: proxy\n      apis:\n        - \"kernel32!ReadProcessMemory\"\n      unmatched: abort\n\n  output:\n",
        );
        let plan: Plan = serde_yml::from_str(&yaml).expect("api_resolution block should parse");
        let api = plan
            .build
            .stub
            .api_resolution
            .expect("api_resolution should be present");
        assert_eq!(api.mode, "proxy");
        assert_eq!(api.unmatched, "abort");
        assert_eq!(api.apis, vec!["kernel32!ReadProcessMemory".to_string()]);
    }

    #[test]
    fn rejects_strings_block_at_build_level() {
        // Schema 2's `build.strings` is no longer a valid sibling of `payload`.
        let yaml = VALID_YAML.replace(
            "  output:\n",
            "  strings:\n    strategy: xor\n\n  output:\n",
        );
        assert!(
            serde_yml::from_str::<Plan>(&yaml).is_err(),
            "build.strings should be rejected (deny_unknown_fields)"
        );
    }

    #[test]
    fn stub_block_is_optional_and_defaults_to_builtin() {
        let plan: Plan = serde_yml::from_str(VALID_YAML).expect("valid YAML should parse");
        assert_eq!(plan.build.stub, StubPlan::default());
    }

    #[test]
    fn parses_stub_path_block() {
        let yaml = VALID_YAML.replace(
            "  output:\n",
            "  stub:\n    path: ./my_stub.rs\n\n  output:\n",
        );
        let plan: Plan = serde_yml::from_str(&yaml).expect("stub block should parse");
        assert_eq!(plan.build.stub.path, Some(PathBuf::from("./my_stub.rs")));
    }

    #[test]
    fn stub_path_null_means_builtin() {
        let yaml = VALID_YAML.replace("  output:\n", "  stub:\n    path: null\n\n  output:\n");
        let plan: Plan = serde_yml::from_str(&yaml).expect("null path should parse");
        assert_eq!(plan.build.stub.path, None);
    }

    #[test]
    fn parses_stub_syscalls_block() {
        let yaml = VALID_YAML.replace(
            "  output:\n",
            "  stub:\n    syscalls:\n      mode: indirect\n\n  output:\n",
        );
        let plan: Plan = serde_yml::from_str(&yaml).expect("syscalls block should parse");
        assert_eq!(plan.build.stub.path, None);
        let syscalls = plan
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
        let plan: Plan = serde_yml::from_str(&yaml).expect("empty syscalls should parse");
        let syscalls = plan
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
        let plan: Plan = serde_yml::from_str(&yaml).expect("a url source should parse");

        assert_eq!(
            plan.build.payload.as_ref().unwrap().source,
            "https://example.com/mimikatz.exe"
        );
    }

    #[test]
    fn process_hollowing_defaults_target() {
        let yaml = VALID_YAML.replace(
            "  - technique: process_hollowing\n    params:\n      target: \"C:\\\\Windows\\\\System32\\\\svchost.exe\"\n",
            "  - technique: process_hollowing\n",
        );
        let plan: Plan =
            serde_yml::from_str(&yaml).expect("process_hollowing without target should parse");
        assert_eq!(
            plan.runtime,
            vec![RuntimeStep::ProcessHollowing {
                params: Params {
                    target: default_target(),
                }
            }]
        );
    }

    #[test]
    fn payload_args_default_to_join() {
        let plan: Plan = serde_yml::from_str(VALID_YAML).expect("valid YAML should parse");
        assert_eq!(plan.build.payload.as_ref().unwrap().args, None);
        assert_eq!(
            plan.build.payload.as_ref().unwrap().args_mode,
            ArgsMode::Join
        );
    }

    /// Locks in the documented migration hazard: unknown keys inside a runtime
    /// entry are dropped, so a plan migrated from schema 3 that leaves its
    /// parameters flat parses and silently falls back to the defaults.
    #[test]
    fn a_flat_param_is_dropped_and_the_default_applies() {
        let yaml = VALID_YAML.replace(
            "    params:\n      target: \"C:\\\\Windows\\\\System32\\\\svchost.exe\"\n",
            "    target: \"C:\\\\Windows\\\\System32\\\\notepad.exe\"\n",
        );
        let plan: Plan = serde_yml::from_str(&yaml).expect("a flat param still parses");
        assert_eq!(
            plan.runtime,
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
        let plan: Plan = serde_yml::from_str(&yaml).expect("args should parse");
        assert_eq!(
            plan.build.payload.as_ref().unwrap().args,
            Some(vec![
                "privilege::debug".to_string(),
                "log".to_string(),
                r"C:\temp\out.log".to_string(),
            ])
        );
        assert_eq!(
            plan.build.payload.as_ref().unwrap().args_mode,
            ArgsMode::Override
        );
    }

    #[test]
    fn empty_payload_args_are_valid() {
        let yaml = VALID_YAML.replace(
            "    source: ./mimikatz.exe\n",
            "    source: ./mimikatz.exe\n    args: []\n",
        );
        let plan: Plan = serde_yml::from_str(&yaml).expect("empty args should parse");
        assert_eq!(plan.build.payload.as_ref().unwrap().args, Some(vec![]));
        assert_eq!(
            plan.build.payload.as_ref().unwrap().args_mode,
            ArgsMode::Join
        );
    }

    #[test]
    fn payload_args_keep_special_characters() {
        let yaml = VALID_YAML.replace(
            "    source: ./mimikatz.exe\n",
            "    source: ./mimikatz.exe\n    args: ['hello world', 'say \"hi\"', 'C:\\Program Files\\x']\n",
        );
        let plan: Plan = serde_yml::from_str(&yaml).expect("special args should parse");
        assert_eq!(
            plan.build.payload.as_ref().unwrap().args,
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
            serde_yml::from_str::<Plan>(&yaml).is_err(),
            "an unknown args_mode should fail"
        );
    }

    #[test]
    fn payload_format_defaults_to_pe() {
        let plan: Plan = serde_yml::from_str(VALID_YAML).expect("valid YAML should parse");
        assert_eq!(
            plan.build.payload.as_ref().unwrap().format,
            PayloadFormat::Pe
        );
        assert_eq!(plan.build.payload.as_ref().unwrap().export, None);
    }

    #[test]
    fn parses_shellcode_format() {
        let yaml = VALID_YAML.replace(
            "    source: ./mimikatz.exe\n",
            "    source: ./beacon.bin\n    format: shellcode\n",
        );
        let plan: Plan = serde_yml::from_str(&yaml).expect("shellcode format should parse");
        assert_eq!(
            plan.build.payload.as_ref().unwrap().format,
            PayloadFormat::Shellcode
        );
        assert!(!plan.build.payload.as_ref().unwrap().format.is_pe_image());
    }

    #[test]
    fn parses_dll_format_with_export() {
        let yaml = VALID_YAML.replace(
            "    source: ./mimikatz.exe\n",
            "    source: ./payload.dll\n    format: dll\n    export: Run\n",
        );
        let plan: Plan = serde_yml::from_str(&yaml).expect("dll format should parse");
        assert_eq!(
            plan.build.payload.as_ref().unwrap().format,
            PayloadFormat::Dll
        );
        assert_eq!(
            plan.build.payload.as_ref().unwrap().export.as_deref(),
            Some("Run")
        );
        assert!(plan.build.payload.as_ref().unwrap().format.is_pe_image());
    }

    #[test]
    fn rejects_unknown_payload_format() {
        let yaml = VALID_YAML.replace(
            "    source: ./mimikatz.exe\n",
            "    source: ./beacon.bin\n    format: vbs\n",
        );
        assert!(
            serde_yml::from_str::<Plan>(&yaml).is_err(),
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
            serde_yml::from_str::<Plan>(&yaml).is_err(),
            "a non-string target should fail"
        );
    }

    #[test]
    fn rejects_schema_one_with_a_migration_message() {
        let yaml = VALID_YAML.replace("schema: 4", "schema: 1");
        let err = serde_yml::from_str::<Plan>(&yaml).expect_err("schema 1 should fail");
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
        let err = serde_yml::from_str::<Plan>(&yaml).expect_err("schema 2 should fail");
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
        let err = serde_yml::from_str::<Plan>(&yaml).expect_err("schema 3 should fail");
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
        let yaml = VALID_YAML.replace("schema: 4", "schema: 6");
        let err = serde_yml::from_str::<Plan>(&yaml).expect_err("schema 6 should fail");
        let msg = err.to_string();
        assert!(
            msg.contains("unsupported schema version"),
            "unclear error message: {msg}"
        );
    }

    #[test]
    fn accepts_the_current_and_legacy_schemas() {
        for version in [4, 5] {
            let yaml = VALID_YAML.replace("schema: 4", &format!("schema: {version}"));
            assert!(
                serde_yml::from_str::<Plan>(&yaml).is_ok(),
                "schema {version} should parse"
            );
        }
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
        let err = serde_yml::from_str::<Plan>(yaml).expect_err("schema 1 should fail");
        assert!(
            err.to_string().contains("schema 1 is no longer supported"),
            "unclear error: {err}"
        );
    }

    #[test]
    fn rejects_unknown_technique() {
        let yaml = VALID_YAML.replace("process_hollowing", "indirect_syscalls");
        assert!(
            serde_yml::from_str::<Plan>(&yaml).is_err(),
            "an unknown technique should fail"
        );
    }

    #[test]
    fn rejects_typo_in_field_name() {
        let yaml = VALID_YAML.replace("name: mimikatz-basic", "naem: mimikatz-basic");
        assert!(
            serde_yml::from_str::<Plan>(&yaml).is_err(),
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
            serde_yml::from_str::<Plan>(&yaml).is_err(),
            "the schema-1 `input` block should fail (deny_unknown_fields)"
        );
    }

    #[test]
    fn allows_empty_runtime() {
        let yaml = VALID_YAML.replace(
            "runtime:\n  - technique: process_hollowing\n    params:\n      target: \"C:\\\\Windows\\\\System32\\\\svchost.exe\"\n",
            "",
        );
        let plan: Plan = serde_yml::from_str(&yaml).expect("an empty runtime should be valid");
        assert!(plan.runtime.is_empty());
    }
}
