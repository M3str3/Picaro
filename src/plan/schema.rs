//! `serde` structs modeling the YAML plan document (schema 6).
//!
//! Each struct maps to a block of the YAML (see `examples/plans/`).
//! The design aims to be:
//! - **Explicit**: fields are required by default (no magic values), except
//!   where `#[serde(default)]` says otherwise.
//! - **Strict**: `deny_unknown_fields` catches typos in the YAML keys.
//! - **Extensible**: the enums centralize the valid options, so adding a new
//!   technique or algorithm is a localized change.
//!
//! Schema 6 groups everything the build needs under `build` (`crypto`,
//! `payloads`, `stub`, `output`) and keeps the ordered technique list under
//! `runtime`. Every runtime step is a technique call (`technique` + `params`)
//! plus its orchestration fields (see [`StepControl`]).
//! See `docs/multistage.md` for the reference.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::engine::api_resolution::YamlApiResolutionPlan;
use crate::engine::args::ArgsMode;
use crate::engine::obfuscation::YamlStringsPlan;
use crate::engine::syscalls::YamlSyscallsPlan;
use crate::techniques::RuntimeStep;

/// The schema version this packer writes.
///
/// Schema 6 is the flat `runtime:` model: one ordered list of technique steps,
/// each with its `params` and its orchestration fields. There is no other shape.
pub const SUPPORTED_SCHEMA: u32 = 6;

/// Migration hint shown for any retired schema version (1–5).
const RETIRED_SCHEMA_MIGRATION: &str = "\
this schema version is no longer supported; schema 6 is the only accepted one.
Migration (schema <= 5 → 6):
  build.payload            → build.payloads.<name>
  stage.payload            → params.payload: <name> (in the execution technique)
  stages: [...actions...]  → runtime: [...steps...]
  stage.action: technique  → technique: <name> (+ params)
  stage.action: exec      → technique: living_off_the_land (+ params)
  stage.action: sleep     → technique: sleep (+ params)
  stage.on_success/on_fail/delay_ms → same fields on the step
A payload crypto block moves to `build.crypto` when shared by every payload.
See docs/multistage.md for the schema-6 reference.";

/// Root document of the YAML.
///
/// Two halves: `build` (what to produce) and `runtime` (the ordered technique
/// steps the generated stub runs), plus the `schema` and `name` metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    /// Schema version. Only [`SUPPORTED_SCHEMA`] is accepted; it is validated on
    /// deserialize.
    #[serde(deserialize_with = "deserialize_schema_version")]
    pub schema: u32,

    /// Descriptive build name (identifies the generated artifact).
    pub name: String,

    /// Build block: payloads, stub and output.
    pub build: BuildPlan,

    /// Ordered chain of technique steps. Each step names a technique and passes
    /// it its `params`; the loader orchestrates the chain from the steps' control
    /// fields. A plan needs at least one step (validated).
    #[serde(default)]
    pub runtime: Vec<RuntimeStep>,
}

/// `build` block: everything needed to produce the packed PE.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildPlan {
    /// Default crypto for every payload, inherited when a payload omits its own
    /// `crypto` block. A plan with no `crypto` here must set one per payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crypto: Option<CryptoPlan>,

    /// The named payloads a `technique` execution step can load by name
    /// (`params.payload: <name>`). A plan needs at least one when it declares an
    /// execution step (validated).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub payloads: BTreeMap<String, PayloadPlan>,

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

    /// Sub-block with the cryptographic configuration. Optional: inherits
    /// `build.crypto` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crypto: Option<CryptoPlan>,

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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoPlan {
    /// Authenticated encryption algorithm (default: `xchacha20poly1305`).
    #[serde(default)]
    pub algo: CryptoAlgorithm,

    /// Source of the encryption key (default: `random`, a fresh key per build).
    #[serde(default)]
    pub key: KeySource,
}

/// Supported encryption algorithms.
///
/// `rename_all = "lowercase"` makes the YAML value `xchacha20poly1305` map to
/// this variant (and vice versa when serializing).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CryptoAlgorithm {
    /// XChaCha20-Poly1305 (AEAD authenticated encryption, 24-byte nonce). The
    /// only supported algorithm, and the default.
    #[default]
    XChaCha20Poly1305,
}

/// Source of the encryption key.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeySource {
    /// Random key generated on every build. The default.
    #[default]
    Random,
}

/// `output` block: defines the final artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputPlan {
    /// Output path of the packed PE.
    pub path: PathBuf,

    /// Target architecture (default: `x64`).
    #[serde(default)]
    pub arch: Arch,

    /// Whether to strip the symbol table from the final binary (default: `true`).
    ///
    /// Stripping removes the symbol and debug tables `rustc` emits, so the
    /// artifact is smaller and carries no function names or debug type info.
    #[serde(default = "default_true")]
    pub strip: bool,

    /// Path-remapping policy for the debug info (default: `all`).
    ///
    /// `all` rewrites the absolute build paths the compiler bakes into the debug
    /// info (the project directory and the Cargo home) so they do not leak the
    /// build machine's layout. Best effort: paths baked into prebuilt dependency
    /// rlibs are outside `rustc`'s control — `strip: true` is what removes those.
    #[serde(default)]
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrimPaths {
    /// Rewrite every absolute build path the compiler emits (the project and the
    /// Cargo home). Best effort: source paths baked into prebuilt dependency
    /// rlibs are outside `rustc`'s control, so `strip: true` is what removes
    /// those. The default.
    #[default]
    All,
    /// Leave build paths untouched.
    None,
    /// Rewrite the project's own paths to relative; absolute paths outside the
    /// project (e.g. the Cargo home) are left untouched.
    Relative,
}

/// Orchestration every runtime step carries, outside the technique's `params`.
///
/// A step is the lego: a technique call plus how the loader reacts to its
/// result. These fields are deliberately *not* part of a technique's `params`
/// — they are not arguments of the function, they are the loader's policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepControl {
    /// What to do when the step completes (default: continue).
    #[serde(default)]
    pub on_success: StepOutcome,

    /// What to do when the step fails (default: stop, i.e. propagate the error
    /// and exit 1).
    #[serde(default)]
    pub on_fail: StepFailure,

    /// Wait this long before starting the step.
    #[serde(default)]
    pub delay_ms: u64,
}

/// Window visibility for `living_off_the_land`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WindowMode {
    /// No console window (`CREATE_NO_WINDOW` + `SW_HIDE`). The default.
    #[default]
    Hidden,
    /// Inherit the parent's console/window state.
    Normal,
}

/// What to do after a step completes (`runtime[].on_success`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StepOutcome {
    /// Run the next step (default).
    #[default]
    Continue,
    /// Stop the chain, exiting with this step's code.
    Stop,
    /// Stop the chain and exit `0` immediately.
    Exit,
}

/// What to do when a step fails (`runtime[].on_fail`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StepFailure {
    /// Propagate the failure: the stub reports it and exits `1` (default).
    #[default]
    Stop,
    /// Log the failure and run the next step.
    Continue,
    /// Report the failure and exit `0`.
    Exit,
}

/// Validates the schema version during deserialization.
///
/// Only [`SUPPORTED_SCHEMA`] (6) is accepted; any other version is rejected with
/// a migration hint pointing at the schema-6 shape.
fn deserialize_schema_version<'de, D>(deserializer: D) -> std::result::Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let version = u32::deserialize(deserializer)?;
    if version == SUPPORTED_SCHEMA {
        Ok(version)
    } else {
        Err(serde::de::Error::custom(format!(
            "schema {version} is not supported (schema {SUPPORTED_SCHEMA} is current).\n\
             {RETIRED_SCHEMA_MIGRATION}"
        )))
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    use crate::techniques::process_hollowing::{default_target, Params};
    use crate::techniques::TechniqueKind;

    /// Minimal valid YAML used as a base in all tests.
    const VALID_YAML: &str = r#"
schema: 6
name: mimikatz-basic

build:
  crypto:
    algo: xchacha20poly1305
    key: random
  payloads:
    mimikatz:
      source: ./mimikatz.exe

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

        assert_eq!(plan.schema, 6);
        assert_eq!(plan.name, "mimikatz-basic");
        let payload = plan.build.payloads.get("mimikatz").expect("the payload");
        assert_eq!(payload.source, "./mimikatz.exe");
        assert_eq!(payload.format, PayloadFormat::Pe);
        let crypto = plan.build.crypto.as_ref().expect("build.crypto");
        assert_eq!(crypto.algo, CryptoAlgorithm::XChaCha20Poly1305);
        assert_eq!(crypto.key, KeySource::Random);
        assert_eq!(plan.build.stub.path, None);
        assert_eq!(plan.build.stub.syscalls, None);
        assert_eq!(plan.build.stub.api_resolution, None);
        assert_eq!(plan.build.stub.strings, None);
        assert_eq!(
            plan.runtime[0].technique,
            TechniqueKind::ProcessHollowing {
                params: Params {
                    payload: None,
                    target: r"C:\Windows\System32\svchost.exe".to_string(),
                }
            }
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
        // Schema 2's `build.strings` is no longer a valid sibling of `payloads`.
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
            "      source: ./mimikatz.exe\n",
            "      source: https://example.com/mimikatz.exe\n",
        );
        let plan: Plan = serde_yml::from_str(&yaml).expect("a url source should parse");

        assert_eq!(
            plan.build.payloads.get("mimikatz").expect("payload").source,
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
            plan.runtime[0].technique,
            TechniqueKind::ProcessHollowing {
                params: Params {
                    payload: None,
                    target: default_target(),
                }
            }
        );
    }

    #[test]
    fn payload_args_default_to_join() {
        let plan: Plan = serde_yml::from_str(VALID_YAML).expect("valid YAML should parse");
        let payload = plan.build.payloads.get("mimikatz").expect("payload");
        assert_eq!(payload.args, None);
        assert_eq!(payload.args_mode, ArgsMode::Join);
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
            plan.runtime[0].technique,
            TechniqueKind::ProcessHollowing {
                params: Params {
                    payload: None,
                    target: default_target(),
                }
            },
            "the flat target must be dropped in favour of the default"
        );
    }

    #[test]
    fn payload_args_and_override_mode_parse() {
        let yaml = VALID_YAML.replace(
            "      source: ./mimikatz.exe\n",
            "      source: ./mimikatz.exe\n      args: [\"privilege::debug\", \"log\", \"C:\\\\temp\\\\out.log\"]\n      args_mode: override\n",
        );
        let plan: Plan = serde_yml::from_str(&yaml).expect("args should parse");
        let payload = plan.build.payloads.get("mimikatz").expect("payload");
        assert_eq!(
            payload.args,
            Some(vec![
                "privilege::debug".to_string(),
                "log".to_string(),
                r"C:\temp\out.log".to_string(),
            ])
        );
        assert_eq!(payload.args_mode, ArgsMode::Override);
    }

    #[test]
    fn empty_payload_args_are_valid() {
        let yaml = VALID_YAML.replace(
            "      source: ./mimikatz.exe\n",
            "      source: ./mimikatz.exe\n      args: []\n",
        );
        let plan: Plan = serde_yml::from_str(&yaml).expect("empty args should parse");
        let payload = plan.build.payloads.get("mimikatz").expect("payload");
        assert_eq!(payload.args, Some(vec![]));
        assert_eq!(payload.args_mode, ArgsMode::Join);
    }

    #[test]
    fn payload_args_keep_special_characters() {
        let yaml = VALID_YAML.replace(
            "      source: ./mimikatz.exe\n",
            "      source: ./mimikatz.exe\n      args: ['hello world', 'say \"hi\"', 'C:\\Program Files\\x']\n",
        );
        let plan: Plan = serde_yml::from_str(&yaml).expect("special args should parse");
        assert_eq!(
            plan.build.payloads.get("mimikatz").expect("payload").args,
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
            "      source: ./mimikatz.exe\n",
            "      source: ./mimikatz.exe\n      args_mode: prepend\n",
        );
        assert!(
            serde_yml::from_str::<Plan>(&yaml).is_err(),
            "an unknown args_mode should fail"
        );
    }

    #[test]
    fn payload_format_defaults_to_pe() {
        let plan: Plan = serde_yml::from_str(VALID_YAML).expect("valid YAML should parse");
        let payload = plan.build.payloads.get("mimikatz").expect("payload");
        assert_eq!(payload.format, PayloadFormat::Pe);
        assert_eq!(payload.export, None);
    }

    #[test]
    fn parses_shellcode_format() {
        let yaml = VALID_YAML.replace(
            "      source: ./mimikatz.exe\n",
            "      source: ./beacon.bin\n      format: shellcode\n",
        );
        let plan: Plan = serde_yml::from_str(&yaml).expect("shellcode format should parse");
        let payload = plan.build.payloads.get("mimikatz").expect("payload");
        assert_eq!(payload.format, PayloadFormat::Shellcode);
        assert!(!payload.format.is_pe_image());
    }

    #[test]
    fn parses_dll_format_with_export() {
        let yaml = VALID_YAML.replace(
            "      source: ./mimikatz.exe\n",
            "      source: ./payload.dll\n      format: dll\n      export: Run\n",
        );
        let plan: Plan = serde_yml::from_str(&yaml).expect("dll format should parse");
        let payload = plan.build.payloads.get("mimikatz").expect("payload");
        assert_eq!(payload.format, PayloadFormat::Dll);
        assert_eq!(payload.export.as_deref(), Some("Run"));
        assert!(payload.format.is_pe_image());
    }

    #[test]
    fn rejects_unknown_payload_format() {
        let yaml = VALID_YAML.replace(
            "      source: ./mimikatz.exe\n",
            "      source: ./beacon.bin\n      format: vbs\n",
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
    fn rejects_retired_schema_versions_with_a_migration_message() {
        for version in [1, 2, 3, 4, 5] {
            let yaml = VALID_YAML.replace("schema: 6", &format!("schema: {version}"));
            let err =
                serde_yml::from_str::<Plan>(&yaml).expect_err("a retired schema version must fail");
            assert!(
                err.to_string().contains("not supported"),
                "schema {version}: unclear error: {err}"
            );
        }
    }

    #[test]
    fn rejects_a_retired_schema_with_a_migration_hint() {
        let yaml = VALID_YAML.replace("schema: 6", "schema: 4");
        let err = serde_yml::from_str::<Plan>(&yaml).expect_err("schema 4 should fail");
        let msg = err.to_string();
        assert!(msg.contains("not supported"), "unclear message: {msg}");
        assert!(
            msg.contains("build.payloads"),
            "missing migration hint: {msg}"
        );
        assert!(
            msg.contains("living_off_the_land"),
            "missing migration hint: {msg}"
        );
    }

    #[test]
    fn accepts_only_the_current_schema() {
        let plan: Plan = serde_yml::from_str(VALID_YAML).expect("schema 6 parses");
        assert_eq!(plan.schema, SUPPORTED_SCHEMA);
    }

    #[test]
    fn rejects_schema_1_keys() {
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
            err.to_string().contains("not supported"),
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
            "build:\n  crypto:\n",
            "input:\n  path: ./mimikatz.exe\nbuild:\n  crypto:\n",
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
