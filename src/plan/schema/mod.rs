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
use crate::engine::polymorphism::{PolymorphismRecord, YamlPolymorphismPlan};
use crate::engine::signing::Signature;
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

    /// Reproduction record. Present in a build manifest (a manifest *is* a
    /// plan) and optionally in a hand-written plan; its presence is what makes
    /// `picaro build <document>` replay the recorded entropy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reproduce: Option<ReproducePlan>,
}

/// What a build recorded so it can be built again.
///
/// This lives in the manifest, which is nothing more than the resolved plan
/// with this block attached. A plan may also carry it by hand (for example
/// `reproduce: { seed: 42 }`), which is how the wizard writes a reproducible
/// recipe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReproducePlan {
    /// Version of the manifest document. Independent from [`SUPPORTED_SCHEMA`].
    #[serde(default = "default_manifest_schema")]
    pub manifest_schema: u32,

    /// Packer version that wrote the record.
    #[serde(default = "default_picaro")]
    pub picaro: String,

    /// Compiler that produced the artifact.
    #[serde(default)]
    pub toolchain: ToolchainRecord,

    /// Shorthand for `entropy.seed`, so a hand-written plan can say
    /// `reproduce: { seed: 42 }`. It takes precedence over the long form.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_seed"
    )]
    pub seed: Option<String>,

    /// The entropy inputs of the build.
    #[serde(default)]
    pub entropy: EntropyRecord,

    /// Whether payload keys are stored. `exact` (the default) stores them;
    /// `audit` strips them for a copy that leaves the lab.
    #[serde(default)]
    pub secrets: SecretsPolicy,

    /// Per-payload pins and cipher inputs, keyed by payload name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub payloads: BTreeMap<String, PayloadReproduction>,

    /// Resolved `VERSIONINFO`, recorded by value because that is what the
    /// artifact embeds (a seed would only add an indirection).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<VersionInfoPlan>,

    /// The build this record describes: its time, artifact path and hashes.
    ///
    /// On a replay this is also the value `--verify` compares against, because
    /// the *source* manifest carries the record of the artifact being
    /// reproduced; the manifest written for the new build records that build.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor: Option<Predecessor>,

    /// Authenticode signature applied to the artifact, when signing ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,

    /// Hash of the effective inputs (plan + entropy + payload pins).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_sha256: Option<String>,

    /// Deprecated alias of [`Self::effective_sha256`], emitted for one release.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_sha256: Option<String>,
}

/// The recorded compiler.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolchainRecord {
    /// `rustc --version` output.
    #[serde(default)]
    pub rustc: String,
    /// Target triple the stub was compiled for.
    #[serde(default)]
    pub target: String,
}

/// The recorded entropy inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntropyRecord {
    /// The master seed, as decimal or `0x` hex. `random` means unknown.
    #[serde(default = "default_seed_record", deserialize_with = "deserialize_seed")]
    pub seed: String,
    /// Resolved polymorphism profile (mode, seed and codegen).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub polymorphism: Option<PolymorphismRecord>,
    /// The string-obfuscation strategy; its key derives from the master seed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strings: Option<StringsRecord>,
    /// Seed of a generated icon (`output.resources.icon: random`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<u64>,
}

impl Default for EntropyRecord {
    fn default() -> Self {
        Self {
            seed: default_seed_record(),
            polymorphism: None,
            strings: None,
            icon: None,
        }
    }
}

/// The recorded string-obfuscation strategy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StringsRecord {
    /// `xor` or `stack`.
    #[serde(default = "default_strings_strategy")]
    pub strategy: String,
}

/// Per-payload reproduction inputs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadReproduction {
    /// SHA-256 of the input payload before encryption. A hard pin on replay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Size of the input payload, in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Public XChaCha20 nonce (24 bytes, hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Symmetric key (32 bytes, hex). Omitted under `secrets: audit`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

/// The build a replay started from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Predecessor {
    /// UTC build time (`YYYY-MM-DDTHH:MM:SSZ`).
    #[serde(default)]
    pub built_at: String,
    /// Path of the artifact the record describes.
    #[serde(default)]
    pub artifact: String,
    /// SHA-256 of the file that was written (after signing).
    #[serde(default)]
    pub artifact_sha256: String,
    /// SHA-256 of the artifact before signing: the reproducibility target.
    #[serde(default)]
    pub unsigned_sha256: String,
}

/// Whether the manifest stores payload keys.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecretsPolicy {
    /// Store keys and nonces: the same inputs produce the same bytes.
    #[default]
    Exact,
    /// Store hashes and public nonces only: the same code, fresh ciphertext.
    Audit,
}

fn default_manifest_schema() -> u32 {
    4
}

fn default_picaro() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

fn default_seed_record() -> String {
    "random".to_string()
}

fn default_strings_strategy() -> String {
    "xor".to_string()
}

/// A recorded seed, accepted as a string or as a bare integer.
///
/// The manifest writes `"0x…"` for readability, but a hand-written plan may
/// say `seed: 42`.
#[derive(Deserialize)]
#[serde(untagged)]
enum SeedValue {
    Text(String),
    Number(u64),
}

impl SeedValue {
    fn into_string(self) -> String {
        match self {
            SeedValue::Text(text) => text,
            SeedValue::Number(number) => number.to_string(),
        }
    }
}

fn deserialize_seed<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(SeedValue::deserialize(deserializer)?.into_string())
}

fn deserialize_optional_seed<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<SeedValue>::deserialize(deserializer)?.map(SeedValue::into_string))
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

    /// Build-time polymorphism: a seeded codegen profile (and, in later phases,
    /// source diversity and PE cosmetics) so two builds of one plan do not
    /// share a `.text`. Defaults to `full`; a debug build forces it off. See
    /// `docs/design/polymorphism.md`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub polymorphism: Option<YamlPolymorphismPlan>,

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

    /// The input's binary format (default: `auto`).
    ///
    /// `auto` is resolved before validation from the source: a PE image is
    /// `pe` (or `dll` when the file header or the `.dll` extension says so,
    /// `dotnet` when it carries a CLR header); a `.ps1`/`.psm1` is
    /// `powershell`; anything else is raw `shellcode`. `exe` is accepted as an
    /// alias for `pe`. The format decides how the packer validates the input
    /// and how the execution technique runs it.
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
    /// Detect from the source before validation (the default). A PE image is
    /// `pe`/`dll`/`dotnet`; anything else is `shellcode` (or `powershell` for a
    /// `.ps1`/`.psm1`).
    #[default]
    Auto,
    /// A PE executable image (PE32/PE32+). `format: exe` is accepted as an
    /// alias, which is the vocabulary the wizard uses.
    #[serde(alias = "exe")]
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
    /// A PowerShell script (`.ps1`/`.psm1`): **text**, embedded and encrypted
    /// like any payload. The packer compiles it into a managed launcher at build
    /// time and the stub hosts that (`technique: powershell_hosting`), so the
    /// script never touches disk.
    Powershell,
    /// Opaque bytes with no execution semantics: **data**, not a payload. It is
    /// embedded and encrypted like any other payload but is never mapped or run;
    /// the only consumer is a technique that writes it back out (the `bouncer`
    /// `on_reject.action: decoy` asset). No Execution technique accepts it, so
    /// `plan::validate` rejects a `plain` payload that a step tries to run.
    Plain,
}

impl PayloadFormat {
    /// Lowercase label used in build output and error messages.
    pub fn label(self) -> &'static str {
        match self {
            PayloadFormat::Auto => "auto",
            PayloadFormat::Pe => "pe",
            PayloadFormat::Shellcode => "shellcode",
            PayloadFormat::Dll => "dll",
            PayloadFormat::Dotnet => "dotnet",
            PayloadFormat::Powershell => "powershell",
            PayloadFormat::Plain => "plain",
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum KeySource {
    /// Random key generated on every build. The default.
    #[default]
    Random,
    /// A literal 32-byte key (`literal:<64 hex chars>`), for tests and pinned
    /// reproductions.
    Literal([u8; 32]),
    /// A file holding the key, raw (32 bytes) or hex (`file:<path>`). The path
    /// is resolved relative to the working directory.
    File(PathBuf),
}

impl std::str::FromStr for KeySource {
    type Err = String;

    /// Parses `random`, `literal:<hex>` or `file:<path>`.
    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let value = value.trim();
        if value.eq_ignore_ascii_case("random") {
            return Ok(KeySource::Random);
        }
        if let Some(hex) = value.strip_prefix("literal:") {
            let bytes = hex::decode(hex.trim())
                .map_err(|e| format!("invalid key 'literal:{hex}': not valid hexadecimal ({e})"))?;
            if bytes.len() != 32 {
                return Err(format!(
                    "invalid key 'literal:{hex}': expected exactly 32 bytes (64 hex chars), got {}",
                    bytes.len()
                ));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            if key.iter().all(|byte| *byte == 0) {
                return Err(
                    "invalid key 'literal:...': the key must not be all zero bytes".to_string(),
                );
            }
            return Ok(KeySource::Literal(key));
        }
        if let Some(path) = value.strip_prefix("file:") {
            let path = path.trim();
            if path.is_empty() {
                return Err("invalid key 'file:': a path is required".to_string());
            }
            return Ok(KeySource::File(PathBuf::from(path)));
        }
        Err(format!(
            "unknown key source '{value}'; expected 'random', 'literal:<hex>' or 'file:<path>'"
        ))
    }
}

impl From<KeySource> for String {
    fn from(source: KeySource) -> Self {
        match source {
            KeySource::Random => "random".to_string(),
            KeySource::Literal(key) => format!("literal:{}", hex::encode(key)),
            KeySource::File(path) => format!("file:{}", path.display()),
        }
    }
}

impl TryFrom<String> for KeySource {
    type Error = String;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        value.parse()
    }
}

/// `output` block: defines the final artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputPlan {
    /// Where the delivered artifact goes (`.exe`, `.dll` or `.bin`; see
    /// `kind`). Optional: when omitted, the artifact is delivered inside the
    /// build bundle at `<bundle>/dist/<plan>.<ext>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,

    /// What the artifact is: an executable (default), a DLL a host process
    /// loads, or position-independent shellcode (`docs/design/dll-output.md`,
    /// `docs/design/shellcode-output.md`).
    #[serde(default, skip_serializing_if = "OutputKind::is_exe")]
    pub kind: OutputKind,

    /// What starts the chain in a `kind: dll` / `kind: shellcode` build
    /// (`auto`, `jni_on_load` or `export:<name>`). Ignored — and rejected — for
    /// `kind: exe`.
    #[serde(default, skip_serializing_if = "DllEntry::is_auto")]
    pub entry: DllEntry,

    /// Console behavior for a `kind: dll` / `kind: shellcode` build.
    ///
    /// `parent` (default) attaches the host's console with
    /// `AttachConsole(ATTACH_PARENT_PROCESS)` so `println!`/`eprintln!` reach the
    /// host's terminal. `none` skips the attach and lets the chain write to
    /// stdout, leaving the host to decide where that goes (a host that redirects
    /// stdout to a pipe). Ignored for `kind: exe`.
    #[serde(default, skip_serializing_if = "ConsoleMode::is_parent")]
    pub console: ConsoleMode,

    /// Target architecture (default: `x64`).
    #[serde(default)]
    pub arch: Arch,

    /// Whether to strip the symbol table from the final binary (default: `true`).
    ///
    /// Stripping removes the symbol and debug tables `rustc` emits, so the
    /// artifact is smaller and carries no function names or debug type info. On
    /// MSVC it also suppresses the linker's debug directory, so the artifact
    /// stops naming the `.pdb` of the build.
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

/// How a host-loaded artifact handles the console (`build.output.console`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConsoleMode {
    /// Attach the host's console (`AttachConsole(ATTACH_PARENT_PROCESS)`), so
    /// the chain's output reaches its terminal. The default.
    #[default]
    Parent,
    /// Do not attach: the chain writes to stdout and the host decides where
    /// that goes (for example, a host that redirects stdout to a named pipe).
    None,
}

impl ConsoleMode {
    /// Whether this is the default mode (used to skip it when serializing).
    pub fn is_parent(&self) -> bool {
        matches!(self, ConsoleMode::Parent)
    }
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

/// What the build produces (`build.output.kind`).
///
/// `exe` (the default) is the standalone artifact. `dll` is a library a host
/// process loads with the normal image loader — a JVM through `System.load`, a
/// CPython interpreter through `ctypes`, a .NET host through `[DllImport]`, or
/// `rundll32` — which is what makes the chain usable where application
/// whitelisting only allows the host program. See `docs/design/dll-output.md`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputKind {
    /// A Windows executable.
    #[default]
    Exe,
    /// A Windows DLL, loaded by a host process.
    Dll,
    /// Position-independent shellcode: the packed DLL converted with sRDI, so a
    /// host that runs shellcode can start the chain without a PE on disk
    /// (`docs/design/shellcode-output.md`).
    Shellcode,
    /// A managed (.NET) PowerShell binary module: `Import-Module` loads it and
    /// its `OnImport` injects the embedded scripts into the caller's session.
    PsModule,
}

impl OutputKind {
    /// Whether this is the default kind (used to skip it when serializing).
    pub fn is_exe(&self) -> bool {
        matches!(self, OutputKind::Exe)
    }

    /// Lowercase label used in messages and the build log.
    pub fn label(self) -> &'static str {
        match self {
            OutputKind::Exe => "exe",
            OutputKind::Dll => "dll",
            OutputKind::Shellcode => "shellcode",
            OutputKind::PsModule => "psmodule",
        }
    }

    /// File extension of the artifact kind (`shellcode` is a raw `.bin`).
    pub fn extension(self) -> &'static str {
        match self {
            OutputKind::Exe => "exe",
            OutputKind::Dll => "dll",
            OutputKind::Shellcode => "bin",
            OutputKind::PsModule => "dll",
        }
    }
}

/// What starts the chain in a `kind: dll` build (`build.output.entry`).
///
/// The chain is identical in every mode; the entry only decides which export a
/// host calls and whether that export waits for the chain (see
/// `docs/design/dll-output.md`, section 4.3).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum DllEntry {
    /// Export every entry point — `JNI_OnLoad` and [`DllEntry::AUTO_EXPORT`] —
    /// so one artifact works from any host.
    #[default]
    Auto,
    /// Export only `JNI_OnLoad`, the JNI hook `System.load` calls. It returns
    /// to the JVM at once, so the host owns the process lifetime.
    JniOnLoad,
    /// Export only a plain function with this name (CPython `ctypes`, P/Invoke,
    /// `rundll32`). It blocks until the chain returns and reports its code.
    Export(String),
}

impl DllEntry {
    /// The export [`DllEntry::Auto`] adds besides `JNI_OnLoad`.
    pub const AUTO_EXPORT: &'static str = "Run";

    /// Whether this is the default entry (used to skip it when serializing).
    pub fn is_auto(&self) -> bool {
        matches!(self, DllEntry::Auto)
    }

    /// The plain export name the build declares, if any.
    pub fn export_name(&self) -> Option<&str> {
        match self {
            DllEntry::Auto => Some(Self::AUTO_EXPORT),
            DllEntry::Export(name) => Some(name),
            DllEntry::JniOnLoad => None,
        }
    }

    /// Whether the build exports `JNI_OnLoad`.
    pub fn exports_jni_on_load(&self) -> bool {
        matches!(self, DllEntry::Auto | DllEntry::JniOnLoad)
    }

    /// Label used in messages and the build log.
    pub fn label(&self) -> String {
        match self {
            DllEntry::Auto => "auto".to_string(),
            DllEntry::JniOnLoad => "jni_on_load".to_string(),
            DllEntry::Export(name) => format!("export:{name}"),
        }
    }
}

impl std::str::FromStr for DllEntry {
    type Err = String;

    /// Parses `auto`, `jni_on_load` or `export:<name>`.
    ///
    /// The *syntax* of `<name>` is checked by `plan::validate` (so a bad name is
    /// a normal validation error); here only the shape is recognized.
    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value.trim() {
            "auto" => Ok(DllEntry::Auto),
            "jni_on_load" => Ok(DllEntry::JniOnLoad),
            other => match other.strip_prefix("export:") {
                Some(name) => Ok(DllEntry::Export(name.trim().to_string())),
                None => Err(format!(
                    "unknown entry '{other}'; expected 'auto', 'jni_on_load' or 'export:<name>'"
                )),
            },
        }
    }
}

impl From<DllEntry> for String {
    fn from(entry: DllEntry) -> Self {
        match entry {
            DllEntry::Auto => "auto".to_string(),
            DllEntry::JniOnLoad => "jni_on_load".to_string(),
            DllEntry::Export(name) => format!("export:{name}"),
        }
    }
}

impl TryFrom<String> for DllEntry {
    type Error = String;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        value.parse()
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

/// `output.resources.icon`: an existing `.ico` file or a procedurally generated
/// icon.
///
/// In YAML it is a single string: `random` (case-insensitive) generates an icon
/// at build time, anything else is a path to a `.ico` file. A generated icon's
/// seed is chosen by the build and written to the manifest, so the icon can be
/// reproduced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum IconPlan {
    /// `icon: random` — a procedurally generated icon. `seed` is `None` in the
    /// plan as written; the build resolves it to a concrete value so the icon
    /// and the manifest agree.
    Random {
        /// The seed the icon was (or will be) rendered from.
        seed: Option<u64>,
    },
    /// `icon: <path>` — embed an existing `.ico` file.
    Path(PathBuf),
}

impl IconPlan {
    /// The seed of a generated icon, once the build has resolved it.
    pub fn seed(&self) -> Option<u64> {
        match self {
            IconPlan::Random { seed } => *seed,
            IconPlan::Path(_) => None,
        }
    }

    /// Returns this icon with a concrete seed, if it is a generated one that has
    /// none yet. A path or an already-seeded icon is returned unchanged.
    pub fn with_seed(self, seed: u64) -> Self {
        match self {
            IconPlan::Random { seed: None } => IconPlan::Random { seed: Some(seed) },
            other => other,
        }
    }
}

impl std::str::FromStr for IconPlan {
    type Err = String;

    /// Parses `random` or a `.ico` path.
    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        if value.trim().eq_ignore_ascii_case("random") {
            Ok(IconPlan::Random { seed: None })
        } else if value.trim().is_empty() {
            Err("empty icon value; expected 'random' or a path to a .ico file".to_string())
        } else {
            Ok(IconPlan::Path(PathBuf::from(value)))
        }
    }
}

impl From<IconPlan> for String {
    fn from(icon: IconPlan) -> Self {
        match icon {
            // The seed is deliberately not serialized: it is recorded separately
            // (in the manifest) so the resolved plan stays stable.
            IconPlan::Random { .. } => "random".to_string(),
            IconPlan::Path(path) => path.to_string_lossy().into_owned(),
        }
    }
}

impl TryFrom<String> for IconPlan {
    type Error = String;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        value.parse()
    }
}

/// `output.resources`: the PE resources to embed into the artifact.
///
/// All fields are optional; each one that is set adds the matching resource
/// type. The resources are built programmatically (no `rc.exe`/`windres`), so
/// the build stays pure Rust and cross-platform.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourcesPlan {
    /// Icon to embed as `RT_GROUP_ICON` + `RT_ICON`: `random` (generated) or a
    /// path to a `.ico` file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<IconPlan>,

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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionLevel {
    /// Run with the caller's privileges (default).
    #[default]
    AsInvoker,
    /// Elevate when the user is an administrator, without prompting.
    HighestAvailable,
    /// Always prompt for elevation.
    RequireAdministrator,
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
mod tests;
