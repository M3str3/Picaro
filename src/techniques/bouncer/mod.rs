//! Bouncer: host environment gate.
//!
//! Checks the current host against a list of *declared* requirements (hostname,
//! user, domain, locale, keyboard layout, processes, local IPs, token privileges,
//! uptime/RAM and the VM/sandbox heuristics) and aborts the pipeline before the
//! payload runs when they are not met. A Preparation technique: it never runs the
//! payload. See `README.md` for the full write-up.

use std::fmt;
use std::net::IpAddr;

use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::engine::obfuscation::StringsConfig;

use super::{Capability, Category, Stability, TechniqueDef};

/// One requirement the gate evaluates.
///
/// Every entry is a single vote: `params.require` is an AND list and
/// `params.any_of` an OR list, so the combinator no longer depends on the sign
/// of the predicate. The YAML reads as `- hostname: "WS-*"`,
/// `- process: { name: x, state: present }`, …
///
/// `Deserialize` and `Serialize` are implemented by hand instead of derived:
/// `serde_yml` renders a derived externally-tagged enum as a YAML tag
/// (`!hostname value`), and the step carries the technique through
/// `#[serde(flatten)]`, whose private `Content` buffer refuses to replay an
/// enum into an internally-tagged enum. Both sides therefore use the map form
/// (`hostname: value`), which is what a hand-written plan contains anyway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Requirement {
    /// Computer name, matched with a case-insensitive glob.
    Hostname(String),
    /// User name, matched with a case-insensitive glob.
    Username(String),
    /// DNS domain (empty when the host is not domain-joined, so the check then
    /// fails). Matched with a case-insensitive glob.
    Domain(String),
    /// Accepted BCP-47 locales (any match passes).
    Locale(Vec<String>),
    /// Accepted 4-digit keyboard layout ids (any match passes).
    Keyboard(Vec<String>),
    /// One process that must be running (`present`) or absent (`absent`).
    Process(ProcessCheck),
    /// Local unicast addresses, matched against IPv4/IPv6 CIDRs.
    Ip(Vec<String>),
    /// Token elevation.
    Elevation(Elevation),
    /// Accepted token integrity levels.
    Integrity(Vec<IntegrityLevel>),
    /// A privilege that must be enabled in the current token (e.g.
    /// `SeDebugPrivilege`).
    Privilege(String),
    /// Minimum system uptime, in minutes.
    UptimeMin(u32),
    /// Minimum physical memory, in MiB.
    RamMb(u32),
    /// Negates the wrapped requirement.
    Not(Box<Requirement>),
}

/// The keys a [`Requirement`] map may carry.
const REQUIREMENT_FIELDS: &[&str] = &[
    "hostname",
    "username",
    "domain",
    "locale",
    "keyboard",
    "process",
    "ip",
    "elevation",
    "integrity",
    "privilege",
    "uptime_min",
    "ram_mb",
    "not",
];

impl<'de> Deserialize<'de> for Requirement {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RequirementVisitor;

        impl<'de> Visitor<'de> for RequirementVisitor {
            type Value = Requirement;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a single-key requirement map, e.g. `hostname: \"WS-*\"`")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let key: String = match map.next_key()? {
                    Some(key) => key,
                    None => {
                        return Err(de::Error::custom("a requirement must have exactly one key"))
                    }
                };
                let requirement = match key.as_str() {
                    "hostname" => Requirement::Hostname(map.next_value()?),
                    "username" => Requirement::Username(map.next_value()?),
                    "domain" => Requirement::Domain(map.next_value()?),
                    "locale" => Requirement::Locale(map.next_value()?),
                    "keyboard" => Requirement::Keyboard(map.next_value()?),
                    "process" => Requirement::Process(map.next_value()?),
                    "ip" => Requirement::Ip(map.next_value()?),
                    "elevation" => Requirement::Elevation(map.next_value()?),
                    "integrity" => Requirement::Integrity(map.next_value()?),
                    "privilege" => Requirement::Privilege(map.next_value()?),
                    "uptime_min" => Requirement::UptimeMin(map.next_value()?),
                    "ram_mb" => Requirement::RamMb(map.next_value()?),
                    "not" => Requirement::Not(Box::new(map.next_value::<Requirement>()?)),
                    _ => return Err(de::Error::unknown_field(&key, REQUIREMENT_FIELDS)),
                };
                if map.next_key::<String>()?.is_some() {
                    return Err(de::Error::custom("a requirement must have exactly one key"));
                }
                Ok(requirement)
            }
        }

        deserializer.deserialize_map(RequirementVisitor)
    }
}

impl Serialize for Requirement {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(1))?;
        match self {
            Requirement::Hostname(value) => map.serialize_entry("hostname", value)?,
            Requirement::Username(value) => map.serialize_entry("username", value)?,
            Requirement::Domain(value) => map.serialize_entry("domain", value)?,
            Requirement::Locale(values) => map.serialize_entry("locale", values)?,
            Requirement::Keyboard(values) => map.serialize_entry("keyboard", values)?,
            Requirement::Process(check) => map.serialize_entry("process", check)?,
            Requirement::Ip(cidrs) => map.serialize_entry("ip", cidrs)?,
            Requirement::Elevation(elevation) => map.serialize_entry("elevation", elevation)?,
            Requirement::Integrity(levels) => map.serialize_entry("integrity", levels)?,
            Requirement::Privilege(name) => map.serialize_entry("privilege", name)?,
            Requirement::UptimeMin(minutes) => map.serialize_entry("uptime_min", minutes)?,
            Requirement::RamMb(megabytes) => map.serialize_entry("ram_mb", megabytes)?,
            Requirement::Not(inner) => map.serialize_entry("not", inner.as_ref())?,
        }
        map.end()
    }
}

/// Whether the process requirement expects the process to be running or absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessState {
    /// The process must be running for the check to pass.
    Present,
    /// The process must not be running for the check to pass.
    Absent,
}

/// One process-existence requirement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessCheck {
    /// Executable name to look for. `*`/`?` make it a case-insensitive glob,
    /// matched against the running process's file name and its `.exe`-stripped
    /// stem (so `corp-agent`, `corp-agent.exe` and `corp-*` all work).
    pub name: String,
    /// Whether the process must be present or absent for the check to pass.
    pub state: ProcessState,
}

/// Whether the current token is elevated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Elevation {
    /// The token is elevated (UAC high or SYSTEM).
    Elevated,
    /// The token is not elevated.
    Unelevated,
}

/// Windows token integrity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityLevel {
    /// Low integrity (sandboxed processes, protected-mode browsers).
    Low,
    /// Medium integrity (a normal unelevated user).
    Medium,
    /// High integrity (an elevated administrator).
    High,
    /// SYSTEM integrity.
    System,
}

impl IntegrityLevel {
    /// The integrity RID the token SID reports.
    pub fn rid(self) -> u32 {
        match self {
            IntegrityLevel::Low => 0x1000,
            IntegrityLevel::Medium => 0x2000,
            IntegrityLevel::High => 0x3000,
            IntegrityLevel::System => 0x4000,
        }
    }
}

/// VM/sandbox heuristics. Both are opt-in and veto the host on their own, so
/// they cannot be bypassed by a passing `any_of` entry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AntiAnalysis {
    /// Require that CPUID reports no hypervisor.
    #[serde(default)]
    pub hypervisor: bool,
    /// Require that the aggregate sandbox heuristic stays below its threshold.
    #[serde(default)]
    pub sandbox: bool,
}

/// What the stub does when the gate rejects the host.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectAction {
    /// Return `Ok(false)` and let the runner exit silently (code 0, default).
    #[default]
    Abort,
    /// Exit the process with `exit_code` (default 1).
    Exit,
    /// Write the decoy asset, then exit with `exit_code` (default 0).
    Decoy,
}

/// Rejection policy, grouped so it never collides with the step's own
/// `runtime[].on_fail` (the loader's error policy).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnReject {
    /// What to do on rejection.
    #[serde(default)]
    pub action: RejectAction,
    /// Exit code for `exit` (default 1) and `decoy` (default 0). Ignored by
    /// `abort`, which must leave it unset or `0`. The range is `0..=255`, the
    /// values `std::process::exit` can represent portably.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<u32>,
    /// The decoy written by `action: decoy`. Required for that action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoy: Option<DecoyParams>,
}

impl OnReject {
    /// Whether a rejected host writes the configured decoy.
    pub fn is_decoy(&self) -> bool {
        self.action == RejectAction::Decoy
    }

    /// Whether the rejection path calls `std::process::exit` (and therefore
    /// cannot be used by a host-loaded DLL).
    pub fn exits_process(&self) -> bool {
        match self.action {
            RejectAction::Exit => true,
            RejectAction::Decoy => self.exit_code.unwrap_or(0) != 0,
            RejectAction::Abort => false,
        }
    }

    /// The code `std::process::exit` receives, when the action exits.
    pub fn effective_exit_code(&self) -> u32 {
        match self.action {
            RejectAction::Exit => self.exit_code.unwrap_or(1),
            RejectAction::Decoy | RejectAction::Abort => self.exit_code.unwrap_or(0),
        }
    }
}

/// The decoy asset written on rejection (`action: decoy`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecoyParams {
    /// Destination path. `%NAME%` is expanded from the environment at run time
    /// (e.g. `%TEMP%\\report.docx`); the whole template is rebuilt through
    /// `StringsConfig`, so it never lands in cleartext in the stub.
    pub path: String,
    /// Name of a `build.payloads` entry with `format: plain`. Required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
}

/// Parameters for the bouncer gate.
///
/// The struct is checks plus one rejection policy; the loader's own
/// `runtime[].on_fail`/`on_success` live in [`super::super::plan::schema::StepControl`]
/// and are a different concern.
///
/// With no requirement and no `anti_analysis` flag the technique is a no-op (it
/// always lets the payload run); `plan::validate::advisories` warns about that.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Params {
    /// Requirements that must **all** pass.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub require: Vec<Requirement>,

    /// Requirements of which **at least one** must pass.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub any_of: Vec<Requirement>,

    /// Opt-in VM/sandbox heuristics (a hard veto).
    #[serde(default, skip_serializing_if = "AntiAnalysis::is_default")]
    pub anti_analysis: AntiAnalysis,

    /// What to do when the gate rejects the host.
    #[serde(default, skip_serializing_if = "OnReject::is_default")]
    pub on_reject: OnReject,
}

impl AntiAnalysis {
    /// Whether neither heuristic is enabled.
    pub fn is_default(&self) -> bool {
        !self.hypervisor && !self.sandbox
    }
}

impl OnReject {
    /// Whether this is the default (`abort`, no code, no decoy).
    pub fn is_default(&self) -> bool {
        *self == OnReject::default()
    }
}

/// Sandbox/analysis process names the `anti_analysis.sandbox` heuristic looks
/// for.
///
/// The list is deliberately small and well known (guest additions, packet
/// capture, Sysinternals process monitoring, the two mainstream user-mode
/// debuggers). Every entry is obfuscated at render time and never reaches
/// `.rdata` in cleartext.
pub const ANALYSIS_PROCESSES: &[&str] = &[
    "vboxservice.exe",
    "vmwaretray.exe",
    "vmtoolsd.exe",
    "wireshark.exe",
    "procmon.exe",
    "procmon64.exe",
    "x64dbg.exe",
    "x32dbg.exe",
];

/// Path/user-name fragments that point at an analysis environment.
pub const ANALYSIS_PATH_TOKENS: &[&str] = &["sandbox", "malware", "test", "analysis"];

/// Substrings of the CPUID leaf `0x40000000` hypervisor vendor that identify a
/// known hypervisor. Matching is a case-insensitive `contains` over the 12-byte
/// vendor string.
///
/// Sources for the vendor strings: VMware `VMwareVMware`, VirtualBox
/// `VBoxVBoxVBox`, Hyper-V `Microsoft Hv`, KVM `KVMKVMKVM`, Xen
/// `XenVMMXenVMM`, QEMU/TCG `TCGTCGTCGTCG`.
pub const HYPERVISOR_VENDOR_TOKENS: &[&str] =
    &["vmware", "vbox", "microsoft hv", "kvm", "xen", "tcg"];

/// Static metadata for the bouncer gate.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "bouncer",
    attck: &["T1497.001", "T1614.001", "T1033", "T1016"],
    stability: Stability::Stable,
    requires: &[Capability::WindowsX64, Capability::WindowsX86],
    conflicts: &[],
    category: Category::Preparation,
    doc_path: "src/techniques/bouncer/README.md",
    readme: include_str!("README.md"),
    stub_fragment: include_str!("stub_fragment.rs"),
    formats: &[],
    requires_indirect_syscalls: false,
    params_example: r#"technique: bouncer
params:
  require:
    - hostname: "WORKSTATION-*"
    - username: "admin"
    - not: { username: "analyst*" }
    - domain: "CORP"
    - ip: ["10.0.0.0/8", "fd00::/8"]
    - elevation: elevated
    - integrity: [high, system]
    - privilege: SeDebugPrivilege
    - process: { name: "corp-agent.exe", state: present }
    - uptime_min: 10
    - ram_mb: 4096
  any_of:
    - locale: ["en-US", "es-ES"]
    - keyboard: ["0409", "0C0A"]
  anti_analysis:
    hypervisor: true
    sandbox: true
  on_reject:
    action: decoy
    decoy:
      path: "%TEMP%\\report.docx"
      payload: decoy_doc
"#,
    // All checks use Win32 APIs directly; routing them through the syscall
    // layer is a later phase.
    syscalls: &[],
    resolves_imports: false,
};

/// Runtime diagnostics the fragment can emit, as `(placeholder, plaintext)`
/// pairs.
///
/// `render_fragment` replaces each placeholder with code that rebuilds the
/// message at runtime, so no diagnostic text lands in the generated stub's
/// `.rdata`. Each message is passed through the fragment's `win32_error` helper,
/// which appends the failing Win32 error code at the call site; the helper keeps
/// a keyword-free `format!` literal (`format!` cannot take a runtime format
/// string).
const MESSAGES: &[(&str, &str)] = &[
    (
        "$MSG_COMPUTER_NAME_FAILED$",
        "could not read the computer name",
    ),
    ("$MSG_USER_NAME_FAILED$", "could not read the user name"),
    ("$MSG_DOMAIN_FAILED$", "could not read the DNS domain"),
    ("$MSG_LOCALE_FAILED$", "could not read the user locale"),
    (
        "$MSG_KEYBOARD_FAILED$",
        "could not read the active keyboard layouts",
    ),
    (
        "$MSG_PROCESS_ENUM_FAILED$",
        "could not enumerate the running processes",
    ),
    (
        "$MSG_MEMORY_QUERY_FAILED$",
        "could not query the physical memory",
    ),
    (
        "$MSG_IP_ENUM_FAILED$",
        "could not enumerate the local addresses",
    ),
    ("$MSG_TOKEN_FAILED$", "could not read the process token"),
    (
        "$MSG_PRIVILEGE_FAILED$",
        "could not check the token privilege",
    ),
    ("$MSG_DECOY_WRITE_FAILED$", "could not write the decoy file"),
];

impl Params {
    /// Whether the gate declares no check at all, so it can never reject a
    /// host. Surfaced as a build advisory by `plan::validate::advisories`.
    pub fn is_noop(&self) -> bool {
        self.require.is_empty() && self.any_of.is_empty() && self.anti_analysis.is_default()
    }

    /// Whether a rejected host writes the configured decoy.
    pub fn is_decoy(&self) -> bool {
        self.on_reject.is_decoy()
    }

    /// The decoy configuration, when one is declared.
    pub fn decoy(&self) -> Option<&DecoyParams> {
        self.on_reject.decoy.as_ref()
    }

    /// Checks the constraints `serde` cannot express.
    ///
    /// Called by `plan::validate` on every bouncer step; the returned message is
    /// prefixed with the offending list (`require` or `any_of`).
    pub fn validate(&self) -> std::result::Result<(), String> {
        for (side, requirements) in [("require", &self.require), ("any_of", &self.any_of)] {
            for (index, requirement) in requirements.iter().enumerate() {
                requirement
                    .validate()
                    .map_err(|message| format!("`params.{side}[{index}]`: {message}"))?;
            }
        }
        self.validate_rejection()
    }

    /// Validates the `on_reject` block against itself.
    fn validate_rejection(&self) -> std::result::Result<(), String> {
        let reject = &self.on_reject;
        if reject.exit_code.is_some_and(|code| code > 255) {
            return Err(
                "`params.on_reject.exit_code` must be between 0 and 255: the stub passes it to \
                 `std::process::exit`"
                    .to_string(),
            );
        }
        match reject.action {
            RejectAction::Abort => {
                if reject.exit_code.unwrap_or(0) != 0 {
                    return Err(
                        "`params.on_reject.exit_code` is only meaningful with `action: exit` \
                         or `action: decoy`"
                            .to_string(),
                    );
                }
                if reject.decoy.is_some() {
                    return Err(
                        "`params.on_reject.decoy` is set but `action` is `abort`; use \
                         `action: decoy` or remove the decoy"
                            .to_string(),
                    );
                }
            }
            RejectAction::Exit => {
                if reject.decoy.is_some() {
                    return Err(
                        "`params.on_reject.decoy` is set but `action` is `exit`; use \
                         `action: decoy` or remove the decoy"
                            .to_string(),
                    );
                }
            }
            RejectAction::Decoy => {
                let decoy = reject.decoy.as_ref().ok_or_else(|| {
                    "`params.on_reject.action: decoy` requires `params.on_reject.decoy`".to_string()
                })?;
                if decoy.path.trim().is_empty() {
                    return Err("`params.on_reject.decoy.path` must not be empty".to_string());
                }
            }
        }
        Ok(())
    }

    /// Renders the bouncer stub fragment for these parameters.
    ///
    /// Every per-build literal (the check patterns, the locale/keyboard lists,
    /// the privilege names and the built-in analysis-environment names) is
    /// emitted as code that rebuilds it at runtime through `strings`, so none of
    /// them lands in cleartext in the generated stub.
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        let mut fragment = DEF.stub_fragment.to_string();

        let substitutions = [
            (
                "$REQUIRE_BLOCKS$",
                render_blocks(&self.require, strings, "require"),
            ),
            (
                "$ANY_OF_BLOCKS$",
                render_blocks(&self.any_of, strings, "any"),
            ),
            (
                "$REQUIRE_HYPERVISOR$",
                self.anti_analysis.hypervisor.to_string(),
            ),
            ("$REQUIRE_SANDBOX$", self.anti_analysis.sandbox.to_string()),
            (
                "$VENDOR_TOKENS$",
                str_list_def(HYPERVISOR_VENDOR_TOKENS, strings, "vendor_token"),
            ),
            (
                "$ANALYSIS_PROCESSES$",
                str_list_def(ANALYSIS_PROCESSES, strings, "env_process"),
            ),
            (
                "$ANALYSIS_PATH_TOKENS$",
                // The variable-name prefix must not spell a sensitive token: the
                // `stack` strategy emits it as an identifier in the stub source.
                str_list_def(ANALYSIS_PATH_TOKENS, strings, "env_token"),
            ),
            (
                "$DECOY_PATH$",
                opt_string_def(
                    self.decoy().map(|decoy| decoy.path.as_str()),
                    strings,
                    "decoy_path",
                ),
            ),
            ("$ON_REJECT_DECOY$", self.is_decoy().to_string()),
            (
                "$ON_REJECT_EXIT$",
                self.on_reject.exits_process().to_string(),
            ),
            (
                "$EXIT_CODE$",
                self.on_reject.effective_exit_code().to_string(),
            ),
        ];

        for (placeholder, value) in substitutions {
            fragment = fragment.replace(placeholder, &value);
        }
        for (index, (placeholder, text)) in MESSAGES.iter().enumerate() {
            fragment = fragment.replace(
                placeholder,
                &strings
                    .obfuscate(text)
                    .render_stub_expr(&format!("bouncer_msg_{index}")),
            );
        }
        fragment
    }
}

impl Requirement {
    /// Rejects the shapes `serde` accepts but the stub cannot evaluate.
    fn validate(&self) -> std::result::Result<(), String> {
        match self {
            Requirement::Hostname(pattern)
            | Requirement::Username(pattern)
            | Requirement::Domain(pattern) => {
                if pattern.trim().is_empty() {
                    Err("the pattern must not be empty".to_string())
                } else {
                    Ok(())
                }
            }
            Requirement::Locale(values) => {
                if values.is_empty() {
                    return Err("the list must not be empty".to_string());
                }
                if values.iter().any(|value| value.trim().is_empty()) {
                    return Err("the list must not contain empty entries".to_string());
                }
                Ok(())
            }
            Requirement::Keyboard(values) => {
                if values.is_empty() {
                    return Err("the list must not be empty".to_string());
                }
                if values.iter().any(|value| value.trim().is_empty()) {
                    return Err("the list must not contain empty entries".to_string());
                }
                for value in values {
                    if !is_keyboard_klid(value) {
                        return Err(format!(
                            "'{value}' is not a keyboard layout id: expected four hex digits, optionally prefixed with 0x"
                        ));
                    }
                }
                Ok(())
            }
            Requirement::Process(check) => {
                if check.name.trim().is_empty() {
                    Err("`process.name` must not be empty".to_string())
                } else {
                    Ok(())
                }
            }
            Requirement::Ip(cidrs) => {
                if cidrs.is_empty() {
                    return Err("the CIDR list must not be empty".to_string());
                }
                for cidr in cidrs {
                    if parse_cidr(cidr).is_none() {
                        return Err(format!(
                            "'{cidr}' is not a valid IPv4/IPv6 address or CIDR block"
                        ));
                    }
                }
                Ok(())
            }
            Requirement::Integrity(levels) => {
                if levels.is_empty() {
                    Err("the integrity-level list must not be empty".to_string())
                } else {
                    Ok(())
                }
            }
            Requirement::Privilege(name) => {
                if name.trim().is_empty() {
                    Err("the privilege name must not be empty".to_string())
                } else {
                    Ok(())
                }
            }
            Requirement::Elevation(_) | Requirement::UptimeMin(_) | Requirement::RamMb(_) => Ok(()),
            Requirement::Not(inner) => {
                if matches!(**inner, Requirement::Not(_)) {
                    return Err("`not` cannot wrap another `not`".to_string());
                }
                inner.validate()
            }
        }
    }

    /// Renders the requirement as a Rust expression that evaluates to `bool`
    /// (or propagates a Win32 read error with `?`).
    fn render_expression(&self, strings: &StringsConfig, side: &str, index: usize) -> String {
        let variable = format!("{side}_{index}");
        match self {
            Requirement::Hostname(pattern) => format!(
                "glob_match(&{}, &computer_name()?)",
                obf(pattern, strings, &format!("{variable}_pattern"))
            ),
            Requirement::Username(pattern) => format!(
                "glob_match(&{}, &user_name()?)",
                obf(pattern, strings, &format!("{variable}_pattern"))
            ),
            Requirement::Domain(pattern) => format!(
                "glob_match(&{}, &dns_domain()?)",
                obf(pattern, strings, &format!("{variable}_pattern"))
            ),
            Requirement::Locale(values) => format!(
                "{{ let locale = locale_name()?; let accepted = {}; \
                 accepted.iter().any(|value| value.eq_ignore_ascii_case(&locale)) }}",
                string_vec(values, strings, side, index)
            ),
            Requirement::Keyboard(values) => format!(
                "{{ let active = keyboard_layouts()?; let accepted = {}; \
                 active.iter().any(|layout| accepted.iter().any(|value| \
                 normalize_klid(value) == layout.as_str())) }}",
                string_vec(values, strings, side, index)
            ),
            Requirement::Process(check) => format!(
                "{{ let running = running_processes()?; let pattern = {}; \
                 let present = running.iter().any(|entry| {{ \
                     let stem = match entry.strip_suffix(\".exe\") {{ \
                         Some(stem) => stem, None => entry.as_str() \
                     }}; \
                     glob_match(&pattern, entry) || glob_match(&pattern, stem) \
                 }}); present == {} }}",
                obf(&check.name, strings, &format!("{variable}_pattern")),
                check.state == ProcessState::Present
            ),
            Requirement::Ip(cidrs) => render_ip(cidrs),
            Requirement::Elevation(elevation) => format!(
                "token_is_elevated()? == {}",
                *elevation == Elevation::Elevated
            ),
            Requirement::Integrity(levels) => {
                let values: Vec<String> = levels
                    .iter()
                    .map(|level| format!("{}u32", level.rid()))
                    .collect();
                format!(
                    "{{ let level = token_integrity()?; [{}].contains(&level) }}",
                    values.join(", ")
                )
            }
            Requirement::Privilege(name) => format!(
                "privilege_enabled(&{})?",
                obf(name, strings, &format!("{variable}_name"))
            ),
            Requirement::UptimeMin(minutes) => format!("uptime_minutes() >= {minutes}u64"),
            Requirement::RamMb(megabytes) => format!("total_ram_mb()? >= {megabytes}u64"),
            Requirement::Not(inner) => {
                format!("!({})", inner.render_expression(strings, side, index))
            }
        }
    }
}

/// Whether `value` is a keyboard layout id the stub can match: an optional
/// `0x`/`0X` prefix followed by exactly four ASCII hex digits.
///
/// `normalize_klid` in the stub keeps the last four characters of the KLID
/// string, so a value that is not four hex digits can never match and would
/// silently disable the check.
fn is_keyboard_klid(value: &str) -> bool {
    let text = value.trim().to_ascii_uppercase();
    let text = text.strip_prefix("0X").unwrap_or(text.as_str());
    text.len() == 4 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Renders one list of requirements as counter updates.
fn render_blocks(requirements: &[Requirement], strings: &StringsConfig, side: &str) -> String {
    let mut blocks = String::new();
    for (index, requirement) in requirements.iter().enumerate() {
        let expression = requirement.render_expression(strings, side, index);
        blocks.push_str(&format!(
            "    {side}_declared += 1;\n    if {expression} {{\n        {side}_passed += 1;\n    }}\n"
        ));
    }
    blocks
}

/// Renders an IP requirement as a CIDR match over the local unicast addresses.
fn render_ip(cidrs: &[String]) -> String {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for value in cidrs {
        let Some(cidr) = parse_cidr(value) else {
            continue;
        };
        match cidr.address {
            IpAddr::V4(address) => {
                let network = u32::from(address) & mask_v4(cidr.prefix);
                v4.push(format!("({}u8, {}u32)", cidr.prefix, network));
            }
            IpAddr::V6(address) => {
                let network = u128::from(address) & mask_v6(cidr.prefix);
                v6.push(format!("({}u8, {}u128)", cidr.prefix, network));
            }
        }
    }
    format!(
        "{{ let (v4, v6) = local_addresses()?; \
         let networks4: &[(u8, u32)] = &[{}]; \
         let networks6: &[(u8, u128)] = &[{}]; \
         networks4.iter().any(|&(prefix, network)| \
             v4.iter().any(|&address| address & mask_v4(prefix) == network)) \
         || networks6.iter().any(|&(prefix, network)| \
             v6.iter().any(|&address| address & mask_v6(prefix) == network)) }}",
        v4.join(", "),
        v6.join(", ")
    )
}

/// A validated CIDR block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    /// Prefix length (0–32 for IPv4, 0–128 for IPv6).
    pub prefix: u8,
    /// The address as written; callers mask it against [`Cidr::prefix`].
    pub address: IpAddr,
}

/// Parses `a.b.c.d/n` or `ipv6/n`; a bare address means a host route (`/32`,
/// `/128`).
pub fn parse_cidr(value: &str) -> Option<Cidr> {
    let value = value.trim();
    let (address, prefix) = match value.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (value, None),
    };
    let address: IpAddr = address.trim().parse().ok()?;
    let maximum = if address.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        Some(prefix) => prefix.trim().parse::<u8>().ok()?,
        None => maximum,
    };
    if prefix > maximum {
        return None;
    }
    Some(Cidr { prefix, address })
}

/// IPv4 network mask for `prefix`; `/0` is the all-zero mask.
pub fn mask_v4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

/// IPv6 network mask for `prefix`; `/0` is the all-zero mask.
pub fn mask_v6(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

/// Case-insensitive glob match supporting `*` (any run) and `?` (one char).
///
/// This is the reference implementation for `hostname`/`username`/`domain`; the
/// stub carries a self-contained copy (`fn glob_match` in `stub_fragment.rs`)
/// because a fragment cannot call back into the packer. A pattern without
/// wildcards degenerates to an exact case-insensitive comparison.
#[cfg(test)]
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.to_lowercase().chars().collect();
    let text: Vec<char> = text.to_lowercase().chars().collect();

    let mut p = 0usize;
    let mut t = 0usize;
    let mut star: Option<usize> = None;
    let mut resume = 0usize;

    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            resume = t;
            p += 1;
        } else if let Some(star_pos) = star {
            p = star_pos + 1;
            resume += 1;
            t = resume;
        } else {
            return false;
        }
    }

    // Trailing wildcards match the empty remainder.
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

/// Renders a string as code that rebuilds it at run time.
fn obf(value: &str, strings: &StringsConfig, name: &str) -> String {
    strings.obfuscate(value).render_stub_expr(name)
}

/// Renders an `Option<String>` placeholder as `Some(<runtime string>)` or `None`.
fn opt_string_def(value: Option<&str>, strings: &StringsConfig, name: &str) -> String {
    match value {
        Some(value) => format!("Some({})", obf(value, strings, name)),
        None => "None".to_string(),
    }
}

/// Renders a `Vec<String>` placeholder from a list of runtime values.
fn string_vec(values: &[String], strings: &StringsConfig, side: &str, index: usize) -> String {
    let items: Vec<String> = values
        .iter()
        .enumerate()
        .map(|(position, value)| obf(value, strings, &format!("{side}_{index}_value_{position}")))
        .collect();
    format!("vec![{}]", items.join(", "))
}

/// Renders a `Vec<String>` placeholder from a static `&[&str]`.
fn str_list_def(values: &[&str], strings: &StringsConfig, prefix: &str) -> String {
    let items: Vec<String> = values
        .iter()
        .enumerate()
        .map(|(i, value)| obf(value, strings, &format!("{prefix}_{i}")))
        .collect();
    format!("vec![{}]", items.join(", "))
}

#[cfg(test)]
mod tests;
