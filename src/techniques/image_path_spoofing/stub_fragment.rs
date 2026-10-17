// --- Image path spoofing (technique fragment) ---
//
// Repoints `PEB->ProcessParameters->ImagePathName` at a decoy path so a PEB
// parser reads the decoy. No byte of the artifact is touched and no syscall is
// involved. Measured on Windows 11 26200: `GetModuleFileNameW(NULL)` resolves
// the main module through the loader list, so it is *not* fooled by this field
// (see `docs/measurements.md`).

/// `PEB->ProcessParameters` offset: `0x10` on x86, `0x20` on x64.
const PROCESS_PARAMETERS_OFFSET: usize = if cfg!(target_arch = "x86") { 0x10 } else { 0x20 };

/// `RTL_USER_PROCESS_PARAMETERS->ImagePathName` offset: `0x38` on x86, `0x60` on
/// x64 (the `UNICODE_STRING` right before `CommandLine`, at `0x40`/`0x70`; an
/// x86 `UNICODE_STRING` is 8 bytes, an x64 one 16).
const IMAGE_PATH_OFFSET: usize = if cfg!(target_arch = "x86") { 0x38 } else { 0x60 };

/// `UNICODE_STRING->Buffer` offset inside the struct: `0x04` on x86 (the 4-byte
/// pointer follows the two `u16` lengths directly), `0x08` on x64 (four bytes of
/// padding align the 8-byte pointer). Getting this wrong writes the pointer over
/// the next field on x86.
const UNICODE_STRING_BUFFER_OFFSET: usize = if cfg!(target_arch = "x86") { 0x04 } else { 0x08 };

/// Reads the current thread's PEB (x64: `gs:[0x60]`).
#[cfg(target_arch = "x86_64")]
unsafe fn current_peb() -> *mut u8 {
    let peb: *mut u8;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags, readonly));
    peb
}

/// Reads the current thread's PEB (x86: `fs:[0x30]`).
#[cfg(target_arch = "x86")]
unsafe fn current_peb() -> *mut u8 {
    let peb: *mut u8;
    core::arch::asm!("mov {}, fs:[0x30]", out(reg) peb, options(nostack, preserves_flags, readonly));
    peb
}

/// Repoints the process's `ImagePathName` at a decoy path.
///
/// Only the `UNICODE_STRING`'s `Buffer`/lengths are rewritten, so the decoy may
/// be any length: the new wide string is leaked on purpose, because the PEB keeps
/// pointing at it for the rest of the process. It does not touch `CommandLine`
/// (the `args` feature owns that), so a check that compares the two sees the
/// mismatch.
pub fn image_path_spoofing() -> Result<bool, String> {
    let path = $SPOOF_PATH_DEF$;
    let mut wide: Vec<u16> = path.encode_utf16().collect();
    let chars = wide.len() as u16;
    wide.push(0);
    let buffer = wide.leak();

    let peb = unsafe { current_peb() };
    if peb.is_null() {
        return Err($MSG_PEB_FAILED$);
    }
    // `PEB->ProcessParameters` is a pointer.
    let params = unsafe { peb.add(PROCESS_PARAMETERS_OFFSET).cast::<*mut u8>().read() };
    if params.is_null() {
        return Err($MSG_PARAMS_FAILED$);
    }
    // `UNICODE_STRING`: Length (u16), MaximumLength (u16), padding (u32),
    // Buffer (*mut u16). Length excludes the terminating NUL.
    let image_path = unsafe { params.add(IMAGE_PATH_OFFSET) };
    unsafe {
        image_path.cast::<u16>().write(chars * 2);
        image_path.add(2).cast::<u16>().write(chars * 2 + 2);
        image_path
            .add(UNICODE_STRING_BUFFER_OFFSET)
            .cast::<*mut u16>()
            .write(buffer.as_mut_ptr());
    }
    crate::tech_dbg!("image_path_spoofing", "PEB image path repointed at the decoy");
    // A Preparation always continues the pipeline when it does not error.
    Ok(true)
}
